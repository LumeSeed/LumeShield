<?php
/** WordPress 生命周期与请求防护入口。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Plugin
{
    public static function register(): void
    {
        add_action('init', [self::class, 'scan'], -100);
        add_action('admin_menu', [Admin::class, 'menu']);
        add_action('admin_init', [Admin::class, 'settings']);
        add_action('admin_notices', [Admin::class, 'notices']);
        add_action('admin_post_lumeseed_lumeshield_action', [Admin::class, 'action']);
        add_action('admin_post_lumeshield_preview', [BlockPage::class, 'preview']);
        add_action('lumeseed_lumeshield_cleanup', [Storage::class, 'cleanup']);
        add_filter('cron_schedules', [self::class, 'schedules']);
        add_filter('authenticate', [LoginGuard::class, 'authenticate'], PHP_INT_MAX, 3);
        add_action('wp_login_failed', [LoginGuard::class, 'failed'], 10, 2);
        add_filter('plugin_action_links_' . plugin_basename(FILE), [self::class, 'links']);
    }

    public static function schedules(array $schedules): array
    {
        $schedules['lumeseed_lumeshield_five_minutes'] = ['interval' => 300, 'display' => 'LumeShield 每五分钟清理'];
        return $schedules;
    }

    public static function links(array $links): array
    {
        array_unshift($links, '<a href="' . esc_url(admin_url('options-general.php?page=lumeseed-lumeshield')) . '">防护设置</a>');
        return $links;
    }

    public static function activate(bool $networkWide = false): void
    {
        // 首版明确支持单站，避免网络启用后只为主站建表造成其他站点静默失效。
        if (is_multisite() || $networkWide) {
            wp_die('LumeShield 1.0 当前支持 WordPress 单站，暂不支持多站点网络。');
        }
        if (!function_exists('mb_strcut')) {
            wp_die('LumeShield 需要 PHP mbstring 扩展，请启用后重试。');
        }
        if (!Storage::install()) {
            wp_die('LumeShield 数据表创建失败，请检查数据库建表权限后重试。');
        }
        add_option(Settings::OPTION, Settings::defaults(), '', false);
        if (!wp_next_scheduled('lumeseed_lumeshield_cleanup')) {
            wp_schedule_event(time() + 300, 'lumeseed_lumeshield_five_minutes', 'lumeseed_lumeshield_cleanup');
        }
    }

    public static function deactivate(): void
    {
        wp_clear_scheduled_hook('lumeseed_lumeshield_cleanup');
        // 停用保留策略和日志，删除插件时按用户选择决定是否清理。
    }

    public static function scan(): void
    {
        static $ran = false;
        if ($ran || (defined('WP_CLI') && WP_CLI) || wp_doing_cron()
            || (defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE)) {
            return;
        }
        $ran = true;
        $s = Settings::get();
        if (!$s['enabled'] || is_multisite()) {
            return;
        }
        // 仅放行已认证且拥有设置权限的管理后台；不按来源 IP 或 URL 猜测管理员身份。
        if (is_admin() && current_user_can('manage_options')) {
            return;
        }
        try {
            self::run($s);
        } catch (\Throwable $e) {
            // 基础设施异常时保证网站可访问，并在后台持续显示降级提示。
            Storage::error('扫描引擎');
        }
    }

    private static function run(array $s): void
    {
        $ip = Ip::resolve($_SERVER, Settings::proxies($s), $s['proxy_header']);
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = Engine::path($uri);
        $ua = (string) ($_SERVER['HTTP_USER_AGENT'] ?? '');
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $hit = null;
        if (Ip::listed($ip, $s['ip_deny'])) {
            $hit = Engine::hit('deny_ip', 'blacklist', 'IP', 'IP 黑名单');
        } elseif (Engine::pathListed($path, $s['path_deny'])) {
            $hit = Engine::hit('deny_path', 'blacklist', '路径', '路径黑名单');
        } elseif (Engine::uaListed($ua, $s['ua_deny'])) {
            $hit = Engine::hit('deny_ua', 'blacklist', 'User-Agent', 'UA 黑名单');
        }
        if ($hit) {
            self::finish($hit, $s, $ip, $method, $path, 403);
            return;
        }
        if (Ip::listed($ip, $s['ip_allow']) || Engine::pathListed($path, $s['path_allow'])) {
            return;
        }
        // 先限流再执行较贵的内容检测；观察模式同样计数，但不会阻断。
        if ($s['rate_enabled'] && $ip !== '') {
            $count = Storage::increment('访问:' . $ip, (int) $s['rate_window']);
            if ($count !== null && $count > (int) $s['rate_limit']) {
                self::finish(Engine::hit('rate_limit', 'rate', 'IP', '请求频率超限'), $s, $ip, $method, $path, 429);
                return;
            }
        }
        $type = (string) ($_SERVER['CONTENT_TYPE'] ?? '');
        $limit = (int) $s['body_limit'];
        $raw = null;
        try {
            if (strlen($uri) > $limit || strlen($ua) > 8192) {
                throw new \LengthException('请求头超出检测范围');
            }
            // 文件内容由上传安全机制负责；这里只扫描 multipart 的表单字段及文件名。
            $multipart = stripos($type, 'multipart/form-data') === 0;
            $hasBody = in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true)
                || !empty($_SERVER['CONTENT_LENGTH']) || !empty($_SERVER['HTTP_TRANSFER_ENCODING']);
            if (!$multipart && $hasBody) {
                if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > $limit) {
                    throw new \LengthException('请求体超出检测上限');
                }
                // 不依赖 Content-Length；未知长度或分块传输也最多读取上限加一个字节。
                $stream = fopen('php://input', 'rb');
                if ($stream === false) {
                    throw new \RuntimeException('无法读取请求体');
                }
                try {
                    $raw = stream_get_contents($stream, $limit + 1);
                } finally {
                    fclose($stream);
                }
                if ($raw === false) {
                    throw new \RuntimeException('请求体读取失败');
                }
                if (strlen($raw) > $limit) {
                    throw new \LengthException('请求体超出检测上限');
                }
                if (!empty($_SERVER['HTTP_CONTENT_ENCODING']) && strtolower($_SERVER['HTTP_CONTENT_ENCODING']) !== 'identity') {
                    throw new \UnexpectedValueException('不支持压缩的请求体');
                }
            }
            $collector = new Inputs($limit);
            foreach ($_FILES as $key => $file) {
                if (is_array($file) && isset($file['name'])) {
                    $collector->walk($file['name'], '文件名[' . (string) $key . ']', 'value');
                }
            }
            $items = $collector->collect(wp_unslash($_GET), wp_unslash($_POST), wp_unslash($_COOKIE), $uri, $raw, $type);
            $hit = Engine::inspect($items, $s['categories'], $path, $ua, Engine::uaListed($ua, $s['ua_allow']), Exceptions::parse($s['exceptions']), $method);
            if ($hit) {
                self::finish($hit, $s, $ip, $method, $path, 403);
            }
        } catch (\LengthException $e) {
            self::finish(Engine::hit('inspection_limit', 'limits', '请求', '请求超出检测上限'), $s, $ip, $method, $path, 413);
        } catch (\UnexpectedValueException $e) {
            self::finish(Engine::hit('invalid_body', 'limits', '请求体', '请求体格式不受支持'), $s, $ip, $method, $path, 400);
        }
    }

    private static function finish(array $hit, array $s, string $ip, string $method, string $path, int $status): void
    {
        $observe = $s['mode'] === 'observe';
        // 日志故障不会取消已经确认的拦截决定。
        try {
            Storage::record($hit, $ip, $method, $path, $observe ? 'observe' : 'block');
        } catch (\Throwable $e) {
            Storage::error('日志存储');
        }
        if ($observe) {
            return;
        }
        status_header($status);
        nocache_headers();
        header('X-Content-Type-Options: nosniff');
        if ($status === 429) {
            header('Retry-After: ' . (int) $s['rate_window']);
        }
        $json = wp_doing_ajax() || stripos($_SERVER['CONTENT_TYPE'] ?? '', 'json') !== false
            || stripos($_SERVER['HTTP_ACCEPT'] ?? '', 'application/json') !== false
            || strpos($path, '/wp-json/') !== false || isset($_GET['rest_route']);
        if ($json) {
            wp_send_json_error(['code' => 'lumeshield_blocked', 'message' => $s['block_message']], $status);
        }
        // 不向访客回显规则表达式、命中内容或内部数据库错误。
        if (($s['block_theme'] ?? 'star') === 'star') {
            BlockPage::output($s, $status, $ip, false, $hit);
        }
        wp_die(esc_html($s['block_message']), esc_html($s['block_title']), ['response' => $status]);
    }
}
