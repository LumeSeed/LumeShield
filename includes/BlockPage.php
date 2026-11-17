<?php
/** 微光盾结果页：展示实际拦截类型，不模拟真人验证。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;
final class BlockPage
{
    public static function type(int $status, array $hit = []): string
    {
        // 只公开固定类别名称，不回显规则表达式、请求内容或内部字段。
        if ($status === 429) return '请求频率超限';
        if ($status === 413) return '请求大小超限';
        if ($status === 400) return '请求格式异常';
        $ids = ['deny_ip' => 'IP 黑名单拦截', 'deny_path' => '路径访问拦截', 'deny_ua' => '客户端访问拦截'];
        $categories = ['sqli' => 'SQL 注入拦截', 'xss' => '跨站脚本拦截', 'rce' => '代码执行拦截',
            'traversal' => '目录穿越拦截', 'probe' => '敏感路径拦截', 'scanner' => '扫描器访问拦截'];
        return $ids[$hit['id'] ?? ''] ?? $categories[$hit['category'] ?? ''] ?? '安全策略拦截';
    }

    public static function metadata(array $server, array $s, string $ip): array
    {
        $result = ['ray' => '不可用', 'region' => '未知'];
        // 只接受配置为可信 Cloudflare 代理的元数据，忽略直连请求伪造的头。
        $peer = Ip::canonical((string) ($server['REMOTE_ADDR'] ?? ''));
        $forwarded = Ip::canonical((string) ($server['HTTP_CF_CONNECTING_IP'] ?? ''));
        if ($s['proxy_header'] !== 'HTTP_CF_CONNECTING_IP' || $peer === '' || $forwarded === ''
            || $forwarded !== $ip || !Ip::listed($peer, Settings::proxies($s))) return $result;
        $ray = $server['HTTP_CF_RAY'] ?? '';
        if (is_string($ray) && preg_match('/\A[a-f0-9]{16,32}(?:-[A-Z]{3})?\z/i', $ray)) $result['ray'] = $ray;
        $region = $server['HTTP_CF_IPCOUNTRY'] ?? '';
        if (is_string($region) && preg_match('/\A[A-Z]{2}\z/', $region) && $region !== 'XX') {
            $names = ['CN' => '中国', 'HK' => '中国香港', 'MO' => '中国澳门', 'TW' => '中国台湾',
                'SG' => '新加坡', 'JP' => '日本', 'US' => '美国', 'GB' => '英国', 'DE' => '德国', 'AU' => '澳大利亚'];
            $result['region'] = $region . (isset($names[$region]) ? ' · ' . $names[$region] : '');
        }
        return $result;
    }

    public static function context(array $s, int $status, string $ip, bool $preview = false, array $hit = []): array
    {
        $title = self::type($status, $hit);
        $message = (string) $s['block_message'];
        if ($status === 429) $message = '访问频率已超过本站限制，请等待 ' . (int) $s['rate_window'] . ' 秒后重试。';
        if ($status === 413) $message = '本次请求超过了本站的检测上限，请缩小提交内容后重试。';
        if ($status === 400) $message = '本次请求的格式不受支持，请检查提交内容后重试。';
        $meta = $preview ? ['ray' => '7c92e4a1b083d65f', 'region' => 'CN · 中国'] : self::metadata($_SERVER, $s, $ip);
        return compact('title', 'message', 'status', 'ip', 'preview') + $meta;
    }

    public static function render(array $data, string $nonce = ''): string
    {
        $e = static fn($v): string => htmlspecialchars((string) $v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        // 内联资源，避免被封 IP 再次请求静态文件。
        $css = file_get_contents(__DIR__ . '/../assets/star-shield.css');
        $asset = __DIR__ . '/../assets/lumeshield-starlight.webp';
        $scene = is_file($asset) ? 'data:image/webp;base64,' . base64_encode(file_get_contents($asset)) : '';
        $emblem = 'data:image/webp;base64,' . base64_encode(file_get_contents(__DIR__ . '/../assets/lumeshield-emblem.webp'));
        ob_start();
        require __DIR__ . '/../templates/star-shield.php';
        return (string) ob_get_clean();
    }

    public static function output(array $s, int $status, string $ip, bool $preview = false, array $hit = []): void
    {
        $nonce = base64_encode(random_bytes(18));
        header('Content-Type: text/html; charset=UTF-8');
        header("Content-Security-Policy: default-src 'none'; img-src data:; style-src 'nonce-" . $nonce . "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        header('Referrer-Policy: no-referrer');
        header('X-Content-Type-Options: nosniff');
        header('X-Robots-Tag: noindex, nofollow');
        echo self::render(self::context($s, $status, $ip, $preview, $hit), $nonce);
        exit;
    }

    public static function preview(): void
    {
        if (!current_user_can('manage_options')) wp_die('没有预览权限。', '', ['response' => 403]);
        check_admin_referer('lumeshield_preview');
        $requested = $_GET['status'] ?? '403';
        $status = is_string($requested) && in_array($requested, ['400', '403', '413', '429'], true) ? (int) $requested : 403;
        nocache_headers();
        // 示例数据不计数、不写日志、不修改名单。
        self::output(Settings::get(), $status, '203.0.113.24', true, ['category' => 'sqli']);
    }
}
