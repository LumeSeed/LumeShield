<?php
/** 分组配置界面；所有字段始终留在同一表单，折叠不影响保存。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class SettingsPage
{
    public static function assets(): void
    {
        wp_enqueue_style('lumeshield-settings', plugins_url('assets/settings.css', FILE), [], VERSION);
        wp_enqueue_script('lumeshield-settings', plugins_url('assets/settings.js', FILE), [], VERSION, true);
    }

    private static function name(string $key): string { return Settings::OPTION . '[' . $key . ']'; }
    private static function id(string $key): string
    {
        return ['log_mode' => 'ls-log-mode', 'log_window' => 'ls-log-window', 'block_theme' => 'ls-block-theme',
            'autoban_enabled' => 'ls-autoban-enabled'][$key] ?? 'ls-' . $key;
    }
    private static function start(string $key, string $title, string $summary, bool $open = false): void
    {
        echo '<details class="ls-section" id="ls-section-' . esc_attr($key) . '"' . ($open ? ' open' : '') . '><summary><span class="ls-section-title">' . esc_html($title) . '</span><span class="ls-section-status">' . esc_html($summary) . '</span></summary><div class="ls-section-body"><div class="ls-fields">';
    }
    private static function end(): void { echo '</div></div></details>'; }
    private static function help(string $text): void
    {
        echo '<details class="ls-help ls-wide"><summary>使用说明</summary><p>' . esc_html($text) . '</p></details>';
    }
    private static function toggle(array $s, string $key, string $label): void
    {
        echo '<label class="ls-switch" for="' . esc_attr(self::id($key)) . '"><input type="checkbox" id="' . esc_attr(self::id($key)) . '" name="' . esc_attr(self::name($key)) . '" value="1" ' . checked($s[$key], 1, false) . '><span>' . esc_html($label) . '</span></label>';
    }
    private static function select(array $s, string $key, string $label, array $options, string $hint = ''): void
    {
        echo '<div class="ls-field"><label for="' . esc_attr(self::id($key)) . '">' . esc_html($label) . '</label><select id="' . esc_attr(self::id($key)) . '" name="' . esc_attr(self::name($key)) . '">';
        foreach ($options as $value => $text) { echo '<option value="' . esc_attr($value) . '" ' . selected($s[$key], $value, false) . '>' . esc_html($text) . '</option>'; }
        echo '</select>';
        self::hint($hint);
        echo '</div>';
    }
    private static function hint(string $text): void
    {
        if ($text !== '') { echo '<p class="description">' . esc_html($text) . '</p>'; }
    }
    private static function number(array $s, string $key, string $label, int $min, int $max, string $hint = ''): void
    {
        echo '<div class="ls-field"><label for="' . esc_attr(self::id($key)) . '">' . esc_html($label) . '</label><input type="number" id="' . esc_attr(self::id($key)) . '" name="' . esc_attr(self::name($key)) . '" min="' . $min . '" max="' . $max . '" value="' . (int) $s[$key] . '" required>';
        self::hint($hint);
        echo '</div>';
    }
    private static function area(array $s, string $key, string $label, string $hint = '', bool $wide = false, bool $required = false): void
    {
        $value = is_array($s[$key]) ? implode("\n", $s[$key]) : $s[$key];
        echo '<div class="ls-field' . ($wide ? ' ls-wide' : '') . '"><label for="' . esc_attr(self::id($key)) . '">' . esc_html($label) . '</label><textarea id="' . esc_attr(self::id($key)) . '" name="' . esc_attr(self::name($key)) . '" rows="3"' . ($required ? ' required' : '') . '>' . esc_textarea($value) . '</textarea>';
        self::hint($hint);
        echo '</div>';
    }

    public static function render(array $s): void
    {
        foreach (get_settings_errors('general') as $notice) {
            if ($notice['code'] === 'settings_updated') {
                echo '<div class="notice notice-success is-dismissible"><p>防护策略已保存，所有分组配置已更新。</p></div>';
            }
        }
        echo '<form id="ls-settings-form" class="ls-settings" action="options.php" method="post">';
        settings_fields('lumeseed_lumeshield');
        echo '<p class="ls-settings-intro">选择一组展开设置，完成后统一保存。</p>';
        self::start('general', '常用设置', ($s['mode'] === 'block' ? '拦截模式' : '观察模式') . ' · ' . ($s['log_mode'] === 'detailed' ? '详细日志' : '脱敏日志'), true);
        echo '<div class="ls-wide">'; self::toggle($s, 'enabled', '启用防护'); echo '</div>';
        self::select($s, 'mode', '运行模式', ['observe' => '观察模式', 'block' => '拦截模式'], '观察只记录；拦截会拒绝命中请求。');
        self::select($s, 'log_mode', '日志记录模式', ['redacted' => '脱敏聚合', 'detailed' => '详细记录：URI、UA 和命中内容'], '详细内容可能包含密码、令牌或个人信息。');
        self::number($s, 'log_window', '日志合并窗口（秒）', 5, 3600, '重复次数累加，保留首次详情。');
        self::number($s, 'retention_days', '日志保留天数', 1, 90);
        self::number($s, 'max_logs', '日志最大条数', 100, 50000);
        self::help('固定窗口内按 IP、方法、规则、路径、字段和处理方式合并，更新次数及最后命中时间，跨窗口新建记录。详细模式保留首次 URI（4096 字节）、UA（2048 字节）及命中片段（4096 字节）；切回脱敏模式不会删除已有详情。每分钟最多记录 120 次事件，日志不代表完整流量。');
        self::end();

        self::start('rules', '防护规则', count($s['categories']) . ' 类开启 · ' . count($s['disabled_rules']) . ' 条停用 · ' . count($s['exceptions']) . ' 条例外');
        echo '<fieldset class="ls-wide ls-checks"><legend>检测分类</legend>';
        foreach (Settings::defaults()['categories'] as $category) {
            echo '<label><input type="checkbox" name="' . esc_attr(self::name('categories')) . '[]" value="' . esc_attr($category) . '" ' . checked(in_array($category, $s['categories'], true), true, false) . '>' . esc_html(Admin::labels()[$category]) . '</label>';
        }
        echo '</fieldset><details class="ls-help ls-wide"><summary>单条规则管理（勾选代表停用）</summary><div class="ls-rule-list">';
        $rules = Engine::rules(); $rules[] = ['scanner_ua', 'scanner', '扫描工具 UA 标识'];
        foreach ($rules as $rule) {
            echo '<label><input type="checkbox" name="' . esc_attr(self::name('disabled_rules')) . '[]" value="' . esc_attr($rule[0]) . '" ' . checked(in_array($rule[0], $s['disabled_rules'], true), true, false) . '><span>' . esc_html($rule[2]) . '<small>' . esc_html($rule[0]) . '</small></span></label>';
        }
        echo '</div></details>';
        self::number($s, 'body_limit', '请求体 / 单字段检测上限（字节）', 16384, 1048576);
        self::area($s, 'exceptions', '规则精细例外', '每行：方法 精确路径 字段 规则编号；最多 50 条。', true);
        self::help('例：POST /api/article JSON[content] xss_script。字段仅支持 GET、POST、JSON、COOKIE 顶层标量；* 表示此路径下整条规则豁免，路径不支持通配符。单条规则编号见上方管理列表。例外不会跳过其他规则、黑名单、大小限制或限流。文件上传只检测表单字段和文件名。');
        self::end();

        self::start('autoban', '自动封禁', ($s['autoban_enabled'] ? '已开启' : '未开启') . ' · ' . (int) $s['autoban_threshold'] . ' 次 / ' . (int) $s['autoban_window'] . ' 秒');
        echo '<div class="ls-wide">'; self::toggle($s, 'autoban_enabled', '频繁命中后临时封禁 IP'); self::hint('仅在拦截模式生效，按攻击规则命中计数。'); echo '</div>';
        self::number($s, 'autoban_window', '统计窗口（秒）', 60, 3600, '300 秒 = 5 分钟');
        self::number($s, 'autoban_threshold', '每 IP 命中次数阈值', 3, 1000);
        self::number($s, 'autoban_duration', '封禁时长（秒）', 60, 604800, '3600 秒 = 1 小时，到期自动解封。');
        self::help('每次请求最多计数一次，与日志合并和写入预算无关。普通访问、限流和登录失败不计入。封禁期间不延长期限；手动解封重置计数。IP / 路径白名单、已登录且有设置权限的管理员、可信代理地址不受自动封禁影响，手动黑名单仍优先。关闭功能或改为观察模式后暂停执行，重新开启时未到期的封禁继续生效。修改时长仅影响后续新封禁。');
        self::end();

        self::start('limits', '限流与登录保护', '请求限流' . ($s['rate_enabled'] ? '开启' : '关闭') . ' · 登录保护' . ($s['login_enabled'] ? '开启' : '关闭'));
        echo '<div class="ls-wide">'; self::toggle($s, 'rate_enabled', '启用请求限流'); echo '</div>';
        self::number($s, 'rate_window', '请求计数窗口（秒）', 5, 3600);
        self::number($s, 'rate_limit', '每 IP 每窗口请求上限', 10, 10000);
        echo '<div class="ls-wide ls-divider">'; self::toggle($s, 'login_enabled', '启用登录失败限速'); echo '</div>';
        self::number($s, 'login_window', '登录失败窗口（秒）', 60, 3600);
        self::number($s, 'login_limit', '每 IP 登录失败次数上限', 3, 100);
        self::help('观察模式仅记录超限；拦截模式返回 429。登录保护独立于请求白名单，达到失败上限后限制后续认证，窗口结束恢复，已登录会话不受影响。共享出口可能有多个用户，请先核对来源 IP。');
        self::end();

        $listCount = 0; foreach (['ip_deny', 'ip_allow', 'path_deny', 'path_allow', 'ua_deny', 'ua_allow'] as $key) { $listCount += count($s[$key]); }
        self::start('lists', '访问名单', $listCount . ' 条名单');
        self::area($s, 'ip_deny', 'IP 黑名单', '每行一个 IP 或 CIDR。');
        self::area($s, 'ip_allow', 'IP 白名单', '跳过内容检测与请求限流。');
        self::area($s, 'path_deny', '路径黑名单', '如 /private 或 /api/*，不含域名与查询串。');
        self::area($s, 'path_allow', '路径白名单', '跳过内容检测与请求限流。');
        self::area($s, 'ua_deny', 'UA 黑名单', '忽略大小写，按普通子串匹配。');
        self::area($s, 'ua_allow', 'UA 白名单', '仅跳过扫描工具 UA 规则。');
        self::help('每种名单最多 200 条。黑名单优先于白名单；路径只支持精确匹配或末尾 * 前缀。IP 支持 IPv4、IPv6、CIDR；UA 不执行正则。已登录且有设置权限的管理员后台放行。');
        self::end();

        self::start('proxy', '代理与来源 IP', ($s['cf_enabled'] ? 'Cloudflare 已开启' : 'Cloudflare 未开启') . ' · ' . count($s['trusted_proxies']) . ' 条手动代理');
        echo '<div class="ls-wide">'; self::toggle($s, 'cf_enabled', '使用 Cloudflare 托管网段'); self::hint('先到“维护与试测”同步官方网段，再启用。'); echo '</div>';
        self::select($s, 'proxy_header', '可信代理读取头', ['HTTP_X_FORWARDED_FOR' => 'X-Forwarded-For（从右向左）', 'HTTP_X_REAL_IP' => 'X-Real-IP', 'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP']);
        self::area($s, 'trusted_proxies', '可信代理 IP / CIDR', '只填写真实回源代理；不要加入普通访客网段。', true);
        self::help('仅直接连接地址位于可信名单时读取代理头，代理必须覆盖伪造头。Cloudflare 托管网段与手动名单合并；同步后可移除手动重复项，避免旧网段继续生效。');
        self::end();

        self::start('appearance', '拦截页与数据', ($s['block_theme'] === 'star' ? '星光拦截页' : '简洁拦截页') . ' · 卸载' . ($s['delete_on_uninstall'] ? '删除数据' : '保留数据'));
        self::select($s, 'block_theme', '拦截页外观', ['star' => '微光盾 · 星光', 'simple' => 'WordPress 简洁页面']);
        echo '<div class="ls-field"><span class="ls-field-label">预览已保存的外观</span><div class="ls-previews">';
        foreach ([403 => '规则拦截', 429 => '请求限流', 413 => '请求超限', 400 => '格式错误'] as $status => $label) {
            $url = wp_nonce_url(add_query_arg(['action' => 'lumeshield_preview', 'status' => $status], admin_url('admin-post.php')), 'lumeshield_preview');
            echo '<a class="button" target="_blank" rel="noopener noreferrer" href="' . esc_url($url) . '">' . esc_html($label) . '</a> ';
        }
        echo '</div></div>';
        self::area($s, 'block_title', '简洁页面标题', '星光主题按实际命中类型显示标题。', false, true);
        self::area($s, 'block_message', '拦截说明', '', false, true);
        echo '<div class="ls-wide ls-divider">'; self::toggle($s, 'delete_on_uninstall', '删除插件时同时删除策略与日志'); self::hint('开启后，卸载会永久清除数据。'); echo '</div>';
        self::help('预览不修改策略、不生成日志。插件仅检查经过 WordPress 的请求，无法检查直接由页面缓存返回的响应。拦截状态码：规则 403、限流 429、超限 413、格式异常 400。');
        self::end();

        echo '<div class="ls-savebar"><span id="ls-save-status" role="status" aria-live="polite">所有分组统一保存</span><button type="submit" class="button button-primary" id="submit">保存防护策略</button></div></form>';
    }
}
