<?php
/** 中文管理界面；所有写操作均使用 POST、权限检查和 WordPress nonce。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Admin
{
    private static ?array $testResult = null;
    public static function labels(): array
    {
        return ['sqli' => 'SQL 注入', 'xss' => '跨站脚本', 'rce' => '代码/命令执行',
            'traversal' => '路径穿越', 'probe' => '敏感路径探测', 'scanner' => '扫描工具 UA',
            'blacklist' => '黑名单', 'rate' => '请求限流', 'limits' => '检测边界', 'login' => '登录保护'];
    }

    public static function menu(): void
    {
        $hook = add_options_page('LumeShield 网站防护', 'LumeShield 防护', 'manage_options', 'lumeseed-lumeshield', [self::class, 'page']);
        if (is_string($hook)) { add_action('load-' . $hook, [self::class, 'prepare']); }
    }

    public static function prepare(): void
    {
        // 在后台页头输出之前验证 POST 与 nonce，确保拒绝请求能正确返回 403。
        if (($_GET['tab'] ?? '') === 'tools') { self::$testResult = Simulator::handle(); }
    }

    public static function settings(): void
    {
        register_setting('lumeseed_lumeshield', Settings::OPTION, [
            'type' => 'array', 'sanitize_callback' => [Settings::class, 'sanitize'],
            'default' => Settings::defaults(), 'show_in_rest' => false,
        ]);
        if (current_user_can('manage_options') && get_option('lumeseed_lumeshield_db_version') !== VERSION && !is_multisite()) {
            if (!Storage::install()) {
                Storage::error('数据表初始化');
            }
        }
        if (function_exists('wp_add_privacy_policy_content')) {
            wp_add_privacy_policy_content('LumeShield', '<p>本网站使用 LumeShield 检测可疑请求，可能记录访问者 IP、请求方法、去除查询参数后的路径、命中规则及时间。默认保留 7 天，最多 5000 条聚合记录；重复命中会合并计数。插件不向第三方传送日志，不保存请求体、Cookie、查询参数或命中值。请按本站实际设置调整此说明。</p>');
        }
    }

    public static function notices(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        if (defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE) {
            echo '<div class="notice notice-warning"><p>LumeShield 已通过 wp-config.php 中的紧急开关停用。</p></div>';
        }
        $error = get_option('lumeseed_lumeshield_error');
        if (is_array($error) && isset($error['time'])) {
            echo '<div class="notice notice-error"><p>LumeShield 曾发生运行降级：' . esc_html($error['component'] ?? '未知组件') . '（'
                . esc_html(wp_date('Y-m-d H:i:s', (int) $error['time'])) . '）。请进入防护设置检查数据表和环境；故障时部分检测可能放行。</p></div>';
        }
    }

    public static function action(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die('没有操作权限。', '', ['response' => 403]);
        }
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
            wp_die('只允许 POST 请求。', '', ['response' => 405]);
        }
        check_admin_referer('lumeseed_lumeshield_action');
        global $wpdb;
        $op = sanitize_key(wp_unslash($_POST['operation'] ?? ''));
        $table = Storage::table('logs');
        $success = false;
        if ($op === 'cf_sync') {
            try { Cloudflare::sync(); $success = true; } catch (\Throwable $e) { $success = false; }
            wp_safe_redirect(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'tools', 'ls_result' => $success ? 'cf_ok' : 'cf_fail'], admin_url('options-general.php')));
            exit;
        }
        if ($op === 'clear' && ($_POST['confirm_clear'] ?? '') === 'yes') {
            $success = $wpdb->query("DELETE FROM $table") !== false;
        } elseif ($op === 'delete') {
            $id = absint($_POST['log_id'] ?? 0);
            $success = $id > 0 && $wpdb->delete($table, ['id' => $id], ['%d']) !== false;
        } elseif ($op === 'deny') {
            // 从服务器日志读取 IP，不接受客户端伪造的任意名单内容。
            $id = absint($_POST['log_id'] ?? 0);
            $ip = $wpdb->get_var($wpdb->prepare("SELECT ip FROM $table WHERE id=%d", $id));
            $ip = Ip::canonical((string) $ip);
            $s = Settings::get();
            if ($ip !== '' && (count($s['ip_deny']) < 200 || in_array($ip, $s['ip_deny'], true))) {
                $s['ip_deny'] = array_values(array_unique(array_merge($s['ip_deny'], [$ip])));
                // 已存在也视为成功；当前模式仍决定记录或拦截。
                update_option(Settings::OPTION, $s, false);
                $success = true;
            }
        } elseif ($op === 'cleanup') {
            Storage::cleanup();
            $success = empty($wpdb->last_error);
        } elseif ($op === 'health') {
            $success = Storage::install();
            if ($success) {
                delete_option('lumeseed_lumeshield_error');
            }
        }
        wp_safe_redirect(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'logs', 'ls_result' => $success ? 'ok' : 'fail'], admin_url('options-general.php')));
        exit;
    }

    private static function actionForm(string $op, string $label, int $id = 0): void
    {
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline-block;margin:2px">';
        wp_nonce_field('lumeseed_lumeshield_action');
        echo '<input type="hidden" name="action" value="lumeseed_lumeshield_action"><input type="hidden" name="operation" value="' . esc_attr($op) . '">';
        if ($id) {
            echo '<input type="hidden" name="log_id" value="' . (int) $id . '">';
        }
        if ($op === 'clear') {
            echo '<label><input type="checkbox" name="confirm_clear" value="yes" required>确认永久清空日志</label> ';
        }
        echo '<button class="button" type="submit">' . esc_html($label) . '</button></form>';
    }

    public static function page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $s = Settings::get();
        $requested = $_GET['tab'] ?? 'settings';
        $tab = in_array($requested, ['logs', 'health', 'tools'], true) ? $requested : 'settings';
        $testResult = self::$testResult;
        echo '<div class="wrap"><h1>LumeShield 微光盾</h1><p>让防护可观察、可调整、可恢复。作者：<a href="https://github.com/LumeSeed" target="_blank" rel="noopener noreferrer">LumeSeed</a> · 版本 ' . esc_html(VERSION) . '</p>';
        settings_errors(Settings::OPTION);
        if (isset($_GET['ls_result'])) {
            $messages = ['ok' => '操作已完成。', 'fail' => '操作失败，请检查权限、数据库或名单条目上限。',
                'cf_ok' => 'Cloudflare 托管网段已更新。是否使用这些网段由防护策略中的独立开关控制。',
                'cf_fail' => '同步失败，原配置已保留。请检查服务器能否通过 HTTPS 访问 Cloudflare 官方列表、响应格式及数据库写入权限。'];
            $resultKey = is_string($_GET['ls_result']) ? $_GET['ls_result'] : '';
            echo '<div class="notice notice-info"><p>' . esc_html($messages[$resultKey] ?? '请核对操作状态。') . '</p></div>';
        }
        echo '<nav class="nav-tab-wrapper">';
        foreach (['settings' => '防护策略', 'logs' => '命中日志', 'health' => '运行检查', 'tools' => '维护与试测'] as $key => $label) {
            echo '<a class="nav-tab ' . ($tab === $key ? 'nav-tab-active' : '') . '" href="' . esc_url(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => $key], admin_url('options-general.php'))) . '">' . esc_html($label) . '</a>';
        }
        [$state, $detail] = Diagnostics::mode($s, defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE, is_multisite());
        echo '</nav><p><strong>当前状态：' . esc_html($state) . '</strong> — ' . esc_html($detail) . '</p>';
        if ($tab === 'logs') {
            self::logs();
        } elseif ($tab === 'health') {
            Diagnostics::render();
        } elseif ($tab === 'tools') {
            Simulator::render($testResult);
        } else {
            self::form($s);
        }
        echo '</div>';
    }

    private static function field(string $key): string
    {
        return Settings::OPTION . '[' . $key . ']';
    }

    private static function form(array $s): void
    {
        echo '<form action="options.php" method="post">';
        settings_fields('lumeseed_lumeshield');
        echo '<table class="form-table" role="presentation"><tbody>';
        foreach (['enabled' => '启用防护', 'rate_enabled' => '启用请求限流', 'login_enabled' => '启用登录失败限速',
            'cf_enabled' => '使用 Cloudflare 托管网段', 'delete_on_uninstall' => '删除插件时同时删除策略与日志'] as $key => $label) {
            echo '<tr><th scope="row">' . esc_html($label) . '</th><td><label><input type="checkbox" name="' . esc_attr(self::field($key)) . '" value="1" ' . checked($s[$key], 1, false) . '>启用</label></td></tr>';
        }
        echo '<tr><th>运行模式</th><td><select name="' . esc_attr(self::field('mode')) . '">';
        foreach (['observe' => '观察模式（建议先使用）', 'block' => '拦截模式'] as $value => $label) {
            echo '<option value="' . esc_attr($value) . '" ' . selected($s['mode'], $value, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">观察模式包含黑名单和限流：只记录命中，不改变业务响应。</p></td></tr><tr><th>规则分类</th><td>';
        foreach (Settings::defaults()['categories'] as $key) {
            echo '<label style="display:inline-block;margin:0 16px 8px 0"><input type="checkbox" name="' . esc_attr(self::field('categories')) . '[]" value="' . esc_attr($key) . '" ' . checked(in_array($key, $s['categories'], true), true, false) . '>' . esc_html(self::labels()[$key]) . '</label>';
        }
        echo '</td></tr>';
        foreach (['rate_window' => ['计数窗口（秒）', 5, 3600], 'rate_limit' => ['每 IP 每窗口请求上限', 10, 10000],
            'login_window' => ['登录失败窗口（秒）', 60, 3600], 'login_limit' => ['每 IP 登录失败次数上限', 3, 100],
            'body_limit' => ['请求体/单字段检测上限（字节）', 16384, 1048576],
            'retention_days' => ['日志保留天数', 1, 90], 'max_logs' => ['日志最大聚合条数', 100, 50000]] as $key => [$label, $min, $max]) {
            echo '<tr><th><label for="ls-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td><input id="ls-' . esc_attr($key) . '" type="number" min="' . $min . '" max="' . $max . '" name="' . esc_attr(self::field($key)) . '" value="' . (int) $s[$key] . '"></td></tr>';
        }
        echo '<tr><th>可信代理读取头</th><td><select name="' . esc_attr(self::field('proxy_header')) . '">';
        foreach (['HTTP_X_FORWARDED_FOR' => 'X-Forwarded-For（从右向左解析）', 'HTTP_X_REAL_IP' => 'X-Real-IP', 'HTTP_CF_CONNECTING_IP' => 'CF-Connecting-IP'] as $key => $label) {
            echo '<option value="' . esc_attr($key) . '" ' . selected($s['proxy_header'], $key, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">只有直接连接地址在下方可信代理名单内才读取此头。代理必须覆盖客户端伪造的头；不要把普通访客网段加入可信代理。</p></td></tr>';
        $lists = ['trusted_proxies' => '可信代理 IP/CIDR', 'ip_deny' => 'IP 黑名单', 'ip_allow' => 'IP 白名单',
            'path_deny' => '路径黑名单', 'path_allow' => '路径白名单', 'ua_deny' => 'UA 黑名单', 'ua_allow' => 'UA 白名单'];
        foreach ($lists as $key => $label) {
            $hint = str_starts_with($key, 'path_') ? '精确路径或末尾 * 前缀，例如 /private 或 /api/*；不要填写域名或查询参数。'
                : (str_starts_with($key, 'ua_') ? '忽略大小写的普通子串；不执行正则表达式。' : '精确 IPv4/IPv6 或 CIDR，例如 192.0.2.5、2001:db8::/32；不支持模糊掩码。');
            echo '<tr><th><label for="ls-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td><textarea id="ls-' . esc_attr($key) . '" class="large-text code" rows="3" name="' . esc_attr(self::field($key)) . '">' . esc_textarea(implode("\n", $s[$key])) . '</textarea><p class="description">每行一条，最多 200 条。' . esc_html($hint) . '</p></td></tr>';
        }
        echo '<tr><th><label for="ls-block-theme">拦截页外观</label></th><td><select id="ls-block-theme" name="' . esc_attr(self::field('block_theme')) . '">';
        foreach (['star' => '微光盾 · 星光', 'simple' => 'WordPress 简洁页面'] as $key => $label) {
            echo '<option value="' . esc_attr($key) . '" ' . selected($s['block_theme'], $key, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select><p class="description">星光主题按实际命中类型显示标题，不包含真人验证服务。预览使用示例请求信息及已保存的说明，不修改策略或生成日志。自定义标题仅用于简洁页面。</p><p>';
        foreach ([403 => '预览拦截页', 429 => '预览限流页', 413 => '预览超限页', 400 => '预览格式错误页'] as $status => $label) {
            $url = wp_nonce_url(add_query_arg(['action' => 'lumeshield_preview', 'status' => $status], admin_url('admin-post.php')), 'lumeshield_preview');
            echo '<a class="button" target="_blank" rel="noopener noreferrer" href="' . esc_url($url) . '">' . esc_html($label) . '</a> ';
        }
        echo '</p></td></tr>';
        foreach (['block_title' => '拦截页标题', 'block_message' => '拦截说明'] as $key => $label) {
            echo '<tr><th>' . esc_html($label) . '</th><td><textarea class="large-text" rows="2" name="' . esc_attr(self::field($key)) . '">' . esc_textarea($s[$key]) . '</textarea></td></tr>';
        }
        echo '<tr><th><label for="ls-exceptions">规则精细例外</label></th><td><textarea class="large-text code" id="ls-exceptions" name="' . esc_attr(self::field('exceptions')) . '" rows="5">' . esc_textarea(implode("\n", $s['exceptions'])) . '</textarea>';
        echo '<p class="description">每行：方法 精确路径 字段 规则编号。例如 <code>POST /api/article JSON[content] xss_script</code>。最多 50 条；字段只支持 GET、POST、JSON、COOKIE 的顶层标量，如 POST[content]；字段 * 表示此路径下整条规则豁免。路径不支持通配符。不会跳过其他规则、黑名单、大小限制或限流。</p><details><summary>可用规则编号</summary><p>' . esc_html(implode('、', array_merge(array_column(Engine::rules(), 0), ['scanner_ua']))) . '</p></details></td></tr>';
        echo '</tbody></table><p><strong>名单顺序：</strong>黑名单优先于白名单。IP/路径白名单跳过内容检测与限流；UA 白名单仅跳过扫描工具 UA 规则。已登录且有设置权限的管理员后台放行。</p>';
        echo '<p>登录保护独立于请求白名单：同 IP 在固定窗口累计达到失败上限后，后续 WordPress 登录认证返回限速错误，窗口结束后自动解除；观察模式只记录超限。升级默认不开启，已登录会话不受影响。</p>';
        echo '<p>Cloudflare 托管网段先在“维护与试测”中同步，再开启使用并选择 CF-Connecting-IP。该列表与手动代理合并；如原先把 Cloudflare 网段填在手动名单内，核对同步成功后可移除重复项，避免手动旧网段继续生效。</p>';
        echo '<p>请求超限在拦截模式返回 413，格式异常返回 400，规则命中返回 403，频率超限返回 429。文件上传仅检测表单字段与文件名，不扫描文件内容。插件无法拦截未经过 WordPress 的请求或已由页面缓存直接返回的响应。</p>';
        submit_button('保存防护策略');
        echo '</form>';
    }

    private static function logs(): void
    {
        global $wpdb;
        $table = Storage::table('logs');
        $category = sanitize_key(wp_unslash($_GET['category'] ?? ''));
        $keyword = sanitize_text_field(wp_unslash($_GET['keyword'] ?? ''));
        $keyword = mb_strcut($keyword, 0, 100, 'UTF-8');
        $where = '1=1';
        if (isset(self::labels()[$category])) {
            $where .= $wpdb->prepare(' AND category=%s', $category);
        }
        if ($keyword !== '') {
            $like = '%' . $wpdb->esc_like($keyword) . '%';
            $where .= $wpdb->prepare(' AND (ip LIKE %s OR path LIKE %s OR rule_id LIKE %s)', $like, $like, $like);
        }
        $total = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE $where");
        $pages = max(1, (int) ceil($total / 20));
        $page = max(1, min($pages, absint($_GET['paged'] ?? 1)));
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table WHERE $where ORDER BY id DESC LIMIT 20 OFFSET %d", ($page - 1) * 20), ARRAY_A);
        echo '<p>同 IP、规则、路径与处理方式在 5 分钟内合并计数；日志写入每分钟最多 120 次，命中次数不是完整流量统计。查询参数、Cookie、请求体和命中值不保存。</p>';
        self::actionForm('cleanup', '立即清理过期日志');
        self::actionForm('health', '检查数据表并清除降级提示');
        echo '<form method="get" style="margin:16px 0"><input type="hidden" name="page" value="lumeseed-lumeshield"><input type="hidden" name="tab" value="logs"><select name="category"><option value="">全部分类</option>';
        foreach (self::labels() as $key => $label) {
            echo '<option value="' . esc_attr($key) . '" ' . selected($category, $key, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select> <input name="keyword" value="' . esc_attr($keyword) . '" placeholder="IP、路径或规则编号"> <button class="button">筛选</button></form>';
        echo '<div style="overflow-x:auto"><table class="widefat striped"><thead><tr><th>最后命中时间</th><th>IP</th><th>方法与路径</th><th>分类 / 规则</th><th>处理</th><th>次数</th><th>操作</th></tr></thead><tbody>';
        foreach ($rows ?: [] as $row) {
            echo '<tr><td>' . esc_html(wp_date('Y-m-d H:i:s', (int) $row['last_seen'])) . '</td><td>' . esc_html($row['ip']) . '</td><td>' . esc_html($row['method'] . ' ' . $row['path']) . '</td><td>' . esc_html((self::labels()[$row['category']] ?? $row['category']) . ' / ' . $row['rule_id']) . '</td><td>' . ($row['action_name'] === 'block' ? '已拦截' : '仅观察') . '</td><td>' . (int) $row['hits'] . '</td><td>';
            self::actionForm('deny', '拉黑 IP', (int) $row['id']);
            self::actionForm('delete', '删除', (int) $row['id']);
            echo '</td></tr>';
        }
        if (!$rows) {
            echo '<tr><td colspan="7">没有匹配的命中日志。</td></tr>';
        }
        echo '</tbody></table></div><p>共 ' . $total . ' 条聚合记录，第 ' . $page . ' / ' . $pages . ' 页</p>';
        $base = add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'logs', 'category' => $category, 'keyword' => $keyword], admin_url('options-general.php'));
        echo wp_kses_post((string) paginate_links(['base' => add_query_arg('paged', '%#%', $base), 'format' => '', 'current' => $page, 'total' => $pages]));
        echo '<hr>';
        self::actionForm('clear', '清空日志');
    }
}
