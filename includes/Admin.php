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
        $hook = add_menu_page('LumeShield 网站防护', 'LumeShield 防护', 'manage_options', 'lumeseed-lumeshield', [self::class, 'page'], 'dashicons-shield', 81);
        if (is_string($hook)) { add_action('load-' . $hook, [self::class, 'prepare']); }
    }

    public static function prepare(): void
    {
        // 在后台页头输出之前验证 POST 与 nonce，确保拒绝请求能正确返回 403。
        if (($_GET['tab'] ?? '') === 'tools') { self::$testResult = Simulator::handle(); }
        if (($_GET['tab'] ?? '') === 'logs') { Console::prepareException(); }
        if (($_GET['tab'] ?? '') === 'settings') { SettingsPage::assets(); }
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
            wp_add_privacy_policy_content('LumeShield', '<p>本网站使用 LumeShield 检测可疑请求，可能记录访问者 IP、请求方法、去除查询参数后的路径、命中规则及时间。默认保留 7 天，最多 5000 条记录；窗口内重复命中会合并计数。默认脱敏模式不保存命中值、完整 URI 或 UA；管理员可启用详细模式，保存有限长度的 URI（含查询串）、UA 和命中片段，其中可能包含个人信息或令牌。启用自动封禁后，还会独立保存 IP、命中次数、触发规则和封禁到期时间；过期记录由定时任务清理。插件不向第三方传送日志。请按本站实际设置调整此说明。</p>');
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
        if ($op === 'unban') {
            $success = AutoBan::release(absint($_POST['ban_id'] ?? 0));
            wp_safe_redirect(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'bans', 'ls_result' => $success ? 'ok' : 'fail'], admin_url('admin.php')));
            exit;
        }
        if ($op === 'cf_sync') {
            try { Cloudflare::sync(); $success = true; } catch (\Throwable $e) { $success = false; }
            wp_safe_redirect(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'tools', 'ls_result' => $success ? 'cf_ok' : 'cf_fail'], admin_url('admin.php')));
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
        } elseif ($op === 'exception') {
            $id = absint($_POST['log_id'] ?? 0);
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE id=%d", $id), ARRAY_A);
            $line = $row ? Exceptions::fromLog($row) : null;
            if ($line !== null && ($_POST['confirm_exception'] ?? '') === 'yes') {
                try {
                    $s = Settings::get();
                    $s['exceptions'] = array_values(array_unique(array_merge($s['exceptions'], [$line])));
                    Exceptions::parse($s['exceptions']);
                    $success = update_option(Settings::OPTION, $s, false) || get_option(Settings::OPTION) === $s;
                } catch (\Throwable $e) { $success = false; }
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
        wp_safe_redirect(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'logs', 'ls_result' => $success ? 'ok' : 'fail'], admin_url('admin.php')));
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
        $requested = $_GET['tab'] ?? 'overview';
        $tab = in_array($requested, ['overview', 'settings', 'logs', 'bans', 'health', 'tools'], true) ? $requested : 'overview';
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
        foreach (['overview' => '防护概览', 'settings' => '防护策略', 'logs' => '命中日志', 'bans' => '自动封禁', 'health' => '运行检查', 'tools' => '维护与试测'] as $key => $label) {
            echo '<a class="nav-tab ' . ($tab === $key ? 'nav-tab-active' : '') . '" href="' . esc_url(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => $key], admin_url('admin.php'))) . '">' . esc_html($label) . '</a>';
        }
        [$state, $detail] = Diagnostics::mode($s, defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE, is_multisite());
        echo '</nav><p><strong>当前状态：' . esc_html($state) . '</strong> — ' . esc_html($detail) . '</p>';
        if ($tab === 'overview') {
            Console::overview();
        } elseif ($tab === 'logs') {
            self::logs();
        } elseif ($tab === 'bans') {
            AutoBanAdmin::render($s);
        } elseif ($tab === 'health') {
            Diagnostics::render();
        } elseif ($tab === 'tools') {
            Simulator::render($testResult);
        } else {
            SettingsPage::render($s);
        }
        echo '</div>';
    }

    private static function logs(): void
    {
        global $wpdb;
        $table = Storage::table('logs');
        Console::exceptionEditor();
        $category = sanitize_key(wp_unslash($_GET['category'] ?? ''));
        $keyword = sanitize_text_field(wp_unslash($_GET['keyword'] ?? ''));
        $keyword = mb_strcut($keyword, 0, 100, 'UTF-8');
        $filters = Console::filters();
        $where = Console::where($filters);
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
        $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table WHERE $where ORDER BY last_seen DESC,id DESC LIMIT 20 OFFSET %d", ($page - 1) * 20), ARRAY_A);
        echo '<p>同 IP、方法、规则、路径、字段、处理方式与日志模式在设定的固定窗口内合并，次数累加并更新最后命中时间，详情保留首次内容。每分钟最多记录 120 次事件，计数可能低于实际流量。脱敏模式不存 URI 查询串、UA 和命中值；详细模式保存有限长度的这些内容。</p>';
        self::actionForm('cleanup', '立即清理过期日志');
        self::actionForm('health', '检查数据表并清除降级提示');
        echo '<form method="get" style="margin:16px 0"><input type="hidden" name="page" value="lumeseed-lumeshield"><input type="hidden" name="tab" value="logs"><select name="category"><option value="">全部分类</option>';
        foreach (self::labels() as $key => $label) {
            echo '<option value="' . esc_attr($key) . '" ' . selected($category, $key, false) . '>' . esc_html($label) . '</option>';
        }
        echo '</select> ';
        Console::filterFields($filters);
        echo '<label>关键词 <input name="keyword" value="' . esc_attr($keyword) . '" placeholder="IP、路径或规则编号"></label> <button class="button">筛选</button></form>';
        echo '<div style="overflow-x:auto"><table class="widefat striped"><thead><tr><th>最后命中时间</th><th>IP</th><th>方法与路径</th><th>分类 / 规则</th><th>处理</th><th>次数</th><th>操作</th></tr></thead><tbody>';
        foreach ($rows ?: [] as $row) {
            echo '<tr><td>' . esc_html(wp_date('Y-m-d H:i:s', (int) $row['last_seen'])) . '</td><td>' . esc_html($row['ip']) . '</td><td>' . esc_html($row['method'] . ' ' . $row['path']) . '</td><td>' . esc_html((self::labels()[$row['category']] ?? $row['category']) . ' / ' . $row['rule_id']) . '</td><td>' . ($row['action_name'] === 'block' ? '已拦截' : '仅观察') . '</td><td>' . (int) $row['hits'] . '</td><td>';
            self::actionForm('deny', '拉黑 IP', (int) $row['id']);
            self::actionForm('delete', '删除', (int) $row['id']);
            echo '</td></tr><tr><td colspan="7">';
            Console::logDetails($row);
            echo '</td></tr>';
        }
        if (!$rows) {
            echo '<tr><td colspan="7">没有匹配的命中日志。</td></tr>';
        }
        echo '</tbody></table></div><p>共 ' . $total . ' 条聚合记录，第 ' . $page . ' / ' . $pages . ' 页</p>';
        $base = add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'logs', 'category' => $category, 'keyword' => $keyword] + $filters, admin_url('admin.php'));
        echo wp_kses_post((string) paginate_links(['base' => add_query_arg('paged', '%#%', $base), 'format' => '', 'current' => $page, 'total' => $pages]));
        echo '<hr>';
        self::actionForm('clear', '清空日志');
    }
}
