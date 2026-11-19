<?php
/** 自动封禁配置与临时名单管理，沿用 WordPress 权限和表单。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class AutoBanAdmin
{
    public static function render(array $s): void
    {
        global $wpdb;
        $table = Storage::table('autobans');
        echo '<h2>自动封禁 IP</h2><p>当前功能：<strong>' . (!empty($s['enabled']) && !empty($s['autoban_enabled']) && $s['mode'] === 'block' ? '已启用' : '未执行自动封禁') . '</strong>。统计窗口 ' . (int) $s['autoban_window'] . ' 秒，达到 ' . (int) $s['autoban_threshold'] . ' 次规则命中后封禁 ' . (int) $s['autoban_duration'] . ' 秒。</p>';
        echo '<p>只列出未到期的记录。白名单和管理员豁免仍然生效；解封不移除手动 IP 黑名单。到期判断在每次请求时执行，不依赖清理任务及时运行。</p>';
        $raw = isset($_GET['ban_ip']) && is_string($_GET['ban_ip']) ? trim(wp_unslash($_GET['ban_ip'])) : '';
        $where = $wpdb->prepare('blocked_until > %d', time());
        if ($raw !== '') {
            $ip = Ip::canonical($raw);
            $where .= $ip !== '' ? $wpdb->prepare(' AND ip=%s', $ip) : ' AND 1=0';
        }
        echo '<form method="get"><input type="hidden" name="page" value="lumeseed-lumeshield"><input type="hidden" name="tab" value="bans"><label for="ls-ban-ip">IP 地址 </label><input id="ls-ban-ip" name="ban_ip" value="' . esc_attr(mb_strcut($raw, 0, 45, 'UTF-8')) . '" placeholder="精确 IPv4 或 IPv6"> <button class="button">筛选</button></form>';
        $previous = $wpdb->suppress_errors(true);
        try {
            $total = $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE $where");
            if ($wpdb->last_error !== '') { echo '<p>无法读取自动封禁表，请到命中日志页检查数据表。</p>'; return; }
            $pages = max(1, (int) ceil((int) $total / 20));
            $page = max(1, min($pages, absint($_GET['paged'] ?? 1)));
            $rows = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table WHERE $where ORDER BY blocked_until DESC,id DESC LIMIT 20 OFFSET %d", ($page - 1) * 20), ARRAY_A);
            if ($wpdb->last_error !== '') { echo '<p>读取失败，请检查数据库。</p>'; return; }
        } finally { $wpdb->suppress_errors($previous); }
        echo '<table class="widefat striped" style="margin-top:12px"><thead><tr><th>IP</th><th>触发规则</th><th>命中次数</th><th>封禁时间</th><th>到期时间</th><th>操作</th></tr></thead><tbody>';
        foreach ($rows as $row) {
            echo '<tr><td>' . esc_html($row['ip']) . '</td><td>' . esc_html($row['last_rule']) . '</td><td>' . (int) $row['hits'] . '</td><td>' . esc_html(wp_date('Y-m-d H:i:s', (int) $row['blocked_at'])) . '</td><td>' . esc_html(wp_date('Y-m-d H:i:s', (int) $row['blocked_until'])) . '</td><td>';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('lumeseed_lumeshield_action');
            echo '<input type="hidden" name="action" value="lumeseed_lumeshield_action"><input type="hidden" name="operation" value="unban"><input type="hidden" name="ban_id" value="' . (int) $row['id'] . '"><button class="button" type="submit">解封并重置计数</button></form></td></tr>';
        }
        if (!$rows) { echo '<tr><td colspan="6">暂无符合条件的临时封禁。</td></tr>'; }
        echo '</tbody></table><p>共 ' . (int) $total . ' 条未到期记录，第 ' . $page . ' / ' . $pages . ' 页</p>';
        foreach ([$page - 1 => '上一页', $page + 1 => '下一页'] as $target => $label) {
            if ($target < 1 || $target > $pages) { continue; }
            echo '<a class="button" href="' . esc_url(add_query_arg(['page' => 'lumeseed-lumeshield', 'tab' => 'bans', 'ban_ip' => $raw, 'paged' => $target], admin_url('admin.php'))) . '">' . esc_html($label) . '</a> ';
        }
    }
}
