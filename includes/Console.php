<?php
/** 概览、日志详情与精细例外编辑；继续沿用 WordPress 原生管理界面。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class Console
{
    private static ?array $preview = null;

    private static function url(array $args): string
    {
        return add_query_arg(['page' => 'lumeseed-lumeshield'] + $args, admin_url('admin.php'));
    }

    public static function filters(): array
    {
        $out = ['outcome' => '', 'verb' => '', 'from' => '', 'until' => ''];
        foreach ($out as $key => $_) {
            $value = isset($_GET[$key]) && is_string($_GET[$key]) ? wp_unslash($_GET[$key]) : '';
            if ($key === 'outcome' && in_array($value, ['block', 'observe'], true)) { $out[$key] = $value; }
            elseif ($key === 'verb' && in_array($value, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], true)) { $out[$key] = $value; }
            elseif (in_array($key, ['from', 'until'], true)) {
                $date = \DateTimeImmutable::createFromFormat('!Y-m-d', $value, wp_timezone());
                if ($date && $date->format('Y-m-d') === $value) { $out[$key] = $value; }
            }
        }
        return $out;
    }

    public static function where(array $filters): string
    {
        global $wpdb;
        $where = '1=1';
        if ($filters['outcome'] !== '') { $where .= $wpdb->prepare(' AND action_name=%s', $filters['outcome']); }
        if ($filters['verb'] !== '') { $where .= $wpdb->prepare(' AND method=%s', $filters['verb']); }
        foreach (['from', 'until'] as $key) {
            if ($filters[$key] === '') { continue; }
            $date = new \DateTimeImmutable($filters[$key], wp_timezone());
            $where .= $key === 'from' ? $wpdb->prepare(' AND last_seen >= %d', $date->getTimestamp())
                : $wpdb->prepare(' AND last_seen < %d', $date->modify('+1 day')->getTimestamp());
        }
        return $where;
    }

    public static function filterFields(array $f): void
    {
        foreach (['outcome' => ['处理方式', ['block' => '已拦截', 'observe' => '仅观察']],
            'verb' => ['方法', array_combine(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'])]] as $key => [$label, $values]) {
            echo '<label>' . esc_html($label) . ' <select name="' . esc_attr($key) . '"><option value="">全部</option>';
            foreach ($values as $value => $text) { echo '<option value="' . esc_attr($value) . '" ' . selected($f[$key], $value, false) . '>' . esc_html($text) . '</option>'; }
            echo '</select></label> ';
        }
        foreach (['from' => '开始日期', 'until' => '结束日期'] as $key => $label) {
            echo '<label>' . esc_html($label) . ' <input type="date" name="' . esc_attr($key) . '" value="' . esc_attr($f[$key]) . '"></label> ';
        }
    }

    public static function logDetails(array $row): void
    {
        $names = array_column(Engine::rules(), 2, 0);
        $names['scanner_ua'] = '扫描工具标识';
        $names['auto_ban'] = '频繁命中自动封禁';
        echo '<details style="margin:0 2px"><summary style="padding:8px 0;cursor:pointer">查看详情</summary><dl style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px 24px;padding:12px 0">';
        $fields = ['规则说明' => $names[$row['rule_id']] ?? (Admin::labels()[$row['category']] ?? $row['rule_id']),
            '命中字段' => $row['field_name'], '首次命中' => wp_date('Y-m-d H:i:s', (int) $row['created_at']),
            '最后命中' => wp_date('Y-m-d H:i:s', (int) $row['last_seen']), '记录次数' => (string) $row['hits'],
            '日志模式' => ($row['log_mode'] ?? 'redacted') === 'detailed' ? '详细记录（保留首次内容）' : '脱敏聚合'];
        if (($row['log_mode'] ?? '') === 'detailed') {
            $fields += ['URI' => $row['request_uri'] ?? '', 'User-Agent' => $row['user_agent'] ?? '', '命中内容（检测文本片段）' => $row['payload'] ?? ''];
        }
        foreach ($fields as $label => $value) {
            echo '<div' . (str_starts_with($label, '命中内容') ? ' style="grid-column:1/-1"' : '') . '><dt><strong>' . esc_html($label) . '</strong></dt><dd style="margin:4px 0 12px;white-space:pre-wrap;overflow-wrap:anywhere;max-height:240px;overflow:auto">' . esc_html((string) $value) . '</dd></div>';
        }
        echo '</dl>';
        if (!empty($row['detail_truncated'])) { echo '<p>部分内容超过保存上限，展示的是截取片段。</p>'; }
        if (Exceptions::fromLog($row) !== null) {
            echo '<a class="button" href="' . esc_url(self::url(['tab' => 'logs', 'exception_id' => (int) $row['id']])) . '">创建精细例外</a>';
        } else { echo '<p>此记录无法精确预填例外；可在防护策略中手动配置并试测。</p>'; }
        echo '</details>';
    }

    private static function exceptionRow(): ?array
    {
        global $wpdb;
        if (!current_user_can('manage_options')) { return null; }
        $id = absint($_GET['exception_id'] ?? 0);
        if (!$id) { return null; }
        return $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . Storage::table('logs') . ' WHERE id=%d', $id), ARRAY_A) ?: null;
    }

    public static function prepareException(): void
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_POST['ls_exception_preview'])) { return; }
        if (!current_user_can('manage_options')) { wp_die('没有操作权限。', '', ['response' => 403]); }
        check_admin_referer('lumeshield_exception_preview');
        try {
            $row = self::exceptionRow();
            $line = $row ? Exceptions::fromLog($row) : null;
            if ($line === null) { throw new \InvalidArgumentException('记录不存在或无法精确生成例外。'); }
            $parsed = Exceptions::parse([$line])[0];
            $sample = wp_unslash($_POST['exception_sample'] ?? '');
            if (!is_string($sample) || strlen($sample) > 16384) { throw new \InvalidArgumentException('试测文本最多 16 KiB。'); }
            if ($parsed['field'] === '*') {
                $items = []; $ua = $parsed['rule'] === 'scanner_ua' ? $sample : '';
            } else {
                preg_match('~^(GET|POST|JSON|COOKIE)\[([^\]]+)\]$~', $parsed['field'], $parts);
                $s = Settings::get();
                $input = ['method' => $parsed['method'], 'path' => $parsed['path'], 'source' => $parts[1], 'field' => $parts[2],
                    'value' => $sample, 'ip' => $row['ip'], 'ua' => 'LumeShield-Simulator'];
                $before = Simulator::evaluate($input, $s);
                $s['exceptions'] = array_values(array_unique(array_merge($s['exceptions'], [$line])));
                $after = Simulator::evaluate($input, $s);
                self::$preview = ['message' => '当前策略：' . $before['decision'] . '；加入例外后：' . $after['decision'] . '。其他规则仍然生效。'];
                return;
            }
            $s = Settings::get();
            $before = Engine::inspect($items, $s['categories'], $parsed['path'], $ua, false, Exceptions::parse($s['exceptions']), $parsed['method'], $s['disabled_rules']);
            $after = Engine::inspect($items, $s['categories'], $parsed['path'], $ua, false, Exceptions::parse(array_unique(array_merge($s['exceptions'], [$line]))), $parsed['method'], $s['disabled_rules']);
            self::$preview = ['message' => '规则试测：当前 ' . ($before ? $before['id'] : '未命中') . '；加入例外后 ' . ($after ? $after['id'] : '未命中') . '。本试测不模拟名单、限流或登录保护。'];
        } catch (\Throwable $e) { self::$preview = ['message' => '试测失败：' . $e->getMessage()]; }
    }

    public static function exceptionEditor(): void
    {
        if (empty($_GET['exception_id'])) { return; }
        $row = self::exceptionRow();
        $line = $row ? Exceptions::fromLog($row) : null;
        if ($line === null) { echo '<p>记录不存在或无法精确生成例外。旧日志不会推断成范围更大的白名单。</p>'; return; }
        echo '<div class="postbox" style="padding:20px"><h2>从日志创建精细例外</h2><p><code>' . esc_html($line) . '</code></p><p>仅豁免上述方法、路径、字段和规则，不跳过其他规则、黑名单或限流。字段 * 表示该路径下整条指定规则豁免。</p>';
        if (self::$preview) { echo '<p role="status">' . esc_html(self::$preview['message']) . '</p>'; }
        echo '<form method="post" action="' . esc_url(self::url(['tab' => 'logs', 'exception_id' => (int) $row['id']])) . '">';
        wp_nonce_field('lumeshield_exception_preview');
        echo '<input type="hidden" name="ls_exception_preview" value="1"><label for="ls-exception-sample">试测字段内容（UA 规则填 UA；敏感路径规则使用记录中的路径）</label><textarea id="ls-exception-sample" name="exception_sample" class="large-text code" rows="3" maxlength="16384"></textarea><p><button class="button">试测例外，不保存</button></p></form>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('lumeseed_lumeshield_action');
        echo '<input type="hidden" name="action" value="lumeseed_lumeshield_action"><input type="hidden" name="operation" value="exception"><input type="hidden" name="log_id" value="' . (int) $row['id'] . '"><label><input type="checkbox" required name="confirm_exception" value="yes">确认添加以上精确例外</label> <button class="button button-primary">保存例外</button></form></div>';
    }

    public static function overview(): void
    {
        global $wpdb;
        $table = Storage::table('logs');
        $today = new \DateTimeImmutable('today', wp_timezone());
        $start = $today->modify('-6 days')->getTimestamp();
        $totals = $wpdb->get_row($wpdb->prepare("SELECT COUNT(*) AS records, COALESCE(SUM(hits),0) AS hits,
            COALESCE(SUM(CASE WHEN action_name='block' THEN hits ELSE 0 END),0) AS blocked,
            COALESCE(SUM(CASE WHEN action_name='observe' THEN hits ELSE 0 END),0) AS observed
            FROM $table WHERE created_at >= %d AND created_at < %d", $today->getTimestamp(), $today->modify('+1 day')->getTimestamp()), ARRAY_A);
        if ($wpdb->last_error !== '') { echo '<p>暂时无法读取统计，请在命中日志页检查数据表。</p>'; return; }
        echo '<h2>今日防护记录</h2><p>按站点时区和记录首次命中日期统计。窗口内次数累计归到首次日期；存在写入预算、聚合、清理和停用期间的数据缺口，不代表完整流量或安全评分。</p><div style="display:flex;flex-wrap:wrap;gap:16px">';
        foreach (['hits' => '记录命中次数', 'blocked' => '已拦截次数', 'observed' => '仅观察次数', 'records' => '日志记录条数'] as $key => $label) {
            echo '<div class="postbox" style="padding:16px 24px;min-width:160px;flex:1"><div>' . esc_html($label) . '</div><strong style="font-size:28px">' . (int) ($totals[$key] ?? 0) . '</strong></div>';
        }
        echo '</div><h2>近 7 天记录命中</h2><table class="widefat striped"><thead><tr><th>日期</th><th>已拦截</th><th>仅观察</th><th>合计</th><th>趋势</th></tr></thead><tbody>';
        $days = []; $maximum = 1;
        for ($i = 6; $i >= 0; $i--) {
            $day = $today->modify('-' . $i . ' days');
            $row = $wpdb->get_row($wpdb->prepare("SELECT COALESCE(SUM(hits),0) AS hits,
                COALESCE(SUM(CASE WHEN action_name='block' THEN hits ELSE 0 END),0) AS blocked,
                COALESCE(SUM(CASE WHEN action_name='observe' THEN hits ELSE 0 END),0) AS observed
                FROM $table WHERE created_at >= %d AND created_at < %d", $day->getTimestamp(), $day->modify('+1 day')->getTimestamp()), ARRAY_A);
            $row = array_merge(['hits' => 0, 'blocked' => 0, 'observed' => 0], $row ?: []);
            $days[] = [$day->format('m-d'), $row]; $maximum = max($maximum, (int) $row['hits']);
        }
        foreach ($days as [$date, $row]) {
            echo '<tr><th scope="row">' . esc_html($date) . '</th><td>' . (int) $row['blocked'] . '</td><td>' . (int) $row['observed'] . '</td><td>' . (int) $row['hits'] . '</td><td><meter aria-label="' . esc_attr($date . ' 记录命中次数') . '" min="0" max="' . $maximum . '" value="' . (int) $row['hits'] . '">' . (int) $row['hits'] . '</meter></td></tr>';
        }
        echo '</tbody></table><div style="display:flex;flex-wrap:wrap;gap:20px">';
        foreach (['category' => '攻击分类', 'ip' => '来源 IP', 'path' => '请求路径'] as $column => $label) {
            $rows = $wpdb->get_results($wpdb->prepare("SELECT $column AS label,SUM(hits) AS hits FROM $table WHERE created_at >= %d GROUP BY $column ORDER BY hits DESC LIMIT 10", $start), ARRAY_A);
            echo '<section style="flex:1;min-width:240px"><h2>近 7 天 · ' . esc_html($label) . '</h2><table class="widefat striped"><thead><tr><th>' . esc_html($label) . '</th><th>记录次数</th></tr></thead><tbody>';
            foreach ($rows ?: [] as $row) {
                $name = $column === 'category' ? (Admin::labels()[$row['label']] ?? $row['label']) : $row['label'];
                echo '<tr><td style="overflow-wrap:anywhere">' . esc_html($name) . '</td><td>' . (int) $row['hits'] . '</td></tr>';
            }
            if (!$rows) { echo '<tr><td colspan="2">暂无记录</td></tr>'; }
            echo '</tbody></table></section>';
        }
        echo '</div>';
    }
}
