<?php
/** 频繁规则命中的临时封禁；计数独立于日志采样与聚合。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class AutoBan
{
    public static function eligible(string $ip, array $s): bool
    {
        return !empty($s['enabled']) && !empty($s['autoban_enabled']) && $s['mode'] === 'block'
            && Ip::canonical($ip) !== '' && !current_user_can('manage_options')
            && !Ip::listed($ip, $s['ip_allow']) && !Ip::listed($ip, Settings::proxies($s));
    }

    public static function active(string $ip, array $s, int $now = 0): ?array
    {
        if (!self::eligible($ip, $s)) { return null; }
        global $wpdb;
        $table = Storage::table('autobans');
        $previous = $wpdb->suppress_errors(true);
        try {
            $row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE ip=%s AND blocked_until>%d", Ip::canonical($ip), $now ?: time()), ARRAY_A);
            if ($wpdb->last_error !== '') { Storage::error('自动封禁读取'); return null; }
            return $row ?: null;
        } catch (\Throwable $e) {
            Storage::error('自动封禁读取');
            return null;
        } finally { $wpdb->suppress_errors($previous); }
    }

    public static function record(array $hit, string $ip, array $s, int $now = 0): void
    {
        if (!self::eligible($ip, $s) || !in_array($hit['category'] ?? '', ['sqli', 'xss', 'rce', 'traversal', 'probe', 'scanner'], true)) { return; }
        global $wpdb;
        $now = $now ?: time();
        $window = (int) $s['autoban_window'];
        $slot = intdiv($now, $window) * $window;
        $table = Storage::table('autobans');
        $previous = $wpdb->suppress_errors(true);
        try {
            // 同一 IP 的计数和封禁决定在同一条 SQL 内原子完成。
            // MySQL 单表更新按赋值顺序执行：先更新 hits，再据其值判断阈值。
            // 封禁中保留原计数与期限；封禁过期后从 1 开始，不复用旧窗口计数。
            $ok = $wpdb->query($wpdb->prepare(
                "INSERT INTO $table (ip,window_start,window_seconds,hits,blocked_at,blocked_until,last_rule,expires_at)
                 VALUES (%s,%d,%d,1,0,0,%s,%d)
                 ON DUPLICATE KEY UPDATE
                 hits=IF(blocked_until>%d,hits,IF(blocked_until=0 AND window_start=VALUES(window_start) AND window_seconds=VALUES(window_seconds),LEAST(hits+1,1000000),1)),
                 window_start=IF(blocked_until>%d,window_start,VALUES(window_start)),
                 window_seconds=IF(blocked_until>%d,window_seconds,VALUES(window_seconds)),
                 last_rule=IF(blocked_until>%d,last_rule,VALUES(last_rule)),
                 blocked_at=IF(blocked_until>%d,blocked_at,IF(hits>=%d,%d,0)),
                 blocked_until=IF(blocked_until>%d,blocked_until,IF(hits>=%d,%d,0)),
                 expires_at=GREATEST(window_start+window_seconds,blocked_until)",
                Ip::canonical($ip), $slot, $window, substr((string) $hit['id'], 0, 64), $slot + $window,
                $now, $now, $now, $now, $now, (int) $s['autoban_threshold'], $now,
                $now, (int) $s['autoban_threshold'], $now + (int) $s['autoban_duration']
            ));
            if ($ok === false) { Storage::error('自动封禁写入'); }
        } catch (\Throwable $e) { Storage::error('自动封禁写入'); }
        finally { $wpdb->suppress_errors($previous); }
    }

    public static function release(int $id): bool
    {
        global $wpdb;
        // 同时移除当前计数，后续新命中从头累计；手动 IP 黑名单不受影响。
        return $id > 0 && $wpdb->delete(Storage::table('autobans'), ['id' => $id], ['%d']) !== false;
    }
}
