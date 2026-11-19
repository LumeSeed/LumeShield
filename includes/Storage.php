<?php
/** 数据库存储与原子限流；运行数据不落在可公开下载的插件目录。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Storage
{
    public static function table(string $suffix): string
    {
        global $wpdb;
        return $wpdb->prefix . 'lumeseed_lumeshield_' . $suffix;
    }

    public static function install(): bool
    {
        global $wpdb;
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $logs = self::table('logs');
        $rates = self::table('rates');
        $autobans = self::table('autobans');
        dbDelta("CREATE TABLE $logs (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            fingerprint char(64) NOT NULL,
            created_at bigint unsigned NOT NULL,
            last_seen bigint unsigned NOT NULL,
            ip varchar(45) NOT NULL,
            method varchar(12) NOT NULL,
            path varchar(400) NOT NULL,
            rule_id varchar(64) NOT NULL,
            category varchar(24) NOT NULL,
            field_name varchar(80) NOT NULL,
            action_name varchar(16) NOT NULL,
            hits bigint unsigned NOT NULL DEFAULT 1,
            log_mode varchar(16) NOT NULL DEFAULT 'redacted',
            request_uri text NULL,
            user_agent text NULL,
            payload text NULL,
            detail_truncated tinyint unsigned NOT NULL DEFAULT 0,
            exception_path varchar(400) NOT NULL DEFAULT '',
            PRIMARY KEY  (id),
            UNIQUE KEY fingerprint (fingerprint),
            KEY last_seen (last_seen),
            KEY created_at (created_at),
            KEY category (category)
        ) $charset;");
        dbDelta("CREATE TABLE $rates (
            bucket char(64) NOT NULL,
            hits int unsigned NOT NULL DEFAULT 1,
            expires_at bigint unsigned NOT NULL,
            PRIMARY KEY  (bucket),
            KEY expires_at (expires_at)
        ) $charset;");
        dbDelta("CREATE TABLE $autobans (
            id bigint unsigned NOT NULL AUTO_INCREMENT,
            ip varchar(45) NOT NULL,
            window_start bigint unsigned NOT NULL,
            window_seconds int unsigned NOT NULL,
            hits int unsigned NOT NULL DEFAULT 1,
            blocked_at bigint unsigned NOT NULL DEFAULT 0,
            blocked_until bigint unsigned NOT NULL DEFAULT 0,
            last_rule varchar(64) NOT NULL,
            expires_at bigint unsigned NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY ip (ip),
            KEY blocked_until (blocked_until),
            KEY expires_at (expires_at)
        ) $charset;");
        foreach ([$logs, $rates, $autobans] as $table) {
            if ($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($table))) !== $table) {
                return false;
            }
        }
        // 表存在不等于升级成功；确认新增列可读取后才记录版本。
        if ($wpdb->query("SELECT log_mode,request_uri,user_agent,payload,detail_truncated,exception_path FROM $logs LIMIT 0") === false) {
            return false;
        }
        if ($wpdb->query("SELECT id,ip,window_start,window_seconds,hits,blocked_at,blocked_until,last_rule,expires_at FROM $autobans LIMIT 0") === false) { return false; }
        update_option('lumeseed_lumeshield_db_version', VERSION, false);
        return true;
    }

    public static function error(string $component): void
    {
        // 仅保存组件名与时间，不向访客暴露数据库连接、SQL 或请求内容。
        $old = get_option('lumeseed_lumeshield_error', []);
        if (empty($old['time']) || (int) $old['time'] < time() - 60) {
            update_option('lumeseed_lumeshield_error', ['component' => $component, 'time' => time()], false);
        }
    }

    public static function increment(string $key, int $window, int $now = 0): ?int
    {
        global $wpdb;
        $now = $now ?: time();
        $slot = intdiv($now, $window);
        $bucket = hash_hmac('sha256', $key . ':' . $slot, wp_salt('auth'));
        $table = self::table('rates');
        $old = $wpdb->suppress_errors(true);
        try {
            // 同一主键的累加由数据库单条语句完成，不使用非原子的先读后写。
            $ok = $wpdb->query($wpdb->prepare(
                "INSERT INTO $table (bucket,hits,expires_at) VALUES (%s,1,%d)
                 ON DUPLICATE KEY UPDATE hits=LEAST(hits+1,1000000)",
                $bucket, ($slot + 1) * $window + 60
            ));
            if ($ok === false) {
                self::error('请求计数');
                return null;
            }
            $count = $wpdb->get_var($wpdb->prepare("SELECT hits FROM $table WHERE bucket=%s", $bucket));
            if ($count === null) {
                self::error('读取计数');
                return null;
            }
            return (int) $count;
        } finally {
            $wpdb->suppress_errors($old);
        }
    }

    public static function counter(string $key, int $window): ?int
    {
        global $wpdb;
        $bucket = hash_hmac('sha256', $key . ':' . intdiv(time(), $window), wp_salt('auth'));
        $table = self::table('rates');
        $old = $wpdb->suppress_errors(true);
        try {
            $value = $wpdb->get_var($wpdb->prepare("SELECT hits FROM $table WHERE bucket=%s", $bucket));
            if ($wpdb->last_error !== '') { self::error('登录计数读取'); return null; }
            return $value === null ? 0 : (int) $value;
        } finally { $wpdb->suppress_errors($old); }
    }

    public static function safePath(string $path): string
    {
        $path = Engine::path($path);
        $path = preg_replace('~[\x00-\x1f\x7f]~', '', $path);
        $path = preg_replace('~(?<=/)[a-zA-Z0-9_%=-]{24,}(?=/|$)~', '[已隐藏]', $path);
        return mb_strcut($path, 0, 390, 'UTF-8');
    }

    public static function record(array $hit, string $ip, string $method, string $path, string $action): void
    {
        global $wpdb;
        // 每分钟最多处理 120 次日志写入，防止攻击流量持续放大数据库写负担。
        $budget = self::increment('日志写入预算', 60);
        if ($budget === null || $budget > 120) {
            return;
        }
        $table = self::table('logs');
        $s = Settings::get();
        $detail = self::details($hit, $_SERVER, $s);
        $rawPath = Engine::path($path);
        $path = self::safePath($path);
        $now = time();
        $field = self::fieldName((string) $hit['field']);
        $window = max(5, min(3600, (int) $s['log_window']));
        $fingerprint = hash_hmac('sha256', (string) json_encode([$ip, $method, $hit['id'], $path, $field, $action, $s['log_mode'], $window, intdiv($now, $window)]), wp_salt('auth'));
        // 仅保留未脱敏、未截断且符合精细例外语法的路径供管理员预填。
        $exceptionPath = $rawPath === $path && preg_match('~^/[A-Za-z0-9/_\-.]*$~D', $path) ? $path : '';
        $old = $wpdb->suppress_errors(true);
        try {
            $ok = $wpdb->query($wpdb->prepare(
                "INSERT INTO $table (fingerprint,created_at,last_seen,ip,method,path,rule_id,category,field_name,action_name,hits,log_mode,request_uri,user_agent,payload,detail_truncated,exception_path)
                 VALUES (%s,%d,%d,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s,%d,%s)
                 ON DUPLICATE KEY UPDATE hits=LEAST(hits+1,1000000),last_seen=VALUES(last_seen)",
                $fingerprint, $now, $now, $ip, substr($method, 0, 12), $path,
                $hit['id'], $hit['category'], $field, $action, $s['log_mode'],
                $detail['uri'], $detail['ua'], $detail['payload'], $detail['truncated'] ? 1 : 0, $exceptionPath
            ));
            if ($ok === false) {
                self::error('日志写入');
            }
            // 对新记录立即限制总条数；重复记录只累加次数。
            if ($ok === 1) {
                self::pruneLogs(Settings::get());
            }
        } finally {
            $wpdb->suppress_errors($old);
        }
    }

    public static function fieldName(string $field): string
    {
        // 只保留可用于精细例外的普通顶层字段名；动态键、嵌套键沿用来源标签。
        if (preg_match('~^(GET|POST|JSON|COOKIE)\[[A-Za-z_][A-Za-z0-9_-]{0,63}\]$~D', $field)) {
            return $field;
        }
        return mb_strcut(preg_replace('~[^a-zA-Z0-9_.\x{4e00}-\x{9fff}-]~u', '', explode('[', $field, 2)[0]) ?? '', 0, 75, 'UTF-8');
    }

    public static function details(array $hit, array $server, array $settings): array
    {
        $out = ['uri' => '', 'ua' => '', 'payload' => '', 'truncated' => false];
        if (($settings['log_mode'] ?? 'redacted') !== 'detailed') { return $out; }
        $values = ['uri' => (string) ($server['REQUEST_URI'] ?? ''),
            'ua' => (string) ($server['HTTP_USER_AGENT'] ?? ''), 'payload' => (string) ($hit['payload'] ?? $hit['name'] ?? '')];
        $out['truncated'] = !empty($hit['payload_truncated']);
        foreach (['uri' => 4096, 'ua' => 2048, 'payload' => 4096] as $key => $limit) {
            $out['truncated'] = $out['truncated'] || strlen($values[$key]) > $limit;
            // 无效编码先替换，防止恶意字节令数据库写入失败；展示端仍必须转义。
            $text = mb_convert_encoding($values[$key], 'UTF-8', 'UTF-8');
            $out[$key] = mb_strcut($text, 0, $limit, 'UTF-8');
        }
        return $out;
    }

    private static function pruneLogs(array $settings): void
    {
        global $wpdb;
        $table = self::table('logs');
        $max = max(100, min(50000, (int) $settings['max_logs']));
        $cut = $wpdb->get_var($wpdb->prepare("SELECT id FROM $table ORDER BY id DESC LIMIT 1 OFFSET %d", $max - 1));
        if ($cut !== null) {
            $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE id < %d", (int) $cut));
        }
    }

    public static function cleanup(): void
    {
        global $wpdb;
        $s = Settings::get();
        $rates = self::table('rates');
        $logs = self::table('logs');
        $old = $wpdb->suppress_errors(true);
        try {
            $wpdb->query($wpdb->prepare("DELETE FROM $rates WHERE expires_at < %d", time()));
            $wpdb->query($wpdb->prepare("DELETE FROM $logs WHERE last_seen < %d", time() - (int) $s['retention_days'] * DAY_IN_SECONDS));
            $autobans = self::table('autobans');
            $wpdb->query($wpdb->prepare("DELETE FROM $autobans WHERE expires_at <= %d", time()));
            self::pruneLogs($s);
        } finally {
            $wpdb->suppress_errors($old);
        }
    }
}
