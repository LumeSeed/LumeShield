<?php
/** 登录失败按来源 IP 单独计数，不保存账号或密码，也不永久锁定账户。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class LoginGuard
{
    private static function context(): ?array
    {
        $s = Settings::get();
        if (empty($s['enabled']) || empty($s['login_enabled']) || is_multisite() || wp_doing_cron()
            || (defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE)) { return null; }
        $ip = Ip::resolve($_SERVER, Settings::proxies($s), $s['proxy_header']);
        return $ip === '' ? null : [$s, $ip];
    }

    public static function authenticate($user, $username, $password)
    {
        if (!is_string($username) || !is_string($password) || $username === '' || $password === '') { return $user; }
        try {
            $context = self::context();
            if (!$context) { return $user; }
            [$s, $ip] = $context;
            $count = Storage::counter('登录失败:' . $ip, (int) $s['login_window']);
            if ($count === null || $count < $s['login_limit']) { return $user; }
            try {
                Storage::record(Engine::hit('login_fail_limit', 'login', '认证', '登录失败次数超限'), $ip,
                    (string) ($_SERVER['REQUEST_METHOD'] ?? 'POST'), Engine::path($_SERVER['REQUEST_URI'] ?? '/wp-login.php'), $s['mode']);
            } catch (\Throwable $e) { Storage::error('登录日志'); }
            if ($s['mode'] === 'observe') { return $user; }
            // 放在 WordPress 认证过滤器末尾，阻止已有认证结果被使用；不承诺阻止密码计算本身。
            return new \WP_Error('lumeshield_login_limited', '此来源的登录失败次数过多，请稍后重试。');
        } catch (\Throwable $e) { Storage::error('登录防护'); return $user; }
    }

    public static function failed($username, $error): void
    {
        try {
            if (is_wp_error($error) && $error->get_error_code() === 'lumeshield_login_limited') { return; }
            $context = self::context();
            if (!$context) { return; }
            [$s, $ip] = $context;
            Storage::increment('登录失败:' . $ip, (int) $s['login_window']);
        } catch (\Throwable $e) { Storage::error('登录失败计数'); }
    }
}
