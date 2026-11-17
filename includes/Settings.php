<?php
/** 配置验证：错误名单拒绝整次保存，避免无效规则悄悄扩大放行范围。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Settings
{
    public const OPTION = 'lumeseed_lumeshield_settings';

    public static function defaults(): array
    {
        return [
            'enabled' => 1, 'mode' => 'observe', 'rate_enabled' => 1,
            'login_enabled' => 0, 'login_window' => 900, 'login_limit' => 5,
            'cf_enabled' => 0, 'exceptions' => [],
            'rate_window' => 60, 'rate_limit' => 120, 'body_limit' => 262144,
            'retention_days' => 7, 'max_logs' => 5000, 'delete_on_uninstall' => 0,
            'categories' => ['sqli', 'xss', 'rce', 'traversal', 'probe', 'scanner'],
            'trusted_proxies' => [], 'proxy_header' => 'HTTP_X_FORWARDED_FOR',
            'ip_deny' => [], 'ip_allow' => [], 'path_deny' => [], 'path_allow' => [],
            'ua_deny' => [], 'ua_allow' => [],
            'block_theme' => 'star', 'block_title' => '访问暂时被阻止',
            'block_message' => '本次请求触发了网站安全策略。如果这是正常操作，请联系网站管理员。',
        ];
    }

    public static function get(): array
    {
        $stored = get_option(self::OPTION, []);
        return array_replace(self::defaults(), is_array($stored) ? $stored : []);
    }

    public static function lines($value): array
    {
        if (!is_string($value) && !is_array($value)) {
            throw new \InvalidArgumentException('名单格式无效');
        }
        $lines = is_array($value) ? $value : preg_split('/\r\n|\r|\n/', $value);
        $out = [];
        foreach ($lines as $line) {
            if (!is_string($line) || strlen($line) > 512) {
                throw new \InvalidArgumentException('名单每行最多 512 字节');
            }
            $line = trim($line);
            if ($line !== '' && $line[0] !== '#') {
                $out[] = $line;
            }
        }
        if (count($out) > 200) {
            throw new \InvalidArgumentException('每种名单最多 200 条');
        }
        return array_values(array_unique($out));
    }

    public static function validate(array $input): array
    {
        $out = self::defaults();
        foreach (['enabled', 'rate_enabled', 'delete_on_uninstall', 'login_enabled', 'cf_enabled'] as $key) {
            $out[$key] = isset($input[$key]) && (string) $input[$key] === '1' ? 1 : 0;
        }
        if (!in_array($input['mode'] ?? '', ['observe', 'block'], true)) {
            throw new \InvalidArgumentException('请选择有效的防护模式');
        }
        $out['mode'] = $input['mode'];
        foreach (['rate_window' => [5, 3600], 'rate_limit' => [10, 10000],
            'body_limit' => [16384, 1048576], 'retention_days' => [1, 90], 'max_logs' => [100, 50000],
            'login_window' => [60, 3600], 'login_limit' => [3, 100]] as $key => [$min, $max]) {
            $value = $input[$key] ?? $out[$key];
            if (!is_scalar($value) || !ctype_digit((string) $value) || (int) $value < $min || (int) $value > $max) {
                throw new \InvalidArgumentException($key . ' 必须在 ' . $min . ' 至 ' . $max . ' 之间');
            }
            $out[$key] = (int) $value;
        }
        $categories = $input['categories'] ?? [];
        if (!is_array($categories) || array_diff($categories, self::defaults()['categories'])) {
            throw new \InvalidArgumentException('规则分类无效');
        }
        $out['categories'] = array_values(array_unique($categories));
        foreach (['trusted_proxies', 'ip_deny', 'ip_allow', 'path_deny', 'path_allow', 'ua_deny', 'ua_allow'] as $key) {
            $out[$key] = self::lines($input[$key] ?? '');
            foreach ($out[$key] as $line) {
                if (in_array($key, ['trusted_proxies', 'ip_deny', 'ip_allow'], true) && !Ip::validRule($line)) {
                    throw new \InvalidArgumentException($key . ' 中存在无效的 IP 或 CIDR：' . $line);
                }
                if ($key === 'trusted_proxies' && preg_match('~/0+$~', $line)) {
                    throw new \InvalidArgumentException('可信代理不能使用 /0 全网网段');
                }
                if (str_starts_with($key, 'path_') && ($line[0] !== '/' || preg_match('~[\s?\x00-\x1f]~', $line)
                    || strpos(rtrim($line, '*'), '*') !== false || substr_count($line, '*') > 1)) {
                    throw new \InvalidArgumentException('路径只能使用以 / 开头的精确路径或末尾单个 * 前缀规则');
                }
            }
        }
        $header = $input['proxy_header'] ?? '';
        if (!in_array($header, ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP'], true)) {
            throw new \InvalidArgumentException('代理头选项无效');
        }
        $out['proxy_header'] = $header;
        $out['exceptions'] = self::lines($input['exceptions'] ?? []);
        Exceptions::parse($out['exceptions']);
        $theme = $input['block_theme'] ?? 'star';
        if (!in_array($theme, ['star', 'simple'], true)) {
            throw new \InvalidArgumentException('拦截页主题无效');
        }
        $out['block_theme'] = $theme;
        foreach (['block_title' => 80, 'block_message' => 500] as $key => $max) {
            if (!is_string($input[$key] ?? null)) {
                throw new \InvalidArgumentException('拦截页文案格式无效');
            }
            $out[$key] = sanitize_textarea_field($input[$key]);
            if (strlen($out[$key]) > $max * 4 || $out[$key] === '') {
                throw new \InvalidArgumentException('拦截页文案为空或过长');
            }
        }
        return $out;
    }

    public static function proxies(array $settings): array
    {
        $managed = !empty($settings['cf_enabled']) ? get_option('lumeseed_lumeshield_cf', []) : [];
        return array_values(array_unique(array_merge($settings['trusted_proxies'], is_array($managed) ? ($managed['ranges'] ?? []) : [])));
    }

    public static function sanitize($input): array
    {
        try {
            if (!is_array($input)) {
                throw new \InvalidArgumentException('设置格式无效');
            }
            return self::validate($input);
        } catch (\Throwable $e) {
            add_settings_error(self::OPTION, 'invalid', '未保存：' . $e->getMessage());
            return self::get();
        }
    }
}
