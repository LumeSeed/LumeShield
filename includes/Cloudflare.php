<?php
/** 仅从固定官方地址获取网段；两份均校验成功才整体替换托管列表。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class Cloudflare
{
    public static function validateList(string $text, bool $ipv6): array
    {
        if (strlen($text) >= 16384 || trim($text) === '') { throw new \RuntimeException('官方列表为空或超长'); }
        $lines = preg_split('/\r\n|\r|\n/', trim($text));
        if (count($lines) < ($ipv6 ? 2 : 5) || count($lines) > 100) { throw new \RuntimeException('官方列表条数异常'); }
        foreach ($lines as $line) {
            $line = trim($line);
            $parts = explode('/', $line);
            if (count($parts) !== 2 || !Ip::validRule($line) || (str_contains($parts[0], ':') !== $ipv6)
                || (int) $parts[1] < ($ipv6 ? 16 : 8)) {
                throw new \RuntimeException('官方列表含无效网段，已保留原配置');
            }
        }
        return array_values(array_unique(array_map('trim', $lines)));
    }

    public static function sync(): int
    {
        $ranges = [];
        foreach (['https://www.cloudflare.com/ips-v4' => false, 'https://www.cloudflare.com/ips-v6' => true] as $url => $ipv6) {
            $response = wp_safe_remote_get($url, ['timeout' => 10, 'redirection' => 0, 'sslverify' => true,
                'limit_response_size' => 16384, 'headers' => ['Accept' => 'text/plain'], 'user-agent' => 'LumeShield/' . VERSION]);
            if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
                throw new \RuntimeException('连接 Cloudflare 官方列表失败；原网段未改变');
            }
            $ranges = array_merge($ranges, self::validateList(wp_remote_retrieve_body($response), $ipv6));
        }
        $old = get_option('lumeseed_lumeshield_cf', []);
        if (count($ranges) < count($old['ranges'] ?? []) / 2) { throw new \RuntimeException('网段数量大幅减少，请人工核对；已保留原网段'); }
        // 不改动手动代理、代理头、工作模式或启用状态，避免同步隐含扩大信任。
        $new = ['ranges' => $ranges, 'updated' => time()];
        if (!update_option('lumeseed_lumeshield_cf', $new, false) && get_option('lumeseed_lumeshield_cf') !== $new) {
            throw new \RuntimeException('网段保存失败，请检查数据库');
        }
        return count($ranges);
    }
}
