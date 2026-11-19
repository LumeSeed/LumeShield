<?php
/** 后台试测只在内存中运行检测，不请求目标地址、不写日志、不推进限流计数。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class Simulator
{
    public static function evaluate(array $input, array $s): array
    {
        foreach (['method', 'path', 'source', 'field', 'value', 'ip', 'ua'] as $key) {
            if (!isset($input[$key]) || !is_string($input[$key])) { throw new \InvalidArgumentException('试测字段格式无效'); }
        }
        if (!in_array($input['method'], ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'], true)
            || !in_array($input['source'], ['GET', 'POST', 'JSON', 'COOKIE'], true)
            || !preg_match('~^[A-Za-z_][A-Za-z0-9_-]{0,63}$~D', $input['field'])
            || !preg_match('~^/[^\s?#\x00-\x1f]*$~D', $input['path']) || strlen($input['path']) > 512
            || strlen($input['value']) > 16384 || strlen($input['ua']) > 1024 || Ip::canonical($input['ip']) === '') {
            throw new \InvalidArgumentException('请填写有效方法、路径、顶层字段与 IP；测试内容最多 16 KiB');
        }
        $path = $input['path']; $ip = Ip::canonical($input['ip']); $ua = $input['ua']; $hit = null;
        if (Ip::listed($ip, $s['ip_deny'])) { $hit = Engine::hit('deny_ip', 'blacklist', 'IP', 'IP 黑名单'); }
        elseif (Engine::pathListed($path, $s['path_deny'])) { $hit = Engine::hit('deny_path', 'blacklist', '路径', '路径黑名单'); }
        elseif (Engine::uaListed($ua, $s['ua_deny'])) { $hit = Engine::hit('deny_ua', 'blacklist', 'User-Agent', 'UA 黑名单'); }
        elseif (Ip::listed($ip, $s['ip_allow']) || Engine::pathListed($path, $s['path_allow'])) {
            return ['decision' => '白名单放行', 'hit' => null, 'exception' => false];
        }
        $exception = false;
        if (!$hit) {
            $get = $post = $cookies = []; $body = null; $type = ''; $uri = $path;
            $data = [$input['field'] => $input['value']];
            if ($input['source'] === 'GET') { $get = $data; $uri .= '?' . http_build_query($data, '', '&', PHP_QUERY_RFC3986); }
            elseif ($input['source'] === 'POST') { $post = $data; $body = http_build_query($data, '', '&', PHP_QUERY_RFC3986); $type = 'application/x-www-form-urlencoded'; }
            elseif ($input['source'] === 'COOKIE') { $cookies = $data; }
            else { $body = json_encode($data, JSON_THROW_ON_ERROR); $type = 'application/json'; }
            $items = (new Inputs((int) $s['body_limit']))->collect($get, $post, $cookies, $uri, $body, $type);
            $uaExempt = Engine::uaListed($ua, $s['ua_allow']);
            $hit = Engine::inspect($items, $s['categories'], $path, $ua, $uaExempt, Exceptions::parse($s['exceptions']), $input['method'], $s['disabled_rules']);
            $exception = !$hit && (bool) Engine::inspect($items, $s['categories'], $path, $ua, $uaExempt, [], $input['method'], $s['disabled_rules']);
        }
        $disabled = empty($s['enabled']) || (defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE);
        return ['decision' => $disabled ? '防护已关闭；以下仅为规则分析' : ($hit ? ($s['mode'] === 'block' ? '会拦截' : '只观察') : '未发现命中'),
            'hit' => $hit, 'exception' => $exception];
    }

    public static function handle(): ?array
    {
        if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || !isset($_POST['ls_simulate'])) { return null; }
        if (!current_user_can('manage_options')) { wp_die('没有操作权限。', '', ['response' => 403]); }
        check_admin_referer('lumeshield_simulate');
        try {
            $input = wp_unslash($_POST['sample'] ?? []);
            if (!is_array($input)) { throw new \InvalidArgumentException('试测内容格式无效'); }
            return self::evaluate($input, Settings::get());
        } catch (\Throwable $e) { return ['error' => '试测失败：' . $e->getMessage()]; }
    }

    public static function render(?array $result): void
    {
        echo '<h2>Cloudflare 托管网段</h2><p>仅连接 Cloudflare 官方 HTTPS 地址获取 IPv4、IPv6 网段；不上传访客日志。同步成功后，在防护策略中勾选“使用 Cloudflare 托管网段”，并选择 CF-Connecting-IP。手动代理名单保留独立管理。</p>';
        $managed = get_option('lumeseed_lumeshield_cf', []);
        echo '<p>已保存 ' . count($managed['ranges'] ?? []) . ' 条网段。最后成功同步：' . esc_html(empty($managed['updated']) ? '尚未同步' : wp_date('Y-m-d H:i:s', (int) $managed['updated'])) . '</p>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('lumeseed_lumeshield_action');
        echo '<input type="hidden" name="action" value="lumeseed_lumeshield_action"><input type="hidden" name="operation" value="cf_sync"><button type="submit" class="button">从官方更新网段</button></form>';
        if (!empty($managed['ranges'])) {
            echo '<details><summary>查看已保存的托管网段</summary><pre>' . esc_html(implode("\n", $managed['ranges'])) . '</pre></details>';
        }
        echo '<hr><h2>策略试测</h2><p>使用当前已保存的名单、规则与精细例外。不会访问填写的路径，不保存测试内容，不写命中日志。试测不模拟自动封禁、登录失败次数、实时限流、代理链或管理员豁免，也不证明内容本身安全。</p>';
        if ($result !== null) {
            echo '<div class="notice notice-info" role="status"><p>' . esc_html($result['error'] ?? $result['decision']) . '</p>';
            if (!empty($result['hit'])) {
                echo '<p>规则：' . esc_html($result['hit']['id']) . '；字段：' . esc_html($result['hit']['field']) . '；说明：' . esc_html($result['hit']['name']) . '</p>';
            }
            if (!empty($result['exception'])) { echo '<p>此次未命中是因为精细例外生效；其他规则仍参与检测。</p>'; }
            echo '</div>';
        }
        $defaults = ['method' => 'POST', 'path' => '/example', 'source' => 'JSON', 'field' => 'content', 'value' => '', 'ip' => '192.0.2.10', 'ua' => 'LumeShield-Simulator'];
        $sample = isset($_POST['ls_simulate']) && is_array($_POST['sample'] ?? null) ? wp_unslash($_POST['sample']) : [];
        echo '<form method="post" action="' . esc_url(admin_url('admin.php?page=lumeseed-lumeshield&tab=tools')) . '">';
        wp_nonce_field('lumeshield_simulate');
        echo '<input type="hidden" name="ls_simulate" value="1"><table class="form-table" role="presentation">';
        foreach (['method' => '请求方法', 'path' => '精确路径', 'source' => '字段来源', 'field' => '顶层字段名', 'ip' => '模拟来源 IP', 'ua' => 'User-Agent', 'value' => '测试内容'] as $key => $label) {
            $value = is_string($sample[$key] ?? null) ? $sample[$key] : $defaults[$key];
            $value = mb_strcut($value, 0, 16384, 'UTF-8');
            echo '<tr><th><label for="sample-' . esc_attr($key) . '">' . esc_html($label) . '</label></th><td>';
            if (in_array($key, ['method', 'source'], true)) {
                echo '<select id="sample-' . esc_attr($key) . '" name="sample[' . esc_attr($key) . ']">';
                foreach ($key === 'method' ? ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] : ['GET', 'POST', 'JSON', 'COOKIE'] as $option) {
                    echo '<option ' . selected($value, $option, false) . '>' . esc_html($option) . '</option>';
                }
                echo '</select>';
            } elseif ($key === 'value') {
                echo '<textarea class="large-text code" rows="6" id="sample-value" name="sample[value]" maxlength="16384">' . esc_textarea($value) . '</textarea>';
            } else {
                echo '<input class="regular-text" id="sample-' . esc_attr($key) . '" name="sample[' . esc_attr($key) . ']" value="' . esc_attr($value) . '">';
            }
            echo '</td></tr>';
        }
        echo '</table>'; submit_button('运行试测'); echo '</form>';
    }
}
