<?php
/** 运行检查只读取状态，不保存设置、不修复表，也不向外部服务发送请求。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Diagnostics
{
    public static function mode(array $settings, bool $emergency, bool $multisite): array
    {
        // 按真实执行优先级展示，避免紧急停用后仍把设置中的“拦截”显示为已生效。
        if ($emergency) {
            return ['暂停', '紧急停用常量已开启，当前不执行请求检测。'];
        }
        if ($multisite) {
            return ['不支持', '当前是多站点网络，本版本不执行请求检测。'];
        }
        if (empty($settings['enabled'])) {
            return ['关闭', '策略总开关已关闭，当前不执行请求检测。'];
        }
        return ($settings['mode'] ?? 'observe') === 'block'
            ? ['拦截', '命中已启用的策略时会拒绝请求；不代表所有攻击都能被检测。']
            : ['观察', '记录命中但保留业务响应，黑名单和限流也不阻断。'];
    }

    public static function report(): array
    {
        global $wpdb;
        $settings = Settings::get();
        [$state, $detail] = self::mode($settings, defined('LUMESHIELD_DISABLE') && LUMESHIELD_DISABLE, is_multisite());
        $rows = [['执行模式', $state, $detail]];
        $rows[] = ['文本处理扩展', function_exists('mb_strcut') ? '可用' : '缺失', '日志安全截断需要 PHP mbstring 扩展。'];
        // LIMIT 0 验证表和所需列可读取，不读取日志内容，也不假定可读就一定可写。
        $previous = $wpdb->suppress_errors(true);
        try {
            foreach (['logs' => ['命中日志表', 'id,last_seen,ip,path,rule_id,action_name,hits'],
                'rates' => ['请求计数表', 'bucket,hits,expires_at']] as $suffix => [$label, $columns]) {
                $result = $wpdb->query('SELECT ' . $columns . ' FROM ' . Storage::table($suffix) . ' LIMIT 0');
                $rows[] = [$label, $result !== false ? '可读取' : '需处理', $result !== false
                    ? '所需字段可读取；本检查没有写入数据，不能证明写入权限正常。'
                    : '数据表或字段不可读取，请在命中日志页检查数据表，并核对数据库权限。'];
            }
        } finally {
            $wpdb->suppress_errors($previous);
        }
        $next = wp_next_scheduled('lumeseed_lumeshield_cleanup');
        $external = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;
        $cronState = !$next ? '未安排' : ($next < time() - 600 ? '已延迟' : '已安排');
        $cronDetail = $next ? '下次计划：' . wp_date('Y-m-d H:i:s', $next) . '。' : '清理任务缺失，可尝试停用后重新启用插件。';
        $cronDetail .= $external ? 'WP-Cron 自动触发已关闭，请确认系统定时任务正在调用 WordPress Cron。' : '由站点访问触发，低访问量时可能延迟；已安排不代表执行成功。';
        $rows[] = ['自动清理', $cronState, $cronDetail];
        $count = count(Settings::proxies($settings));
        $rows[] = ['来源地址信任', $count ? '已设代理' : '直连地址', $count
            ? '已配置 ' . $count . ' 条代理规则。请核对实际回源网段；仅凭配置无法验证代理是否覆盖伪造头。'
            : '不读取访客提供的代理头。若站点位于 CDN 后方，请配置可信回源地址，否则不同访客可能共享限流计数。'];
        $error = get_option('lumeseed_lumeshield_error', []);
        $hasError = is_array($error) && !empty($error['time']);
        $rows[] = ['历史降级记录', $hasError ? '待核查' : '无记录', $hasError
            ? '最近记录：' . wp_date('Y-m-d H:i:s', (int) $error['time']) . '，组件：' . ($error['component'] ?? '未知') . '。这不是当前故障的实时判断，请结合日志排查。'
            : '没有保存的降级记录；不代表所有请求都受到了完整检查。'];
        return $rows;
    }

    public static function render(): void
    {
        echo '<h2>运行检查</h2><p>这些检查帮助确认防护是否按配置运行，不给网站安全打分，也不会自动更改策略。</p>';
        echo '<table class="widefat striped"><thead><tr><th scope="col">检查项</th><th scope="col">状态</th><th scope="col">说明与下一步</th></tr></thead><tbody>';
        foreach (self::report() as [$label, $state, $detail]) {
            echo '<tr><th scope="row">' . esc_html($label) . '</th><td>' . esc_html($state) . '</td><td>' . esc_html($detail) . '</td></tr>';
        }
        echo '</tbody></table><h2>建议的启用流程</h2><ol><li>保持观察模式，核对实际代理与来源地址。</li><li>测试登录、评论、编辑器、表单和支付回调，查看命中日志。</li><li>按业务调整检测分类和必要的精确例外，再开启拦截。</li><li>保留紧急停用方法，定期复查日志与清理任务。</li></ol>';
        echo '<p>如需紧急停用，在 wp-config.php 加载 WordPress 前加入 <code>define(\'LUMESHIELD_DISABLE\', true);</code>。</p>';
    }
}
