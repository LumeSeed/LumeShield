<?php
/** 只有 WordPress 发起卸载且用户事先选择清理时才删除数据。 */
defined('WP_UNINSTALL_PLUGIN') || exit;

$settings = get_option('lumeseed_lumeshield_settings', []);
wp_clear_scheduled_hook('lumeseed_lumeshield_cleanup');
if (empty($settings['delete_on_uninstall'])) {
    return;
}
global $wpdb;
// 表名仅来自 WordPress 自己的前缀和固定后缀，不读取请求参数。
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'lumeseed_lumeshield_logs');
$wpdb->query('DROP TABLE IF EXISTS ' . $wpdb->prefix . 'lumeseed_lumeshield_rates');
delete_option('lumeseed_lumeshield_settings');
delete_option('lumeseed_lumeshield_db_version');
delete_option('lumeseed_lumeshield_error');
delete_option('lumeseed_lumeshield_cf');
