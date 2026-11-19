<?php
/** 仅用于隔离测试站点；重置自动封禁表，须设置 LUMESHIELD_TEST_SITE=1。 */
if (getenv('LUMESHIELD_TEST_SITE') !== '1' || empty($argv[1])) { exit(2); }
define('WP_CLI', true);
require $argv[1];
use LumeSeed\LumeShield\{AutoBan, Settings, Storage, Engine, BlockPage};
global $wpdb;
$passed = 0;
function check($ok, $name) { global $passed; if (!$ok) { throw new RuntimeException($name); } $passed++; echo "通过：$name\n"; }
$s = Settings::defaults();
check($s['autoban_enabled'] === 0 && $s['autoban_window'] === 300 && $s['autoban_threshold'] === 20 && $s['autoban_duration'] === 3600, '新功能默认关闭且阈值可配置');
check(Settings::validate($s) === $s, '默认配置可保存');
foreach (['autoban_window' => 0, 'autoban_threshold' => 2, 'autoban_duration' => 604801] as $key => $value) {
    try { Settings::validate(array_replace($s, [$key => $value])); check(false, '拒绝无效配置'); }
    catch (InvalidArgumentException $e) { check(true, '拒绝无效 ' . $key); }
}
check(Storage::install(), '创建自动封禁表并完成迁移');
$table = Storage::table('autobans');
$wpdb->query("DELETE FROM $table");
$ip = '192.0.2.120'; $now = intdiv(time(), 300) * 300 + 5;
$hit = Engine::hit('xss_script', 'xss', 'GET[test]', '测试规则');
wp_set_current_user(0);
AutoBan::record($hit, $ip, $s, $now);
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table") === 0, '关闭功能不写自动计数');
$s['autoban_enabled'] = 1;
AutoBan::record($hit, $ip, $s, $now);
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table") === 0, '观察模式不累计封禁');
$s['mode'] = 'block'; $s['autoban_threshold'] = 3;
foreach (['blacklist', 'rate', 'login', 'limits'] as $category) { AutoBan::record(Engine::hit('other', $category, 'IP', '测试'), $ip, $s, $now); }
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table") === 0, '黑名单限流登录及边界事件不计入');
AutoBan::record($hit, $ip, $s, $now);
AutoBan::record($hit, $ip, $s, $now + 1);
check(AutoBan::active($ip, $s, $now + 1) === null, '未达阈值不封禁');
AutoBan::record($hit, $ip, $s, $now + 2);
$ban = AutoBan::active($ip, $s, $now + 2);
check($ban && (int) $ban['hits'] === 3 && (int) $ban['blocked_until'] === $now + 3602, '达到阈值当次创建临时封禁');
AutoBan::record($hit, $ip, $s, $now + 3);
$again = AutoBan::active($ip, $s, $now + 3);
check($again['blocked_until'] === $ban['blocked_until'] && (int) $again['hits'] === 3, '封禁期间不延长且不重复累计');
check(AutoBan::active($ip, array_replace($s, ['mode' => 'observe']), $now + 3) === null, '观察模式不执行已有封禁');
check(AutoBan::active($ip, array_replace($s, ['autoban_enabled' => 0]), $now + 3) === null, '关闭开关不执行已有封禁');
check(AutoBan::active($ip, array_replace($s, ['ip_allow' => [$ip]]), $now + 3) === null, 'IP 白名单不受自动封禁影响');
check(AutoBan::active($ip, array_replace($s, ['trusted_proxies' => ['192.0.2.0/24']]), $now + 3) === null, '可信代理不受自动封禁影响');
wp_set_current_user(1);
check(AutoBan::active($ip, $s, $now + 3) === null, '已认证管理员不受自动封禁影响');
AutoBan::record($hit, '192.0.2.121', $s, $now);
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE ip='192.0.2.121'") === 0, '管理员命中不参与累计');
wp_set_current_user(0);
check(AutoBan::active($ip, $s, (int) $ban['blocked_until']) === null, '到期立即解除且无需等待定时清理');
AutoBan::record($hit, $ip, $s, (int) $ban['blocked_until']);
check((int) $wpdb->get_var("SELECT hits FROM $table WHERE ip='192.0.2.120'") === 1, '封禁到期后新命中从头累计');
AutoBan::record($hit, $ip, $s, (int) $ban['blocked_until'] + 1);
AutoBan::record($hit, $ip, $s, (int) $ban['blocked_until'] + 2);
$newBan = AutoBan::active($ip, $s, (int) $ban['blocked_until'] + 2);
check($newBan && AutoBan::release((int) $newBan['id']), '可手动解除自动封禁');
AutoBan::record($hit, $ip, $s, (int) $ban['blocked_until'] + 3);
check((int) $wpdb->get_var("SELECT hits FROM $table WHERE ip='192.0.2.120'") === 1, '手动解封同时重置计数');
$wpdb->query("DELETE FROM $table");
AutoBan::record($hit, $ip, $s, $now);
AutoBan::record($hit, $ip, $s, $now + 1);
AutoBan::record($hit, $ip, $s, $now + 300);
check((int) $wpdb->get_var("SELECT hits FROM $table") === 1, '跨固定窗口重新累计');
AutoBan::record($hit, $ip, array_replace($s, ['autoban_window' => 600]), $now + 301);
check((int) $wpdb->get_var("SELECT hits FROM $table") === 1, '修改窗口不复用旧窗口计数');
$wpdb->query("DELETE FROM $table");
foreach (['2001:db8::1', '2001:0db8:0:0:0:0:0:1', '2001:db8::1'] as $ipv6) { AutoBan::record($hit, $ipv6, $s, $now); }
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table") === 1 && AutoBan::active('2001:db8::1', $s, $now) !== null, '等价 IPv6 地址共用封禁计数');
$wpdb->query("UPDATE $table SET expires_at=1,blocked_until=1");
Storage::cleanup();
check((int) $wpdb->get_var("SELECT COUNT(*) FROM $table") === 0, '定时清理过期封禁与计数');
check(BlockPage::type(403, ['id' => 'auto_ban']) === 'IP 临时封禁', '访客页面显示临时封禁原因');
echo "总计 $passed 项自动封禁集成检查通过。\n";
