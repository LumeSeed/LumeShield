<?php
/** 独立进程测试；可传入原 1.2.0 入口路径测试真实跨版本重复加载。 */
define('ABSPATH', __DIR__ . '/');
$actions = $filters = $activations = $deactivations = [];
function add_action(...$args) { global $actions; $actions[] = $args; }
function add_filter(...$args) { global $filters; $filters[] = $args; }
function register_activation_hook($file, $callback) { global $activations; $activations[$file] = $callback; }
function register_deactivation_hook($file, $callback) { global $deactivations; $deactivations[$file] = $callback; }
function plugin_basename($file) { return basename(dirname($file)) . '/' . basename($file); }
function wp_die($message) { throw new RuntimeException($message); }
function current_user_can($capability) { return true; }
function esc_html($value) { return htmlspecialchars($value, ENT_QUOTES, 'UTF-8'); }
$passed = 0;
function check($ok, $name) { global $passed; if (!$ok) { throw new RuntimeException($name); } $passed++; echo "通过：$name\n"; }
set_error_handler(static function ($severity, $message) { throw new ErrorException($message, 0, $severity); });
$entry = realpath(dirname(__DIR__) . '/lumeshield.php');
require $argv[1] ?? $entry;
$originalFile = \LumeSeed\LumeShield\FILE;
$originalVersion = \LumeSeed\LumeShield\VERSION;
check(class_exists('LumeSeed\\LumeShield\\Plugin', false), '首份插件正常加载');
$actionCount = count($actions);
$filterCount = count($filters);
$deactivationCount = count($deactivations);
require $entry;
check(\LumeSeed\LumeShield\FILE === $originalFile && \LumeSeed\LumeShield\VERSION === $originalVersion, '保留首份插件常量且不产生重定义警告');
check(count($actions) === $actionCount + 1 && count($filters) === $filterCount, '重复副本仅注册说明，不重复注册防护钩子');
check(count($deactivations) === $deactivationCount, '重复副本不注册清理定时任务的停用钩子');
try { $activations[$entry](); check(false, '应阻止重复启用'); }
catch (RuntimeException $e) { check(str_contains($e->getMessage(), '已有另一份 LumeShield'), '重复启用显示明确原因'); }
ob_start(); $actions[array_key_last($actions)][1](); $notice = ob_get_clean();
check(str_contains($notice, '重复加载') && str_contains($notice, '覆盖升级'), '管理员提示正确升级方式');
echo "总计 $passed 项入口检查通过。\n";
