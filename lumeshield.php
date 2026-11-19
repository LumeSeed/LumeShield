<?php
/**
 * Plugin Name: LumeShield 微光盾
 * Description: 提供请求特征检测、可信代理解析、IP/路径/UA 名单、请求限流与脱敏日志，默认使用观察模式。
 * Version: 1.4.1
 * Author: LumeSeed
 * Author URI: https://github.com/LumeSeed
 * Requires at least: 6.0
 * Requires PHP: 8.0
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: lumeshield
 */

namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

// Linux 可同时存在 LumeShield/ 与 lumeshield/；在声明常量、加载类之前阻止重复副本。
if (defined(__NAMESPACE__ . '\\FILE') || class_exists(__NAMESPACE__ . '\\Plugin', false)) {
    register_activation_hook(__FILE__, static function (): void {
        wp_die('已有另一份 LumeShield 正在运行。请使用 WordPress 安装包覆盖原插件目录升级，不要同时启用两份副本。现有防护、配置和日志保持不变。');
    });
    add_action('admin_notices', static function (): void {
        if (current_user_can('manage_options')) {
            echo '<div class="notice notice-error"><p>' . esc_html('检测到重复加载的 LumeShield 副本；仅先加载的版本运行。请保留一个插件目录，并使用安装包覆盖升级。') . '</p></div>';
        }
    });
    return;
}

const VERSION = '1.4.1';
const FILE = __FILE__;

require_once __DIR__ . '/includes/Engine.php';
require_once __DIR__ . '/includes/Exceptions.php';
require_once __DIR__ . '/includes/Settings.php';
require_once __DIR__ . '/includes/Storage.php';
require_once __DIR__ . '/includes/AutoBan.php';
require_once __DIR__ . '/includes/AutoBanAdmin.php';
require_once __DIR__ . '/includes/Diagnostics.php';
require_once __DIR__ . '/includes/Cloudflare.php';
require_once __DIR__ . '/includes/LoginGuard.php';
require_once __DIR__ . '/includes/Simulator.php';
require_once __DIR__ . '/includes/Admin.php';
require_once __DIR__ . '/includes/SettingsPage.php';
require_once __DIR__ . '/includes/Console.php';
require_once __DIR__ . '/includes/BlockPage.php';
require_once __DIR__ . '/includes/Plugin.php';

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [Plugin::class, 'deactivate']);
Plugin::register();
