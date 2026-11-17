<?php
/**
 * Plugin Name: LumeShield 微光盾
 * Description: 提供请求特征检测、可信代理解析、IP/路径/UA 名单、请求限流与脱敏日志，默认使用观察模式。
 * Version: 1.2.0
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

const VERSION = '1.2.0';
const FILE = __FILE__;

require_once __DIR__ . '/includes/Engine.php';
require_once __DIR__ . '/includes/Exceptions.php';
require_once __DIR__ . '/includes/Settings.php';
require_once __DIR__ . '/includes/Storage.php';
require_once __DIR__ . '/includes/Diagnostics.php';
require_once __DIR__ . '/includes/Cloudflare.php';
require_once __DIR__ . '/includes/LoginGuard.php';
require_once __DIR__ . '/includes/Simulator.php';
require_once __DIR__ . '/includes/Admin.php';
require_once __DIR__ . '/includes/BlockPage.php';
require_once __DIR__ . '/includes/Plugin.php';

register_activation_hook(__FILE__, [Plugin::class, 'activate']);
register_deactivation_hook(__FILE__, [Plugin::class, 'deactivate']);
Plugin::register();
