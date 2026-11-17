=== LumeShield 微光盾 ===
Tags: security, firewall, rate-limit
Requires at least: 6.0
Requires PHP: 8.0
Stable tag: 1.2.0
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress 原生请求防护插件，作者 LumeSeed：https://github.com/LumeSeed 。中文注释与后台，默认观察模式。

== Description ==

支持请求特征检测、可信代理解析、IP/路径/UA 名单、数据库原子限流、脱敏日志及自动清理。
需要 PHP mbstring 扩展和 WordPress 标准 MySQL/MariaDB 驱动。当前支持单站，不支持多站点网络。
不采集遥测，不向第三方发送请求日志。默认仅记录检测命中，需要管理员手动启用拦截。
完整使用说明、检测边界和数据保留策略见随包 README.md。

== Installation ==

1. 后台“插件 → 安装新插件 → 上传插件”，选择安装 ZIP。
2. 启用后打开“设置 → LumeShield 防护”。
3. 先使用观察模式核对业务，再启用拦截模式。

== Frequently Asked Questions ==

= 能防御所有攻击吗？ =

不能。插件只检查经过 WordPress init 阶段的请求，规则有误报和漏报，不能代替服务器或 CDN 防护。

= 如何紧急关闭？ =

在 wp-config.php 加载 WordPress 前定义 LUMESHIELD_DISABLE 为 true，或重命名插件目录。

= 删除插件会删除日志吗？ =

默认保留。先在设置中开启“删除插件时同时删除策略与日志”，再停用并删除，才会清理数据库记录。

== Changelog ==

= 1.2.0 =

* 新增微光盾星光拦截页，支持 PC 与手机。
* 主标题展示实际拦截类型，移除返回首页与帮助按钮。
* 显示 RAY ID、IP、区域；不信任直连伪造的代理头。
* 管理员可使用 nonce 保护的预览，无需触发封禁。
* 保留简洁页面与 JSON API 响应。

= 1.1.0 =

* 新增独立登录失败限速，默认关闭，尊重观察模式与紧急开关。
* 官方 Cloudflare 网段手动更新，严格验证后原子保存，失败保留旧配置。
* 按方法、精确路径、顶层字段和规则设置例外，其他检测继续执行。
* 后台策略试测不请求外部地址、不保存载荷、不写日志或计数。
* 覆盖升级保留原有配置与日志。

= 1.0.0 =

* 首个独立版本，提供 WordPress 原生策略、中文界面与运行检查。
* 严格代理信任及 CIDR 校验，完整嵌套参数采集与 JSON 解码。
* 数据库原子计数、请求大小限制、日志脱敏、聚合和自动清理。
* 原生权限、nonce、POST 写入与可配置卸载清理。
