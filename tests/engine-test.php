<?php
/** 独立回归测试：只使用虚构请求，不访问任何外部站点。运行：php tests/engine-test.php */
define('ABSPATH', __DIR__ . '/');
require_once dirname(__DIR__) . '/includes/Engine.php';
require_once dirname(__DIR__) . '/includes/Exceptions.php';
require_once dirname(__DIR__) . '/includes/Settings.php';

use LumeSeed\LumeShield\Ip;
use LumeSeed\LumeShield\Inputs;
use LumeSeed\LumeShield\Engine;
use LumeSeed\LumeShield\Settings;

// 仅模拟配置清洗函数；WordPress 生命周期另外进行集成测试。
function sanitize_textarea_field($text) { return trim(strip_tags($text)); }
$passed = 0;
function check($value, string $name): void {
    global $passed;
    if (!$value) { throw new RuntimeException('失败：' . $name); }
    $passed++;
    echo '通过：' . $name . PHP_EOL;
}
function detects(string $text): ?array {
    return Engine::inspect([['field' => 'POST[text]', 'value' => $text, 'context' => 'value']], Settings::defaults()['categories'], '/', 'Mozilla/5.0', false);
}

check(!Ip::validRule('192.0.2.1/abc'), '非法掩码不会退化为 /0');
check(!Ip::validRule('192.0.2.1/-1'), '拒绝负掩码');
check(!Ip::validRule('192.0.2.1/33'), '拒绝越界掩码');
check(!Ip::validRule('192.0.2.1/'), '拒绝空掩码');
check(Ip::matches('192.0.2.7', '192.0.2.0/24'), 'IPv4 CIDR 命中');
check(!Ip::matches('192.0.3.7', '192.0.2.0/24'), 'IPv4 CIDR 范围外不命中');
check(Ip::matches('2001:db8::1', '2001:0db8:0000:0000:0000:0000:0000:0001'), '等价 IPv6 文本规范化');
check(Ip::matches('2001:db8:1::5', '2001:db8::/32'), 'IPv6 CIDR 命中');
check(!Ip::matches('192.0.2.1', '2001:db8::/32'), '不同地址族不匹配');
$server = ['REMOTE_ADDR' => '198.51.100.8', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1'];
check(Ip::resolve($server, ['10.0.0.0/8'], 'HTTP_X_FORWARDED_FOR') === '198.51.100.8', '非可信来源不能伪造代理 IP');
$server = ['REMOTE_ADDR' => '10.0.0.2', 'HTTP_X_FORWARDED_FOR' => '192.0.2.1, 198.51.100.8, 10.0.0.1'];
check(Ip::resolve($server, ['10.0.0.0/8'], 'HTTP_X_FORWARDED_FOR') === '198.51.100.8', '代理链停在最近非可信节点');
$server['HTTP_X_FORWARDED_FOR'] = 'invalid, 198.51.100.8';
check(Ip::resolve($server, ['10.0.0.0/8'], 'HTTP_X_FORWARDED_FOR') === '10.0.0.2', '无效代理链回退直接连接 IP');
$server['HTTP_CF_CONNECTING_IP'] = '192.0.2.9';
check(Ip::resolve($server, ['10.0.0.0/8'], 'HTTP_CF_CONNECTING_IP') === '192.0.2.9', '可信代理指定单值头');
check(!Engine::pathListed('/api-public', ['/api']), '精确白名单不意外扩展前缀');
check(Engine::pathListed('/api/test', ['/api/*']), '显式路径前缀匹配');
check(Engine::pathListed('/%61pi/test', ['/api/*']), '路径编码匹配');
$items = (new Inputs(65536))->collect([], ['a' => ['same' => '<script>x</script>'], 'b' => ['same' => '正常']], [], '/', null, 'multipart/form-data');
check(count(array_filter($items, fn($v) => str_ends_with($v['field'], '[same]'))) === 2, '同名嵌套字段都被保留');
check(Engine::inspect($items, ['xss'], '/', '', false)['id'] === 'xss_script', '嵌套字段中的特征不会被后续值覆盖');
$items = (new Inputs(65536))->collect([], [], [], '/', '{"text":"\u003cscript\u003ex\u003c/script\u003e"}', 'application/json; charset=utf-8');
check(Engine::inspect($items, ['xss'], '/', '', false)['id'] === 'xss_script', 'JSON Unicode 转义参与检测');
try {
    (new Inputs(16384))->collect([], [], [], '/', str_repeat('a', 16385), 'text/plain');
    check(false, '超限必须显式失败');
} catch (LengthException $e) { check(true, '超限明确标记，不截断放行'); }
try {
    (new Inputs(16384))->collect([], [], [], '/', '{bad}', 'application/json');
    check(false, '无效 JSON 必须显式失败');
} catch (UnexpectedValueException $e) { check(true, '无效 JSON 明确标记'); }
check(detects('UNION/**/SELECT password FROM accounts')['id'] === 'sql_union', 'SQL 注释空白归一化');
check(detects('uni/**/on select password')['id'] === 'sql_union', 'SQL 分割关键词归一化');
check(detects("INTO OUTFILE '/tmp/demo.txt'")['id'] === 'sql_file', 'SQL 文件写入无需错误的括号条件');
check(detects('../private/file')['category'] === 'traversal', 'Unix 路径穿越');
check(detects('..\\private\\file')['category'] === 'traversal', 'Windows 路径穿越');
check(detects('%253Cscript%253Ex%253C/script%253E')['category'] === 'xss', '双重 URL 编码检测');
check(detects('<img src="x" onerror="demo()">')['category'] === 'xss', 'HTML 事件属性检测');
foreach (['having a nice day', 'PowerShell 教程', 'curl 工具介绍', 'hello@example.com', '普通中文评论', '<p>正常段落</p>'] as $text) {
    check(detects($text) === null, '正常内容通过：' . $text);
}
check(Engine::inspect([], ['scanner'], '/', 'curl/8.0', false) === null, '普通 curl UA 不误拦');
check(Engine::inspect([], ['scanner'], '/', 'sqlmap/1.0', false)['category'] === 'scanner', '扫描器 UA 识别');
check(Engine::inspect([], ['scanner'], '/', 'sqlmap/1.0', true) === null, 'UA 白名单跳过 UA 规则');
check(Engine::inspect([['field' => 'POST[x]', 'value' => '<script>x</script>', 'context' => 'value']], ['xss'], '/', 'sqlmap/1.0', true) !== null, 'UA 白名单不跳过参数检测');
check(Engine::inspect([], ['probe'], '/.git/config', '', false) !== null, '敏感路径识别');
$s = Settings::defaults();
check(Settings::validate($s)['mode'] === 'observe', '默认配置可往返保存');
$s['trusted_proxies'] = '0.0.0.0/0';
try { Settings::validate($s); check(false, '不能信任整个互联网'); }
catch (InvalidArgumentException $e) { check(true, '拒绝全网可信代理'); }
$s = Settings::defaults(); $s['ip_allow'] = '192.0.2.1/abc';
try { Settings::validate($s); check(false, '非法名单必须拒绝'); }
catch (InvalidArgumentException $e) { check(true, '保存时拒绝非法 CIDR'); }
foreach (Engine::rules() as $rule) {
    check(preg_match($rule[3], '') !== false, '正则语法有效：' . $rule[0]);
}
require_once __DIR__ . '/../includes/Diagnostics.php';
use LumeSeed\LumeShield\Diagnostics;
check(Diagnostics::mode(['enabled' => 1, 'mode' => 'block'], true, false)[0] === '暂停', '紧急开关优先于拦截模式显示');
check(Diagnostics::mode(['enabled' => 1, 'mode' => 'block'], false, true)[0] === '不支持', '多站环境不显示为正在拦截');
check(Diagnostics::mode(['enabled' => 0, 'mode' => 'block'], false, false)[0] === '关闭', '总开关关闭状态');
check(Diagnostics::mode(Settings::defaults(), false, false)[0] === '观察', '默认真实执行状态');
check(Diagnostics::mode(['enabled' => 1, 'mode' => 'block'], false, false)[0] === '拦截', '拦截状态显示');
echo "总计 {$passed} 项通过。" . PHP_EOL;
