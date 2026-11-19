<?php
/** 1.3 回归：详细日志、规则开关、例外预填和安全展示。 */
define('ABSPATH', __DIR__ . '/');
foreach (['Engine', 'Settings', 'Exceptions', 'Storage', 'Simulator', 'Console'] as $name) {
    require_once dirname(__DIR__) . '/includes/' . $name . '.php';
}
use LumeSeed\LumeShield\{Engine, Inputs, Settings, Exceptions, Storage, Simulator, Console};
function sanitize_textarea_field($v) { return trim(strip_tags($v)); }
function wp_timezone() { return new DateTimeZone('Asia/Singapore'); }
function wp_unslash($v) { return $v; }
$passed = 0;
function check($value, $name) { global $passed; if (!$value) { throw new RuntimeException($name); } $passed++; echo "通过：$name\n"; }
$s = Settings::defaults();
check($s['log_mode'] === 'redacted' && $s['log_window'] === 300, '升级默认保留脱敏聚合');
check(Settings::validate($s) === $s, '新增默认配置可往返保存');
$s['log_mode'] = 'detailed'; $s['log_window'] = 60; $s['disabled_rules'] = ['xss_script'];
check(Settings::validate($s)['disabled_rules'] === ['xss_script'], '可保存详细模式、窗口和停用规则');
foreach (['log_mode' => 'invalid', 'log_window' => 0, 'disabled_rules' => ['unknown']] as $key => $bad) {
    $input = $s; $input[$key] = $bad;
    try { Settings::validate($input); check(false, '必须拒绝无效配置'); }
    catch (InvalidArgumentException $e) { check(true, '拒绝无效 ' . $key); }
}
$item = [['field' => 'POST[content]', 'value' => '<script>alert(1)</script>', 'context' => 'value']];
$items = (new Inputs(65536))->collect([], [], [], '/api', '{"content":"<script>x</script>"}', 'application/json');
check(Engine::inspect($items, ['xss'], '/api', '', false)['field'] === 'JSON[content]', '优先报告具体 JSON 字段，原始体仍参与后续检测');
check(Engine::inspect($item, ['xss'], '/', '', false, [], 'POST', ['xss_script']) === null, '停用单条规则生效');
check(Engine::inspect([['field'=>'POST[x]', 'value'=>'<img onerror="x">', 'context'=>'value']], ['xss'], '/', '', false, [], 'POST', ['xss_script'])['id'] === 'xss_event', '同分类其他规则仍生效');
check(Engine::inspect([], ['probe'], '/.env', '', false, [], 'GET', ['sensitive_path']) === null, '路径规则可独立停用');
check(Engine::inspect([], ['scanner'], '/', 'sqlmap', false, [], 'GET', ['scanner_ua']) === null, 'UA 规则可独立停用');
$hit = Engine::inspect($item, ['xss'], '/', '', false);
check(!isset($hit['payload']), '默认引擎不捕获命中片段');
$hit = Engine::inspect($item, ['xss'], '/', '', false, [], 'POST', [], true);
check(str_contains($hit['payload'], '<script>'), '详细模式捕获实际命中片段');
$long = [['field'=>'POST[x]', 'value'=>str_repeat('a', 8000).'<script>x</script>', 'context'=>'value']];
$hit = Engine::inspect($long, ['xss'], '/', '', false, [], 'POST', [], true);
check(str_contains($hit['payload'], '<script>') && $hit['payload_truncated'], '长字段保留命中位置附近内容而非无关前缀');
$server = ['REQUEST_URI'=>'/api?token=example', 'HTTP_USER_AGENT'=>'test-agent'];
$detail = Storage::details($hit, $server, Settings::defaults());
check($detail === ['uri'=>'', 'ua'=>'', 'payload'=>'', 'truncated'=>false], '脱敏模式不会持久化 URI UA 或载荷');
$detail = Storage::details($hit, $server, $s);
check($detail['uri'] === $server['REQUEST_URI'] && $detail['ua'] === 'test-agent', '详细模式保留含查询串的 URI 和 UA');
$detail = Storage::details(['payload'=>str_repeat('文', 3000)], ['REQUEST_URI'=>str_repeat('a', 5000), 'HTTP_USER_AGENT'=>str_repeat('b', 3000)], $s);
check(strlen($detail['uri']) === 4096 && strlen($detail['ua']) === 2048 && strlen($detail['payload']) <= 4096 && mb_check_encoding($detail['payload'], 'UTF-8') && $detail['truncated'], '详细内容有长度上限且保留合法 UTF-8');
$detail = Storage::details(['payload'=>"bad\xffbytes"], [], $s);
check(mb_check_encoding($detail['payload'], 'UTF-8'), '非法编码不会写入无效 UTF-8');
check(Storage::fieldName('JSON[content]') === 'JSON[content]', '保留精确顶层字段用于例外');
check(Storage::fieldName('JSON[secret][nested]') === 'JSON', '嵌套字段不会推断成顶层例外');
$row = ['exception_path'=>'/api/article', 'method'=>'POST', 'field_name'=>'JSON[content]', 'rule_id'=>'xss_script'];
check(Exceptions::fromLog($row) === 'POST /api/article JSON[content] xss_script', '从记录生成精确例外');
foreach (['exception_path'=>'', 'field_name'=>'JSON', 'rule_id'=>'rate_limit', 'method'=>'INVALID'] as $key=>$bad) {
    $invalid = $row; $invalid[$key]=$bad;
    check(Exceptions::fromLog($invalid) === null, '不能从不完整记录扩大例外：'.$key);
}
$s = Settings::defaults(); $s['disabled_rules']=['xss_script'];
$sample=['method'=>'POST','path'=>'/api/article','source'=>'JSON','field'=>'content','value'=>'<script>x</script>','ip'=>'192.0.2.10','ua'=>'test'];
check(Simulator::evaluate($sample,$s)['hit'] === null, '策略试测使用同样的单条规则开关');
check(!Simulator::evaluate($sample,$s)['exception'], '停用规则不会被误报成例外生效');
$_GET = ['from'=>'2026-02-30','until'=>'2026-11-19','verb'=>'POST','outcome'=>'block'];
$f = Console::filters();
check($f['from'] === '' && $f['until'] === '2026-11-19' && $f['verb'] === 'POST', '筛选拒绝不存在的日期');
$_GET = ['verb'=>"POST' OR 1=1",'outcome'=>['block']];
check(Console::filters()['verb'] === '' && Console::filters()['outcome'] === '', '筛选拒绝异常类型与非枚举值');
echo "总计 $passed 项通过。\n";
