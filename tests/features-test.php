<?php
/** 1.1 功能回归：精细例外、原始输入保留、试测及网段格式；不访问网络。 */
define('ABSPATH', __DIR__ . '/');
foreach (['Engine', 'Settings', 'Exceptions', 'Cloudflare', 'Simulator'] as $file) { require_once dirname(__DIR__) . '/includes/' . $file . '.php'; }
use LumeSeed\LumeShield\{Engine, Inputs, Settings, Exceptions, Cloudflare, Simulator};
function sanitize_textarea_field($text) { return trim(strip_tags($text)); }
$passed = 0;
function check($ok, $label) { global $passed; if (!$ok) { throw new RuntimeException($label); } $passed++; echo "通过：$label\n"; }
function inspect(array $data, string $source, array $lines, string $path = '/api/article', string $method = 'POST', ?string $raw = null) {
    $get = $post = $cookies = []; $body = null; $type = ''; $uri = $path;
    if ($source === 'GET') { $get = $data; $uri .= '?' . ($raw ?? http_build_query($data)); }
    elseif ($source === 'POST') { $post = $data; $body = $raw ?? http_build_query($data); $type = 'application/x-www-form-urlencoded'; }
    elseif ($source === 'COOKIE') { $cookies = $data; }
    else { $body = $raw ?? json_encode($data); $type = 'application/json'; }
    return Engine::inspect((new Inputs(262144))->collect($get,$post,$cookies,$uri,$body,$type), Settings::defaults()['categories'], $path, '', false, Exceptions::parse($lines), $method);
}
$tag = '<script type="application/json">test</script>';
foreach (['GET','POST','JSON','COOKIE'] as $source) {
    $rules = ["POST /api/article $source" . '[content] xss_script'];
    check(inspect(['content'=>$tag],$source,$rules) === null, "$source 顶层例外包含原始表示");
    check(inspect(['content'=>$tag,'other'=>$tag],$source,$rules) !== null, "$source 其他字段不被放行");
    check(inspect(['content'=>'UNION SELECT NULL'],$source,$rules)['id'] === 'sql_union', "$source 其他规则继续检测");
    check(inspect(['content'=>$tag],$source,$rules,'/other') !== null, "$source 其他路径不被放行");
    check(inspect(['content'=>$tag],$source,$rules,'/api/article','GET') !== null, "$source 其他方法不被放行");
}
$rules = ['POST /api/article JSON[content] xss_script'];
check(inspect([], 'JSON', $rules, '/api/article', 'POST', '{"content":"\\u003cscript>ok</script>"}') === null, 'JSON Unicode 转义按字段豁免');
check(inspect([], 'JSON', $rules, '/api/article', 'POST', '{"content":"<script>a</script>","content":"<script>b</script>"}') === null, '重复 JSON 同键仍仅豁免该字段');
check(inspect([], 'JSON', $rules, '/api/article', 'POST', '{"content":"ok","other":"<script>a</script>","other":"ok"}') !== null, '重复 JSON 其他键的早期载荷保留检测');
check(inspect(['content'=>['sub'=>$tag]], 'JSON', $rules) !== null, '顶层例外不扩大到对象子字段');
check(inspect(['content]'=>$tag], 'JSON', $rules) !== null, '特殊键名不能冒充例外字段');
check(inspect(['content'=>'ok'], 'POST', ['POST /api/article POST[content] xss_script'], '/api/article', 'POST', 'other=%3Cscript%3Ex%3C%2Fscript%3E&other=ok') !== null, '原始表单重复其他键不能绕过');
check(inspect(['content'=>'ok'], 'GET', ['POST /api/article GET[content] xss_script'], '/api/article', 'POST', 'other=%3Cscript%3Ex%3C%2Fscript%3E&other=ok') !== null, '原始查询重复其他键不能绕过');
check(inspect(['other'=>$tag], 'JSON', ['POST /api/article * xss_script']) === null, '明确指定整条规则例外生效');
foreach (['POST /* JSON[content] xss_script','POST /api/article JSON[content][x] xss_script','POST /api/article * unknown','POST /api/article JSON[content] scanner_ua','POST /api/article?x=1 * xss_script'] as $line) {
    try { Exceptions::parse([$line]); check(false,'应拒绝无效例外'); } catch (InvalidArgumentException $e) { check(true,'拒绝无效例外：'.$line); }
}
$s = Settings::defaults(); $s['mode']='block';
$sample=['method'=>'POST','path'=>'/api/article','source'=>'JSON','field'=>'content','value'=>$tag,'ip'=>'192.0.2.10','ua'=>'test'];
check(Simulator::evaluate($sample,$s)['decision']==='会拦截','试测使用拦截模式');
$s['exceptions']=$rules;
check(Simulator::evaluate($sample,$s)['exception']===true,'试测解释精细例外生效');
$s['ip_deny']=['192.0.2.10'];$s['ip_allow']=['192.0.2.10'];
check(Simulator::evaluate($sample,$s)['hit']['id']==='deny_ip','试测黑名单优先');
foreach (['', '0.0.0.0/0', "<html>bad</html>", "192.0.2.1/abc"] as $bad) {
    try { Cloudflare::validateList($bad,false); check(false,'应拒绝无效官方响应'); } catch (RuntimeException $e) { check(true,'拒绝无效官方响应'); }
}
check(count(Cloudflare::validateList("173.245.48.0/20\n103.21.244.0/22\n103.22.200.0/22\n103.31.4.0/22\n141.101.64.0/18",false))===5,'IPv4 网段校验');
check(count(Cloudflare::validateList("2400:cb00::/32\n2606:4700::/32",true))===2,'IPv6 网段校验');
check(Settings::validate(Settings::defaults())['login_enabled']===0,'新功能默认保持关闭');
echo "总计 $passed 项通过。\n";
