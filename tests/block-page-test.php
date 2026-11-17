<?php
/** 拦截结果页回归：使用虚构地址，不访问外部网站。 */
define('ABSPATH', __DIR__ . '/');
require dirname(__DIR__) . '/includes/Engine.php';
require dirname(__DIR__) . '/includes/Settings.php';
require dirname(__DIR__) . '/includes/BlockPage.php';
use LumeSeed\LumeShield\BlockPage;
use LumeSeed\LumeShield\Settings;
$passed = 0;
function check($condition, $name) { global $passed; if (!$condition) throw new RuntimeException($name); $passed++; }
$s = Settings::defaults();
check(BlockPage::type(403, ['category'=>'sqli']) === 'SQL 注入拦截', 'SQL 分类');
check(BlockPage::type(403, ['category'=>'xss']) === '跨站脚本拦截', 'XSS 分类');
check(BlockPage::type(403, ['id'=>'deny_ip']) === 'IP 黑名单拦截', 'IP 黑名单');
check(BlockPage::type(429) === '请求频率超限', '限流');
check(BlockPage::type(413) === '请求大小超限', '请求大小');
check(BlockPage::type(400) === '请求格式异常', '请求格式');
check(BlockPage::type(403, ['name'=>'<script>secret</script>']) === '安全策略拦截', '未知类型不得回显数据');
$headers = ['REMOTE_ADDR'=>'192.0.2.1','HTTP_CF_CONNECTING_IP'=>'203.0.113.24','HTTP_CF_RAY'=>'7c92e4a1b083d65f-SIN','HTTP_CF_IPCOUNTRY'=>'CN'];
check(BlockPage::metadata($headers,$s,'203.0.113.24')['ray']==='不可用', '直连头不可信');
$s['trusted_proxies']=['192.0.2.1']; $s['proxy_header']='HTTP_CF_CONNECTING_IP';
$meta=BlockPage::metadata($headers,$s,'203.0.113.24');
check($meta['ray']==='7c92e4a1b083d65f-SIN' && $meta['region']==='CN · 中国', '可信元数据');
check(BlockPage::metadata($headers,$s,'198.51.100.2')['ray']==='不可用', '客户端不一致拒绝元数据');
$headers['HTTP_CF_RAY']='<script>x</script>'; $headers['HTTP_CF_IPCOUNTRY']='<CN>';
check(BlockPage::metadata($headers,$s,'203.0.113.24')===['ray'=>'不可用','region'=>'未知'], '拒绝无效元数据');
$s['block_message']='<script>alert(1)</script>';
$data=BlockPage::context($s,403,'203.0.113.24',true,['category'=>'sqli']);
$html=BlockPage::render($data,'test-nonce');
check(strpos($html,'<h1>SQL 注入拦截</h1>')!==false, '结果类型传入主标题');
check(strpos($html,'<script>')===false && strpos($html,'&lt;script&gt;')!==false, '文案转义');
check(strpos($html,'<a ')===false && strpos($html,'<button')===false, '无返回或帮助操作');
check(strpos($html,'data:image/webp;base64,')!==false, '资源内联');
check(strpos($html,'RAY ID')!==false && strpos($html,'区域')!==false, '页脚元数据');
check(strpos($html,'示例数据')!==false, '预览标记');
check(strpos($html,'STAR SHIELD')===false && strpos($html,'LUMESHIELD')!==false, '品牌');
echo "Block page checks: $passed passed\n";
