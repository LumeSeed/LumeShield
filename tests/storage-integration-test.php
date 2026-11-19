<?php
/** 仅针对隔离 WordPress 测试库运行，会重建插件日志表。须显式设置 LUMESHIELD_TEST_SITE=1。 */
if (getenv('LUMESHIELD_TEST_SITE') !== '1' || empty($argv[1])) { fwrite(STDERR, "Only isolated test sites: set LUMESHIELD_TEST_SITE=1 and pass wp-load.php\n"); exit(2); }
define('WP_CLI', true);
require $argv[1];
use LumeSeed\LumeShield\{Storage, Settings, Engine, Exceptions, Console, Admin};
$passed=0;
function check($ok,$name) { global $passed; if(!$ok){throw new RuntimeException($name);} $passed++; echo "通过：$name\n"; }
global $wpdb;
$logs=Storage::table('logs'); $rates=Storage::table('rates');
// 重建 1.2 原日志结构，保留一条代表历史数据的记录，再用生产迁移逻辑升级。
$wpdb->query("DROP TABLE IF EXISTS $logs");
$wpdb->query("CREATE TABLE $logs (
id bigint unsigned NOT NULL AUTO_INCREMENT, fingerprint char(64) NOT NULL, created_at bigint unsigned NOT NULL,
last_seen bigint unsigned NOT NULL, ip varchar(45) NOT NULL, method varchar(12) NOT NULL, path varchar(400) NOT NULL,
rule_id varchar(64) NOT NULL, category varchar(24) NOT NULL, field_name varchar(80) NOT NULL, action_name varchar(16) NOT NULL,
hits bigint unsigned NOT NULL DEFAULT 1, PRIMARY KEY(id), UNIQUE KEY fingerprint(fingerprint), KEY last_seen(last_seen),KEY category(category)) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
$wpdb->query($wpdb->prepare("INSERT INTO $logs (fingerprint,created_at,last_seen,ip,method,path,rule_id,category,field_name,action_name,hits) VALUES (%s,%d,%d,'192.0.2.1','POST','/legacy','xss_script','xss','POST','block',7)", str_repeat('a',64),time(),time()));
update_option('lumeseed_lumeshield_db_version','1.2.0');
$legacySettings=Settings::defaults();unset($legacySettings['log_mode'],$legacySettings['log_window'],$legacySettings['disabled_rules']);
$legacySettings['ip_deny']=['192.0.2.99'];update_option(Settings::OPTION,$legacySettings);
check(Storage::install(),'真实 dbDelta 从 1.2 升级到当前版本');
$legacy=$wpdb->get_row("SELECT * FROM $logs WHERE path='/legacy'", ARRAY_A);
check((int)$legacy['hits']===7 && $legacy['log_mode']==='redacted' && $legacy['payload']===null,'升级保留历史记录与次数');
check(Settings::get()['ip_deny']===['192.0.2.99'] && Settings::get()['log_mode']==='redacted','旧配置与新增默认值兼容');
check(Storage::install(),'重复升级可安全执行');
$wpdb->query("DELETE FROM $rates");
$s=Settings::defaults();$s['log_mode']='detailed';$s['log_window']=3600;update_option(Settings::OPTION,$s);
$_SERVER['REQUEST_URI']='/api?token=first';$_SERVER['HTTP_USER_AGENT']='first-agent';
$hit=['id'=>'xss_script','category'=>'xss','field'=>'POST[content]','name'=>'脚本标签','payload'=>'<script>first</script>'];
Storage::record($hit,'192.0.2.10','POST','/api','block');
$first=$wpdb->get_row("SELECT * FROM $logs WHERE ip='192.0.2.10'",ARRAY_A);
check($first && $first['request_uri']==='/api?token=first' && $first['user_agent']==='first-agent','首次详细 URI 和 UA 保存成功');
sleep(1);
$_SERVER['REQUEST_URI']='/api?token=second';$_SERVER['HTTP_USER_AGENT']='second-agent';$hit['payload']='second';
Storage::record($hit,'192.0.2.10','POST','/api','block');
Storage::record($hit,'192.0.2.10','POST','/api','block');
$row=$wpdb->get_row("SELECT * FROM $logs WHERE ip='192.0.2.10'",ARRAY_A);
check((int)$row['hits']===3 && (int)$wpdb->get_var("SELECT COUNT(*) FROM $logs WHERE ip='192.0.2.10'")===1,'重复三次只保留一行并累加到 3');
check($row['payload']==='<script>first</script>' && $row['request_uri']==='/api?token=first' && $row['user_agent']==='first-agent','重复事件不覆盖首次详情');
check((int)$row['last_seen']>(int)$first['last_seen'] && $row['created_at']===$first['created_at'],'更新最后时间，保持首次时间');
check(Exceptions::fromLog($row)==='POST /api POST[content] xss_script','真实日志可生成精确例外');
Storage::record($hit,'192.0.2.10','GET','/api','block');
$hit['field']='POST[other]';Storage::record($hit,'192.0.2.10','POST','/api','block');
check((int)$wpdb->get_var("SELECT COUNT(*) FROM $logs WHERE ip='192.0.2.10'")===3,'方法与字段不同分别聚合');
$s['log_mode']='redacted';update_option(Settings::OPTION,$s);$hit['field']='POST[content]';
Storage::record($hit,'192.0.2.10','POST','/api','block');
$redacted=$wpdb->get_row("SELECT * FROM $logs WHERE log_mode='redacted' AND ip='192.0.2.10'",ARRAY_A);
check($redacted['payload']==='' && $redacted['request_uri']==='' && $redacted['user_agent']==='','切回脱敏模式不再持久化详细内容');
check((int)$wpdb->get_var("SELECT COUNT(*) FROM $logs WHERE log_mode='detailed'")===3,'模式切换不覆盖已保存详情');
// 用历史时间修改聚合键，模拟旧窗口；新请求应生成新窗口记录。
$wpdb->update($logs,['fingerprint'=>str_repeat('b',64),'created_at'=>time()-7200,'last_seen'=>time()-7200],['id'=>$redacted['id']]);
Storage::record($hit,'192.0.2.10','POST','/api','block');
check((int)$wpdb->get_var("SELECT COUNT(*) FROM $logs WHERE log_mode='redacted' AND ip='192.0.2.10'")===2,'新窗口生成新记录');
// 详情只输出经过转义的内容。
wp_set_current_user(1);ob_start();Console::logDetails($row);$html=ob_get_clean();
check(str_contains($html,'&lt;script&gt;first&lt;/script&gt;') && !str_contains($html,'<script>first'),'载荷不会在管理界面执行');
check(str_contains($html,'admin.php?page=lumeseed-lumeshield'),'例外链接使用一级菜单入口');
$_GET=['outcome'=>'block','verb'=>'POST','from'=>wp_date('Y-m-d'),'until'=>wp_date('Y-m-d')];
$where=Console::where(Console::filters());
check((int)$wpdb->get_var("SELECT COUNT(*) FROM $logs WHERE $where")>=1,'日期方法处理方式筛选可执行');
ob_start();Console::overview();$html=ob_get_clean();
check(str_contains($html,'今日防护记录') && str_contains($html,'<meter') && $wpdb->last_error==='','概览统计 SQL 与展示正常');
$s=Settings::defaults();$s['retention_days']=1;update_option(Settings::OPTION,$s);
$wpdb->update($logs,['last_seen'=>time()-172800],['id'=>$legacy['id']]);Storage::cleanup();
check($wpdb->get_var($wpdb->prepare("SELECT id FROM $logs WHERE id=%d",$legacy['id']))===null,'保留期限清理包含旧记录');
check(get_option('lumeseed_lumeshield_db_version')===\LumeSeed\LumeShield\VERSION,'迁移完成后版本正确');
echo "总计 $passed 项集成检查通过。\n";
