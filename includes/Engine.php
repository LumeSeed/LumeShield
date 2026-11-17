<?php
/** 请求检测的纯逻辑：不写数据库、不输出页面，便于独立测试。 */
namespace LumeSeed\LumeShield;

defined('ABSPATH') || exit;

final class Ip
{
    public static function canonical(string $ip): string
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return '';
        }
        return (string) inet_ntop(inet_pton($ip));
    }

    public static function validRule(string $rule): bool
    {
        $parts = explode('/', $rule);
        if (count($parts) > 2 || self::canonical($parts[0]) === '') {
            return false;
        }
        if (count($parts) === 1) {
            return true;
        }
        // 必须先检查纯数字，避免 abc 被 intval 转成 0 而匹配所有地址。
        return $parts[1] !== '' && ctype_digit($parts[1])
            && (int) $parts[1] <= (strpos($parts[0], ':') === false ? 32 : 128);
    }

    public static function matches(string $ip, string $rule): bool
    {
        if (!self::validRule($rule) || self::canonical($ip) === '') {
            return false;
        }
        $parts = explode('/', $rule);
        $a = inet_pton($ip);
        $b = inet_pton($parts[0]);
        if (strlen($a) !== strlen($b)) {
            return false;
        }
        $bits = isset($parts[1]) ? (int) $parts[1] : strlen($a) * 8;
        $bytes = intdiv($bits, 8);
        $tail = $bits % 8;
        return substr($a, 0, $bytes) === substr($b, 0, $bytes)
            && ($tail === 0 || ((ord($a[$bytes]) ^ ord($b[$bytes])) & (255 << (8 - $tail))) === 0);
    }

    public static function listed(string $ip, array $rules): bool
    {
        foreach ($rules as $rule) {
            if (self::matches($ip, $rule)) {
                return true;
            }
        }
        return false;
    }

    public static function resolve(array $server, array $trusted, string $header): string
    {
        $peer = self::canonical((string) ($server['REMOTE_ADDR'] ?? ''));
        if ($peer === '' || !self::listed($peer, $trusted)) {
            return $peer;
        }
        $allowed = ['HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP'];
        if (!in_array($header, $allowed, true)) {
            return $peer;
        }
        $raw = (string) ($server[$header] ?? '');
        if ($raw === '' || strlen($raw) > 2048) {
            return $peer;
        }
        if ($header !== 'HTTP_X_FORWARDED_FOR') {
            return self::canonical(trim($raw)) ?: $peer;
        }
        $chain = array_map('trim', explode(',', $raw));
        if (count($chain) > 32) {
            return $peer;
        }
        foreach ($chain as $hop) {
            if (self::canonical($hop) === '') {
                return $peer;
            }
        }
        // 从最近的代理向左回溯，遇到第一个非可信节点即停止。
        $current = $peer;
        foreach (array_reverse($chain) as $hop) {
            if (!self::listed($current, $trusted)) {
                break;
            }
            $current = self::canonical($hop);
        }
        return $current;
    }
}

final class Inputs
{
    private array $items = [];
    private int $bytes = 0;
    private int $nodes = 0;
    private int $limit;

    public function __construct(int $limit)
    {
        $this->limit = $limit;
    }

    public function add(string $field, string $value, string $context): void
    {
        $this->bytes += strlen($value);
        if (count($this->items) >= 1024 || strlen($value) > $this->limit || $this->bytes > $this->limit * 4) {
            throw new \LengthException('请求字段数量或长度超出检测上限');
        }
        // 使用列表保存完整路径，不以叶子键覆盖前一个字段。
        $this->items[] = ['field' => $field, 'value' => $value, 'context' => $context];
    }

    public function walk($value, string $path, string $context, int $depth = 0): void
    {
        if (++$this->nodes > 2048 || $depth > 16) {
            throw new \LengthException('请求结构过深或节点过多');
        }
        if (is_array($value)) {
            foreach ($value as $key => $child) {
                if (is_string($key)) {
                    $this->add($path . '.[键名]', $key, 'key');
                }
                $this->walk($child, $path . '[' . rawurlencode((string) $key) . ']', $context, $depth + 1);
            }
        } elseif (is_string($value)) {
            $this->add($path, $value, $context);
        }
    }

    public function collect(array $get, array $post, array $cookies, string $uri, ?string $body, string $type): array
    {
        $this->add('URI', $uri, 'uri');
        $this->walk($get, 'GET', 'value');
        $this->walk($post, 'POST', 'value');
        $this->walk($cookies, 'COOKIE', 'value');
        if ($body !== null && $body !== '') {
            $this->add('请求体', $body, 'body');
            $mime = strtolower(trim(explode(';', $type)[0]));
            $this->items[count($this->items) - 1]['format'] = $mime === 'application/x-www-form-urlencoded' ? 'form' : '';
            if ($mime === 'application/json' || str_ends_with($mime, '+json')) {
                $this->items[count($this->items) - 1]['format'] = 'json';
                $decoded = json_decode($body, true, 18);
                if (json_last_error() !== JSON_ERROR_NONE) {
                    throw new \UnexpectedValueException('JSON 格式无效或结构过深');
                }
                // 解析 JSON 后检测转义字符，避免只扫描原始文本漏掉 Unicode 编码内容。
                $this->walk($decoded, 'JSON', 'value');
            }
        }
        return $this->items;
    }
}

final class Engine
{
    public static function path(string $uri): string
    {
        $path = explode('?', $uri, 2)[0];
        return $path === '' ? '/' : $path;
    }

    public static function pathListed(string $path, array $list): bool
    {
        $variants = [$path, rawurldecode($path), rawurldecode(rawurldecode($path))];
        foreach ($list as $rule) {
            foreach ($variants as $value) {
                if (str_ends_with($rule, '*')) {
                    if (strncmp($value, substr($rule, 0, -1), strlen($rule) - 1) === 0) {
                        return true;
                    }
                } elseif ($value === $rule) {
                    return true;
                }
            }
        }
        return false;
    }

    public static function uaListed(string $ua, array $list): bool
    {
        foreach ($list as $needle) {
            if ($needle !== '' && stripos($ua, $needle) !== false) {
                return true;
            }
        }
        return false;
    }

    public static function hit(string $id, string $category, string $field, string $name): array
    {
        return ['id' => $id, 'category' => $category, 'field' => $field, 'name' => $name];
    }

    public static function rules(): array
    {
        // 只保留有上下文的明显特征；不把 having、powershell 等普通词单独判为攻击。
        return [
            ['sql_union', 'sqli', 'SQL 联合查询特征', '~\bunion\s+(?:(?:all|distinct)\s+)?select\b~i'],
            ['sql_boolean', 'sqli', 'SQL 布尔拼接特征', '~[\x27\x22]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|[\x27\x22][^\x27\x22]{0,40}[\x27\x22]\s*=)~i'],
            ['sql_delay', 'sqli', 'SQL 延时函数特征', '~\b(?:sleep|benchmark|pg_sleep)\s*\(\s*\d+|\bwaitfor\s+delay\s+[\x27\x22]~i'],
            ['sql_file', 'sqli', 'SQL 文件读写特征', '~\binto\s+(?:out|dump)file\s+[\x27\x22]|\bload_file\s*\(~i'],
            ['sql_catalog', 'sqli', 'SQL 元数据查询特征', '~\binformation_schema\s*\.\s*(?:tables|columns|schemata)\b~i'],
            ['sql_stack', 'sqli', 'SQL 堆叠写操作特征', '~;\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b~i'],
            ['xss_script', 'xss', '脚本标签特征', '~<\s*/?\s*script\b~i'],
            ['xss_event', 'xss', 'HTML 事件属性特征', '~<[a-z][^>]{0,4096}\s+on[a-z]+\s*=~i'],
            ['xss_protocol', 'xss', '可执行链接协议特征', '~\b(?:javascript|vbscript)\s*:|\bdata\s*:\s*text/html~i'],
            ['xss_expression', 'xss', 'CSS 表达式特征', '~\bexpression\s*\(~i'],
            ['rce_php', 'rce', 'PHP 执行标签特征', '~<\?(?:php\b|=)~i'],
            ['rce_shell', 'rce', 'Shell 命令拼接特征', '~(?:;|&&|\|\||\|)\s*(?:/bin/)?(?:sh|bash|curl|wget|nc|whoami|cat)\b|\$\(\s*(?:id|whoami|cat|curl|wget)\b~i'],
            ['rce_eval', 'rce', '代码执行函数特征', '~\b(?:eval|system|shell_exec|passthru|assert)\s*\(\s*(?:\$_|[\x27\x22])~i'],
            ['path_traversal', 'traversal', '目录穿越特征', '~(?:^|[/\\\\=])\.\.[/\\\\]|^\.\.[/\\\\]~'],
            ['file_wrapper', 'traversal', '高风险文件协议特征', '~\b(?:php://(?:input|filter)|expect://|phar://)~i'],
            ['sensitive_path', 'probe', '敏感文件探测', '~(?:^|/)(?:\.git(?:/|$)|\.env(?:\.|/|$)|\.svn(?:/|$))~i'],
        ];
    }

    public static function variants(string $value): array
    {
        $decoded = rawurldecode(rawurldecode($value));
        $decoded = html_entity_decode($decoded, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $decoded = str_replace("\0", '', $decoded);
        $spaced = preg_replace('~/\*.*?\*/~s', ' ', $decoded);
        $joined = preg_replace('~/\*.*?\*/~s', '', $decoded);
        return array_unique([$value, $decoded, $spaced ?? $decoded, $joined ?? $decoded]);
    }

    public static function inspect(array $items, array $categories, string $path, string $ua, bool $uaExempt, array $exceptions = [], string $method = 'GET'): ?array
    {
        $rules = self::rules();
        // 在字段外层归一化，避免每条规则都重复解码同一内容。
        foreach ($items as $item) {
            $variants = self::variants($item['value']);
                foreach ($rules as [$id, $category, $name, $pattern]) {
                    if ($category === 'probe' || !in_array($category, $categories, true)) {
                        continue;
                    }
                    if ($exceptions && Exceptions::allows($exceptions, $method, $path, $item['field'], $id, $item['context'])) { continue; }
                    $masked = $exceptions ? Exceptions::mask($item, $exceptions, $method, $path, $id) : $item['value'];
                    foreach ($masked === $item['value'] ? $variants : self::variants($masked) as $value) {
                    $matched = preg_match($pattern, $value);
                    if ($matched === false) {
                        throw new \RuntimeException('规则匹配异常：' . $id);
                    }
                    if ($matched === 1) {
                        return self::hit($id, $category, $item['field'], $name);
                    }
                }
            }
        }
        if (in_array('probe', $categories, true) && !($exceptions && Exceptions::allows($exceptions, $method, $path, '路径', 'sensitive_path'))) {
            foreach (self::variants($path) as $value) {
                if (preg_match($rules[15][3], $value) === 1) {
                    return self::hit('sensitive_path', 'probe', '路径', '敏感文件探测');
                }
            }
        }
        // 不拦截 curl、WordPress、支付回调等通用客户端标识。
        if (!$uaExempt && in_array('scanner', $categories, true)
            && !($exceptions && Exceptions::allows($exceptions, $method, $path, 'User-Agent', 'scanner_ua'))
            && preg_match('~\b(?:sqlmap|nikto|masscan|nuclei|dirbuster)\b~i', $ua)) {
            return self::hit('scanner_ua', 'scanner', 'User-Agent', '扫描工具标识');
        }
        return null;
    }
}
