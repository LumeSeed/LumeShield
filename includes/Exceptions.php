<?php
/** 精细例外：精确方法、路径、单个规则与顶层字段组合，不把整个请求加入白名单。 */
namespace LumeSeed\LumeShield;
defined('ABSPATH') || exit;

final class Exceptions
{
    public static function fromLog(array $row): ?string
    {
        // 旧记录、脱敏路径和非顶层字段不推断成范围更大的通配例外。
        $path = (string) ($row['exception_path'] ?? '');
        $field = (string) ($row['field_name'] ?? '');
        $rule = (string) ($row['rule_id'] ?? '');
        if ($path === '') { return null; }
        if (in_array($rule, ['sensitive_path', 'scanner_ua'], true)) { $field = '*'; }
        elseif (!preg_match('~^(GET|POST|JSON|COOKIE)\[[A-Za-z_][A-Za-z0-9_-]{0,63}\]$~D', $field)) { return null; }
        $line = ($row['method'] ?? '') . ' ' . $path . ' ' . $field . ' ' . $rule;
        try { self::parse([$line]); return $line; }
        catch (\InvalidArgumentException $e) { return null; }
    }

    public static function parse($input): array
    {
        $lines = Settings::lines($input);
        if (count($lines) > 50) {
            throw new \InvalidArgumentException('精细例外最多 50 条');
        }
        $ids = array_column(Engine::rules(), 0);
        $ids[] = 'scanner_ua';
        $rows = [];
        foreach ($lines as $line) {
            $parts = preg_split('/\s+/', $line);
            if (count($parts) !== 4) {
                throw new \InvalidArgumentException('例外格式：请求方法 路径 字段 规则编号');
            }
            [$method, $path, $field, $rule] = $parts;
            if (!in_array($method, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'], true)
                || !preg_match('~^/[A-Za-z0-9/_\-.]*$~D', $path) || str_contains($path, '..') || str_contains($path, '//')
                || !in_array($rule, $ids, true)
                || ($field !== '*' && !preg_match('~^(GET|POST|JSON|COOKIE)\[[A-Za-z_][A-Za-z0-9_-]{0,63}\]$~D', $field))
                || ($field !== '*' && in_array($rule, ['sensitive_path', 'scanner_ua'], true))) {
                throw new \InvalidArgumentException('例外须使用精确方法、无查询串的 ASCII 路径、顶层字段及有效规则编号；不支持路径通配符');
            }
            $rows[] = compact('method', 'path', 'field', 'rule');
        }
        return $rows;
    }

    public static function allows(array $rows, string $method, string $path, string $field, string $rule, string $context = 'value'): bool
    {
        foreach ($rows as $row) {
            if ($row['method'] === $method && $row['path'] === $path && $row['rule'] === $rule
                && ($row['field'] === '*' || ($context === 'value' && $row['field'] === $field))) {
                return true;
            }
        }
        return false;
    }

    public static function mask(array $item, array $rows, string $method, string $path, string $rule): string
    {
        $value = $item['value'];
        // 原始 URI / 表单中也包含参数值：逐个替换获准字段的值，保留其他参数、键名与编码。
        if ($item['context'] === 'uri' || ($item['format'] ?? '') === 'form') {
            $uri = $item['context'] === 'uri';
            $offset = $uri ? strpos($value, '?') : false;
            if ($uri && $offset === false) { return $value; }
            $prefix = $uri ? substr($value, 0, $offset + 1) : '';
            $query = $uri ? substr($value, $offset + 1) : $value;
            $parts = explode('&', $query);
            foreach ($parts as &$part) {
                $pair = explode('=', $part, 2);
                $key = urldecode($pair[0]);
                // 只处理精确顶层标量键，不把带方括号、空格或点的键折叠成另一个字段。
                if (count($pair) === 2 && preg_match('~^[A-Za-z_][A-Za-z0-9_-]{0,63}$~D', $key)
                    && self::allows($rows, $method, $path, ($uri ? 'GET' : 'POST') . '[' . $key . ']', $rule)) {
                    $part = $pair[0] . '=LUMESHIELD_EXEMPT';
                }
            }
            unset($part);
            return $prefix . implode('&', $parts);
        }
        if (($item['format'] ?? '') === 'json') {
            // 已通过 JSON 格式验证；按原文令牌位置替换顶层字符串值，保留重复键和其他原始内容。
            preg_match_all('~"(?:\\\\.|[^"\\\\])*"|[{}\[\]:,]|-?[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|true|false|null~s', $value, $matches, PREG_OFFSET_CAPTURE);
            $depth = 0; $key = null; $expectKey = false; $expectValue = false; $spans = [];
            foreach ($matches[0] as [$token, $position]) {
                if ($depth === 0 && $token === '{') { $depth = 1; $expectKey = true; continue; }
                if ($depth === 1 && $expectKey && $token[0] === '"') {
                    $key = json_decode($token, true); $expectKey = false; continue;
                }
                if ($depth === 1 && $token === ':') { $expectValue = true; continue; }
                if ($depth === 1 && $expectValue) {
                    if ($token[0] === '"' && is_string($key) && preg_match('~^[A-Za-z_][A-Za-z0-9_-]{0,63}$~D', $key)
                        && self::allows($rows, $method, $path, 'JSON[' . $key . ']', $rule)) {
                        $spans[] = [$position, strlen($token)];
                    }
                    $expectValue = false;
                }
                if ($token === '{' || $token === '[') { $depth++; }
                if ($token === '}' || $token === ']') { $depth--; }
                if ($depth === 1 && $token === ',') { $expectKey = true; $key = null; }
            }
            foreach (array_reverse($spans) as [$position, $length]) {
                $value = substr_replace($value, '"LUMESHIELD_EXEMPT"', $position, $length);
            }
        }
        return $value;
    }
}
