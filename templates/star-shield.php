<?php
/** 动态文字统一转义；装饰图不包含品牌或用户数据。 */
defined('ABSPATH') || exit;
?>
<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="robots" content="noindex,nofollow">
<title><?= $e($data['title']) ?> · LumeShield</title>
<style nonce="<?= $e($nonce) ?>"><?= $css ?></style>
</head>
<body>
<div class="shield-page">
    <?php if ($scene !== ''): ?><img class="star-scene" src="<?= $e($scene) ?>" alt="" aria-hidden="true" width="1586" height="992"><?php endif; ?>
    <header class="site-header"><div class="brand"><img class="brand-star" src="<?= $e($emblem) ?>" alt="" aria-hidden="true" width="60" height="60"><span>LumeShield</span></div><span class="brand-en">LUMESHIELD</span></header>
    <main class="shield-main">
        <p class="eyebrow"><?= (int) $data['status'] ?> <span aria-hidden="true">/</span> 拦截类型</p>
        <h1><?= $e($data['title']) ?></h1>
        <div class="explanation"><p>LumeShield 已拦截本次请求。</p><p><?= $e($data['message']) ?></p></div>
        <?php if ($data['preview']): ?><p class="preview-badge">外观预览 · 示例数据 · 未执行拦截</p><?php endif; ?>
    </main>
    <p class="protected" aria-hidden="true">PROTECTED BY LUMESHIELD</p>
    <footer class="site-footer" aria-label="本次请求信息"><dl><div><dt>RAY ID</dt><dd><?= $e($data['ray']) ?></dd></div><div><dt>IP</dt><dd><?= $e($data['ip'] ?: '不可用') ?></dd></div><div><dt>区域</dt><dd><?= $e($data['region']) ?></dd></div></dl></footer>
</div>
</body>
</html>
