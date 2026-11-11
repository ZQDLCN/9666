<?php
/**
 * tvlist.php IP 透传代理（PHP 单文件）
 *
 * 作用：访问者打开本脚本时，把**访问者自己的 IP** 放进 X-Forwarded-For 传给
 *      http://38.75.136.137:88/api/tvlist.php，再把返回的清单原样回给访问者。
 *      这样每个用户拿到的清单和 usign token 都是按他自己的省份+运营商分支签发的，
 *      播放时不会被判 sign error。
 *
 * 部署：
 *   php -S 0.0.0.0:19196 tvlist_proxy.php
 *   或丢到 Apache/Nginx 站点根直接访问（单文件，无依赖）
 *
 * 用法：
 *   http://你的地址/tvlist_proxy.php            ← 正常用（订阅地址填这个）
 *   ?ip=123.53.118.4                             ← 强制指定来源 IP（调试用）
 *   ?mirror=2                                    ← 换第二个镜像 205.185.127.175:88
 *   ?debug=1                                     ← 只返回诊断信息，不取清单
 *   ?raw=1                                       ← 按上游原始 Content-Type 返回（默认 text/plain）
 *   ?filter=0                                    ← 不删广告频道（默认删）
 *   ?hdr=keep|pipe|strip                         ← 播放头处理（默认 strip）；filter=0&hdr=keep = 与上游逐字节一致
 *   ?trust=1                                     ← 强制信任代理头（CDN 只加了 XFF 又取不到时用）
 *   ?trust=0                                     ← 只用 REMOTE_ADDR
 *   ?src=cfg                                     ← 改成取配置接口 config.php，原样返回 JSON
 *   ?src=cfg&cfg=2                               ← 换配置源（1=yunshangtv 2=chenfengtv 3/4=两个 IP 镜像）
 *   ?src=cfg&list=1                              ← 取配置里 m3uUrl 指向的那份清单（带过滤/头处理）
 *
 * 关于 CDN：站点前面挂了 CDN 时 REMOTE_ADDR 是 CDN 节点 IP，直接用会查到 CDN 所在省份的分支。
 *   auto（默认）会按 CF-Connecting-IP / True-Client-IP / X-Real-IP / X-Forwarded-For 取真实访客 IP；
 *   若 CDN 回源 IP 固定，建议把其网段写进下面的 TRUSTED_PROXIES。
 *   另外务必在 CDN 侧对本 URL 关闭缓存，否则所有人拿到的是第一个访客那份清单。
 *
 * 上游 tvlist.php 的行为（已实测）：
 *   - 认 X-Forwarded-For / Client-IP 两个头，不认 X-Real-IP 等
 *   - 按「省 + 运营商」分成多套清单，不同分支的 usign 不能混用
 *   - 返回 TXT 清单（4,300～4,718 行），其中 kdsvod 已被预签名成 usign 直链
 */

const MIRRORS = [
    1 => '38.75.136.137:88',
    2 => '205.185.127.175:88',
];
const UPSTREAM_PATH = '/api/tvlist.php';
/** 配置接口（返回 JSON）：jsUrl / m3uUrl / epgUrl 等，同样按来源 IP 分支下发 */
const CFG_HOSTS = [
    1 => 'tvapius.yunshangtv.cc',
    2 => 'tvapi.chenfengtv.com',
    3 => '38.75.136.137:88',
    4 => '205.185.127.175:88',
];
const CFG_PATH = '/api/config.php';
const UA = 'okhttp/3.12.0';
const TIMEOUT = 25;

/**
 * 可信反代/CDN 的 IP 段（CIDR）。走 CDN 时把 CDN 的回源 IP 段填进来，
 * 这样即使 CDN 只加了 X-Forwarded-For 也能正确取到访客 IP。
 * 留空也能正常工作：下面 auto 模式会优先用 CDN 专属单值头。
 */
const TRUSTED_PROXIES = [
    // 示例：'104.16.0.0/12'      // Cloudflare
    // 示例：'203.0.113.0/24'     // 你自己的 CDN 回源段
];

const CDN_SINGLE_HEADERS = ['HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_CLIENT_IP'];

function is_private_ip(string $ip): bool
{
    return $ip === '' || $ip === '::1'
        || preg_match('/^(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|169\.254\.)/', $ip) === 1;
}

function ip_in_cidr(string $ip, string $cidr): bool
{
    [$net, $bits] = array_pad(explode('/', $cidr, 2), 2, null);
    $ipLong = ip2long($ip);
    $netLong = ip2long($net);
    if ($ipLong === false || $netLong === false) {
        return false;                          // 只做 IPv4 段匹配
    }
    $bits = $bits === null ? 32 : (int) $bits;
    if ($bits < 0 || $bits > 32) {
        return false;
    }
    $mask = $bits === 0 ? 0 : (~0 << (32 - $bits)) & 0xFFFFFFFF;
    return ($ipLong & $mask) === ($netLong & $mask);
}

function is_trusted_proxy(string $ip): bool
{
    foreach (TRUSTED_PROXIES as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

/**
 * 解析访问者真实 IP，返回 [ip, source, mode]
 * mode: auto（默认）| 1（强制信任代理头）| 0（只用 REMOTE_ADDR）
 * 关键：CDN 后 REMOTE_ADDR 是 CDN 节点 IP，直接转发上去就查错分支。
 */
function resolve_client_ip(array $srv, string $mode = 'auto'): array
{
    $remote = (string) ($srv['REMOTE_ADDR'] ?? '');

    if ($mode === '0') {
        return [$remote, 'REMOTE_ADDR', 'force-off'];
    }

    // 1) REMOTE_ADDR 是回环/内网 → 一定站在反代后面，直接信头
    $behind_local = is_private_ip($remote);

    // 2) 命中可信 CDN 段 → 信头
    $behind_trusted = $remote !== '' && is_trusted_proxy($remote);

    // 3) 强制模式 → 信头
    $force = $mode === '1';

    // CDN 专属单值头：浏览器/NAT 客户端发不出来，只能中间层写入，可单独信任
    $cdnIp = '';
    if (!$force && !$behind_local && !$behind_trusted) {
        foreach (CDN_SINGLE_HEADERS as $k) {
            $v = trim(explode(',', (string) ($srv[$k] ?? ''))[0]);
            if ($v !== '' && filter_var($v, FILTER_VALIDATE_IP)) {
                $cdnIp = $v;
                break;
            }
        }
    }

    if ($behind_local || $behind_trusted || $force) {
        foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_CLIENT_IP', 'HTTP_X_FORWARDED_FOR'] as $k) {
            $v = trim(explode(',', (string) ($srv[$k] ?? ''))[0]);
            if ($v !== '' && filter_var($v, FILTER_VALIDATE_IP)) {
                return [$v, str_replace('HTTP_', '', $k), $behind_local ? 'proxy-local' : ($behind_trusted ? 'proxy-trusted' : 'force-on')];
            }
        }
        if (!$force) {
            return [$remote, 'REMOTE_ADDR', 'proxy-no-header'];
        }
    }

    if ($cdnIp !== '') {
        return [$cdnIp, 'cdn-header', 'auto-cdn'];
    }

    // auto 模式兜底：XFF 第一跳与 REMOTE_ADDR 不同且是公网 → 视为 CDN 回源时才有的头
    // （普通播放器/浏览器发不出 X-Forwarded-For，这里信它最多只影响请求者自己的分支）
    if ($mode === 'auto') {
        $xff = trim(explode(',', (string) ($srv['HTTP_X_FORWARDED_FOR'] ?? ''))[0]);
        if ($xff !== '' && filter_var($xff, FILTER_VALIDATE_IP) && $xff !== $remote && !is_private_ip($xff)) {
            return [$xff, 'X_FORWARDED_FOR', 'auto-xff'];
        }
    }

    return [$remote, 'REMOTE_ADDR', 'direct'];
}

/** 取访问者真实 IP（兼容旧调用） */
function client_ip(): string
{
    return resolve_client_ip($_SERVER, trust_mode())[0];
}

/** 读 ?trust= 参数：auto（默认）/ 1 强制信头 / 0 只用 REMOTE_ADDR */
function trust_mode(): string
{
    if (!isset($_GET['trust'])) {
        return 'auto';
    }
    $v = strtolower(trim((string) $_GET['trust']));
    if (in_array($v, ['1', 'on', 'true', 'cdn', 'proxy'], true)) {
        return '1';
    }
    if (in_array($v, ['0', 'off', 'false', 'direct'], true)) {
        return '0';
    }
    return 'auto';
}

/** 只允许合法的 IPv4/IPv6，避免头注入 */
function clean_ip(?string $ip): ?string
{
    if ($ip === null || $ip === '') {
        return null;
    }
    $ip = trim($ip);
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : null;
}

/** 发请求：curl 优先，缺 curl 时退化到 file_get_contents */
function fetch_upstream(string $url, array $headers): array
{
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => TIMEOUT,
            CURLOPT_USERAGENT      => UA,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_ENCODING       => '',
        ]);
        $body = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $ctype = (string) curl_getinfo($ch, CURLINFO_CONTENT_TYPE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($body === false) {
            return [0, '', '', $err];
        }
        return [$code, $body, $ctype, ''];
    }

    $hdr = "User-Agent: " . UA . "\r\n";
    foreach ($headers as $h) {
        $hdr .= $h . "\r\n";
    }
    $ctx = stream_context_create(['http' => [
        'method'        => 'GET',
        'header'        => $hdr,
        'timeout'       => TIMEOUT,
        'ignore_errors' => true,
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    if ($body === false) {
        return [0, '', '', 'file_get_contents failed'];
    }
    $code = 200;
    if (isset($http_response_header[0]) && preg_match('#\s(\d{3})\s#', $http_response_header[0], $m)) {
        $code = (int) $m[1];
    }
    return [$code, $body, '', ''];
}

// ---------------------------------------------------------------- 主流程
$trust  = trust_mode();
[$ip, $ipSource, $ipMode] = resolve_client_ip($_SERVER, $trust);
$ip     = clean_ip($_GET['ip'] ?? null) ?: clean_ip($ip);
$mirror = (int) ($_GET['mirror'] ?? 1);
$mirror = MIRRORS[$mirror] ?? MIRRORS[1];
$debug  = isset($_GET['debug']);
$raw    = isset($_GET['raw']);
$json   = isset($_GET['json']) && $_GET['json'] !== '0';   // src=cfg 时：1=返回配置 JSON，默认=继续取 m3uUrl 指向的清单
// 上游源：tvlist=电视清单接口（默认） / cfg=配置接口 config.php（返回 JSON）
$src = isset($_GET['src']) ? strtolower(trim((string) $_GET['src'])) : 'tvlist';
if (!in_array($src, ['tvlist', 'cfg'], true)) {
    $src = 'tvlist';
}
$cfg_host = CFG_HOSTS[(int) ($_GET['cfg'] ?? 1)] ?? CFG_HOSTS[1];
$upstream = ($src === 'cfg') ? 'http://' . $cfg_host . CFG_PATH : 'http://' . $mirror . UPSTREAM_PATH;

if ($debug) {
    header('Content-Type: application/json; charset=utf-8');
    $seen = [];
    foreach (['REMOTE_ADDR', 'HTTP_CF_CONNECTING_IP', 'HTTP_TRUE_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_USER_AGENT'] as $k) {
        $seen[$k] = $_SERVER[$k] ?? null;
    }
    // 自检：用同一套函数跑几种典型场景，确认判断逻辑正确
    $cases = [
        '直连无CDN'            => ['REMOTE_ADDR' => '123.53.118.4'],
        'CDN只加XFF'           => ['REMOTE_ADDR' => '172.20.1.9', 'HTTP_X_FORWARDED_FOR' => '123.53.118.4, 172.20.1.9'],
        'CDN加X-Real-IP'       => ['REMOTE_ADDR' => '43.249.1.20', 'HTTP_X_REAL_IP' => '123.53.118.4'],
        '宝塔本地回环+CDN头'   => ['REMOTE_ADDR' => '127.0.0.1', 'HTTP_X_FORWARDED_FOR' => '123.53.118.4'],
    ];
    $selftest = [];
    foreach ($cases as $name => $srv) {
        [$cip, $src, $m] = resolve_client_ip($srv, $trust);
        $selftest[$name] = ['ip' => $cip, 'source' => $src, 'mode' => $m];
    }
    echo json_encode([
        'client_ip'     => $ip,
        'ip_source'     => $ipSource,
        'ip_mode'       => $ipMode,
        'trust_param'   => $trust,
        'remote_addr'   => $_SERVER['REMOTE_ADDR'] ?? '',
        'headers_seen'  => $seen,
        'trusted_proxies' => TRUSTED_PROXIES,
        'mirror'        => $mirror,
        'src'           => $src,
        'cfg_host'      => $cfg_host,
        'upstream'      => $upstream,
        'forward_headers' => $ip ? ['X-Forwarded-For: ' . $ip, 'Client-IP: ' . $ip] : [],
        'selftest'      => $selftest,
    ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    return true;
}

// 组转发头：X-Forwarded-For 与 Client-IP 上游都认，两个都给
// 只转发公网 IP：回环/内网地址（本机调试、局域网访问）不转发，让上游按代理机自己的 IP 判分支
$fwd = [];
if ($ip !== null) {
    $priv = !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    if (!$priv) {
        $fwd[] = 'X-Forwarded-For: ' . $ip;
        $fwd[] = 'Client-IP: ' . $ip;
    }
}

// ---------------------------------------------------------------- 广告频道过滤
/** 广告专用的两个域名/路径（实测承载 18 个广告频道 × 2 = 36 条） */
const AD_URL_PATTERNS = [
    'live1/ad.m3u8',
    'enai1.cn',
];
/** 广告频道名（含变体，用包含匹配） */
const AD_NAME_KEYWORDS = [
    '休闲推荐', '日用百货', '随心看', '热门推荐', '今日热销',
    '乐享好物', '猜你喜欢', '新品特惠',
];

/**
 * 把一行里的 @@Referer=..@@ 播放头规范化。
 * mode: strip=直接剥掉（TVBox 能播，但部分频道会 403）/ pipe=转成 |Referer=.. 写法（FongMi 内核认）/ keep=原样
 */
function normalize_line(string $line, string $mode): array
{
    if ($mode === 'keep' || $line === '' || strpos($line, '@@') === false) {
        return [$line, false];
    }
    [$name, $url] = explode(',', $line, 2);

    $headers = [];
    if (preg_match_all('/@@(.*?)@@/s', $url, $blocks)) {
        foreach ($blocks[1] as $b) {
            if (preg_match_all('/(Referer|User-Agent|X-Forwarded-For)=([^@]*)/i', $b, $mm, PREG_SET_ORDER)) {
                foreach ($mm as $one) {
                    $k = strtolower($one[1]);
                    if ($k === 'user-agent') {
                        $key = 'User-Agent';
                    } elseif ($k === 'x-forwarded-for') {
                        $key = 'X-Forwarded-For';
                    } else {
                        $key = 'Referer';
                    }
                    $headers[$key] = trim($one[2]);
                }
            }
        }
    }
    $url = rtrim(preg_replace('/@@.*?@@/s', '', $url), '@');

    if ($mode === 'pipe' && $headers) {
        $pairs = [];
        foreach ($headers as $k => $v) {
            $pairs[] = $k . '=' . $v;
        }
        $url .= '|' . implode('&', $pairs);
    }
    return [$name . ',' . $url, true];
}

/** 全表处理播放头，返回 [新正文, 改写条数]。mode=keep 时原样返回，保证与上游逐字节一致 */
function normalize_all(string $body, string $mode): array
{
    if ($mode === 'keep') {
        return [$body, 0];
    }
    $eol = (strpos($body, "\r\n") !== false) ? "\r\n" : "\n";
    $n = 0;
    $out = [];
    foreach (preg_split('/\r?\n/', $body) as $l) {
        $t = rtrim($l, "\r");
        if ($t === '') {
            $out[] = '';                     // 空行保留，不做压缩
            continue;
        }
        [$t, $changed] = normalize_line($t, $mode);
        if ($changed) {
            $n++;
        }
        $out[] = $t;
    }
    return [implode($eol, $out), $n];
}

function is_ad_line(string $line): bool
{
    if ($line === '' || strpos($line, ',') === false) {
        return false;
    }
    // #genre# 分组行不过滤
    if (strpos($line, '#genre#') !== false) {
        return false;
    }
    [$name, $url] = explode(',', $line, 2);
    foreach (AD_URL_PATTERNS as $p) {
        if (stripos($url, $p) !== false) {
            return true;
        }
    }
    foreach (AD_NAME_KEYWORDS as $k) {
        if (strpos($name, $k) !== false) {
            return true;
        }
    }
    return false;
}

/** 删掉广告行，顺带把变空的分组头也删掉；返回 [新正文, 删除条数]。保留原换行风格与空行 */
function filter_ads(string $body): array
{
    $eol = (strpos($body, "\r\n") !== false) ? "\r\n" : "\n";
    $lines = explode($eol === "\r\n" ? "\r\n" : "\n", $body);
    $kept = [];
    $pending_genre = null;     // 还没确认有内容的 #genre# 行
    $removed = 0;

    foreach ($lines as $l) {
        $t = rtrim($l, "\r");
        if (trim($t) === '') {
            $kept[] = '';         // 空行原样保留
            continue;
        }
        if (strpos($t, '#genre#') !== false) {
            $pending_genre = $t;
            continue;
        }
        if (is_ad_line(trim($t))) {
            $removed++;
            continue;
        }
        if ($pending_genre !== null) {
            $kept[] = $pending_genre;
            $pending_genre = null;
        }
        $kept[] = $t;
    }
    return [implode($eol, $kept), $removed];
}

[$code, $body, $ctype, $err] = fetch_upstream($upstream, $fwd);

if ($code !== 200 || $body === '') {
    http_response_code(502);
    header('Content-Type: text/plain; charset=utf-8');
    echo "上游取数失败：code={$code} err={$err}\n";
    return true;
}

// ---------------------------------------------------------- src=cfg：配置接口
$cfg_m3u = '';
if ($src === 'cfg') {
    $j = json_decode($body, true);
    if (!is_array($j)) {
        http_response_code(502);
        header('Content-Type: text/plain; charset=utf-8');
        echo "上游 config.php 返回的不是合法 JSON（可能是错误页）\n";
        return true;
    }
    $cfg_m3u = (string) ($j['m3uData']['m3uUrl'] ?? '');

    if ($json) {
        // ?json=1：原样返回 JSON，只补诊断头，不做任何改写
        header('Content-Type: application/json; charset=UTF-8');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
        header('Expires: 0');
        header('X-Client-IP: ' . ($ip ?? 'unknown'));
        header('X-Upstream: ' . $upstream);
        header('X-Config-M3u: ' . ($cfg_m3u !== '' ? basename(parse_url($cfg_m3u, PHP_URL_PATH) ?? '') : 'none'));
        echo $body;
        return true;
    }

    // list=1：顺带取回 m3uUrl 指向的那份清单（相当于一步到位拿到可播放清单）
    if ($cfg_m3u === '' || !preg_match('#^http#i', $cfg_m3u)) {
        http_response_code(502);
        header('Content-Type: text/plain; charset=utf-8');
        echo "config.php 里没有可用的 m3uUrl：{$cfg_m3u}\n";
        return true;
    }
    $upstream = $cfg_m3u;
    [$code, $body, $ctype, $err] = fetch_upstream($cfg_m3u, $fwd);
    if ($code !== 200 || $body === '') {
        http_response_code(502);
        header('Content-Type: text/plain; charset=utf-8');
        echo "取 m3uUrl 失败：code={$code} err={$err} url={$cfg_m3u}\n";
        return true;
    }
    $ctype = '';
}

// 播放头处理：默认 strip（剥掉 @@Referer=..@@）；?hdr=pipe 转成 |Referer=.. ；?hdr=keep 不动
$hdr_mode = isset($_GET['hdr']) ? (string) $_GET['hdr'] : 'strip';
if (!in_array($hdr_mode, ['strip', 'pipe', 'keep'], true)) {
    $hdr_mode = 'strip';
}
[$body, $n_hdr] = normalize_all($body, $hdr_mode);

// 默认过滤广告频道；?filter=0 关闭
$do_filter = !isset($_GET['filter']) || $_GET['filter'] !== '0';
$removed = 0;
if ($do_filter) {
    [$body, $removed] = filter_ads($body);
}

header('Content-Type: ' . ($raw && $ctype !== '' ? $ctype : 'text/plain; charset=UTF-8'));
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Client-IP: ' . ($ip ?? 'unknown'));
header('X-Upstream: ' . $upstream);
header('X-Ad-Filtered: ' . $removed);
header('X-Hdr-Mode: ' . $hdr_mode . ' (' . $n_hdr . ')');
if ($cfg_m3u !== '') {
    header('X-Config-M3u: ' . basename(parse_url($cfg_m3u, PHP_URL_PATH) ?? ''));
}
echo $body;
return true;
