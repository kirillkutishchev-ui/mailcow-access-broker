<?php
declare(strict_types=1);

const DATA_DIR = '/var/lib/mailcow-access';

function env_required(string $name): string
{
    $value = getenv($name);
    if ($value === false || trim($value) === '') {
        throw new RuntimeException("Missing required environment variable: {$name}");
    }
    return trim($value);
}

function env_value(string $name, string $default = ''): string
{
    $value = getenv($name);
    return $value === false ? $default : trim($value);
}

function h(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function db(): PDO
{
    static $pdo;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $pdo = new PDO('sqlite:' . DATA_DIR . '/broker.sqlite3', null, null, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
    $pdo->exec('PRAGMA journal_mode=WAL');
    $pdo->exec('PRAGMA foreign_keys=ON');
    $pdo->exec(<<<'SQL'
CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('admin', 'mailbox')),
    token_hash TEXT NOT NULL UNIQUE,
    mailbox TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    use_count INTEGER NOT NULL DEFAULT 0,
    last_used_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_links_active ON links(revoked_at, kind);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT NOT NULL,
    event TEXT NOT NULL,
    link_id INTEGER,
    link_name TEXT,
    kind TEXT,
    ip TEXT NOT NULL,
    result TEXT NOT NULL,
    mailbox TEXT,
    actor TEXT,
    user_agent TEXT,
    FOREIGN KEY(link_id) REFERENCES links(id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(occurred_at);
CREATE INDEX IF NOT EXISTS idx_audit_ip_time ON audit(ip, occurred_at);
SQL);

    $days = max(1, (int)env_value('AUDIT_RETENTION_DAYS', '90'));
    $stmt = $pdo->prepare("DELETE FROM audit WHERE occurred_at < datetime('now', :retention)");
    $stmt->execute([':retention' => '-' . $days . ' days']);
    return $pdo;
}

function mailcow_db(): PDO
{
    static $pdo;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        env_required('MAILCOW_DB_HOST'),
        (int)env_value('MAILCOW_DB_PORT', '3306'),
        env_required('MAILCOW_DB_NAME')
    );
    $pdo = new PDO($dsn, env_required('MAILCOW_DB_USER'), env_required('MAILCOW_DB_PASSWORD'), [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 3,
    ]);
    return $pdo;
}

function ip_in_cidr(string $ip, string $cidr): bool
{
    $cidr = trim($cidr);
    if ($cidr === '') {
        return false;
    }
    if (!str_contains($cidr, '/')) {
        $cidr .= str_contains($cidr, ':') ? '/128' : '/32';
    }
    [$network, $bits] = explode('/', $cidr, 2);
    $ipBin = @inet_pton($ip);
    $networkBin = @inet_pton($network);
    if ($ipBin === false || $networkBin === false || strlen($ipBin) !== strlen($networkBin)) {
        return false;
    }
    $bits = (int)$bits;
    $maxBits = strlen($ipBin) * 8;
    if ($bits < 0 || $bits > $maxBits) {
        return false;
    }
    $bytes = intdiv($bits, 8);
    $remainder = $bits % 8;
    if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($networkBin, 0, $bytes)) {
        return false;
    }
    if ($remainder === 0) {
        return true;
    }
    $mask = (0xff << (8 - $remainder)) & 0xff;
    return (ord($ipBin[$bytes]) & $mask) === (ord($networkBin[$bytes]) & $mask);
}

function ip_in_list(string $ip, string $list): bool
{
    foreach (preg_split('/[\s,;]+/', $list, -1, PREG_SPLIT_NO_EMPTY) as $cidr) {
        if (ip_in_cidr($ip, $cidr)) {
            return true;
        }
    }
    return false;
}

function request_ip(): string
{
    $remote = $_SERVER['REMOTE_ADDR'] ?? '';
    if (ip_in_list($remote, env_value('TRUSTED_PROXY_CIDRS', '127.0.0.1/32'))) {
        $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
        if ($forwarded !== '') {
            $candidate = trim(explode(',', $forwarded)[0]);
            if (filter_var($candidate, FILTER_VALIDATE_IP)) {
                return $candidate;
            }
        }
        $real = trim($_SERVER['HTTP_X_REAL_IP'] ?? '');
        if (filter_var($real, FILTER_VALIDATE_IP)) {
            return $real;
        }
    }
    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

function owner_ip_allowed(): bool
{
    return ip_in_list(request_ip(), env_required('TRUSTED_ADMIN_CIDRS'));
}

function audit(string $event, string $result, ?array $link = null, ?string $mailbox = null, ?string $actor = null): void
{
    $stmt = db()->prepare(<<<'SQL'
INSERT INTO audit (occurred_at, event, link_id, link_name, kind, ip, result, mailbox, actor, user_agent)
VALUES (datetime('now'), :event, :link_id, :link_name, :kind, :ip, :result, :mailbox, :actor, :user_agent)
SQL);
    $stmt->execute([
        ':event' => $event,
        ':link_id' => $link['id'] ?? null,
        ':link_name' => $link['name'] ?? null,
        ':kind' => $link['kind'] ?? null,
        ':ip' => request_ip(),
        ':result' => $result,
        ':mailbox' => $mailbox ?? ($link['mailbox'] ?? null),
        ':actor' => $actor,
        ':user_agent' => substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 500),
    ]);
}

function rate_limited(): bool
{
    $stmt = db()->prepare("SELECT COUNT(*) FROM audit WHERE ip = :ip AND result = 'denied' AND occurred_at >= datetime('now', '-10 minutes')");
    $stmt->execute([':ip' => request_ip()]);
    return (int)$stmt->fetchColumn() >= 20;
}

function mailcow_admin_active(string $username): bool
{
    $stmt = mailcow_db()->prepare('SELECT 1 FROM admin WHERE username = :username AND active = 1 AND superadmin = 1 LIMIT 1');
    $stmt->execute([':username' => $username]);
    return (bool)$stmt->fetchColumn();
}

function mailbox_active(string $username): bool
{
    $stmt = mailcow_db()->prepare('SELECT 1 FROM mailbox WHERE username = :username AND active = 1 LIMIT 1');
    $stmt->execute([':username' => strtolower($username)]);
    return (bool)$stmt->fetchColumn();
}

function login_mailcow_mailbox(string $mailbox, string $password): ?string
{
    $internalBase = rtrim(env_required('MAILCOW_INTERNAL_URL'), '/');
    $publicHost = parse_url(env_required('MAILCOW_BASE_URL'), PHP_URL_HOST);
    if (!is_string($publicHost) || $publicHost === '') {
        throw new RuntimeException('Invalid MAILCOW_BASE_URL');
    }

    $headers = [
        'Host: ' . $publicHost,
        'User-Agent: ' . substr($_SERVER['HTTP_USER_AGENT'] ?? 'Mailcow-Access-Broker', 0, 300),
        'X-Forwarded-Proto: https',
        'X-Real-IP: ' . request_ip(),
    ];
    $tlsVerify = env_value('MAILCOW_INTERNAL_TLS_VERIFY', '1') === '1';
    $getContext = stream_context_create([
        'http' => [
            'method' => 'GET',
            'header' => implode("\r\n", $headers),
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => 8,
        ],
        'ssl' => ['verify_peer' => $tlsVerify, 'verify_peer_name' => $tlsVerify],
    ]);
    $loginPage = @file_get_contents($internalBase . '/', false, $getContext);
    $getHeaders = $http_response_header ?? [];
    if ($loginPage === false) {
        throw new RuntimeException('Mailcow login page is unavailable');
    }
    $cookieName = env_value('MAILCOW_SESSION_COOKIE', 'MCSESSID');
    $sessionId = response_cookie($getHeaders, $cookieName);
    if ($sessionId === ''
        || !preg_match('/value=["\']([a-f0-9]{64})["\'][^>]*>.*?attr\(["\']name["\'],\s*["\']csrf_token["\']\)/is', $loginPage, $csrfMatch)) {
        throw new RuntimeException('Mailcow login form changed');
    }
    $body = http_build_query([
        'login_user' => $mailbox,
        'pass_user' => $password,
        'csrf_token' => $csrfMatch[1],
    ], '', '&', PHP_QUERY_RFC3986);
    $headers[] = 'Content-Type: application/x-www-form-urlencoded';
    $headers[] = 'Cookie: ' . $cookieName . '=' . $sessionId;
    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => implode("\r\n", $headers),
            'content' => $body,
            'ignore_errors' => true,
            'follow_location' => 0,
            'timeout' => 8,
        ],
        'ssl' => [
            'verify_peer' => $tlsVerify,
            'verify_peer_name' => $tlsVerify,
        ],
    ]);
    $response = @file_get_contents($internalBase . '/', false, $context);
    $responseHeaders = $http_response_header ?? [];
    unset($password, $body);
    if ($response === false && $responseHeaders === []) {
        throw new RuntimeException('Mailcow login endpoint is unavailable');
    }

    $location = '';
    foreach ($responseHeaders as $header) {
        if (stripos($header, 'Location:') === 0) {
            $location = trim(substr($header, 9));
        }
    }
    $rotatedSessionId = response_cookie($responseHeaders, $cookieName);
    if ($rotatedSessionId !== '') {
        $sessionId = $rotatedSessionId;
    }
    $locationPath = parse_url($location, PHP_URL_PATH);
    if (!is_string($locationPath)
        || !in_array(rtrim($locationPath, '/'), ['/user', '/SOGo/so'], true)
        || $sessionId === '') {
        return null;
    }
    setcookie($cookieName, $sessionId, [
        'expires' => 0,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ]);
    return rtrim($locationPath, '/') === '/SOGo/so' ? '/SOGo/so/' : '/user';
}

function response_cookie(array $headers, string $cookieName): string
{
    foreach ($headers as $header) {
        if (stripos($header, 'Set-Cookie:') === 0
            && preg_match('/(?:^|\s)' . preg_quote($cookieName, '/') . '=([^;\s]+)/', substr($header, 11), $match)) {
            return $match[1];
        }
    }
    return '';
}

function php_session_encode_array(array $values): string
{
    $encoded = '';
    foreach ($values as $key => $value) {
        if (!preg_match('/^[A-Za-z0-9_]+$/', (string)$key)) {
            throw new RuntimeException('Invalid PHP session key');
        }
        $encoded .= $key . '|' . serialize($value);
    }
    return $encoded;
}

function create_mailcow_admin_session(): string
{
    $username = env_required('MAILCOW_ADMIN_USERNAME');
    if (!mailcow_admin_active($username)) {
        throw new RuntimeException('Configured Mailcow superadmin is missing or inactive');
    }

    $sessionId = bin2hex(random_bytes(32));
    $csrf = bin2hex(random_bytes(32));
    $payload = php_session_encode_array([
        'access_all_exception' => '0',
        'CSRF' => ['TOKEN' => $csrf],
        'SESS_REMOTE_UA' => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'LAST_ACTIVITY' => time(),
        'mailcow_cc_username' => $username,
        'mailcow_cc_role' => 'admin',
    ]);

    $redis = new Redis();
    $redis->connect(env_required('MAILCOW_REDIS_HOST'), (int)env_value('MAILCOW_REDIS_PORT', '6379'), 3.0);
    $redis->auth(env_required('MAILCOW_REDIS_PASSWORD'));
    $prefix = env_value('MAILCOW_SESSION_PREFIX', 'PHPREDIS_SESSION:');
    $ttl = max(300, (int)env_value('MAILCOW_SESSION_TTL', '10800'));
    $redis->setEx($prefix . $sessionId, $ttl, $payload);
    $redis->close();

    $cookie = [
        'expires' => 0,
        'path' => '/',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Lax',
    ];
    setcookie(env_value('MAILCOW_SESSION_COOKIE', 'MCSESSID'), $sessionId, $cookie);
    return $username;
}

function token_string(): string
{
    return rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
}

function token_hash(string $token): string
{
    return hash('sha256', $token);
}

function find_link(string $token, string $kind): ?array
{
    if (!preg_match('/^[A-Za-z0-9_-]{43}$/', $token)) {
        return null;
    }
    $stmt = db()->prepare('SELECT * FROM links WHERE token_hash = :hash AND kind = :kind LIMIT 1');
    $stmt->execute([':hash' => token_hash($token), ':kind' => $kind]);
    $row = $stmt->fetch();
    return $row ?: null;
}

function mark_used(array $link): void
{
    $stmt = db()->prepare("UPDATE links SET use_count = use_count + 1, last_used_at = datetime('now') WHERE id = :id");
    $stmt->execute([':id' => $link['id']]);
}

function broker_csrf(): string
{
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf'];
}

function require_broker_csrf(): void
{
    $token = $_POST['csrf'] ?? '';
    if (!is_string($token) || !hash_equals($_SESSION['csrf'] ?? '', $token)) {
        $_SESSION['error'] = 'Страница управления была обновлена. Повторите действие.';
        redirect_to('/access-links/');
    }
}

function redirect_to(string $url): never
{
    header('Location: ' . $url, true, 303);
    exit;
}

function not_found(): never
{
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    exit("Not Found\n");
}

