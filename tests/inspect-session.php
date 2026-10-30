<?php
declare(strict_types=1);

ob_start();

if ($argc !== 2 || !preg_match('/^[a-f0-9]{64}$/', $argv[1])) {
    fwrite(STDERR, "usage: inspect-session.php <redacted-session-id>\n");
    exit(2);
}

$sid = $argv[1];
$redis = new Redis();
$redis->connect(getenv('MAILCOW_REDIS_HOST'), (int)getenv('MAILCOW_REDIS_PORT'), 3.0);
$redis->auth(getenv('MAILCOW_REDIS_PASSWORD'));

$iterator = null;
$found = [];
do {
    $keys = $redis->scan($iterator, '*' . $sid . '*', 100);
    if ($keys !== false) {
        $found = array_merge($found, $keys);
    }
} while ($iterator > 0);

foreach ($found as $key) {
    $value = (string)$redis->get($key);
    echo 'key_pattern=' . str_replace($sid, '<session-id>', $key) . PHP_EOL;
    echo 'ttl=' . $redis->ttl($key) . PHP_EOL;
    echo 'has_username=' . (str_contains($value, 'mailcow_cc_username|') ? 'yes' : 'no') . PHP_EOL;
    echo 'has_admin_role=' . (str_contains($value, 'mailcow_cc_role|s:5:"admin";') ? 'yes' : 'no') . PHP_EOL;
    echo 'has_user_agent=' . (str_contains($value, 'SESS_REMOTE_UA|') ? 'yes' : 'no') . PHP_EOL;
    echo 'has_sogo_allowed=' . (str_contains($value, 'sogo-sso-user-allowed|') ? 'yes' : 'no') . PHP_EOL;
    echo 'has_dual_login=' . (str_contains($value, 'dual-login|') ? 'yes' : 'no') . PHP_EOL;
    ini_set('session.use_cookies', '0');
    session_start();
    session_decode($value);
    $current = (string)($_SESSION['mailcow_cc_username'] ?? '');
    $allowed = $_SESSION['sogo-sso-user-allowed'] ?? [];
    echo 'role=' . ($_SESSION['mailcow_cc_role'] ?? 'missing') . PHP_EOL;
    echo 'current_is_email=' . (filter_var($current, FILTER_VALIDATE_EMAIL) ? 'yes' : 'no') . PHP_EOL;
    echo 'current_in_sogo_allowed=' . (is_array($allowed) && in_array($current, $allowed, true) ? 'yes' : 'no') . PHP_EOL;
    echo 'pending_pw_update=' . (!empty($_SESSION['pending_pw_update']) ? 'yes' : 'no') . PHP_EOL;
    echo 'pending_tfa_setup=' . (!empty($_SESSION['pending_tfa_setup']) ? 'yes' : 'no') . PHP_EOL;
    session_abort();
}

if ($found === []) {
    echo "session_key=not_found\n";
    exit(1);
}

