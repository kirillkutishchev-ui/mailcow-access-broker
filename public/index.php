<?php
declare(strict_types=1);

require_once '/var/www/src/bootstrap.php';

header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; form-action 'self' " . env_required('MAILCOW_BASE_URL') . "; frame-ancestors 'none'; base-uri 'none'");
header('Cache-Control: no-store');

session_name('MCABSESSID');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/access-links/',
    'secure' => true,
    'httponly' => true,
    'samesite' => 'Strict',
]);
session_start();

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
$method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');

if ($path === '/health') {
    header('Content-Type: text/plain; charset=utf-8');
    try {
        db()->query('SELECT 1');
        echo "ok\n";
    } catch (Throwable $e) {
        http_response_code(503);
        echo "unhealthy\n";
    }
    exit;
}

if ($path === '/admin') {
    if (!owner_ip_allowed()) {
        audit('ip_admin_login', 'denied', null, null, env_required('MAILCOW_ADMIN_USERNAME'));
        not_found();
    }
    try {
        $actor = create_mailcow_admin_session();
        audit('ip_admin_login', 'success', null, null, $actor);
        redirect_to(rtrim(env_required('MAILCOW_BASE_URL'), '/') . '/admin/dashboard');
    } catch (Throwable $e) {
        error_log('Admin IP login failed: ' . $e->getMessage());
        audit('ip_admin_login', 'error', null, null, env_required('MAILCOW_ADMIN_USERNAME'));
        http_response_code(503);
        exit('Service unavailable');
    }
}

if (preg_match('#^/access/([A-Za-z0-9_-]+)$#', $path, $match)) {
    if (rate_limited()) {
        http_response_code(429);
        exit('Too many requests');
    }
    $link = find_link($match[1], 'admin');
    if (!$link || $link['revoked_at'] !== null) {
        audit('admin_link_use', 'denied', $link);
        not_found();
    }
    try {
        $actor = create_mailcow_admin_session();
        mark_used($link);
        audit('admin_link_use', 'success', $link, null, $actor);
        redirect_to(rtrim(env_required('MAILCOW_BASE_URL'), '/') . '/admin/dashboard');
    } catch (Throwable $e) {
        error_log('Admin link login failed: ' . $e->getMessage());
        audit('admin_link_use', 'error', $link);
        http_response_code(503);
        exit('Service unavailable');
    }
}

if (preg_match('#^/mailbox-access/([A-Za-z0-9_-]+)$#', $path, $match)) {
    if (rate_limited()) {
        http_response_code(429);
        exit('Too many requests');
    }
    $link = find_link($match[1], 'mailbox');
    if (!$link || $link['revoked_at'] !== null || !$link['mailbox'] || !mailbox_active($link['mailbox'])) {
        audit('mailbox_link_open', 'denied', $link);
        not_found();
    }
    if ($method === 'POST') {
        $password = (string)($_POST['password'] ?? '');
        if ($password === '') {
            audit('mailbox_link_login', 'denied', $link, $link['mailbox']);
            render_mailbox_login($link['mailbox'], $link['name'], 'Введите пароль.');
            exit;
        }
        try {
            $destination = login_mailcow_mailbox($link['mailbox'], $password);
            if ($destination === null) {
                audit('mailbox_link_login', 'denied', $link, $link['mailbox']);
                render_mailbox_login($link['mailbox'], $link['name'], 'Неверный пароль.');
                exit;
            }
            mark_used($link);
            audit('mailbox_link_login', 'success', $link, $link['mailbox']);
            redirect_to(rtrim(env_required('MAILCOW_BASE_URL'), '/') . $destination);
        } catch (Throwable $e) {
            error_log('Mailbox link login failed: ' . $e->getMessage());
            audit('mailbox_link_login', 'error', $link, $link['mailbox']);
            http_response_code(503);
            exit('Service unavailable');
        }
    }
    audit('mailbox_link_open', 'success', $link, $link['mailbox']);
    render_mailbox_login($link['mailbox'], $link['name']);
    exit;
}

if ($path === '/access-links' || $path === '/access-links/') {
    if (!owner_ip_allowed()) {
        audit('management_open', 'denied', null, null, env_required('MAILCOW_ADMIN_USERNAME'));
        not_found();
    }

    if ($method === 'POST') {
        require_broker_csrf();
        $action = $_POST['action'] ?? '';
        if ($action === 'create') {
            $name = trim((string)($_POST['name'] ?? ''));
            $kind = (string)($_POST['kind'] ?? '');
            $mailbox = strtolower(trim((string)($_POST['mailbox'] ?? '')));
            if ($name === '' || mb_strlen($name) > 120 || !in_array($kind, ['admin', 'mailbox'], true)) {
                $_SESSION['error'] = 'Проверьте название и тип ссылки.';
                redirect_to('/access-links/');
            }
            if ($kind === 'mailbox' && (!filter_var($mailbox, FILTER_VALIDATE_EMAIL) || !mailbox_active($mailbox))) {
                $_SESSION['error'] = 'Активный почтовый ящик не найден.';
                redirect_to('/access-links/');
            }
            if ($kind === 'admin') {
                $mailbox = '';
            }
            $token = token_string();
            $stmt = db()->prepare(<<<'SQL'
INSERT INTO links (name, kind, token_hash, mailbox, created_at, created_by)
VALUES (:name, :kind, :token_hash, :mailbox, datetime('now'), :created_by)
SQL);
            $actor = env_required('MAILCOW_ADMIN_USERNAME');
            $stmt->execute([
                ':name' => $name,
                ':kind' => $kind,
                ':token_hash' => token_hash($token),
                ':mailbox' => $mailbox !== '' ? $mailbox : null,
                ':created_by' => $actor,
            ]);
            $link = [
                'id' => (int)db()->lastInsertId(),
                'name' => $name,
                'kind' => $kind,
                'mailbox' => $mailbox !== '' ? $mailbox : null,
            ];
            audit('link_created', 'success', $link, $link['mailbox'], $actor);
            $prefix = $kind === 'admin' ? '/access/' : '/mailbox-access/';
            $_SESSION['new_link'] = rtrim(env_required('PUBLIC_BASE_URL'), '/') . $prefix . $token;
            redirect_to('/access-links/');
        }

        if ($action === 'revoke') {
            $id = filter_var($_POST['id'] ?? null, FILTER_VALIDATE_INT);
            $stmt = db()->prepare('SELECT * FROM links WHERE id = :id LIMIT 1');
            $stmt->execute([':id' => $id]);
            $link = $stmt->fetch();
            if (!$link) {
                not_found();
            }
            if ($link['revoked_at'] === null) {
                $actor = env_required('MAILCOW_ADMIN_USERNAME');
                $update = db()->prepare("UPDATE links SET revoked_at = datetime('now'), revoked_by = :actor WHERE id = :id AND revoked_at IS NULL");
                $update->execute([':actor' => $actor, ':id' => $id]);
                audit('link_revoked', 'success', $link, $link['mailbox'], $actor);
            }
            redirect_to('/access-links/');
        }
        http_response_code(400);
        exit('Bad request');
    }

    $links = db()->query('SELECT * FROM links ORDER BY id DESC')->fetchAll();
    $auditRows = db()->query('SELECT * FROM audit ORDER BY id DESC LIMIT 200')->fetchAll();
    $newLink = $_SESSION['new_link'] ?? null;
    $error = $_SESSION['error'] ?? null;
    unset($_SESSION['new_link'], $_SESSION['error']);
    render_management($links, $auditRows, $newLink, $error);
    exit;
}

not_found();

function render_mailbox_login(string $mailbox, string $name, ?string $error = null): void
{
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>Вход в почтовый ящик</title><style>' . base_css() . '</style></head><body><main class="card login">';
    echo '<h1>Вход в почтовый ящик</h1><p class="muted">' . h($name) . '</p>';
    if ($error !== null) {
        echo '<div class="alert error">' . h($error) . '</div>';
    }
    echo '<form method="post">';
    echo '<p><strong>' . h($mailbox) . '</strong></p>';
    echo '<label>Пароль<input type="password" name="password" required autofocus autocomplete="current-password"></label>';
    echo '<button type="submit">Войти</button></form></main></body></html>';
}

function render_management(array $links, array $auditRows, ?string $newLink, ?string $error): void
{
    $csrf = broker_csrf();
    echo '<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">';
    echo '<title>Управление ссылками Mailcow</title><style>' . base_css() . '</style></head><body><main class="wrap">';
    echo '<header><div><h1>Ссылки доступа Mailcow</h1><p class="muted">Многоразовые, бессрочные и отзывные</p></div><a class="button secondary" href="' . h(rtrim(env_required('MAILCOW_BASE_URL'), '/') . '/admin/dashboard') . '">В Mailcow</a></header>';
    if ($error) {
        echo '<div class="alert error">' . h($error) . '</div>';
    }
    if ($newLink) {
        echo '<div class="alert success"><strong>Ссылка создана. Скопируйте сейчас — токен больше не показывается.</strong><input class="copy" readonly value="' . h($newLink) . '" onclick="this.select()"></div>';
    }
    echo '<section class="card"><h2>Создать ссылку</h2><form method="post" class="grid">';
    echo '<input type="hidden" name="csrf" value="' . h($csrf) . '"><input type="hidden" name="action" value="create">';
    echo '<label>Название<input name="name" maxlength="120" required placeholder="Например: Иван — админ"></label>';
    echo '<label>Тип<select name="kind" id="kind"><option value="admin">Администратор без пароля и 2FA</option><option value="mailbox">Почтовый ящик с запросом пароля</option></select></label>';
    echo '<label>Почтовый ящик<input type="email" name="mailbox" placeholder="user@example.com"></label>';
    echo '<button type="submit">Создать бессрочную ссылку</button></form></section>';

    echo '<section class="card"><h2>Ссылки</h2><div class="table"><table><thead><tr><th>ID</th><th>Название</th><th>Тип</th><th>Ящик</th><th>Создана</th><th>Использований</th><th>Последний вход</th><th>Статус</th><th></th></tr></thead><tbody>';
    foreach ($links as $link) {
        $active = $link['revoked_at'] === null;
        echo '<tr><td>' . (int)$link['id'] . '</td><td>' . h($link['name']) . '</td><td>' . h($link['kind']) . '</td><td>' . h($link['mailbox'] ?? '—') . '</td><td>' . h($link['created_at']) . '</td><td>' . (int)$link['use_count'] . '</td><td>' . h($link['last_used_at'] ?? '—') . '</td><td><span class="status ' . ($active ? 'on' : 'off') . '">' . ($active ? 'активна' : 'отозвана') . '</span></td><td>';
        if ($active) {
            echo '<form method="post" onsubmit="return confirm(\'Отозвать ссылку?\')"><input type="hidden" name="csrf" value="' . h($csrf) . '"><input type="hidden" name="action" value="revoke"><input type="hidden" name="id" value="' . (int)$link['id'] . '"><button class="danger" type="submit">Отозвать</button></form>';
        }
        echo '</td></tr>';
    }
    echo '</tbody></table></div></section>';

    echo '<section class="card"><h2>Журнал (последние 200 событий)</h2><div class="table"><table><thead><tr><th>Время UTC</th><th>Событие</th><th>Ссылка</th><th>IP</th><th>Результат</th><th>Ящик</th><th>Кем</th></tr></thead><tbody>';
    foreach ($auditRows as $row) {
        echo '<tr><td>' . h($row['occurred_at']) . '</td><td>' . h($row['event']) . '</td><td>' . h($row['link_name'] ?? '—') . '</td><td>' . h($row['ip']) . '</td><td>' . h($row['result']) . '</td><td>' . h($row['mailbox'] ?? '—') . '</td><td>' . h($row['actor'] ?? '—') . '</td></tr>';
    }
    echo '</tbody></table></div></section></main></body></html>';
}

function base_css(): string
{
    return <<<'CSS'
:root{color-scheme:dark;--bg:#11151a;--card:#1d232b;--line:#35404b;--text:#edf3f8;--muted:#9eb0bf;--green:#32c45b;--red:#e65050;--blue:#3287e6}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.45 system-ui,-apple-system,Segoe UI,sans-serif}.wrap{max-width:1500px;margin:0 auto;padding:28px}.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px;margin:18px 0;box-shadow:0 10px 35px #0004}.login{max-width:480px;margin:10vh auto}header{display:flex;align-items:center;justify-content:space-between;gap:20px}h1,h2{margin:.1em 0 .4em}.muted{color:var(--muted)}label{display:flex;flex-direction:column;gap:7px;font-weight:600}input,select,button,.button{width:100%;border:1px solid var(--line);border-radius:7px;padding:11px 12px;background:#12171d;color:var(--text);font:inherit}button,.button{cursor:pointer;background:var(--green);border-color:transparent;color:#07140a;font-weight:750;text-align:center;text-decoration:none}.button.secondary{width:auto;background:var(--blue);color:white}.danger{background:var(--red);color:white;padding:7px 10px}.grid{display:grid;grid-template-columns:1.2fr 1fr 1.2fr auto;align-items:end;gap:14px}.grid button{white-space:nowrap}.alert{border-radius:9px;padding:15px;margin:16px 0}.alert.success{background:#143e22;border:1px solid #267a41}.alert.error{background:#482020;border:1px solid #8f3939}.copy{margin-top:10px;background:#0b1610}.table{overflow:auto}table{width:100%;border-collapse:collapse;white-space:nowrap}th,td{text-align:left;padding:10px;border-bottom:1px solid var(--line)}th{color:var(--muted)}.status{padding:4px 8px;border-radius:99px}.status.on{background:#174c28;color:#72ea91}.status.off{background:#4a2424;color:#ff9090}@media(max-width:900px){.grid{grid-template-columns:1fr}.wrap{padding:14px}header{align-items:flex-start;flex-direction:column}}
CSS;
}

