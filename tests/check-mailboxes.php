<?php
declare(strict_types=1);

$dsn = sprintf(
    'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
    getenv('MAILCOW_DB_HOST'),
    (int)getenv('MAILCOW_DB_PORT'),
    getenv('MAILCOW_DB_NAME')
);
$pdo = new PDO($dsn, getenv('MAILCOW_DB_USER'), getenv('MAILCOW_DB_PASSWORD'), [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);
echo (int)$pdo->query('SELECT COUNT(*) FROM mailbox WHERE active = 1')->fetchColumn(), PHP_EOL;

