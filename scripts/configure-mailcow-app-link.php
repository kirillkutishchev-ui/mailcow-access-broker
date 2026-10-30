<?php
declare(strict_types=1);

$redis = new Redis();
$redis->connect('redis-mailcow', 6379, 3.0);
$redis->auth((string)getenv('REDISPASS'));

$raw = $redis->get('APP_LINKS');
$links = $raw ? json_decode($raw, true, 512, JSON_THROW_ON_ERROR) : [];
if (!is_array($links)) {
    throw new RuntimeException('APP_LINKS has an invalid format');
}

foreach ($links as $entry) {
    if (is_array($entry) && array_key_exists('Ссылки доступа', $entry)) {
        echo "app_link=already_present\n";
        exit(0);
    }
}

$links[] = [
    'Ссылки доступа' => [
        'link' => '/access-links/',
        'user_link' => '/access-links/',
        'hide' => false,
    ],
];
$redis->set('APP_LINKS', json_encode($links, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
echo "app_link=added\n";
