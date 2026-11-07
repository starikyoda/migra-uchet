<?php
declare(strict_types=1);

$https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (int)($_SERVER['SERVER_PORT'] ?? 0) === 443;

session_set_cookie_params([
    'httponly' => true,
    'secure' => $https,
    'samesite' => 'Lax'
]);
session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit('Метод не разрешён');
}

$_SESSION = [];

if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();

    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $params['path'],
        'domain' => $params['domain'],
        'secure' => $https,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);
}

session_destroy();

header('Location: login.php');
exit;