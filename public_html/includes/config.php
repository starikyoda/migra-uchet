<?php
declare(strict_types=1);

$DB_HOST = 'localhost';
$DB_NAME = 'migr_uchet2';
$DB_USER = 'migr_uchet2';

$DB_PASS = getenv('DB_PASS');
if (!is_string($DB_PASS) || $DB_PASS === '') {
    $fromEnv = $_ENV['DB_PASS'] ?? $_SERVER['DB_PASS'] ?? '';
    $DB_PASS = is_string($fromEnv) ? $fromEnv : '';
}

if ($DB_PASS === '') {
    $localFile = __DIR__ . '/config.local.php';
    if (is_file($localFile)) {
        $local = require $localFile;
        if (is_array($local) && isset($local['DB_PASS']) && is_string($local['DB_PASS'])) {
            $DB_PASS = $local['DB_PASS'];
        }
    }
}

if ($DB_PASS === '') {
    http_response_code(500);
    exit('Не задан пароль базы данных. Укажите переменную окружения DB_PASS или файл includes/config.local.php.');
}

$pdo = new PDO(
    "mysql:host={$DB_HOST};dbname={$DB_NAME};charset=utf8mb4",
    $DB_USER,
    $DB_PASS,
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

$pdo->exec("SET NAMES utf8mb4");
