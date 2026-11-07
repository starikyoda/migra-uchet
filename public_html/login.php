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

if (!empty($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

function h(mixed $value): string
{
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username !== '' && $password !== '') {
        require __DIR__ . '/includes/config.php';

        $stmt = $pdo->prepare(
            'SELECT id, username, password_hash, full_name, role, is_active
             FROM users
             WHERE username = ?
             LIMIT 1'
        );
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        $passwordOk = is_array($user)
            && (int)$user['is_active'] === 1
            && password_verify($password, (string)$user['password_hash']);

        if ($passwordOk) {
            session_regenerate_id(true);

            $_SESSION['user_id'] = (int)$user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['full_name'] = $user['full_name'];
            $_SESSION['role'] = $user['role'];

            header('Location: index.php');
            exit;
        }
    }

    $error = 'Неверный логин или пароль.';
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Вход — Миграционный учёт</title>
    <link rel="stylesheet" href="includes/site.css">
    
</head>
<body class="page-login">
    <h1>Миграционный учёт</h1>
    <h2>Вход в кабинет</h2>

    <?php if ($error !== ''): ?>
        <p class="error"><?= h($error) ?></p>
    <?php endif; ?>

    <form method="post" action="login.php">
        <label for="username">Логин</label>
        <input id="username" name="username" required maxlength="100"
               autocomplete="username">

        <label for="password">Пароль</label>
        <input id="password" type="password" name="password" required
               autocomplete="current-password">

        <button type="submit">Войти</button>
    </form>
</body>
</html>
