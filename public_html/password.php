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

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require __DIR__ . '/includes/config.php';

$stmt = $pdo->prepare(
    "SELECT id, username, full_name, role, is_active, password_hash
     FROM users
     WHERE id = :id
     LIMIT 1"
);
$stmt->execute([':id' => (int)$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user || (int)$user['is_active'] !== 1) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

$_SESSION['username'] = $user['username'];
$_SESSION['full_name'] = $user['full_name'];
$_SESSION['role'] = $user['role'];

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals(
        $_SESSION['csrf_token'],
        (string)($_POST['csrf_token'] ?? '')
    )) {
        $error = 'Сессия формы устарела. Обновите страницу и попробуйте снова.';
    } else {
        $current = (string)($_POST['current_password'] ?? '');
        $password = (string)($_POST['password'] ?? '');
        $confirm = (string)($_POST['password_confirm'] ?? '');

        if (!password_verify($current, (string)$user['password_hash'])) {
            $error = 'Текущий пароль указан неверно.';
        } elseif (strlen($password) < 12) {
            $error = 'Пароль должен содержать не менее 12 символов.';
        } elseif (!hash_equals($password, $confirm)) {
            $error = 'Новый пароль и повтор не совпадают.';
        } else {
            try {
                $update = $pdo->prepare(
                    "UPDATE users
                     SET password_hash = :password_hash
                     WHERE id = :id"
                );
                $update->execute([
                    ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
                    ':id' => (int)$user['id']
                ]);
                $success = 'Пароль изменён.';
            } catch (PDOException $e) {
                error_log('Own password change error: ' . $e->getMessage());
                $error = 'Не удалось изменить пароль. Попробуйте снова.';
            }
        }
    }
}

function h(mixed $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

require __DIR__ . '/includes/header.php';
?>

<h1>Смена пароля</h1>

<p class="employee-hint">
    Укажите текущий пароль и новый. Минимум 12 символов.
</p>

<?php if ($error !== ''): ?>
    <div class="employee-message employee-error"><?= h($error) ?></div>
<?php endif; ?>

<?php if ($success !== ''): ?>
    <div class="employee-message employee-success"><?= h($success) ?></div>
<?php endif; ?>

<section class="card password-card">
    <form method="post">
        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">

        <label class="employee-field">
            Текущий пароль
            <input type="password" name="current_password" autocomplete="current-password" required>
        </label>

        <label class="employee-field">
            Новый пароль
            <input type="password" name="password" minlength="12" autocomplete="new-password" required>
        </label>

        <label class="employee-field">
            Повтор нового пароля
            <input type="password" name="password_confirm" minlength="12" autocomplete="new-password" required>
        </label>

        <button type="submit" class="action-button">Сохранить пароль</button>
    </form>
</section>

</main>
</body>
</html>