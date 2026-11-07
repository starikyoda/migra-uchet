<?php
declare(strict_types=1);

session_set_cookie_params([
    'httponly' => true,
    'secure' => true,
    'samesite' => 'Lax'
]);
session_start();

if (empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}

require __DIR__ . '/includes/config.php';

$stmt = $pdo->prepare(
    "SELECT full_name, username, role
     FROM users
     WHERE id = :id AND is_active = 1
     LIMIT 1"
);
$stmt->execute([':id' => (int)$_SESSION['user_id']]);
$user = $stmt->fetch();

if (!$user) {
    $_SESSION = [];

    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();

        setcookie(session_name(), '', [
            'expires' => time() - 42000,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => true,
            'httponly' => true,
            'samesite' => 'Lax'
        ]);
    }

    session_destroy();
    header('Location: login.php');
    exit;
}

$_SESSION['full_name'] = $user['full_name'];
$_SESSION['username'] = $user['username'];
$_SESSION['role'] = $user['role'];

function h(mixed $value): string
{
    return htmlspecialchars(
        (string)($value ?? ''),
        ENT_QUOTES,
        'UTF-8'
    );
}

require __DIR__ . '/includes/header.php';
?>

<section class="dashboard-heading">
    <h1>Рабочий кабинет</h1>
    <p>Выберите действие для работы с иностранными гражданами.</p>
</section>

<section class="dashboard-grid">

    <a class="dashboard-card" href="citizens.php">
        <span class="dashboard-icon">⌕</span>
        <h2>Найти гражданина</h2>
        <p>Поиск по фамилии, имени, номеру паспорта или телефону. Просмотр карточки и истории посещений.</p>
        <span class="dashboard-action">Перейти к поиску →</span>
    </a>

    <a class="dashboard-card" href="citizen_new.php">
        <span class="dashboard-icon">＋</span>
        <h2>Зарегистрировать гражданина</h2>
        <p>Создать новую карточку и сохранить личные, паспортные и контактные данные.</p>
        <span class="dashboard-action">Создать карточку →</span>
    </a>

    <a class="dashboard-card" href="citizens.php">
        <span class="dashboard-icon">↻</span>
        <h2>Оформить повторный приезд</h2>
        <p>Найти зарегистрированного человека и добавить новое посещение.</p>
        <span class="dashboard-action">Найти гражданина →</span>
    </a>

    <?php if ($user['role'] === 'admin'): ?>
        <a class="dashboard-card" href="employees.php">
            <span class="dashboard-icon">⚙</span>
            <h2>Управление сотрудниками</h2>
            <p>Создание учётных записей, просмотр списка сотрудников и управление доступом.</p>
            <span class="dashboard-action">Перейти к сотрудникам →</span>
        </a>
    <?php endif; ?>

</section>

</main>
</body>
</html>