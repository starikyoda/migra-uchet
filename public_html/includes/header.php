<?php
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'httponly' => true,
        'secure' => true,
        'samesite' => 'Lax'
    ]);
    session_start();
}

if (!empty($_SESSION['user_id'])) {
    require_once __DIR__ . '/config.php';
    require_once __DIR__ . '/activity.php';
    touchLastSeen($pdo, (int)$_SESSION['user_id']);
}
$currentUser = $_SESSION['full_name'] ?? $_SESSION['username'] ?? 'Сотрудник';
$isAdmin = ($_SESSION['role'] ?? '') === 'admin';
$currentRole = $isAdmin ? 'Администратор' : 'Сотрудник';

$currentPage = basename($_SERVER['PHP_SELF'] ?? '');

if ($currentPage === 'citizen.php') {
    $activeSection = 'citizens.php';
} else {
    $activeSection = $currentPage;
}

function navActive(string $page, string $currentPage): string
{
    return $page === $currentPage ? ' active' : '';
}

function navItem(string $page, string $label, string $activeSection): string
{
    $safeLabel = htmlspecialchars($label, ENT_QUOTES, 'UTF-8');

    if ($page === $activeSection) {
        return '<span class="nav-link active" aria-current="page">'
            . $safeLabel
            . '</span>';
    }

    $safePage = htmlspecialchars($page, ENT_QUOTES, 'UTF-8');

    return '<a class="nav-link" href="' . $safePage . '">'
        . $safeLabel
        . '</a>';
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Учёт иностранных граждан</title>
    <link rel="stylesheet" href="includes/site.css">
    
</head>
<?php
$pageClass = 'page-' . str_replace('_', '-', basename((string)$currentPage, '.php'));
?>
<body class="app <?= htmlspecialchars($pageClass, ENT_QUOTES, 'UTF-8') ?>">

<header class="app-header">
    <div class="header-inner">
        <div class="brand">Учёт иностранных граждан</div>

        <div class="user-area">
            <div class="user-info">
                <strong><?= htmlspecialchars($currentUser, ENT_QUOTES, 'UTF-8') ?></strong>
                <span class="user-role"><?= htmlspecialchars($currentRole, ENT_QUOTES, 'UTF-8') ?></span>
            </div>

            <a class="secondary-button" href="password.php">Сменить пароль</a>

            <form class="logout-form" action="logout.php" method="post">
                <button class="logout-button" type="submit">
                    Выйти из системы
                </button>
            </form>
        </div>
    </div>
</header>

<nav class="main-nav">
    <div class="nav-inner">
        <?= navItem('index.php', 'Главная', $activeSection) ?>

        <?= navItem('citizens.php', 'Поиск граждан', $activeSection) ?>

        <?= navItem('citizen_new.php', 'Регистрация гражданина', $activeSection) ?>

        <?= navItem('visit_new.php', 'Повторный въезд', $activeSection) ?>

        <?= navItem('employees.php', 'Управление сотрудниками', $activeSection) ?>
    </div>
</nav>

<main class="page-container">