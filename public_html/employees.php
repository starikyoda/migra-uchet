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

$userStmt = $pdo->prepare(
    "SELECT id, username, full_name, role, is_active
     FROM users
     WHERE id = :id
     LIMIT 1"
);
$userStmt->execute([':id' => (int)$_SESSION['user_id']]);
$adminUser = $userStmt->fetch();

if (!$adminUser || (int)$adminUser['is_active'] !== 1) {
    $_SESSION = [];
    session_destroy();
    header('Location: login.php');
    exit;
}

if ($adminUser['role'] !== 'admin') {
    http_response_code(403);
    exit('Доступ запрещён. Этот раздел доступен только администратору.');
}

$_SESSION['username'] = $adminUser['username'];
$_SESSION['full_name'] = $adminUser['full_name'];
$_SESSION['role'] = $adminUser['role'];

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$error = '';
$success = '';

$values = [
    'username' => '',
    'full_name' => '',
    'role' => 'employee'
];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string)($_POST['action'] ?? '');

    if (!hash_equals(
        $_SESSION['csrf_token'],
        (string)($_POST['csrf_token'] ?? '')
    )) {
        $error = 'Сессия формы устарела. Обновите страницу и попробуйте снова.';
    } elseif ($action === 'create') {
        $values['username'] = trim((string)($_POST['username'] ?? ''));
        $values['full_name'] = trim((string)($_POST['full_name'] ?? ''));
        $values['role'] = (string)($_POST['role'] ?? 'employee');
        $password = (string)($_POST['password'] ?? '');
        $fullNameLength = function_exists('mb_strlen')
            ? mb_strlen($values['full_name'], 'UTF-8')
            : strlen($values['full_name']);

        if (
            $values['username'] === '' ||
            !preg_match('/^[a-zA-Z0-9_.-]{3,50}$/', $values['username'])
        ) {
            $error = 'Логин должен содержать от 3 до 50 символов: латинские буквы, цифры, точку, дефис или подчёркивание.';
        } elseif ($values['full_name'] === '' || $fullNameLength > 150) {
            $error = 'Укажите ФИО сотрудника, не длиннее 150 символов.';
        } elseif (!in_array($values['role'], ['admin', 'employee'], true)) {
            $error = 'Выбрана недопустимая роль.';
        } elseif (strlen($password) < 12) {
            $error = 'Пароль должен содержать не менее 12 символов.';
        } else {
            try {
                $stmt = $pdo->prepare(
                    "INSERT INTO users
                    (username, password_hash, full_name, role, is_active, created_at)
                    VALUES
                    (:username, :password_hash, :full_name, :role, 1, NOW())"
                );

                $stmt->execute([
                    ':username' => $values['username'],
                    ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
                    ':full_name' => $values['full_name'],
                    ':role' => $values['role']
                ]);

                $success = 'Сотрудник успешно добавлен.';
                $values = [
                    'username' => '',
                    'full_name' => '',
                    'role' => 'employee'
                ];
            } catch (PDOException $e) {
                error_log('Employee create error: ' . $e->getMessage());

                if ((string)$e->getCode() === '23000') {
                    $error = 'Такой логин уже существует.';
                } else {
                    $error = 'Не удалось добавить сотрудника. Проверьте данные и попробуйте снова.';
                }
            }
        }
    } elseif ($action === 'toggle') {
        $employeeId = filter_var(
            $_POST['employee_id'] ?? null,
            FILTER_VALIDATE_INT
        );

        if (!$employeeId || $employeeId < 1) {
            $error = 'Не выбран сотрудник.';
        } elseif ($employeeId === (int)$adminUser['id']) {
            $error = 'Нельзя заблокировать собственную учётную запись.';
        } else {
            try {
                $pdo->beginTransaction();

                $stmt = $pdo->prepare(
                    "SELECT id, role, is_active
                     FROM users
                     WHERE id = :id
                     FOR UPDATE"
                );
                $stmt->execute([':id' => $employeeId]);
                $target = $stmt->fetch();

                if (!$target) {
                    $error = 'Сотрудник не найден.';
                } elseif (
                    $target['role'] === 'admin' &&
                    (int)$target['is_active'] === 1
                ) {
                    $stmt = $pdo->prepare(
                        "SELECT COUNT(*)
                         FROM users
                         WHERE role = 'admin' AND is_active = 1"
                    );
                    $stmt->execute();

                    if ((int)$stmt->fetchColumn() <= 1) {
                        $error = 'Нельзя заблокировать последнего активного администратора.';
                    }
                }

                if ($error === '') {
                    $newStatus = (int)$target['is_active'] === 1 ? 0 : 1;

                    $stmt = $pdo->prepare(
                        "UPDATE users
                         SET is_active = :status
                         WHERE id = :id"
                    );
                    $stmt->execute([
                        ':status' => $newStatus,
                        ':id' => $employeeId
                    ]);

                    $success = $newStatus === 1
                        ? 'Доступ сотрудника восстановлен.'
                        : 'Учётная запись сотрудника заблокирована.';
                    $pdo->commit();
                } else {
                    $pdo->rollBack();
                }
            } catch (PDOException $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }

                error_log('Employee status error: ' . $e->getMessage());
                $error = 'Не удалось изменить статус сотрудника.';
            }
        }
    } elseif ($action === 'set_password') {
        $employeeId = filter_var(
            $_POST['employee_id'] ?? null,
            FILTER_VALIDATE_INT
        );
        $password = (string)($_POST['password'] ?? '');

        if (!$employeeId || $employeeId < 1) {
            $error = 'Не выбран сотрудник.';
        } elseif (strlen($password) < 12) {
            $error = 'Пароль должен содержать не менее 12 символов.';
        } else {
            try {
                $stmt = $pdo->prepare(
                    "SELECT id
                     FROM users
                     WHERE id = :id
                     LIMIT 1"
                );
                $stmt->execute([':id' => $employeeId]);

                if (!$stmt->fetch()) {
                    $error = 'Сотрудник не найден.';
                } else {
                    $stmt = $pdo->prepare(
                        "UPDATE users
                         SET password_hash = :password_hash
                         WHERE id = :id"
                    );
                    $stmt->execute([
                        ':password_hash' => password_hash($password, PASSWORD_DEFAULT),
                        ':id' => $employeeId
                    ]);
                    $success = 'Пароль сотрудника обновлён.';
                }
            } catch (PDOException $e) {
                error_log('Employee password error: ' . $e->getMessage());
                $error = 'Не удалось обновить пароль.';
            }
        }
    } else {
        $error = 'Неизвестная операция.';
    }
}

require_once __DIR__ . '/includes/activity.php';
touchLastSeen($pdo, (int)$adminUser['id']);

$stmt = $pdo->query(
    "SELECT id, username, full_name, role, is_active, last_seen, created_at
     FROM users
     ORDER BY
         CASE WHEN role = 'admin' THEN 0 ELSE 1 END,
         full_name ASC,
         id ASC"
);
$employees = $stmt->fetchAll();


function presenceLabel(?string $lastSeenUtc): array
{
    if ($lastSeenUtc === null || $lastSeenUtc === '') {
        return ['online' => false, 'text' => 'ещё не заходил'];
    }

    $seen = new DateTimeImmutable($lastSeenUtc, new DateTimeZone('UTC'));
    $now = new DateTimeImmutable('now', new DateTimeZone('UTC'));
    $age = $now->getTimestamp() - $seen->getTimestamp();

    if ($age <= 300) {
        return ['online' => true, 'text' => 'на сайте'];
    }

    $local = $seen->setTimezone(new DateTimeZone('Asia/Krasnoyarsk'));

    return ['online' => false, 'text' => $local->format('d.m.Y H:i')];
}
function h(mixed $value): string
{
    return htmlspecialchars((string)($value ?? ''), ENT_QUOTES, 'UTF-8');
}

require __DIR__ . '/includes/header.php';
?>

<h1>Управление сотрудниками</h1>

<p class="employee-hint">
    Здесь можно создавать учётные записи и управлять доступом сотрудников.
    Этот раздел доступен только администраторам.
</p>

<?php if ($error !== ''): ?>
    <div class="employee-message employee-error"><?= h($error) ?></div>
<?php endif; ?>

<?php if ($success !== ''): ?>
    <div class="employee-message employee-success"><?= h($success) ?></div>
<?php endif; ?>

<div class="employees-grid">
    <section class="card">
        <h2>Добавить сотрудника</h2>

        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
            <input type="hidden" name="action" value="create">

            <label class="employee-field">
                Логин
                <input
                    type="text"
                    name="username"
                    value="<?= h($values['username']) ?>"
                    minlength="3"
                    maxlength="50"
                    pattern="[a-zA-Z0-9_.-]+"
                    autocomplete="off"
                    required
                >
            </label>

            <label class="employee-field">
                ФИО сотрудника
                <input
                    type="text"
                    name="full_name"
                    value="<?= h($values['full_name']) ?>"
                    maxlength="150"
                    required
                >
            </label>

            <label class="employee-field">
                Роль
                <select name="role" required>
                    <option value="employee" <?= $values['role'] === 'employee' ? 'selected' : '' ?>>
                        Сотрудник
                    </option>
                    <option value="admin" <?= $values['role'] === 'admin' ? 'selected' : '' ?>>
                        Администратор
                    </option>
                </select>
            </label>

            <label class="employee-field">
                Временный пароль
                <input
                    type="password"
                    name="password"
                    minlength="12"
                    autocomplete="new-password"
                    required
                >
            </label>

            <p class="employee-hint">
                Минимум 12 символов. Передайте пароль сотруднику безопасным способом.
            </p>

            <button type="submit" class="action-button">
                Добавить сотрудника
            </button>
        </form>
    </section>

    <section class="card">
        <h2>Учётные записи</h2>

        <div class="employee-table-wrap">
            <table class="employee-table">
                <thead>
                    <tr>
                        <th>Сотрудник</th>
                        <th>Роль</th>
                        <th>Статус</th>
                        <th>На сайте</th>
                        <th>Действие</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($employees as $employee): ?>
                        <tr>
                            <td>
                                <strong><?= h($employee['full_name']) ?></strong>
                                <div class="employee-hint"><?= h($employee['username']) ?></div>
                            </td>
                            <td>
                                <?= $employee['role'] === 'admin' ? 'Администратор' : 'Сотрудник' ?>
                            </td>
                            <td>
                                <?php if ((int)$employee['is_active'] === 1): ?>
                                    <span class="employee-status active">Активен</span>
                                <?php else: ?>
                                    <span class="employee-status inactive">Заблокирован</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php $presence = presenceLabel($employee['last_seen'] !== null ? (string)$employee['last_seen'] : null); ?>
                                <?php if ($presence['online']): ?>
                                    <span class="employee-status online">на сайте</span>
                                <?php else: ?>
                                    <span class="employee-hint"><?= h($presence['text']) ?></span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ((int)$employee['id'] === (int)$adminUser['id']): ?>
                                    <span class="employee-hint">Текущая учётная запись</span>
                                <?php else: ?>
                                    <form
                                        class="employee-action-form"
                                        method="post"
                                        onsubmit="return confirm('Изменить доступ этому сотруднику?');"
                                    >
                                        <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                        <input type="hidden" name="action" value="toggle">
                                        <input type="hidden" name="employee_id" value="<?= (int)$employee['id'] ?>">

                                        <button type="submit" class="employee-action-button">
                                            <?= (int)$employee['is_active'] === 1 ? 'Заблокировать' : 'Восстановить' ?>
                                        </button>
                                    </form>
                                <?php endif; ?>
                                <form class="employee-password-form" method="post">
                                    <input type="hidden" name="csrf_token" value="<?= h($_SESSION['csrf_token']) ?>">
                                    <input type="hidden" name="action" value="set_password">
                                    <input type="hidden" name="employee_id" value="<?= (int)$employee['id'] ?>">
                                    <input
                                        type="password"
                                        name="password"
                                        minlength="12"
                                        autocomplete="new-password"
                                        placeholder="Новый пароль"
                                        aria-label="Новый пароль"
                                        required
                                    >
                                    <button type="submit" class="employee-action-button">Задать пароль</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>

                    <?php if (!$employees): ?>
                        <tr>
                            <td colspan="5">Сотрудников пока нет.</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </section>
</div>

</main>
</body>
</html>