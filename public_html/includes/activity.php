<?php
declare(strict_types=1);

function touchLastSeen(PDO $pdo, int $userId): void
{
    if ($userId < 1) {
        return;
    }

    $stmt = $pdo->prepare(
        'UPDATE users
         SET last_seen = UTC_TIMESTAMP()
         WHERE id = :id AND is_active = 1'
    );
    $stmt->execute([':id' => $userId]);
}