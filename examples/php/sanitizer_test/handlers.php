<?php
// PHP sanitizer-fixture — parallel handlers per sink family.

class Handlers {
    private $pdo;

    public function __construct($pdo) {
        $this->pdo = $pdo;
    }

    // --- Command injection ----------------------------------------------

    public function cmdRaw($input) {
        return exec("ping " . $input);
    }

    public function cmdSafe($input) {
        $safe = escapeshellarg($input);
        return exec("ping " . $safe);
    }

    // --- SQL injection --------------------------------------------------

    public function sqlRaw($userId) {
        return $this->pdo->query("SELECT * FROM users WHERE id = '" . $userId . "'");
    }

    public function sqlSafe($userId) {
        $stmt = $this->pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        return $stmt;
    }

    // --- XSS ------------------------------------------------------------

    public function xssRaw($name) {
        return "<p>Hello, " . $name . "</p>";
    }

    public function xssSafe($name) {
        $safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
        return "<p>Hello, " . $safe . "</p>";
    }
}
