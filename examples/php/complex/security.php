<?php

// Authentication, authorization, CSRF protection, and input sanitization.

class Security {
    public static function escapeHtml($input) {
        return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }

    public static function sanitizeSql($input) {
        return addslashes($input);
    }

    public static function hashPassword($password) {
        return password_hash($password, PASSWORD_BCRYPT);
    }

    public static function verifyPassword($password, $hash) {
        return password_verify($password, $hash);
    }

    public static function generateToken($length = 32) {
        return bin2hex(random_bytes($length));
    }

    public static function validateEmail($email) {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
    }

    public static function sanitizeFilename($filename) {
        $name = basename($filename);
        return preg_replace('/[^a-zA-Z0-9._-]/', '', $name);
    }

    public static function validateUrl($url) {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }
        $parsed = parse_url($url);
        $blocked = ['localhost', '127.0.0.1', '0.0.0.0', '169.254.169.254'];
        if (in_array($parsed['host'] ?? '', $blocked)) {
            return false;
        }
        return true;
    }

    public static function csrfToken() {
        if (!isset($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = self::generateToken();
        }
        return $_SESSION['csrf_token'];
    }

    public static function verifyCsrf($token) {
        return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
    }
}

// Session manager with authentication
class SessionManager {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection in session lookup
    public function loadSession($sessionId) {
        $sql = "SELECT * FROM sessions WHERE session_id = '" . $sessionId . "'";
        return $this->db->rawQuery($sql);
    }

    // Safe version
    public function loadSessionSafe($sessionId) {
        return $this->db->preparedQuery(
            "SELECT * FROM sessions WHERE session_id = ?",
            "s", $sessionId
        );
    }

    // VULN: Session fixation -- tainted cookie used as session key
    public function resumeSession() {
        $sid = $_COOKIE['PHPSESSID'];
        $sessionData = $this->loadSession($sid);
        return $sessionData;
    }

    public function createSession($userId) {
        $sid = Security::generateToken();
        $this->db->preparedQuery(
            "INSERT INTO sessions (session_id, user_id, created_at) VALUES (?, ?, NOW())",
            "si", $sid, $userId
        );
        return $sid;
    }
}

// Authentication service
class AuthService {
    private $db;
    private $sessionMgr;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->sessionMgr = new SessionManager($db);
    }

    // VULN: SQL injection through login
    public function authenticateUnsafe($username, $password) {
        $sql = "SELECT * FROM users WHERE username = '" . $username . "' AND password = '" . $password . "'";
        return $this->db->rawQuery($sql);
    }

    // Safe version
    public function authenticate($username, $password) {
        $result = $this->db->preparedQuery(
            "SELECT * FROM users WHERE username = ?",
            "s", $username
        );
        $user = $result ? $result->fetch_assoc() : null;
        if ($user && password_verify($password, $user['password_hash'])) {
            return $user;
        }
        return null;
    }

    // VULN: SQL injection in password reset token lookup
    public function lookupResetToken($token) {
        $sql = "SELECT * FROM password_resets WHERE token = '" . $token . "'";
        return $this->db->rawQuery($sql);
    }

    public function getSessionManager() {
        return $this->sessionMgr;
    }
}

// Input validation and filtering
class InputFilter {
    private $rules = [];

    public function addRule($field, $type, $options = []) {
        $this->rules[$field] = ['type' => $type, 'options' => $options];
    }

    public function validate($data) {
        $errors = [];
        foreach ($this->rules as $field => $rule) {
            if (!isset($data[$field])) {
                $errors[$field] = 'Required field missing';
                continue;
            }
            $value = $data[$field];
            switch ($rule['type']) {
                case 'string':
                    $maxLen = $rule['options']['max_length'] ?? 255;
                    if (strlen($value) > $maxLen) {
                        $errors[$field] = "Too long (max {$maxLen})";
                    }
                    break;
                case 'int':
                    if (!is_numeric($value)) {
                        $errors[$field] = 'Must be a number';
                    }
                    break;
                case 'email':
                    if (!Security::validateEmail($value)) {
                        $errors[$field] = 'Invalid email';
                    }
                    break;
            }
        }
        return $errors;
    }

    public function sanitize($data) {
        $clean = [];
        foreach ($data as $key => $value) {
            if (is_string($value)) {
                $clean[$key] = trim(strip_tags($value));
            } else {
                $clean[$key] = $value;
            }
        }
        return $clean;
    }
}

// Access control
class AccessControl {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection in permission check
    public function hasPermission($userId, $permission) {
        $sql = "SELECT COUNT(*) as cnt FROM user_permissions WHERE user_id = " . $userId . " AND permission = '" . $permission . "'";
        return $this->db->rawQuery($sql);
    }

    // Safe version
    public function hasPermissionSafe($userId, $permission) {
        $result = $this->db->preparedQuery(
            "SELECT COUNT(*) as cnt FROM user_permissions WHERE user_id = ? AND permission = ?",
            "is", $userId, $permission
        );
        $row = $result ? $result->fetch_assoc() : null;
        return $row && $row['cnt'] > 0;
    }
}

// Rate limiter
class RateLimiter {
    public static function check($key, $maxRequests = 100, $windowSeconds = 60) {
        $cacheFile = '/tmp/ratelimit_' . md5($key);
        $data = [];
        if (file_exists($cacheFile)) {
            $data = json_decode(file_get_contents($cacheFile), true) ?: [];
        }
        $now = time();
        $data = array_filter($data, function($ts) use ($now, $windowSeconds) {
            return ($now - $ts) < $windowSeconds;
        });
        if (count($data) >= $maxRequests) {
            return false;
        }
        $data[] = $now;
        file_put_contents($cacheFile, json_encode(array_values($data)));
        return true;
    }
}
