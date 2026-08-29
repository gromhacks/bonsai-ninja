<?php

// Database abstraction layer for e-commerce CMS.
// Provides connection management, query builder, and repository classes.

class DatabaseConnection {
    private $conn;
    private $host;
    private $dbName;
    private $user;
    private $pass;

    public function __construct($host, $dbName, $user, $pass) {
        $this->host = $host;
        $this->dbName = $dbName;
        $this->user = $user;
        $this->pass = $pass;
    }

    public function getConnection() {
        if ($this->conn === null) {
            $this->conn = new mysqli($this->host, $this->user, $this->pass, $this->dbName);
            if ($this->conn->connect_error) {
                throw new RuntimeException("Connection failed: " . $this->conn->connect_error);
            }
        }
        return $this->conn;
    }

    // VULN: Raw query execution with no parameterization
    public function rawQuery($sql) {
        $conn = $this->getConnection();
        $result = mysqli_query($conn, $sql);
        return $result;
    }

    // Safe: prepared statement execution
    public function preparedQuery($sql, $types, ...$params) {
        $conn = $this->getConnection();
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        return $stmt->get_result();
    }

    public function close() {
        if ($this->conn) {
            $this->conn->close();
            $this->conn = null;
        }
    }
}

// Query builder with fluent interface -- VULN when user input used in conditions
class QueryBuilder {
    private $table = '';
    private $conditions = [];
    private $orderClause = '';
    private $limitClause = '';
    private $joinClauses = [];
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    public function select(string $table) {
        $this->table = $table;
        return $this;
    }

    public function where(string $condition) {
        $this->conditions[] = $condition;
        return $this;
    }

    public function join(string $joinClause) {
        $this->joinClauses[] = $joinClause;
        return $this;
    }

    public function orderBy(string $field) {
        $this->orderClause = " ORDER BY " . $field;
        return $this;
    }

    public function limit(int $count, int $offset = 0) {
        $this->limitClause = " LIMIT " . intval($count) . " OFFSET " . intval($offset);
        return $this;
    }

    public function buildSQL() {
        $sql = "SELECT * FROM " . $this->table;
        foreach ($this->joinClauses as $join) {
            $sql .= " " . $join;
        }
        if (!empty($this->conditions)) {
            $sql .= " WHERE " . implode(" AND ", $this->conditions);
        }
        $sql .= $this->orderClause;
        $sql .= $this->limitClause;
        return $sql;
    }

    // VULN: executes assembled SQL containing tainted fragments
    public function execute() {
        $sql = $this->buildSQL();
        return $this->db->rawQuery($sql);
    }
}

// Article repository
class ArticleRepository {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection via tainted filter string
    public function findByFilter($filterSQL) {
        $sql = "SELECT * FROM articles WHERE " . $filterSQL;
        return $this->db->rawQuery($sql);
    }

    // Safe version with prepared statements
    public function findByFilterSafe($query, $sortBy) {
        $allowed = ['date' => 'created_at', 'title' => 'title'];
        $safeSort = $allowed[$sortBy] ?? 'created_at';
        $sql = "SELECT * FROM articles WHERE title LIKE ? ORDER BY " . $safeSort;
        $param = "%" . $query . "%";
        return $this->db->preparedQuery($sql, "s", $param);
    }

    public function findAll($offset, $limit) {
        return $this->db->preparedQuery(
            "SELECT * FROM articles ORDER BY created_at DESC LIMIT ? OFFSET ?",
            "ii", $limit, $offset
        );
    }

    public function findById($id) {
        $result = $this->db->preparedQuery("SELECT * FROM articles WHERE id = ?", "i", $id);
        return $result ? $result->fetch_assoc() : null;
    }

    public function create($title, $content, $authorId) {
        return $this->db->preparedQuery(
            "INSERT INTO articles (title, content, author_id) VALUES (?, ?, ?)",
            "ssi", $title, $content, $authorId
        );
    }

    // VULN: SQL injection in tag search
    public function findByTag($tag) {
        $sql = "SELECT * FROM articles WHERE tags LIKE '%" . $tag . "%'";
        return $this->db->rawQuery($sql);
    }

    // VULN: SQL injection in full-text search
    public function fullTextSearch($term, $category) {
        $sql = "SELECT * FROM articles WHERE MATCH(title, content) AGAINST('" . $term . "') AND category = '" . $category . "'";
        return $this->db->rawQuery($sql);
    }
}

// Product repository for e-commerce
class ProductRepository {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection in product search
    public function searchProducts($keyword) {
        $sql = "SELECT * FROM products WHERE name LIKE '%" . $keyword . "%'";
        return $this->db->rawQuery($sql);
    }

    // VULN: SQL injection in price range filter
    public function filterByPrice($minPrice, $maxPrice, $sortField) {
        $sql = "SELECT * FROM products WHERE price BETWEEN " . $minPrice . " AND " . $maxPrice . " ORDER BY " . $sortField;
        return $this->db->rawQuery($sql);
    }

    // Safe version
    public function filterByPriceSafe($minPrice, $maxPrice) {
        $safeMin = floatval($minPrice);
        $safeMax = floatval($maxPrice);
        return $this->db->preparedQuery(
            "SELECT * FROM products WHERE price BETWEEN ? AND ? ORDER BY price",
            "dd", $safeMin, $safeMax
        );
    }

    public function findById($id) {
        $result = $this->db->preparedQuery("SELECT * FROM products WHERE id = ?", "i", $id);
        return $result ? $result->fetch_assoc() : null;
    }

    // VULN: SQL injection via category
    public function findByCategory($category) {
        $sql = "SELECT * FROM products WHERE category = '" . $category . "'";
        return $this->db->rawQuery($sql);
    }
}

// Order repository
class OrderRepository {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection in order lookup
    public function findByCustomer($customerId) {
        $sql = "SELECT * FROM orders WHERE customer_id = '" . $customerId . "'";
        return $this->db->rawQuery($sql);
    }

    // VULN: SQL injection in date range filter
    public function findByDateRange($startDate, $endDate) {
        $sql = "SELECT * FROM orders WHERE created_at BETWEEN '" . $startDate . "' AND '" . $endDate . "'";
        return $this->db->rawQuery($sql);
    }

    public function createOrder($customerId, $total, $status) {
        return $this->db->preparedQuery(
            "INSERT INTO orders (customer_id, total, status) VALUES (?, ?, ?)",
            "ids", $customerId, $total, $status
        );
    }

    // VULN: SQL injection in status update
    public function updateStatus($orderId, $status) {
        $sql = "UPDATE orders SET status = '" . $status . "' WHERE id = " . $orderId;
        return $this->db->rawQuery($sql);
    }
}

// Comment repository
class CommentRepository {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    public function findByArticle($articleId) {
        return $this->db->preparedQuery(
            "SELECT * FROM comments WHERE article_id = ? ORDER BY created_at DESC",
            "i", $articleId
        );
    }

    // VULN: SQL injection in comment search
    public function search($keyword) {
        $sql = "SELECT * FROM comments WHERE content LIKE '%" . $keyword . "%'";
        return $this->db->rawQuery($sql);
    }

    public function create($articleId, $authorName, $content) {
        return $this->db->preparedQuery(
            "INSERT INTO comments (article_id, author_name, content) VALUES (?, ?, ?)",
            "iss", $articleId, $authorName, $content
        );
    }
}

// Audit log repository
class AuditRepository {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    public function log($userId, $action, $details) {
        return $this->db->preparedQuery(
            "INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)",
            "iss", $userId, $action, $details
        );
    }

    // VULN: SQL injection in audit filter
    public function searchByFilter($filter) {
        $sql = "SELECT * FROM audit_log WHERE " . $filter;
        return $this->db->rawQuery($sql);
    }
}
