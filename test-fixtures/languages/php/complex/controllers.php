<?php

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/security.php';
require_once __DIR__ . '/template_engine.php';

// Search query value object -- builds SQL filter from user input
class SearchQuery {
    private $rawQuery;
    private $sortField;
    private $categoryFilter;

    public function __construct($query, $sortBy, $category = '') {
        $this->rawQuery = $query;
        $this->sortField = $sortBy;
        $this->categoryFilter = $category;
    }

    public function validate() {
        if (strlen($this->rawQuery) > 500) {
            throw new InvalidArgumentException('Query too long');
        }
    }

    // VULN: SQL injection in filter building (tainted rawQuery concatenated)
    public function buildFilterSQL() {
        $parts = [];
        if ($this->rawQuery) {
            $parts[] = "title LIKE '%" . $this->rawQuery . "%'";
        }
        if ($this->categoryFilter) {
            $parts[] = "category = '" . $this->categoryFilter . "'";
        }
        $sql = implode(" AND ", $parts);
        if ($this->sortField) {
            $sql .= " ORDER BY " . $this->sortField;
        }
        return $sql;
    }

    public function getRawQuery() {
        return $this->rawQuery;
    }
}

// Article controller -- handles article CRUD and search
class ArticleController {
    private $db;
    private $articleRepo;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->articleRepo = new ArticleRepository($db);
    }

    // Multi-hop VULN: $_GET -> SearchQuery -> buildFilterSQL -> ArticleRepository -> rawQuery -> mysqli_query
    public function search($query, $sortBy, $category = '') {
        $searchQuery = new SearchQuery($query, $sortBy, $category);
        $searchQuery->validate();
        $filterSQL = $searchQuery->buildFilterSQL();
        return $this->articleRepo->findByFilter($filterSQL);
    }

    private function listArticles($page = 1, $perPage = 20) {
        $offset = ($page - 1) * $perPage;
        return $this->articleRepo->findAll($offset, $perPage);
    }

    private function getArticleById($id) {
        return $this->articleRepo->findById($id);
    }

    // VULN: XSS in article rendering + file write
    public function renderArticle($id) {
        $article = $this->articleRepo->findById($id);
        $html = '<article>';
        $html .= '<h1>' . $article['title'] . '</h1>';
        $html .= '<div>' . $article['content'] . '</div>';
        $html .= '</article>';
        // Also cache to file (adds file_put_contents chain)
        file_put_contents('/var/cache/article_' . $id . '.html', $html);
        return $html;
    }

    // Multi-hop: search by tag flows through repository
    public function searchByTag($tag) {
        return $this->articleRepo->findByTag($tag);
    }

    // Multi-hop: full-text search with category
    public function fullTextSearch($term, $category) {
        return $this->articleRepo->fullTextSearch($term, $category);
    }
}

// Product controller for e-commerce
class ProductController {
    private $db;
    private $productRepo;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->productRepo = new ProductRepository($db);
    }

    // Multi-hop VULN: user input -> normalizeSearchTerm -> searchProducts -> rawQuery -> mysqli_query
    public function search($keyword) {
        $normalized = $this->normalizeSearchTerm($keyword);
        return $this->productRepo->searchProducts($normalized);
    }

    private function normalizeSearchTerm($term) {
        $trimmed = trim($term);
        $lower = strtolower($trimmed);
        return $lower;
    }

    // Multi-hop VULN: price filter with tainted sort field
    public function filterProducts($minPrice, $maxPrice, $sortField) {
        return $this->productRepo->filterByPrice($minPrice, $maxPrice, $sortField);
    }

    private function getProductById($id) {
        return $this->productRepo->findById($id);
    }

    // Multi-hop VULN: category browsing
    public function browseCategory($category) {
        $formatted = $this->formatCategory($category);
        return $this->productRepo->findByCategory($formatted);
    }

    private function formatCategory($cat) {
        $formatted = str_replace('-', ' ', $cat);
        return $formatted;
    }
}

// Order controller
class OrderController {
    private $db;
    private $orderRepo;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->orderRepo = new OrderRepository($db);
    }

    // Multi-hop VULN: order lookup with tainted customer ID
    public function getCustomerOrders($customerId) {
        $sanitizedId = $this->preprocessId($customerId);
        return $this->orderRepo->findByCustomer($sanitizedId);
    }

    private function preprocessId($id) {
        // Weak "sanitization" that does not prevent SQLi
        $cleaned = trim($id);
        return $cleaned;
    }

    // Multi-hop VULN: date range search
    public function searchByDateRange($startDate, $endDate) {
        return $this->orderRepo->findByDateRange($startDate, $endDate);
    }

    // Multi-hop VULN: status update
    public function updateOrderStatus($orderId, $status) {
        $formattedStatus = $this->formatStatus($status);
        return $this->orderRepo->updateStatus($orderId, $formattedStatus);
    }

    private function formatStatus($status) {
        $upper = strtoupper($status);
        return $upper;
    }

    public function createOrder($customerId, $items) {
        $total = 0.0;
        foreach ($items as $item) {
            $total += $item['price'] * $item['quantity'];
        }
        return $this->orderRepo->createOrder($customerId, $total, 'pending');
    }
}

// User controller with profile management
class UserController {
    private $db;
    private $authService;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->authService = new AuthService($db);
    }

    // Multi-hop VULN: login with SQL injection
    public function loginUnsafe($username, $password) {
        return $this->authService->authenticateUnsafe($username, $password);
    }

    private function loginSafe($username, $password) {
        return $this->authService->authenticate($username, $password);
    }

    // Multi-hop VULN: password reset token lookup
    public function resetPassword($token) {
        $result = $this->authService->lookupResetToken($token);
        return $result;
    }

    // VULN: SQL injection in user search
    public function searchUsers($query) {
        $conn = $this->db->getConnection();
        $sql = "SELECT * FROM users WHERE username LIKE '%" . $query . "%'";
        $result = mysqli_query($conn, $sql);
        return $result;
    }

    private function registerUser($username, $email, $password) {
        $hash = Security::hashPassword($password);
        return $this->db->preparedQuery(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            "sss", $username, $email, $hash
        );
    }
}

// Admin controller
class AdminController {
    private $db;
    private $accessControl;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->accessControl = new AccessControl($db);
    }

    // VULN: Command injection in backup creation
    public function createBackup($format) {
        $cmd = "mysqldump --format=" . $format . " cms > /tmp/backup.sql";
        exec($cmd, $output);
        return implode("\n", $output);
    }

    // VULN: Command injection in image processing
    public function processImage($filename, $width, $height) {
        $cmd = "convert /var/www/uploads/" . $filename . " -resize " . $width . "x" . $height . " /var/www/uploads/resized_" . $filename;
        exec($cmd);
    }

    // Multi-hop VULN: permission check with tainted user ID
    public function checkAccess($userId, $permission) {
        return $this->accessControl->hasPermission($userId, $permission);
    }

    // Multi-hop VULN: audit log search
    public function searchAuditLogs($filter) {
        $auditRepo = new AuditRepository($this->db);
        $formattedFilter = $this->buildAuditFilter($filter);
        return $auditRepo->searchByFilter($formattedFilter);
    }

    private function buildAuditFilter($rawFilter) {
        $filter = "action LIKE '%" . $rawFilter . "%'";
        return $filter;
    }

    // Multi-hop VULN: system diagnostics
    public function runDiagnostic($command) {
        $prepared = $this->prepareCommand($command);
        $output = shell_exec($prepared);
        return $output;
    }

    private function prepareCommand($cmd) {
        $full = "/usr/bin/" . $cmd;
        return $full;
    }
}

// CMS page controller -- handles dynamic pages
class PageController {
    private $db;
    private $templateEngine;

    public function __construct(DatabaseConnection $db, TemplateEngine $engine) {
        $this->db = $db;
        $this->templateEngine = $engine;
    }

    // Multi-hop VULN: page name -> resolveTemplatePath -> include
    public function renderPage($pageName) {
        return $this->templateEngine->render($pageName);
    }

    // Multi-hop VULN: load page content from filesystem
    public function loadPageContent($pagePath) {
        return $this->templateEngine->loadRawTemplate($pagePath);
    }

    // Multi-hop VULN: dynamic page eval
    public function evalDynamicPage($code) {
        return $this->templateEngine->evalTemplate($code, []);
    }

    // Multi-hop VULN: page render and cache
    public function renderAndCachePage($templateName, $data) {
        return $this->templateEngine->renderAndCache($templateName, $data);
    }

    // Multi-hop VULN: compile page with user content
    public function compilePageContent($templateStr, $vars) {
        $compiled = $this->templateEngine->compileTemplate($templateStr, $vars);
        $this->templateEngine->cacheCompiledTemplate('page-cache', $compiled);
        return $compiled;
    }
}

// Notification service
class NotificationService {
    private $emailRenderer;

    public function __construct(EmailRenderer $renderer) {
        $this->emailRenderer = $renderer;
    }

    // Multi-hop VULN: send notification -> exec(sendmail)
    public function sendAlert($to, $subject, $message) {
        $this->emailRenderer->sendNotification($to, $subject, $message);
    }

    // Multi-hop VULN: render and send
    public function notifyUser($email, $title, $body) {
        $html = $this->emailRenderer->renderNotification($email, $title, $body);
        return $html;
    }
}

// Export service for reports
class ExportService {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: Command injection in PDF export
    public function exportToPdf($htmlContent, $outputPath) {
        $cmd = "wkhtmltopdf - " . $outputPath;
        exec($cmd);
    }

    // VULN: Command injection in CSV export
    public function exportToCsv($query, $outputFile) {
        $cmd = "mysql -e \"" . $query . "\" > " . $outputFile;
        exec($cmd);
    }

    // VULN: SQL injection in data export
    public function exportData($tableName, $filter) {
        $sql = "SELECT * FROM " . $tableName . " WHERE " . $filter;
        return $this->db->rawQuery($sql);
    }
}

// Inventory service
class InventoryService {
    private $productRepo;

    public function __construct(ProductRepository $repo) {
        $this->productRepo = $repo;
    }

    // Multi-hop VULN: search products through inventory layer
    public function findAvailableProducts($keyword) {
        return $this->productRepo->searchProducts($keyword);
    }

    // Multi-hop VULN: filter by category through inventory layer
    public function getProductsByCategory($category) {
        return $this->productRepo->findByCategory($category);
    }

    // Multi-hop VULN: price range search
    public function findInPriceRange($min, $max, $sort) {
        return $this->productRepo->filterByPrice($min, $max, $sort);
    }
}


// Shipping calculator with command injection
class ShippingService {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: Command injection in label generation
    public function generateLabel($address) {
        $cmd = "lpr -P label_printer -o " . $address;
        exec($cmd);
    }

    // VULN: SQL injection in rate lookup
    public function lookupRate($destination) {
        $sql = "SELECT rate FROM shipping_rates WHERE destination = '" . $destination . "'";
        return $this->db->rawQuery($sql);
    }

    // VULN: Command injection in tracking
    public function trackPackage($trackingNumber) {
        $cmd = "curl https://api.shipping.com/track/" . $trackingNumber;
        $output = shell_exec($cmd);
        return $output;
    }
}

// Cron/task scheduler
class TaskScheduler {
    // VULN: Command injection in scheduled tasks
    public function scheduleTask($command, $schedule) {
        $cmd = "echo '" . $schedule . " " . $command . "' | crontab -";
        exec($cmd);
    }

    // VULN: eval in dynamic task execution
    public function executeDynamicTask($taskCode) {
        $result = eval($taskCode);
        return $result;
    }
}

// Search indexer
class SearchIndexer {
    private $db;

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
    }

    // VULN: SQL injection in index rebuild
    public function rebuildIndex($tableName) {
        $sql = "SELECT * FROM " . $tableName . " WHERE indexed = 0";
        return $this->db->rawQuery($sql);
    }

    // VULN: SQL injection in search query
    public function searchIndex($query, $index) {
        $sql = "SELECT * FROM search_index WHERE index_name = '" . $index . "' AND content LIKE '%" . $query . "%'";
        return $this->db->rawQuery($sql);
    }
}

// Cache manager
class CacheManager {
    // VULN: Path traversal in cache file operations
    public function readCache($key) {
        $path = '/var/cache/' . $key . '.dat';
        return file_get_contents($path);
    }

    // VULN: Tainted content written to cache
    public function writeCache($key, $data) {
        $path = '/var/cache/' . $key . '.dat';
        file_put_contents($path, $data);
    }

    // VULN: Command injection in cache purge
    public function purgeCache($pattern) {
        $cmd = "rm -rf /var/cache/" . $pattern;
        exec($cmd);
    }
}

// Image gallery manager
class GalleryManager {
    private $mediaProcessor;

    public function __construct(MediaProcessor $processor) {
        $this->mediaProcessor = $processor;
    }

    // Multi-hop VULN: gallery upload -> resizeImage -> exec
    public function uploadToGallery($filename, $dimensions) {
        return $this->mediaProcessor->resizeImage($filename, $dimensions);
    }

    // Multi-hop VULN: gallery download -> getFile -> file_get_contents
    public function downloadFromGallery($path) {
        return $this->mediaProcessor->getFile($path);
    }
}

// Report generator using template engine
class ReportGenerator {
    private $templateEngine;
    private $db;

    public function __construct(DatabaseConnection $db, TemplateEngine $engine) {
        $this->db = $db;
        $this->templateEngine = $engine;
    }

    // Multi-hop VULN: report content flows through template engine to file
    public function generateReport($reportName, $data) {
        $compiled = $this->templateEngine->compileTemplate(
            '<h1>Report: {{title}}</h1><div>{{content}}</div>',
            $data
        );
        $this->templateEngine->cacheCompiledTemplate($reportName, $compiled);
        return $compiled;
    }

    // Multi-hop VULN: render and store report with user data
    public function renderCustomReport($templateName, $userContent) {
        $data = ['content' => $userContent, 'timestamp' => date('Y-m-d')];
        return $this->templateEngine->renderAndCache($templateName, $data);
    }
}
