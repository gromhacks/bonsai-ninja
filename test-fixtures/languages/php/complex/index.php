<?php

// Front controller for e-commerce CMS.
// Routes requests to controllers, handles dispatch and middleware.

require_once __DIR__ . '/controllers.php';
require_once __DIR__ . '/database.php';
require_once __DIR__ . '/template_engine.php';
require_once __DIR__ . '/security.php';

// Router class
class Router {
    private $routes = [];

    public function get($path, $handler) {
        $this->routes['GET'][$path] = $handler;
    }

    public function post($path, $handler) {
        $this->routes['POST'][$path] = $handler;
    }

    public function dispatch($method, $path) {
        if (isset($this->routes[$method][$path])) {
            $handler = $this->routes[$method][$path];
            return call_user_func($handler);
        }
        http_response_code(404);
        echo json_encode(['error' => 'Not found']);
    }
}

// Request helper
class RequestHelper {
    public static function getQueryParam($name, $default = '') {
        $value = $_GET[$name] ?? $default;
        return $value;
    }

    public static function getPostParam($name, $default = '') {
        $value = $_POST[$name] ?? $default;
        return $value;
    }

    public static function getHeader($name) {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        $value = $_SERVER[$key] ?? '';
        return $value;
    }

    public static function getClientIp() {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'];
        return $ip;
    }

    public static function getRequestBody() {
        $body = file_get_contents('php://input');
        return $body;
    }

    public static function getJsonBody() {
        $raw = self::getRequestBody();
        $decoded = json_decode($raw, true);
        return $decoded;
    }

    public static function getCookie($name) {
        $value = $_COOKIE[$name] ?? '';
        return $value;
    }
}

// Application bootstrap
$config = [
    'db_host' => getenv('DB_HOST') ?: 'localhost',
    'db_name' => getenv('DB_NAME') ?: 'ecommerce_cms',
    'db_user' => getenv('DB_USER') ?: 'root',
    'db_pass' => getenv('DB_PASS') ?: '',
];

$db = new DatabaseConnection($config['db_host'], $config['db_name'], $config['db_user'], $config['db_pass']);
$articleController = new ArticleController($db);
$productController = new ProductController($db);
$orderController = new OrderController($db);
$userController = new UserController($db);
$adminController = new AdminController($db);
$templateEngine = new TemplateEngine($db);
$reportGenerator = new ReportGenerator($db, $templateEngine);
$router = new Router();

// ---- Closure-based routes ----

$router->get('/api/articles/search', function() use ($articleController) {
    $query = $_GET['q'] ?? '';
    $sort = $_GET['sort'] ?? 'date';
    $category = $_GET['cat'] ?? '';
    $results = $articleController->search($query, $sort, $category);
    echo json_encode($results);
});

$router->get('/api/articles/by-tag', function() use ($articleController) {
    $tag = $_GET['tag'];
    $results = $articleController->searchByTag($tag);
    echo json_encode($results);
});

$router->get('/api/articles/fulltext', function() use ($articleController) {
    $term = $_GET['q'];
    $category = $_GET['cat'];
    $results = $articleController->fullTextSearch($term, $category);
    echo json_encode($results);
});

$router->get('/api/products/search', function() use ($productController) {
    $keyword = $_GET['q'];
    $results = $productController->search($keyword);
    echo json_encode($results);
});

$router->get('/api/products/filter', function() use ($productController) {
    $min = $_GET['min'];
    $max = $_GET['max'];
    $sort = $_GET['sort'];
    $results = $productController->filterProducts($min, $max, $sort);
    echo json_encode($results);
});

$router->get('/api/products/category', function() use ($productController) {
    $category = $_GET['category'];
    $results = $productController->browseCategory($category);
    echo json_encode($results);
});

$router->get('/api/orders', function() use ($orderController) {
    $customerId = $_GET['customer_id'];
    $results = $orderController->getCustomerOrders($customerId);
    echo json_encode($results);
});

$router->post('/api/orders/search', function() use ($orderController) {
    $start = $_POST['start_date'];
    $end = $_POST['end_date'];
    $results = $orderController->searchByDateRange($start, $end);
    echo json_encode($results);
});

$router->post('/api/orders/status', function() use ($orderController) {
    $orderId = $_POST['order_id'];
    $status = $_POST['status'];
    $orderController->updateOrderStatus($orderId, $status);
    echo json_encode(['ok' => true]);
});

$router->post('/api/auth/login-unsafe', function() use ($userController) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $result = $userController->loginUnsafe($username, $password);
    echo json_encode($result);
});

$router->post('/api/auth/reset', function() use ($userController) {
    $token = $_POST['token'];
    $result = $userController->resetPassword($token);
    echo json_encode($result);
});

$router->get('/api/users/search', function() use ($userController) {
    $query = $_GET['q'];
    $result = $userController->searchUsers($query);
    echo json_encode($result);
});

$router->post('/api/admin/backup', function() use ($adminController) {
    $format = $_POST['format'];
    $output = $adminController->createBackup($format);
    echo json_encode(['output' => $output]);
});

$router->post('/api/admin/diagnostic', function() use ($adminController) {
    $command = $_POST['command'];
    $output = $adminController->runDiagnostic($command);
    echo json_encode(['output' => $output]);
});

$router->get('/api/admin/audit', function() use ($adminController) {
    $filter = $_GET['filter'];
    $results = $adminController->searchAuditLogs($filter);
    echo json_encode($results);
});

$router->post('/api/admin/image', function() use ($adminController) {
    $filename = $_POST['filename'];
    $width = $_POST['width'];
    $height = $_POST['height'];
    $adminController->processImage($filename, $width, $height);
});

// Direct vulnerability routes
$router->get('/api/raw-search', function() use ($db) {
    $query = $_GET['q'];
    $sql = "SELECT * FROM articles WHERE title LIKE '%" . $query . "%'";
    $result = $db->rawQuery($sql);
    echo json_encode($result);
});

$router->post('/api/admin/system', function() {
    $command = $_POST['command'];
    $output = shell_exec($command);
    echo json_encode(['output' => $output]);
});

$router->post('/api/admin/eval', function() {
    $expression = $_POST['expression'];
    $result = eval('return ' . $expression . ';');
    echo json_encode(['result' => $result]);
});

$router->get('/api/pages', function() {
    $page = $_GET['page'];
    include('/var/www/pages/' . $page . '.php');
});

$router->post('/api/session/restore', function() {
    $data = $_POST['session_data'];
    $decoded = base64_decode($data);
    $session = unserialize($decoded);
    echo json_encode(['session' => $session]);
});

$router->get('/api/proxy', function() {
    $url = $_GET['url'];
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    echo $response;
});

$router->get('/api/files/download', function() {
    $filename = $_GET['filename'];
    $path = '/var/www/uploads/' . $filename;
    $content = file_get_contents($path);
    header('Content-Type: application/octet-stream');
    echo $content;
});

$router->post('/api/files/upload', function() {
    $uploadDir = '/var/www/uploads/';
    $filename = $_FILES['file']['name'];
    $tmpName = $_FILES['file']['tmp_name'];
    move_uploaded_file($tmpName, $uploadDir . $filename);
    echo json_encode(['uploaded' => $filename]);
});

$router->post('/api/validate', function() {
    $pattern = $_POST['pattern'];
    $input = $_POST['input'];
    $result = preg_match('/' . $pattern . '/', $input);
    echo json_encode(['match' => (bool)$result]);
});

$router->get('/admin/dashboard', function() {
    $search = $_GET['search'] ?? '';
    echo '<p>Search: ' . $search . '</p>';
});

// Template/Report routes
$router->post('/api/reports/generate', function() use ($reportGenerator) {
    $title = $_POST['title'];
    $content = $_POST['content'];
    $data = ['title' => $title, 'content' => $content];
    $result = $reportGenerator->generateReport('custom-report', $data);
    echo $result;
});

$router->post('/api/reports/custom', function() use ($reportGenerator) {
    $templateName = $_POST['template'];
    $userContent = $_POST['content'];
    $result = $reportGenerator->renderCustomReport($templateName, $userContent);
    echo $result;
});

$router->get('/api/template/render', function() use ($templateEngine) {
    $templateName = $_GET['template'];
    $result = $templateEngine->render($templateName);
    echo $result;
});

$router->get('/api/template/load', function() use ($templateEngine) {
    $name = $_GET['name'];
    $content = $templateEngine->loadRawTemplate($name);
    echo $content;
});

$router->post('/api/template/eval', function() use ($templateEngine) {
    $code = $_POST['code'];
    $result = $templateEngine->evalTemplate($code, []);
    echo json_encode(['result' => $result]);
});

$router->get('/api/session/check', function() use ($db) {
    $sessionMgr = new SessionManager($db);
    $session = $sessionMgr->resumeSession();
    echo json_encode($session);
});

// Dispatch
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
$router->dispatch($method, $path);
