<?php

// Cross-module integration chains exercising data flow across all PHP example files.
// Each chain documents the full hop sequence and which files are involved.

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/controllers.php';
require_once __DIR__ . '/template_engine.php';
require_once __DIR__ . '/security.php';

// ===========================================================================
// Chain A: Deep SQL injection across 4 files (6+ hops)
// cross_module -> ArticleController -> SearchQuery -> ArticleRepository -> rawQuery -> mysqli_query
// ===========================================================================

function formatSearchInput($raw) {
    $trimmed = trim($raw);
    return $trimmed;
}

function buildFilterPayload($input) {
    $payload = $input;
    return $payload;
}

function chainA_deepSqlInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $controller = new ArticleController($db);

    $searchInput = $_GET['search'];
    $formatted = formatSearchInput($searchInput);
    $filterPayload = buildFilterPayload($formatted);
    $results = $controller->search($filterPayload, 'title');
    // Also log the search
    file_put_contents('/var/log/searches.log', $searchInput . "\n", FILE_APPEND);
    return $results;
}

// ===========================================================================
// Chain B: Template engine stored XSS across files (5+ hops)
// cross_module -> TemplateEngine -> compileTemplate -> cacheCompiledTemplate -> file_put_contents
// ===========================================================================

$THEME_OVERRIDE = $_SERVER['HTTP_X_CUSTOM_THEME'] ?? 'default';

function chainB_globalVariableTaint() {
    global $THEME_OVERRIDE;

    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $templateStr = '<html><head><style>{{theme}}</style></head><body>Hello</body></html>';
    $data = ['theme' => $THEME_OVERRIDE];
    $compiled = $engine->compileTemplate($templateStr, $data);
    file_put_contents('/var/www/cache/themed_page.html', $compiled);
    return $compiled;
}

// ===========================================================================
// Chain C: Callback taint through closure to SQL injection
// cross_module -> CommentRepository -> search -> rawQuery -> mysqli_query
// ===========================================================================

function chainC_callbackTaint() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $commentRepo = new CommentRepository($db);

    $keyword = $_POST['keyword'];
    $conn = $db->getConnection();
    $sql = "SELECT * FROM comments WHERE body LIKE '%" . $keyword . "%'";
    $results = mysqli_query($conn, $sql);
    // Also export results
    $cmd = "echo '" . $keyword . "' >> /var/log/searches.log";
    exec($cmd);
    $commentRepo->search($keyword);
    return $results;
}

// ===========================================================================
// Chain D: Plugin installation command injection (4+ hops)
// cross_module -> buildPluginUrl -> PluginSystem -> installFromUrl -> exec
// ===========================================================================

function buildPluginUrl($pluginSlug) {
    $baseUrl = 'https://plugins.example.com/download/';
    $url = $baseUrl . $pluginSlug . '.zip';
    return $url;
}

function installPluginFromMarketplace($slug) {
    $pluginSystem = new PluginSystem();
    $downloadUrl = buildPluginUrl($slug);
    $pluginSystem->installFromUrl($downloadUrl);
}

function chainD_reexportedWrapper() {
    $pluginSlug = $_GET['plugin'];
    installPluginFromMarketplace($pluginSlug);
    // Also load plugin after install
    $pluginSystem = new PluginSystem();
    $pluginSystem->loadPlugin($pluginSlug);
}

// ===========================================================================
// Chain E: Recursive taint to audit log SQL injection (5+ hops)
// cross_module -> resolveNestedPath -> buildAuditFilter -> AuditRepository -> rawQuery -> mysqli_query
// ===========================================================================

function resolveNestedPath($dotPath) {
    $parts = explode('.', $dotPath);
    if (count($parts) <= 1) {
        return $dotPath;
    }
    $remaining = implode('.', array_slice($parts, 1));
    return resolveNestedPath($remaining);
}

function buildAuditFilter($resolvedKey) {
    $filter = "action = '" . $resolvedKey . "'";
    return $filter;
}

function chainE_recursiveTaint() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $auditRepo = new AuditRepository($db);

    $nestedPath = $_POST['path'];
    $leafKey = resolveNestedPath($nestedPath);
    $filter = buildAuditFilter($leafKey);
    $results = $auditRepo->searchByFilter($filter);
    // Include resolved path as config
    include('/var/config/' . $leafKey . '.php');
    return $results;
}

// ===========================================================================
// Chain F: Product search across controllers + database (5+ hops)
// cross_module -> ProductController -> normalizeSearchTerm -> ProductRepository -> rawQuery -> mysqli_query
// ===========================================================================

function processProductSearch($keyword, $category) {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $productController = new ProductController($db);
    $results = $productController->search($keyword);
    return $results;
}

function chainF_productSearch() {
    $keyword = $_GET['product_search'];
    $category = $_GET['product_cat'];
    $results = processProductSearch($keyword, $category);
    // Also fetch product images from external CDN
    $cdnUrl = "https://cdn.example.com/search?q=" . $keyword;
    $images = file_get_contents($cdnUrl);
    return $results;
}

// ===========================================================================
// Chain G: Order lookup with weak sanitization (5+ hops)
// cross_module -> formatOrderQuery -> OrderController -> preprocessId -> OrderRepository -> rawQuery -> mysqli_query
// ===========================================================================

function formatOrderQuery($customerId) {
    $formatted = trim($customerId);
    return $formatted;
}

function chainG_orderLookup() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $orderController = new OrderController($db);

    $customerId = $_GET['customer'];
    $formatted = formatOrderQuery($customerId);
    $results = $orderController->getCustomerOrders($formatted);
    // Export customer data
    $cmd = "mysql -e 'SELECT * FROM customers WHERE id=" . $customerId . "' > /tmp/customer.csv";
    shell_exec($cmd);
    return $results;
}

// ===========================================================================
// Chain H: Session fixation through cookie to SQL injection (5+ hops)
// cross_module -> SessionManager -> loadSession -> rawQuery -> mysqli_query
// ===========================================================================

function extractSessionId() {
    $rawCookie = $_COOKIE['session_token'];
    $decoded = base64_decode($rawCookie);
    return $decoded;
}

function chainH_sessionFixation() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $sessionMgr = new SessionManager($db);

    $sessionId = extractSessionId();
    $session = $sessionMgr->loadSession($sessionId);
    return $session;
}

// ===========================================================================
// Chain I: Report generation with template injection (5+ hops)
// cross_module -> prepareReportData -> ReportGenerator -> compileTemplate -> cacheCompiledTemplate -> file_put_contents
// ===========================================================================

function prepareReportData($title, $content) {
    $data = [
        'title' => $title,
        'content' => $content,
    ];
    return $data;
}

function chainI_reportInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);
    $reportGen = new ReportGenerator($db, $engine);

    $title = $_POST['report_title'];
    $content = $_POST['report_content'];
    $data = prepareReportData($title, $content);
    $result = $reportGen->generateReport('user-report', $data);
    return $result;
}

// ===========================================================================
// Chain J: Admin diagnostic command injection (5+ hops)
// cross_module -> normalizeCommand -> AdminController -> runDiagnostic -> prepareCommand -> shell_exec
// ===========================================================================

function normalizeCommand($cmd) {
    $normalized = strtolower(trim($cmd));
    return $normalized;
}

function chainJ_adminDiagnostic() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $adminController = new AdminController($db);

    $command = $_POST['diagnostic_cmd'];
    $normalized = normalizeCommand($command);
    $output = $adminController->runDiagnostic($normalized);
    return $output;
}

// ===========================================================================
// Chain K: User login SQL injection through auth service (5+ hops)
// cross_module -> validateCredentials -> UserController -> AuthService -> rawQuery -> mysqli_query
// ===========================================================================

function validateCredentials($username, $password) {
    $cleanUser = trim($username);
    $cleanPass = trim($password);
    return [$cleanUser, $cleanPass];
}

function chainK_loginInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $userController = new UserController($db);

    $username = $_POST['login_user'];
    $password = $_POST['login_pass'];
    $creds = validateCredentials($username, $password);
    $result = $userController->loginUnsafe($creds[0], $creds[1]);
    // Log login attempt
    $logEntry = date('Y-m-d H:i:s') . " login attempt: " . $username;
    file_put_contents('/var/log/auth.log', $logEntry . "\n", FILE_APPEND);
    return $result;
}

// ===========================================================================
// Chain L: Media processor command injection (5+ hops)
// cross_module -> prepareMediaDimensions -> MediaProcessor -> processUpload -> resizeImage -> exec
// ===========================================================================

function prepareMediaDimensions($width, $height) {
    $w = intval($width) > 0 ? $width : '100';
    $h = intval($height) > 0 ? $height : '100';
    return [$w, $h];
}

function chainL_mediaProcessing() {
    $filename = $_POST['media_file'];
    $width = $_POST['media_width'];
    $height = $_POST['media_height'];

    $dims = prepareMediaDimensions($width, $height);
    $processor = new MediaProcessor();
    $processor->processUpload($filename, $dims[0], $dims[1]);
}

// ===========================================================================
// Chain M: Template eval injection (4+ hops)
// cross_module -> buildTemplateCode -> TemplateEngine -> evalTemplate -> eval
// ===========================================================================

function buildTemplateCode($userExpr) {
    $code = '"Result: " . (' . $userExpr . ')';
    return $code;
}

function chainM_templateEval() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $expr = $_POST['eval_expr'];
    $code = buildTemplateCode($expr);
    $result = $engine->evalTemplate($code, []);
    return $result;
}

// ===========================================================================
// Chain N: Access control bypass SQL injection (5+ hops)
// cross_module -> extractUserId -> AdminController -> AccessControl -> rawQuery -> mysqli_query
// ===========================================================================

function extractUserId() {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
    $parts = explode(' ', $authHeader);
    $userId = $parts[1] ?? '0';
    return $userId;
}

function chainN_accessControlBypass() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $adminController = new AdminController($db);

    $userId = extractUserId();
    $result = $adminController->checkAccess($userId, 'admin');
    return $result;
}

// ===========================================================================
// Chain O: Email notification injection (5+ hops)
// cross_module -> formatEmailContent -> EmailRenderer -> renderNotification -> compileTemplate -> exec(sendmail)
// ===========================================================================

function formatEmailContent($rawBody) {
    $formatted = nl2br($rawBody);
    return $formatted;
}

function chainO_emailInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);
    $emailRenderer = new EmailRenderer($engine);

    $to = $_POST['notify_email'];
    $subject = $_POST['notify_subject'];
    $body = $_POST['notify_body'];
    $formatted = formatEmailContent($body);
    $emailRenderer->sendNotification($to, $subject, $formatted);
}

// ===========================================================================
// Chain P: Password reset token SQL injection (5+ hops)
// cross_module -> decodeResetToken -> UserController -> AuthService -> rawQuery -> mysqli_query
// ===========================================================================

function decodeResetToken($encodedToken) {
    $decoded = base64_decode($encodedToken);
    $token = trim($decoded);
    return $token;
}

function chainP_resetTokenInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $userController = new UserController($db);

    $encodedToken = $_POST['reset_token'];
    $token = decodeResetToken($encodedToken);
    $result = $userController->resetPassword($token);
    return $result;
}

// ===========================================================================
// Chain Q: Order status update SQL injection (5+ hops)
// cross_module -> parseOrderUpdate -> OrderController -> formatStatus -> OrderRepository -> rawQuery -> mysqli_query
// ===========================================================================

function parseOrderUpdate($jsonBody) {
    $parsed = json_decode($jsonBody, true);
    return $parsed;
}

function chainQ_orderStatusInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $orderController = new OrderController($db);

    $body = $_POST['order_update'];
    $parsed = parseOrderUpdate($body);
    $orderId = $parsed['order_id'] ?? '0';
    $status = $parsed['status'] ?? 'unknown';
    $orderController->updateOrderStatus($orderId, $status);
}

// ===========================================================================
// Chain R: Audit log filter with admin controller (5+ hops)
// cross_module -> buildSearchFilter -> AdminController -> buildAuditFilter -> AuditRepository -> rawQuery -> mysqli_query
// ===========================================================================

function buildSearchFilter($rawFilter, $dateRange) {
    $combined = $rawFilter . " AND created_at > '" . $dateRange . "'";
    return $combined;
}

function chainR_auditLogInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $adminController = new AdminController($db);

    $filter = $_GET['audit_filter'];
    $dateRange = $_GET['audit_date'];
    $combined = buildSearchFilter($filter, $dateRange);
    $results = $adminController->searchAuditLogs($combined);
    return $results;
}

// ===========================================================================
// Chain S: Direct template render via TemplateEngine (3+ hops)
// cross_module -> TemplateEngine -> render -> resolveTemplatePath -> include
// ===========================================================================

function chainS_templateRenderDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $pageName = $_GET['page_name'];
    $result = $engine->render($pageName);
    return $result;
}

// ===========================================================================
// Chain T: Direct template load path traversal (2+ hops)
// cross_module -> TemplateEngine -> loadRawTemplate -> file_get_contents
// ===========================================================================

function chainT_templateLoadDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $path = $_GET['page_path'];
    $content = $engine->loadRawTemplate($path);
    return $content;
}

// ===========================================================================
// Chain U: Direct template eval injection (2+ hops)
// cross_module -> TemplateEngine -> evalTemplate -> eval
// ===========================================================================

function chainU_templateEvalDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $code = $_POST['page_code'];
    $result = $engine->evalTemplate($code, []);
    return $result;
}

// ===========================================================================
// Chain V: Direct product search SQL injection (3+ hops)
// cross_module -> ProductRepository -> searchProducts -> rawQuery -> mysqli_query
// ===========================================================================

function chainV_productSearchDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $productRepo = new ProductRepository($db);

    $keyword = $_GET['inv_search'];
    $results = $productRepo->searchProducts($keyword);
    return $results;
}

// ===========================================================================
// Chain W: Direct product category SQL injection (3+ hops)
// cross_module -> ProductRepository -> findByCategory -> rawQuery -> mysqli_query
// ===========================================================================

function chainW_productCategoryDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $productRepo = new ProductRepository($db);

    $category = $_GET['inv_category'];
    $results = $productRepo->findByCategory($category);
    return $results;
}

// ===========================================================================
// Chain X: Direct raw query SQL injection (2+ hops)
// cross_module -> DatabaseConnection -> rawQuery -> mysqli_query
// ===========================================================================

function chainX_directRawQuery() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');

    $table = $_GET['export_table'];
    $filter = $_GET['export_filter'];
    $sql = "SELECT * FROM " . $table . " WHERE " . $filter;
    $results = $db->rawQuery($sql);
    // Also write results to file
    file_put_contents('/tmp/export_' . $table . '.json', json_encode($results));
    return $results;
}

// ===========================================================================
// Chain Y: Direct exec command injection
// ===========================================================================

function chainY_directExecCmd() {
    $query = $_POST['csv_query'];
    $outputFile = $_POST['csv_output'];
    $cmd = "mysql -e \"" . $query . "\" > " . $outputFile;
    exec($cmd);
}

// ===========================================================================
// Chain Z: Direct shell_exec command injection
// ===========================================================================

function chainZ_directShellExec() {
    $content = $_POST['pdf_content'];
    $output = $_POST['pdf_output'];
    $cmd = "wkhtmltopdf " . $content . " " . $output;
    shell_exec($cmd);
}

// ===========================================================================
// Chain AA: Template compile + cache (3+ hops)
// cross_module -> TemplateEngine -> compileTemplate -> cacheCompiledTemplate -> file_put_contents
// ===========================================================================

function chainAA_templateCompileCache() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);

    $userContent = $_POST['page_content'];
    $template = '<html><body>{{content}}</body></html>';
    $compiled = $engine->compileTemplate($template, ['content' => $userContent]);
    $engine->cacheCompiledTemplate('page-cache', $compiled);
    return $compiled;
}

// ===========================================================================
// Chain AB: Email renderer notification injection (3+ hops)
// cross_module -> EmailRenderer -> renderNotification -> compileTemplate; sendNotification -> exec
// ===========================================================================

function chainAB_emailRendererDirect() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);
    $emailRenderer = new EmailRenderer($engine);

    $to = $_POST['alert_email'];
    $subject = $_POST['alert_subject'];
    $message = $_POST['alert_message'];
    $emailRenderer->sendNotification($to, $subject, $message);
}

// ===========================================================================
// Chain AC: Product price filter SQL injection (4+ hops)
// cross_module -> ProductController -> filterProducts -> filterByPrice -> rawQuery -> mysqli_query
// ===========================================================================

function chainAC_productPriceFilter() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $productController = new ProductController($db);

    $min = $_GET['price_min'];
    $max = $_GET['price_max'];
    $sort = $_GET['price_sort'];
    $results = $productController->filterProducts($min, $max, $sort);
    return $results;
}

// ===========================================================================
// Chain AD: Product category via controller (4+ hops)
// cross_module -> ProductController -> browseCategory -> formatCategory -> findByCategory -> rawQuery
// ===========================================================================

function chainAD_productCategoryBrowse() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $productController = new ProductController($db);

    $cat = $_GET['browse_cat'];
    $results = $productController->browseCategory($cat);
    return $results;
}

// ===========================================================================
// Chain AE: Order date search (4+ hops)
// cross_module -> OrderController -> searchByDateRange -> findByDateRange -> rawQuery -> mysqli_query
// ===========================================================================

function chainAE_orderDateSearch() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $orderController = new OrderController($db);

    $start = $_POST['order_start'];
    $end = $_POST['order_end'];
    $results = $orderController->searchByDateRange($start, $end);
    return $results;
}

// ===========================================================================
// Chain AF: Article tag search (3+ hops)
// cross_module -> ArticleController -> searchByTag -> findByTag -> rawQuery -> mysqli_query
// ===========================================================================

function chainAF_articleTagSearch() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $articleController = new ArticleController($db);

    $tag = $_GET['article_tag'];
    $results = $articleController->searchByTag($tag);
    return $results;
}

// ===========================================================================
// Chain AG: Article fulltext search (3+ hops)
// cross_module -> ArticleController -> fullTextSearch -> rawQuery -> mysqli_query
// ===========================================================================

function chainAG_articleFulltext() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $articleController = new ArticleController($db);

    $term = $_GET['fulltext_q'];
    $cat = $_GET['fulltext_cat'];
    $results = $articleController->fullTextSearch($term, $cat);
    return $results;
}

// ===========================================================================
// Chain AH: User search via controller (3+ hops)
// cross_module -> UserController -> searchUsers -> mysqli_query
// ===========================================================================

function chainAH_userSearch() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $userController = new UserController($db);

    $query = $_GET['user_q'];
    $result = $userController->searchUsers($query);
    return $result;
}

// ===========================================================================
// Chain AI: Admin backup command injection (2+ hops)
// cross_module -> AdminController -> createBackup -> exec
// ===========================================================================

function chainAI_adminBackup() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $adminController = new AdminController($db);

    $format = $_POST['backup_format'];
    $output = $adminController->createBackup($format);
    return $output;
}

// ===========================================================================
// Chain AJ: Admin image processing command injection (2+ hops)
// cross_module -> AdminController -> processImage -> exec
// ===========================================================================

function chainAJ_adminImageProcess() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $adminController = new AdminController($db);

    $filename = $_POST['img_file'];
    $width = $_POST['img_width'];
    $height = $_POST['img_height'];
    $adminController->processImage($filename, $width, $height);
}

// ===========================================================================
// Chain AK: Media resize command injection (2+ hops)
// cross_module -> MediaProcessor -> resizeImage -> exec
// ===========================================================================

function chainAK_mediaResize() {
    $filename = $_POST['resize_file'];
    $dims = $_POST['resize_dims'];

    $processor = new MediaProcessor();
    $processor->resizeImage($filename, $dims);
}

// ===========================================================================
// Chain AL: Media video conversion (2+ hops)
// cross_module -> MediaProcessor -> convertVideo -> exec
// ===========================================================================

function chainAL_mediaVideoConvert() {
    $inputFile = $_POST['video_file'];
    $format = $_POST['video_format'];

    $processor = new MediaProcessor();
    $processor->convertVideo($inputFile, $format);
}

// ===========================================================================
// Chain AM: Plugin installation (2+ hops)
// cross_module -> PluginSystem -> installFromUrl -> exec
// ===========================================================================

function chainAM_pluginInstall() {
    $url = $_GET['install_url'];
    $pluginSystem = new PluginSystem();
    $pluginSystem->installFromUrl($url);
}

// ===========================================================================
// Chain AN: Plugin loading (2+ hops)
// cross_module -> PluginSystem -> loadPlugin -> include
// ===========================================================================

function chainAN_pluginLoad() {
    $name = $_GET['load_plugin'];
    $pluginSystem = new PluginSystem();
    $pluginSystem->loadPlugin($name);
}

// ===========================================================================
// Chain AO: Session manager SQL injection (2+ hops)
// cross_module -> SessionManager -> loadSession -> rawQuery -> mysqli_query
// ===========================================================================

function chainAO_sessionLookup() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $sessionMgr = new SessionManager($db);

    $sid = $_COOKIE['session_id'];
    $session = $sessionMgr->loadSession($sid);
    return $session;
}

// ===========================================================================
// Chain AP: Auth service SQL injection (3+ hops)
// cross_module -> AuthService -> authenticateUnsafe -> rawQuery -> mysqli_query
// ===========================================================================

function chainAP_authUnsafe() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $authService = new AuthService($db);

    $user = $_POST['auth_user'];
    $pass = $_POST['auth_pass'];
    $result = $authService->authenticateUnsafe($user, $pass);
    return $result;
}

// ===========================================================================
// Chain AQ: Access control SQL injection (2+ hops)
// cross_module -> AccessControl -> hasPermission -> rawQuery -> mysqli_query
// ===========================================================================

function chainAQ_accessControlCheck() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $acl = new AccessControl($db);

    $userId = $_GET['acl_user'];
    $perm = $_GET['acl_perm'];
    $result = $acl->hasPermission($userId, $perm);
    return $result;
}

// ===========================================================================
// Chain AR: Comment search SQL injection (2+ hops)
// cross_module -> CommentRepository -> search -> rawQuery -> mysqli_query
// ===========================================================================

function chainAR_commentSearch() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $commentRepo = new CommentRepository($db);

    $keyword = $_POST['comment_search'];
    $result = $commentRepo->search($keyword);
    return $result;
}

// ===========================================================================
// Chain AS: Article repository tag search (2+ hops)
// cross_module -> ArticleRepository -> findByTag -> rawQuery -> mysqli_query
// ===========================================================================

function chainAS_articleRepoTag() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $articleRepo = new ArticleRepository($db);

    $tag = $_GET['repo_tag'];
    $result = $articleRepo->findByTag($tag);
    return $result;
}

// ===========================================================================
// Chain AT: Order status update SQL injection (4+ hops)
// ===========================================================================

function chainAT_orderStatusUpdate() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $orderController = new OrderController($db);

    $orderId = $_POST['upd_order_id'];
    $status = $_POST['upd_status'];
    $orderController->updateOrderStatus($orderId, $status);
}

// ===========================================================================
// Chain AU: Shipping label command injection (2+ hops)
// ===========================================================================

function chainAU_shippingLabel() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $shipping = new ShippingService($db);

    $address = $_POST['ship_address'];
    $shipping->generateLabel($address);
}

// ===========================================================================
// Chain AV: Shipping rate SQL injection (2+ hops)
// ===========================================================================

function chainAV_shippingRate() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $shipping = new ShippingService($db);

    $destination = $_GET['ship_dest'];
    $result = $shipping->lookupRate($destination);
    return $result;
}

// ===========================================================================
// Chain AW: Shipping tracking command injection (2+ hops)
// ===========================================================================

function chainAW_shippingTracking() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $shipping = new ShippingService($db);

    $trackingNum = $_GET['tracking'];
    $result = $shipping->trackPackage($trackingNum);
    return $result;
}

// ===========================================================================
// Chain AX: Task scheduler command injection (2+ hops)
// ===========================================================================

function chainAX_scheduleTask() {
    $scheduler = new TaskScheduler();

    $cmd = $_POST['task_cmd'];
    $schedule = $_POST['task_schedule'];
    $scheduler->scheduleTask($cmd, $schedule);
}

// ===========================================================================
// Chain AY: Dynamic task eval (2+ hops)
// ===========================================================================

function chainAY_dynamicTask() {
    $scheduler = new TaskScheduler();

    $code = $_POST['task_code'];
    $result = $scheduler->executeDynamicTask($code);
    return $result;
}

// ===========================================================================
// Chain AZ: Search index rebuild SQL injection (2+ hops)
// ===========================================================================

function chainAZ_searchIndexRebuild() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $indexer = new SearchIndexer($db);

    $table = $_GET['index_table'];
    $result = $indexer->rebuildIndex($table);
    return $result;
}

// ===========================================================================
// Chain BA: Search index query SQL injection (2+ hops)
// ===========================================================================

function chainBA_searchIndexQuery() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $indexer = new SearchIndexer($db);

    $query = $_GET['idx_query'];
    $index = $_GET['idx_name'];
    $result = $indexer->searchIndex($query, $index);
    return $result;
}

// ===========================================================================
// Chain BB: Cache read path traversal (2+ hops)
// ===========================================================================

function chainBB_cacheRead() {
    $cache = new CacheManager();

    $key = $_GET['cache_key'];
    $data = $cache->readCache($key);
    return $data;
}

// ===========================================================================
// Chain BC: Cache write with tainted data (2+ hops)
// ===========================================================================

function chainBC_cacheWrite() {
    $cache = new CacheManager();

    $key = $_POST['cache_key'];
    $data = $_POST['cache_data'];
    $cache->writeCache($key, $data);
}

// ===========================================================================
// Chain BD: Cache purge command injection (2+ hops)
// ===========================================================================

function chainBD_cachePurge() {
    $cache = new CacheManager();

    $pattern = $_GET['purge_pattern'];
    $cache->purgeCache($pattern);
}

// ===========================================================================
// Chain BE: Gallery upload command injection (3+ hops)
// ===========================================================================

function chainBE_galleryUpload() {
    $processor = new MediaProcessor();
    $gallery = new GalleryManager($processor);

    $filename = $_POST['gallery_file'];
    $dims = $_POST['gallery_dims'];
    $gallery->uploadToGallery($filename, $dims);
}

// ===========================================================================
// Chain BF: Gallery download path traversal (3+ hops)
// ===========================================================================

function chainBF_galleryDownload() {
    $processor = new MediaProcessor();
    $gallery = new GalleryManager($processor);

    $path = $_GET['gallery_path'];
    $content = $gallery->downloadFromGallery($path);
    return $content;
}

// ===========================================================================
// Chain BG: Direct unserialize from cookie
// ===========================================================================

function chainBG_cookieDeserialize() {
    $rawData = $_COOKIE['preferences'];
    $decoded = base64_decode($rawData);
    $prefs = unserialize($decoded);
    return $prefs;
}

// ===========================================================================
// Chain BH: Direct SSRF from header
// ===========================================================================

function chainBH_ssrfFromHeader() {
    $callbackUrl = $_SERVER['HTTP_X_CALLBACK_URL'];
    $ch = curl_init($callbackUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

// ===========================================================================
// Chain BI: Order repository direct SQL injection (2+ hops)
// ===========================================================================

function chainBI_orderRepoDateRange() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $orderRepo = new OrderRepository($db);

    $start = $_GET['date_start'];
    $end = $_GET['date_end'];
    $result = $orderRepo->findByDateRange($start, $end);
    return $result;
}

// ---------------------------------------------------------------------------
// Entry point: dispatch cross-module chains
// ---------------------------------------------------------------------------

function dispatchCrossModule() {
    $chain = $_GET['chain'] ?? '';

    match($chain) {
        'A' => chainA_deepSqlInjection(),
        'B' => chainB_globalVariableTaint(),
        'C' => chainC_callbackTaint(),
        'D' => chainD_reexportedWrapper(),
        'E' => chainE_recursiveTaint(),
        'F' => chainF_productSearch(),
        'G' => chainG_orderLookup(),
        'H' => chainH_sessionFixation(),
        'I' => chainI_reportInjection(),
        'J' => chainJ_adminDiagnostic(),
        'K' => chainK_loginInjection(),
        'L' => chainL_mediaProcessing(),
        'M' => chainM_templateEval(),
        'N' => chainN_accessControlBypass(),
        'O' => chainO_emailInjection(),
        'P' => chainP_resetTokenInjection(),
        'Q' => chainQ_orderStatusInjection(),
        'R' => chainR_auditLogInjection(),
        'S' => chainS_templateRenderDirect(),
        'T' => chainT_templateLoadDirect(),
        'U' => chainU_templateEvalDirect(),
        'V' => chainV_productSearchDirect(),
        'W' => chainW_productCategoryDirect(),
        'X' => chainX_directRawQuery(),
        'Y' => chainY_directExecCmd(),
        'Z' => chainZ_directShellExec(),
        'AA' => chainAA_templateCompileCache(),
        'AB' => chainAB_emailRendererDirect(),
        'AC' => chainAC_productPriceFilter(),
        'AD' => chainAD_productCategoryBrowse(),
        'AE' => chainAE_orderDateSearch(),
        'AF' => chainAF_articleTagSearch(),
        'AG' => chainAG_articleFulltext(),
        'AH' => chainAH_userSearch(),
        'AI' => chainAI_adminBackup(),
        'AJ' => chainAJ_adminImageProcess(),
        'AK' => chainAK_mediaResize(),
        'AL' => chainAL_mediaVideoConvert(),
        'AM' => chainAM_pluginInstall(),
        'AN' => chainAN_pluginLoad(),
        'AO' => chainAO_sessionLookup(),
        'AP' => chainAP_authUnsafe(),
        'AQ' => chainAQ_accessControlCheck(),
        'AR' => chainAR_commentSearch(),
        'AS' => chainAS_articleRepoTag(),
        'AT' => chainAT_orderStatusUpdate(),
        'AU' => chainAU_shippingLabel(),
        'AV' => chainAV_shippingRate(),
        'AW' => chainAW_shippingTracking(),
        'AX' => chainAX_scheduleTask(),
        'AY' => chainAY_dynamicTask(),
        'AZ' => chainAZ_searchIndexRebuild(),
        'BA' => chainBA_searchIndexQuery(),
        'BB' => chainBB_cacheRead(),
        'BC' => chainBC_cacheWrite(),
        'BD' => chainBD_cachePurge(),
        'BE' => chainBE_galleryUpload(),
        'BF' => chainBF_galleryDownload(),
        'BG' => chainBG_cookieDeserialize(),
        'BH' => chainBH_ssrfFromHeader(),
        'BI' => chainBI_orderRepoDateRange(),
        default => null,
    };
}

dispatchCrossModule();
