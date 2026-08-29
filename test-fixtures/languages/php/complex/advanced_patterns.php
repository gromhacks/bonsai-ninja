<?php

// Advanced PHP vulnerability patterns for taint analysis testing.
// Each chain exercises specific PHP language features routing tainted data to sinks.

require_once __DIR__ . '/database.php';
require_once __DIR__ . '/template_engine.php';

// ---------------------------------------------------------------------------
// VULN 1: Arrow function routing taint
// Chain: $_GET[cmd] -> arrow fn -> shell_exec
// ---------------------------------------------------------------------------

function handleArrowFunctionRoute() {
    $userCmd = $_GET['cmd'];
    $transform = fn($x) => strtolower($x);
    $prepared = $transform($userCmd);
    $output = shell_exec($prepared);
    // Also log the command output
    file_put_contents('/var/log/commands.log', $output, FILE_APPEND);
    return $output;
}

// ---------------------------------------------------------------------------
// VULN 2: Closure with use() capturing tainted variable
// Chain: $_POST[query] -> closure capture -> mysqli_query
// ---------------------------------------------------------------------------

function handleClosureCapture() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $conn = $db->getConnection();
    $taintedFilter = $_POST['query'];
    $sql = "SELECT * FROM products WHERE name LIKE '%" . $taintedFilter . "%'";
    $results = mysqli_query($conn, $sql);
    // Also export to CSV
    $cmd = "mysql -e \"" . $sql . "\" > /tmp/export.csv";
    exec($cmd);
    return $results;
}

// ---------------------------------------------------------------------------
// VULN 3: Trait method propagating tainted data
// Chain: $_REQUEST[host] -> trait method -> exec
// ---------------------------------------------------------------------------

trait NetworkDiagnostics {
    public function buildPingCommand($host) {
        $cmd = "ping -c 4 " . $host;
        return $cmd;
    }

    public function runDiagnostic($host) {
        $cmd = $this->buildPingCommand($host);
        exec($cmd, $output);
        return implode("\n", $output);
    }
}

class ServerMonitor {
    use NetworkDiagnostics;

    public function diagnose() {
        $targetHost = $_REQUEST['host'];
        return $this->runDiagnostic($targetHost);
    }
}

// ---------------------------------------------------------------------------
// VULN 4: Null safe operator (?->) preserving taint
// Chain: $_GET[id] -> ProfileLoader -> mysqli_query
// ---------------------------------------------------------------------------

class UserProfile {
    private $name;
    private $preferences;

    public function __construct($name) {
        $this->name = $name;
        $this->preferences = null;
    }

    public function getPreferences() {
        return $this->preferences;
    }
}

class ProfileLoader {
    private $conn;

    public function __construct($conn) {
        $this->conn = $conn;
    }

    public function findUser($identifier) {
        $profile = $this->loadProfile($identifier);
        $prefStr = $profile?->getPreferences()?->toString();
        $filter = $prefStr ?? $identifier;
        $sql = "SELECT * FROM user_data WHERE lookup = '" . $filter . "'";
        return mysqli_query($this->conn, $sql);
    }

    private function loadProfile($id) {
        return new UserProfile($id);
    }
}

function handleNullSafe() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $conn = $db->getConnection();
    $loader = new ProfileLoader($conn);
    $userId = $_GET['id'];
    return $loader->findUser($userId);
}

// ---------------------------------------------------------------------------
// VULN 5: Match expression routing taint to different sinks
// Chain: $_POST[action/payload] -> match -> eval/shell_exec/include
// ---------------------------------------------------------------------------

function handleMatchExpression() {
    $action = $_POST['action'];
    $payload = $_POST['payload'];

    $result = match($action) {
        'eval'    => eval('return ' . $payload . ';'),
        'exec'    => shell_exec($payload),
        'include' => include($payload),
        default   => 'unknown action',
    };

    return $result;
}

// ---------------------------------------------------------------------------
// VULN 6: Named arguments passing taint
// Chain: $_GET[file] -> named arg -> file_put_contents
// ---------------------------------------------------------------------------

function writeLog(string $message, string $destination, bool $append = true) {
    $flags = $append ? FILE_APPEND : 0;
    file_put_contents($destination, $message . "\n", $flags);
}

function handleNamedArgs() {
    $logPath = $_GET['file'];
    $logMessage = $_POST['message'];

    writeLog(
        destination: $logPath,
        message: $logMessage,
        append: true,
    );
}

// ---------------------------------------------------------------------------
// VULN 7: Spread operator propagating taint
// Chain: $_GET[bin/flags] -> spread -> system
// ---------------------------------------------------------------------------

function runCommand(string $binary, string ...$flags) {
    $cmd = $binary . ' ' . implode(' ', $flags);
    system($cmd);
}

function handleSpreadOperator() {
    $binary = $_GET['bin'];
    $rawFlags = $_GET['flags'];
    $flagList = explode(',', $rawFlags);
    runCommand($binary, ...$flagList);
}

// ---------------------------------------------------------------------------
// VULN 8: JSON body -> exec
// Chain: file_get_contents(php://input) -> json_decode -> exec
// ---------------------------------------------------------------------------

function handleJsonBodyExec() {
    $body = file_get_contents('php://input');
    $data = json_decode($body, true);
    $cmd = $data['commands'][0] ?? 'echo none';
    exec($cmd);
}

// ---------------------------------------------------------------------------
// VULN 9: SSRF via POST data
// Chain: $_POST[urls] -> explode -> file_get_contents
// ---------------------------------------------------------------------------

function handleSsrfFromPost() {
    $rawUrls = $_POST['urls'];
    $firstUrl = explode("\n", $rawUrls)[0];
    // SSRF via file_get_contents
    $response = file_get_contents($firstUrl);
    // Also try via curl
    $ch = curl_init($firstUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $curlResponse = curl_exec($ch);
    curl_close($ch);
    return $response;
}

// ---------------------------------------------------------------------------
// VULN 10: Fluent builder SQL injection
// Chain: $_GET[q/sort] -> QueryBuilder -> buildSQL -> rawQuery -> mysqli_query
// ---------------------------------------------------------------------------

function handleFluentBuilder() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');

    $searchTerm = $_GET['q'];
    $sortField = $_GET['sort'];

    $builder = new QueryBuilder($db);
    $builder->select('articles')
        ->where("title LIKE '%" . $searchTerm . "%'")
        ->orderBy($sortField);
    $results = $builder->execute();
    // Cache results to file
    file_put_contents('/var/cache/search_results.json', json_encode($results));
    return $results;
}

// ---------------------------------------------------------------------------
// VULN 11: Server variable log injection
// Chain: $_SERVER[HTTP_USER_AGENT] -> string concat -> file_put_contents
// ---------------------------------------------------------------------------

function handleLogInjection() {
    $userAgent = $_SERVER['HTTP_USER_AGENT'];
    $remoteAddr = $_SERVER['REMOTE_ADDR'];
    $requestUri = $_SERVER['REQUEST_URI'];
    $timestamp = date('Y-m-d H:i:s');

    $logEntry = "[" . $timestamp . "] Request from " . $remoteAddr
        . "\nURI: " . $requestUri
        . "\nUser-Agent: " . $userAgent;

    file_put_contents('/var/log/access_custom.log', $logEntry, FILE_APPEND);
}

// ---------------------------------------------------------------------------
// VULN 12: Direct eval injection
// Chain: $_GET[expr] -> eval
// ---------------------------------------------------------------------------

function handleEvalInjection() {
    $rawExpr = $_GET['expr'];
    $result = eval('return ' . $rawExpr . ';');
    return $result;
}

// ---------------------------------------------------------------------------
// VULN 13: Trait + interface taint through abstract contract
// Chain: $_POST[template] -> PageRenderer -> DynamicRenderer trait -> eval
// ---------------------------------------------------------------------------

interface Renderable {
    public function renderContent(string $content);
}

trait DynamicRenderer {
    public function renderContent(string $content) {
        $rendered = eval('return "' . $content . '";');
        return $rendered;
    }
}

class PageRenderer implements Renderable {
    use DynamicRenderer;
}

function handleTraitInterface() {
    $template = $_POST['template'];
    $renderer = new PageRenderer();
    return $renderer->renderContent($template);
}

// ---------------------------------------------------------------------------
// VULN 14: Multi-hop email injection via template engine
// Chain: $_POST[email/subject/body] -> EmailRenderer -> compileTemplate -> exec(sendmail)
// ---------------------------------------------------------------------------

function handleEmailInjection() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);
    $emailRenderer = new EmailRenderer($engine);

    $to = $_POST['email'];
    $subject = $_POST['subject'];
    $body = $_POST['body'];
    $emailRenderer->sendNotification($to, $subject, $body);
}

// ---------------------------------------------------------------------------
// VULN 15: Multi-hop media processing
// Chain: $_POST[filename/width/height] -> processUpload -> resizeImage -> exec
// ---------------------------------------------------------------------------

function handleMediaUpload() {
    $filename = $_POST['filename'];
    $width = $_POST['width'];
    $height = $_POST['height'];

    $processor = new MediaProcessor();
    $processor->processUpload($filename, $width, $height);
    // Also read the processed file
    $content = $processor->getFile('thumb_' . $filename);
    file_put_contents('/var/cache/thumb_preview.dat', $content);
}

// ---------------------------------------------------------------------------
// VULN 16: Multi-hop video conversion
// Chain: $_POST[file/format] -> convertVideo -> exec
// ---------------------------------------------------------------------------

function handleVideoConversion() {
    $inputFile = $_POST['file'];
    $format = $_POST['format'];

    $processor = new MediaProcessor();
    $processor->convertVideo($inputFile, $format);
}

// ---------------------------------------------------------------------------
// VULN 17: Plugin installation command injection
// Chain: $_GET[plugin_url] -> buildDownloadUrl -> installFromUrl -> exec
// ---------------------------------------------------------------------------

function buildDownloadUrl($userUrl) {
    $finalUrl = $userUrl . '?v=' . time();
    return $finalUrl;
}

function handlePluginInstall() {
    $pluginUrl = $_GET['plugin_url'];
    $downloadUrl = buildDownloadUrl($pluginUrl);

    $pluginSystem = new PluginSystem();
    $pluginSystem->installFromUrl($downloadUrl);
    // Also load the installed plugin
    $pluginSystem->loadPlugin($pluginUrl);
}

// ---------------------------------------------------------------------------
// VULN 18: Plugin loading path traversal
// Chain: $_GET[plugin] -> PluginSystem -> loadPlugin -> include
// ---------------------------------------------------------------------------

function handlePluginLoad() {
    $pluginName = $_GET['plugin'];
    $pluginSystem = new PluginSystem();
    $pluginSystem->loadPlugin($pluginName);
}

// ---------------------------------------------------------------------------
// VULN 19: Multi-hop template rendering with file inclusion
// Chain: $_GET[template] -> TemplateEngine -> render -> resolveTemplatePath -> include
// ---------------------------------------------------------------------------

function handleTemplateRender() {
    $db = new DatabaseConnection('localhost', 'app', 'root', '');
    $engine = new TemplateEngine($db);
    $templateName = $_GET['template'];
    $data = ['user' => 'anonymous'];
    $result = $engine->render($templateName, $data);
    echo $result;
}

// ---------------------------------------------------------------------------
// VULN 20: Chained SSRF and deserialization
// Chain: $_POST[callback_url] -> curl -> unserialize
// ---------------------------------------------------------------------------

function handleCallbackSsrf() {
    $callbackUrl = $_POST['callback_url'];
    $ch = curl_init($callbackUrl);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    // Dangerous: deserialize remote response
    $data = unserialize($response);
    return $data;
}

// ---------------------------------------------------------------------------
// VULN 21: File upload + move
// Chain: $_FILES -> move_uploaded_file
// ---------------------------------------------------------------------------

function handleProfilePicUpload() {
    $tmpFile = $_FILES['avatar']['tmp_name'];
    $fileName = $_FILES['avatar']['name'];
    $destPath = '/var/www/uploads/avatars/' . $fileName;
    move_uploaded_file($tmpFile, $destPath);
    return $destPath;
}

// ---------------------------------------------------------------------------
// VULN 22: Regex injection via POST
// ---------------------------------------------------------------------------

function handleRegexSearch() {
    $pattern = $_POST['regex'];
    $subject = $_POST['text'];
    $matches = [];
    preg_match('/' . $pattern . '/', $subject, $matches);
    return $matches;
}

// ---------------------------------------------------------------------------
// Entry point: dispatch based on route parameter
// ---------------------------------------------------------------------------

function dispatchAdvanced() {
    $route = $_GET['route'] ?? '';

    match($route) {
        'arrow'      => handleArrowFunctionRoute(),
        'closure'    => handleClosureCapture(),
        'trait'      => (new ServerMonitor())->diagnose(),
        'nullsafe'   => handleNullSafe(),
        'match'      => handleMatchExpression(),
        'named'      => handleNamedArgs(),
        'spread'     => handleSpreadOperator(),
        'json'       => handleJsonBodyExec(),
        'ssrf'       => handleSsrfFromPost(),
        'builder'    => handleFluentBuilder(),
        'log'        => handleLogInjection(),
        'eval'       => handleEvalInjection(),
        'traitif'    => handleTraitInterface(),
        'email'      => handleEmailInjection(),
        'media'      => handleMediaUpload(),
        'video'      => handleVideoConversion(),
        'install'    => handlePluginInstall(),
        'plugin'     => handlePluginLoad(),
        'template'   => handleTemplateRender(),
        'callback'   => handleCallbackSsrf(),
        'avatar'     => handleProfilePicUpload(),
        'regex'      => handleRegexSearch(),
        default      => null,
    };

    // Additional inline sinks (not separate handlers)
    $lang = $_COOKIE['lang'] ?? 'en';
    header('Content-Language: ' . $lang);

    $sourcePath = $_GET['source'] ?? '';
    if ($sourcePath) {
        $processor = new MediaProcessor();
        $processor->getFile($sourcePath);
    }
}

dispatchAdvanced();

// ============================================================
// ADDITIONAL PATTERNS - Attributes, enums, first-class callables
// ============================================================

// PHP 8.0 Attributes
#[Route('/api/exec', methods: ['POST'])]
function attributeHandler(string $input): string {
    return shell_exec($input);  // taint in attributed handler
}

// PHP 8.1 Enums with methods
enum CommandType: string {
    case Execute = 'exec';
    case Query = 'query';

    public function run(string $input): void {
        match ($this) {
            self::Execute => system($input),
            self::Query => mysqli_query(null, $input),
        };
    }
}

// First-class callable (PHP 8.1)
function firstClassCallable(string $input): void {
    $executor = system(...);  // first-class callable
    $executor($input);  // taint through callable
}

// Named arguments flow
function namedArgFlow(string $cmd, string $dir = '/'): void {
    system(command: $cmd, ...[]);  // taint through named arg
}

// Fiber flow (PHP 8.1)
function fiberFlow(string $input): void {
    $fiber = new Fiber(function () use ($input): void {
        Fiber::suspend($input);
        system($input);
    });
    $fiber->start();
    $result = $fiber->resume();
}

// Named arguments
function executeCommand(string $command, string $dir = '/', bool $sudo = false): void {
    system(command: $command);
}
