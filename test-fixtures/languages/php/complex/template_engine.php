<?php

// Template rendering engine with layout processing, includes, and user content.

class TemplateEngine {
    private $db;
    private $templateDir;
    private $cacheDir;
    private $globals = [];

    public function __construct(DatabaseConnection $db) {
        $this->db = $db;
        $this->templateDir = '/var/www/templates';
        $this->cacheDir = '/var/www/cache';
    }

    public function setGlobal($key, $value) {
        $this->globals[$key] = $value;
    }

    // VULN: Template injection via extract + include
    public function render($templateName, $data = []) {
        $templatePath = $this->resolveTemplatePath($templateName);
        $merged = array_merge($this->globals, $data);
        extract($merged);
        ob_start();
        include($templatePath);
        return ob_get_clean();
    }

    // VULN: Path traversal in template resolution
    public function resolveTemplatePath($name) {
        $path = $this->templateDir . '/' . $name . '.php';
        return $path;
    }

    // Safe version with path validation
    public function resolveTemplatePathSafe($name) {
        $safeName = basename($name);
        $path = $this->templateDir . '/' . $safeName . '.php';
        $realPath = realpath($path);
        $realBase = realpath($this->templateDir);
        if ($realPath === false || strpos($realPath, $realBase) !== 0) {
            throw new RuntimeException("Invalid template path");
        }
        return $realPath;
    }

    // VULN: Path traversal in raw template loading
    public function loadRawTemplate($name) {
        $path = $this->templateDir . '/' . $name;
        $content = file_get_contents($path);
        return $content;
    }

    // VULN: Code injection via template compilation with user data
    public function compileTemplate($templateStr, $data) {
        $compiled = $templateStr;
        foreach ($data as $key => $value) {
            $compiled = str_replace('{{' . $key . '}}', $value, $compiled);
        }
        return $compiled;
    }

    // VULN: eval-based template rendering
    public function evalTemplate($code, $data) {
        extract($data);
        $result = eval('return ' . $code . ';');
        return $result;
    }

    // VULN: Tainted content written to cache file (stored XSS)
    public function cacheCompiledTemplate($name, $content) {
        $cachePath = $this->cacheDir . '/' . md5($name) . '.html';
        file_put_contents($cachePath, $content);
    }

    public function getCachedTemplate($name) {
        $cachePath = $this->cacheDir . '/' . md5($name) . '.html';
        if (file_exists($cachePath)) {
            return file_get_contents($cachePath);
        }
        return null;
    }

    // Multi-hop: render a page layout with header, body, footer
    public function renderLayout($layoutName, $bodyContent, $vars = []) {
        $vars['body'] = $bodyContent;
        $template = $this->loadRawTemplate($layoutName);
        $compiled = $this->compileTemplate($template, $vars);
        return $compiled;
    }

    // Multi-hop: render and cache
    public function renderAndCache($templateName, $data) {
        $templateStr = $this->loadRawTemplate($templateName);
        $compiled = $this->compileTemplate($templateStr, $data);
        $this->cacheCompiledTemplate($templateName, $compiled);
        return $compiled;
    }
}

// Plugin system with file inclusion
class PluginSystem {
    private $plugins = [];
    private $pluginDir;

    public function __construct($pluginDir = '/var/www/plugins') {
        $this->pluginDir = $pluginDir;
    }

    // VULN: Path traversal in plugin loading
    public function loadPlugin($pluginName) {
        $pluginPath = $this->pluginDir . '/' . $pluginName . '/init.php';
        include($pluginPath);
        $this->plugins[] = $pluginName;
        return true;
    }

    // Safe version
    public function loadPluginSafe($pluginName) {
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $pluginName)) {
            return false;
        }
        $pluginPath = $this->pluginDir . '/' . $pluginName . '/init.php';
        $realPath = realpath($pluginPath);
        $realBase = realpath($this->pluginDir);
        if ($realPath === false || strpos($realPath, $realBase) !== 0) {
            return false;
        }
        include($realPath);
        $this->plugins[] = $pluginName;
        return true;
    }

    // VULN: Command injection in plugin installation from URL
    public function installFromUrl($url) {
        $cmd = "wget " . $url . " -O /tmp/plugin.zip && unzip /tmp/plugin.zip -d " . $this->pluginDir;
        exec($cmd);
    }

    // Safe version
    public function installFromUrlSafe($pluginName) {
        if (!preg_match('/^[a-zA-Z0-9_-]+$/', $pluginName)) {
            return false;
        }
        $safeUrl = escapeshellarg("https://plugins.example.com/" . $pluginName . ".zip");
        $safeDir = escapeshellarg($this->pluginDir);
        exec("wget " . $safeUrl . " -O /tmp/plugin.zip && unzip /tmp/plugin.zip -d " . $safeDir);
        return true;
    }

    public function getLoadedPlugins() {
        return $this->plugins;
    }
}

// Media processor with image manipulation
class MediaProcessor {
    private $uploadDir;

    public function __construct($uploadDir = '/var/www/uploads') {
        $this->uploadDir = $uploadDir;
    }

    // VULN: Command injection via filename in image resize
    public function resizeImage($filename, $dimensions) {
        $input = $this->uploadDir . '/' . $filename;
        $output = $this->uploadDir . '/thumb_' . $filename;
        $cmd = "convert " . $input . " -resize " . $dimensions . " " . $output;
        exec($cmd);
        return $output;
    }

    // Safe version
    public function resizeImageSafe($filename, $width, $height) {
        $safeName = basename($filename);
        $safeWidth = intval($width);
        $safeHeight = intval($height);
        $input = escapeshellarg($this->uploadDir . '/' . $safeName);
        $output = escapeshellarg($this->uploadDir . '/thumb_' . $safeName);
        exec("convert " . $input . " -resize " . escapeshellarg($safeWidth . "x" . $safeHeight) . " " . $output);
    }

    // VULN: Path traversal in file reading
    public function getFile($path) {
        $fullPath = $this->uploadDir . '/' . $path;
        return file_get_contents($fullPath);
    }

    // VULN: Command injection in video conversion
    public function convertVideo($inputFile, $outputFormat) {
        $cmd = "ffmpeg -i " . $this->uploadDir . "/" . $inputFile . " -f " . $outputFormat . " /tmp/output";
        exec($cmd);
    }

    // Multi-hop: process upload through multiple steps
    public function processUpload($filename, $width, $height) {
        $dimensions = $width . "x" . $height;
        $result = $this->resizeImage($filename, $dimensions);
        return $result;
    }
}

// Email template renderer
class EmailRenderer {
    private $engine;

    public function __construct(TemplateEngine $engine) {
        $this->engine = $engine;
    }

    // Multi-hop: render email through template engine (taint flows through)
    public function renderNotification($recipientName, $subject, $bodyHtml) {
        $data = [
            'recipient' => $recipientName,
            'subject' => $subject,
            'content' => $bodyHtml,
        ];
        $rendered = $this->engine->compileTemplate(
            '<html><body><h1>{{subject}}</h1><p>Dear {{recipient}},</p><div>{{content}}</div></body></html>',
            $data
        );
        return $rendered;
    }

    // Multi-hop: render and send (tainted content flows to mail command)
    public function sendNotification($to, $subject, $bodyHtml) {
        $rendered = $this->renderNotification($to, $subject, $bodyHtml);
        $cmd = "echo " . $rendered . " | sendmail " . $to;
        exec($cmd);
    }
}
