use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::process::Command;
use std::time::Duration;

// ---------------------------------------------------------------------------
// Core proxy types
// ---------------------------------------------------------------------------

pub struct ProxyConfig {
    pub upstream_url: String,
    pub timeout: Duration,
    pub max_retries: u32,
    pub headers: HashMap<String, String>,
}

impl ProxyConfig {
    pub fn new(upstream_url: &str, timeout_secs: u64) -> Self {
        ProxyConfig {
            upstream_url: upstream_url.to_string(),
            timeout: Duration::from_secs(timeout_secs),
            max_retries: 3,
            headers: HashMap::new(),
        }
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }
}

pub struct ProxyService {
    config: ProxyConfig,
    resolver: UpstreamResolver,
}

impl ProxyService {
    pub fn new(config: ProxyConfig) -> Self {
        let resolver = UpstreamResolver::new(&config.upstream_url);
        ProxyService { config, resolver }
    }

    pub fn forward(&self, path: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        let target = self.resolver.resolve(path)?;
        let response = self.make_request(&target, headers)?;
        Ok(response)
    }

    pub fn make_request(&self, url: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
        Ok(format!("Response from {}", url).into_bytes())
    }

    pub fn forward_with_rewrite(&self, path: &str, headers: &HashMap<String, String>, rewrite_rules: &[RewriteRule]) -> Result<Vec<u8>, String> {
        let rewritten_path = apply_rewrites(path, rewrite_rules);
        self.forward(&rewritten_path, headers)
    }
}

pub struct UpstreamResolver {
    base_url: String,
    routes: HashMap<String, String>,
}

impl UpstreamResolver {
    pub fn new(base_url: &str) -> Self {
        UpstreamResolver {
            base_url: base_url.to_string(),
            routes: HashMap::new(),
        }
    }

    pub fn add_route(&mut self, prefix: &str, upstream: &str) {
        self.routes.insert(prefix.to_string(), upstream.to_string());
    }

    pub fn resolve(&self, path: &str) -> Result<String, String> {
        for (prefix, upstream) in &self.routes {
            if path.starts_with(prefix) {
                let remainder = &path[prefix.len()..];
                return Ok(format!("{}{}", upstream, remainder));
            }
        }
        Ok(format!("{}{}", self.base_url, path))
    }
}

pub struct RewriteRule {
    pub pattern: String,
    pub replacement: String,
}

impl RewriteRule {
    pub fn new(pattern: &str, replacement: &str) -> Self {
        RewriteRule {
            pattern: pattern.to_string(),
            replacement: replacement.to_string(),
        }
    }
}

fn apply_rewrites(path: &str, rules: &[RewriteRule]) -> String {
    let mut result = path.to_string();
    for rule in rules {
        result = result.replace(&rule.pattern, &rule.replacement);
    }
    result
}

// ---------------------------------------------------------------------------
// VULN: 5-hop SSRF chain
// env::var -> parse_upstream_url -> build_proxy_target -> resolve_upstream -> make_request
// ---------------------------------------------------------------------------
fn parse_upstream_url(raw: &str) -> String {
    let trimmed = raw.trim().to_string();
    if !trimmed.starts_with("http") {
        format!("http://{}", trimmed)
    } else {
        trimmed
    }
}

fn build_proxy_target(base_url: &str, path: &str) -> String {
    format!("{}/{}", base_url.trim_end_matches('/'), path.trim_start_matches('/'))
}

fn resolve_upstream(target: &str) -> Result<String, String> {
    if target.len() > 2048 {
        return Err("URL too long".into());
    }
    Ok(target.to_string())
}

pub fn serve_dynamic_proxy() -> Result<Vec<u8>, String> {
    let upstream = env::var("DYNAMIC_UPSTREAM").map_err(|e| e.to_string())?;
    let parsed = parse_upstream_url(&upstream);
    let target = build_proxy_target(&parsed, "/api/data");
    let resolved = resolve_upstream(&target)?;
    let proxy = ProxyService::new(ProxyConfig::new(&resolved, 30));
    let headers = HashMap::new();
    proxy.make_request(&resolved, &headers)
}

// ---------------------------------------------------------------------------
// VULN: 6-hop request routing chain
// stdin -> read_request -> parse_route -> match_backend -> build_url -> forward -> make_request
// ---------------------------------------------------------------------------
struct IncomingRequest {
    path: String,
    method: String,
    headers: HashMap<String, String>,
}

fn read_request() -> Result<IncomingRequest, String> {
    let mut path = String::new();
    io::stdin().read_line(&mut path).map_err(|e| e.to_string())?;
    Ok(IncomingRequest {
        path: path.trim().to_string(),
        method: "GET".to_string(),
        headers: HashMap::new(),
    })
}

fn parse_route(req: &IncomingRequest) -> (&str, &str) {
    let path = req.path.as_str();
    if let Some(pos) = path[1..].find('/') {
        let prefix = &path[..pos + 1];
        let remainder = &path[pos + 1..];
        (prefix, remainder)
    } else {
        (path, "/")
    }
}

fn match_backend(prefix: &str, backends: &HashMap<String, String>) -> String {
    backends.get(prefix)
        .cloned()
        .unwrap_or_else(|| "http://default-backend:8080".into())
}

fn build_full_url(backend: &str, path: &str) -> String {
    format!("{}{}", backend, path)
}

pub fn serve_routed_request() -> Result<Vec<u8>, String> {
    let req = read_request()?;
    let (prefix, remainder) = parse_route(&req);
    let mut backends = HashMap::new();
    backends.insert("/api".to_string(), "http://api-backend:8080".to_string());
    backends.insert("/auth".to_string(), "http://auth-backend:8080".to_string());
    let backend = match_backend(prefix, &backends);
    let url = build_full_url(&backend, remainder);
    let proxy = ProxyService::new(ProxyConfig::new(&url, 30));
    proxy.make_request(&url, &req.headers)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop command execution via proxy health check
// env::var -> build_health_endpoint -> build_check_command -> format_with_timeout -> Command
// ---------------------------------------------------------------------------
fn build_health_endpoint(host: &str) -> String {
    format!("http://{}:8080/health", host)
}

fn build_check_command(endpoint: &str) -> String {
    format!("curl -sf {}", endpoint)
}

fn format_with_timeout(cmd: &str, timeout_secs: u32) -> String {
    format!("timeout {} {}", timeout_secs, cmd)
}

pub fn serve_upstream_health_check() -> Result<String, String> {
    let host = env::var("UPSTREAM_HOST").map_err(|e| e.to_string())?;
    let endpoint = build_health_endpoint(&host);
    let cmd = build_check_command(&endpoint);
    let full_cmd = format_with_timeout(&cmd, 5);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ---------------------------------------------------------------------------
// VULN: 4-hop stdin -> config file write
// stdin -> read_line -> build_nginx_config -> write_config_file -> fs::write
// ---------------------------------------------------------------------------
fn build_nginx_config(server_name: &str, upstream: &str) -> String {
    format!(
        "server {{\n  server_name {};\n  location / {{\n    proxy_pass {};\n  }}\n}}",
        server_name, upstream
    )
}

fn write_config_file(name: &str, content: &str) -> Result<(), String> {
    let path = format!("/etc/nginx/sites-enabled/{}.conf", name);
    fs::write(&path, content).map_err(|e| e.to_string())
}

pub fn serve_add_vhost() -> Result<(), String> {
    let mut server_name = String::new();
    io::stdin().read_line(&mut server_name).map_err(|e| e.to_string())?;
    let name = server_name.trim();
    let config = build_nginx_config(name, "http://backend:8080");
    write_config_file(name, &config)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop stdin -> command injection via proxy reload
// stdin -> parse_reload_args -> validate_service_name -> build_reload_cmd -> execute_reload -> Command
// ---------------------------------------------------------------------------
fn parse_reload_args(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let service = parts.first().unwrap_or(&"nginx").to_string();
    let signal = parts.get(1).unwrap_or(&"reload").to_string();
    (service, signal)
}

fn validate_service_name(name: &str) -> Result<String, String> {
    if name.len() > 64 {
        return Err("service name too long".into());
    }
    Ok(name.to_string())
}

fn build_reload_cmd(service: &str, signal: &str) -> String {
    format!("systemctl {} {}", signal, service)
}

fn execute_reload(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn serve_service_reload() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let (service, signal) = parse_reload_args(input.trim());
    let validated = validate_service_name(&service)?;
    let cmd = build_reload_cmd(&validated, &signal);
    execute_reload(&cmd)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop env -> SSL cert file read
// env::var -> build_cert_path -> validate_cert_file -> fs::read
// ---------------------------------------------------------------------------
fn build_cert_path(domain: &str) -> String {
    format!("/etc/ssl/certs/{}.pem", domain)
}

fn validate_cert_file(path: &str) -> Result<String, String> {
    if path.contains('\0') {
        return Err("null byte in path".into());
    }
    Ok(path.to_string())
}

pub fn serve_cert_load() -> Result<Vec<u8>, String> {
    let domain = env::var("SSL_DOMAIN").map_err(|e| e.to_string())?;
    let cert_path = build_cert_path(&domain);
    let validated = validate_cert_file(&cert_path)?;
    fs::read(&validated).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Sanitized SSRF: url passes through starts_with() check before request
// ---------------------------------------------------------------------------
pub fn forward_with_validation(proxy: &ProxyService, url: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
    let validated = url.trim();
    if !validated.starts_with("https://") {
        return Err("Only HTTPS URLs allowed".into());
    }
    if validated.contains("localhost") || validated.contains("127.0.0.1") {
        return Err("Internal hosts blocked".into());
    }
    proxy.forward(validated, headers)
}

// Sanitized rewrite: path passes through replace() before forwarding
pub fn forward_with_sanitized_rewrite(proxy: &ProxyService, path: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
    let clean_path = path.replace("..", "").replace("//", "/");
    proxy.forward(&clean_path, headers)
}

// ---------------------------------------------------------------------------
// Load balancer and rate limiter (infrastructure)
// ---------------------------------------------------------------------------

pub struct LoadBalancer {
    backends: Vec<String>,
    current: std::sync::atomic::AtomicUsize,
}

impl LoadBalancer {
    pub fn new(backends: Vec<String>) -> Self {
        LoadBalancer {
            backends,
            current: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn next_backend(&self) -> &str {
        let idx = self.current.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.backends.len();
        &self.backends[idx]
    }

    fn add_backend(&mut self, backend: String) {
        self.backends.push(backend);
    }

    fn remove_backend(&mut self, backend: &str) {
        self.backends.retain(|b| b != backend);
    }
}

pub struct RateLimiter {
    limits: HashMap<String, (u32, u64)>,
    counters: HashMap<String, Vec<u64>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            limits: HashMap::new(),
            counters: HashMap::new(),
        }
    }

    fn set_limit(&mut self, key: &str, max_requests: u32, window_ms: u64) {
        self.limits.insert(key.to_string(), (max_requests, window_ms));
    }

    fn check(&mut self, key: &str) -> bool {
        let now = current_time_ms();
        if let Some((max_req, window)) = self.limits.get(key) {
            let timestamps = self.counters.entry(key.to_string()).or_insert_with(Vec::new);
            let cutoff = now - window;
            timestamps.retain(|t| *t > cutoff);
            if timestamps.len() >= *max_req as usize {
                return false;
            }
            timestamps.push(now);
            true
        } else {
            true
        }
    }
}

fn current_time_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
