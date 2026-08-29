use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, Read, BufRead};
use std::process::Command;
use std::path::Path;

mod proxy;
mod cache;
mod admin;
mod sanitize;
mod advanced_patterns;
mod cross_module;

use proxy::{ProxyService, ProxyConfig, UpstreamResolver};
use cache::{CacheManager, CacheEntry, CachePolicy};
use admin::{AdminHandler, UserManager, AuditLogger};
use sanitize::{InputValidator, PathSanitizer, HtmlEscaper, SqlSanitizer};

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------

struct AppState {
    proxy: ProxyService,
    cache: CacheManager,
    admin: AdminHandler,
    db_url: String,
}

impl AppState {
    fn new(config: &AppConfig) -> Self {
        let proxy_config = ProxyConfig::new(&config.upstream_url, config.timeout);
        let proxy = ProxyService::new(proxy_config);
        let cache = CacheManager::new(config.cache_size);
        let admin = AdminHandler::new(&config.db_url);
        AppState {
            proxy,
            cache,
            admin,
            db_url: config.db_url.clone(),
        }
    }
}

struct AppConfig {
    upstream_url: String,
    timeout: u64,
    cache_size: usize,
    db_url: String,
    bind_addr: String,
}

impl AppConfig {
    fn from_env() -> Self {
        AppConfig {
            upstream_url: env::var("UPSTREAM_URL").unwrap_or_else(|_| "http://localhost:8080".into()),
            timeout: env::var("TIMEOUT").unwrap_or_else(|_| "30".into()).parse().unwrap_or(30),
            cache_size: env::var("CACHE_SIZE").unwrap_or_else(|_| "1000".into()).parse().unwrap_or(1000),
            db_url: env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:///proxy.db".into()),
            bind_addr: env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:3000".into()),
        }
    }
}

// ---------------------------------------------------------------------------
// VULN: 4-hop command injection
// env::var -> parse_cli_args -> build_command_string -> execute_shell_command -> Command::new
// ---------------------------------------------------------------------------
fn parse_cli_args() -> Vec<String> {
    env::args().collect()
}

fn build_command_string(args: &[String]) -> String {
    if args.len() > 1 {
        let user_cmd = &args[1];
        format!("system-check {}", user_cmd)
    } else {
        "system-check health".to_string()
    }
}

fn execute_shell_command(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_cli_command() -> Result<String, String> {
    let args = parse_cli_args();
    let cmd = build_command_string(&args);
    let result = execute_shell_command(&cmd)?;
    fs::write("/tmp/cli_command_output.log", &result).map_err(|e| e.to_string())?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop path traversal
// env::var -> resolve_config_path -> validate_path_length -> read_config_file -> fs::read_to_string
// ---------------------------------------------------------------------------
fn resolve_config_path(name: &str) -> String {
    format!("/etc/proxy/configs/{}", name)
}

fn validate_path_length(path: &str) -> Result<String, String> {
    if path.len() > 512 {
        return Err("path too long".into());
    }
    Ok(path.to_string())
}

fn read_config_file(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| e.to_string())
}

fn run_config_load() -> Result<String, String> {
    let config_name = env::var("CONFIG_NAME").map_err(|e| e.to_string())?;
    let path = resolve_config_path(&config_name);
    let validated = validate_path_length(&path)?;
    read_config_file(&validated)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop SQL injection
// stdin -> read_user_query -> build_search_filter -> construct_sql -> admin.execute_query
// ---------------------------------------------------------------------------
fn read_user_query() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn build_search_filter(query: &str) -> String {
    format!("name LIKE '%{}%'", query)
}

fn construct_sql(filter: &str, table: &str) -> String {
    format!("SELECT * FROM {} WHERE {}", table, filter)
}

fn run_search(state: &AppState) -> Result<Vec<HashMap<String, String>>, String> {
    let query = read_user_query()?;
    let filter = build_search_filter(&query);
    let sql = construct_sql(&filter, "proxy_logs");
    state.admin.execute_query(&sql)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop file write from env
// env::var -> build_report_path -> generate_report_content -> write_report -> fs::write
// ---------------------------------------------------------------------------
fn build_report_path(name: &str) -> String {
    format!("/var/reports/{}.html", name)
}

fn generate_report_content(title: &str, body: &str) -> String {
    format!("<html><head><title>{}</title></head><body>{}</body></html>", title, body)
}

fn write_report(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

fn run_report_generation() -> Result<(), String> {
    let report_name = env::var("REPORT_NAME").map_err(|e| e.to_string())?;
    let path = build_report_path(&report_name);
    let content = generate_report_content(&report_name, "Auto-generated report");
    write_report(&path, &content)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop command injection from stdin via multi-step pipeline
// stdin -> read_line -> extract_target_host -> build_curl_command -> format_with_args -> Command
// ---------------------------------------------------------------------------
fn extract_target_host(input: &str) -> String {
    input.split_whitespace().next().unwrap_or("localhost").to_string()
}

fn build_curl_command(host: &str, endpoint: &str) -> String {
    format!("curl -s http://{}{}", host, endpoint)
}

fn format_with_args(base_cmd: &str, extra_args: &[&str]) -> String {
    let args_str = extra_args.join(" ");
    format!("{} {}", base_cmd, args_str)
}

fn run_health_check() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let host = extract_target_host(input.trim());
    let cmd = build_curl_command(&host, "/health");
    let full_cmd = format_with_args(&cmd, &["-H", "Accept: application/json"]);
    execute_shell_command(&full_cmd)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop proxy request chain
// env::var -> cache.compute_key -> proxy.forward -> make_request (SSRF)
// ---------------------------------------------------------------------------
fn run_proxy(state: &AppState, path: &str, headers: &HashMap<String, String>) -> Result<Vec<u8>, String> {
    let cache_key = state.cache.compute_key(path, headers);
    if let Some(cached) = state.cache.get(&cache_key) {
        return Ok(cached.data.clone());
    }
    let response = state.proxy.forward(path, headers)?;
    Ok(response)
}

// ---------------------------------------------------------------------------
// VULN: 6-hop env -> serialize -> file write chain
// env::var -> parse_json_config -> merge_with_defaults -> serialize_config -> write_to_path -> fs::write
// ---------------------------------------------------------------------------
fn parse_json_config(raw: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    for part in raw.split(',') {
        if let Some((k, v)) = part.split_once('=') {
            config.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    config
}

fn merge_with_defaults(config: &HashMap<String, String>) -> HashMap<String, String> {
    let mut merged = HashMap::new();
    merged.insert("host".into(), "0.0.0.0".into());
    merged.insert("port".into(), "8080".into());
    for (k, v) in config {
        merged.insert(k.clone(), v.clone());
    }
    merged
}

fn serialize_config(config: &HashMap<String, String>) -> String {
    config.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

fn write_to_path(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

fn run_config_import() -> Result<(), String> {
    let raw_config = env::var("IMPORT_CONFIG").map_err(|e| e.to_string())?;
    let parsed = parse_json_config(&raw_config);
    let merged = merge_with_defaults(&parsed);
    let serialized = serialize_config(&merged);
    let output_path = merged.get("output_path").cloned().unwrap_or("/tmp/config.txt".into());
    write_to_path(&output_path, &serialized)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop log injection
// env::var -> format audit entry -> write_audit_log -> fs::write
// ---------------------------------------------------------------------------
fn format_audit_entry(user: &str, action: &str) -> String {
    format!("AUDIT: user={} action={} timestamp={}", user, action, current_timestamp())
}

fn write_audit_log(entry: &str) -> Result<(), String> {
    let path = "/var/log/proxy/audit.log";
    fs::write(path, entry).map_err(|e| e.to_string())
}

fn run_audit_from_env() -> Result<(), String> {
    let username = env::var("AUDIT_USER").map_err(|e| e.to_string())?;
    let action = env::var("AUDIT_ACTION").map_err(|e| e.to_string())?;
    let entry = format_audit_entry(&username, &action);
    write_audit_log(&entry)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop stdin -> multiple format hops -> Command
// stdin -> read_line -> trim_and_validate -> build_deploy_target -> build_deploy_cmd -> Command
// ---------------------------------------------------------------------------
fn trim_and_validate(input: &str) -> Result<String, String> {
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() {
        return Err("empty input".into());
    }
    Ok(trimmed)
}

fn build_deploy_target(service: &str) -> String {
    format!("/opt/services/{}/deploy.sh", service)
}

fn build_deploy_cmd(target: &str, version: &str) -> String {
    format!("{} --version {}", target, version)
}

fn run_deploy() -> Result<String, String> {
    let mut service_input = String::new();
    io::stdin().read_line(&mut service_input).map_err(|e| e.to_string())?;
    let service = trim_and_validate(&service_input)?;
    let target = build_deploy_target(&service);
    let cmd = build_deploy_cmd(&target, "latest");
    execute_shell_command(&cmd)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop file read from stdin
// stdin -> read_line -> resolve_log_path -> validate_extension -> fs::read
// ---------------------------------------------------------------------------
fn resolve_log_path(filename: &str) -> String {
    format!("/var/log/proxy/{}", filename)
}

fn validate_extension(path: &str) -> Result<String, String> {
    if path.ends_with(".log") || path.ends_with(".txt") {
        Ok(path.to_string())
    } else {
        Err("invalid file extension".into())
    }
}

fn run_log_download() -> Result<Vec<u8>, String> {
    let mut filename = String::new();
    io::stdin().read_line(&mut filename).map_err(|e| e.to_string())?;
    let path = resolve_log_path(filename.trim());
    let validated = validate_extension(&path)?;
    fs::read(&validated).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN: 5-hop env var -> backup command chain
// env::var -> build_backup_name -> build_backup_path -> build_backup_cmd -> Command::new
// ---------------------------------------------------------------------------
fn build_backup_name(db_name: &str) -> String {
    format!("{}_backup", db_name)
}

fn build_backup_path(name: &str) -> String {
    format!("/var/backups/{}.sql", name)
}

fn build_backup_cmd(db_url: &str, output_path: &str) -> String {
    format!("pg_dump {} -f {}", db_url, output_path)
}

fn run_backup() -> Result<String, String> {
    let db_name = env::var("BACKUP_DB").map_err(|e| e.to_string())?;
    let name = build_backup_name(&db_name);
    let path = build_backup_path(&name);
    let cmd = build_backup_cmd(&db_name, &path);
    execute_shell_command(&cmd)
}

// ---------------------------------------------------------------------------
// Safe versions (with sanitization)
// ---------------------------------------------------------------------------

fn run_system_check_safe(check_type: &str) -> Result<String, String> {
    let allowed = vec!["health", "disk", "memory", "cpu"];
    if !allowed.contains(&check_type) {
        return Err("Invalid check type".into());
    }
    let output = Command::new("system-check")
        .arg(check_type)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_log_download_safe(filename: &str) -> Result<Vec<u8>, String> {
    let sanitizer = PathSanitizer::new("/var/log/proxy");
    let safe_path = sanitizer.sanitize(filename)?;
    fs::read(&safe_path).map_err(|e| e.to_string())
}

fn run_search_safe(state: &AppState, query: &str) -> Result<Vec<HashMap<String, String>>, String> {
    state.admin.execute_query_safe("SELECT * FROM proxy_logs WHERE path LIKE ?", &[&format!("%{}%", query)])
}

// Sanitized SQL: query passes through SqlSanitizer.escape_string before execute_query
fn run_search_escaped(state: &AppState, query: &str) -> Result<Vec<HashMap<String, String>>, String> {
    let escaped = SqlSanitizer::escape_string(query);
    let sql = format!("SELECT * FROM proxy_logs WHERE path LIKE '%{}%'", escaped);
    state.admin.execute_query(&sql)
}

// Sanitized path: filename passes through canonicalize before fs::read
fn run_log_view_canonicalized(filename: &str) -> Result<Vec<u8>, String> {
    let base = Path::new("/var/log/proxy");
    let target = base.join(filename);
    let canonical = target.canonicalize().map_err(|e| e.to_string())?;
    if !canonical.starts_with(base) {
        return Err("Path traversal detected".into());
    }
    fs::read(&canonical).map_err(|e| e.to_string())
}

// Sanitized path: filename passes through file_name() to strip directory components
fn run_log_download_basename(filename: &str) -> Result<Vec<u8>, String> {
    let safe_name = Path::new(filename)
        .file_name()
        .ok_or("Invalid filename")?
        .to_str()
        .ok_or("Invalid UTF-8")?;
    let path = format!("/var/log/proxy/{}", safe_name);
    fs::read(&path).map_err(|e| e.to_string())
}

// Sanitized command: check_name passes through replace() before Command
fn run_system_check_sanitized(check_name: &str) -> Result<String, String> {
    let sanitized = check_name.replace(|c: char| !c.is_alphanumeric() && c != '-', "");
    let cmd = format!("system-check {}", sanitized);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Sanitized template: user data passes through HtmlEscaper.escape before rendering
fn run_render_status_escaped(template: &str, data: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in data {
        let escaped_value = HtmlEscaper::escape(value);
        result = result.replace(&format!("{{{{{}}}}}", key), &escaped_value);
    }
    result
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

// ---------------------------------------------------------------------------
// VULN: 5-hop stdin -> deserialization + file write
// stdin -> read_line -> decode_input -> parse_config_data -> write_parsed_config -> fs::write
// ---------------------------------------------------------------------------
fn decode_input(raw: &str) -> String {
    raw.trim().replace("\\n", "\n")
}

fn parse_config_data(input: &str) -> HashMap<String, String> {
    let mut config = HashMap::new();
    for line in input.lines() {
        if let Some((k, v)) = line.split_once('=') {
            config.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    config
}

fn write_parsed_config(config: &HashMap<String, String>, path: &str) -> Result<(), String> {
    let content = config.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(path, &content).map_err(|e| e.to_string())
}

fn run_stdin_config_import() -> Result<(), String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let decoded = decode_input(&input);
    let config = parse_config_data(&decoded);
    let path = config.get("output").cloned().unwrap_or("/tmp/parsed.conf".into());
    write_parsed_config(&config, &path)
}

// ---------------------------------------------------------------------------
// VULN: 6-hop env -> template rendering -> file write
// env::var -> load_template_name -> read_template_file -> render_template -> write_output -> fs::write
// ---------------------------------------------------------------------------
fn load_template_name() -> Result<String, String> {
    env::var("TEMPLATE_NAME").map_err(|e| e.to_string())
}

fn read_template_file(name: &str) -> Result<String, String> {
    let path = format!("/etc/proxy/templates/{}.html", name);
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

fn render_template(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    result
}

fn write_rendered_output(content: &str, name: &str) -> Result<(), String> {
    let path = format!("/var/www/html/{}.html", name);
    fs::write(&path, content).map_err(|e| e.to_string())
}

fn run_template_render() -> Result<(), String> {
    let name = load_template_name()?;
    let template = read_template_file(&name)?;
    let mut vars = HashMap::new();
    vars.insert("title".into(), name.clone());
    let rendered = render_template(&template, &vars);
    write_rendered_output(&rendered, &name)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop env -> database restore command
// env::var -> build_restore_url -> build_restore_args -> format_restore_cmd -> Command
// ---------------------------------------------------------------------------
fn build_restore_url(host: &str, db: &str) -> String {
    format!("postgres://admin@{}:5432/{}", host, db)
}

fn build_restore_args(url: &str, dump_file: &str) -> String {
    format!("--dbname={} --file={}", url, dump_file)
}

fn format_restore_cmd(args: &str) -> String {
    format!("pg_restore {}", args)
}

fn run_database_restore() -> Result<String, String> {
    let host = env::var("RESTORE_HOST").map_err(|e| e.to_string())?;
    let db = env::var("RESTORE_DB").unwrap_or_else(|_| "main".into());
    let url = build_restore_url(&host, &db);
    let args = build_restore_args(&url, "/tmp/dump.sql");
    let cmd = format_restore_cmd(&args);
    execute_shell_command(&cmd)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop stdin -> file removal chain
// stdin -> read_line -> validate_filename -> build_removal_path -> confirm_removal -> fs::remove_file
// ---------------------------------------------------------------------------
fn validate_filename(name: &str) -> Result<String, String> {
    if name.is_empty() || name.contains('\0') {
        return Err("invalid filename".into());
    }
    Ok(name.to_string())
}

fn build_removal_path(name: &str) -> String {
    format!("/var/tmp/uploads/{}", name)
}

fn confirm_removal(path: &str) -> Result<(), String> {
    fs::remove_file(path).map_err(|e| e.to_string())
}

fn run_file_removal() -> Result<(), String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let name = validate_filename(input.trim())?;
    let path = build_removal_path(&name);
    confirm_removal(&path)
}

fn main() {
    let config = AppConfig::from_env();
    let state = AppState::new(&config);
    println!("Proxy server starting on {}", config.bind_addr);

    let headers = HashMap::new();
    let _ = run_proxy(&state, "/api/test", &headers);
    let _ = run_cli_command();
    let _ = run_config_load();
    let _ = run_report_generation();
    let _ = run_health_check();
    let _ = run_search(&state);
    let _ = run_deploy();
    let _ = run_log_download();
    let _ = run_backup();
    let _ = run_config_import();
    let _ = run_audit_from_env();
    let _ = run_stdin_config_import();
    let _ = run_template_render();
    let _ = run_database_restore();
    let _ = run_file_removal();
}
