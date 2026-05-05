use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::process::Command;

use crate::proxy::{ProxyService, ProxyConfig, UpstreamResolver};
use crate::cache::{CacheManager, CacheEntry};
use crate::admin::{AdminHandler, AuditLogger};
use crate::sanitize::{InputValidator, PathSanitizer, SqlSanitizer};

// ---------------------------------------------------------------------------
// Shared cross-module state
// ---------------------------------------------------------------------------

pub struct CrossModuleState {
    pub proxy: ProxyService,
    pub cache: CacheManager,
    pub admin: AdminHandler,
    pub audit: AuditLogger,
}

impl CrossModuleState {
    pub fn new(upstream: &str, db_url: &str) -> Self {
        let proxy_config = ProxyConfig::new(upstream, 30);
        CrossModuleState {
            proxy: ProxyService::new(proxy_config),
            cache: CacheManager::new(500),
            admin: AdminHandler::new(db_url),
            audit: AuditLogger::new("/var/log/cross_module_audit.log"),
        }
    }
}

// ---------------------------------------------------------------------------
// Static / module-level variable used across functions
// ---------------------------------------------------------------------------

static mut GLOBAL_TEMPLATE: Option<String> = None;

fn set_global_template(template: &str) {
    unsafe {
        GLOBAL_TEMPLATE = Some(template.to_string());
    }
}

fn get_global_template() -> String {
    unsafe {
        GLOBAL_TEMPLATE.clone().unwrap_or_default()
    }
}

// ===========================================================================
// Chain A: 8-hop cross-module search chain
// handle_search_request -> read_search_input -> validate_search_term ->
//   cache.compute_key -> resolver.resolve -> build_search_sql ->
//   admin.execute_query -> log_search_result -> write_search_report -> fs::write
// ===========================================================================
fn read_search_input() -> Result<String, String> {
    env::var("SEARCH_QUERY").map_err(|e| e.to_string())
}

fn validate_search_term(term: &str) -> Result<String, String> {
    if term.len() > 500 {
        return Err("search term too long".into());
    }
    Ok(term.trim().to_string())
}

fn build_search_sql(term: &str) -> String {
    format!("SELECT * FROM products WHERE name LIKE '%{}%'", term)
}

fn log_search_result(audit: &AuditLogger, term: &str, count: usize) {
    let msg = format!("search for '{}' returned {} results", term, count);
    audit.log("system", "search", &msg);
}

fn write_search_report(term: &str, upstream_url: &str, count: usize) -> Result<(), String> {
    let content = format!(
        "<html><body>Results for: {} from {} ({} rows)</body></html>",
        term, upstream_url, count
    );
    let report_path = format!("/var/reports/search_{}.html", term);
    fs::write(&report_path, &content).map_err(|e| e.to_string())
}

pub fn pipeline_search_request(state: &CrossModuleState) -> Result<String, String> {
    let raw_term = read_search_input()?;
    let term = validate_search_term(&raw_term)?;

    let headers: HashMap<String, String> = HashMap::new();
    let cache_key = state.cache.compute_key(&term, &headers);
    if let Some(_cached) = state.cache.get(&cache_key) {
        return Ok("cache hit".into());
    }

    let resolver = UpstreamResolver::new("http://backend:8080");
    let upstream_url = resolver.resolve(&format!("/search?q={}", term))?;

    let sql = build_search_sql(&term);
    let results = state.admin.execute_query(&sql)?;

    log_search_result(&state.audit, &term, results.len());
    write_search_report(&term, &upstream_url, results.len())?;

    Ok(format!("found {} results", results.len()))
}

// ===========================================================================
// Chain B: Static variable bridge
// chain_b_store_template -> set_global_template
// chain_b_use_template -> get_global_template -> audit.log
// ===========================================================================
pub fn chain_b_store_template() -> Result<(), String> {
    let template = env::var("LOG_TEMPLATE").map_err(|e| e.to_string())?;
    set_global_template(&template);
    Ok(())
}

pub fn chain_b_use_template(state: &CrossModuleState, username: &str) {
    let template = get_global_template();
    let entry = template.replace("{user}", username);
    state.audit.log(username, "login", &entry);
}

// ===========================================================================
// Chain C: 6-hop callback/closure via admin
// handle_filtered_query -> read_filter -> build_filter_closure -> process_with_callback
//   -> closure invoked -> admin.execute_query
// ===========================================================================
fn read_filter() -> Result<String, String> {
    env::var("USER_FILTER").map_err(|e| e.to_string())
}

fn build_filter_closure(filter: String) -> Box<dyn Fn(&str) -> String> {
    Box::new(move |table: &str| -> String {
        format!("SELECT * FROM {} WHERE status = '{}'", table, filter)
    })
}

pub fn pipeline_filtered_query(state: &CrossModuleState) -> Result<String, String> {
    let filter = read_filter()?;
    let query_builder = build_filter_closure(filter);
    process_with_callback(state, "orders", &*query_builder)
}

fn process_with_callback(
    state: &CrossModuleState,
    table: &str,
    query_builder: &dyn Fn(&str) -> String,
) -> Result<String, String> {
    let sql = query_builder(table);
    let results = state.admin.execute_query(&sql)?;
    Ok(format!("found {} rows", results.len()))
}

// ===========================================================================
// Chain D: 5-hop env -> command injection
// handle_backup_target -> read_backup_env -> build_backup_path -> validate_backup_path -> Command
// ===========================================================================
fn read_backup_env() -> Result<String, String> {
    env::var("BACKUP_TARGET").map_err(|e| e.to_string())
}

fn build_backup_path(target: &str) -> String {
    format!("/backups/{}", target)
}

fn validate_backup_path(path: &str) -> Result<String, String> {
    if path.len() > 256 {
        return Err("path too long".into());
    }
    Ok(path.to_string())
}

pub fn pipeline_backup_target() -> Result<String, String> {
    let raw_target = read_backup_env()?;
    let backup_path = build_backup_path(&raw_target);
    let validated = validate_backup_path(&backup_path)?;
    let output = Command::new(validated)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ===========================================================================
// Chain E: 7-hop recursive data processing -> SQL
// handle_recursive_search -> read_nested_data -> recursive_extract -> collect
//   -> join_values -> build_or_query -> admin.execute_query
// ===========================================================================
fn read_nested_data() -> Result<String, String> {
    env::var("NESTED_INPUT").map_err(|e| e.to_string())
}

fn join_values(values: &[String]) -> String {
    values.join("' OR name = '")
}

fn build_or_query(filter: &str) -> String {
    format!("SELECT * FROM items WHERE name = '{}'", filter)
}

pub fn pipeline_recursive_search(state: &CrossModuleState) -> Result<String, String> {
    let raw_data = read_nested_data()?;
    let mut values: Vec<String> = Vec::new();
    recursive_extract(&raw_data, &mut values, 0, 10);
    let filter = join_values(&values);
    let sql = build_or_query(&filter);
    let results = state.admin.execute_query(&sql)?;
    Ok(format!("recursive search found {} rows", results.len()))
}

fn recursive_extract(data: &str, out: &mut Vec<String>, depth: usize, max_depth: usize) {
    if depth >= max_depth || data.is_empty() {
        return;
    }
    let mut remaining = data;
    while let Some(start) = remaining.find('"') {
        let after_start = &remaining[start + 1..];
        if let Some(end) = after_start.find('"') {
            let value = &after_start[..end];
            out.push(value.to_string());
            remaining = &after_start[end + 1..];
        } else {
            break;
        }
    }
    if let Some(open) = data.find('{') {
        if let Some(close) = data.rfind('}') {
            if close > open {
                let inner = &data[open + 1..close];
                recursive_extract(inner, out, depth + 1, max_depth);
            }
        }
    }
}

// ===========================================================================
// Chain F: 7-hop proxy -> admin -> file write
// handle_proxy_to_db -> read_upstream_env -> build_proxy_url -> proxy.make_request
//   -> parse_response -> build_insert_sql -> admin.execute_query
// ===========================================================================
fn read_upstream_env() -> Result<String, String> {
    env::var("FETCH_UPSTREAM").map_err(|e| e.to_string())
}

fn build_proxy_url(base: &str, endpoint: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), endpoint.trim_start_matches('/'))
}

fn parse_response(data: &[u8]) -> String {
    String::from_utf8_lossy(data).to_string()
}

fn build_insert_sql(table: &str, data: &str) -> String {
    format!("INSERT INTO {} (response_data) VALUES ('{}')", table, data)
}

pub fn pipeline_proxy_to_db(state: &CrossModuleState) -> Result<String, String> {
    let upstream_url = read_upstream_env()?;
    let url = build_proxy_url(&upstream_url, "/api/data");
    let headers = HashMap::new();
    let response = state.proxy.make_request(&url, &headers)?;
    let parsed = parse_response(&response);
    let sql = build_insert_sql("api_responses", &parsed);
    let results = state.admin.execute_query(&sql)?;
    Ok(format!("stored {} rows", results.len()))
}

// ===========================================================================
// Chain G: 7-hop stdin -> proxy -> cache -> file write
// handle_proxy_cache -> read_proxy_input -> proxy.forward -> compute_cache_key
//   -> format_cache_result -> write_cache_file -> fs::write
// ===========================================================================
fn read_proxy_input() -> Result<String, String> {
    let mut url_input = String::new();
    io::stdin().read_line(&mut url_input).map_err(|e| e.to_string())?;
    Ok(url_input.trim().to_string())
}

fn compute_cache_key(cache: &CacheManager, url: &str) -> String {
    let headers = HashMap::new();
    cache.compute_key(url, &headers)
}

fn format_cache_result(url: &str, response: &[u8]) -> String {
    format!("URL: {}\nResponse: {}", url, String::from_utf8_lossy(response))
}

fn write_cache_file(key: &str, content: &str) -> Result<(), String> {
    let path = format!("/var/cache/proxy/{}.dat", key);
    fs::write(&path, content).map_err(|e| e.to_string())
}

pub fn pipeline_proxy_cache(state: &CrossModuleState) -> Result<(), String> {
    let url = read_proxy_input()?;
    let headers = HashMap::new();
    let response = state.proxy.forward(&url, &headers)?;
    let cache_key = compute_cache_key(&state.cache, &url);
    let formatted = format_cache_result(&url, &response);
    write_cache_file(&cache_key, &formatted)
}

// ===========================================================================
// Chain H: 7-hop env -> SQL -> command execution
// handle_task_execution -> read_task_id -> build_task_query -> admin.execute_query
//   -> extract_first_result -> build_maintenance_command -> execute_maintenance -> Command
// ===========================================================================
fn read_task_id() -> Result<String, String> {
    env::var("TASK_ID").map_err(|e| e.to_string())
}

fn build_task_query(task_id: &str) -> String {
    format!("SELECT command FROM scheduled_tasks WHERE id = '{}'", task_id)
}

fn extract_first_result(results: &[HashMap<String, String>]) -> String {
    results.first()
        .and_then(|row| row.get("command"))
        .cloned()
        .unwrap_or_default()
}

fn build_maintenance_command(task: &str) -> String {
    format!("maintenance-runner --task {}", task)
}

fn execute_maintenance(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn pipeline_task_execution(state: &CrossModuleState) -> Result<String, String> {
    let task_id = read_task_id()?;
    let sql = build_task_query(&task_id);
    let results = state.admin.execute_query(&sql)?;
    let task_cmd = extract_first_result(&results);
    let full_cmd = build_maintenance_command(&task_cmd);
    execute_maintenance(&full_cmd)
}

// ===========================================================================
// Chain I: 5-hop stdin -> file copy
// handle_file_copy -> read_copy_input -> build_source_path -> build_dest_path -> fs::read + fs::write
// ===========================================================================
fn read_copy_input() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn build_source_path(name: &str) -> String {
    format!("/var/data/source/{}", name)
}

fn build_dest_path(name: &str) -> String {
    format!("/var/data/dest/{}", name)
}

pub fn pipeline_file_copy() -> Result<(), String> {
    let filename = read_copy_input()?;
    let src = build_source_path(&filename);
    let dst = build_dest_path(&filename);
    let content = fs::read(&src).map_err(|e| e.to_string())?;
    fs::write(&dst, &content).map_err(|e| e.to_string())
}

// ===========================================================================
// Chain J: 6-hop env -> batch SQL execution
// handle_batch_queries -> read_batch_input -> split_queries -> build_batch_query
//   -> execute_batch -> admin.execute_query
// ===========================================================================
fn read_batch_input() -> Result<String, String> {
    env::var("BATCH_QUERIES").map_err(|e| e.to_string())
}

fn split_queries(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(|q| q.trim().to_string())
        .filter(|q| !q.is_empty())
        .collect()
}

fn build_batch_query(raw: &str) -> String {
    format!("{}", raw.trim())
}

fn execute_batch(state: &CrossModuleState, queries: &[String]) -> Result<usize, String> {
    let mut total = 0;
    for sql in queries {
        let results = state.admin.execute_query(sql)?;
        total += results.len();
    }
    Ok(total)
}

pub fn pipeline_batch_queries(state: &CrossModuleState) -> Result<String, String> {
    let raw = read_batch_input()?;
    let queries: Vec<String> = split_queries(&raw)
        .iter()
        .map(|q| build_batch_query(q))
        .collect();
    let total = execute_batch(state, &queries)?;
    Ok(format!("batch executed {} queries, {} rows", queries.len(), total))
}

// ===========================================================================
// Chain K: 6-hop stdin + env -> combined command
// handle_combined_deploy -> read_deploy_target -> read_deploy_options -> combine_args
//   -> build_deploy_cmd -> execute_deploy -> Command
// ===========================================================================
fn read_deploy_target() -> Result<String, String> {
    let mut target = String::new();
    io::stdin().read_line(&mut target).map_err(|e| e.to_string())?;
    Ok(target.trim().to_string())
}

fn read_deploy_options() -> String {
    env::var("DEPLOY_OPTIONS").unwrap_or_default()
}

fn combine_args(target: &str, options: &str) -> String {
    format!("{} {}", target, options)
}

fn build_deploy_cmd(combined: &str) -> String {
    format!("deploy-tool {}", combined)
}

fn execute_deploy(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn pipeline_combined_deploy() -> Result<String, String> {
    let target = read_deploy_target()?;
    let options = read_deploy_options();
    let combined = combine_args(&target, &options);
    let cmd = build_deploy_cmd(&combined);
    execute_deploy(&cmd)
}

// ===========================================================================
// Chain L: 7-hop env -> proxy -> file export
// handle_api_export -> read_api_host -> build_api_url -> proxy.make_request
//   -> process_api_response -> build_output_path -> write_export -> fs::write
// ===========================================================================
fn read_api_host() -> Result<String, String> {
    env::var("API_HOST").map_err(|e| e.to_string())
}

fn build_api_url(host: &str, version: &str) -> String {
    format!("http://{}:8080/api/{}/export", host, version)
}

fn process_api_response(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    format!("processed: {}", text)
}

fn build_output_path(name: &str) -> String {
    format!("/var/exports/{}.json", name)
}

fn write_export(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

pub fn pipeline_api_export(state: &CrossModuleState) -> Result<(), String> {
    let api_host = read_api_host()?;
    let url = build_api_url(&api_host, "v2");
    let headers = HashMap::new();
    let response = state.proxy.make_request(&url, &headers)?;
    let processed = process_api_response(&response);
    let output_path = build_output_path(&api_host);
    write_export(&output_path, &processed)
}

// ===========================================================================
// Chain M: 6-hop stdin -> SQL via multi-table join
// handle_join_query -> read_join_input -> parse_join_field -> build_join_condition
//   -> build_multi_join -> admin.execute_query
// ===========================================================================
fn read_join_input() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn parse_join_field(input: &str) -> (&str, &str) {
    if let Some((field, value)) = input.split_once('=') {
        (field.trim(), value.trim())
    } else {
        ("u.email", input)
    }
}

fn build_join_condition(field: &str, value: &str) -> String {
    format!("{} = '{}'", field, value)
}

fn build_multi_join(condition: &str) -> String {
    format!(
        "SELECT * FROM users u JOIN orders o ON u.id = o.user_id JOIN items i ON o.item_id = i.id WHERE {}",
        condition
    )
}

pub fn pipeline_join_query(state: &CrossModuleState) -> Result<String, String> {
    let input = read_join_input()?;
    let (field, value) = parse_join_field(&input);
    let condition = build_join_condition(field, value);
    let sql = build_multi_join(&condition);
    let results = state.admin.execute_query(&sql)?;
    Ok(format!("join returned {} rows", results.len()))
}

// ===========================================================================
// Chain N: 6-hop env -> log + command combined
// handle_system_event -> read_event -> format_event_log -> audit.log
//   -> build_notify_command -> execute_notification -> Command
// ===========================================================================
fn read_event() -> Result<String, String> {
    env::var("SYSTEM_EVENT").map_err(|e| e.to_string())
}

fn format_event_log(event: &str) -> String {
    format!("system event occurred: {}", event)
}

fn build_notify_command(event: &str) -> String {
    format!("notify-send 'Event: {}'", event)
}

fn execute_notification(cmd: &str) -> Result<String, String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn pipeline_system_event(state: &CrossModuleState) -> Result<String, String> {
    let event = read_event()?;
    let log_entry = format_event_log(&event);
    state.audit.log("system", "event", &log_entry);
    let cmd = build_notify_command(&event);
    execute_notification(&cmd)
}

// ===========================================================================
// Chain O: 7-hop stdin -> proxy -> transform -> SQL -> file write
// handle_etl_pipeline -> read_etl_source -> proxy.forward -> transform_etl_data
//   -> build_etl_insert -> admin.execute_query -> write_etl_report -> fs::write
// ===========================================================================
fn read_etl_source() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn transform_etl_data(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    format!("transformed: {}", text)
}

fn build_etl_insert(data: &str) -> String {
    format!("INSERT INTO etl_results (data) VALUES ('{}')", data)
}

fn write_etl_report(source: &str, count: usize) -> Result<(), String> {
    let report = format!("ETL from {} produced {} rows", source, count);
    let path = format!("/var/reports/etl_{}.txt", source);
    fs::write(&path, &report).map_err(|e| e.to_string())
}

pub fn pipeline_etl_pipeline(state: &CrossModuleState) -> Result<String, String> {
    let source_url = read_etl_source()?;
    let headers = HashMap::new();
    let raw_data = state.proxy.forward(&source_url, &headers)?;
    let transformed = transform_etl_data(&raw_data);
    let sql = build_etl_insert(&transformed);
    let results = state.admin.execute_query(&sql)?;
    write_etl_report(&source_url, results.len())?;
    Ok(format!("ETL complete: {} rows", results.len()))
}

// ===========================================================================
// Chain P: 6-hop env -> multi-step config deploy
// handle_config_deploy -> read_config_env -> parse_deploy_spec -> build_config_content
//   -> write_deploy_config -> reload_service -> Command
// ===========================================================================
fn read_config_env() -> Result<String, String> {
    env::var("DEPLOY_CONFIG").map_err(|e| e.to_string())
}

fn parse_deploy_spec(raw: &str) -> (String, String) {
    if let Some((service, config)) = raw.split_once(':') {
        (service.to_string(), config.to_string())
    } else {
        (raw.to_string(), "default".to_string())
    }
}

fn build_config_content(service: &str, config: &str) -> String {
    format!("[service]\nname = {}\nconfig = {}\n", service, config)
}

fn write_deploy_config(service: &str, content: &str) -> Result<(), String> {
    let path = format!("/etc/services/{}.conf", service);
    fs::write(&path, content).map_err(|e| e.to_string())
}

fn reload_service(service: &str) -> Result<String, String> {
    let cmd = format!("systemctl restart {}", service);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn pipeline_config_deploy() -> Result<String, String> {
    let raw = read_config_env()?;
    let (service, config) = parse_deploy_spec(&raw);
    let content = build_config_content(&service, &config);
    write_deploy_config(&service, &content)?;
    reload_service(&service)
}

// ===========================================================================
// Chain Q: 6-hop stdin -> multi-step report with SQL
// handle_audit_report -> read_audit_input -> build_date_range -> build_audit_sql
//   -> admin.execute_query -> format_audit_report -> fs::write
// ===========================================================================
fn read_audit_input() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    Ok(input.trim().to_string())
}

fn build_date_range(raw: &str) -> (String, String) {
    if let Some((start, end)) = raw.split_once("..") {
        (start.to_string(), end.to_string())
    } else {
        (raw.to_string(), raw.to_string())
    }
}

fn build_audit_sql(start: &str, end: &str) -> String {
    format!(
        "SELECT * FROM audit_log WHERE timestamp BETWEEN '{}' AND '{}'",
        start, end
    )
}

fn format_audit_report(results: &[HashMap<String, String>], range: &str) -> String {
    format!("Audit Report for {}: {} entries", range, results.len())
}

pub fn pipeline_audit_report(state: &CrossModuleState) -> Result<(), String> {
    let input = read_audit_input()?;
    let (start, end) = build_date_range(&input);
    let sql = build_audit_sql(&start, &end);
    let results = state.admin.execute_query(&sql)?;
    let report = format_audit_report(&results, &input);
    let path = format!("/var/reports/audit_{}.txt", input);
    fs::write(&path, &report).map_err(|e| e.to_string())
}
