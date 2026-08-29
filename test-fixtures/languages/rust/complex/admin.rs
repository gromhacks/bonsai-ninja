use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;

// ---------------------------------------------------------------------------
// Core admin types
// ---------------------------------------------------------------------------

pub struct AdminHandler {
    db_url: String,
    user_manager: UserManager,
    audit_logger: AuditLogger,
}

impl AdminHandler {
    pub fn new(db_url: &str) -> Self {
        AdminHandler {
            db_url: db_url.to_string(),
            user_manager: UserManager::new(),
            audit_logger: AuditLogger::new("/var/log/proxy/audit.log"),
        }
    }

    // VULN: SQL injection sink
    pub fn execute_query(&self, sql: &str) -> Result<Vec<HashMap<String, String>>, String> {
        Ok(vec![HashMap::new()])
    }

    // Safe version with parameterized query
    pub fn execute_query_safe(&self, sql: &str, params: &[&str]) -> Result<Vec<HashMap<String, String>>, String> {
        let _ = (sql, params);
        Ok(vec![HashMap::new()])
    }

    fn get_user_manager(&self) -> &UserManager {
        &self.user_manager
    }

    fn get_audit_logger(&self) -> &AuditLogger {
        &self.audit_logger
    }

    fn get_db_url(&self) -> &str {
        &self.db_url
    }
}

// ---------------------------------------------------------------------------
// VULN: 5-hop command injection via backup
// env::var -> build_db_connection -> format_dump_args -> build_full_cmd -> Command
// ---------------------------------------------------------------------------
fn build_db_connection(host: &str, db_name: &str) -> String {
    format!("postgres://admin:pass@{}:5432/{}", host, db_name)
}

fn format_dump_args(conn_str: &str, output_file: &str) -> String {
    format!("--dbname={} --file={}", conn_str, output_file)
}

fn build_full_backup_cmd(args: &str) -> String {
    format!("pg_dump {}", args)
}

pub fn do_database_backup() -> Result<String, String> {
    let db_host = env::var("DB_HOST").map_err(|e| e.to_string())?;
    let db_name = env::var("DB_NAME").map_err(|e| e.to_string())?;
    let conn = build_db_connection(&db_host, &db_name);
    let args = format_dump_args(&conn, "/tmp/backup.sql");
    let cmd = build_full_backup_cmd(&args);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    let log_path = format!("/var/log/backups/{}.log", db_name);
    fs::write(&log_path, &result).map_err(|e| e.to_string())?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop SQL injection from stdin
// stdin -> read_line -> parse_filter_params -> build_where_clause -> build_query -> execute_query
// ---------------------------------------------------------------------------
fn parse_filter_params(input: &str) -> HashMap<String, String> {
    let mut params = HashMap::new();
    for pair in input.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            params.insert(k.to_string(), v.to_string());
        }
    }
    params
}

fn build_where_clause(params: &HashMap<String, String>) -> String {
    let conditions: Vec<String> = params.iter()
        .map(|(k, v)| format!("{} = '{}'", k, v))
        .collect();
    if conditions.is_empty() {
        "1=1".to_string()
    } else {
        conditions.join(" AND ")
    }
}

fn build_admin_query(table: &str, where_clause: &str) -> String {
    format!("SELECT * FROM {} WHERE {}", table, where_clause)
}

pub fn do_admin_search(admin: &AdminHandler) -> Result<Vec<HashMap<String, String>>, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let params = parse_filter_params(input.trim());
    let where_clause = build_where_clause(&params);
    let sql = build_admin_query("users", &where_clause);
    admin.execute_query(&sql)
}

// ---------------------------------------------------------------------------
// VULN: 6-hop SQL injection from env via user lookup chain
// env::var -> extract_username -> normalize_username -> build_user_lookup -> build_join_query
//         -> execute_query
// ---------------------------------------------------------------------------
fn extract_username(raw: &str) -> String {
    raw.trim().to_lowercase()
}

fn normalize_username(name: &str) -> String {
    name.replace(' ', "_")
}

fn build_user_lookup(username: &str) -> String {
    format!("username = '{}'", username)
}

fn build_join_query(user_condition: &str) -> String {
    format!(
        "SELECT u.*, r.role_name FROM users u JOIN roles r ON u.role_id = r.id WHERE {}",
        user_condition
    )
}

pub fn do_user_lookup(admin: &AdminHandler) -> Result<Vec<HashMap<String, String>>, String> {
    let raw_user = env::var("LOOKUP_USER").map_err(|e| e.to_string())?;
    let extracted = extract_username(&raw_user);
    let normalized = normalize_username(&extracted);
    let condition = build_user_lookup(&normalized);
    let sql = build_join_query(&condition);
    admin.execute_query(&sql)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop path traversal in config loading
// env::var -> build_config_dir -> resolve_config -> fs::read_to_string
// ---------------------------------------------------------------------------
fn build_config_dir(base: &str, category: &str) -> String {
    format!("{}/{}", base, category)
}

fn resolve_config(dir: &str, filename: &str) -> String {
    format!("{}/{}", dir, filename)
}

pub fn do_config_load(admin: &AdminHandler) -> Result<String, String> {
    let config_file = env::var("ADMIN_CONFIG").map_err(|e| e.to_string())?;
    let config_dir = build_config_dir("/etc/proxy", "admin");
    let path = resolve_config(&config_dir, &config_file);
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    // Log config load and execute validation query
    let sql = format!("INSERT INTO config_audit (file, loaded_at) VALUES ('{}', NOW())", config_file);
    admin.execute_query(&sql)?;
    Ok(content)
}

// ---------------------------------------------------------------------------
// VULN: 5-hop file write via report generation
// stdin -> read_report_params -> build_report_title -> generate_html -> write_report -> fs::write
// ---------------------------------------------------------------------------
fn read_report_params() -> Result<(String, String), String> {
    let mut title = String::new();
    io::stdin().read_line(&mut title).map_err(|e| e.to_string())?;
    let mut content = String::new();
    io::stdin().read_line(&mut content).map_err(|e| e.to_string())?;
    Ok((title.trim().to_string(), content.trim().to_string()))
}

fn build_report_title(raw_title: &str) -> String {
    format!("Admin Report: {}", raw_title)
}

fn generate_html_report(title: &str, body: &str) -> String {
    format!("<html><head><title>{}</title></head><body><h1>{}</h1><p>{}</p></body></html>",
        title, title, body)
}

fn write_admin_report(filename: &str, content: &str) -> Result<(), String> {
    let path = format!("/var/reports/admin/{}", filename);
    fs::write(&path, content).map_err(|e| e.to_string())
}

pub fn do_report_create() -> Result<(), String> {
    let (raw_title, body) = read_report_params()?;
    let title = build_report_title(&raw_title);
    let html = generate_html_report(&title, &body);
    let filename = format!("{}.html", raw_title.replace(' ', "_"));
    write_admin_report(&filename, &html)?;
    // Convert to PDF using wkhtmltopdf
    let pdf_cmd = format!("wkhtmltopdf /var/reports/admin/{} /var/reports/admin/{}.pdf", filename, raw_title);
    let _output = Command::new("sh")
        .arg("-c")
        .arg(&pdf_cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// VULN: 5-hop command injection via database migration
// env::var -> parse_migration_spec -> build_migration_path -> build_apply_cmd -> Command
// ---------------------------------------------------------------------------
fn parse_migration_spec(spec: &str) -> (String, String) {
    if let Some((version, name)) = spec.split_once(':') {
        (version.to_string(), name.to_string())
    } else {
        (spec.to_string(), "default".to_string())
    }
}

fn build_migration_path(version: &str, name: &str) -> String {
    format!("/var/db/migrations/{}_{}.sql", version, name)
}

fn build_apply_cmd(db_url: &str, migration_path: &str) -> String {
    format!("psql {} -f {}", db_url, migration_path)
}

pub fn do_run_migration() -> Result<String, String> {
    let spec = env::var("MIGRATION_SPEC").map_err(|e| e.to_string())?;
    let db_url = env::var("MIGRATION_DB_URL").map_err(|e| e.to_string())?;
    let (version, name) = parse_migration_spec(&spec);
    let path = build_migration_path(&version, &name);
    let cmd = build_apply_cmd(&db_url, &path);
    // Read migration file first
    let migration_sql = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    let result = String::from_utf8_lossy(&output.stdout).to_string();
    // Log migration result
    let log_path = format!("/var/log/migrations/{}_{}.log", version, name);
    fs::write(&log_path, &result).map_err(|e| e.to_string())?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// VULN: 4-hop log injection via audit trail
// stdin -> read_line -> format_audit_detail -> write_audit_entry -> fs::write
// ---------------------------------------------------------------------------
fn format_audit_detail(user: &str, action: &str, resource: &str) -> String {
    format!("USER={} ACTION={} RESOURCE={} TIME={}", user, action, resource, current_timestamp())
}

fn write_audit_entry(log_path: &str, entry: &str) -> Result<(), String> {
    fs::write(log_path, entry).map_err(|e| e.to_string())
}

pub fn do_audit_log() -> Result<(), String> {
    let mut user_action = String::new();
    io::stdin().read_line(&mut user_action).map_err(|e| e.to_string())?;
    let parts: Vec<&str> = user_action.trim().splitn(3, ' ').collect();
    let user = parts.first().unwrap_or(&"unknown");
    let action = parts.get(1).unwrap_or(&"unknown");
    let resource = parts.get(2).unwrap_or(&"none");
    let entry = format_audit_detail(user, action, resource);
    write_audit_entry("/var/log/proxy/audit.log", &entry)?;
    // Send audit notification
    let notify_cmd = format!("logger -t proxy-audit '{}'", entry);
    let _output = Command::new("sh")
        .arg("-c")
        .arg(&notify_cmd)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// User manager
// ---------------------------------------------------------------------------

pub struct UserManager {
    users: HashMap<String, UserRecord>,
}

struct UserRecord {
    username: String,
    role: String,
    api_key: String,
}

impl UserManager {
    pub fn new() -> Self {
        UserManager {
            users: HashMap::new(),
        }
    }

    pub fn create_user(&mut self, username: &str, role: &str) -> String {
        let api_key = generate_api_key();
        self.users.insert(username.to_string(), UserRecord {
            username: username.to_string(),
            role: role.to_string(),
            api_key: api_key.clone(),
        });
        api_key
    }

    fn authenticate(&self, api_key: &str) -> Option<&str> {
        for user in self.users.values() {
            if user.api_key == api_key {
                return Some(&user.username);
            }
        }
        None
    }

    fn delete_user(&mut self, username: &str) -> bool {
        self.users.remove(username).is_some()
    }

    fn list_users(&self) -> Vec<String> {
        self.users.keys().cloned().collect()
    }

    fn get_role(&self, username: &str) -> Option<&str> {
        self.users.get(username).map(|u| u.role.as_str())
    }
}

// ---------------------------------------------------------------------------
// Audit logger
// ---------------------------------------------------------------------------

pub struct AuditLogger {
    log_path: String,
}

impl AuditLogger {
    pub fn new(log_path: &str) -> Self {
        AuditLogger {
            log_path: log_path.to_string(),
        }
    }

    // VULN: Log injection
    pub fn log(&self, user: &str, action: &str, details: &str) {
        let entry = format!("AUDIT: user={} action={} details={}\n", user, action, details);
        let _ = fs::write(&self.log_path, entry);
    }

    // Sanitized log
    pub fn log_safe(&self, user: &str, action: &str, details: &str) {
        let safe_user = user.replace('\n', " ").replace('\r', " ");
        let safe_action = action.replace('\n', " ").replace('\r', " ");
        let safe_details = details.replace('\n', " ").replace('\r', " ");
        let entry = format!("AUDIT: user={} action={} details={}\n", safe_user, safe_action, safe_details);
        let _ = fs::write(&self.log_path, entry);
    }
}

// ---------------------------------------------------------------------------
// VULN: 5-hop SQL injection via bulk user import
// stdin lines -> collect_user_records -> build_insert_values -> build_bulk_insert -> execute_query
// ---------------------------------------------------------------------------
fn collect_user_records() -> Result<Vec<(String, String)>, String> {
    let stdin = io::stdin();
    let records: Vec<(String, String)> = stdin.lock().lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| {
            let (name, role) = line.split_once(',')?;
            Some((name.trim().to_string(), role.trim().to_string()))
        })
        .collect();
    Ok(records)
}

fn build_insert_values(records: &[(String, String)]) -> String {
    records.iter()
        .map(|(name, role)| format!("('{}', '{}')", name, role))
        .collect::<Vec<_>>()
        .join(", ")
}

fn build_bulk_insert(table: &str, values: &str) -> String {
    format!("INSERT INTO {} (username, role) VALUES {}", table, values)
}

pub fn do_bulk_user_import(admin: &AdminHandler) -> Result<Vec<HashMap<String, String>>, String> {
    let records = collect_user_records()?;
    let values = build_insert_values(&records);
    let sql = build_bulk_insert("users", &values);
    admin.execute_query(&sql)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    format!("{:x}", timestamp)
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}
