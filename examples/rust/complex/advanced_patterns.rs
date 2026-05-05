use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{self, BufRead};
use std::process::Command;

// ---------------------------------------------------------------------------
// Structs, enums, and traits exercising Rust-specific syntax
// ---------------------------------------------------------------------------

pub struct DatabaseConfig {
    pub host: String,
    pub port: u16,
    pub name: String,
}

impl DatabaseConfig {
    pub fn connection_string(&self) -> String {
        format!("postgres://{}:{}/{}", self.host, self.port, self.name)
    }
}

pub struct QueryResult {
    pub rows: Vec<HashMap<String, String>>,
    pub affected: usize,
}

pub enum RequestPayload {
    Json(String),
    Form(HashMap<String, String>),
    Raw(Vec<u8>),
}

pub trait Executable {
    fn execute(&self, input: &str) -> Result<String, String>;
}

pub struct ShellRunner;

impl Executable for ShellRunner {
    fn execute(&self, input: &str) -> Result<String, String> {
        let output = Command::new("sh")
            .arg("-c")
            .arg(input)
            .output()
            .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

pub struct ScriptRunner {
    pub interpreter: String,
}

impl Executable for ScriptRunner {
    fn execute(&self, input: &str) -> Result<String, String> {
        let output = Command::new(&self.interpreter)
            .arg("-e")
            .arg(input)
            .output()
            .map_err(|e| e.to_string())?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

// ---------------------------------------------------------------------------
// VULN 1: 5-hop Result/Option chain
// env::var -> unwrap -> map(trim) -> and_then(validate) -> format! -> Command
// ---------------------------------------------------------------------------
pub fn result_option_chain_vuln() -> Result<String, String> {
    let raw_cmd = env::var("USER_CMD").map_err(|e| e.to_string())?;

    let output = Some(raw_cmd)
        .map(|s| s.trim().to_string())
        .and_then(|trimmed| {
            if trimmed.is_empty() { None } else { Some(trimmed) }
        })
        .ok_or_else(|| "empty command".to_string())?;

    let full_cmd = format!("runner {}", output);
    let result = Command::new("sh")
        .arg("-c")
        .arg(&full_cmd)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&result.stdout).to_string();
    fs::write("/tmp/last_command_output.txt", &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// VULN 2: 5-hop Match expression routing through enum
// stdin -> read_line -> RequestPayload::Json -> match arm -> format!(SQL) -> execute_query
// ---------------------------------------------------------------------------
pub fn match_routing_vuln(db: &DatabaseConfig) -> Result<QueryResult, String> {
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|e| e.to_string())?;
    let payload = RequestPayload::Json(line.trim().to_string());

    let filter = match payload {
        RequestPayload::Json(ref body) => body.clone(),
        RequestPayload::Form(ref fields) => {
            fields.get("filter").cloned().unwrap_or_default()
        }
        RequestPayload::Raw(ref bytes) => {
            String::from_utf8_lossy(bytes).to_string()
        }
    };

    let sql = format!(
        "SELECT * FROM events WHERE data LIKE '%{}%'",
        filter
    );
    execute_query(&db.connection_string(), &sql)
}

// ---------------------------------------------------------------------------
// VULN 3: 4-hop if-let pattern
// env::var -> if let Ok(name) -> format! path -> fs::write
// ---------------------------------------------------------------------------
pub fn if_let_vuln(report_content: &str) -> Result<(), String> {
    if let Ok(filename) = env::var("REPORT_FILE") {
        let path = format!("/var/reports/{}", filename);
        fs::write(&path, report_content).map_err(|e| e.to_string())?;
        // Also notify via command
        let _out = Command::new("notify-send")
            .arg(&format!("Report written: {}", filename))
            .output()
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VULN 4: 5-hop let-else pattern
// env::var -> let else -> format! script path -> format! cmd -> Command
// ---------------------------------------------------------------------------
pub fn let_else_vuln() -> Result<String, String> {
    let Ok(script_name) = env::var("SCRIPT_NAME") else {
        return Err("SCRIPT_NAME not set".into());
    };
    let script_path = format!("/opt/scripts/{}", script_name);
    let cmd = format!("bash {}", script_path);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    fs::write("/tmp/script_output.log", &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// VULN 5: 5-hop closure argument chain
// stdin -> read_line -> closure -> run_with_transform -> closure invoked -> Command
// ---------------------------------------------------------------------------
pub fn closure_argument_vuln() -> Result<String, String> {
    let mut user_input = String::new();
    io::stdin().read_line(&mut user_input).map_err(|e| e.to_string())?;

    let transformer = |s: &str| -> String {
        format!("deploy --target {}", s.trim())
    };

    run_with_transform(&user_input, transformer)
}

fn run_with_transform<F>(input: &str, transform: F) -> Result<String, String>
where
    F: Fn(&str) -> String,
{
    let cmd_line = transform(input);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&cmd_line)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    fs::write("/tmp/transform_output.log", &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// VULN 6: 5-hop iterator chain
// env::var -> split -> map(trim) -> filter -> collect -> join -> fs::write
// ---------------------------------------------------------------------------
pub fn iterator_chain_vuln() -> Result<(), String> {
    let raw_paths = env::var("INCLUDE_PATHS").map_err(|e| e.to_string())?;

    let cleaned: Vec<String> = raw_paths
        .split(';')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();

    let manifest = cleaned.join("\n");
    fs::write("/tmp/build_manifest.txt", &manifest).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN 7: 5-hop Box<dyn Trait> dispatch
// env::var -> select runner -> stdin -> read_line -> dyn Executable::execute -> Command
// ---------------------------------------------------------------------------
pub fn trait_object_dispatch_vuln() -> Result<String, String> {
    let runner_type = env::var("RUNNER_TYPE").unwrap_or_else(|_| "shell".into());

    let runner: Box<dyn Executable> = match runner_type.as_str() {
        "script" => Box::new(ScriptRunner {
            interpreter: "python3".into(),
        }),
        _ => Box::new(ShellRunner),
    };

    let mut user_code = String::new();
    io::stdin().read_line(&mut user_code).map_err(|e| e.to_string())?;
    let result = runner.execute(user_code.trim())?;
    fs::write("/tmp/runner_output.log", &result).map_err(|e| e.to_string())?;
    Ok(result)
}

// ---------------------------------------------------------------------------
// VULN 8: 6-hop struct update syntax
// env::var -> DatabaseConfig { name: tainted, ..defaults } -> connection_string
//          -> build_diagnostic_query -> format! -> execute_query
// ---------------------------------------------------------------------------
pub fn struct_update_vuln() -> Result<QueryResult, String> {
    let user_db = env::var("TARGET_DB").map_err(|e| e.to_string())?;

    let defaults = DatabaseConfig {
        host: "localhost".into(),
        port: 5432,
        name: "default".into(),
    };

    let config = DatabaseConfig {
        name: user_db,
        ..defaults
    };

    let conn = config.connection_string();
    let diagnostic = build_diagnostic_query(&conn);
    execute_query(&conn, &diagnostic)
}

fn build_diagnostic_query(conn_info: &str) -> String {
    format!("SELECT version() -- connected to {}", conn_info)
}

// ---------------------------------------------------------------------------
// VULN 9: 5-hop tuple destructuring
// stdin -> read_line -> split_once -> (host, port) -> format! url -> Command(curl)
// ---------------------------------------------------------------------------
pub fn tuple_destructure_vuln() -> Result<String, String> {
    let mut address = String::new();
    io::stdin().read_line(&mut address).map_err(|e| e.to_string())?;

    let (host, port) = address
        .trim()
        .split_once(':')
        .ok_or("expected host:port")?;

    let url = format!("http://{}:{}/health", host, port);
    let output = Command::new("curl")
        .arg("-s")
        .arg(&url)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    fs::write("/tmp/health_check_result.txt", &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// VULN 10: 6-hop multi-format chain
// stdin -> read_line -> format!(clause) -> format!(subquery) -> format!(full_sql) -> execute_query
// ---------------------------------------------------------------------------
pub fn format_chain_vuln(db_url: &str) -> Result<QueryResult, String> {
    let mut search_term = String::new();
    io::stdin().read_line(&mut search_term).map_err(|e| e.to_string())?;
    let term = search_term.trim();

    let clause = format!("name LIKE '%{}%'", term);
    let subquery = format!("SELECT id FROM users WHERE {}", clause);
    let full_sql = format!(
        "SELECT * FROM orders WHERE user_id IN ({})",
        subquery
    );
    execute_query(db_url, &full_sql)
}

// ---------------------------------------------------------------------------
// VULN 11: 5-hop HashMap insert then get
// stdin -> read_line -> HashMap::insert -> get -> unwrap -> fs::write
// ---------------------------------------------------------------------------
pub fn hashmap_insert_get_vuln() -> Result<(), String> {
    let mut config_value = String::new();
    io::stdin().read_line(&mut config_value).map_err(|e| e.to_string())?;

    let mut settings: HashMap<String, String> = HashMap::new();
    settings.insert("output_path".into(), config_value.trim().to_string());

    let target = settings.get("output_path").ok_or("missing output_path")?;
    fs::write(target, "deployment complete").map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN 12: 6-hop enum data variant
// env::var -> stdin -> read_line -> enum variant -> extract_payload_body -> format!(SQL) -> execute_query
// ---------------------------------------------------------------------------
pub fn enum_data_variant_vuln(db_url: &str) -> Result<QueryResult, String> {
    let payload_type = env::var("PAYLOAD_TYPE").unwrap_or_else(|_| "json".into());

    let mut body = String::new();
    io::stdin().read_line(&mut body).map_err(|e| e.to_string())?;

    let payload = match payload_type.as_str() {
        "form" => {
            let mut fields = HashMap::new();
            fields.insert("data".into(), body.trim().to_string());
            RequestPayload::Form(fields)
        }
        "raw" => RequestPayload::Raw(body.trim().as_bytes().to_vec()),
        _ => RequestPayload::Json(body.trim().to_string()),
    };

    let extracted = extract_payload_body(&payload);
    let sql = format!("INSERT INTO inbox (body) VALUES ('{}')", extracted);
    execute_query(db_url, &sql)
}

fn extract_payload_body(payload: &RequestPayload) -> String {
    match payload {
        RequestPayload::Json(s) => s.clone(),
        RequestPayload::Form(fields) => {
            fields.get("data").cloned().unwrap_or_default()
        }
        RequestPayload::Raw(bytes) => String::from_utf8_lossy(bytes).to_string(),
    }
}

// ---------------------------------------------------------------------------
// VULN 13: 7-hop combined patterns chain
// stdin lines -> map(parse_kv) -> collect -> get("cmd") -> closure -> format! -> Command
// ---------------------------------------------------------------------------
pub fn combined_patterns_vuln() -> Result<String, String> {
    let stdin = io::stdin();
    let kvs: HashMap<String, String> = stdin
        .lock()
        .lines()
        .filter_map(|line| line.ok())
        .filter_map(|line| {
            let (k, v) = line.split_once('=')?;
            Some((k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let raw_cmd = kvs.get("cmd").ok_or("missing 'cmd' key")?;

    let build_command = |base: &str| -> String {
        let workspace = kvs.get("workspace").cloned().unwrap_or_else(|| "/tmp".into());
        format!("cd {} && {}", workspace, base)
    };

    let full = build_command(raw_cmd);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&full)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let log_path = format!("/tmp/combined_output_{}.log", raw_cmd.len());
    fs::write(&log_path, &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// VULN 14: 6-hop env -> iterator -> file write chain
// env::var -> split -> map -> filter -> collect -> build_script_content -> fs::write
// ---------------------------------------------------------------------------
pub fn env_to_script_vuln() -> Result<(), String> {
    let raw_commands = env::var("BATCH_COMMANDS").map_err(|e| e.to_string())?;

    let commands: Vec<String> = raw_commands
        .split('|')
        .map(|c| c.trim().to_string())
        .filter(|c| !c.is_empty())
        .collect();

    let script = build_script_content(&commands);
    let script_path = env::var("SCRIPT_OUTPUT").unwrap_or_else(|_| "/tmp/batch.sh".into());
    fs::write(&script_path, &script).map_err(|e| e.to_string())?;
    // Execute the generated batch script
    let _output = Command::new("bash")
        .arg(&script_path)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn build_script_content(commands: &[String]) -> String {
    let mut script = String::from("#!/bin/bash\nset -e\n\n");
    for cmd in commands {
        script.push_str(&format!("{}\n", cmd));
    }
    script
}

// ---------------------------------------------------------------------------
// VULN 15: 5-hop generic function chain
// stdin -> read_line -> process_input::<String> -> transform_data -> execute_query
// ---------------------------------------------------------------------------
fn process_input<T: From<String>>(raw: &str) -> T {
    T::from(raw.trim().to_string())
}

fn transform_data(data: &str, table: &str) -> String {
    format!("INSERT INTO {} (data) VALUES ('{}')", table, data)
}

pub fn generic_chain_vuln() -> Result<QueryResult, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let processed: String = process_input(&input);
    let sql = transform_data(&processed, "events");
    execute_query("localhost", &sql)
}

// ---------------------------------------------------------------------------
// VULN 16: 5-hop env -> regex construction (ReDoS)
// env::var -> trim -> validate_pattern_length -> build_search_regex -> Regex::new
// ---------------------------------------------------------------------------
fn validate_pattern_length(pattern: &str) -> Result<String, String> {
    if pattern.len() > 1024 {
        return Err("pattern too long".into());
    }
    Ok(pattern.to_string())
}

fn build_search_regex(user_pattern: &str) -> String {
    format!("(?i).*{}.*", user_pattern)
}

pub fn regex_injection_vuln() -> Result<String, String> {
    let user_pattern = env::var("SEARCH_REGEX").map_err(|e| e.to_string())?;
    let validated = validate_pattern_length(user_pattern.trim())?;
    let regex_str = build_search_regex(&validated);
    // Write the compiled regex to a config file (path traversal via pattern)
    let config_path = format!("/etc/proxy/regex/{}.pattern", validated);
    fs::write(&config_path, &regex_str).map_err(|e| e.to_string())?;
    // Test the regex with grep
    let _grep = Command::new("grep")
        .arg("-rP")
        .arg(&regex_str)
        .arg("/var/log/proxy/")
        .output()
        .map_err(|e| e.to_string())?;
    Ok(format!("Compiled regex: {}", regex_str))
}

// ---------------------------------------------------------------------------
// VULN 17: 5-hop env -> deserialization chain
// env::var -> decode_base64 -> parse_json_header -> extract_payload -> serde_json::from_str
// ---------------------------------------------------------------------------
fn decode_base64(encoded: &str) -> Result<String, String> {
    // Simulated base64 decode
    Ok(encoded.to_string())
}

fn parse_json_header(raw: &str) -> Result<String, String> {
    if raw.starts_with('{') {
        Ok(raw.to_string())
    } else {
        Err("invalid JSON header".into())
    }
}

fn extract_payload(json_str: &str) -> String {
    json_str.to_string()
}

pub fn deserialization_chain_vuln() -> Result<HashMap<String, String>, String> {
    let encoded = env::var("ENCODED_CONFIG").map_err(|e| e.to_string())?;
    let decoded = decode_base64(&encoded)?;
    let header = parse_json_header(&decoded)?;
    let payload = extract_payload(&header);
    // Write decoded config to disk before parsing
    fs::write("/tmp/decoded_config.json", &payload).map_err(|e| e.to_string())?;
    // Validate config with external tool
    let _check = Command::new("jq")
        .arg(".")
        .arg("/tmp/decoded_config.json")
        .output()
        .map_err(|e| e.to_string())?;
    let config: HashMap<String, String> = serde_json_from_str(&payload)?;
    Ok(config)
}

fn serde_json_from_str(s: &str) -> Result<HashMap<String, String>, String> {
    Ok(HashMap::new())
}

// ---------------------------------------------------------------------------
// VULN 18: 5-hop env -> Command + fs::write combined
// env::var -> build_script -> write_script -> execute_script -> Command
// ---------------------------------------------------------------------------
fn build_script(name: &str) -> String {
    format!("#!/bin/bash\necho 'Running {}'\n", name)
}

fn write_script(path: &str, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|e| e.to_string())
}

fn execute_script(path: &str) -> Result<String, String> {
    let output = Command::new("bash")
        .arg(path)
        .output()
        .map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn script_execution_vuln() -> Result<String, String> {
    let script_name = env::var("SCRIPT_NAME").map_err(|e| e.to_string())?;
    let content = build_script(&script_name);
    let path = format!("/tmp/scripts/{}.sh", script_name);
    write_script(&path, &content)?;
    execute_script(&path)
}

// ---------------------------------------------------------------------------
// VULN 19: 5-hop stdin -> file read + SQL combined
// stdin -> read_line -> build_data_path -> fs::read_to_string -> format!(SQL) -> execute_query
// ---------------------------------------------------------------------------
fn build_data_path(name: &str) -> String {
    format!("/var/data/{}.csv", name)
}

fn load_data_file(path: &str) -> Result<String, String> {
    fs::read_to_string(path).map_err(|e| e.to_string())
}

fn build_import_sql(data: &str, table: &str) -> String {
    format!("INSERT INTO {} (raw_data) VALUES ('{}')", table, data)
}

pub fn data_import_vuln() -> Result<QueryResult, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let path = build_data_path(input.trim());
    let data = load_data_file(&path)?;
    let sql = build_import_sql(&data, "imports");
    execute_query("localhost", &sql)
}

// ---------------------------------------------------------------------------
// VULN 20: 4-hop env -> file copy via fs::read + fs::write
// env::var -> build_src_path -> fs::read -> fs::write
// ---------------------------------------------------------------------------
pub fn file_copy_vuln() -> Result<(), String> {
    let source = env::var("COPY_SOURCE").map_err(|e| e.to_string())?;
    let dest = env::var("COPY_DEST").map_err(|e| e.to_string())?;
    let src_path = format!("/var/data/{}", source);
    let data = fs::read(&src_path).map_err(|e| e.to_string())?;
    let dst_path = format!("/var/output/{}", dest);
    fs::write(&dst_path, &data).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// VULN 21: 5-hop stdin -> Command with multiple args
// stdin -> read_line -> parse_args -> build_rsync_cmd -> Command::new + arg chain
// ---------------------------------------------------------------------------
fn parse_rsync_args(input: &str) -> (String, String) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    let src = parts.first().unwrap_or(&"/tmp").to_string();
    let dst = parts.get(1).unwrap_or(&"/backup").to_string();
    (src, dst)
}

pub fn rsync_vuln() -> Result<String, String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input).map_err(|e| e.to_string())?;
    let (src, dst) = parse_rsync_args(input.trim());
    let output = Command::new("rsync")
        .arg("-avz")
        .arg(&src)
        .arg(&dst)
        .output()
        .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let log = format!("/tmp/rsync_{}.log", dst.replace('/', "_"));
    fs::write(&log, &stdout).map_err(|e| e.to_string())?;
    Ok(stdout)
}

// ---------------------------------------------------------------------------
// Helper: simulated SQL execution
// ---------------------------------------------------------------------------
fn execute_query(db_url: &str, sql: &str) -> Result<QueryResult, String> {
    let _ = db_url;
    let _ = sql;
    Ok(QueryResult {
        rows: vec![HashMap::new()],
        affected: 0,
    })
}

// Lifetime annotation
fn borrow_flow<'a>(input: &'a str) -> &'a str {
    input  // lifetime ensures same reference
}

// Async function
async fn async_fetch(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    Ok(url.to_string())
}
