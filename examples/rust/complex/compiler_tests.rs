//! Compiler architecture test cases for the tree-sitter-sast flow engine.
//!
//! Each section tests a specific capability with both positive (flow expected)
//! and negative (no flow expected) scenarios.

use std::env;
use std::io::{self, BufRead};
use std::process::Command;

// ---------------------------------------------------------------------------
// 1. BRANCH-AWARE KILL ANALYSIS
// ---------------------------------------------------------------------------

/// [NO FLOW EXPECTED] Both branches sanitize
fn branch_kill_both_paths(user_input: &str) {
    let cmd = if user_input.len() > 100 {
        "default_command".to_string()
    } else {
        "safe_fallback".to_string()
    };
    Command::new(&cmd).status().ok(); // safe
}

/// [FLOW EXPECTED] Only one branch kills taint
fn branch_kill_one_path(user_input: &str) {
    let mut cmd = user_input.to_string();
    if cmd.len() > 100 {
        cmd = "truncated".to_string();
    }
    // else: cmd still holds user_input
    Command::new(&cmd).status().ok(); // tainted
}

/// [FLOW EXPECTED] Match without exhaustive kill
fn branch_kill_match(user_input: &str) {
    let mut query = user_input.to_string();
    match user_input.chars().next() {
        Some('a') => query = "SELECT * FROM a".to_string(),
        Some('b') => query = "SELECT * FROM b".to_string(),
        _ => {} // query keeps user_input
    }
    Command::new("sqlite3").arg(&query).status().ok();
}


// ---------------------------------------------------------------------------
// 2. INTERPROCEDURAL KILL (2+ levels deep)
// ---------------------------------------------------------------------------

fn sanitize(value: &str) -> String {
    value.replace("'", "").replace(";", "").replace("--", "")
}

fn wrap_sanitize(value: &str) -> String {
    sanitize(value)
}

/// [NO FLOW EXPECTED] Sanitizer applied
fn interprocedural_kill_direct(user_input: &str) {
    let clean = sanitize(user_input);
    let query = format!("SELECT * FROM t WHERE x = '{}'", clean);
    Command::new("sqlite3").arg(&query).status().ok();
}

/// [NO FLOW EXPECTED] Sanitizer 2 levels deep
fn interprocedural_kill_two_levels(user_input: &str) {
    let clean = wrap_sanitize(user_input);
    let query = format!("SELECT * FROM t WHERE x = '{}'", clean);
    Command::new("sqlite3").arg(&query).status().ok();
}

/// [FLOW EXPECTED] No sanitizer
fn interprocedural_no_kill(user_input: &str) {
    let query = format!("SELECT * FROM t WHERE x = '{}'", user_input);
    Command::new("sqlite3").arg(&query).status().ok();
}


// ---------------------------------------------------------------------------
// 3. FIELD-SENSITIVE TRACKING
// ---------------------------------------------------------------------------

struct Config {
    command: String,
    label: String,
}

/// [FLOW EXPECTED] Tainted field flows to sink
fn field_sensitive_tainted(user_input: &str) {
    let cfg = Config {
        command: user_input.to_string(),
        label: "safe".to_string(),
    };
    Command::new(&cfg.command).status().ok();
}

/// [NO FLOW EXPECTED] Only safe field used
fn field_sensitive_safe(user_input: &str) {
    let cfg = Config {
        command: user_input.to_string(),
        label: "safe".to_string(),
    };
    Command::new(&cfg.label).status().ok();
}

/// [NO FLOW EXPECTED] Tainted field overwritten
fn field_sensitive_overwrite(user_input: &str) {
    let mut cfg = Config {
        command: user_input.to_string(),
        label: String::new(),
    };
    cfg.command = "hardcoded_safe".to_string();
    Command::new(&cfg.command).status().ok();
}


// ---------------------------------------------------------------------------
// 4. TRAIT DISPATCH (Rust-specific polymorphism)
// ---------------------------------------------------------------------------

trait Executor {
    fn execute(&self, cmd: &str);
}

struct SafeExecutor;
impl Executor for SafeExecutor {
    fn execute(&self, cmd: &str) {
        println!("Would execute: {}", cmd); // safe
    }
}

struct UnsafeExecutor;
impl Executor for UnsafeExecutor {
    fn execute(&self, cmd: &str) {
        Command::new(cmd).status().ok(); // dangerous
    }
}

/// [FLOW EXPECTED]
fn type_tracked_unsafe(user_input: &str) {
    let executor: Box<dyn Executor> = Box::new(UnsafeExecutor);
    executor.execute(user_input);
}

/// [NO FLOW EXPECTED]
fn type_tracked_safe(user_input: &str) {
    let executor: Box<dyn Executor> = Box::new(SafeExecutor);
    executor.execute(user_input);
}


// ---------------------------------------------------------------------------
// 5. IMPLICIT RETURN (Rust-specific)
// ---------------------------------------------------------------------------

fn process_input(user_input: &str) -> String {
    format!("cmd: {}", user_input) // implicit return
}

/// [FLOW EXPECTED] Implicit return carries taint
fn implicit_return_sink(user_input: &str) {
    let cmd = process_input(user_input);
    Command::new(&cmd).status().ok();
}


// ---------------------------------------------------------------------------
// 6. RESULT/OPTION CHAIN
// ---------------------------------------------------------------------------

fn parse_command(input: &str) -> Result<String, String> {
    Ok(input.to_string())
}

/// [FLOW EXPECTED] Taint flows through Result chain
fn result_chain_taint(user_input: &str) {
    let cmd = parse_command(user_input)
        .map(|c| c.trim().to_string())
        .unwrap_or_default();
    Command::new(&cmd).status().ok();
}


// ---------------------------------------------------------------------------
// 7. CLOSURE TAINT
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Closure captures tainted variable
fn closure_taint(user_input: &str) {
    let process = |cmd: &str| {
        Command::new(cmd).status().ok();
    };
    process(user_input);
}


// ---------------------------------------------------------------------------
// 8. PARAMETER SOURCE SYNTHESIS
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] External entry point
pub fn handle_webhook(payload: &str, signature: &str) {
    Command::new("process").arg(payload).status().ok();
}


// ---------------------------------------------------------------------------
// 9. STRUCT METHOD CROSS-CALL TAINT
// ---------------------------------------------------------------------------

struct Pipeline {
    data: String,
}

impl Pipeline {
    fn new() -> Self {
        Pipeline { data: String::new() }
    }

    fn ingest(&mut self, raw: &str) {
        self.data = raw.to_string();
    }

    fn process(&self) {
        Command::new(&self.data).status().ok();
    }
}

/// [FLOW EXPECTED] Taint flows through struct field across methods
fn cross_method_field_taint(user_input: &str) {
    let mut p = Pipeline::new();
    p.ingest(user_input);
    p.process();
}


// ---------------------------------------------------------------------------
// 10. TUPLE DESTRUCTURING PRECISION
// ---------------------------------------------------------------------------

fn fetch_data(source: &str) -> (String, String) {
    (source.to_string(), "no_error".to_string())
}

/// [FLOW EXPECTED] Position 0 carries taint
fn tuple_tainted_position(user_input: &str) {
    let (data, _err) = fetch_data(user_input);
    Command::new(&data).status().ok();
}

/// [NO FLOW EXPECTED] Position 1 is literal
fn tuple_safe_position(user_input: &str) {
    let (_data, err) = fetch_data(user_input);
    Command::new(&err).status().ok(); // safe: err is "no_error"
}


// ---------------------------------------------------------------------------
// 11. IF-LET PATTERN TAINT
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Taint flows through if-let binding
fn if_let_taint(user_input: &str) {
    let maybe_cmd: Option<&str> = Some(user_input);
    if let Some(cmd) = maybe_cmd {
        Command::new(cmd).status().ok();
    }
}


// ---------------------------------------------------------------------------
// 12. ITERATOR CHAIN TAINT
// ---------------------------------------------------------------------------

/// [FLOW EXPECTED] Taint flows through iterator chain
fn iterator_chain_taint(user_input: &str) {
    let parts: Vec<&str> = user_input.split(',').collect();
    let joined = parts.join(" ");
    Command::new(&joined).status().ok();
}


fn main() {
    let user_input = env::args().nth(1).unwrap_or_default();
    branch_kill_one_path(&user_input);
}
