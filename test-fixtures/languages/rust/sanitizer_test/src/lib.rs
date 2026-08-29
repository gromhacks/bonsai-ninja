// Rust sanitizer-fixture — parallel handlers per sink family. Safe
// variants keep the tainted value flowing all the way to the sink
// (with the sanitizer wrapping it in between) so the engine attaches
// sanitizer evidence to the finding.
use std::process::Command;

// --- Command injection ---------------------------------------------------

pub fn cmd_raw(cmd: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh").arg("-c").arg(format!("ping {cmd}")).output()
}

pub fn cmd_safe(cmd: &str) -> std::io::Result<std::process::Output> {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let safe = utf8_percent_encode(cmd, NON_ALPHANUMERIC).to_string();
    Command::new("sh").arg("-c").arg(format!("ping {safe}")).output()
}

// --- Open redirect -------------------------------------------------------

pub fn redirect_raw(target: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh").arg("-c").arg(format!("curl -L {target}")).output()
}

pub fn redirect_safe(target: &str) -> std::io::Result<std::process::Output> {
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    let safe = utf8_percent_encode(target, NON_ALPHANUMERIC).to_string();
    Command::new("sh").arg("-c").arg(format!("curl -L {safe}")).output()
}

// --- XSS ------------------------------------------------------------------

pub fn xss_raw(name: &str) -> String {
    format!("<p>Hello, {}</p>", name)
}

pub fn xss_safe(name: &str) -> String {
    let safe = ammonia::clean(name);
    format!("<p>Hello, {}</p>", safe)
}

// --- Timing attack --------------------------------------------------------

pub fn token_eq_raw(given: &[u8], expected: &[u8]) -> bool {
    given == expected
}

pub fn token_eq_safe(given: &[u8], expected: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(given, expected)
}
