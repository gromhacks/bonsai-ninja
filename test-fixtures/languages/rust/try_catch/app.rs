// Rust uses Result; the analog is `match Result`.
use std::env;
use std::process::Command;

pub fn tainted_through_try() {
    let t = env::var("CMD").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(t).output();
}
