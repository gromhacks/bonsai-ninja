use std::env;
use std::process::Command;

pub fn taint_one_leg(cond: bool) {
    let x = if cond { env::var("CMD").unwrap_or_default() } else { "safe-static".to_string() };
    let _ = Command::new("sh").arg("-c").arg(x).output();
}

pub fn taint_overwritten(cond: bool) {
    let mut x = env::var("CMD").unwrap_or_default();
    x = if cond { "clean-then".to_string() } else { "clean-else".to_string() };
    let _ = Command::new("sh").arg("-c").arg(x).output();
}
