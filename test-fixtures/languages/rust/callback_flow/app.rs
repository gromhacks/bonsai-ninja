use std::env;
use std::process::Command;

fn executor(cmd: &str) {
    let _ = Command::new("sh").arg("-c").arg(cmd).output();
}

fn run_cb(cb: fn(&str), value: &str) {
    cb(value);
}

pub fn pass_to_callback() {
    let t = env::var("CMD").unwrap_or_default();
    run_cb(executor, &t);
}
