use std::process::Command;

pub fn execute(cmd: &str) {
    // POSITIVE (terminal cross-file sink)
    let _ = Command::new("sh").arg("-c").arg(cmd).output();
}
