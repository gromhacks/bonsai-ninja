use std::process::Command;

pub fn run_in_other_file(cmd: &str) {
    // POSITIVE (cross-file)
    let _ = Command::new("sh").arg("-c").arg(cmd).output();
}
