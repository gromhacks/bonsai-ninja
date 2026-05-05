use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    let git = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "nogit".to_string());

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .is_some_and(|out| !out.stdout.is_empty());

    println!(
        "cargo:rustc-env=BONSAI_BUILD_FINGERPRINT={}-{}",
        git,
        if dirty { "dirty" } else { "clean" }
    );
}
