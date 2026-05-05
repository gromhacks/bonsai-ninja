use std::env;
use std::process::Command;

const CONST_OK: &str = "ls /tmp";

pub fn decoy() {
    let _unused = env::var("IGNORED").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(CONST_OK).output();
}

pub fn unrelated_chain() -> String {
    "hello".to_uppercase()
}
