use std::env;
use std::process::Command;

pub fn unsanitized() {
    let t = env::var("CMD").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(t).output();
}

pub fn sanitized() {
    let t = env::var("CMD").unwrap_or_default();
    // shell-escape crate
    let safe = shell_escape::escape(t.into());
    let _ = Command::new("sh").arg("-c").arg(safe.as_ref()).output();
}
