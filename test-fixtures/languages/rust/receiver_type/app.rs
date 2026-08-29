// Receiver-type audit fixture (Rust).
// Rust's std::process::Command has builder-style methods; rules
// match by `name: arg` / `name: output` etc. — receiver-type-aware
// when the adapter tracks Command's type.
use std::env;
use std::process::Command;

pub fn handle() {
    // POSITIVE
    let tainted = env::var("CMD").unwrap_or_default();
    let _ = Command::new("sh").arg("-c").arg(&tainted).output();
}
