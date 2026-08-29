// Cross-file argument flow audit fixture (Rust).
use std::env;

mod pipeline;

pub fn handler() {
    // POSITIVE
    let user = env::var("CMD").unwrap_or_default();
    pipeline::run_pipeline(&user);
}

pub fn handler_split() {
    // POSITIVE
    let user = env::var("FROM").unwrap_or_default();
    let flag = env::var("FLAG").unwrap_or_default();
    pipeline::run_pipeline(&format!("{}:{}", user, flag));
}
