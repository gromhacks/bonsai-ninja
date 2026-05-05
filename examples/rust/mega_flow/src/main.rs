use std::io::{self, BufRead};

mod pipeline;
mod storage;
mod executor;

// mega_flow Rust entry — reads one tainted stdin line, then dispatches
// through a pipeline that exercises every idiomatic Rust flow construct
// (enums + pattern matching, traits, closures, iterators, Option/Result,
// `?` operator, if-let, while-let, generics, lifetimes).

#[derive(Clone, Debug)]
pub enum Kind { Run, Eval }

type CmdText = String;

#[derive(Clone, Debug)]
pub struct Envelope {
    pub kind: Kind,
    pub cmd: String,
    pub user: String,
    pub length: usize,
    pub extras: Vec<String>,
}

fn main() {
    let out = handle_request();
    println!("{}", out);
}

fn handle_request() -> String {
    // SOURCE — read one tainted line from stdin.
    let stdin = io::stdin();
    let mut raw: CmdText = String::new();
    let _ = stdin.lock().read_line(&mut raw);
    let user = std::env::var("USER").unwrap_or_else(|_| "anon".to_string());

    let envelope = Envelope {
        kind: Kind::Run,
        cmd: format!("{}", raw.trim()),
        length: raw.trim().len(),
        extras: vec![raw.clone()],
        user,
    };

    pipeline::orchestrate(envelope)
}
