use axum::extract::Query;
use serde::Deserialize;

mod application;
mod domain;
mod runtime;

// language_gauntlet Rust entry — reads a typed Axum query, then dispatches
// through a pipeline that exercises every idiomatic Rust flow construct
// (enums + pattern matching, traits, closures, iterators, Option/Result,
// `?` operator, if-let, while-let, generics, lifetimes).

#[derive(Clone, Debug)]
pub enum Kind {
    Run,
    Eval,
}

type CmdText = String;

#[derive(Clone, Debug, Deserialize)]
struct RequestQuery {
    cmd: CmdText,
}

#[derive(Clone, Debug)]
pub struct Envelope {
    pub kind: Kind,
    pub cmd: String,
    pub user: String,
    pub length: usize,
    pub extras: Vec<String>,
}

fn main() {
    let out = handle_request(Query(RequestQuery {
        cmd: String::new(),
    }));
    println!("{}", out);
}

fn handle_request(Query(query): Query<RequestQuery>) -> String {
    // SOURCE — Axum destructures attacker-controlled query parameters.
    let raw = query.cmd;
    let user = "remote".to_string();

    let envelope = Envelope {
        kind: Kind::Run,
        cmd: format!("{}", raw.trim()),
        length: raw.trim().len(),
        extras: vec![raw.clone()],
        user,
    };

    application::pipeline::orchestrate(envelope)
}
