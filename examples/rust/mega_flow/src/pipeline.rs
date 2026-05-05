use crate::storage as store;
use crate::{Envelope, Kind};

// Pipeline — exercises Rust's idiomatic flow constructs: iterators,
// closures, match expressions, Result / Option, `?`, generics, traits,
// if-let, while-let.

// Closure factory — returns a boxed Fn reducer that joins tokens.
fn make_joiner(sep: &'static str) -> Box<dyn Fn(String, &str) -> String> {
    Box::new(move |acc: String, tok: &str| -> String {
        if acc.is_empty() { tok.to_string() } else { format!("{}{}{}", acc, sep, tok) }
    })
}

pub fn orchestrate(envelope: Envelope) -> String {
    let cmd = envelope.cmd.clone();
    let user = envelope.user.clone();

    // Iterator chain — map / filter / fold with a closure.
    let joiner = make_joiner(" ");
    let joined: String = cmd
        .split_whitespace()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .fold(String::new(), |acc, tok| joiner(acc, tok));

    // Match expression — every arm preserves taint.
    let routed: String = match envelope.kind {
        Kind::Run => format!("{}", joined),
        Kind::Eval => joined.trim().to_string(),
    };
    let routed = if let Some(value) = Some(routed) {
        value
    } else {
        String::new()
    };
    let mut pending = vec![routed.clone()];
    while let Some(value) = pending.pop() {
        if value.is_empty() {
            break;
        }
    }

    // Result style — taint survives the branch via closures.
    let valid: Envelope = (|| -> Result<Envelope, &str> {
        if routed.is_empty() { return Err("empty"); }
        Ok(Envelope {
            kind: envelope.kind.clone(),
            cmd: routed.clone(),
            user: user.clone(),
            length: routed.len(),
            extras: envelope.extras.clone(),
        })
    })().unwrap_or_else(|_| Envelope {
        kind: envelope.kind.clone(),
        cmd: routed.clone(),
        user: user.clone(),
        length: routed.len(),
        extras: envelope.extras.clone(),
    });

    store::persist(valid)
}
