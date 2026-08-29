//! Rust web extractors are normally destructured in the handler signature.
//! The adapter must expose the inner binding plus its tuple-struct wrapper
//! type so existing rule-data parameter constraints remain usable.

use std::path::{Path, PathBuf};

fn rules_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("security-patterns")
}

#[test]
fn axum_destructured_extractors_match_their_typed_parameter_rules() {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(
        "handler.rs",
        r#"use axum::extract::{Form, Path, Query};
use axum::Json;
use axum_extra::TypedHeader;

async fn handler(
    Query(query): Query<String>,
    Json(json): Json<String>,
    Path(path): Path<String>,
    Form(form): Form<String>,
    TypedHeader(header): TypedHeader<String>,
) {
    consume(query, json, path, form, header);
}

fn consume(_: String, _: String, _: String, _: String, _: String) {}
"#,
    );
    let pack = bonsai_security::load_rulepack(&rules_root()).expect("load rulepack");
    let matches =
        bonsai_security::source_inventory(&ws, &pack, bonsai_security::SecurityInventoryOptions::default())
            .expect("source inventory");
    let ids = matches
        .iter()
        .map(|source| source.rule_id.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    for expected in [
        "rust.axum.query",
        "rust.axum.json",
        "rust.axum.path",
        "rust.axum.form",
        "rust.axum.typed_header",
    ] {
        assert!(
            ids.contains(expected),
            "destructured extractor must match {expected}; matched {ids:?}; inventory={matches:#?}"
        );
    }
}
