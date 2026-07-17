//! Focused regressions for the May 2026 benchmark taint gaps.
//!
//! These tests use the shipped rulepack, not synthetic one-off rules, so
//! they exercise the real source models, sink models, cross-file call
//! resolution, and negative cases that guard against over-taint.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn bin_path() -> Option<PathBuf> {
    if let Some(path) = option_env!("CARGO_BIN_EXE_bonsai-ninja") {
        return Some(PathBuf::from(path));
    }
    let debug = repo_root().join("target/debug/bonsai-ninja");
    if debug.exists() {
        return Some(debug);
    }
    let release = repo_root().join("target/release/bonsai-ninja");
    release.exists().then_some(release)
}

fn rules_dir() -> PathBuf {
    repo_root().join("security-patterns")
}

fn temp_workspace(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir();
    for attempt in 0..100 {
        let path = base.join(format!(
            "bonsai-benchmark-gap-{tag}-{}-{nanos}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create temp workspace {}: {e}", path.display()),
        }
    }
    panic!("could not allocate temp workspace for {tag}");
}

fn write_file(root: &Path, rel: &str, text: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create fixture parent");
    }
    fs::write(path, text).expect("write fixture");
}

fn run_taint_json(ws: &Path, source: &str, sink: &str) -> Vec<Value> {
    run_taint_json_with_flags(ws, source, sink, &[])
}

fn run_taint_json_with_flags(ws: &Path, source: &str, sink: &str, flags: &[&str]) -> Vec<Value> {
    let Some(bin) = bin_path() else {
        return Vec::new();
    };
    let mut cmd = Command::new(bin);
    cmd.args(["--no-cache", "--no-progress", "security"])
        .arg(ws)
        .args([
            "taint-analysis",
            "--rules-dir",
            rules_dir().to_str().expect("rules dir"),
            "--source",
            source,
            "--sink",
            sink,
            "--format",
            "json",
            "--all",
            "--no-color",
        ])
        .args(flags)
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200");
    let out = cmd.output().expect("run bonsai-ninja");

    assert!(
        out.status.success(),
        "taint-analysis failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let value = serde_json::from_slice::<Value>(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid taint JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    value
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| value.as_array().cloned())
        .unwrap_or_else(|| {
            panic!(
                "taint JSON must be a paged envelope or row array\nstdout:\n{}",
                String::from_utf8_lossy(&out.stdout)
            )
        })
}

fn run_sinks_json(ws: &Path, rule_regex: &str) -> Vec<Value> {
    let Some(bin) = bin_path() else {
        return Vec::new();
    };
    let out = Command::new(bin)
        .args(["--no-cache", "--no-progress", "security"])
        .arg(ws)
        .args([
            "sinks",
            "--rules-dir",
            rules_dir().to_str().expect("rules dir"),
            "--rule-regex",
            rule_regex,
            "--format",
            "json",
            "--all",
            "--no-color",
        ])
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .output()
        .expect("run bonsai-ninja sinks");

    assert!(
        out.status.success(),
        "sinks failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let value = serde_json::from_slice::<Value>(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid sinks JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    value
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| panic!("sinks JSON missing rows array: {value:#}"))
}

fn run_sources_json(ws: &Path, rule_regex: &str) -> Vec<Value> {
    let Some(bin) = bin_path() else {
        return Vec::new();
    };
    let out = Command::new(bin)
        .args(["--no-cache", "--no-progress", "security"])
        .arg(ws)
        .args([
            "sources",
            "--rules-dir",
            rules_dir().to_str().expect("rules dir"),
            "--rule-regex",
            rule_regex,
            "--format",
            "json",
            "--all",
            "--no-color",
        ])
        .env("NO_COLOR", "1")
        .env("COLUMNS", "200")
        .output()
        .expect("run bonsai-ninja sources");

    assert!(
        out.status.success(),
        "sources failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let value = serde_json::from_slice::<Value>(&out.stdout).unwrap_or_else(|error| {
        panic!(
            "invalid sources JSON: {error}\nstdout:\n{}",
            String::from_utf8_lossy(&out.stdout)
        )
    });
    value
        .get("rows")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_else(|| panic!("sources JSON missing rows array: {value:#}"))
}

fn assert_has_finding(rows: &[Value], fragments: &[&str]) {
    let text = serde_json::to_string_pretty(rows).expect("serialize rows");
    assert!(!rows.is_empty(), "expected at least one finding:\n{text}");
    for fragment in fragments {
        assert!(
            text.contains(fragment),
            "expected JSON finding to contain `{fragment}`:\n{text}"
        );
    }
}

fn assert_no_finding(rows: &[Value]) {
    let text = serde_json::to_string_pretty(rows).expect("serialize rows");
    assert!(rows.is_empty(), "expected no findings:\n{text}");
}

fn assert_any_finding_has_status(rows: &[Value], status: &str) {
    let text = serde_json::to_string_pretty(rows).expect("serialize rows");
    assert!(
        rows.iter()
            .any(|row| row.get("status").and_then(Value::as_str) == Some(status)),
        "expected at least one finding with status `{status}`:\n{text}"
    );
}

fn assert_no_adjacent_duplicate_taint_path_steps(rows: &[Value]) {
    for row in rows {
        let Some(path) = row.get("taint_path").and_then(Value::as_array) else {
            continue;
        };
        for pair in path.windows(2) {
            let left = &pair[0];
            let right = &pair[1];
            let same_file = left.get("file") == right.get("file");
            let same_line = left.get("line") == right.get("line");
            assert!(
                !(same_file && same_line),
                "adjacent duplicate taint path steps should be normalized:\n{}",
                serde_json::to_string_pretty(row).expect("serialize row")
            );
        }
    }
}

fn assert_has_row(rows: &[Value], fragments: &[&str]) {
    assert_has_finding(rows, fragments);
}

fn assert_rows_do_not_contain(rows: &[Value], fragments: &[&str]) {
    let text = serde_json::to_string_pretty(rows).expect("serialize rows");
    for fragment in fragments {
        assert!(
            !text.contains(fragment),
            "expected JSON rows not to contain `{fragment}`:\n{text}"
        );
    }
}

#[test]
fn go_cross_file_nethttp_query_reaches_service_path_sink() {
    let ws = temp_workspace("go-cross-file-path");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/api/files.go",
        r#"package api

import (
    "net/http"
    "example.com/app/internal/service"
)

func Files(w http.ResponseWriter, r *http.Request) {
    name := r.URL.Query().Get("name")
    service.Store("/srv/uploads", name)
}
"#,
    );
    write_file(
        &ws,
        "internal/service/store.go",
        r#"package service

import "path/filepath"

func Store(base string, name string) string {
    return filepath.Join(base, name)
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.path\\.filepath_join$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.nethttp.query_value_get",
            "go.path.filepath_join",
            "internal/api/files.go",
            "internal/service/store.go",
            "Files",
            "Store",
        ],
    );
}

#[test]
fn go_cross_file_nethttp_query_reaches_repo_sql_querycontext() {
    let ws = temp_workspace("go-cross-file-sqli-querycontext");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/handlers/users.go",
        r#"package handlers

import (
    "database/sql"
    "net/http"

    "example.com/app/internal/repo"
)

func Users(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    name := r.URL.Query().Get("name")
    repo.FindUsers(r.Context(), db, name)
}
"#,
    );
    write_file(
        &ws,
        "internal/repo/users.go",
        r#"package repo

import (
    "context"
    "database/sql"
)

func FindUsers(ctx context.Context, db *sql.DB, name string) (*sql.Rows, error) {
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    return db.QueryContext(ctx, query)
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.sqli\\.db_query_context$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.nethttp.query_value_get",
            "go.sqli.db_query_context",
            "internal/handlers/users.go",
            "internal/repo/users.go",
            "Users",
            "FindUsers",
        ],
    );

    let clean = temp_workspace("go-cross-file-sqli-querycontext-clean");
    write_file(&clean, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &clean,
        "internal/handlers/users.go",
        r#"package handlers

import (
    "database/sql"
    "net/http"

    "example.com/app/internal/repo"
)

func Users(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    _ = r.URL.Query().Get("name")
    repo.FindUsers(r.Context(), db, "alice")
}
"#,
    );
    write_file(
        &clean,
        "internal/repo/users.go",
        r#"package repo

import (
    "context"
    "database/sql"
)

func FindUsers(ctx context.Context, db *sql.DB, name string) (*sql.Rows, error) {
    query := "SELECT * FROM users WHERE name = '" + name + "'"
    return db.QueryContext(ctx, query)
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.sqli\\.db_query_context$",
    );
    assert_no_finding(&rows);
}

#[test]
fn go_ssrf_newrequest_requires_tainted_url_not_method() {
    let ws = temp_workspace("go-ssrf-newrequest-url");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/api/preview.go",
        r#"package api

import "net/http"

func Preview(w http.ResponseWriter, r *http.Request) {
    target := r.URL.Query().Get("url")
    _, _ = http.NewRequest("GET", target, nil)
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.ssrf\\.http_newrequest$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.nethttp.query_value_get",
            "go.ssrf.http_newrequest",
            "preview.go",
            "Preview",
        ],
    );

    let clean = temp_workspace("go-ssrf-newrequest-method");
    write_file(&clean, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &clean,
        "internal/api/preview.go",
        r#"package api

import "net/http"

func Preview(w http.ResponseWriter, r *http.Request) {
    method := r.URL.Query().Get("method")
    _, _ = http.NewRequest(method, "https://example.test/health", nil)
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.ssrf\\.http_newrequest$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_commonjs_route_source_reaches_service_sink() {
    let ws = temp_workspace("js-cjs-cross-file-path");
    write_file(
        &ws,
        "src/routes/upload.js",
        r#"const express = require("express");
const store = require("../services/store");

function upload(req) {
  const name = req.query.name;
  return store.save(name);
}

module.exports = { upload };
"#,
    );
    write_file(
        &ws,
        "src/services/store.js",
        r#"const path = require("path");

function save(name) {
  return path.join("/srv/uploads", name);
}

module.exports = { save };
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.upload\\.path_join_original_filename$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_query",
            "javascript.upload.path_join_original_filename",
            "src/routes/upload.js",
            "src/services/store.js",
            "upload",
            "save",
        ],
    );
}

#[test]
fn javascript_route_query_reaches_cross_file_html_return_sink() {
    let ws = temp_workspace("js-cross-file-html-return");
    write_file(
        &ws,
        "src/server.js",
        r#"const express = require("express");
const { renderResults } = require("./render");

function search(req, res) {
  const q = req.query.q;
  return res.end(renderResults(q));
}

module.exports = { search };
"#,
    );
    write_file(
        &ws,
        "src/render.js",
        r#"function renderResults(q) {
  return `<html><body>${q}</body></html>`;
}

module.exports = { renderResults };
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.html_return$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_query",
            "javascript.xss.html_return",
            "src/server.js",
            "src/render.js",
            "search",
            "renderResults",
            "req.query",
        ],
    );

    let clean = temp_workspace("js-cross-file-html-return-clean");
    write_file(
        &clean,
        "src/server.js",
        r#"const express = require("express");
const { renderResults } = require("./render");

function search(req, res) {
  const unused = req.query.q;
  return res.end(renderResults("ok"));
}

module.exports = { search };
"#,
    );
    write_file(
        &clean,
        "src/render.js",
        r#"function renderResults(q) {
  return `<html><body>${q}</body></html>`;
}

module.exports = { renderResults };
"#,
    );

    let rows = run_taint_json(
        &clean,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.html_return$",
    );
    assert_no_finding(&rows);
}

#[test]
fn typescript_framework_source_requires_matching_package_evidence() {
    let ws = temp_workspace("ts-framework-source-package-gate");
    write_file(
        &ws,
        "fastify.ts",
        r#"import fastify from "fastify";

function route(request: any): unknown {
  return request.headers;
}
"#,
    );
    write_file(
        &ws,
        "hono.ts",
        r#"import { Hono } from "hono";

function route(request: any): unknown {
  return request.headers;
}
"#,
    );

    let rows = run_sources_json(&ws, "^typescript\\.source\\.fastify_request_headers$");
    assert_has_row(
        &rows,
        &["typescript.source.fastify_request_headers", "fastify.ts"],
    );
    assert_rows_do_not_contain(&rows, &["hono.ts"]);
}

#[test]
fn typescript_package_gated_xss_sinks_require_matching_package_evidence() {
    let ws = temp_workspace("ts-xss-sink-package-gate");
    write_file(
        &ws,
        "serialize-js.ts",
        r#"import serialize from "serialize-javascript";

function embed(value: unknown): string {
  return serialize(value, { unsafe: true });
}
"#,
    );
    write_file(
        &ws,
        "local-cookie.ts",
        r#"import { serialize } from "./utils/cookie";

function generateCookie(name: string, value: string): string {
  return serialize(name, value);
}
"#,
    );
    write_file(
        &ws,
        "koa.ts",
        r#"import Koa from "koa";

function route(ctx: any, html: string): void {
  ctx.body = "<h1>" + html + "</h1>";
}
"#,
    );
    write_file(
        &ws,
        "hono.ts",
        r#"import { Hono } from "hono";

function createRequest(requestInit: RequestInit, body: string): void {
  requestInit.body = body;
}
"#,
    );

    let serialize_rows = run_sinks_json(&ws, "^typescript\\.xss\\.serialize_javascript_unsafe_embed$");
    assert_has_row(
        &serialize_rows,
        &[
            "typescript.xss.serialize_javascript_unsafe_embed",
            "serialize-js.ts",
        ],
    );
    assert_rows_do_not_contain(&serialize_rows, &["local-cookie.ts"]);

    let body_rows = run_sinks_json(&ws, "^typescript\\.xss\\.koa_ctx_body_html$");
    assert_has_row(&body_rows, &["typescript.xss.koa_ctx_body_html", "koa.ts"]);
    assert_rows_do_not_contain(&body_rows, &["hono.ts"]);
}

#[test]
fn lua_luasql_execute_requires_matching_package_evidence() {
    let ws = temp_workspace("lua-luasql-package-gate");
    write_file(
        &ws,
        "luasql.lua",
        r#"local _luasql = require("luasql")

function lookup(conn, name)
  return conn:execute("SELECT id FROM users WHERE name = '" .. name .. "'")
end
"#,
    );
    write_file(
        &ws,
        "generic.lua",
        r#"local Executor = {}

function Executor.execute(cmd)
  os.execute(cmd)
end

function run(cmd)
  return Executor.execute(cmd)
end
"#,
    );

    let rows = run_sinks_json(&ws, "^lua\\.sqli\\.luasql_execute$");
    assert_has_row(&rows, &["lua.sqli.luasql_execute", "luasql.lua"]);
    assert_rows_do_not_contain(&rows, &["generic.lua", "Executor.execute"]);
}

#[test]
fn ruby_actionview_template_sink_accepts_manifest_package_evidence() {
    let ws = temp_workspace("ruby-actionview-manifest-gate");
    write_file(&ws, "Gemfile", "gem \"actionview\"\n");
    write_file(
        &ws,
        "show.html.erb",
        r#"<div>
  <%= raw @comment %>
</div>
"#,
    );

    let rows = run_sinks_json(&ws, "^ruby\\.xss\\.raw$");
    assert_has_row(&rows, &["ruby.xss.raw", "show.html.erb"]);

    let no_manifest = temp_workspace("ruby-actionview-no-manifest-gate");
    write_file(
        &no_manifest,
        "show.html.erb",
        r#"<div>
  <%= raw @comment %>
</div>
"#,
    );
    let no_manifest_rows = run_sinks_json(&no_manifest, "^ruby\\.xss\\.raw$");
    assert_no_finding(&no_manifest_rows);
}

#[test]
fn javascript_browser_source_crosses_commonjs_default_export_to_dom_sink() {
    let ws = temp_workspace("js-cjs-default-domxss");
    write_file(
        &ws,
        "src/controller.js",
        r#"const render = require("./view");

function handle(el) {
  const html = window.location.hash;
  return render(el, html);
}

module.exports = { handle };
"#,
    );
    write_file(
        &ws,
        "src/view.js",
        r#"module.exports = function render(el, html) {
  el.innerHTML = html;
};
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.window_location_hash$",
        "^javascript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.window_location_hash",
            "javascript.xss.innerhtml",
            "src/controller.js",
            "src/view.js",
            "handle",
            "default",
            "window.location.hash",
            "el.innerHTML",
        ],
    );
    assert_no_adjacent_duplicate_taint_path_steps(&rows);
}

#[test]
fn javascript_proto_pollution_unguarded_recursive_merge_still_reports() {
    let ws = temp_workspace("js-proto-unguarded-merge");
    write_file(&ws, "package.json", r#"{"dependencies":{"express":"latest"}}"#);
    write_file(
        &ws,
        "app.js",
        r#"const express = require("express");

function merge(target, source) {
  for (const key in source) {
    target[key] = source[key];
  }
  return target;
}

function handler(req) {
  return merge({}, req.body);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_body$",
        "^javascript\\.proto_pollution\\.recursive_merge$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_body",
            "javascript.proto_pollution.recursive_merge",
            "target.key",
        ],
    );
}

#[test]
fn javascript_proto_pollution_denylist_guard_blocks_recursive_merge_write() {
    let ws = temp_workspace("js-proto-guarded-merge");
    write_file(&ws, "package.json", r#"{"dependencies":{"express":"latest"}}"#);
    write_file(
        &ws,
        "app.js",
        r#"const express = require("express");

function merge(target, source) {
  for (const key in source) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    target[key] = source[key];
  }
  return target;
}

function handler(req) {
  return merge({}, req.body);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_body$",
        "^javascript\\.proto_pollution\\.recursive_merge$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_graphql_args_arbitrary_field_reaches_cross_file_sql_sink() {
    let ws = temp_workspace("js-graphql-q");
    write_file(
        &ws,
        "src/schema.js",
        r#"const { createYoga } = require("graphql-yoga");
const { search } = require("./products");

function resolver(parent, args, user) {
  createYoga;
  const ignored = user.id;
  return search(args.q);
}

module.exports = { resolver };
"#,
    );
    write_file(
        &ws,
        "src/products.js",
        r#"const mysql = require("mysql");

function search(term) {
  const conn = mysql.createConnection({});
  return conn.query("SELECT * FROM products WHERE name = " + term);
}

module.exports = { search };
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.graphql_args_field$",
        "^javascript\\.sqli\\.method_query_concat$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.graphql_args_field",
            "javascript.sqli.method_query_concat",
            "src/schema.js",
            "src/products.js",
            "resolver",
            "search",
            "args.q",
        ],
    );
}

#[test]
fn javascript_graphql_rule_does_not_taint_sibling_user_field() {
    let ws = temp_workspace("js-graphql-no-user-field");
    write_file(
        &ws,
        "src/schema.js",
        r#"const { graphql } = require("graphql");
const { search } = require("./products");

function resolver(parent, args, user) {
  graphql;
  const q = user.id;
  return search(q);
}

module.exports = { resolver };
"#,
    );
    write_file(
        &ws,
        "src/products.js",
        r#"const mysql = require("mysql");

function search(term) {
  const conn = mysql.createConnection({});
  return conn.query("SELECT * FROM products WHERE id = " + term);
}

module.exports = { search };
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.graphql_args_field$",
        "^javascript\\.sqli\\.method_query_concat$",
    );
    assert_no_finding(&rows);
}

#[test]
fn typescript_graphql_args_arbitrary_field_reaches_cross_file_sql_sink() {
    let ws = temp_workspace("ts-graphql-q");
    write_file(
        &ws,
        "src/yoga.ts",
        r#"import { createYoga } from "graphql-yoga";
import { search } from "./products";

export function resolver(parent: unknown, args: { q: string }, user: { id: string }) {
  createYoga;
  const ignored = user.id;
  return search(args.q);
}
"#,
    );
    write_file(
        &ws,
        "src/products.ts",
        r#"import mysql from "mysql2";

export function search(term: string) {
  const conn: any = mysql.createConnection({});
  return conn.query("SELECT * FROM products WHERE name = " + term);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.graphql_args_field$",
        "^typescript\\.sqli\\.method_query_concat$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.graphql_args_field",
            "typescript.sqli.method_query_concat",
            "src/yoga.ts",
            "src/products.ts",
            "resolver",
            "search",
            "args.q",
        ],
    );
}

#[test]
fn typescript_graphql_rule_does_not_taint_sibling_user_field() {
    let ws = temp_workspace("ts-graphql-no-user-field");
    write_file(
        &ws,
        "src/yoga.ts",
        r#"import { createYoga } from "graphql-yoga";
import { search } from "./products";

export function resolver(parent: unknown, args: { q: string }, user: { id: string }) {
  createYoga;
  const q = user.id;
  return search(q);
}
"#,
    );
    write_file(
        &ws,
        "src/products.ts",
        r#"import mysql from "mysql2";

export function search(term: string) {
  const conn: any = mysql.createConnection({});
  return conn.query("SELECT * FROM products WHERE id = " + term);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.graphql_args_field$",
        "^typescript\\.sqli\\.method_query_concat$",
    );
    assert_no_finding(&rows);
}

#[test]
fn typescript_route_query_reaches_cross_file_html_return_sink() {
    let ws = temp_workspace("ts-cross-file-html-return");
    write_file(
        &ws,
        "src/server.ts",
        r#"import express from "express";
import { renderResults } from "./render";

export function search(req: any, res: any) {
  express;
  const q = req.query.q;
  return res.end(renderResults(q));
}
"#,
    );
    write_file(
        &ws,
        "src/render.ts",
        r#"export function renderResults(q: string): string {
  return `<html><body>${q}</body></html>`;
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.express_req_query$",
        "^typescript\\.xss\\.html_return$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.express_req_query",
            "typescript.xss.html_return",
            "src/server.ts",
            "src/render.ts",
            "search",
            "renderResults",
            "req.query",
        ],
    );

    let clean = temp_workspace("ts-cross-file-html-return-clean");
    write_file(
        &clean,
        "src/server.ts",
        r#"import express from "express";
import { renderResults } from "./render";

export function search(req: any, res: any) {
  express;
  const unused = req.query.q;
  return res.end(renderResults("ok"));
}
"#,
    );
    write_file(
        &clean,
        "src/render.ts",
        r#"export function renderResults(q: string): string {
  return `<html><body>${q}</body></html>`;
}
"#,
    );

    let rows = run_taint_json(
        &clean,
        "^typescript\\.source\\.express_req_query$",
        "^typescript\\.xss\\.html_return$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_response_send_error_stack_rule_requires_error_operand() {
    let ws = temp_workspace("js-response-send-error-stack");
    write_file(
        &ws,
        "src/server.js",
        r#"const express = require("express");

function leak(req, res, err) {
  express;
  return res.send(err.stack);
}
"#,
    );

    let rows = run_sinks_json(&ws, "^javascript\\.info_disclosure\\.response_send_error_stack$");
    assert_has_row(
        &rows,
        &[
            "javascript.info_disclosure.response_send_error_stack",
            "src/server.js",
            "res.send",
        ],
    );

    let clean = temp_workspace("js-response-send-error-stack-clean");
    write_file(
        &clean,
        "src/server.js",
        r#"const express = require("express");

function page(req, res, html) {
  express;
  return res.send(html);
}
"#,
    );
    let rows = run_sinks_json(
        &clean,
        "^javascript\\.info_disclosure\\.response_send_error_stack$",
    );
    assert_rows_do_not_contain(&rows, &["response_send_error_stack"]);
}

#[test]
fn typescript_response_send_error_stack_rule_requires_error_operand() {
    let ws = temp_workspace("ts-response-send-error-stack");
    write_file(
        &ws,
        "src/server.ts",
        r#"import express from "express";

export function leak(req: any, res: any, err: Error) {
  express;
  return res.send(err.stack);
}
"#,
    );

    let rows = run_sinks_json(&ws, "^typescript\\.info_disclosure\\.response_send_error_stack$");
    assert_has_row(
        &rows,
        &[
            "typescript.info_disclosure.response_send_error_stack",
            "src/server.ts",
            "res.send",
        ],
    );

    let clean = temp_workspace("ts-response-send-error-stack-clean");
    write_file(
        &clean,
        "src/server.ts",
        r#"import express from "express";

export function page(req: any, res: any, html: string) {
  express;
  return res.send(html);
}
"#,
    );
    let rows = run_sinks_json(
        &clean,
        "^typescript\\.info_disclosure\\.response_send_error_stack$",
    );
    assert_rows_do_not_contain(&rows, &["response_send_error_stack"]);
}

#[test]
fn python_graphql_args_reach_untyped_connection_execute_sql_sink() {
    let ws = temp_workspace("py-graphql-conn-execute");
    write_file(
        &ws,
        "app/schema.py",
        r#"import graphene
from products import search

def resolve_products(obj, info, args):
    return search(args["q"])
"#,
    );
    write_file(
        &ws,
        "app/products.py",
        r#"import sqlite3

def search(term):
    conn = sqlite3.connect(":memory:")
    sql = "SELECT * FROM products WHERE name = " + term
    return conn.execute(sql)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.graphql\\.graphene_resolver_args$",
        "^python\\.sqli\\.named_connection_execute$",
    );
    assert_has_finding(
        &rows,
        &[
            "python.graphql.graphene_resolver_args",
            "python.sqli.named_connection_execute",
            "app/schema.py",
            "app/products.py",
            "resolve_products",
            "search",
        ],
    );
}

#[test]
fn python_graphql_args_requires_graphql_package_evidence() {
    let ws = temp_workspace("py-graphql-args-package-gate");
    write_file(
        &ws,
        "app/release.py",
        r#"import os

def clone(args):
    os.system(args)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.graphql\\.graphene_resolver_args$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_no_finding(&rows);
}

#[test]
fn python_tornado_get_argument_flows_to_os_system_without_sibling_overtaint() {
    let ws = temp_workspace("py-tornado-get-argument");
    write_file(
        &ws,
        "app/handlers.py",
        r#"import os
import tornado.web

class AdminHandler(tornado.web.RequestHandler):
    def get(self):
        cmd = self.get_argument("cmd")
        return os.system(cmd)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.tornado\\.get_argument$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_has_finding(
        &rows,
        &[
            "python.tornado.get_argument",
            "python.cmdi.os_system",
            "app/handlers.py",
            "get",
            "self.get_argument",
        ],
    );

    let clean = temp_workspace("py-tornado-get-argument-clean");
    write_file(
        &clean,
        "app/handlers.py",
        r#"import os
import tornado.web

class AdminHandler(tornado.web.RequestHandler):
    def get(self):
        unused = self.get_argument("cmd")
        return os.system("status")
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^python\\.tornado\\.get_argument$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_no_finding(&rows);
}

#[test]
fn python_falcon_get_param_flows_to_os_system_without_sibling_overtaint() {
    let ws = temp_workspace("py-falcon-get-param");
    write_file(
        &ws,
        "app/resources.py",
        r#"import os
import falcon

class AdminResource:
    def on_get(self, req, resp):
        cmd = req.get_param("cmd")
        return os.system(cmd)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.falcon\\.get_param$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_has_finding(
        &rows,
        &[
            "python.falcon.get_param",
            "python.cmdi.os_system",
            "app/resources.py",
            "on_get",
            "req.get_param",
        ],
    );

    let clean = temp_workspace("py-falcon-get-param-clean");
    write_file(
        &clean,
        "app/resources.py",
        r#"import os
import falcon

class AdminResource:
    def on_get(self, req, resp):
        unused = req.get_param("cmd")
        return os.system("status")
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^python\\.falcon\\.get_param$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_no_finding(&rows);
}

#[test]
fn python_aiohttp_match_info_index_flows_to_os_system_without_sibling_overtaint() {
    let ws = temp_workspace("py-aiohttp-match-info");
    write_file(
        &ws,
        "app/routes.py",
        r#"import os
import aiohttp

async def run(request):
    cmd = request.match_info["cmd"]
    return os.system(cmd)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.aiohttp\\.request_match_info$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_has_finding(
        &rows,
        &[
            "python.aiohttp.request_match_info",
            "python.cmdi.os_system",
            "app/routes.py",
            "run",
            "request.match_info",
        ],
    );

    let clean = temp_workspace("py-aiohttp-match-info-clean");
    write_file(
        &clean,
        "app/routes.py",
        r#"import os
import aiohttp

async def run(request):
    unused = request.match_info["cmd"]
    return os.system("status")
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^python\\.aiohttp\\.request_match_info$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_no_finding(&rows);
}

#[test]
fn go_graphql_resolveparams_args_reach_cross_file_sql_querycontext() {
    let ws = temp_workspace("go-graphql-cross-file-sqli");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/api/gql.go",
        r#"package api

import (
    "example.com/app/internal/repo"
    "github.com/graphql-go/graphql"
)

func ResolveProducts(p graphql.ResolveParams, products *repo.Products) any {
    q := p.Args["q"].(string)
    return products.Search(q)
}
"#,
    );
    write_file(
        &ws,
        "internal/repo/products.go",
        r#"package repo

import (
    "context"
    "database/sql"
)

type Products struct {
    DB *sql.DB
}

func (p *Products) Search(q string) *sql.Rows {
    query := "SELECT * FROM products WHERE name = '" + q + "'"
    rows, _ := p.DB.QueryContext(context.Background(), query)
    return rows
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.graphql\\.resolveparams_args$",
        "^go\\.sqli\\.db_query_context$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.graphql.resolveparams_args",
            "go.sqli.db_query_context",
            "internal/api/gql.go",
            "internal/repo/products.go",
            "ResolveProducts",
            "Search",
        ],
    );

    let clean = temp_workspace("go-graphql-cross-file-sqli-clean");
    write_file(&clean, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &clean,
        "internal/api/gql.go",
        r#"package api

import (
    "example.com/app/internal/repo"
    "github.com/graphql-go/graphql"
)

func ResolveProducts(p graphql.ResolveParams, products *repo.Products) any {
    _ = p.Args["q"].(string)
    return products.Search("fixed")
}
"#,
    );
    write_file(
        &clean,
        "internal/repo/products.go",
        r#"package repo

import (
    "context"
    "database/sql"
)

type Products struct {
    DB *sql.DB
}

func (p *Products) Search(q string) *sql.Rows {
    query := "SELECT * FROM products WHERE name = '" + q + "'"
    rows, _ := p.DB.QueryContext(context.Background(), query)
    return rows
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^go\\.graphql\\.resolveparams_args$",
        "^go\\.sqli\\.db_query_context$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_document_url_reaches_innerhtml_without_document_title_overtaint() {
    let ws = temp_workspace("js-document-url");
    write_file(
        &ws,
        "dom.js",
        r#"function renderFromUrl(el) {
  const html = document.URL;
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.document_url$",
        "^javascript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.document_url",
            "javascript.xss.innerhtml",
            "dom.js",
            "renderFromUrl",
            "document.URL",
        ],
    );

    let clean = temp_workspace("js-document-title");
    write_file(
        &clean,
        "dom.js",
        r#"function renderTitle(el) {
  const html = document.title;
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^javascript\\.source\\.document_url$",
        "^javascript\\.xss\\.innerhtml$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_document_referrer_and_cookie_reach_innerhtml() {
    let ws = temp_workspace("js-document-referrer-cookie");
    write_file(
        &ws,
        "dom.js",
        r#"function renderReferrer(el) {
  const html = document.referrer;
  el.innerHTML = html;
}

function renderCookie(el) {
  const html = document.cookie;
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.document_(referrer|cookie)$",
        "^javascript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.document_referrer",
            "javascript.xss.innerhtml",
            "dom.js",
            "renderReferrer",
            "document.referrer",
        ],
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.document_cookie",
            "javascript.xss.innerhtml",
            "dom.js",
            "renderCookie",
            "document.cookie",
        ],
    );
}

#[test]
fn javascript_browser_storage_getitem_reaches_innerhtml() {
    let ws = temp_workspace("js-browser-storage-domxss");
    write_file(
        &ws,
        "dom.js",
        r#"function renderStoredHtml(el) {
  const html = localStorage.getItem("profileHtml");
  el.innerHTML = html;
}

function renderSessionHtml(el) {
  const html = sessionStorage.getItem("profileHtml");
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.(localstorage|sessionstorage)_getitem$",
        "^javascript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.localstorage_getitem",
            "javascript.xss.innerhtml",
            "dom.js",
            "renderStoredHtml",
            "localStorage.getItem",
        ],
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.sessionstorage_getitem",
            "javascript.xss.innerhtml",
            "dom.js",
            "renderSessionHtml",
            "sessionStorage.getItem",
        ],
    );
}

#[test]
fn javascript_html_return_requires_tainted_return_expression() {
    let ws = temp_workspace("js-html-return-tainted");
    write_file(
        &ws,
        "src/page.js",
        r#"const express = require("express");

function page(req) {
  const name = req.query.name;
  return `<h1>${name}</h1>`;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.html_return$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_query",
            "javascript.xss.html_return",
            "src/page.js",
            "page",
        ],
    );

    let clean = temp_workspace("js-html-return-clean");
    write_file(
        &clean,
        "src/page.js",
        r#"const express = require("express");

function page(req) {
  const unused = req.query.name;
  return `<h1>safe</h1>`;
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.html_return$",
    );
    assert_no_finding(&rows);
}

#[test]
fn typescript_location_hash_reaches_innerhtml_without_sibling_overtaint() {
    let ws = temp_workspace("ts-location-hash");
    write_file(
        &ws,
        "dom.ts",
        r#"function renderFromHash(el: any): void {
  const html = location.hash;
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.window_location_hash$",
        "^typescript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.window_location_hash",
            "typescript.xss.innerhtml",
            "dom.ts",
            "renderFromHash",
            "location.hash",
        ],
    );

    let clean = temp_workspace("ts-location-hash-clean");
    write_file(
        &clean,
        "dom.ts",
        r#"function renderLiteral(el: any): void {
  const unused = location.hash;
  el.innerHTML = "<p>safe</p>";
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^typescript\\.source\\.window_location_hash$",
        "^typescript\\.xss\\.innerhtml$",
    );
    assert_no_finding(&rows);
}

#[test]
fn typescript_document_referrer_and_cookie_reach_innerhtml() {
    let ws = temp_workspace("ts-document-referrer-cookie");
    write_file(
        &ws,
        "dom.ts",
        r#"function renderReferrer(el: any): void {
  const html = document.referrer;
  el.innerHTML = html;
}

function renderCookie(el: any): void {
  const html = document.cookie;
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.document_(referrer|cookie)$",
        "^typescript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.document_referrer",
            "typescript.xss.innerhtml",
            "dom.ts",
            "renderReferrer",
            "document.referrer",
        ],
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.document_cookie",
            "typescript.xss.innerhtml",
            "dom.ts",
            "renderCookie",
            "document.cookie",
        ],
    );
}

#[test]
fn typescript_browser_storage_getitem_reaches_innerhtml() {
    let ws = temp_workspace("ts-browser-storage-domxss");
    write_file(
        &ws,
        "dom.ts",
        r#"function renderStoredHtml(el: any): void {
  const html = localStorage.getItem("profileHtml");
  el.innerHTML = html;
}

function renderSessionHtml(el: any): void {
  const html = sessionStorage.getItem("profileHtml");
  el.innerHTML = html;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.(localstorage|sessionstorage)_getitem$",
        "^typescript\\.xss\\.innerhtml$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.localstorage_getitem",
            "typescript.xss.innerhtml",
            "dom.ts",
            "renderStoredHtml",
            "localStorage.getItem",
        ],
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.sessionstorage_getitem",
            "typescript.xss.innerhtml",
            "dom.ts",
            "renderSessionHtml",
            "sessionStorage.getItem",
        ],
    );
}

#[test]
fn typescript_html_return_requires_tainted_return_expression() {
    let ws = temp_workspace("ts-html-return-tainted");
    write_file(
        &ws,
        "src/page.ts",
        r#"import express from "express";

function page(req: any): string {
  const name = req.query.name;
  return `<h1>${name}</h1>`;
}
"#,
    );
    let rows = run_taint_json(
        &ws,
        "^typescript\\.source\\.express_req_query$",
        "^typescript\\.xss\\.html_return$",
    );
    assert_has_finding(
        &rows,
        &[
            "typescript.source.express_req_query",
            "typescript.xss.html_return",
            "src/page.ts",
            "page",
        ],
    );

    let clean = temp_workspace("ts-html-return-clean");
    write_file(
        &clean,
        "src/page.ts",
        r#"import express from "express";

function page(req: any): string {
  const unused = req.query.name;
  return `<h1>safe</h1>`;
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^typescript\\.source\\.express_req_query$",
        "^typescript\\.xss\\.html_return$",
    );
    assert_no_finding(&rows);
}

#[test]
fn java_jaxrs_queryparam_flows_to_runtime_exec() {
    let ws = temp_workspace("java-jaxrs");
    write_file(
        &ws,
        "src/ScriptResource.java",
        r#"import jakarta.ws.rs.GET;
import jakarta.ws.rs.QueryParam;

class ScriptResource {
  @GET
  void run(@QueryParam("cmd") String cmd) throws Exception {
    Runtime.getRuntime().exec(cmd);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.jaxrs_queryparam$",
        "^java\\.cmdi\\.runtime_exec$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.jaxrs_queryparam",
            "java.cmdi.runtime_exec",
            "ScriptResource.java",
            "run",
        ],
    );
}

#[test]
fn java_vertx_request_param_flows_to_runtime_exec() {
    let ws = temp_workspace("java-vertx");
    write_file(
        &ws,
        "src/AuditVerticle.java",
        r#"import io.vertx.core.http.HttpServerRequest;

class AuditVerticle {
  void handle(HttpServerRequest request, Runtime runtime) throws Exception {
    String cmd = request.getParam("cmd");
    runtime.exec(cmd);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.vertx_request_getparam$",
        "^java\\.cmdi\\.runtime_exec_local$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.vertx_request_getparam",
            "java.cmdi.runtime_exec_local",
            "AuditVerticle.java",
            "handle",
        ],
    );
}

#[test]
fn java_vertx_routing_context_request_param_flows_to_runtime_exec() {
    let ws = temp_workspace("java-vertx-routingcontext-request");
    write_file(
        &ws,
        "src/AuditVerticle.java",
        r#"import io.vertx.ext.web.RoutingContext;

class AuditVerticle {
  void handle(RoutingContext ctx, Runtime runtime) throws Exception {
    String cmd = ctx.request().getParam("cmd");
    runtime.exec(cmd);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.vertx_routingcontext_request_getparam$",
        "^java\\.cmdi\\.runtime_exec_local$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.vertx_routingcontext_request_getparam",
            "java.cmdi.runtime_exec_local",
            "AuditVerticle.java",
            "handle",
            "ctx.request().getParam",
        ],
    );

    let clean = temp_workspace("java-vertx-routingcontext-request-clean");
    write_file(
        &clean,
        "src/AuditVerticle.java",
        r#"import io.vertx.ext.web.RoutingContext;

class AuditVerticle {
  void handle(RoutingContext ctx, Runtime runtime) throws Exception {
    String unused = ctx.request().getParam("cmd");
    runtime.exec("status");
  }
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^java\\.source\\.vertx_routingcontext_request_getparam$",
        "^java\\.cmdi\\.runtime_exec_local$",
    );
    assert_no_finding(&rows);
}

#[test]
fn java_vertx_routing_context_body_json_flows_to_runtime_exec() {
    let ws = temp_workspace("java-vertx-routingcontext-body-json");
    write_file(
        &ws,
        "src/AuditVerticle.java",
        r#"import io.vertx.ext.web.RoutingContext;

class AuditVerticle {
  void handle(RoutingContext ctx, Runtime runtime) throws Exception {
    Object body = ctx.getBodyAsJson();
    runtime.exec(body);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.vertx_routingcontext_getbodyasjson$",
        "^java\\.cmdi\\.runtime_exec_local$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.vertx_routingcontext_getbodyasjson",
            "java.cmdi.runtime_exec_local",
            "AuditVerticle.java",
            "handle",
            "ctx.getBodyAsJson",
        ],
    );

    let clean = temp_workspace("java-vertx-routingcontext-body-json-clean");
    write_file(
        &clean,
        "src/AuditVerticle.java",
        r#"import io.vertx.ext.web.RoutingContext;

class AuditVerticle {
  void handle(RoutingContext ctx, Runtime runtime) throws Exception {
    Object unused = ctx.getBodyAsJson();
    runtime.exec("status");
  }
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^java\\.source\\.vertx_routingcontext_getbodyasjson$",
        "^java\\.cmdi\\.runtime_exec_local$",
    );
    assert_no_finding(&rows);
}

#[test]
fn java_esapi_html_encoder_marks_xss_flow_sanitized() {
    let ws = temp_workspace("java-esapi-html-sanitized");
    write_file(
        &ws,
        "FeedController.java",
        r#"import org.owasp.esapi.ESAPI;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
class FeedController {
  @GetMapping("/feed")
  ResponseEntity<String> feed(@RequestParam String name) {
    String safe = ESAPI.encoder().encodeForHTML(name);
    return ResponseEntity.ok("<p>" + safe + "</p>");
  }
}
"#,
    );

    let rows = run_taint_json_with_flags(
        &ws,
        "^java\\.source\\.spring_request_param$",
        "^java\\.xss\\.spring_responseentity_ok_html_concat$",
        &["--show-sanitized"],
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.spring_request_param",
            "java.xss.spring_responseentity_ok_html_concat",
            "java.sanitizer.esapi_encode_for_html",
            "FeedController.java",
            "encodeForHTML",
            "ResponseEntity.ok",
        ],
    );
    assert_any_finding_has_status(&rows, "sanitized");
}

#[test]
fn java_servlet_header_survives_urldecode_into_preparecall_without_sibling_overtaint() {
    let ws = temp_workspace("java-servlet-urldecode-sqli");
    write_file(
        &ws,
        "src/ReportServlet.java",
        r#"import java.net.URLDecoder;
import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;

class ReportServlet {
  void doPost(HttpServletRequest request, Connection connection) throws Exception {
    String param = request.getHeader("X-Report");
    param = URLDecoder.decode(param, "UTF-8");
    String sql = "{call " + param + "}";
    connection.prepareCall(sql);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.servlet_getheader$",
        "^java\\.sqli\\.jdbc_prepare_call$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.servlet_getheader",
            "java.sqli.jdbc_prepare_call",
            "ReportServlet.java",
            "doPost",
            "prepareCall",
        ],
    );

    let clean = temp_workspace("java-servlet-clean-urldecode-sqli");
    write_file(
        &clean,
        "src/ReportServlet.java",
        r#"import java.net.URLDecoder;
import java.sql.Connection;
import javax.servlet.http.HttpServletRequest;

class ReportServlet {
  void doPost(HttpServletRequest request, Connection connection) throws Exception {
    String unused = request.getHeader("X-Report");
    String decoded = URLDecoder.decode("healthcheck", "UTF-8");
    String sql = "{call " + decoded + "}";
    connection.prepareCall(sql);
  }
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^java\\.source\\.servlet_getheader$",
        "^java\\.sqli\\.jdbc_prepare_call$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_decode_uri_component_preserves_query_taint_without_sibling_overtaint() {
    let ws = temp_workspace("js-decode-uri-component");
    write_file(
        &ws,
        "src/upload.js",
        r#"const express = require("express");
const path = require("path");

function upload(req) {
  const raw = req.query.name;
  const decoded = decodeURIComponent(raw);
  return path.join("/srv/uploads", decoded);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.upload\\.path_join_original_filename$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_query",
            "javascript.upload.path_join_original_filename",
            "decodeURIComponent",
            "upload.js",
            "upload",
        ],
    );

    let clean = temp_workspace("js-decode-uri-component-clean");
    write_file(
        &clean,
        "src/upload.js",
        r#"const express = require("express");
const path = require("path");

function upload(req) {
  const unused = req.query.name;
  const decoded = decodeURIComponent("avatar.png");
  return path.join("/srv/uploads", decoded);
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.upload\\.path_join_original_filename$",
    );
    assert_no_finding(&rows);
}

#[test]
fn python_urllib_unquote_preserves_query_taint_without_sibling_overtaint() {
    let ws = temp_workspace("py-urllib-unquote");
    write_file(
        &ws,
        "app.py",
        r#"import os
from flask import request
from urllib import parse

def run():
    raw = request.args.get("cmd")
    decoded = parse.unquote(raw)
    return os.system(decoded)
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^python\\.flask\\.request_args_get$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_has_finding(
        &rows,
        &[
            "python.flask.request_args_get",
            "python.cmdi.os_system",
            "parse.unquote",
            "app.py",
            "run",
        ],
    );

    let clean = temp_workspace("py-urllib-unquote-clean");
    write_file(
        &clean,
        "app.py",
        r#"import os
from flask import request
from urllib import parse

def run():
    unused = request.args.get("cmd")
    decoded = parse.unquote("whoami")
    return os.system(decoded)
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^python\\.flask\\.request_args_get$",
        "^python\\.cmdi\\.os_system$",
    );
    assert_no_finding(&rows);
}

#[test]
fn go_url_query_unescape_preserves_query_taint_without_sibling_overtaint() {
    let ws = temp_workspace("go-query-unescape");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/api/files.go",
        r#"package api

import (
    "net/http"
    "net/url"
    "path/filepath"
)

func Files(w http.ResponseWriter, r *http.Request) string {
    raw := r.URL.Query().Get("name")
    decoded, _ := url.QueryUnescape(raw)
    return filepath.Join("/srv/uploads", decoded)
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.path\\.filepath_join$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.nethttp.query_value_get",
            "go.path.filepath_join",
            "url.QueryUnescape",
            "files.go",
            "Files",
        ],
    );

    let clean = temp_workspace("go-query-unescape-clean");
    write_file(&clean, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &clean,
        "internal/api/files.go",
        r#"package api

import (
    "net/http"
    "net/url"
    "path/filepath"
)

func Files(w http.ResponseWriter, r *http.Request) string {
    _ = r.URL.Query().Get("name")
    decoded, _ := url.QueryUnescape("avatar.png")
    return filepath.Join("/srv/uploads", decoded)
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.path\\.filepath_join$",
    );
    assert_no_finding(&rows);
}

#[test]
fn go_template_html_requires_tainted_value_not_literal_or_sibling_source() {
    let ws = temp_workspace("go-template-html-tainted");
    write_file(&ws, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &ws,
        "internal/api/page.go",
        r#"package api

import (
    "html/template"
    "net/http"
)

func Page(w http.ResponseWriter, r *http.Request) template.HTML {
    name := r.URL.Query().Get("name")
    return template.HTML("<h1>" + name + "</h1>")
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.xss\\.html_template_html$",
    );
    assert_has_finding(
        &rows,
        &[
            "go.nethttp.query_value_get",
            "go.xss.html_template_html",
            "template.HTML",
            "page.go",
            "Page",
        ],
    );

    let clean = temp_workspace("go-template-html-clean");
    write_file(&clean, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &clean,
        "internal/api/page.go",
        r#"package api

import (
    "html/template"
    "net/http"
)

func Page(w http.ResponseWriter, r *http.Request) template.HTML {
    _ = r.URL.Query().Get("name")
    return template.HTML("<h1>safe</h1>")
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^go\\.nethttp\\.query_value_get$",
        "^go\\.xss\\.html_template_html$",
    );
    assert_no_finding(&rows);
}

#[test]
fn javascript_express_res_end_requires_tainted_body_not_literal_or_sibling_query() {
    let ws = temp_workspace("js-express-res-end-tainted");
    write_file(
        &ws,
        "src/server.js",
        r#"const express = require("express");

function handler(req, res) {
  const name = req.query.name;
  return res.end("<h1>" + name + "</h1>");
}

module.exports = { handler };
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.express_res_end_html$",
    );
    assert_has_finding(
        &rows,
        &[
            "javascript.source.express_req_query",
            "javascript.xss.express_res_end_html",
            "res.end",
            "server.js",
            "handler",
        ],
    );

    let clean = temp_workspace("js-express-res-end-clean");
    write_file(
        &clean,
        "src/server.js",
        r#"const express = require("express");

function handler(req, res) {
  const unused = req.query.name;
  return res.end("<h1>safe</h1>");
}

module.exports = { handler };
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^javascript\\.source\\.express_req_query$",
        "^javascript\\.xss\\.express_res_end_html$",
    );
    assert_no_finding(&rows);
}

#[test]
fn java_graphql_datafetching_argument_reaches_cross_file_sink() {
    let ws = temp_workspace("java-graphql");
    write_file(
        &ws,
        "src/GqlConfig.java",
        r#"package app;

import graphql.schema.DataFetchingEnvironment;

class GqlConfig {
  Object products(DataFetchingEnvironment env, UserRepo repo) throws Exception {
    String q = env.getArgument("q");
    return repo.search(q);
  }
}
"#,
    );
    write_file(
        &ws,
        "src/UserRepo.java",
        r#"package app;

class UserRepo {
  Object search(String q) throws Exception {
    Runtime.getRuntime().exec(q);
    return null;
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^java\\.source\\.graphql_datafetching_environment_getargument$",
        "^java\\.cmdi\\.runtime_exec$",
    );
    assert_has_finding(
        &rows,
        &[
            "java.source.graphql_datafetching_environment_getargument",
            "java.cmdi.runtime_exec",
            "GqlConfig.java",
            "UserRepo.java",
            "products",
            "search",
        ],
    );
}

#[test]
fn csharp_graphql_context_argument_reaches_graphql_parse_sink() {
    let ws = temp_workspace("csharp-graphql-context");
    write_file(
        &ws,
        "Resolvers.cs",
        r#"using GraphQL;
using GraphQLParser;

class Resolver {
  void Resolve(IResolveFieldContext context) {
    var query = context.GetArgument<string>("q");
    Parser.Parse(query);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^csharp\\.source\\.graphql_resolvefieldcontext_getargument$",
        "^csharp\\.graphql\\.parser_parse$",
    );
    assert_has_finding(
        &rows,
        &[
            "csharp.source.graphql_resolvefieldcontext_getargument",
            "csharp.graphql.parser_parse",
            "Resolvers.cs",
            "Resolve",
        ],
    );
}

#[test]
fn csharp_process_start_info_arguments_requires_qualified_member_write() {
    let ws = temp_workspace("csharp-process-start-info-args");
    write_file(
        &ws,
        "App.cs",
        r#"using System.Diagnostics;
using Microsoft.AspNetCore.Http;

class App {
  void Run(HttpRequest Request) {
    var input = Request.Query["cmd"];
    var psi = new ProcessStartInfo();
    psi.Arguments = input;
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^csharp\\.source\\.aspnet_request_query$",
        "^csharp\\.cmdi\\.process_start_info_args$",
    );
    assert_has_finding(
        &rows,
        &[
            "csharp.source.aspnet_request_query",
            "csharp.cmdi.process_start_info_args",
            "psi.Arguments",
            "App.cs",
            "Run",
        ],
    );

    let clean = temp_workspace("csharp-local-arguments-clean");
    write_file(
        &clean,
        "App.cs",
        r#"using Microsoft.AspNetCore.Http;

class App {
  void Run(HttpRequest Request) {
    var input = Request.Query["cmd"];
    var Arguments = input;
  }
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^csharp\\.source\\.aspnet_request_query$",
        "^csharp\\.cmdi\\.process_start_info_args$",
    );
    assert_no_finding(&rows);
}

#[test]
fn swift_and_objc_process_property_sinks_ignore_local_variables() {
    let swift = temp_workspace("swift-process-property-sinks");
    write_file(
        &swift,
        "App.swift",
        r#"import Foundation

func local(input: String) {
  let arguments = input
  let launchPath = input
  let executableURL = input
}

func task(input: String) {
  let process = Process()
  process.arguments = [input]
  process.launchPath = input
  process.executableURL = URL(fileURLWithPath: input)
}
"#,
    );
    let rows = run_sinks_json(
        &swift,
        "^swift\\.cmdi\\.(arguments_write|launchpath_write|executableurl_write)$",
    );
    assert_has_row(
        &rows,
        &[
            "swift.cmdi.arguments_write",
            "process.arguments",
            "swift.cmdi.launchpath_write",
            "process.launchPath",
            "swift.cmdi.executableurl_write",
            "process.executableURL",
        ],
    );
    assert_rows_do_not_contain(&rows, &["\"text\": \"arguments\"", "\"text\": \"launchPath\""]);

    let objc = temp_workspace("objc-process-property-sinks");
    write_file(
        &objc,
        "App.m",
        r#"#import <Foundation/Foundation.h>

void local(id input) {
  id launchPath = input;
  id arguments = input;
}

void task(id input) {
  NSTask *task = [NSTask new];
  task.launchPath = input;
  task.arguments = input;
}
"#,
    );
    let rows = run_sinks_json(&objc, "^objc\\.cmdi\\.nstask_setters$");
    assert_has_row(
        &rows,
        &["objc.cmdi.nstask_setters", "task.launchPath", "task.arguments"],
    );
    assert_rows_do_not_contain(&rows, &["\"text\": \"launchPath\"", "\"text\": \"arguments\""]);
}

#[test]
fn browser_property_write_sinks_ignore_same_named_local_variables() {
    let js = temp_workspace("js-dom-property-sinks");
    write_file(
        &js,
        "dom.js",
        r#"function local(input, el, frame) {
  const innerHTML = input;
  const outerHTML = input;
  const srcdoc = input;
  el.innerHTML = input;
  el.outerHTML = input;
  frame.srcdoc = input;
}
"#,
    );
    let rows = run_sinks_json(&js, "^javascript\\.xss\\.(innerhtml|outerhtml|iframe_srcdoc)$");
    assert_has_row(
        &rows,
        &[
            "javascript.xss.innerhtml",
            "el.innerHTML",
            "javascript.xss.outerhtml",
            "el.outerHTML",
            "javascript.xss.iframe_srcdoc",
            "frame.srcdoc",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &[
            "\"text\": \"innerHTML\"",
            "\"text\": \"outerHTML\"",
            "\"text\": \"srcdoc\"",
        ],
    );

    let ts = temp_workspace("ts-dom-property-sinks");
    write_file(
        &ts,
        "dom.ts",
        r#"function local(input: string, el: any, frame: any) {
  const innerHTML = input;
  const outerHTML = input;
  const srcdoc = input;
  el.innerHTML = input;
  el.outerHTML = input;
  frame.srcdoc = input;
}
"#,
    );
    let rows = run_sinks_json(&ts, "^typescript\\.xss\\.(innerhtml|outerhtml|iframe_srcdoc)$");
    assert_has_row(
        &rows,
        &[
            "typescript.xss.innerhtml",
            "el.innerHTML",
            "typescript.xss.outerhtml",
            "el.outerHTML",
            "typescript.xss.iframe_srcdoc",
            "frame.srcdoc",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &[
            "\"text\": \"innerHTML\"",
            "\"text\": \"outerHTML\"",
            "\"text\": \"srcdoc\"",
        ],
    );

    let dart = temp_workspace("dart-dom-property-sinks");
    write_file(
        &dart,
        "app.dart",
        r#"void local(input, el, frame, window) {
  var innerHtml = input;
  var srcdoc = input;
  var href = input;
  el.innerHtml = input;
  frame.srcdoc = input;
  window.location.href = input;
}
"#,
    );
    let rows = run_sinks_json(
        &dart,
        "^dart\\.(xss\\.(innerhtml|iframe_srcdoc)|open_redirect\\.window_location_href)$",
    );
    assert_has_row(
        &rows,
        &[
            "dart.xss.innerhtml",
            "el.innerHtml",
            "dart.xss.iframe_srcdoc",
            "frame.srcdoc",
            "dart.open_redirect.window_location_href",
            "window.location.href",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &[
            "\"text\": \"innerHtml\"",
            "\"text\": \"srcdoc\"",
            "\"text\": \"href\"",
        ],
    );
}

#[test]
fn xxe_config_write_sinks_ignore_same_named_local_variables() {
    let csharp = temp_workspace("csharp-xxe-config-writes");
    write_file(
        &csharp,
        "App.cs",
        r#"class App {
  void local(string input) {
    var DtdProcessing = input;
    var ProhibitDtd = input;
  }

  void settings(string input) {
    settings.DtdProcessing = input;
    reader.ProhibitDtd = input;
  }
}
"#,
    );
    let rows = run_sinks_json(
        &csharp,
        "^csharp\\.xxe\\.(dtd_processing_parse|prohibitdtd_false)$",
    );
    assert_has_row(
        &rows,
        &[
            "csharp.xxe.dtd_processing_parse",
            "settings.DtdProcessing",
            "csharp.xxe.prohibitdtd_false",
            "reader.ProhibitDtd",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &["\"text\": \"DtdProcessing\"", "\"text\": \"ProhibitDtd\""],
    );

    let go = temp_workspace("go-xxe-config-writes");
    write_file(&go, "go.mod", "module example.com/app\n\ngo 1.22\n");
    write_file(
        &go,
        "app.go",
        r#"package main

import "encoding/xml"

func local(input string) {
    Strict := input
    Entity := map[string]string{}
    CharsetReader := input
    _, _, _ = Strict, Entity, CharsetReader
}

func decoder(input string) {
    var d xml.Decoder
    d.Strict = false
    d.Entity = map[string]string{"xxe": input}
    d.CharsetReader = nil
}
"#,
    );
    let rows = run_sinks_json(
        &go,
        "^go\\.xxe\\.xml_decoder_(strict_false|entity_map|charsetreader)$",
    );
    assert_has_row(
        &rows,
        &[
            "go.xxe.xml_decoder_strict_false",
            "d.Strict",
            "go.xxe.xml_decoder_entity_map",
            "d.Entity",
            "go.xxe.xml_decoder_charsetreader",
            "d.CharsetReader",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &[
            "\"text\": \"Strict\"",
            "\"text\": \"Entity\"",
            "\"text\": \"CharsetReader\"",
        ],
    );
}

#[test]
fn lua_swift_objc_property_write_sinks_ignore_same_named_local_variables() {
    let lua = temp_workspace("lua-header-property-write");
    write_file(
        &lua,
        "app.lua",
        r#"local _openresty = require("openresty")

function handle(input)
  local header = input
  ngx.header["X-User"] = input
  ngx.header.Location = input
end
"#,
    );
    let rows = run_sinks_json(&lua, "^lua\\.header\\.ngx_header_assign$");
    assert_has_row(
        &rows,
        &[
            "lua.header.ngx_header_assign",
            "ngx.header.X-User",
            "ngx.header.Location",
        ],
    );
    assert_rows_do_not_contain(&rows, &["\"text\": \"header\""]);

    let swift = temp_workspace("swift-security-property-writes");
    write_file(
        &swift,
        "App.swift",
        r#"func local(input: Bool, predicateValue: NSPredicate, headers: [String: String]) {
  let allHTTPHeaderFields = headers
  let predicate = predicateValue
  let shouldResolveExternalEntities = input

  request.allHTTPHeaderFields = headers
  request.predicate = predicateValue
  parser.shouldResolveExternalEntities = input
}
"#,
    );
    let rows = run_sinks_json(
        &swift,
        "^swift\\.(header\\.urlrequest_allhttpheaderfields|nosql\\.coredata_fetch_predicate|xxe\\.should_resolve_external_entities)$",
    );
    assert_has_row(
        &rows,
        &[
            "swift.header.urlrequest_allhttpheaderfields",
            "request.allHTTPHeaderFields",
            "swift.nosql.coredata_fetch_predicate",
            "request.predicate",
            "swift.xxe.should_resolve_external_entities",
            "parser.shouldResolveExternalEntities",
        ],
    );
    assert_rows_do_not_contain(
        &rows,
        &[
            "\"text\": \"allHTTPHeaderFields\"",
            "\"text\": \"predicate\"",
            "\"text\": \"shouldResolveExternalEntities\"",
        ],
    );

    let objc = temp_workspace("objc-xxe-property-write");
    write_file(
        &objc,
        "App.m",
        r#"void local(id input) {
  id shouldResolveExternalEntities = input;
  parser.shouldResolveExternalEntities = input;
}
"#,
    );
    let rows = run_sinks_json(&objc, "^objc\\.xxe\\.shouldresolveexternalentities_yes$");
    assert_has_row(
        &rows,
        &[
            "objc.xxe.shouldresolveexternalentities_yes",
            "parser.shouldResolveExternalEntities",
        ],
    );
    assert_rows_do_not_contain(&rows, &["\"text\": \"shouldResolveExternalEntities\""]);
}

#[test]
fn php_graphql_resolver_args_reach_execute_query_without_helper_overtaint() {
    let ws = temp_workspace("php-graphql-resolver");
    write_file(
        &ws,
        "Resolver.php",
        r#"<?php
use webonyx\graphqlphp;

class Resolver {
  public function resolve($root, $args, $schema) {
    return GraphQL::executeQuery($schema, $args);
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^php\\.source\\.graphql_resolver_args_param$",
        "^php\\.graphql\\.execute_query$",
    );
    assert_has_finding(
        &rows,
        &[
            "php.source.graphql_resolver_args_param",
            "php.graphql.execute_query",
            "Resolver.php",
            "resolve",
        ],
    );

    let clean = temp_workspace("php-graphql-helper");
    write_file(
        &clean,
        "Helper.php",
        r#"<?php
use webonyx\graphqlphp;

function helper($args, $schema) {
  return GraphQL::executeQuery($schema, $args);
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^php\\.source\\.graphql_resolver_args_param$",
        "^php\\.graphql\\.execute_query$",
    );
    assert_no_finding(&rows);
}

#[test]
fn ruby_graphql_resolver_args_reach_schema_execute_without_helper_overtaint() {
    let ws = temp_workspace("ruby-graphql-resolver");
    write_file(
        &ws,
        "resolver.rb",
        r#"require "graphql"

class ProductResolver
  def resolve(args, schema)
    schema.execute(args)
  end
end
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^ruby\\.source\\.graphql_resolver_args$",
        "^ruby\\.graphql\\.schema_execute$",
    );
    assert_has_finding(
        &rows,
        &[
            "ruby.source.graphql_resolver_args",
            "ruby.graphql.schema_execute",
            "resolver.rb",
            "resolve",
        ],
    );

    let clean = temp_workspace("ruby-graphql-helper");
    write_file(
        &clean,
        "helper.rb",
        r#"require "graphql"

def helper(args, schema)
  schema.execute(args)
end
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^ruby\\.source\\.graphql_resolver_args$",
        "^ruby\\.graphql\\.schema_execute$",
    );
    assert_no_finding(&rows);
}

#[test]
fn kotlin_graphql_argument_reaches_graphql_execute_sink() {
    let ws = temp_workspace("kotlin-graphql");
    write_file(
        &ws,
        "App.kt",
        r#"import com.graphqljava.graphqljava.*

class App {
  fun handle(env: DataFetchingEnvironment) {
    val query = env.getArgument("q")
    GraphQL.executeAsync(query)
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^kotlin\\.source\\.graphql_datafetching_environment_getargument$",
        "^kotlin\\.graphql\\.graphql_execute_async$",
    );
    assert_has_finding(
        &rows,
        &[
            "kotlin.source.graphql_datafetching_environment_getargument",
            "kotlin.graphql.graphql_execute_async",
            "App.kt",
            "handle",
        ],
    );
}

#[test]
fn scala_graphql_argument_reaches_graphql_execute_sink() {
    let ws = temp_workspace("scala-graphql");
    write_file(
        &ws,
        "App.scala",
        r#"import graphql._

object App {
  def handle(env: DataFetchingEnvironment): Unit = {
    val query = env.getArgument("q")
    GraphQL.executeAsync(query)
  }
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^scala\\.source\\.graphql_datafetching_getargument$",
        "^scala\\.graphql\\.graphql_execute_async$",
    );
    assert_has_finding(
        &rows,
        &[
            "scala.source.graphql_datafetching_getargument",
            "scala.graphql.graphql_execute_async",
            "App.scala",
            "handle",
        ],
    );
}

#[test]
fn rust_async_graphql_context_args_reach_schema_execute_without_helper_overtaint() {
    let ws = temp_workspace("rust-async-graphql");
    write_file(
        &ws,
        "src/lib.rs",
        r#"use async_graphql::Context;

struct Schema;

impl Schema {
    fn execute(&self, query: &str) {}
}

fn resolve(ctx: &Context, schema: &Schema) {
    let query = ctx.args();
    schema.execute(query);
}
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^rust\\.source\\.async_graphql_context_args$",
        "^rust\\.graphql\\.async_graphql_schema_execute$",
    );
    assert_has_finding(
        &rows,
        &[
            "rust.source.async_graphql_context_args",
            "rust.graphql.async_graphql_schema_execute",
            "lib.rs",
            "resolve",
        ],
    );

    let clean = temp_workspace("rust-async-graphql-helper");
    write_file(
        &clean,
        "src/lib.rs",
        r#"use async_graphql::Context;

struct Helper;
struct Schema;

impl Helper {
    fn args(&self) -> &'static str { "safe" }
}

impl Schema {
    fn execute(&self, query: &str) {}
}

fn helper(ctx: &Helper, schema: &Schema) {
    let query = ctx.args();
    schema.execute(query);
}
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^rust\\.source\\.async_graphql_context_args$",
        "^rust\\.graphql\\.async_graphql_schema_execute$",
    );
    assert_no_finding(&rows);
}

#[test]
fn elixir_absinthe_resolver_args_reach_absinthe_run_without_helper_overtaint() {
    let ws = temp_workspace("elixir-absinthe-resolver");
    write_file(
        &ws,
        "app.ex",
        r#"alias Absinthe

defmodule App do
  def resolve(args) do
    Absinthe.run(args)
  end
end
"#,
    );

    let rows = run_taint_json(
        &ws,
        "^elixir\\.absinthe\\.resolver_args$",
        "^elixir\\.graphql\\.absinthe_run$",
    );
    assert_has_finding(
        &rows,
        &[
            "elixir.absinthe.resolver_args",
            "elixir.graphql.absinthe_run",
            "app.ex",
            "resolve",
        ],
    );

    let clean = temp_workspace("elixir-absinthe-helper");
    write_file(
        &clean,
        "app.ex",
        r#"alias Absinthe

defmodule App do
  def helper(args) do
    Absinthe.run(args)
  end
end
"#,
    );
    let rows = run_taint_json(
        &clean,
        "^elixir\\.absinthe\\.resolver_args$",
        "^elixir\\.graphql\\.absinthe_run$",
    );
    assert_no_finding(&rows);
}
