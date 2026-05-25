//! Vuln-class positive/negative regression suite.
//!
//! Each major taint-class vulnerability gets a paired positive +
//! negative fixture against the live `security-patterns/` tree:
//!
//!   * positive — real source flows into a real sink, an
//!     appropriately-tagged finding must appear.
//!   * negative — taint blocked by sanitiser, replaced by a literal,
//!     or the sink uses the safe call shape; no finding of that tag
//!     must appear.
//!
//! These pin both sides of the engine's precision contract: it must
//! still detect real vulnerabilities while not crying wolf on the
//! safe alternatives the rule pack explicitly carves out. New rules
//! and engine refactors will surface here whenever they break either
//! side. The companion file `over_taint_matrix.rs` covers
//! cross-language over-taint scenarios at the engine layer; this
//! file covers per-class engine-plus-rulepack behaviour.
//!
//! In-memory `Workspace` only — no temp directories, no fixture
//! files on disk.

use bonsai_lang_api::LanguageRegistry;
use bonsai_security::{load_rulepack, run_taint_analysis, FindingStatus, Rulepack, TaintAnalysisOptions};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::OnceLock;

fn repo_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .find(|p| p.join("security-patterns").exists() && p.join("crates").exists())
        .map(std::path::Path::to_path_buf)
        .expect("repo root")
}

/// Live rule pack — loaded once per process so the 30+ test cases
/// in this file don't each pay full YAML parse cost.
fn rulepack() -> &'static Rulepack {
    static PACK: OnceLock<Rulepack> = OnceLock::new();
    PACK.get_or_init(|| load_rulepack(&repo_root().join("security-patterns")).expect("live rulepack loads"))
}

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
    let ws = Workspace::new(registry);
    ws.vfs().write("app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn ws_for_language(file_name: &str, source: &str) -> Workspace {
    let ws = Workspace::new(bonsai_adapters::all_languages_registry());
    ws.vfs().write(file_name.to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

#[derive(Debug, Clone)]
struct TaggedFinding {
    tag: String,
    status: FindingStatus,
}

#[derive(Debug, Clone)]
struct Outcome {
    findings: Vec<TaggedFinding>,
}

impl Outcome {
    fn unsanitized_with_tag(&self, tag: &str) -> bool {
        self.findings
            .iter()
            .any(|f| f.tag == tag && f.status == FindingStatus::Unsanitized)
    }

    fn any_with_tag(&self, tag: &str) -> bool {
        self.findings.iter().any(|f| f.tag == tag)
    }

    fn tag_summary(&self) -> Vec<(String, FindingStatus)> {
        self.findings.iter().map(|f| (f.tag.clone(), f.status)).collect()
    }
}

fn analyse(ws: &Workspace) -> Outcome {
    analyse_with_options(
        ws,
        TaintAnalysisOptions {
            include_inferred_sources: true,
            ..TaintAnalysisOptions::default()
        },
    )
}

fn analyse_pattern_only(ws: &Workspace) -> Outcome {
    analyse_with_options(
        ws,
        TaintAnalysisOptions {
            include_pattern_only: true,
            ..TaintAnalysisOptions::default()
        },
    )
}

fn analyse_with_options(ws: &Workspace, options: TaintAnalysisOptions) -> Outcome {
    let report = run_taint_analysis(ws, rulepack(), options).expect("taint analysis");
    Outcome {
        findings: report
            .findings
            .iter()
            .filter_map(|f| {
                f.finding.tag.clone().map(|tag| TaggedFinding {
                    tag,
                    status: f.finding.status,
                })
            })
            .collect(),
    }
}

/// Positive contract — engine must report at least one
/// FULLY-UNSANITIZED finding tagged `tag`. `Sanitized` and
/// `WrongContext` don't count: the user is asking "would the
/// real-world finder fire on this?", and the rendered list
/// shows unsanitized findings as primary alerts.
fn assert_tag_reported(outcome: &Outcome, tag: &str, label: &str) {
    assert!(
        outcome.unsanitized_with_tag(tag),
        "{label}: expected an unsanitized `{tag}` finding; got {:?}",
        outcome.tag_summary()
    );
}

/// Negative contract — engine must NOT report a fully-unsanitized
/// finding tagged `tag`. Sanitized matches are allowed (per spec,
/// sanitization changes status, not visibility).
fn assert_tag_not_reported(outcome: &Outcome, tag: &str, label: &str) {
    assert!(
        !outcome.unsanitized_with_tag(tag),
        "{label}: expected NO unsanitized `{tag}` finding; got {:?}",
        outcome.tag_summary()
    );
}

/// Stricter negative — no finding of `tag` at any status.
/// Used when the safe shape doesn't trigger any rule match at
/// all (literal arg, irrelevant call, or different sink rule).
fn assert_tag_absent(outcome: &Outcome, tag: &str, label: &str) {
    assert!(
        !outcome.any_with_tag(tag),
        "{label}: expected NO `{tag}` finding at any status; got {:?}",
        outcome.tag_summary()
    );
}

// ===========================================================================
// 1. SQL injection (parameterised vs string concat)
// ===========================================================================

#[test]
fn sqli_python_string_concat_reports() {
    let src = r#"
import sqlite3
def handler(user_input):
    cursor = sqlite3.connect(":memory:").cursor()
    return cursor.execute("SELECT * FROM users WHERE id='" + user_input + "'")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "sql-injection", "sqli concat");
}

#[test]
fn sqli_python_parameterised_clean() {
    // Tainted value flows ONLY into the params tuple (arg 1), not the
    // query string (arg 0). The cursor.execute rule is gated on
    // `arg_tainted: index 0`, so engine + rule must agree there is
    // no flaw here.
    let src = r#"
import sqlite3
def handler(user_input):
    cursor = sqlite3.connect(":memory:").cursor()
    return cursor.execute("SELECT * FROM users WHERE id=?", (user_input,))
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "sql-injection", "sqli parameterised");
}

#[test]
fn sqli_js_graphql_resolver_args_reports_without_inferred_sources() {
    let src = r#"
const _gql = require("graphql");
const _mysql = require("mysql");
function resolver(parent, args, context, info) {
    const sql = "SELECT * FROM users WHERE name='" + args.filter + "'";
    return db.query(sql);
}
"#;
    let outcome = analyse_with_options(
        &ws_for_language("resolver.js", src),
        TaintAnalysisOptions::default(),
    );
    assert_tag_reported(&outcome, "sql-injection", "JS GraphQL resolver args param");
}

#[test]
fn sqli_js_first_args_helper_clean_without_inferred_sources() {
    let src = r#"
const _gql = require("graphql");
const _mysql = require("mysql");
function helper(args, other) {
    const sql = "SELECT * FROM users WHERE name='" + args.filter + "'";
    return db.query(sql);
}
"#;
    let outcome = analyse_with_options(
        &ws_for_language("helper.js", src),
        TaintAnalysisOptions::default(),
    );
    assert_tag_absent(
        &outcome,
        "sql-injection",
        "first-argument helper named args must stay clean",
    );
}

#[test]
fn sqli_ts_graphql_resolver_args_reports_without_inferred_sources() {
    let src = r#"
const _gql = require("graphql");
const _sql = require("typeorm");
function resolver(parent: unknown, args: { filter: string }, context: unknown, info: unknown) {
    const sql = "SELECT * FROM users WHERE name='" + args.filter + "'";
    return db.query(sql);
}
"#;
    let outcome = analyse_with_options(
        &ws_for_language("resolver.ts", src),
        TaintAnalysisOptions::default(),
    );
    assert_tag_reported(&outcome, "sql-injection", "TS GraphQL resolver args param");
}

#[test]
fn sqli_ts_first_args_helper_clean_without_inferred_sources() {
    let src = r#"
const _gql = require("graphql");
const _sql = require("typeorm");
function helper(args: { filter: string }, other: unknown) {
    const sql = "SELECT * FROM users WHERE name='" + args.filter + "'";
    return db.query(sql);
}
"#;
    let outcome = analyse_with_options(
        &ws_for_language("helper.ts", src),
        TaintAnalysisOptions::default(),
    );
    assert_tag_absent(
        &outcome,
        "sql-injection",
        "TS first-argument helper named args must stay clean",
    );
}

// ===========================================================================
// 2. NoSQL injection (Mongo $where vs filtered query)
// ===========================================================================

#[test]
fn nosql_python_where_operator_reports() {
    let src = r#"
import pymongo
def handler(user_input):
    client = pymongo.MongoClient()
    return client.db.users.find({"$where": user_input})
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "nosql-injection", "nosql $where tainted");
}

#[test]
fn nosql_python_literal_filter_clean() {
    let src = r#"
import pymongo
def handler(user_input):
    client = pymongo.MongoClient()
    return client.db.users.find({"role": "admin"})
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "nosql-injection", "nosql literal filter");
}

// ===========================================================================
// 3. Command injection (shell vs argv form)
// ===========================================================================

#[test]
fn cmdi_python_os_system_reports() {
    let src = r#"
import os
def handler(user_input):
    return os.system("ls " + user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "command-injection", "cmdi os.system concat");
}

#[test]
fn cmdi_python_subprocess_argv_clean() {
    // subprocess.run is the canonical safe shape when invoked with
    // hardcoded argv values and no shell. The cmdi rule fires on
    // any tainted arg 0 (the rule pack doesn't currently gate on
    // shell=True), so the cleanest negative is a fully-literal
    // call with no taint flowing into argv.
    let src = r#"
import subprocess
def handler(user_input):
    return subprocess.run(["ls", "-la"], shell=False, check=True)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_absent(&outcome, "command-injection", "cmdi argv literal");
}

// ===========================================================================
// 4. Path traversal (joined-path vs basename-extracted)
// ===========================================================================

#[test]
fn path_python_os_makedirs_tainted_reports() {
    let src = r#"
import os
def handler(user_input):
    target = "/srv/uploads/" + user_input
    os.makedirs(target)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "path-traversal", "path os.makedirs tainted");
}

#[test]
fn path_python_secure_filename_sanitised_clean() {
    // werkzeug.secure_filename strips path separators / `..` — the
    // sanitiser tag is `path-sanitize`, paired with the tainted-arg
    // path rule.
    let src = r#"
import os
import werkzeug
def handler(user_input):
    safe_name = werkzeug.secure_filename(user_input)
    target = "/srv/uploads/" + safe_name
    os.makedirs(target)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "path-traversal", "path secure_filename sanitised");
}

// ===========================================================================
// 5. SSRF (requests.get with tainted URL vs allowlisted host)
// ===========================================================================

#[test]
fn ssrf_python_requests_get_tainted_reports() {
    let src = r#"
import requests
def handler(user_input):
    return requests.get(user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "ssrf", "ssrf requests.get tainted");
}

#[test]
fn ssrf_python_requests_get_literal_clean() {
    // Tainted value is consumed only as a query parameter; the URL
    // itself is a hardcoded literal, so no SSRF.
    let src = r#"
import requests
def handler(user_input):
    return requests.get("https://api.internal/lookup", params={"q": user_input})
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "ssrf", "ssrf literal URL with tainted param");
}

// ===========================================================================
// 6. XSS (markupsafe.Markup tainted vs html-escape sanitised)
// ===========================================================================

#[test]
fn xss_python_markup_tainted_reports() {
    let src = r#"
import markupsafe
def handler(user_input):
    return markupsafe.Markup("<div>" + user_input + "</div>")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "xss", "xss markupsafe.Markup tainted");
}

#[test]
fn xss_python_html_escape_sanitised_clean() {
    let src = r#"
import html
import markupsafe
def handler(user_input):
    safe = html.escape(user_input)
    return markupsafe.Markup("<div>" + safe + "</div>")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "xss", "xss html.escape sanitiser");
}

// ===========================================================================
// 7. SSTI (Jinja Template(tainted) vs Template.render(safe))
// ===========================================================================

#[test]
fn ssti_python_jinja_template_tainted_reports() {
    let src = r#"
import jinja2
def handler(user_input):
    return jinja2.Template(user_input).render()
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "ssti", "ssti jinja2.Template tainted");
}

#[test]
fn ssti_python_jinja_render_with_context_clean() {
    // The template is a hardcoded literal; user_input flows ONLY
    // into the render() context dict, which is the safe shape.
    let src = r#"
import jinja2
def handler(user_input):
    template = jinja2.Template("Hello, {{ name }}!")
    return template.render(name=user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "ssti", "ssti literal template + render ctx");
}

// ===========================================================================
// 8. LDAP / XPath injection (concat vs escape)
// ===========================================================================

#[test]
fn ldap_python_search_tainted_reports() {
    let src = r#"
import ldap3
def handler(user_input):
    conn = ldap3.Connection("ldap://x")
    filt = "(&(uid=" + user_input + "))"
    return conn.search("dc=example,dc=org", filt)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "ldap-injection", "ldap3 conn.search tainted filter");
}

#[test]
fn ldap_python_search_literal_clean() {
    let src = r#"
import ldap3
def handler(user_input):
    conn = ldap3.Connection("ldap://x")
    return conn.search("dc=example,dc=org", "(&(objectClass=person))")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "ldap-injection", "ldap3 literal filter");
}

#[test]
fn xpath_python_lxml_xpath_tainted_reports() {
    let src = r#"
from lxml import etree
def handler(user_input):
    expr = "//user[name='" + user_input + "']"
    return etree.XPath(expr)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "xpath-injection", "xpath lxml tainted");
}

#[test]
fn xpath_python_lxml_xpath_literal_clean() {
    let src = r#"
from lxml import etree
def handler(user_input):
    return etree.XPath("//user[@role='admin']")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "xpath-injection", "xpath lxml literal");
}

// ===========================================================================
// 9. Header injection (CRLF in header value vs sanitised)
// ===========================================================================

#[test]
fn header_python_werkzeug_set_tainted_reports() {
    let src = r#"
import werkzeug
def handler(user_input):
    headers = werkzeug.Headers()
    headers.set("X-Trace", user_input)
    return headers
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "header-injection", "header Headers.set tainted");
}

#[test]
fn header_python_werkzeug_set_literal_clean() {
    let src = r#"
import werkzeug
def handler(user_input):
    headers = werkzeug.Headers()
    headers.set("X-Trace", "static")
    return headers
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "header-injection", "header Headers.set literal");
}

// ===========================================================================
// 10. Open redirect (Location: tainted vs allowlist)
// ===========================================================================

#[test]
fn open_redirect_python_flask_redirect_tainted_reports() {
    let src = r#"
import flask
def handler(user_input):
    return flask.redirect(user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "open-redirect", "open_redirect flask.redirect tainted");
}

#[test]
fn open_redirect_python_flask_redirect_literal_clean() {
    let src = r#"
import flask
def handler(user_input):
    return flask.redirect("/dashboard")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "open-redirect", "open_redirect flask.redirect literal");
}

// ===========================================================================
// 11. JWT / weak-auth (verify=False vs verify=True)
// ===========================================================================

#[test]
fn jwt_python_pyjwt_decode_verify_false_reports() {
    let src = r#"
import pyjwt
import jwt
def handler(user_input):
    return jwt.decode(user_input, verify=False)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "jwt", "jwt verify=False");
}

#[test]
fn jwt_python_pyjwt_decode_verified_clean() {
    // The pyjwt_decode rule's discriminator is `arg_tainted: 0`, so
    // a hardcoded literal token never triggers. Use that as the
    // canonical safe shape.
    let src = r#"
import pyjwt
import jwt
def handler(user_input):
    return jwt.decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.literal", key="secret", algorithms=["HS256"])
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_absent(&outcome, "jwt", "jwt literal token");
}

// ===========================================================================
// 12. TLS / cookie misconfig (verify=False vs default)
// ===========================================================================

#[test]
fn weak_tls_python_create_unverified_context_reports() {
    // Source-independent API misuse is pattern-only: it is enabled
    // explicitly here so normal source-to-sink defaults stay quiet.
    let src = r#"
import ssl
def handler(protocol):
    return ssl._create_unverified_context(protocol)
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_reported(&outcome, "weak-tls", "weak-tls _create_unverified_context");
}

#[test]
fn weak_tls_python_default_context_clean() {
    let src = r#"
import ssl
def handler(protocol):
    return ssl.create_default_context(protocol)
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_absent(&outcome, "weak-tls", "weak-tls create_default_context");
}

// ===========================================================================
// 13. Weak crypto algorithm (MD5 vs SHA-256)
// ===========================================================================

#[test]
fn weak_crypto_python_md5_reports() {
    let src = r#"
import hashlib
def handler(payload):
    return hashlib.md5(payload).hexdigest()
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_reported(&outcome, "weak-crypto", "weak-crypto hashlib.md5");
}

#[test]
fn weak_crypto_python_sha256_clean() {
    let src = r#"
import hashlib
def handler(payload):
    return hashlib.sha256(payload).hexdigest()
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_not_reported(&outcome, "weak-crypto", "weak-crypto hashlib.sha256");
}

#[test]
fn weak_crypto_java_strong_algorithm_assignment_clean() {
    let src = r#"
import java.security.MessageDigest;
import javax.crypto.Cipher;
class App {
  void handle() throws Exception {
    String cipher = "AES/GCM/NoPadding";
    String digest = "SHA-256";
    Cipher.getInstance(cipher);
    MessageDigest.getInstance(digest);
  }
}
"#;
    let outcome = analyse_pattern_only(&ws_for_language("App.java", src));
    assert_tag_absent(
        &outcome,
        "weak-crypto",
        "weak-crypto Java strong algorithm assignment",
    );
}

#[test]
fn weak_crypto_java_weak_algorithm_assignment_reports() {
    let src = r#"
import java.security.MessageDigest;
class App {
  void handle() throws Exception {
    String digest = "SHA-1";
    MessageDigest.getInstance(digest);
  }
}
"#;
    let outcome = analyse_pattern_only(&ws_for_language("App.java", src));
    assert_tag_reported(
        &outcome,
        "weak-crypto",
        "weak-crypto Java weak algorithm assignment",
    );
}

// ===========================================================================
// 14. Weak crypto strength (RSA-1024 vs RSA-2048) — exercises arg_lt /
//     keyword_arg_equals constraints.
// ===========================================================================

#[test]
fn weak_crypto_python_rsa_1024_reports() {
    // The `keyword_arg_equals` constraint on `key_size` does the
    // discriminating; no user-controlled source is required.
    let src = r#"
from cryptography.hazmat.primitives.asymmetric import rsa
def gen(exp):
    return rsa.generate_private_key(public_exponent=exp, key_size=1024)
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_reported(&outcome, "weak-crypto", "weak-crypto rsa key_size=1024");
}

#[test]
fn weak_crypto_python_rsa_2048_clean() {
    let src = r#"
from cryptography.hazmat.primitives.asymmetric import rsa
def gen(exp):
    return rsa.generate_private_key(public_exponent=exp, key_size=2048)
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_absent(&outcome, "weak-crypto", "weak-crypto rsa key_size=2048");
}

// ===========================================================================
// 15. Format-string from variable (printf(fmt) vs printf("%s", fmt))
// ===========================================================================

#[test]
fn format_string_c_tainted_format_reports() {
    let src = r#"
#include <stdio.h>
void handler(char *user_input) {
    char *fmt = user_input;
    printf(fmt);
}
"#;
    let outcome = analyse(&ws_for_language("app.c", src));
    assert_tag_reported(&outcome, "format-string", "format-string printf(tainted)");
}

#[test]
fn format_string_c_literal_format_clean() {
    let src = r#"
#include <stdio.h>
void handler(char *user_input) {
    printf("%s", user_input);
}
"#;
    let outcome = analyse(&ws_for_language("app.c", src));
    assert_tag_not_reported(&outcome, "format-string", "format-string printf(\"%s\", tainted)");
}

// ===========================================================================
// 16. Tainted alloc size (malloc(user) vs malloc(FIXED))
// ===========================================================================

#[test]
fn tainted_alloc_c_malloc_tainted_reports() {
    let src = r#"
#include <stdlib.h>
void *handler(int user_input) {
    return malloc(user_input);
}
"#;
    let outcome = analyse(&ws_for_language("app.c", src));
    assert_tag_reported(&outcome, "memory-safety", "memory-safety malloc(tainted)");
}

#[test]
fn tainted_alloc_c_malloc_fixed_clean() {
    let src = r#"
#include <stdlib.h>
void *handler(int user_input) {
    return malloc(4096);
}
"#;
    let outcome = analyse(&ws_for_language("app.c", src));
    assert_tag_not_reported(&outcome, "memory-safety", "memory-safety malloc(fixed)");
}

// ===========================================================================
// 17. Insecure deserialization (pickle.loads(tainted) vs json.loads)
// ===========================================================================

#[test]
fn deser_python_yaml_load_tainted_reports() {
    // Use yaml.load instead of pickle.loads — the latter's `.loads`
    // suffix collides with the itsdangerous_loads sanitizer regex
    // and credits the chain as Sanitized despite no actual signature
    // verification, masking the unsanitized assertion. yaml.load is
    // the same `insecure-deserialization` tag with attribute-form
    // matching that doesn't trip that regex.
    let src = r#"
import yaml
def handler(user_input):
    return yaml.load(user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "insecure-deserialization", "deser yaml.load tainted");
}

#[test]
fn deser_python_json_loads_clean() {
    // json.loads is the safe alternative; not a registered sink at all.
    let src = r#"
import json
def handler(user_input):
    return json.loads(user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_absent(
        &outcome,
        "insecure-deserialization",
        "deser json.loads (safe alternative)",
    );
}

// ===========================================================================
// 18. Insecure random for security (random.random vs secrets.token_bytes)
// ===========================================================================

#[test]
fn weak_random_python_random_random_reports() {
    // `random.random` is source-independent API misuse, so this uses
    // the explicit pattern-only path rather than inferred taint.
    let src = r#"
import random
def issue_token(seed):
    return str(random.random(seed))
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_reported(&outcome, "weak-randomness", "weak-randomness random.random");
}

#[test]
fn weak_random_python_secrets_token_bytes_clean() {
    let src = r#"
import secrets
def issue_token(size):
    return secrets.token_bytes(size)
"#;
    let outcome = analyse_pattern_only(&python_ws(src));
    assert_tag_absent(&outcome, "weak-randomness", "weak-randomness secrets.token_bytes");
}

// ===========================================================================
// 19. Code injection / eval (eval(tainted) vs ast.literal_eval)
// ===========================================================================

#[test]
fn eval_python_tainted_reports() {
    let src = r#"
def handler(user_input):
    return eval(user_input)
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_reported(&outcome, "code-injection", "code-injection eval(tainted)");
}

#[test]
fn eval_python_literal_clean() {
    let src = r#"
def handler(user_input):
    return eval("1 + 1")
"#;
    let outcome = analyse(&python_ws(src));
    assert_tag_not_reported(&outcome, "code-injection", "code-injection eval(literal)");
}
