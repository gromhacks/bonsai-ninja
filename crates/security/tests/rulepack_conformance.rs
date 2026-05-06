//! Whole-rulepack conformance checks for the checked-in
//! `security-patterns/` tree.

use bonsai_security::{
    load_rulepack, match_rule_against_facts, match_rules_against_facts,
    rule::{MatchKind, RuleKind},
    run_taint_analysis, ConstraintKind, Rule, TaintAnalysisOptions,
};
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn repo_root() -> PathBuf {
    let mut p = std::env::current_dir().expect("cwd");
    p.push("../..");
    p.canonicalize().expect("repo root")
}

fn rules_dir() -> PathBuf {
    repo_root().join("security-patterns")
}

fn default_example_path(language: &str) -> String {
    let ext = bonsai_adapters::all_adapters()
        .into_iter()
        .find(|adapter| adapter.language_id().as_str() == language)
        .and_then(|adapter| adapter.file_extensions().first().copied())
        .unwrap_or("txt");
    format!("example.{ext}")
}

fn example_workspace(language: &str, path: Option<&str>, code: &str) -> bonsai_workspace::Workspace {
    let ws = bonsai_workspace::Workspace::new(bonsai_adapters::all_languages_registry());
    let path = path
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| default_example_path(language));
    ws.vfs().write(path, Arc::<str>::from(code));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn rule_uses_taint_dependent_constraint(rule: &Rule) -> bool {
    rule.constraints.iter().any(|constraint| {
        matches!(
            constraint,
            ConstraintKind::ArgTainted { .. }
                | ConstraintKind::AnyArgTainted { .. }
                | ConstraintKind::ReceiverTainted { .. }
        )
    })
}

fn documented_sink_tags() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "access-control",
        "address-squatting",
        "abi-encoding",
        "auth-bypass",
        "atom-exhaustion",
        "cache-poisoning",
        "code-injection",
        "command-injection",
        "context-injection",
        "cookie-misconfig",
        "cors",
        "csrf",
        "cql-injection",
        "cypher-injection",
        "dos",
        "env-leak",
        "ets-match-dos",
        "external-call",
        "file-upload",
        "format-string",
        "graphql",
        "graphql-injection",
        "hash-collision",
        "header-injection",
        "information-exposure",
        "information-disclosure",
        "host-header",
        "insecure-deserialization",
        "integer-overflow",
        "insecure-temp-file",
        "intent-redirection",
        "jndi-injection",
        "jwt",
        "ldap-injection",
        "lfi",
        "log-injection",
        "mass-assignment",
        "memory-safety",
        "nosql-injection",
        "oauth",
        "open-redirect",
        "oracle-manipulation",
        "path-traversal",
        "prototype-pollution",
        "queue-injection",
        "race",
        "readonly-reentrancy",
        "redos",
        "reentrancy",
        "signature-replay",
        "slippage",
        "smtp-injection",
        "sql-injection",
        "sqli",
        "state-manipulation",
        "ssrf",
        "ssti",
        "timeout-bypass",
        "timing-attack",
        "unchecked-return",
        "untrusted-token",
        "weak-auth",
        "weak-crypto",
        "weak-randomness",
        "weak-tls",
        "web-llm",
        "world-writable",
        "xpath-injection",
        "xss",
        "xxe",
        "zip-slip",
    ])
}

fn documented_source_tags() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "block-context",
        "browser-input",
        "calldata",
        "caller-identity",
        "caller-input",
        "caller-value",
        "cli-input",
        "clipboard-input",
        "cloud-event",
        "cloud-input",
        "config-input",
        "db-input",
        "db-row",
        "deep-link",
        "deprecated-auth",
        "env-input",
        "event-input",
        "graphql-input",
        "http-input",
        "hw-input",
        "ipc-input",
        "ipc-message",
        "local-input",
        "net-input",
        "network-input",
        "network-response",
        "oracle-input",
        "push-input",
        "push-message",
        "queue-input",
        "queue-message",
        "rpc-input",
        "socket-input",
        "token-input",
        "ui-input",
        "ws-input",
    ])
}

fn documented_sink_files() -> BTreeSet<&'static str> {
    BTreeSet::from([
        "access.yml",
        "auth.yml",
        "authz.yml",
        "cache_poisoning.yml",
        "cmdi.yml",
        "cookie.yml",
        "cors.yml",
        "cors_csrf.yml",
        "create2.yml",
        "csrf.yml",
        "dex.yml",
        "log_injection.yml",
        "mass_assignment.yml",
        "request_smuggling.yml",
        "crypto.yml",
        "delegatecall.yml",
        "deserialization.yml",
        "downstream.yml",
        "eval.yml",
        "file_upload.yml",
        "format.yml",
        "graphql.yml",
        "hash.yml",
        "hardware.yml",
        "header_injection.yml",
        "host_header.yml",
        "info_disclosure.yml",
        "jwt.yml",
        "ldap.yml",
        "ldapi.yml",
        "llm.yml",
        "math.yml",
        "memory.yml",
        "nosql.yml",
        "oauth.yml",
        "open_redirect.yml",
        "oracle.yml",
        "path.yml",
        "prototype_pollution.yml",
        "queue.yml",
        "race.yml",
        "randomness.yml",
        "redis.yml",
        "redos.yml",
        "reentrancy.yml",
        "regex_dos.yml",
        "selfdestruct.yml",
        "securecookie.yml",
        "signature.yml",
        "smtp_inject.yml",
        "sqli.yml",
        "ssrf.yml",
        "template.yml",
        "tls.yml",
        "token.yml",
        "trustbound.yml",
        "unchecked_return.yml",
        "xpath.yml",
        "xss.yml",
        "xxe.yml",
    ])
}

fn enabled_sink_family_tags(file_name: &str) -> Option<BTreeSet<&'static str>> {
    Some(BTreeSet::from_iter(match file_name {
        "access.yml" => vec!["access-control", "auth-bypass", "jndi-injection"],
        "auth.yml" => vec!["access-control", "jwt", "weak-auth"],
        "authz.yml" => vec!["weak-auth"],
        "cache_poisoning.yml" => vec!["cache-poisoning"],
        "cmdi.yml" => vec!["command-injection", "env-leak"],
        "cookie.yml" => vec!["cookie-misconfig"],
        "cors.yml" | "cors_csrf.yml" => vec!["cors"],
        "create2.yml" => vec!["access-control", "address-squatting"],
        "csrf.yml" => vec!["csrf"],
        "dex.yml" => vec!["slippage"],
        "log_injection.yml" => vec![
            "code-injection",
            "format-string",
            "header-injection",
            "log-injection",
        ],
        "mass_assignment.yml" => vec!["mass-assignment"],
        "request_smuggling.yml" => vec!["header-injection"],
        "crypto.yml" => vec!["timing-attack", "weak-crypto", "weak-randomness"],
        "delegatecall.yml" => vec!["access-control", "code-injection"],
        "deserialization.yml" => vec![
            "atom-exhaustion",
            "ets-match-dos",
            "hash-collision",
            "insecure-deserialization",
        ],
        "downstream.yml" => vec!["information-exposure", "external-call", "state-manipulation"],
        "eval.yml" => vec!["code-injection", "dos", "format-string"],
        "file_upload.yml" => vec!["file-upload"],
        "format.yml" => vec!["format-string"],
        "graphql.yml" => vec!["graphql", "graphql-injection"],
        "hash.yml" => vec!["weak-crypto"],
        "hardware.yml" => vec!["state-manipulation"],
        "header_injection.yml" => vec!["cache-poisoning", "header-injection", "smtp-injection"],
        "host_header.yml" => vec!["host-header"],
        "info_disclosure.yml" => vec!["information-disclosure", "information-exposure"],
        "jwt.yml" => vec!["jwt", "untrusted-token", "signature-replay"],
        "ldap.yml" => vec!["auth-bypass", "ldap-injection"],
        "ldapi.yml" => vec!["ldap-injection"],
        "llm.yml" => vec!["web-llm"],
        "math.yml" => vec!["integer-overflow", "weak-crypto"],
        "memory.yml" => vec!["memory-safety"],
        "nosql.yml" => vec![
            "code-injection",
            "cql-injection",
            "cypher-injection",
            "nosql-injection",
            "sqli",
        ],
        "oauth.yml" => vec!["oauth"],
        "open_redirect.yml" => vec!["open-redirect", "intent-redirection"],
        "oracle.yml" => vec!["oracle-manipulation", "readonly-reentrancy"],
        "path.yml" => vec![
            "insecure-temp-file",
            "lfi",
            "path-traversal",
            "world-writable",
            "zip-slip",
        ],
        "prototype_pollution.yml" => vec!["prototype-pollution"],
        "queue.yml" => vec!["queue-injection"],
        "race.yml" => vec!["race", "timeout-bypass"],
        "randomness.yml" => vec!["weak-randomness"],
        "redis.yml" => vec!["nosql-injection"],
        "reentrancy.yml" => vec!["reentrancy"],
        "redos.yml" => vec!["redos"],
        "regex_dos.yml" => vec!["redos"],
        "selfdestruct.yml" => vec!["access-control"],
        "securecookie.yml" => vec!["cookie-misconfig"],
        "signature.yml" => vec!["abi-encoding", "signature-replay", "hash-collision"],
        "smtp_inject.yml" => vec!["smtp-injection"],
        "sqli.yml" => vec!["sql-injection", "sqli"],
        "ssrf.yml" => vec!["ssrf"],
        "template.yml" => vec!["format-string", "open-redirect", "ssti", "xss"],
        "tls.yml" => vec!["address-squatting", "cors", "weak-tls"],
        "token.yml" => vec!["context-injection", "env-leak", "untrusted-token"],
        "trustbound.yml" => vec!["access-control"],
        "unchecked_return.yml" => vec!["unchecked-return"],
        "xpath.yml" => vec!["xpath-injection"],
        "xss.yml" => vec!["xss", "open-redirect"],
        "xxe.yml" => vec!["xxe"],
        _ => return None,
    }))
}

#[test]
fn enabled_rules_keep_required_metadata() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        match rule.kind {
            RuleKind::Source => {
                if rule.enabled && rule.tag.is_none() {
                    missing.push(format!("source missing tag: {}", rule.id));
                }
                if rule.enabled && rule.trust.is_none() {
                    missing.push(format!("source missing trust: {}", rule.id));
                }
            }
            RuleKind::Sink => {
                if rule.enabled && rule.tag.is_none() {
                    missing.push(format!("sink missing tag: {}", rule.id));
                }
                if rule.enabled && rule.severity.is_none() {
                    missing.push(format!("sink missing severity: {}", rule.id));
                }
            }
            RuleKind::Sanitizer => {
                if rule.enabled && rule.tag.is_none() {
                    missing.push(format!("sanitizer missing tag: {}", rule.id));
                }
            }
        }
    }
    assert!(
        missing.is_empty(),
        "enabled rulepack entries are missing required metadata:\n{}",
        missing.join("\n")
    );
}

#[test]
fn every_source_rule_declares_trust() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind == RuleKind::Source && rule.trust.is_none() {
            missing.push(format!("{} is missing trust metadata", rule.id));
        }
    }
    assert!(
        missing.is_empty(),
        "source rules must declare trust regardless of enabled state:\n{}",
        missing.join("\n")
    );
}

#[test]
fn source_files_match_trust_boundary_split() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut violations = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Source {
            continue;
        }
        let Some(trust) = rule.trust else { continue };
        let Some(file_name) = Path::new(&rule.source_path)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            violations.push(format!(
                "{} has unreadable source path {}",
                rule.id, rule.source_path
            ));
            continue;
        };
        let file_ok = match file_name {
            "remote.yml" | "web_extra.yml" => matches!(
                trust,
                bonsai_security::rule::TrustClass::Remote
                    | bonsai_security::rule::TrustClass::Service
                    | bonsai_security::rule::TrustClass::Database
                    | bonsai_security::rule::TrustClass::Ipc
                    | bonsai_security::rule::TrustClass::Local
            ),
            "cloud.yml" => matches!(trust, bonsai_security::rule::TrustClass::Service),
            "queue.yml" => matches!(
                trust,
                bonsai_security::rule::TrustClass::Service
                    | bonsai_security::rule::TrustClass::Database
                    | bonsai_security::rule::TrustClass::Remote
                    | bonsai_security::rule::TrustClass::Local
            ),
            "cli.yml" | "config.yml" => matches!(
                trust,
                bonsai_security::rule::TrustClass::Local
                    | bonsai_security::rule::TrustClass::Config
                    | bonsai_security::rule::TrustClass::Physical
                    | bonsai_security::rule::TrustClass::Ipc
            ),
            "database.yml" => matches!(trust, bonsai_security::rule::TrustClass::Database),
            "ipc.yml" => matches!(trust, bonsai_security::rule::TrustClass::Ipc),
            "physical.yml" => matches!(trust, bonsai_security::rule::TrustClass::Physical),
            "tx.yml" | "block.yml" | "calldata.yml" => rule.language == "solidity",
            "embedded.yml" | "windows.yml" | "linux.yml" | "macos.yml" | "android.yml" | "ios.yml" => true,
            other => {
                violations.push(format!("{} lives in unexpected source file `{other}`", rule.id));
                true
            }
        };
        if !file_ok {
            violations.push(format!(
                "{} has trust {:?} but lives in {}",
                rule.id, trust, file_name
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "source files drifted from the documented trust-boundary split:\n{}",
        violations.join("\n")
    );
}

#[test]
fn non_solidity_languages_keep_canonical_source_files() {
    let langs_dir = rules_dir().join("langs");
    let required: BTreeSet<&str> = BTreeSet::from(["cli.yml", "cloud.yml", "queue.yml", "remote.yml"]);
    let mut missing = Vec::new();

    for entry in std::fs::read_dir(&langs_dir).expect("read langs dir") {
        let entry = entry.expect("lang entry");
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let lang = entry.file_name().to_string_lossy().into_owned();
        if lang == "solidity" {
            continue;
        }
        let sources = path.join("sources");
        let present: BTreeSet<String> = std::fs::read_dir(&sources)
            .expect("read sources dir")
            .filter_map(|ent| {
                let ent = ent.ok()?;
                let name = ent.file_name().to_string_lossy().into_owned();
                ent.path().is_file().then_some(name)
            })
            .collect();
        for req in &required {
            if !present.contains(*req) {
                missing.push(format!("{lang} missing sources/{req}"));
            }
        }
    }

    assert!(
        missing.is_empty(),
        "non-solidity languages drifted from the canonical sources/ split:\n{}",
        missing.join("\n")
    );
}

#[test]
fn audited_languages_only_enable_param_rules_for_real_identifiers() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let audited: BTreeSet<&str> = BTreeSet::from(["java", "kotlin", "csharp", "javascript", "typescript"]);
    let invalid_handler_names: BTreeSet<&str> =
        BTreeSet::from(["handleDelivery", "handleRequest", "service"]);
    let mut violations = Vec::new();

    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Source || !rule.enabled || !audited.contains(rule.language.as_str()) {
            continue;
        }
        if rule.match_spec.kind != MatchKind::Param {
            continue;
        }
        let Some(name) = rule
            .match_spec
            .target
            .as_ref()
            .and_then(|target| target.name.as_deref())
        else {
            continue;
        };
        let starts_upper = name
            .chars()
            .next()
            .map(|c| c.is_ascii_uppercase())
            .unwrap_or(false);
        if starts_upper || invalid_handler_names.contains(name) {
            violations.push(format!(
                "{} uses enabled `kind: param` target `{}` in {}, but these adapters only index parameter identifiers",
                rule.id, name, rule.language
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "enabled param rules in audited languages must target real parameter identifiers:\n{}",
        violations.join("\n")
    );
}

#[test]
fn c_and_cpp_argv_sources_are_only_main_argv() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");

    for (lang, file, rule_id, main_code, helper_code) in [
        (
            "c",
            "demo.c",
            "c.input.argv_param",
            "int main(int argc, char **argv) { return argc; }\n",
            "int ACLSelectorCheckCmd(void *selector, void *cmd, void **argv, int argc) { return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.input.argv_param",
            "int main(int argc, char **argv) { return argc; }\n",
            "int helper(int argc, char **argv) { return argc; }\n",
        ),
    ] {
        let rule = pack.find_rule_by_id(rule_id).expect("argv source rule");
        let main_ws = example_workspace(lang, Some(file), main_code);
        assert!(
            !match_rule_against_facts(&main_ws, rule).is_empty(),
            "{rule_id} must still match the process entry-point argv"
        );

        let helper_ws = example_workspace(lang, Some(file), helper_code);
        assert!(
            match_rule_against_facts(&helper_ws, rule).is_empty(),
            "{rule_id} must not treat arbitrary helper parameters named argv as process input"
        );
    }
}

#[test]
fn c_main_argv_reachability_does_not_taint_sizeof_allocator_size() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let ws = example_workspace(
        "c",
        Some("demo.c"),
        r#"
void *malloc(unsigned long size);

static int moduleTempClientCap;

void moduleReleaseTempClient(void *c) {
    if (moduleTempClientCap == 0) {
        moduleTempClientCap = 32;
    }
    malloc(sizeof(c) * moduleTempClientCap);
}

int main(int argc, char **argv) {
    moduleReleaseTempClient(argv);
    return argc;
}
"#,
    );
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");

    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.finding.sink.rule_id != "c.memory.malloc_tainted_size"),
        "argv can reach the helper, but sizeof(c) * moduleTempClientCap is not an attacker-controlled allocation size: {:#?}",
        report.findings
    );
}

#[test]
fn caller_scheduling_preserves_source_attribution() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let ws = example_workspace(
        "python",
        Some("demo.py"),
        r#"
import os

def unrelated_source():
    return os.environ["OTHER"]

def mid():
    return os.environ["CMD"]

def top():
    cmd = mid()
    os.system(cmd)
"#,
    );
    let report = run_taint_analysis(
        &ws,
        &pack,
        TaintAnalysisOptions {
            include_inferred_sources: false,
            ..TaintAnalysisOptions::default()
        },
    )
    .expect("taint analysis");

    let top_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| {
            finding.finding.sink.rule_id == "python.cmdi.os_system"
                && finding.finding.chain_display.iter().any(|hop| hop == "top")
        })
        .collect();

    assert!(
        top_findings
            .iter()
            .any(|finding| finding.finding.source.enclosing_fn.as_deref() == Some("mid")),
        "real source must be attributed to the top -> mid chain: {:#?}",
        report.findings
    );
    assert!(
        top_findings
            .iter()
            .all(|finding| finding.finding.source.enclosing_fn.as_deref() != Some("unrelated_source")),
        "caller scheduling must not borrow an unrelated source for the chain: {:#?}",
        report.findings
    );
}

#[test]
fn c_and_cpp_bounded_copy_rules_require_tainted_length_argument() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");

    for (lang, file, rule_id, positive, fixed) in [
        (
            "c",
            "demo.c",
            "c.memory.memcpy",
            "void *memcpy(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { char dst[64]; char src[64]; memcpy(dst, src, argv); return argc; }\n",
            "#define FIXED_LEN 40\nvoid *memcpy(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { void *it_node = 0; void **cp = (void**)argv; memcpy(argv, argv, FIXED_LEN); memcpy(&it_node, cp, sizeof(it_node)); memcpy(cp, &it_node, sizeof(it_node)); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.memmove",
            "void *memmove(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { char dst[64]; char src[64]; memmove(dst, src, argv); return argc; }\n",
            "#define FIXED_LEN 40\nvoid *memmove(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { void *it_node = 0; void **cp = (void**)argv; memmove(argv, argv, FIXED_LEN); memmove(&it_node, cp, sizeof(it_node)); memmove(cp, &it_node, sizeof(it_node)); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.memcpy",
            "void *memcpy(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { char dst[64]; char src[64]; memcpy(dst, src, argv); return argc; }\n",
            "#define FIXED_LEN 40\nvoid *memcpy(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { void *it_node = 0; void **cp = (void**)argv; memcpy(argv, argv, FIXED_LEN); memcpy(&it_node, cp, sizeof(it_node)); memcpy(cp, &it_node, sizeof(it_node)); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.memmove",
            "void *memmove(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { char dst[64]; char src[64]; memmove(dst, src, argv); return argc; }\n",
            "#define FIXED_LEN 40\nvoid *memmove(void *dst, const void *src, unsigned long n);\nint main(int argc, char **argv) { void *it_node = 0; void **cp = (void**)argv; memmove(argv, argv, FIXED_LEN); memmove(&it_node, cp, sizeof(it_node)); memmove(cp, &it_node, sizeof(it_node)); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.bcopy",
            "void bcopy(const void *src, void *dst, unsigned long n);\nint main(int argc, char **argv) { char dst[64]; char src[64]; bcopy(src, dst, argv); return argc; }\n",
            "#define FIXED_LEN 40\nvoid bcopy(const void *src, void *dst, unsigned long n);\nint main(int argc, char **argv) { void *it_node = 0; void **cp = (void**)argv; bcopy(argv, argv, FIXED_LEN); bcopy(cp, &it_node, sizeof(it_node)); bcopy(&it_node, cp, sizeof(it_node)); return argc; }\n",
        ),
    ] {
        let positive_ws = example_workspace(lang, Some(file), positive);
        let positive_report = run_taint_analysis(
            &positive_ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: false,
                ..TaintAnalysisOptions::default()
            },
        )
        .expect("positive taint analysis");
        assert!(
            positive_report
                .findings
                .iter()
                .any(|finding| finding.finding.sink.rule_id == rule_id),
            "{rule_id} must report when the bounded-copy length argument itself is tainted: {:#?}",
            positive_report.findings
        );

        let fixed_ws = example_workspace(lang, Some(file), fixed);
        let fixed_report = run_taint_analysis(
            &fixed_ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: false,
                ..TaintAnalysisOptions::default()
            },
        )
        .expect("fixed-length taint analysis");
        assert!(
            fixed_report
                .findings
                .iter()
                .all(|finding| finding.finding.sink.rule_id != rule_id),
            "{rule_id} must not report just because dst/src are tainted when length is fixed: {:#?}",
            fixed_report.findings
        );
    }
}

#[test]
fn c_and_cpp_allocation_rules_require_size_bearing_argument() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");

    for (lang, file, rule_id, positive, negative) in [
        (
            "c",
            "demo.c",
            "c.memory.malloc_tainted_size",
            "void *malloc(unsigned long size);\nint main(int argc, char **argv) { malloc(argv); return argc; }\n",
            "void *malloc(unsigned long size);\nint main(int argc, char **argv) { unsigned long cap = 32; malloc(sizeof(argv) * cap); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.realloc_tainted_size",
            "void *realloc(void *ptr, unsigned long size);\nint main(int argc, char **argv) { void *ptr = 0; realloc(ptr, argv); return argc; }\n",
            "void *realloc(void *ptr, unsigned long size);\nint main(int argc, char **argv) { realloc(argv, 64); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.calloc_tainted_size",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(argv, 8); return argc; }\n",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, 8); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.calloc_tainted_element_size",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, argv); return argc; }\n",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, 8); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.aligned_alloc_tainted_size",
            "void *aligned_alloc(unsigned long alignment, unsigned long size);\nint main(int argc, char **argv) { aligned_alloc(16, argv); return argc; }\n",
            "void *aligned_alloc(unsigned long alignment, unsigned long size);\nint main(int argc, char **argv) { aligned_alloc(argv, 64); return argc; }\n",
        ),
        (
            "c",
            "demo.c",
            "c.memory.alloca",
            "void *alloca(unsigned long size);\nint main(int argc, char **argv) { alloca(argv); return argc; }\n",
            "void *alloca(unsigned long size);\nint main(int argc, char **argv) { alloca(64); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.malloc_tainted_size",
            "void *malloc(unsigned long size);\nint main(int argc, char **argv) { malloc(argv); return argc; }\n",
            "void *malloc(unsigned long size);\nint main(int argc, char **argv) { unsigned long cap = 32; malloc(sizeof(argv) * cap); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.realloc_tainted_size",
            "void *realloc(void *ptr, unsigned long size);\nint main(int argc, char **argv) { void *ptr = 0; realloc(ptr, argv); return argc; }\n",
            "void *realloc(void *ptr, unsigned long size);\nint main(int argc, char **argv) { realloc(argv, 64); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.calloc_tainted_size",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(argv, 8); return argc; }\n",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, 8); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.calloc_tainted_element_size",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, argv); return argc; }\n",
            "void *calloc(unsigned long count, unsigned long size);\nint main(int argc, char **argv) { calloc(32, 8); return argc; }\n",
        ),
        (
            "cpp",
            "demo.cpp",
            "cpp.memory.alloca",
            "void *alloca(unsigned long size);\nint main(int argc, char **argv) { alloca(argv); return argc; }\n",
            "void *alloca(unsigned long size);\nint main(int argc, char **argv) { alloca(64); return argc; }\n",
        ),
    ] {
        let positive_ws = example_workspace(lang, Some(file), positive);
        let positive_report = run_taint_analysis(
            &positive_ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: false,
                ..TaintAnalysisOptions::default()
            },
        )
        .expect("positive allocation taint analysis");
        assert!(
            positive_report
                .findings
                .iter()
                .any(|finding| finding.finding.sink.rule_id == rule_id),
            "{rule_id} must report when its size-bearing argument is tainted: {:#?}",
            positive_report.findings
        );

        let negative_ws = example_workspace(lang, Some(file), negative);
        let negative_report = run_taint_analysis(
            &negative_ws,
            &pack,
            TaintAnalysisOptions {
                include_inferred_sources: false,
                ..TaintAnalysisOptions::default()
            },
        )
        .expect("negative allocation taint analysis");
        assert!(
            negative_report
                .findings
                .iter()
                .all(|finding| finding.finding.sink.rule_id != rule_id),
            "{rule_id} must not report when taint is only on pointer/alignment/context or value-free sizeof operands: {:#?}",
            negative_report.findings
        );
    }
}

#[test]
fn canonical_sanitizer_tags_stay_canonical() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let canonical: BTreeSet<&str> = BTreeSet::from([
        "auth-sanitizer",
        "allowlist-validate",
        "base64-encode",
        "bounds-check",
        "char-allowlist",
        "constant-time",
        "constant-time-compare",
        "controlled-exposure",
        "cookie-secure",
        "crypto-bounds",
        "crypto-mode",
        "csrf-protect",
        "css-encode",
        "db-bind-parameter",
        "deser-secure",
        "format-string",
        "hash",
        "html-encode",
        "html-sanitize",
        "js-encode",
        "jwt-verify",
        "kdf",
        "ldap-escape",
        "lock-acquire",
        "non-sanitizer",
        "nosql-parameter",
        "nosql-sanitize",
        "numeric-coerce",
        "open-redirect-sanitize",
        "passthrough-decode",
        "passthrough-encode",
        "password-verify",
        "path-sanitize",
        "rate-limit",
        "regex-escape",
        "regex-validate",
        "same-origin-path",
        "schema-validate",
        "shell-escape",
        "signature-sanitizer",
        "signature-verify",
        "signed-token-verify",
        "sql-escape",
        "sql-parameter",
        "sql-parameterize",
        "ssrf-sanitize",
        "url-build",
        "url-decode",
        "url-encode",
        "validation",
        "xss-sanitize",
        "xpath-parameter",
        "xxe-sanitizer",
        "zip-slip-guard",
        "header-sanitize",
    ]);
    let mut invalid = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sanitizer {
            continue;
        }
        let Some(tag) = rule.tag.as_deref() else { continue };
        if !canonical.contains(tag) {
            invalid.push(format!("{} uses non-canonical sanitizer tag `{tag}`", rule.id));
        }
    }
    assert!(
        invalid.is_empty(),
        "sanitizer tags drifted from the documented canonical set:\n{}",
        invalid.join("\n")
    );
}

#[test]
fn legacy_sink_tag_aliases_are_not_present() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut legacy = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sink {
            continue;
        }
        match rule.tag.as_deref() {
            Some("deserialization") => legacy.push(format!(
                "{} uses `deserialization`; use `insecure-deserialization`",
                rule.id
            )),
            Some("weak-random") => {
                legacy.push(format!("{} uses `weak-random`; use `weak-randomness`", rule.id));
            }
            _ => {}
        }
    }
    assert!(
        legacy.is_empty(),
        "legacy sink tag aliases break exact `--tag` filtering:\n{}",
        legacy.join("\n")
    );
}

#[test]
fn sink_tags_stay_documented() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let documented = documented_sink_tags();
    let mut invalid = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sink {
            continue;
        }
        let Some(tag) = rule.tag.as_deref() else { continue };
        if !documented.contains(tag) {
            invalid.push(format!("{} uses undocumented sink tag `{tag}`", rule.id));
        }
    }
    assert!(
        invalid.is_empty(),
        "sink tag vocabulary drifted from the documented set:\n{}",
        invalid.join("\n")
    );
}

#[test]
fn source_tags_stay_documented() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let documented = documented_source_tags();
    let mut invalid = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Source {
            continue;
        }
        let Some(tag) = rule.tag.as_deref() else { continue };
        if !documented.contains(tag) {
            invalid.push(format!("{} uses undocumented source tag `{tag}`", rule.id));
        }
    }
    assert!(
        invalid.is_empty(),
        "source tag vocabulary drifted from the documented set:\n{}",
        invalid.join("\n")
    );
}

#[test]
fn sink_files_stay_documented() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let documented = documented_sink_files();
    let mut invalid = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sink {
            continue;
        }
        let Some(file_name) = Path::new(&rule.source_path)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            invalid.push(format!(
                "{} has unreadable source path {}",
                rule.id, rule.source_path
            ));
            continue;
        };
        if !documented.contains(file_name) {
            invalid.push(format!(
                "{} lives in undocumented sink file `{file_name}`",
                rule.id
            ));
        }
    }
    assert!(
        invalid.is_empty(),
        "sink file taxonomy drifted from the documented set:\n{}",
        invalid.join("\n")
    );
}

/// Every rule — enabled or not — must carry a non-trivial description.
/// "Trivial" = shorter than 15 characters, which catches one-word
/// placeholders like `"exec()."`, `"copy()."`, `"SHA1.Create."`.
/// Long enough to fit "<api> — <consequence>" which is the minimum
/// PATTERN_GUIDE §Authoring conventions requires.
#[test]
fn every_rule_has_a_non_trivial_description() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut thin = Vec::new();
    for rule in pack.all_rules() {
        let trimmed = rule.description.trim();
        if trimmed.is_empty() {
            thin.push(format!("{}: no description", rule.id));
        } else if trimmed.len() < 15 {
            thin.push(format!("{}: description `{trimmed}` too short", rule.id));
        }
    }
    assert!(
        thin.is_empty(),
        "rules with trivial descriptions — expand the `why` per PATTERN_GUIDE:\n{}",
        thin.join("\n")
    );
}

/// Every sink rule must carry a CWE code. Findings bubble CWE up to
/// the security-narrative header, and an unlabelled finding tells a
/// reviewer nothing about the vuln class.
#[test]
fn every_sink_rule_carries_a_cwe() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sink {
            continue;
        }
        if rule.cwe.is_empty() {
            missing.push(rule.id.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "sink rules missing CWE:\n{}",
        missing.join("\n")
    );
}

/// Every rule id must be dotted lowercase — the `[a-z][a-z0-9_]*`
/// per-segment pattern PATTERN_GUIDE §Rule schema documents. CamelCase
/// leaks upstream-API casing (`dangerouslySetInnerHTML`) into finding
/// ids which are user-visible; snake_case is the stable form.
#[test]
fn every_rule_id_is_dotted_lowercase() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let id_re = regex::Regex::new(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$").unwrap();
    let mut bad = Vec::new();
    for rule in pack.all_rules() {
        if !id_re.is_match(&rule.id) {
            bad.push(rule.id.clone());
        }
    }
    assert!(
        bad.is_empty(),
        "rule ids must be dotted lowercase (PATTERN_GUIDE §Rule schema):\n{}",
        bad.join("\n")
    );
}

#[test]
fn rulepack_validator_accepts_checked_in_pack() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let report = bonsai_security::validate_pack(
        &pack,
        &bonsai_security::PackInventoryOptions::default(),
        bonsai_adapters::all_languages_registry(),
    );
    assert!(
        report.valid,
        "checked-in rulepack validator issues:\n{:#?}",
        report.issues
    );
    assert_eq!(report.errors, 0, "validator errors: {:#?}", report.issues);
}

#[test]
fn every_rule_yaml_declares_matching_language() {
    // Each shipped rule lives under
    // `security-patterns/langs/<lang>/...` AND must declare
    // `language: <lang>` in its YAML body. The loader rejects
    // mismatches at parse time, so this test is really a check that
    // the YAML field is *present* (the directory provides the value
    // when the field is missing — but we want every shipped rule to
    // carry the field so flat-layout / custom-pack consumers see a
    // uniform schema).
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let rules: Vec<&Rule> = pack.all_rules();
    let missing: Vec<String> = rules
        .par_iter()
        .filter_map(|rule| {
            let text = std::fs::read_to_string(&rule.source_path)
                .unwrap_or_else(|e| panic!("read {}: {e}", rule.source_path));
            let needle = format!("- id: {}", rule.id);
            let rule_block_start = text.find(&needle)?;
            // Look from `- id: <this>` up to the next `- id:` (or EOF)
            // for a `  language: <lang>` line.
            let after = &text[rule_block_start + needle.len()..];
            let block_end = after.find("\n- id: ").unwrap_or(after.len());
            let block = &after[..block_end];
            let want_line = format!("\n  language: {}\n", rule.language);
            if !block.contains(&want_line) {
                Some(format!(
                    "{} ({}) is missing or has wrong `language: {}` in YAML body",
                    rule.id, rule.source_path, rule.language
                ))
            } else {
                None
            }
        })
        .collect();
    let body_missing: Vec<String> = rules
        .par_iter()
        .filter(|rule| {
            let text = std::fs::read_to_string(&rule.source_path).unwrap_or_default();
            let needle = format!("- id: {}", rule.id);
            !text.contains(&needle)
        })
        .map(|rule| format!("{}: rule body not found in {}", rule.id, rule.source_path))
        .collect();
    let mut all_missing = missing;
    all_missing.extend(body_missing);
    assert!(
        all_missing.is_empty(),
        "rules missing canonical YAML `language:` field:\n{}",
        all_missing.join("\n")
    );
}

#[test]
fn declared_rule_match_examples_fire() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    // Flatten the (rule, example) work upfront so rayon can balance
    // across all examples, not just rules — some rules carry many
    // examples while others carry one. Disabled rules' examples are
    // aspirational documentation, not live contract; skip those.
    let work: Vec<(&Rule, &bonsai_security::rule::RuleMatchExample)> = pack
        .all_rules()
        .into_iter()
        .filter(|rule| rule.enabled)
        .flat_map(|rule| rule.match_examples.iter().map(move |ex| (rule, ex)))
        .collect();
    let example_count = work.len();
    let failures: Vec<String> = work
        .par_iter()
        .filter_map(|(rule, example)| {
            if example.expect_no_match || rule_uses_taint_dependent_constraint(rule) {
                return None;
            }
            let ws = example_workspace(&rule.language, example.path.as_deref(), &example.code);
            let matches = match_rule_against_facts(&ws, rule);
            if matches.is_empty() {
                return Some(format!(
                    "{} example `{}` produced no matches",
                    rule.id,
                    example.name.as_deref().unwrap_or("<unnamed>")
                ));
            }
            for expected in &example.expect_match_text {
                if !matches.iter().any(|m| m.match_text == *expected) {
                    let got = matches
                        .iter()
                        .map(|m| m.match_text.as_str())
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Some(format!(
                        "{} example `{}` expected match_text `{expected}`, got [{got}]",
                        rule.id,
                        example.name.as_deref().unwrap_or("<unnamed>")
                    ));
                }
            }
            None
        })
        .collect();

    assert!(example_count > 0, "rulepack must include YAML match_examples");
    assert!(
        failures.is_empty(),
        "rule match_examples drifted from adapter facts:\n{}",
        failures.join("\n")
    );
}

#[test]
fn enabled_rule_match_examples_do_not_collide() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let rules = pack.all_rules();
    let enabled_rules: Vec<_> = rules.iter().copied().filter(|rule| rule.enabled).collect();
    let mut collisions = Vec::new();
    let mut example_count = 0usize;

    for owner in &enabled_rules {
        let peer_rules: Vec<_> = enabled_rules
            .iter()
            .copied()
            .filter(|candidate| candidate.language == owner.language && candidate.kind == owner.kind)
            .collect();
        for example in &owner.match_examples {
            example_count += 1;
            if example.expect_no_match || rule_uses_taint_dependent_constraint(owner) {
                continue;
            }
            let ws = example_workspace(&owner.language, example.path.as_deref(), &example.code);
            let matches = match_rules_against_facts(&ws, &peer_rules);
            for hit in matches {
                if hit.rule_id == owner.id {
                    continue;
                }
                collisions.push(format!(
                    "{} example `{}` also matched {} ({:?}) at {}:{} text `{}`",
                    owner.id,
                    example.name.as_deref().unwrap_or("<unnamed>"),
                    hit.rule_id,
                    owner.kind,
                    hit.file,
                    hit.line,
                    hit.match_text
                ));
            }
        }
    }

    assert!(
        example_count > 0,
        "enabled rulepack entries must include YAML match_examples"
    );
    assert!(
        collisions.is_empty(),
        "enabled rule match_examples collide; merge duplicate rules or tighten their match clauses:\n{}",
        collisions.join("\n")
    );
}

#[test]
fn enabled_rules_must_have_match_examples() {
    // Every enabled rule (source, sink, sanitizer) must ship at
    // least one `match_examples` entry. Without an example we
    // can't assert the rule fires on its canonical shape, can't
    // catch adapter drift, and can't validate the
    // OnlyWhenPackaged per-file gate. Hard-fails the rule pack.
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        if !rule.enabled || !rule.match_examples.is_empty() {
            continue;
        }
        missing.push(format!(
            "{} [{}] ({})",
            rule.id,
            match rule.kind {
                RuleKind::Source => "source",
                RuleKind::Sink => "sink",
                RuleKind::Sanitizer => "sanitizer",
            },
            rule.source_path
        ));
    }
    assert!(
        missing.is_empty(),
        "{} enabled rules without match_examples:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn packaged_rule_examples_include_real_imports() {
    // Any rule that declares `packages:` / `imports:` / `modules:`
    // — the signals the matcher's per-file `OnlyWhenPackaged`
    // gate consults — must embed at least one signal string in
    // every positive `match_examples[*].code` body. Otherwise the rule's
    // own firing example fails its own per-file gate and the rule won't
    // fire on its canonical shape. Negative examples may omit the package
    // signal when they are only demonstrating a literal/clean operand.
    //
    // The check is a substring-match on the rule's signal text.
    // `import asyncpg`, `from asyncpg import X`,
    // `import * as asyncpg from "asyncpg"`, `#include <sqlite3.h>`
    // (matches `sqlite3`), `use DBI;`, `import 'package:foo/foo.dart'`
    // all satisfy the same textual contract.
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut missing = Vec::new();
    for rule in pack.all_rules() {
        if !rule.enabled {
            continue;
        }
        let signals: Vec<&str> = rule
            .packages
            .iter()
            .chain(rule.imports.iter())
            .chain(rule.modules.iter())
            .map(String::as_str)
            .filter(|s| !s.is_empty())
            .collect();
        if signals.is_empty() {
            continue;
        }
        for (i, example) in rule.match_examples.iter().enumerate() {
            if example.expect_no_match {
                continue;
            }
            let mentions_signal = signals.iter().any(|sig| example.code.contains(sig));
            if !mentions_signal {
                missing.push(format!(
                    "{} [{}] match_examples[{}] `{}` does not mention any of {:?} — \
                     OnlyWhenPackaged gate will never fire on this example",
                    rule.id,
                    rule.source_path,
                    i,
                    example.name.as_deref().unwrap_or("<unnamed>"),
                    signals
                ));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "{} packaged-rule examples without an embedded import / package signal:\n{}",
        missing.len(),
        missing.join("\n")
    );
}

#[test]
fn enabled_sink_rules_match_family_file() {
    let pack = load_rulepack(&rules_dir()).expect("rulepack loads");
    let mut invalid = Vec::new();
    for rule in pack.all_rules() {
        if rule.kind != RuleKind::Sink || !rule.enabled {
            continue;
        }
        let Some(tag) = rule.tag.as_deref() else { continue };
        let Some(file_name) = Path::new(&rule.source_path)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            invalid.push(format!(
                "{} has unreadable source path {}",
                rule.id, rule.source_path
            ));
            continue;
        };
        let Some(allowed_tags) = enabled_sink_family_tags(file_name) else {
            invalid.push(format!("{} lives in unexpected sink file `{file_name}`", rule.id));
            continue;
        };
        if !allowed_tags.contains(tag) {
            invalid.push(format!(
                "{} uses tag `{tag}` in {}, expected one of {:?}",
                rule.id, file_name, allowed_tags
            ));
        }
    }
    assert!(
        invalid.is_empty(),
        "enabled sink rules drifted from their family taxonomy:\n{}",
        invalid.join("\n")
    );
}
