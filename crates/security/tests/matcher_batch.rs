use bonsai_lang_api::{DeclKind, LanguageRegistry, Visibility};
use bonsai_security::rule::{
    ArgRegexSpec, ConstraintKind, KeywordArgEqualsSpec, MatchKind, MatchSpec, Rule, RuleConstraint, RuleKind,
    RuleTarget, Severity,
};
use bonsai_security::{
    match_rule_against_facts, match_rules_against_facts, match_rules_against_facts_with_progress,
};
use bonsai_workspace::Workspace;
use std::collections::BTreeSet;
use std::sync::Arc;

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

fn java_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("App.java".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn java_ws_files(files: &[(&str, &str)]) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    for (path, source) in files {
        ws.vfs().write((*path).to_string(), Arc::<str>::from(*source));
    }
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn typescript_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("app.ts".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn javascript_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("app.js".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn csharp_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("App.cs".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn kotlin_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs()
        .write("Handlers.kt".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn objc_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("Example.m".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn php_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("app.php".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn ruby_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("app.rb".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn lua_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("app.lua".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

fn solidity_ws(source: &str) -> Workspace {
    let registry = bonsai_adapters::all_languages_registry();
    let ws = Workspace::new(registry);
    ws.vfs().write("App.sol".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
        let _ = ws.db().import_index(file);
    }
    ws
}

#[test]
fn empty_rule_batches_still_report_file_progress() {
    let ws = python_ws("print('ok')\n");
    let mut ticks = 0usize;

    let matches = match_rules_against_facts_with_progress(&ws, &[], || {
        ticks += 1;
    });

    assert!(matches.is_empty());
    assert_eq!(
        ticks,
        ws.db().global_index().all_files().count(),
        "empty rule selections should still complete the per-file progress bar"
    );
}

#[test]
fn precision_constraints_filter_common_fp_shapes() {
    let ws = python_ws(
        r#"
def printf(fmt, value=None):
    pass

def open(path, mode="r"):
    pass

class Location:
    def replace(self, value):
        pass

class Text:
    def replace(self, value):
        pass

def handler(user_input):
    printf("%s", user_input)
    printf(user_input)
    open("static.txt")
    obj.open(user_input)
    location.replace(user_input)
    text.replace(user_input)
"#,
    );

    let mut fmt = call_name_rule("python.test.dynamic_format", "printf");
    fmt.constraints = RuleConstraint(vec![ConstraintKind::FormatArgIndex { format_arg_index: 0 }]);

    let mut top_level_open = call_name_rule("python.test.top_level_open", "open");
    top_level_open.constraints = RuleConstraint(vec![ConstraintKind::TopLevel { top_level: true }]);

    let mut pipe_open = call_name_rule("python.test.pipe_open", "open");
    pipe_open.constraints = RuleConstraint(vec![ConstraintKind::ArgMatchesRegex {
        arg_matches_regex: ArgRegexSpec {
            index: 0,
            regex: r#"^\s*["']\|"#.to_string(),
        },
    }]);

    let rules = [fmt, top_level_open, pipe_open];
    let refs: Vec<&Rule> = rules.iter().collect();
    let hits = match_rules_against_facts(&ws, &refs);

    assert_eq!(
        hits.iter()
            .filter(|m| m.rule_id == "python.test.dynamic_format")
            .count(),
        1,
        "format_arg_index must skip static format strings"
    );
    assert_eq!(
        hits.iter()
            .filter(|m| m.rule_id == "python.test.top_level_open")
            .count(),
        1,
        "top_level must skip receiver calls like obj.open(...)"
    );
    assert_eq!(
        hits.iter()
            .filter(|m| m.rule_id == "python.test.pipe_open")
            .count(),
        0,
        "arg_matches_regex must not match ordinary file open"
    );
}

fn base_rule(id: &str, kind: RuleKind, match_kind: MatchKind) -> Rule {
    Rule {
        id: id.to_string(),
        aliases: Vec::new(),
        enabled: true,
        disabled_reason: None,
        title: None,
        tag: Some("test".to_string()),
        severity: Some(Severity::High),
        trust: None,
        category: None,
        cwe: vec![],
        owasp: vec![],
        frameworks: vec![],
        packages: vec![],
        imports: vec![],
        modules: vec![],
        manifests: vec![],
        lockfiles: vec![],
        payload_types: vec![],
        match_spec: MatchSpec {
            kind: match_kind,
            callee: None,
            target: None,
            search_depth: 0,
        },
        taint_semantics: None,
        returns_type: None,
        constraints: RuleConstraint::default(),
        match_examples: Vec::new(),
        description: "test rule".to_string(),
        kind,
        language: "python".to_string(),
        source_path: "synthetic.yml".to_string(),
    }
}

fn call_attr_rule(id: &str, attr: &[&str]) -> Rule {
    let mut rule = base_rule(id, RuleKind::Sink, MatchKind::Call);
    rule.match_spec.callee = Some(RuleTarget {
        attribute: Some(attr.iter().map(|s| (*s).to_string()).collect()),
        ..Default::default()
    });
    rule
}

fn call_attr_rule_for_language(id: &str, language: &str, attr: &[&str]) -> Rule {
    let mut rule = call_attr_rule(id, attr);
    rule.language = language.to_string();
    rule
}

fn call_name_rule(id: &str, name: &str) -> Rule {
    let mut rule = base_rule(id, RuleKind::Sink, MatchKind::Call);
    rule.match_spec.callee = Some(RuleTarget {
        name: Some(name.to_string()),
        ..Default::default()
    });
    rule
}

fn call_regex_rule_for_language(id: &str, language: &str, regex: &str) -> Rule {
    let mut rule = base_rule(id, RuleKind::Sink, MatchKind::Call);
    rule.language = language.to_string();
    rule.match_spec.callee = Some(RuleTarget {
        regex: Some(regex.to_string()),
        ..Default::default()
    });
    rule
}

#[test]
fn objc_uppercase_c_function_regex_matches_call_facts() {
    let ws = objc_ws(
        r#"
void test(const void *input, unsigned char *digest) {
    CC_MD5(input, 1, digest);
}
"#,
    );
    let rule = call_regex_rule_for_language("objc.test.cc_md5", "objc", "^CC_MD5(_Init|_Update|_Final)?$");
    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "CC_MD5"),
        "expected ObjC C function regex to match CC_MD5 call, got {matches:?}"
    );
}

#[test]
fn javascript_prisma_scoped_package_regex_matches_local_client_call() {
    let ws = javascript_ws(
        r#"
const _u = require("@prisma/client");
async function byId(prisma, id) {
    return prisma.$queryRawUnsafe("SELECT * FROM users WHERE id = " + id);
}
"#,
    );
    let mut ungated = call_regex_rule_for_language(
        "javascript.test.prisma_query_raw_unsafe",
        "javascript",
        r"^(?:this\.)?[A-Za-z_$][A-Za-z0-9_$]*\.\$queryRawUnsafe$",
    );
    if let Some(target) = ungated.match_spec.callee.as_mut() {
        target.base_name_in = vec!["prisma".to_string()];
    }
    let ungated_matches = match_rule_against_facts(&ws, &ungated);
    assert!(
        ungated_matches
            .iter()
            .any(|m| m.match_text == "prisma.$queryRawUnsafe"),
        "expected ungated Prisma regex to match local client call, got {ungated_matches:?}"
    );

    let mut rule = ungated;
    rule.packages = vec!["@prisma/client".to_string()];

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "prisma.$queryRawUnsafe"),
        "expected scoped package evidence to gate local Prisma client call, got {matches:?}"
    );
}

#[test]
fn package_gated_kotlin_chain_uses_constructor_property_receiver_type() {
    let ws = kotlin_ws(
        r#"
package demo
import java.sql.Connection

class Handlers(private val conn: Connection) {
    fun sqlRaw(userId: String) =
        conn.createStatement().executeQuery("SELECT * FROM users WHERE id = '$userId'")
}
"#,
    );
    let mut rule = base_rule(
        "kotlin.test.connection_createstatement_execute",
        RuleKind::Sink,
        MatchKind::Call,
    );
    rule.language = "kotlin".to_string();
    rule.packages = vec!["java.sql".to_string()];
    rule.match_spec.callee = Some(RuleTarget {
        regex: Some(r"^[A-Za-z_$][A-Za-z0-9_$]*\.createStatement\(\)\.executeQuery$".to_string()),
        ..Default::default()
    });

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "constructor-property receiver type should satisfy package-gated chained JDBC rule: {hits:?}"
    );
}

#[test]
fn receiver_agnostic_regex_rules_are_gated_by_import_context() {
    let mut rule = base_rule("python.test.gql_execute", RuleKind::Sink, MatchKind::Call);
    rule.packages = vec!["gql".to_string()];
    rule.imports = vec!["gql".to_string()];
    rule.match_spec.callee = Some(RuleTarget {
        regex: Some(r"^[A-Za-z_$][A-Za-z0-9_$]*\.execute$".to_string()),
        ..Default::default()
    });

    let without_import = python_ws(
        r#"
def handler(client, payload):
    return client.execute(payload)
"#,
    );
    assert!(
        match_rule_against_facts(&without_import, &rule).is_empty(),
        "receiver-agnostic regex must not fire without adapter-surfaced package context"
    );

    let imported_but_unrelated_receiver = python_ws(
        r#"
import gql

def handler(client, payload):
    return client.execute(payload)
"#,
    );
    assert!(
        match_rule_against_facts(&imported_but_unrelated_receiver, &rule).is_empty(),
        "file-level imports must not make an unrelated receiver satisfy a package-scoped regex"
    );

    let direct_package_call = python_ws(
        r#"
import gql

def handler(payload):
    return gql.execute(payload)
"#,
    );
    let matches = match_rule_against_facts(&direct_package_call, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "gql.execute"),
        "receiver-agnostic regex should fire when the call site itself names the imported package: {matches:?}"
    );
}

#[test]
fn java_ldapi_package_gate_accepts_imported_and_fully_qualified_jndi_contexts() {
    let mut rule = call_name_rule("java.test.ldapi_search", "search");
    rule.language = "java".to_string();
    rule.packages = vec!["javax.naming.directory".to_string()];

    let imported = java_ws(
        r#"
import javax.naming.directory.*;
class App {
    void handle(DirContext ctx, String filter) throws Exception {
        ctx.search("ou=users", filter, null);
    }
}
"#,
    );
    let imported_matches = match_rule_against_facts(&imported, &rule);
    assert!(
        imported_matches.iter().any(|m| m.match_text == "ctx.search"),
        "wildcard javax.naming.directory import should satisfy the LDAP package gate: {imported_matches:?}"
    );

    let fully_qualified = java_ws(
        r#"
class App {
    void handle(String filter) throws Exception {
        javax.naming.directory.InitialDirContext ctx = new javax.naming.directory.InitialDirContext();
        ctx.search("ou=users", filter, null);
    }
}
"#,
    );
    let fqn_matches = match_rule_against_facts(&fully_qualified, &rule);
    assert!(
        fqn_matches.iter().any(|m| m.match_text == "ctx.search"),
        "fully-qualified javax.naming.directory.InitialDirContext with no import should satisfy the LDAP package gate: {fqn_matches:?}"
    );
}

fn target_name_rule(id: &str, kind: MatchKind, name: &str) -> Rule {
    let mut rule = base_rule(id, RuleKind::Source, kind);
    rule.match_spec.target = Some(RuleTarget {
        name: Some(name.to_string()),
        ..Default::default()
    });
    rule
}

fn target_attr_rule(id: &str, kind: MatchKind, attr: &[&str]) -> Rule {
    let mut rule = base_rule(id, RuleKind::Source, kind);
    rule.match_spec.target = Some(RuleTarget {
        attribute: Some(attr.iter().map(|s| (*s).to_string()).collect()),
        ..Default::default()
    });
    rule
}

#[test]
fn nested_read_match_uses_innermost_enclosing_function() {
    let ws = typescript_ws(
        r#"
import Hapi from "@hapi/hapi";

export const init = async () => {
  const server = Hapi.server({ port: 8080 });
  server.route({
    method: "POST",
    path: "/eval",
    handler: async (req) => {
      const body = req.payload || {};
      return body.script;
    },
  });
};
"#,
    );
    let mut rule = target_attr_rule(
        "typescript.test.hapi_req_payload",
        MatchKind::Read,
        &["req", "payload"],
    );
    rule.language = "typescript".to_string();

    let hits = match_rules_against_facts(&ws, &[&rule]);
    assert!(
        hits.iter()
            .any(|hit| { hit.match_text == "req.payload" && hit.enclosing_fn.as_deref() == Some("handler") }),
        "read source inside inline route handler must attach to innermost handler decl: {hits:?}"
    );
}

#[test]
fn param_rule_location_uses_declaration_site() {
    let ws = python_ws(
        r#"
def handler(user_input):
    clean = 0
    sink(user_input)
"#,
    );
    let rule = target_name_rule("python.test.param_user_input", MatchKind::Param, "user_input");
    let hits = match_rule_against_facts(&ws, &rule);
    let hit = hits
        .iter()
        .find(|hit| hit.rule_id == "python.test.param_user_input")
        .unwrap_or_else(|| panic!("expected param match, got {hits:?}"));
    assert_eq!(hit.match_text, "user_input");
    assert_eq!(
        hit.line, 2,
        "param source should point at the declaration, not the first body read"
    );
}

#[test]
fn annotated_java_param_rule_location_uses_declaration_site() {
    let ws = java_ws(
        r#"
import jakarta.ws.rs.QueryParam;
class App {
    void read(@QueryParam("file") String file) throws Exception {
        new FileInputStream(file);
    }
}
"#,
    );
    let mut rule = base_rule("java.test.jaxrs_queryparam", RuleKind::Source, MatchKind::Param);
    rule.language = "java".to_string();
    rule.packages = vec!["jakarta.ws.rs".to_string()];
    rule.match_spec.target = Some(RuleTarget {
        annotation: Some("QueryParam".to_string()),
        ..Default::default()
    });

    let hits = match_rule_against_facts(&ws, &rule);
    let hit = hits
        .iter()
        .find(|hit| hit.rule_id == "java.test.jaxrs_queryparam")
        .unwrap_or_else(|| panic!("expected annotated param match, got {hits:?}"));
    assert_eq!(hit.match_text, "file");
    assert_eq!(
        hit.line, 4,
        "annotated Java param source should point at the signature parameter"
    );
}

#[test]
fn param_rule_decl_kind_and_visibility_filters_exclude_non_entry_shapes() {
    let ws = solidity_ws(
        r#"
pragma solidity ^0.8.19;

contract App {
    modifier audit(bytes calldata data) {
        sink(data);
        _;
    }

    function handle(bytes calldata data) external audit(data) {
        sink(data);
    }

    function helper(bytes calldata data) internal {
        sink(data);
    }

    function sink(bytes calldata) internal {}
}
"#,
    );
    let mut rule = target_name_rule("solidity.test.public_method_data_param", MatchKind::Param, "data");
    rule.language = "solidity".to_string();
    if let Some(target) = rule.match_spec.target.as_mut() {
        target.decl_kind_in = vec![DeclKind::Method];
        target.visibility_in = vec![Visibility::Public];
    }

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "only the public/external contract method param should match: {hits:?}"
    );
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("handle"));
}

#[test]
fn param_rule_method_prefix_and_index_filters_resolver_args() {
    let ws = python_ws(
        r#"
import graphene

def resolve_products(obj, info, args):
    return args

def helper(args, other):
    return args

def resolve_bad(args, other):
    return args
"#,
    );
    let mut rule = target_name_rule("python.test.graphql_args", MatchKind::Param, "args");
    if let Some(target) = rule.match_spec.target.as_mut() {
        target.in_method_prefix = vec!["resolve_".to_string()];
        target.param_index_in = vec![2];
    }

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "only the GraphQL-style third resolver arg should match: {hits:?}"
    );
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("resolve_products"));
}

#[test]
fn param_rule_base_name_not_in_excludes_dedicated_param_shapes() {
    let ws = python_ws(
        r#"
import graphene

def resolve_products(obj, info, name):
    return name

def resolve_with_args(obj, info, args):
    return args
"#,
    );
    let mut rule = base_rule(
        "python.test.graphql_field_arg_without_args",
        RuleKind::Source,
        MatchKind::Param,
    );
    rule.language = "python".to_string();
    rule.packages = vec!["graphene".to_string()];
    rule.match_spec.target = Some(RuleTarget {
        regex: Some("^[A-Za-z_][A-Za-z0-9_]*$".to_string()),
        in_method_prefix: vec!["resolve_".to_string()],
        param_index_in: vec![2],
        base_name_not_in: vec!["args".to_string()],
        ..Default::default()
    });

    let hits = match_rule_against_facts(&ws, &rule);
    assert_eq!(
        hits.len(),
        1,
        "`args` should be excluded while named resolver field args still match: {hits:?}"
    );
    assert_eq!(hits[0].match_text, "name");
    assert_eq!(hits[0].enclosing_fn.as_deref(), Some("resolve_products"));
}

fn signature(rows: &[bonsai_security::RuleMatch]) -> BTreeSet<(String, String, u32, String, Option<String>)> {
    rows.iter()
        .map(|m| {
            (
                m.rule_id.clone(),
                m.file.clone(),
                m.line,
                m.match_text.clone(),
                m.enclosing_fn.clone(),
            )
        })
        .collect()
}

#[test]
fn java_declared_receiver_types_match_instance_receivers_without_factory_tail_fallback() {
    let ws = java_ws(
        r"
import org.apache.logging.log4j.core.net.JndiManager;

class App {
    private JndiManager fieldManager;

    void handle(JndiManager paramManager, String key) {
        paramManager.lookup(key);
        JndiManager localManager = JndiManager.getDefaultManager();
        localManager.lookup(key);
        this.fieldManager.lookup(key);
        JndiManager.getDefaultManager().lookup(key);
    }
}
",
    );
    let rule = call_attr_rule_for_language(
        "java.test.jndi_manager_lookup",
        "java",
        &["JndiManager", "lookup"],
    );

    let hits = match_rule_against_facts(&ws, &rule);
    let matched: BTreeSet<String> = hits.iter().map(|hit| hit.match_text.clone()).collect();

    for expected in [
        "paramManager.lookup",
        "localManager.lookup",
        "this.fieldManager.lookup",
    ] {
        assert!(
            matched.contains(expected),
            "expected Java receiver-type match for {expected}; got {matched:?}"
        );
    }
    assert!(
        !matched.contains("JndiManager.getDefaultManager().lookup"),
        "typed receiver rule must not skip over the factory call; got {matched:?}"
    );

    let factory_rule = call_attr_rule_for_language(
        "java.test.jndi_manager_factory_lookup",
        "java",
        &["JndiManager", "getDefaultManager", "lookup"],
    );
    let factory_hits = match_rule_against_facts(&ws, &factory_rule);
    let factory_matched: BTreeSet<String> = factory_hits.iter().map(|hit| hit.match_text.clone()).collect();
    assert!(
        factory_matched.contains("JndiManager.getDefaultManager().lookup"),
        "explicit factory-chain rule should match factory lookup; got {factory_matched:?}"
    );
}

#[test]
fn java_cross_file_inherited_receiver_types_match_base_rules() {
    let ws = java_ws_files(&[
        (
            "Base.java",
            r"
class Base {
    void sink(String value) {}
}
",
        ),
        (
            "Child.java",
            r"
class Child extends Base {}
",
        ),
        (
            "App.java",
            r"
class App {
    void handle(String input) {
        Child child = new Child();
        child.sink(input);
    }
}
",
        ),
    ]);
    let rule = call_attr_rule_for_language("java.test.base_sink", "java", &["Base", "sink"]);

    let hits = match_rule_against_facts(&ws, &rule);
    let matched: BTreeSet<String> = hits.iter().map(|hit| hit.match_text.clone()).collect();

    assert!(
        matched.contains("child.sink"),
        "base-type rule should match inherited method call through cross-file Child receiver; got {matched:?}"
    );
}

#[test]
fn source_sink_type_rules_do_not_match_unknown_receivers() {
    let ws = csharp_ws(
        r"
using System.Security.Cryptography;

class App {
    void Handle(byte[] data, dynamic encoder) {
        MD5.HashData(data);
        SHA1.HashData(data);
        encoder.HashData(data);
    }
}
",
    );
    let rule = call_attr_rule_for_language("csharp.test.md5_hashdata", "csharp", &["MD5", "HashData"]);

    let hits = match_rule_against_facts(&ws, &rule);
    let matched: BTreeSet<String> = hits.iter().map(|hit| hit.match_text.clone()).collect();

    assert!(
        matched.contains("MD5.HashData"),
        "exact type receiver should match; got {matched:?}"
    );
    assert!(
        !matched.contains("encoder.HashData"),
        "unknown instance receiver must not match without receiver-type evidence; got {matched:?}"
    );
    assert!(
        !matched.contains("SHA1.HashData"),
        "explicit different type receiver must not match strict receiver matching rule; got {matched:?}"
    );
}

#[test]
fn batched_matcher_matches_single_rule_semantics_for_all_fact_kinds() {
    let ws = python_ws(
        r#"
from os import system as run

def dangerous(first, second):
    pass

def handler(request, user_input):
    value = request.args
    verify_mode = "CERT_NONE"
    run(user_input)
    dangerous(second=user_input, first=0)
"#,
    );

    let mut keyword = call_name_rule("python.test.keyword_dangerous", "dangerous");
    keyword.constraints = RuleConstraint(vec![ConstraintKind::KeywordArgEquals {
        keyword_arg_equals: KeywordArgEqualsSpec {
            name: "second".to_string(),
            value: "user_input".to_string(),
        },
    }]);

    let rules = [
        call_attr_rule("python.test.alias_system", &["os", "system"]),
        keyword,
        target_attr_rule("python.test.request_args", MatchKind::Read, &["request", "args"]),
        target_name_rule("python.test.verify_mode", MatchKind::Write, "verify_mode"),
        target_name_rule("python.test.param_user_input", MatchKind::Param, "user_input"),
    ];
    let rule_refs: Vec<&Rule> = rules.iter().collect();

    let single: Vec<_> = rule_refs
        .iter()
        .flat_map(|rule| match_rule_against_facts(&ws, rule))
        .collect();
    let batched = match_rules_against_facts(&ws, &rule_refs);

    assert_eq!(
        signature(&single),
        signature(&batched),
        "batched matcher must preserve single-rule semantics"
    );
    for id in [
        "python.test.alias_system",
        "python.test.keyword_dangerous",
        "python.test.request_args",
        "python.test.verify_mode",
        "python.test.param_user_input",
    ] {
        assert!(
            batched.iter().any(|m| m.rule_id == id),
            "expected batched match for {id}; got {batched:?}"
        );
    }
}

#[test]
fn attribute_match_accepts_php_arrow_callees() {
    let ws = php_ws(
        r#"<?php
function handler($mysqli) {
    $mysqli->query("SELECT 1");
}
"#,
    );
    let mut rule = call_attr_rule_for_language("php.test.mysqli_query", "php", &["mysqli", "query"]);
    rule.constraints = RuleConstraint(vec![ConstraintKind::ArgMatchesRegex {
        arg_matches_regex: ArgRegexSpec {
            index: 0,
            regex: "SELECT".to_string(),
        },
    }]);

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "$mysqli->query"),
        "expected php arrow callee to satisfy attribute rule, got {matches:?}"
    );
}

#[test]
fn arg_regex_constraints_follow_simple_assignment_indirection() {
    let ws = python_ws(
        r#"
def execute(sql):
    pass

def handler(user_input):
    sql = "SELECT * FROM users WHERE name = '" + user_input + "'"
    execute(sql)
"#,
    );
    let mut rule = call_name_rule("python.test.execute_select", "execute");
    rule.constraints = RuleConstraint(vec![ConstraintKind::ArgMatchesRegex {
        arg_matches_regex: ArgRegexSpec {
            index: 0,
            regex: "SELECT\\s+\\*\\s+FROM".to_string(),
        },
    }]);

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "execute"),
        "arg_matches_regex should inspect the same-function assignment feeding execute(sql), got {matches:?}"
    );
}

#[test]
fn typed_attribute_matches_inline_qualified_constructor_receiver() {
    let ws = java_ws(
        r"
class App {
    void handle() {
        new java.util.Random().nextFloat();
    }
}
",
    );
    let mut rule = call_attr_rule_for_language("java.test.random_next", "java", &["Random", "nextFloat"]);
    rule.language = "java".to_string();

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text.contains("nextFloat")),
        "inline qualified constructor receiver should expose semantic Random receiver type, got {matches:?}"
    );
}

#[test]
fn new_rule_name_matches_qualified_constructor_tail() {
    let ws = java_ws(
        r"
class App {
    void handle() {
        new java.util.Random();
    }
}
",
    );
    let mut rule = base_rule("java.test.random_ctor", RuleKind::Sink, MatchKind::New);
    rule.language = "java".to_string();
    rule.match_spec.callee = Some(RuleTarget {
        name: Some("Random".to_string()),
        ..Default::default()
    });

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text.contains("Random")),
        "qualified constructor should match bare constructor rule name, got {matches:?}"
    );
}

#[test]
fn write_rules_match_structured_attribute_assignments_with_constraints() {
    let ws = ruby_ws(
        r"
def handler(response, value)
  response.headers = value
end
",
    );
    let mut rule = target_attr_rule(
        "ruby.test.response_headers",
        MatchKind::Write,
        &["response", "headers"],
    );
    rule.language = "ruby".to_string();
    rule.constraints = RuleConstraint(vec![ConstraintKind::AnyArgMatchesRegex {
        any_arg_matches_regex: "^value$".to_string(),
    }]);

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "response.headers"),
        "expected structured response.headers assignment match, got {matches:?}"
    );
}

#[test]
fn top_level_false_accepts_lua_colon_receivers() {
    let ws = lua_ws(
        r#"
function handler(self)
  self:render("view")
end
"#,
    );
    let mut rule = call_name_rule("lua.test.receiver_render", "render");
    rule.language = "lua".to_string();
    rule.constraints = RuleConstraint(vec![ConstraintKind::TopLevel { top_level: false }]);

    let matches = match_rule_against_facts(&ws, &rule);
    assert!(
        matches.iter().any(|m| m.match_text == "self:render"),
        "expected Lua colon receiver to satisfy top_level:false, got {matches:?}"
    );
}

#[test]
fn batched_matcher_keeps_constraints_per_rule_without_cross_rule_leakage() {
    let ws = python_ws(
        r#"
def dangerous(first, second):
    pass

def handler(user_input):
    dangerous(second=user_input, first=0)
    dangerous(second="clean", first=user_input)
"#,
    );

    let mut tainted_second = call_name_rule("python.test.second_user_input", "dangerous");
    tainted_second.constraints = RuleConstraint(vec![ConstraintKind::KeywordArgEquals {
        keyword_arg_equals: KeywordArgEqualsSpec {
            name: "second".to_string(),
            value: "user_input".to_string(),
        },
    }]);
    let mut clean_second = call_name_rule("python.test.second_clean", "dangerous");
    clean_second.constraints = RuleConstraint(vec![ConstraintKind::KeywordArgEquals {
        keyword_arg_equals: KeywordArgEqualsSpec {
            name: "second".to_string(),
            value: "\"clean\"".to_string(),
        },
    }]);
    let rules = [tainted_second, clean_second];
    let rule_refs: Vec<&Rule> = rules.iter().collect();

    let batched = match_rules_against_facts(&ws, &rule_refs);
    let tainted_count = batched
        .iter()
        .filter(|m| m.rule_id == "python.test.second_user_input")
        .count();
    let clean_count = batched
        .iter()
        .filter(|m| m.rule_id == "python.test.second_clean")
        .count();

    assert_eq!(
        tainted_count, 1,
        "keyword constraint must match exactly one tainted call"
    );
    assert_eq!(
        clean_count, 1,
        "keyword constraint must match exactly one clean call"
    );
    assert_eq!(
        signature(&batched),
        signature(
            &rule_refs
                .iter()
                .flat_map(|rule| match_rule_against_facts(&ws, rule))
                .collect::<Vec<_>>()
        )
    );
}
