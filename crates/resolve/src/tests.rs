// Path-tail aliasing for unaliased Go imports (`import "io/fs"`
// → local `fs`) is now an adapter responsibility — see
// `crates/lang_go/src/lib.rs::parse_imports`. Resolve simply
// honors `ImportSpec.alias` whether the adapter populated it
// explicitly or implicitly. Coverage for the path-tail rule
// lives in the lang_go and per-lang CLI conformance tests.

use super::*;
use bonsai_common::{FileId, Span, SymbolId};
use bonsai_lang_api::{
    AliasTarget, Decl, DeclIndex, DeclKind, ImportScope, ImportSpec, ModulePath, Visibility,
};

fn span() -> Span {
    Span::new(FileId::new(0), 0, 0)
}

fn spec(module: &str, alias: Option<&str>, original: Option<&str>) -> ImportSpec {
    ImportSpec {
        span: span(),
        module: module.to_string(),
        alias: alias.map(str::to_string),
        is_wildcard: false,
        original_name: original.map(str::to_string),
        scope: ImportScope::Module,
    }
}

fn decl(file: FileId, kind: DeclKind, name: &str, module: &[&str], start: u64) -> Decl {
    let span = Span::new(file, start, start + 10);
    let module_path = ModulePath::from_segments(module.iter().copied());
    let qualified_name = (!module.is_empty()).then(|| format!("{}.{}", module.join("."), name));
    Decl {
        symbol: SymbolId::new(0),
        kind,
        name: name.to_string(),
        qualified_name,
        module_path,
        span,
        name_span: span,
        visibility: Visibility::Public,
        parent: None,
        body_span: None,
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    }
}

fn insert_one(global: &mut GlobalIndex, file: FileId, decl: Decl) {
    global.insert(DeclIndex {
        file,
        defs: vec![decl],
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });
}

#[test]
fn unqualified_callable_resolution_rejects_sibling_module_without_import() {
    let mut global = GlobalIndex::new();
    let cross_file = FileId::new(1);
    let mega_file = FileId::new(2);
    insert_one(
        &mut global,
        cross_file,
        decl(
            cross_file,
            DeclKind::Function,
            "run_pipeline",
            &["python", "cross_file_chain", "pipeline"],
            10,
        ),
    );
    insert_one(
        &mut global,
        mega_file,
        decl(
            mega_file,
            DeclKind::Function,
            "run_pipeline",
            &["python", "mega_flow", "pipeline"],
            20,
        ),
    );

    let caller_module = ModulePath::from_segments(["python", "cross_file_chain", "app"]);
    let ctx = ResolveContext::new(FileId::new(99), &caller_module);
    let hits = resolve_callable_with_context(&global, "run_pipeline", &ctx);

    assert!(
        hits.is_empty(),
        "a nearest-prefix public name is not semantic evidence for an unqualified call: {hits:?}"
    );
}

#[test]
fn unqualified_callable_resolution_accepts_same_module_package() {
    let mut global = GlobalIndex::new();
    let helper_file = FileId::new(1);
    insert_one(
        &mut global,
        helper_file,
        decl(
            helper_file,
            DeclKind::Function,
            "run_pipeline",
            &["app", "service"],
            10,
        ),
    );

    let caller_module = ModulePath::from_segments(["app", "service"]);
    let ctx = ResolveContext::new(FileId::new(99), &caller_module);
    let hits = resolve_callable_with_context(&global, "run_pipeline", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(SymbolId::new(hits[0].raw())).expect("hit decl");
    assert_eq!(hit.module_path, caller_module);
}

#[test]
fn unqualified_callable_resolution_accepts_same_directory_kotlin_globals() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    insert_one(
        &mut global,
        helper_file,
        decl(helper_file, DeclKind::Function, "runPipeline", &["pipeline"], 10),
    );

    let caller_module = ModulePath::from_segments(["app"]);
    let path_lookup = |file: FileId| match file.raw() {
        1 => Some("src/app.kt".to_string()),
        2 => Some("src/pipeline.kt".to_string()),
        _ => None,
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_file_path_lookup(&path_lookup);
    let hits = resolve_callable_with_context(&global, "runPipeline", &ctx);

    assert_eq!(hits.len(), 1);
}

#[test]
fn unqualified_callable_resolution_accepts_same_directory_cpp_globals() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    insert_one(
        &mut global,
        helper_file,
        decl(helper_file, DeclKind::Function, "execute", &[], 10),
    );

    let caller_module = ModulePath::default();
    let path_lookup = |file: FileId| match file.raw() {
        1 => Some("src/storage.cpp".to_string()),
        2 => Some("src/executor.cpp".to_string()),
        _ => None,
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_file_path_lookup(&path_lookup);
    let hits = resolve_callable_with_context(&global, "execute", &ctx);

    assert_eq!(hits.len(), 1);
}

#[test]
fn unqualified_callable_resolution_rejects_same_directory_python_file_modules() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    insert_one(
        &mut global,
        helper_file,
        decl(helper_file, DeclKind::Function, "run_pipeline", &["pipeline"], 10),
    );

    let caller_module = ModulePath::from_segments(["app"]);
    let path_lookup = |file: FileId| match file.raw() {
        1 => Some("src/app.py".to_string()),
        2 => Some("src/pipeline.py".to_string()),
        _ => None,
    };
    let ctx = ResolveContext::new(caller_file, &caller_module).with_file_path_lookup(&path_lookup);
    let hits = resolve_callable_with_context(&global, "run_pipeline", &ctx);

    assert!(hits.is_empty());
}

#[test]
fn unqualified_method_resolution_rejects_same_package_other_files_without_receiver() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let sibling_file = FileId::new(2);
    insert_one(
        &mut global,
        caller_file,
        decl(
            caller_file,
            DeclKind::Method,
            "doPost",
            &["org", "owasp", "benchmark", "testcode"],
            10,
        ),
    );
    insert_one(
        &mut global,
        sibling_file,
        decl(
            sibling_file,
            DeclKind::Method,
            "doPost",
            &["org", "owasp", "benchmark", "testcode"],
            20,
        ),
    );

    let caller_module = ModulePath::from_segments(["org", "owasp", "benchmark", "testcode"]);
    let ctx = ResolveContext::new(caller_file, &caller_module);
    let hits = resolve_callable_with_context(&global, "doPost", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(SymbolId::new(hits[0].raw())).expect("hit decl");
    assert_eq!(global.declaring_file(hit.symbol), Some(caller_file));
}

#[test]
fn unqualified_class_resolution_rejects_sibling_module_without_import() {
    let mut global = GlobalIndex::new();
    let local_file = FileId::new(1);
    let sibling_file = FileId::new(2);
    insert_one(
        &mut global,
        local_file,
        decl(
            local_file,
            DeclKind::Class,
            "Repository",
            &["go", "mega_flow", "repository"],
            10,
        ),
    );
    insert_one(
        &mut global,
        sibling_file,
        decl(
            sibling_file,
            DeclKind::Class,
            "Repository",
            &["go", "cross_file_chain", "repository"],
            20,
        ),
    );

    let caller_module = ModulePath::from_segments(["go", "mega_flow", "app"]);
    let ctx = ResolveContext::new(FileId::new(99), &caller_module);
    let hits = resolve_class(&global, "Repository", &ctx);

    assert!(
        hits.is_empty(),
        "a nearest-prefix public class is not semantic evidence for an unqualified type reference: {hits:?}"
    );
}

#[test]
fn unqualified_class_resolution_accepts_same_module_package() {
    let mut global = GlobalIndex::new();
    let class_file = FileId::new(1);
    insert_one(
        &mut global,
        class_file,
        decl(class_file, DeclKind::Class, "Repository", &["app", "service"], 10),
    );

    let caller_module = ModulePath::from_segments(["app", "service"]);
    let ctx = ResolveContext::new(FileId::new(99), &caller_module);
    let hits = resolve_class(&global, "Repository", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(hits[0]).expect("hit decl");
    assert_eq!(hit.module_path, caller_module);
}

#[test]
fn static_member_resolution_accepts_enum_receivers_in_same_module() {
    let mut global = GlobalIndex::new();
    let local_file = FileId::new(1);
    let sibling_file = FileId::new(2);

    let mut local_enum = decl(local_file, DeclKind::Enum, "Executor", &["copy_0"], 10);
    local_enum.symbol = SymbolId::new(1);
    local_enum.visibility = Visibility::Module;
    let mut local_execute = decl(local_file, DeclKind::Method, "execute", &["copy_0"], 20);
    local_execute.symbol = SymbolId::new(2);
    local_execute.parent = Some(local_enum.symbol);
    local_execute.visibility = Visibility::Module;
    global.insert(DeclIndex {
        file: local_file,
        defs: vec![local_enum, local_execute],
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });

    let mut sibling_enum = decl(sibling_file, DeclKind::Enum, "Executor", &["copy_1"], 10);
    sibling_enum.symbol = SymbolId::new(1);
    sibling_enum.visibility = Visibility::Module;
    let mut sibling_execute = decl(sibling_file, DeclKind::Method, "execute", &["copy_1"], 20);
    sibling_execute.symbol = SymbolId::new(2);
    sibling_execute.parent = Some(sibling_enum.symbol);
    sibling_execute.visibility = Visibility::Module;
    global.insert(DeclIndex {
        file: sibling_file,
        defs: vec![sibling_enum, sibling_execute],
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });

    let caller_module = ModulePath::from_segments(["copy_0"]);
    let ctx = ResolveContext::new(FileId::new(99), &caller_module);
    let hits = resolve_callable_with_context(&global, "Executor.execute", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global
        .decl_of(SymbolId::new(hits[0].raw()))
        .expect("resolved enum static method");
    assert_eq!(hit.name, "execute");
    assert_eq!(hit.module_path, caller_module);
    assert_eq!(global.declaring_file(hit.symbol), Some(local_file));
}

#[test]
fn unqualified_class_resolution_accepts_wildcard_import_target_only() {
    let mut global = GlobalIndex::new();
    let imported_file = FileId::new(1);
    let unrelated_file = FileId::new(2);
    insert_one(
        &mut global,
        imported_file,
        decl(imported_file, DeclKind::Class, "Pipeline", &["pipeline"], 10),
    );
    insert_one(
        &mut global,
        unrelated_file,
        decl(unrelated_file, DeclKind::Class, "Pipeline", &["other"], 20),
    );

    let caller_module = ModulePath::from_segments(["app"]);
    let mut aliases = AHashMap::new();
    aliases.insert(
        format!("{WILDCARD_IMPORT_ALIAS_PREFIX}/pipeline.php"),
        AliasTarget::Namespace {
            module: "/pipeline.php".to_string(),
        },
    );
    let ctx = ResolveContext::new(FileId::new(99), &caller_module).with_alias_map(&aliases);
    let hits = resolve_class(&global, "Pipeline", &ctx);

    assert_eq!(hits.len(), 1, "wildcard imports must not fan out: {hits:?}");
    let hit = global.decl_of(hits[0]).expect("hit decl");
    assert_eq!(hit.module_path, ModulePath::from_segments(["pipeline"]));
}

#[test]
fn module_target_matches_rust_root_prefixed_modules() {
    let module = ModulePath::from_segments(["util"]);

    assert!(module_target_matches_decl_module_path("crate::util", &module));
    assert!(module_target_matches_decl_module_path("crate::util::*", &module));
    assert!(module_target_matches_decl_module_path("self::util", &module));
    assert!(module_target_matches_decl_module_path("super::util", &module));
}

#[test]
fn relative_alias_target_resolves_against_caller_module() {
    let mut global = GlobalIndex::new();
    let local_file = FileId::new(1);
    let sibling_file = FileId::new(2);
    insert_one(
        &mut global,
        local_file,
        decl(
            local_file,
            DeclKind::Function,
            "execute",
            &["javascript", "cross_file_chain", "executor"],
            10,
        ),
    );
    insert_one(
        &mut global,
        sibling_file,
        decl(
            sibling_file,
            DeclKind::Function,
            "execute",
            &["javascript", "mega_flow", "executor"],
            20,
        ),
    );

    let caller_module = ModulePath::from_segments(["javascript", "cross_file_chain", "transformer"]);
    let mut aliases = AHashMap::new();
    aliases.insert(
        "execute".to_string(),
        AliasTarget::Member {
            module: "./executor.js".to_string(),
            member: "execute".to_string(),
        },
    );
    let ctx = ResolveContext::new(FileId::new(99), &caller_module).with_alias_map(&aliases);
    let hits = resolve_callable_with_context(&global, "execute", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(SymbolId::new(hits[0].raw())).expect("hit decl");
    assert_eq!(
        hit.module_path,
        ModulePath::from_segments(["javascript", "cross_file_chain", "executor"])
    );
}

#[test]
fn rust_crate_root_member_import_resolves_by_exact_workspace_path() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let callee_file = FileId::new(2);
    insert_one(
        &mut global,
        callee_file,
        decl(callee_file, DeclKind::Function, "get_user", &["user_service"], 10),
    );

    let caller_module = ModulePath::from_segments(["gateway"]);
    let mut aliases = AHashMap::new();
    aliases.insert(
        "get_user".to_string(),
        AliasTarget::Member {
            module: "crate::micro::user_service".to_string(),
            member: "get_user".to_string(),
        },
    );
    let path_lookup =
        |file| (file == callee_file).then(|| "/repo/examples/rust/micro/user_service.rs".to_string());
    let ctx = ResolveContext::new(caller_file, &caller_module)
        .with_alias_map(&aliases)
        .with_file_path_lookup(&path_lookup);

    let hits = resolve_callable_with_context(&global, "get_user", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(SymbolId::new(hits[0].raw())).expect("hit decl");
    assert_eq!(global.declaring_file(hit.symbol), Some(callee_file));
}

#[test]
fn multi_segment_import_path_does_not_match_by_leaf_alone() {
    assert!(
        !module_target_matches_path(
            "crate::admin::user_service",
            "/repo/examples/rust/micro/user_service.rs",
        ),
        "multi-segment imports must match their parent path, not only the file stem"
    );
}

#[test]
fn aliased_member_binds_local_to_original_symbol() {
    // The kotlin double-tail drift guard at the unit level: an
    // adapter that produces `module="x.y", alias="Z",
    // original_name="z"` (the corrected pass-8 shape) must
    // produce `Z → z`, NOT `Z → "x.y.z"`. If a future change
    // re-routes alias resolution through the generic
    // extractor — which would emit `module="x.y.z",
    // alias="Z", original_name=None` — `Z` would map to the
    // dotted module path and downstream callee resolution
    // would expand `Z(...)` to `"x.y.z.z(...)"`.
    let map = alias_map_for_file(&[spec("x.y", Some("Z"), Some("z"))]);
    assert_eq!(map.get("Z").map(String::as_str), Some("z"));
    assert!(
        !map.values().any(|v| v.contains('.')),
        "alias must not be dotted: {map:?}"
    );
}

#[test]
fn from_x_import_y_as_z_binds_z_to_y() {
    // Python `from flask import request as req` → req → request.
    let map = alias_map_for_file(&[spec("flask", Some("req"), Some("request"))]);
    assert_eq!(map.get("req").map(String::as_str), Some("request"));
}

#[test]
fn semantic_import_binding_retains_member_module_identity() {
    let direct = semantic_import_binding_map_for_file(&[spec("storage", None, Some("Repository"))]);
    assert_eq!(
        direct.get("Repository").map(String::as_str),
        Some("storage.Repository")
    );

    let renamed = semantic_import_binding_map_for_file(&[spec("storage", Some("Repo"), Some("Repository"))]);
    assert_eq!(
        renamed.get("Repo").map(String::as_str),
        Some("storage.Repository")
    );
}

#[test]
fn module_only_alias_binds_local_to_module() {
    // Python `import os as o` → o → os.
    let map = alias_map_for_file(&[spec("os", Some("o"), None)]);
    assert_eq!(map.get("o").map(String::as_str), Some("os"));
}

#[test]
fn member_alias_whole_name_rewrites_to_module_member() {
    let mut map = ahash::AHashMap::new();
    map.insert(
        "u".to_string(),
        AliasTarget::Member {
            module: "pkg".to_string(),
            member: "util".to_string(),
        },
    );
    let module = ModulePath::default();
    let ctx = ResolveContext::new(FileId::new(0), &module).with_alias_map(&map);

    assert_eq!(
        rewrite_through_alias_map_with_target("u", &ctx)
            .map(|r| r.rewritten)
            .as_deref(),
        Some("pkg.util")
    );
}

#[test]
fn member_alias_prefix_preserves_imported_member() {
    let mut map = ahash::AHashMap::new();
    map.insert(
        "u".to_string(),
        AliasTarget::Member {
            module: "pkg".to_string(),
            member: "util".to_string(),
        },
    );
    let module = ModulePath::default();
    let ctx = ResolveContext::new(FileId::new(0), &module).with_alias_map(&map);

    assert_eq!(
        rewrite_through_alias_map_with_target("u.run", &ctx)
            .map(|r| r.rewritten)
            .as_deref(),
        Some("pkg.util.run")
    );
}

#[test]
fn rewrite_handles_double_colon_separator() {
    // Rust / C++ `pipeline::orchestrate` must split into the
    // module head and bare tail, not chop at the first `:`
    // (which would leave a stray colon in the rewritten form).
    let mut map = ahash::AHashMap::new();
    map.insert(
        "pipeline".to_string(),
        AliasTarget::Namespace {
            module: "pipeline".to_string(),
        },
    );
    let module = ModulePath::default();
    let ctx = ResolveContext::new(FileId::new(0), &module).with_alias_map(&map);

    assert_eq!(
        rewrite_through_alias_map_with_target("pipeline::orchestrate", &ctx)
            .map(|r| r.rewritten)
            .as_deref(),
        Some("pipeline.orchestrate")
    );
}

#[test]
fn module_target_match_handles_php_namespace_separator() {
    // PHP `use App\Util as H;` produces alias target
    // `App\Util`. The decl module path is `["App"]` (file
    // namespace). Match should drop the trailing class-name
    // segment and accept the suffix.
    let module = ModulePath::from_segments(["App"]);
    assert!(module_target_matches_decl_module_path("App\\Util", &module));
}

#[test]
fn module_target_match_handles_dart_file_extension() {
    // Dart `import 'storage.dart' as store;` exposes the
    // `.dart` extension in the alias target. The decl path
    // canonicalizes to `["storage"]`; the trailing-segment
    // drop is what closes the gap.
    let module = ModulePath::from_segments(["storage"]);
    assert!(module_target_matches_decl_module_path("storage.dart", &module));
}

#[test]
fn module_target_match_rejects_unrelated_modules() {
    // Negative: alias `Envelope` (a type-only import) must
    // not match a decl in module `helpers` even though both
    // are workspace-internal.
    let module = ModulePath::from_segments(["helpers"]);
    assert!(!module_target_matches_decl_module_path("Envelope", &module));
}

#[test]
fn self_binding_alias_kept_for_external_head_detection() {
    // Go `import "fmt"` (adapter sets alias = path tail)
    // → fmt → fmt. The taint engine relies on this entry
    // existing so `fmt.Println` is recognised as an external-
    // package head instead of bare-tailing into a workspace
    // function literally named `Println`.
    let map = alias_map_for_file(&[spec("fmt", Some("fmt"), None)]);
    assert_eq!(map.get("fmt").map(String::as_str), Some("fmt"));
}

#[test]
fn class_resolution_rewrites_alias_map() {
    let mut global = GlobalIndex::new();
    let file = FileId::new(1);
    let span = Span::new(file, 0, 20);
    let class = bonsai_lang_api::Decl {
        symbol: SymbolId::new(0),
        kind: bonsai_lang_api::DeclKind::Class,
        name: "Service".to_string(),
        qualified_name: Some("pkg.Service".to_string()),
        module_path: ModulePath::from_segments(["pkg"]),
        span,
        name_span: span,
        visibility: bonsai_lang_api::Visibility::Public,
        parent: None,
        body_span: None,
        flow_events: Vec::new(),
        has_implicit_returns: false,
        params: Vec::new(),
        param_annotations: Vec::new(),
        type_aliases: Vec::new(),
        bases: Vec::new(),
        receiver_param_index: None,
        receiver_field_writes: Vec::new(),
        implicit_receiver_names: Vec::new(),
        receiver_state_sources: Vec::new(),
        return_type: None,
        is_variadic: false,
    };
    global.insert(DeclIndex {
        file,
        defs: vec![class],
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });

    let caller_module = ModulePath::from_segments(["pkg"]);
    let mut aliases = AHashMap::new();
    aliases.insert(
        "Svc".to_string(),
        AliasTarget::Type {
            type_name: "pkg.Service".to_string(),
        },
    );
    let ctx = ResolveContext::new(file, &caller_module).with_alias_map(&aliases);
    let hits = resolve_class(&global, "Svc", &ctx);
    assert_eq!(hits.len(), 1, "aliased type should resolve by rewritten tail");
}

#[test]
fn type_alias_member_call_does_not_fall_back_to_bare_method() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let helper_file = FileId::new(2);
    insert_one(
        &mut global,
        caller_file,
        decl(caller_file, DeclKind::Function, "doPost", &["app"], 10),
    );
    let mut cert = decl(helper_file, DeclKind::Class, "Certificate", &["helpers"], 20);
    cert.symbol = SymbolId::new(2);
    let mut equals = decl(helper_file, DeclKind::Method, "equals", &["helpers"], 30);
    equals.symbol = SymbolId::new(3);
    equals.parent = Some(cert.symbol);
    global.insert(DeclIndex {
        file: helper_file,
        defs: vec![cert, equals],
        refs: Vec::new(),
        strings: Vec::new(),
        comments: Vec::new(),
    });

    let caller_module = ModulePath::from_segments(["app"]);
    let aliases = AHashMap::from_iter([(
        "value".to_string(),
        AliasTarget::Type {
            type_name: "String".to_string(),
        },
    )]);
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(&aliases);
    let hits = resolve_callable_with_context(&global, "value.equals", &ctx);

    assert!(
        hits.is_empty(),
        "external type alias must not collapse to a same-named workspace method: {hits:?}"
    );
}

#[test]
fn class_resolution_uses_import_target_before_bare_duplicate_scan() {
    let mut global = GlobalIndex::new();
    for i in 0..256 {
        let file = FileId::new(i + 1);
        insert_one(
            &mut global,
            file,
            decl(
                file,
                DeclKind::Class,
                "CommandRunner",
                &[&format!("shard_{i:03}"), &format!("flow_{i:05}_executor")],
                u64::from(i) * 10,
            ),
        );
    }

    let caller_file = FileId::new(999);
    let caller_module = ModulePath::from_segments(["shard_042", "flow_00042_storage"]);
    let aliases = AHashMap::from_iter([(
        "CommandRunner".to_string(),
        AliasTarget::Member {
            module: "shard_042.flow_00042_executor".to_string(),
            member: "CommandRunner".to_string(),
        },
    )]);
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(&aliases);
    let hits = resolve_class(&global, "CommandRunner", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(hits[0]).expect("resolved class");
    assert_eq!(
        hit.qualified_name.as_deref(),
        Some("shard_042.flow_00042_executor.CommandRunner")
    );
}

#[test]
fn class_resolution_keeps_same_file_class_precedence_over_import() {
    let mut global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let imported_file = FileId::new(2);
    insert_one(
        &mut global,
        caller_file,
        decl(
            caller_file,
            DeclKind::Class,
            "CommandRunner",
            &["app", "storage"],
            10,
        ),
    );
    insert_one(
        &mut global,
        imported_file,
        decl(
            imported_file,
            DeclKind::Class,
            "CommandRunner",
            &["app", "executor"],
            20,
        ),
    );

    let caller_module = ModulePath::from_segments(["app", "storage"]);
    let aliases = AHashMap::from_iter([(
        "CommandRunner".to_string(),
        AliasTarget::Member {
            module: "app.executor".to_string(),
            member: "CommandRunner".to_string(),
        },
    )]);
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(&aliases);
    let hits = resolve_class(&global, "CommandRunner", &ctx);

    assert_eq!(hits.len(), 1);
    let hit = global.decl_of(hits[0]).expect("resolved class");
    assert_eq!(hit.qualified_name.as_deref(), Some("app.storage.CommandRunner"));
}

#[test]
fn type_alias_rewrite_cycle_does_not_loop() {
    let global = GlobalIndex::new();
    let caller_file = FileId::new(1);
    let caller_module = ModulePath::from_segments(["app"]);
    let aliases = AHashMap::from_iter([
        (
            "Foo".to_string(),
            AliasTarget::Type {
                type_name: "Bar".to_string(),
            },
        ),
        (
            "Bar".to_string(),
            AliasTarget::Type {
                type_name: "Foo".to_string(),
            },
        ),
    ]);
    let ctx = ResolveContext::new(caller_file, &caller_module).with_alias_map(&aliases);
    let hits = resolve_class(&global, "Foo", &ctx);

    assert!(hits.is_empty());
}

#[test]
fn redundant_alias_equal_to_original_is_skipped() {
    // `from x import y as y` would produce a no-op binding.
    // We skip redundant entries to keep the map tight.
    let map = alias_map_for_file(&[spec("x", Some("y"), Some("y"))]);
    assert!(map.is_empty(), "redundant alias should not emit: {map:?}");
}

#[test]
fn empty_inputs_produce_empty_map() {
    assert!(alias_map_for_file(&[]).is_empty());
}

#[test]
fn first_alias_wins_on_collision() {
    // `import os as o` followed by `import "other" as o` —
    // first entry wins for the module-alias case (insert via
    // `entry().or_insert_with`).
    let map = alias_map_for_file(&[spec("os", Some("o"), None), spec("other", Some("o"), None)]);
    assert_eq!(map.get("o").map(String::as_str), Some("os"));
}

#[test]
fn unaliased_import_derives_namespace_binding() {
    // `import os` (no alias, no original_name) still binds the
    // module head locally. Downstream qualified calls must resolve
    // through that namespace or remain unresolved; they must not
    // fall through to broad bare-name resolution.
    let map = alias_map_for_file(&[spec("os", None, None)]);
    assert_eq!(map.get("os").map(String::as_str), Some("os"));
}

#[test]
fn unaliased_path_import_derives_stem_binding() {
    let map = alias_map_for_file(&[spec("./storage.ts", None, None)]);
    assert_eq!(map.get("storage").map(String::as_str), Some("./storage.ts"));
}

#[test]
fn module_target_path_match_accepts_workspace_root_suffix() {
    assert!(module_target_matches_path("app/util", "util/util.go"));
    assert!(module_target_matches_path(
        "com/example/Util",
        "src/example/Util.java"
    ));
    assert!(!module_target_matches_path("app/util", "helpers/helper.go"));
}
