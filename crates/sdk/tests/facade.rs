use std::path::PathBuf;
use std::sync::Mutex;

static IDG_SIDECAR_LIMIT_ENV_LOCK: Mutex<()> = Mutex::new(());
static DATAFLOW_ENV_LOCK: Mutex<()> = Mutex::new(());

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

fn python_micro() -> PathBuf {
    repo_root().join("examples/python/micro")
}

fn temp_python_micro(name: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!(
        "bonsai-sdk-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    copy_dir(&python_micro(), &dst);
    dst
}

fn tempdir(name: &str) -> PathBuf {
    let dst = std::env::temp_dir().join(format!(
        "bonsai-sdk-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dst).expect("create tempdir");
    dst
}

fn copy_dir(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create temp fixture dir");
    for entry in std::fs::read_dir(src).expect("read fixture dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let name = entry.file_name();
        if name == ".bonsai" {
            continue;
        }
        let target = dst.join(name);
        if path.is_dir() {
            copy_dir(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap_or_else(|err| {
                panic!(
                    "copy fixture file {} -> {} failed: {err}",
                    path.display(),
                    target.display()
                )
            });
        }
    }
}

fn copy_dir_including_bonsai(src: &std::path::Path, dst: &std::path::Path) {
    std::fs::create_dir_all(dst).expect("create copied workspace dir");
    for entry in std::fs::read_dir(src).expect("read workspace dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let target = dst.join(entry.file_name());
        if path.is_dir() {
            copy_dir_including_bonsai(&path, &target);
        } else {
            std::fs::copy(&path, &target).unwrap_or_else(|err| {
                panic!(
                    "copy workspace file {} -> {} failed: {err}",
                    path.display(),
                    target.display()
                )
            });
        }
    }
}

fn sdk() -> bonsai_sdk::Bonsai {
    bonsai_sdk::Bonsai::new()
        .with_rulepack(repo_root().join("security-patterns"))
        .expect("rulepack")
}

#[test]
fn facade_indexes_and_exposes_workspace_basics() {
    let root = temp_python_micro("cache");
    let project = sdk().index_structural(&root).expect("structural index");

    assert!(project.stats().files > 0);
    assert!(project.diagnostics().is_empty());
    let diagnostics = project.diagnostics_report();
    assert!(diagnostics.diagnostics.is_empty());
    assert!(diagnostics
        .workspace_languages
        .iter()
        .any(|lang| lang == "python"));
    assert!(diagnostics
        .adapter_capabilities
        .iter()
        .any(|row| row.language == "python" && !row.file_extensions.is_empty()));
    assert!(project.rulepack().is_some());
    assert!(project.rulepack_root().is_some());
    let stats = project.cache().stats().expect("cache stats after index");
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "SDK structural index should avoid dataflow sidecars"
    );
    project.cache().rebuild_dataflow().expect("rebuild dataflow");
    assert!(project.load_dataflow_sidecar().expect("load sidecar") > 0);
    let stats = project.cache().stats().expect("cache stats");
    assert!(stats.bonsai_dir_exists);
    assert!(
        stats.dataflow_sidecar_exists,
        "explicit cache rebuild should write the legacy SDK dataflow sidecar"
    );
    assert!(
        !stats.dataflow_factstore_sidecar_exists,
        "cache rebuild should not imply the streaming full-prewarm factstore path"
    );
    project.cache().clear_dataflow_only().expect("clear dataflow");
    let stats = project.cache().stats().expect("cache stats after clear");
    assert!(!stats.dataflow_sidecar_exists);
    assert!(!stats.dataflow_factstore_sidecar_exists);
    project.cache().rebuild_dataflow().expect("rebuild dataflow");
    assert!(
        project
            .cache()
            .stats()
            .expect("cache stats after rebuild")
            .dataflow_sidecar_exists
    );
    project
        .export()
        .warm_default_json_cache()
        .expect("warm default export cache");
    let stats = project.cache().stats().expect("cache stats after export warm");
    assert!(
        stats.export_sidecar_exists,
        "warming the default export cache must write the sidecar"
    );
    assert!(
        stats.validation.export_ready,
        "cache stats should validate the export sidecar through export metadata: {stats:#?}"
    );
    let export_json = std::fs::read_to_string(&stats.export_sidecar).expect("read export sidecar");
    let parsed: serde_json::Value = serde_json::from_str(&export_json).expect("export sidecar JSON parses");
    assert!(
        parsed.get("taint_graph").is_some(),
        "export sidecar should contain native export JSON"
    );
    let root_cache = sdk().cache(&root);
    assert!(root_cache.stats().expect("root cache stats").bonsai_dir_exists);
    root_cache.clear_all().expect("root cache clear all");
    assert!(
        !root_cache
            .stats()
            .expect("root cache stats after clear")
            .bonsai_dir_exists
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_cache_rebuild_structural_matches_cli_rebuild_scope() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("structural-cache");
    let sdk = sdk();

    let stats = sdk
        .rebuild_structural_cache(&root, false)
        .expect("root-level structural cache rebuild");
    assert!(
        stats.callgraph_sidecar_exists && stats.callgraph_sidecar_bytes > 0,
        "SDK structural rebuild should write callgraph sidecar: {stats:#?}"
    );
    assert!(
        stats.idg_sidecar_exists && stats.idg_sidecar_bytes > 0,
        "SDK structural rebuild should write IDG sidecar: {stats:#?}"
    );
    assert!(
        stats.retrieval_sidecar_exists && stats.retrieval_sidecar_bytes > 0,
        "SDK structural rebuild should write retrieval factstore: {stats:#?}"
    );
    assert!(
        stats.manifest_exists && stats.manifest_bytes > 0,
        "SDK structural rebuild should write a cache manifest: {stats:#?}"
    );
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "SDK structural rebuild must match CLI cache rebuild and avoid full dataflow prewarm: {stats:#?}"
    );
    assert!(
        !stats.export_sidecar_exists,
        "export cache should only be warmed when requested: {stats:#?}"
    );

    let project = sdk.open_query(&root).expect("open project after rebuild");
    let stats = project
        .cache()
        .rebuild_structural_with_export(true)
        .expect("project structural cache rebuild with export");
    assert!(
        stats.callgraph_sidecar_exists
            && stats.idg_sidecar_exists
            && stats.retrieval_sidecar_exists
            && stats.export_sidecar_exists,
        "project cache rebuild with export should warm structural, retrieval, and export sidecars: {stats:#?}"
    );
    assert!(
        !stats.dataflow_sidecar_exists && !stats.dataflow_factstore_sidecar_exists,
        "project structural rebuild with export should still avoid full dataflow prewarm: {stats:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn root_cache_stats_preserve_builder_rulepack_validation() {
    let root = temp_python_micro("root-cache-rulepack-validation");
    let sdk = sdk();
    sdk.rebuild_structural_cache(&root, false)
        .expect("root-level structural cache rebuild");

    let stats = sdk.cache(&root).stats().expect("root cache stats");
    assert_eq!(
        stats.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "root-only cache stats should validate with the builder rulepack root: {stats:#?}"
    );
    assert!(
        stats.validation.semantic_ready,
        "root-only cache stats should preserve validated semantic readiness: {stats:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_index_semantic_writes_structural_sidecars_and_query_hydrates_idg() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-index");
    let sdk = sdk();

    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let stats = indexed.cache().stats().expect("semantic cache stats");
    assert!(
        stats.callgraph_sidecar_exists && stats.callgraph_sidecar_bytes > 0,
        "SDK index should write callgraph sidecar: {stats:#?}"
    );
    assert!(
        stats.idg_sidecar_exists && stats.idg_sidecar_bytes > 0,
        "SDK index should write IDG sidecar: {stats:#?}"
    );
    assert!(
        stats.retrieval_sidecar_exists && stats.retrieval_sidecar_bytes > 0,
        "SDK index should write retrieval factstore: {stats:#?}"
    );
    assert!(
        !stats.dataflow_factstore_sidecar_exists
            && !stats.value_flow_sidecar_exists
            && !stats.flow_ids_sidecar_exists,
        "SDK semantic index should not run all-entry dataflow/value-flow/flow-id prewarm: {stats:#?}"
    );
    assert!(
        stats.manifest_exists && stats.manifest_bytes > 0,
        "SDK index should write the cache manifest: {stats:#?}"
    );
    assert_eq!(
        stats.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "fresh semantic index should validate its cache manifest: {stats:#?}"
    );
    assert!(
        stats.validation.semantic_ready,
        "fresh semantic index should report validated semantic readiness: {stats:#?}"
    );
    let manifest = indexed
        .cache()
        .read_manifest()
        .expect("read semantic cache manifest")
        .expect("semantic cache manifest exists");
    assert!(
        manifest.coverage.semantic_ready,
        "semantic manifest should declare reusable semantic facts ready: {manifest:#?}"
    );
    assert!(
        manifest.sidecars.iter().any(|sidecar| sidecar.name == "idg"
            && sidecar.status == bonsai_sdk::CacheManifestSidecarStatus::Present),
        "semantic manifest should list the IDG factstore: {manifest:#?}"
    );
    assert!(
        manifest.sidecars.iter().any(|sidecar| sidecar.name == "retrieval"
            && sidecar.status == bonsai_sdk::CacheManifestSidecarStatus::Present),
        "semantic manifest should list the retrieval factstore: {manifest:#?}"
    );
    let callgraph_modified = std::fs::metadata(&stats.callgraph_sidecar)
        .expect("callgraph sidecar metadata")
        .modified()
        .expect("callgraph sidecar modified time");
    let idg_modified = std::fs::metadata(&stats.idg_sidecar)
        .expect("idg sidecar metadata")
        .modified()
        .expect("idg sidecar modified time");
    let retrieval_modified = std::fs::metadata(&stats.retrieval_sidecar)
        .expect("retrieval sidecar metadata")
        .modified()
        .expect("retrieval sidecar modified time");
    std::thread::sleep(std::time::Duration::from_millis(20));
    let reindexed = sdk.index_semantic(&root).expect("second semantic index");
    let second_stats = reindexed.cache().stats().expect("second semantic cache stats");
    assert_eq!(
        callgraph_modified,
        std::fs::metadata(&second_stats.callgraph_sidecar)
            .expect("second callgraph sidecar metadata")
            .modified()
            .expect("second callgraph sidecar modified time"),
        "second semantic index should reuse a fresh callgraph sidecar instead of rewriting it"
    );
    assert_eq!(
        idg_modified,
        std::fs::metadata(&second_stats.idg_sidecar)
            .expect("second idg sidecar metadata")
            .modified()
            .expect("second idg sidecar modified time"),
        "second semantic index should reuse a fresh IDG sidecar instead of rewriting it"
    );
    assert_eq!(
        retrieval_modified,
        std::fs::metadata(&second_stats.retrieval_sidecar)
            .expect("second retrieval sidecar metadata")
            .modified()
            .expect("second retrieval sidecar modified time"),
        "second semantic index should reuse a fresh retrieval sidecar instead of rewriting it"
    );

    let queried = sdk.open_query(&root).expect("query open after semantic index");
    assert!(
        queried.workspace().db().idg_service().is_some(),
        "query open should hydrate the existing IDG sidecar"
    );
    let path = queried
        .browse()
        .paths(bonsai_sdk::PathFilters {
            from: "handle_request",
            to: "run_admin_command",
            ..Default::default()
        })
        .expect("semantic path after index");
    assert!(
        path.idg_available
            && path
                .backends
                .iter()
                .any(|backend| backend == "warmed-idg-cross-call"),
        "path should reuse the hydrated IDG semantic backend after SDK index: {path:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_marks_semantic_sidecars_stale_after_source_change() {
    let root = temp_python_micro("semantic-cache-validation-stale");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert_eq!(
        fresh.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "fixture should start with a fresh manifest: {fresh:#?}"
    );
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic sidecars: {fresh:#?}"
    );

    let gateway = root.join("gateway.py");
    let mut source = std::fs::read_to_string(&gateway).expect("read gateway fixture");
    source.push_str("\n# cache validation edit\n");
    std::fs::write(&gateway, source).expect("modify source after semantic cache warm");

    let stale = sdk.cache(&root).stats().expect("stale cache stats");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Stale,
        "source edit should stale the cache manifest: {stale:#?}"
    );
    assert!(
        !stale.validation.semantic_ready,
        "stale manifest must not report reusable semantic sidecars: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("workspace source content changed")),
        "stale stats should explain the source-content invalidation: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "callgraph" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "callgraph sidecar should be marked stale when manifest source fingerprint changes: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "retrieval" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "retrieval factstore should be marked stale when manifest source fingerprint changes: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_requires_fresh_retrieval_sidecar() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-cache-validation-retrieval-missing");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic readiness: {fresh:#?}"
    );

    std::fs::remove_file(&fresh.retrieval_sidecar).expect("remove retrieval sidecar");
    let stale = sdk.cache(&root).stats().expect("stats after retrieval removal");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "the manifest itself is still fresh; the sidecar validation should catch the missing retrieval factstore: {stale:#?}"
    );
    assert!(
        !stale.validation.structural_ready && !stale.validation.semantic_ready,
        "semantic readiness must require a fresh retrieval sidecar: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "retrieval" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "missing retrieval sidecar listed by the manifest should be stale: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("retrieval: cache manifest lists the sidecar")),
        "cache stats should explain the retrieval invalidation: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_rejects_retrieval_sidecar_from_moved_workspace() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-cache-validation-retrieval-moved-src");
    let moved = tempdir("semantic-cache-validation-retrieval-moved-dst");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic readiness: {fresh:#?}"
    );

    copy_dir_including_bonsai(&root, &moved);
    let moved_stats = sdk
        .cache(&moved)
        .stats()
        .expect("stats for moved workspace cache");
    assert_eq!(
        moved_stats.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "moving a workspace preserves relative source fingerprints, so retrieval payload validation must prove the stale sidecar: {moved_stats:#?}"
    );
    assert!(
        !moved_stats.validation.structural_ready && !moved_stats.validation.semantic_ready,
        "semantic readiness must reject retrieval sidecars written for another workspace path: {moved_stats:#?}"
    );
    assert!(
        moved_stats.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "retrieval" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "moved retrieval sidecar should be stale under the query-time pipeline: {moved_stats:#?}"
    );
    assert!(
        moved_stats
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("retrieval sidecar validation failed")),
        "cache stats should explain moved retrieval invalidation: {moved_stats:#?}"
    );
    assert!(
        sdk.retrieval_candidate_file_filters(
            &moved,
            "handle_request",
            bonsai_browse::SearchFilters::default(),
        )
        .expect("retrieval candidate check")
        .is_none(),
        "query-time retrieval loading must also reject the moved sidecar"
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(moved);
}

#[test]
fn cache_stats_validation_rejects_moved_full_prewarm_factstores() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let _dataflow_guard = DATAFLOW_ENV_LOCK.lock().expect("dataflow env lock");
    let root = temp_python_micro("semantic-cache-validation-full-prewarm-moved-src");
    let moved = tempdir("semantic-cache-validation-full-prewarm-moved-dst");
    let sdk = sdk();
    let project = sdk
        .open_with_options(&root, bonsai_sdk::OpenOptions::full_prewarm())
        .expect("full-prewarm index");
    let fresh = project.cache().stats().expect("fresh full-prewarm stats");
    assert_eq!(
        fresh.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "fixture should start with a fresh cache manifest: {fresh:#?}"
    );
    for name in ["callgraph", "dataflow_factstore", "value_flow", "flow_ids"] {
        assert!(
            fresh
                .validation
                .sidecars
                .iter()
                .any(|sidecar| sidecar.name == name
                    && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Fresh),
            "fixture should start with fresh {name} sidecar: {fresh:#?}"
        );
    }

    copy_dir_including_bonsai(&root, &moved);
    let moved_stats = sdk
        .cache(&moved)
        .stats()
        .expect("stats for moved full-prewarm cache");
    assert_eq!(
        moved_stats.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "moving preserves relative manifest fingerprints; sidecar payload validation must prove stale paths: {moved_stats:#?}"
    );
    for name in ["callgraph", "dataflow_factstore", "value_flow", "flow_ids"] {
        assert!(
            moved_stats
                .validation
                .sidecars
                .iter()
                .any(|sidecar| sidecar.name == name
                    && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale),
            "moved full-prewarm cache should mark {name} stale: {moved_stats:#?}"
        );
    }
    assert!(
        !moved_stats.validation.legacy_dataflow_ready,
        "dataflow readiness must not claim a moved factstore is reusable: {moved_stats:#?}"
    );
    assert!(
        moved_stats
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("source fingerprint mismatch")
                || reason.contains("pipeline hash mismatch")),
        "moved full-prewarm stats should explain strict sidecar validation failure: {moved_stats:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
    let _ = std::fs::remove_dir_all(moved);
}

#[test]
fn sdk_retrieval_candidate_filters_are_relative_and_fact_backed() {
    let root = tempdir("retrieval-search-candidates");
    std::fs::create_dir_all(root.join("pkg")).expect("mkdir");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(
        root.join("pkg/service.py"),
        "def sdk_unique_symbol():\n    return 'ok'\n",
    )
    .expect("write service");
    let bonsai = bonsai_sdk::Bonsai::new();
    bonsai.index_semantic(&root).expect("semantic index");

    let filters = bonsai
        .retrieval_candidate_file_filters(&root, "sdk_unique_symbol", bonsai_sdk::SearchFilters::default())
        .expect("candidate filters")
        .expect("fresh retrieval sidecar");

    assert_eq!(filters, vec!["pkg/service.py"]);

    let legacy_filters = bonsai
        .retrieval_search_candidate_file_filters(
            &root,
            "sdk_unique_symbol",
            bonsai_sdk::SearchFilters::default(),
        )
        .expect("legacy candidate filters")
        .expect("fresh retrieval sidecar");
    assert_eq!(
        legacy_filters, filters,
        "search-named compatibility helper should delegate to the neutral retrieval helper"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_retrieval_candidate_file_filter_is_workspace_relative() {
    let outer = tempdir("retrieval-search-candidates-parent");
    let root = outer.join("tests/chosen-workspace");
    std::fs::create_dir_all(root.join("tests")).expect("mkdir workspace");
    std::fs::create_dir_all(root.join("unit-tests")).expect("mkdir unit-tests");
    std::fs::write(root.join("app.py"), "def app_marker():\n    return 1\n").expect("write app");
    std::fs::write(root.join("tests/helper.py"), "def test_marker():\n    return 2\n").expect("write helper");
    std::fs::write(
        root.join("unit-tests/helper.py"),
        "def unit_tests_marker():\n    return 3\n",
    )
    .expect("write unit-tests helper");
    let bonsai = bonsai_sdk::Bonsai::new();
    bonsai.index_semantic(&root).expect("semantic index");

    let filters = bonsai
        .retrieval_candidate_file_filters(
            &root,
            "marker",
            bonsai_sdk::SearchFilters {
                file: Some("tests/"),
                ..bonsai_sdk::SearchFilters::default()
            },
        )
        .expect("candidate filters")
        .expect("fresh retrieval sidecar");

    assert_eq!(filters, vec!["tests/helper.py"]);
    let _ = std::fs::remove_dir_all(outer);
}

#[test]
fn sdk_retrieval_candidate_filters_cover_operation_candidates() {
    let root = tempdir("retrieval-operation-candidates");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(root.join("gen.py"), "def gen(payload):\n    yield payload[0]\n").expect("write gen");
    let bonsai = bonsai_sdk::Bonsai::new();
    bonsai.index_semantic(&root).expect("semantic index");

    let filters = bonsai
        .retrieval_candidate_file_filters(
            &root,
            "payload[0]",
            bonsai_sdk::SearchFilters {
                kind: Some("operation"),
                ..Default::default()
            },
        )
        .expect("candidate filters")
        .expect("fresh retrieval sidecar");

    assert_eq!(filters, vec!["gen.py"]);
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_retrieval_candidate_filters_reject_stale_sidecar() {
    let root = tempdir("retrieval-search-stale");
    let service = root.join("service.py");
    std::fs::write(root.join("app.py"), "def unrelated():\n    return 1\n").expect("write app");
    std::fs::write(&service, "def stale_sdk_symbol():\n    return 'old'\n").expect("write service");
    let bonsai = bonsai_sdk::Bonsai::new();
    bonsai.index_semantic(&root).expect("semantic index");

    std::fs::write(&service, "def fresh_sdk_symbol():\n    return 'new'\n").expect("edit service");
    let filters = bonsai
        .retrieval_candidate_file_filters(&root, "stale_sdk_symbol", bonsai_sdk::SearchFilters::default())
        .expect("candidate filters");

    assert!(
        filters.is_none(),
        "SDK must reject stale retrieval sidecars before candidate narrowing"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_retrieval_search_hydration_filters_do_not_expand_empty_candidates() {
    let root = tempdir("retrieval-search-empty");
    std::fs::write(root.join("app.py"), "def only_symbol():\n    return 1\n").expect("write app");
    let bonsai = bonsai_sdk::Bonsai::new();
    bonsai.index_semantic(&root).expect("semantic index");

    let candidate_files = bonsai
        .retrieval_candidate_file_filters(&root, "missing_symbol", bonsai_sdk::SearchFilters::default())
        .expect("candidate filters")
        .expect("fresh retrieval sidecar");
    assert!(
        candidate_files.is_empty(),
        "actual candidate files should be empty for a fresh no-match sidecar"
    );

    let include_filters = bonsai
        .retrieval_hydration_include_filters(&root, "missing_symbol", bonsai_sdk::SearchFilters::default())
        .expect("hydration filters")
        .expect("fresh retrieval sidecar");
    assert!(
        !include_filters.is_empty(),
        "hydration filters must not use [] because [] opens the whole workspace"
    );

    let scoped = bonsai
        .open_query_filtered_paths(&root, &include_filters, &[])
        .expect("open scoped project");
    assert_eq!(
        scoped.stats().files,
        0,
        "fresh no-match retrieval filters should hydrate an empty workspace, not all files"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_reduced_query_opens_keep_their_initial_scope() {
    let root = tempdir("reduced-query-stable-scope");
    std::fs::write(root.join("included.py"), "def included_marker():\n    return 1\n")
        .expect("write included");
    std::fs::write(root.join("excluded.py"), "def excluded_marker():\n    return 2\n")
        .expect("write excluded");
    std::fs::write(
        root.join("literal.py"),
        "def literal_marker():\n    return 'literal-needle'\n",
    )
    .expect("write literal");
    let bonsai = bonsai_sdk::Bonsai::new();
    let include_filters = vec!["included.py".to_string()];
    let filtered = bonsai
        .open_query_filtered_paths(&root, &include_filters, &[])
        .expect("open filtered project");

    assert_eq!(filtered.stats().files, 1);
    assert!(filtered
        .browse()
        .search("included_marker", Default::default(), usize::MAX)
        .expect("included search")
        .iter()
        .any(|hit| hit.name == "included_marker"));
    assert!(
        filtered
            .browse()
            .search("excluded_marker", Default::default(), usize::MAX)
            .expect("excluded search")
            .is_empty(),
        "path-filtered SDK project must not auto-refresh and add files outside the initial filter"
    );

    let literal = bonsai
        .open_query_matching_literal(&root, "literal-needle")
        .expect("open literal project");
    assert_eq!(literal.stats().files, 1);
    assert!(literal
        .browse()
        .search("literal_marker", Default::default(), usize::MAX)
        .expect("literal search")
        .iter()
        .any(|hit| hit.name == "literal_marker"));
    assert!(
        literal
            .browse()
            .search("included_marker", Default::default(), usize::MAX)
            .expect("included search from literal project")
            .is_empty(),
        "literal-reduced SDK project must not auto-refresh and add files outside the matched set"
    );

    let path = bonsai
        .open_query_matching_path(&root, "included.py")
        .expect("open path project");
    assert_eq!(path.stats().files, 1);
    assert!(path
        .browse()
        .search("included_marker", Default::default(), usize::MAX)
        .expect("included search from path project")
        .iter()
        .any(|hit| hit.name == "included_marker"));
    assert!(
        path.browse()
            .search("literal_marker", Default::default(), usize::MAX)
            .expect("literal search from path project")
            .is_empty(),
        "path-reduced SDK project must not auto-refresh and add files outside the requested file"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn sdk_browse_file_filters_are_workspace_relative() {
    let outer = tempdir("browse-root-under-tests");
    let root = outer.join("tests/chosen-workspace");
    std::fs::create_dir_all(root.join("tests")).expect("create nested workspace");
    std::fs::create_dir_all(root.join("unit-tests")).expect("create unit-tests workspace dir");
    std::fs::write(root.join("app.py"), "def app_marker():\n    return 1\n").expect("write app");
    std::fs::write(root.join("tests/helper.py"), "def test_marker():\n    return 2\n").expect("write helper");
    std::fs::write(
        root.join("unit-tests/helper.py"),
        "def unit_tests_marker():\n    return 3\n",
    )
    .expect("write unit-tests helper");

    let project = bonsai_sdk::Bonsai::new()
        .index_structural(&root)
        .expect("open project");
    let defs = project
        .browse()
        .defs(bonsai_sdk::DefsFilters {
            file: Some("tests/"),
            ..Default::default()
        })
        .expect("defs");
    assert!(
        defs.iter().any(|def| def.name == "test_marker"),
        "workspace-local tests/helper.py should match tests/: {defs:?}"
    );
    assert!(
        defs.iter().all(|def| def.name != "app_marker"),
        "root app.py must not match tests/ only because a parent outside the workspace is tests/: {defs:?}"
    );
    assert!(
        defs.iter().all(|def| def.name != "unit_tests_marker"),
        "unit-tests/helper.py must not match a component filter for tests/: {defs:?}"
    );

    let tree = project
        .browse()
        .tree(bonsai_sdk::TreeFilters {
            file: Some("tests/"),
            ..Default::default()
        })
        .expect("tree");
    assert_eq!(
        tree.summary.total_files_scanned, 1,
        "tree --file tests/ should scan only the workspace-local tests file"
    );
    let _ = std::fs::remove_dir_all(outer);
}

#[test]
fn cache_stats_validation_rejects_corrupt_retrieval_sidecar_even_when_size_matches() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-cache-validation-retrieval-corrupt");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic readiness: {fresh:#?}"
    );
    assert!(
        fresh.retrieval_sidecar_bytes > 0,
        "fixture should write a non-empty retrieval sidecar: {fresh:#?}"
    );

    std::fs::write(
        &fresh.retrieval_sidecar,
        vec![0_u8; fresh.retrieval_sidecar_bytes as usize],
    )
    .expect("overwrite retrieval sidecar with same-size corrupt payload");
    let stale = sdk
        .cache(&root)
        .stats()
        .expect("stats after corrupt retrieval sidecar");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "same-size corruption should leave the manifest fresh so sidecar payload validation proves the issue: {stale:#?}"
    );
    assert!(
        !stale.validation.structural_ready && !stale.validation.semantic_ready,
        "semantic readiness must require a decodable retrieval factstore: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "retrieval" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt retrieval sidecar should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("retrieval sidecar validation failed")),
        "cache stats should explain retrieval payload validation failure: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_rejects_corrupt_callgraph_sidecar_even_when_size_matches() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-cache-validation-callgraph-corrupt");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic readiness: {fresh:#?}"
    );
    assert!(
        fresh.callgraph_sidecar_bytes > 0,
        "fixture should write a non-empty callgraph sidecar: {fresh:#?}"
    );

    std::fs::write(
        &fresh.callgraph_sidecar,
        vec![0_u8; fresh.callgraph_sidecar_bytes as usize],
    )
    .expect("overwrite callgraph sidecar with same-size corrupt payload");
    let stale = sdk
        .cache(&root)
        .stats()
        .expect("stats after corrupt callgraph sidecar");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "same-size corruption should leave the manifest fresh so sidecar payload validation proves the issue: {stale:#?}"
    );
    assert!(
        !stale.validation.structural_ready && !stale.validation.semantic_ready,
        "semantic readiness must require a decodable callgraph sidecar: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "callgraph" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt callgraph sidecar should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("callgraph sidecar validation failed")),
        "cache stats should explain callgraph payload validation failure: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_rejects_corrupt_idg_sidecar_even_when_size_matches() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-cache-validation-idg-corrupt");
    let sdk = sdk();
    let indexed = sdk.index_semantic(&root).expect("semantic index");
    let fresh = indexed.cache().stats().expect("fresh semantic cache stats");
    assert!(
        fresh.validation.semantic_ready,
        "fixture should start with validated semantic readiness: {fresh:#?}"
    );
    assert!(
        fresh.idg_sidecar_bytes > 0,
        "fixture should write a non-empty IDG sidecar: {fresh:#?}"
    );

    std::fs::write(&fresh.idg_sidecar, vec![0_u8; fresh.idg_sidecar_bytes as usize])
        .expect("overwrite IDG sidecar with same-size corrupt payload");
    let stale = sdk.cache(&root).stats().expect("stats after corrupt IDG sidecar");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "same-size corruption should leave the manifest fresh so sidecar payload validation proves the issue: {stale:#?}"
    );
    assert!(
        !stale.validation.structural_ready && !stale.validation.semantic_ready,
        "semantic readiness must require a decodable IDG sidecar: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "idg" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt IDG sidecar should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("idg sidecar validation failed")),
        "cache stats should explain IDG payload validation failure: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_rejects_corrupt_flow_ids_sidecar_even_when_size_matches() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let _dataflow_guard = DATAFLOW_ENV_LOCK.lock().expect("dataflow env lock");
    let root = temp_python_micro("semantic-cache-validation-flow-ids-corrupt");
    let project = sdk()
        .open_with_options(&root, bonsai_sdk::OpenOptions::full_prewarm())
        .expect("full prewarm index");
    let fresh = project.cache().stats().expect("fresh full-prewarm cache stats");
    assert_eq!(
        fresh.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "fixture should start with a fresh cache manifest: {fresh:#?}"
    );
    assert!(
        fresh.flow_ids_sidecar_exists && fresh.flow_ids_sidecar_bytes > 0,
        "full prewarm should write a non-empty flow-id sidecar: {fresh:#?}"
    );

    std::fs::write(
        &fresh.flow_ids_sidecar,
        vec![0_u8; fresh.flow_ids_sidecar_bytes as usize],
    )
    .expect("overwrite flow-id sidecar with same-size corrupt payload");
    let stale = sdk()
        .cache(&root)
        .stats()
        .expect("stats after corrupt flow-id sidecar");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "same-size corruption should leave the manifest fresh so sidecar payload validation proves the issue: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "flow_ids" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt flow-id sidecar should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("flow-id sidecar validation failed")),
        "cache stats should explain flow-id payload validation failure: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn cache_stats_validation_rejects_corrupt_full_prewarm_factstores_even_when_size_matches() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let _dataflow_guard = DATAFLOW_ENV_LOCK.lock().expect("dataflow env lock");
    let root = temp_python_micro("semantic-cache-validation-full-prewarm-corrupt");
    let project = sdk()
        .open_with_options(&root, bonsai_sdk::OpenOptions::full_prewarm())
        .expect("full prewarm index");
    let fresh = project.cache().stats().expect("fresh full-prewarm cache stats");
    assert_eq!(
        fresh.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "fixture should start with a fresh cache manifest: {fresh:#?}"
    );
    assert!(
        fresh.dataflow_factstore_sidecar_exists && fresh.dataflow_factstore_sidecar_bytes > 0,
        "full prewarm should write a non-empty dataflow factstore: {fresh:#?}"
    );
    assert!(
        fresh.value_flow_sidecar_exists && fresh.value_flow_sidecar_bytes > 0,
        "full prewarm should write a non-empty value-flow sidecar: {fresh:#?}"
    );

    std::fs::write(
        &fresh.dataflow_factstore_sidecar,
        vec![0_u8; fresh.dataflow_factstore_sidecar_bytes as usize],
    )
    .expect("overwrite dataflow factstore with same-size corrupt payload");
    std::fs::write(
        &fresh.value_flow_sidecar,
        vec![0_u8; fresh.value_flow_sidecar_bytes as usize],
    )
    .expect("overwrite value-flow sidecar with same-size corrupt payload");

    let stale = sdk()
        .cache(&root)
        .stats()
        .expect("stats after corrupt full-prewarm factstores");
    assert_eq!(
        stale.validation.manifest_status,
        bonsai_sdk::CacheFreshnessStatus::Fresh,
        "same-size corruption should leave the manifest fresh so sidecar payload validation proves the issue: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "dataflow_factstore" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt dataflow factstore should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "value_flow" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::Stale
        }),
        "corrupt value-flow sidecar should be stale even when its size matches the manifest: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("dataflow factstore sidecar validation failed")),
        "cache stats should explain dataflow factstore payload validation failure: {stale:#?}"
    );
    assert!(
        stale
            .validation
            .stale_reasons
            .iter()
            .any(|reason| reason.contains("value-flow sidecar validation failed")),
        "cache stats should explain value-flow payload validation failure: {stale:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_index_semantic_explicitly_prewarms_sidecars() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let root = temp_python_micro("semantic-index-alias");
    let indexed = sdk().index_semantic(&root).expect("semantic index alias");
    let stats = indexed.cache().stats().expect("semantic alias cache stats");
    assert!(
        stats.manifest_exists
            && stats.callgraph_sidecar_exists
            && stats.idg_sidecar_exists
            && stats.retrieval_sidecar_exists,
        "index_semantic should explicitly prewarm structural semantic and retrieval sidecars: {stats:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_semantic_manifest_treats_disabled_idg_sidecar_as_not_applicable() {
    let _guard = IDG_SIDECAR_LIMIT_ENV_LOCK.lock().expect("idg sidecar env lock");
    let old_limit = std::env::var("BONSAI_IDG_SIDECAR_FILE_LIMIT").ok();
    std::env::set_var("BONSAI_IDG_SIDECAR_FILE_LIMIT", "0");

    let root = temp_python_micro("semantic-index-idg-disabled");
    let indexed = sdk().index_semantic(&root).expect("semantic index");
    let stats = indexed.cache().stats().expect("semantic cache stats");
    assert!(
        stats.callgraph_sidecar_exists && stats.retrieval_sidecar_exists && !stats.idg_sidecar_exists,
        "semantic index should write callgraph/retrieval and skip a disabled IDG sidecar: {stats:#?}"
    );
    assert!(
        stats.validation.semantic_ready,
        "disabled IDG sidecar should validate as semantic-ready through not-applicable status: {stats:#?}"
    );
    assert!(
        stats.validation.sidecars.iter().any(|sidecar| {
            sidecar.name == "idg" && sidecar.status == bonsai_sdk::CacheFreshnessStatus::NotApplicable
        }),
        "disabled IDG sidecar should be reported as not-applicable in cache stats: {stats:#?}"
    );
    let manifest = indexed
        .cache()
        .read_manifest()
        .expect("read manifest")
        .expect("manifest exists");
    assert!(
        manifest.coverage.semantic_ready,
        "disabled IDG sidecar should be not-applicable, not a semantic readiness miss: {manifest:#?}"
    );
    assert!(
        !manifest
            .coverage
            .missing_reasons
            .iter()
            .any(|reason| reason.contains("idg")),
        "disabled IDG sidecar should not appear in missing reasons: {manifest:#?}"
    );

    match old_limit {
        Some(value) => std::env::set_var("BONSAI_IDG_SIDECAR_FILE_LIMIT", value),
        None => std::env::remove_var("BONSAI_IDG_SIDECAR_FILE_LIMIT"),
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn query_open_loads_callgraph_sidecar_when_dataflow_is_disabled() {
    let _guard = DATAFLOW_ENV_LOCK.lock().expect("dataflow env lock");
    let old = std::env::var("BONSAI_NO_DATAFLOW").ok();
    std::env::set_var("BONSAI_NO_DATAFLOW", "1");

    let root = temp_python_micro("query-no-dataflow-callgraph");
    sdk().index_semantic(&root).expect("semantic index");
    let events = Mutex::new(Vec::new());
    sdk()
        .open_with_options_and_progress(&root, bonsai_sdk::OpenOptions::query_only(), |event| {
            events.lock().expect("events lock").push(event);
        })
        .expect("query open");
    let events = events.into_inner().expect("events lock");
    assert!(
        events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::CacheChecked {
                cache: "dataflow",
                status: bonsai_sdk::WorkspaceCacheStatus::Skipped,
                ..
            }
        )),
        "test setup should skip dataflow through BONSAI_NO_DATAFLOW: {events:#?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::CacheChecked {
                cache: "callgraph",
                status: bonsai_sdk::WorkspaceCacheStatus::Hit,
                ..
            }
        )),
        "query open should still load a fresh callgraph sidecar when dataflow is disabled: {events:#?}"
    );

    match old {
        Some(value) => std::env::set_var("BONSAI_NO_DATAFLOW", value),
        None => std::env::remove_var("BONSAI_NO_DATAFLOW"),
    }
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_index_is_structural_by_default() {
    let root = temp_python_micro("default-index");
    let indexed = sdk().index(&root).expect("index");
    let stats = indexed.cache().stats().expect("default index cache stats");
    assert!(
        !stats.callgraph_sidecar_exists
            && !stats.idg_sidecar_exists
            && !stats.dataflow_factstore_sidecar_exists
            && !stats.value_flow_sidecar_exists
            && !stats.flow_ids_sidecar_exists
            && !stats.manifest_exists,
        "default SDK index should stay structural and avoid semantic sidecars: {stats:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn bonsai_builder_accepts_preloaded_rulepack_before_opening_project() {
    let root = temp_python_micro("builder-preloaded-rulepack");
    let rulepack_root = repo_root().join("security-patterns");
    let rulepack = bonsai_sdk::load_rulepack(&rulepack_root).expect("load rulepack once");
    let project = bonsai_sdk::Bonsai::new()
        .with_loaded_rulepack(&rulepack_root, rulepack)
        .open_query(&root)
        .expect("open project with preloaded rulepack");

    assert!(project.rulepack().is_some());
    assert_eq!(project.rulepack_root(), Some(rulepack_root.as_path()));
    assert!(!project
        .security()
        .taint_analysis(Default::default())
        .expect("taint analysis with preloaded builder rulepack")
        .findings
        .is_empty());

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_show_reopens_structured_stable_ids() {
    let root = temp_python_micro("show-stable-ids");
    let project = sdk().open_query(&root).expect("open query");

    let edge = project
        .dump()
        .edges(Default::default())
        .into_iter()
        .next()
        .expect("fixture should emit at least one edge");
    match project
        .show()
        .by_id(&edge.edge_id, Default::default())
        .expect("show edge id")
    {
        bonsai_sdk::ShowOutcome::Edge(row) => assert_eq!(row.edge_id, edge.edge_id),
        other => panic!("expected edge outcome, got {other:?}"),
    }

    let ast_root = match project.dump().ast(bonsai_sdk::AstFilters {
        function: Some("handle_request"),
        max_depth: Some(0),
        ..Default::default()
    }) {
        bonsai_sdk::AstOutcome::Dumps(mut dumps) => dumps.pop().expect("AST dump"),
        bonsai_sdk::AstOutcome::NodeIdNotFound => panic!("function AST should exist"),
    };
    match project
        .show()
        .by_id(&ast_root.root.node_id, Default::default())
        .expect("show AST node id")
    {
        bonsai_sdk::ShowOutcome::AstNode(row) => assert_eq!(row.root.node_id, ast_root.root.node_id),
        other => panic!("expected AST node outcome, got {other:?}"),
    }

    let candidate_id = match project.dump().resolve("handle_request", Default::default()) {
        bonsai_sdk::ResolveOutcome::Trace(trace) => trace
            .candidates
            .first()
            .expect("resolver candidate")
            .candidate_id
            .clone(),
        other => panic!("expected resolver trace, got {other:?}"),
    };
    match project
        .show()
        .by_id(
            &candidate_id,
            bonsai_sdk::ShowOptions {
                query: Some("handle_request"),
                ..Default::default()
            },
        )
        .expect("show resolver candidate id")
    {
        bonsai_sdk::ShowOutcome::ResolverCandidate(trace) => {
            assert_eq!(trace.candidates.len(), 1);
            assert_eq!(trace.candidates[0].candidate_id, candidate_id);
        }
        other => panic!("expected resolver candidate outcome, got {other:?}"),
    }

    let inspect_targets = project
        .inspect()
        .chains(bonsai_sdk::InspectQuery {
            pattern: Some("handle_request"),
            max_chains: usize::MAX,
            max_probes: usize::MAX,
            ..Default::default()
        })
        .expect("inspect graph-flow chains");
    let target_chains = inspect_targets
        .iter()
        .find(|target| !target.chains.is_empty() && !target.groups.is_empty())
        .expect("fixture should emit graph-flow chains and groups");
    let flow_id = target_chains.chains[0].flow_id.clone();
    assert!(flow_id.starts_with("F:"), "flow_id malformed: {flow_id}");
    match project
        .show()
        .by_id(&flow_id, Default::default())
        .expect("show inspect flow id")
    {
        bonsai_sdk::ShowOutcome::InspectFlow(flow) => {
            assert_eq!(flow.flow_id, flow_id);
            assert!(flow
                .matches
                .iter()
                .any(|matched| matched.chain.flow_id == flow_id));
        }
        other => panic!("expected inspect flow outcome, got {other:?}"),
    }

    let group_id = target_chains.groups[0].group_id.clone();
    assert!(group_id.starts_with("G:"), "group_id malformed: {group_id}");
    let expected_member = target_chains.groups[0]
        .member_flow_ids
        .first()
        .expect("group should have member flow ids")
        .clone();
    match project
        .show()
        .by_id(&group_id, Default::default())
        .expect("show inspect flow group id")
    {
        bonsai_sdk::ShowOutcome::InspectFlowGroup(group) => {
            assert_eq!(group.group_id, group_id);
            assert!(group.matches.iter().any(|matched| {
                matched.group.group_id == group_id
                    && matched
                        .chains
                        .iter()
                        .any(|chain| chain.flow_id == expected_member)
            }));
        }
        other => panic!("expected inspect flow group outcome, got {other:?}"),
    }

    let taint = match project.dump().taint(bonsai_sdk::TaintFilters {
        source: "update_user",
        seeds: vec!["token".into(), "action".into()],
        ..Default::default()
    }) {
        bonsai_sdk::TaintOutcome::Report(report) => report,
        other => panic!("expected taint report, got {other:?}"),
    };
    let taint_id = taint
        .records
        .first()
        .expect("fixture should emit a T: propagation id")
        .taint_id
        .clone();
    match project
        .show()
        .by_id(
            &taint_id,
            bonsai_sdk::ShowOptions {
                taint_source: Some("update_user"),
                taint_seeds: &["token", "action"],
                ..Default::default()
            },
        )
        .expect("show taint propagation id")
    {
        bonsai_sdk::ShowOutcome::TaintPropagation(report) => {
            assert_eq!(report.records.len(), 1);
            assert_eq!(report.records[0].taint_id, taint_id);
        }
        other => panic!("expected taint propagation outcome, got {other:?}"),
    }

    let security = project
        .security()
        .taint_analysis(bonsai_sdk::TaintAnalysisOptions {
            include_pattern_only: true,
            show_sanitized: true,
            ..Default::default()
        })
        .expect("security findings");
    let finding_id = security
        .findings
        .first()
        .expect("fixture should emit at least one security finding")
        .finding
        .finding_id
        .clone();
    let security_flow_id = security
        .findings
        .first()
        .and_then(|finding| finding.finding.representative_flow_id.clone())
        .expect("fixture should emit a security representative flow id");
    let security_group_id = security
        .findings
        .first()
        .and_then(|finding| finding.finding.group_id.clone())
        .expect("fixture should emit a security group id");
    match project
        .show()
        .by_id(&finding_id, Default::default())
        .expect("show security finding id")
    {
        bonsai_sdk::ShowOutcome::SecurityFinding(finding) => {
            assert_eq!(finding.finding.finding_id, finding_id);
        }
        other => panic!("expected security finding outcome, got {other:?}"),
    }
    match project
        .show()
        .by_id(&security_flow_id, Default::default())
        .expect("show security flow id")
    {
        bonsai_sdk::ShowOutcome::SecurityFinding(finding) => {
            assert_eq!(
                finding.finding.representative_flow_id.as_deref(),
                Some(security_flow_id.as_str())
            );
        }
        other => panic!("expected security finding outcome for security F: id, got {other:?}"),
    }
    match project
        .show()
        .by_id(&security_group_id, Default::default())
        .expect("show security group id")
    {
        bonsai_sdk::ShowOutcome::SecurityFindingGroup(group) => {
            assert_eq!(group.group_id, security_group_id.as_str());
            assert!(group
                .findings
                .iter()
                .any(|finding| finding.finding.group_id.as_deref() == Some(security_group_id.as_str())));
        }
        other => panic!("expected security group outcome for security G: id, got {other:?}"),
    }

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_semantic_context_reports_shared_workspace_shape() {
    let root = tempdir("semantic-context");
    std::fs::create_dir_all(root.join("src")).expect("create src");
    std::fs::create_dir_all(root.join("generated")).expect("create generated");
    std::fs::create_dir_all(root.join("node_modules/pkg")).expect("create dependency root");
    std::fs::create_dir_all(root.join("dist")).expect("create build output root");
    std::fs::create_dir_all(root.join(".bonsai")).expect("create excluded root");
    std::fs::write(root.join("package.json"), r#"{"name":"fixture"}"#).expect("write package json");
    std::fs::write(root.join("compile_commands.json"), "[]").expect("write compile database");
    std::fs::write(root.join("src/app.py"), "def app():\n    return 1\n").expect("write source");
    std::fs::write(
        root.join("generated/client.py"),
        "def generated_client():\n    return 2\n",
    )
    .expect("write generated source");
    std::fs::write(
        root.join("node_modules/pkg/index.py"),
        "def vendored():\n    return 3\n",
    )
    .expect("write dependency source");
    std::fs::write(root.join("dist/app.py"), "def built():\n    return 4\n").expect("write build output");

    let project = bonsai_sdk::Bonsai::new()
        .index(&root)
        .expect("index context fixture");
    let context = project.semantic_context();

    assert_eq!(context.summary.indexed_files, project.stats().files);
    assert_eq!(context.summary.first_party_files, 1);
    assert_eq!(context.summary.generated_files, 1);
    assert!(context
        .toolchain_manifests
        .iter()
        .any(|manifest| manifest.path == "package.json" && manifest.kind == "package_manifest"));
    assert!(context
        .toolchain_manifests
        .iter()
        .any(|manifest| manifest.path == "compile_commands.json" && manifest.kind == "compile_database"));
    assert!(context
        .configured_source_variants
        .iter()
        .any(|variant| variant.kind == "configured_translation_units"));
    assert!(context
        .dependency_roots
        .iter()
        .any(|root| root.path == "node_modules"));
    assert!(context
        .generated_roots
        .iter()
        .any(|root| root.path == "generated"));
    assert!(context.generated_roots.iter().any(|root| root.path == "dist"));
    assert!(context.excluded_roots.iter().any(|root| root.path == ".bonsai"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_index_with_progress_reports_structural_lifecycle() {
    let root = temp_python_micro("progress");
    let events = Mutex::new(Vec::new());
    let project = sdk()
        .index_with_progress(&root, |event| {
            events.lock().expect("events lock").push(event);
        })
        .expect("index with progress");

    assert!(project.stats().files > 0);
    let events = events.into_inner().expect("events lock");
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestStarted));
    let parsed_files = events
        .iter()
        .find_map(|event| match event {
            bonsai_sdk::WorkspaceOpenEvent::ParseStarted { files } => Some(*files),
            _ => None,
        })
        .expect("parse started event");
    assert_eq!(parsed_files, project.stats().files);
    assert_eq!(
        events
            .iter()
            .filter(|event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::ParseFileIndexed))
            .count(),
        parsed_files
    );
    assert!(
        !events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmStarted { .. }
                | bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmFinished
                | bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmStarted
                | bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmFinished
                | bonsai_sdk::WorkspaceOpenEvent::FlowIdsPrewarmStarted
                | bonsai_sdk::WorkspaceOpenEvent::FlowIdsPrewarmFinished
        )),
        "index_with_progress should stay structural by default: {events:#?}"
    );
    assert!(
        !project.cache().stats().expect("cache stats").manifest_exists,
        "structural progress index should not write a semantic cache manifest"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_full_prewarm_with_progress_reports_analysis_prewarm() {
    let _dataflow_guard = DATAFLOW_ENV_LOCK.lock().expect("dataflow env lock");
    let root = temp_python_micro("progress-full-prewarm");
    let events = Mutex::new(Vec::new());
    let project = sdk()
        .open_with_options_and_progress(&root, bonsai_sdk::OpenOptions::full_prewarm(), |event| {
            events.lock().expect("events lock").push(event);
        })
        .expect("full prewarm with progress");

    assert!(project.stats().files > 0);
    let events = events.into_inner().expect("events lock");
    assert!(events.iter().any(|event| matches!(
        event,
        bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmStarted { .. }
    )));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::DataflowPrewarmFinished));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmStarted));
    assert!(events.contains(&bonsai_sdk::WorkspaceOpenEvent::ValueFlowPrewarmFinished));
    assert!(
        events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::CacheChecked {
                cache: "dataflow factstore",
                status: bonsai_sdk::WorkspaceCacheStatus::Miss,
                entries: 0,
            }
        )),
        "full prewarm should explain the dataflow sidecar cache decision: {events:#?}"
    );
    assert!(
        events.iter().any(|event| matches!(
            event,
            bonsai_sdk::WorkspaceOpenEvent::CacheChecked {
                cache: "value-flow",
                status: bonsai_sdk::WorkspaceCacheStatus::Miss,
                entries: 0,
            }
        )),
        "full prewarm should explain the value-flow sidecar cache decision: {events:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_reduced_query_opens_report_progress_events() {
    let root = temp_python_micro("reduced-progress");

    let literal_events = Mutex::new(Vec::new());
    let literal_project = sdk()
        .open_query_matching_literal_with_progress(&root, "handle_request", |event| {
            literal_events.lock().expect("events lock").push(event);
        })
        .expect("literal open with progress");
    assert!(literal_project.stats().files > 0);
    let literal_events = literal_events.into_inner().expect("events lock");
    assert!(literal_events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestStarted));
    assert!(literal_events.iter().any(
        |event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::IngestFinished { files } if *files > 0)
    ));
    assert!(literal_events
        .iter()
        .any(|event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::ParseStarted { files } if *files > 0)));
    assert!(literal_events
        .iter()
        .any(|event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::ParseFileIndexed)));
    assert!(literal_events.contains(&bonsai_sdk::WorkspaceOpenEvent::ParseFinished));

    let include = vec!["gateway.py".to_string()];
    let filtered_events = Mutex::new(Vec::new());
    let filtered_project = sdk()
        .open_query_filtered_paths_with_progress(&root, &include, &[], |event| {
            filtered_events.lock().expect("events lock").push(event);
        })
        .expect("filtered open with progress");
    assert!(filtered_project.stats().files > 0);
    let filtered_events = filtered_events.into_inner().expect("events lock");
    assert!(filtered_events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestStarted));
    assert!(filtered_events.iter().any(
        |event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::IngestFinished { files } if *files > 0)
    ));

    let path_events = Mutex::new(Vec::new());
    let _path_project = sdk()
        .open_query_matching_path_with_progress(&root, "gateway.py", |event| {
            path_events.lock().expect("events lock").push(event);
        })
        .expect("single-file open with progress");
    let path_events = path_events.into_inner().expect("events lock");
    assert!(path_events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestStarted));
    assert!(path_events.contains(&bonsai_sdk::WorkspaceOpenEvent::IngestFinished { files: 1 }));
    assert!(path_events.contains(&bonsai_sdk::WorkspaceOpenEvent::ParseStarted { files: 1 }));
    assert_eq!(
        path_events
            .iter()
            .filter(|event| matches!(event, bonsai_sdk::WorkspaceOpenEvent::ParseFileIndexed))
            .count(),
        1
    );
    assert!(path_events.contains(&bonsai_sdk::WorkspaceOpenEvent::ParseFinished));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_hot_reloads_saved_source_changes() {
    let root = tempdir("hot-reload");
    let app = root.join("app.py");
    std::fs::write(&app, "def old_name():\n    pass\n").expect("write initial source");
    let project = bonsai_sdk::Bonsai::new().index(&root).expect("index");

    let names = |project: &bonsai_sdk::Project| -> Vec<String> {
        project
            .browse()
            .defs(Default::default())
            .expect("defs")
            .into_iter()
            .map(|def| def.name)
            .collect()
    };
    assert!(names(&project).contains(&"old_name".to_string()));

    std::fs::write(&app, "def new_name():\n    pass\n").expect("modify source");
    let after_modify = names(&project);
    assert!(after_modify.contains(&"new_name".to_string()));
    assert!(!after_modify.contains(&"old_name".to_string()));

    let extra = root.join("extra.py");
    std::fs::write(&extra, "def added_name():\n    pass\n").expect("add source");
    let after_add = names(&project);
    assert!(after_add.contains(&"added_name".to_string()));

    std::fs::remove_file(&extra).expect("remove source");
    let after_remove = names(&project);
    assert!(!after_remove.contains(&"added_name".to_string()));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_browse_plain_text_filters_rank_exact_before_prefix_and_substring() {
    let root = tempdir("browse-relevance");
    std::fs::write(
        root.join("app.py"),
        r#"
import atoken
import token
import token_extra
import user_token

# atoken
# token
# token_extra
# user_token

class atoken:
    def run(self):
        pass

class token:
    def run(self):
        pass

class token_extra:
    def run(self):
        pass

class user_token:
    def run(self):
        pass

def atoken():
    pass

def token():
    pass

def token_extra():
    pass

def user_token():
    pass

def aroot():
    pass

def root():
    pass

def root_extra():
    pass

def user_root():
    pass

def sink(value):
    return value

def handle():
    atoken_value = "atoken"
    token = "token"
    token_extra = "token_extra"
    user_token = "user_token"
    sink(atoken_value)
    sink(token)
    sink(token_extra)
    sink(user_token)
"#,
    )
    .expect("write relevance fixture");
    let project = bonsai_sdk::Bonsai::new()
        .index(&root)
        .expect("index relevance fixture");
    let browse = project.browse();

    let defs = browse
        .defs(bonsai_sdk::DefsFilters {
            kind: Some("function"),
            name: Some("token"),
            ..Default::default()
        })
        .expect("defs");
    assert_eq!(defs.first().map(|row| row.name.as_str()), Some("token"));

    let entrypoints = browse
        .entrypoints(bonsai_sdk::EntryPointsFilters {
            kind: Some("function"),
            name: Some("root"),
            ..Default::default()
        })
        .expect("entrypoints");
    assert_eq!(entrypoints.first().map(|row| row.name.as_str()), Some("root"));

    let imports = browse
        .imports(bonsai_sdk::ImportsFilters {
            module: Some("token"),
            ..Default::default()
        })
        .expect("imports");
    assert_eq!(imports.first().map(|row| row.module.as_str()), Some("token"));

    let vars = browse
        .vars(bonsai_sdk::VarsFilters {
            name: Some("token"),
            ..Default::default()
        })
        .expect("vars");
    assert_eq!(vars.first().map(|row| row.name.as_str()), Some("token"));

    let strings = browse
        .strings(bonsai_sdk::StringsFilters {
            contains: Some("token"),
            ..Default::default()
        })
        .expect("strings");
    assert_eq!(strings.first().map(|row| row.text.as_str()), Some("\"token\""));

    let comments = browse
        .comments(bonsai_sdk::CommentsFilters {
            contains: Some("token"),
            ..Default::default()
        })
        .expect("comments");
    assert_eq!(comments.first().map(|row| row.text.as_str()), Some("# token"));

    let args = browse
        .args(bonsai_sdk::ArgsFilters {
            value: Some("token"),
            ..Default::default()
        })
        .expect("args");
    assert_eq!(args.first().map(|row| row.value.as_str()), Some("token"));

    let classes = browse
        .classes(bonsai_sdk::ClassesFilters {
            name: Some("token"),
            ..Default::default()
        })
        .expect("classes");
    assert_eq!(classes.first().map(|row| row.name.as_str()), Some("token"));

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn facade_browse_dump_export_security_trace_and_inspect_work() {
    let root = python_micro();
    let project = sdk().open_query(&root).expect("open query");
    let ws = project.workspace();

    assert_eq!(
        project.browse().defs(Default::default()).expect("defs").len(),
        bonsai_browse::defs(ws, &Default::default())
            .expect("raw defs")
            .len()
    );
    assert!(!project
        .browse()
        .calls(Default::default())
        .expect("calls")
        .is_empty());
    assert!(!project
        .browse()
        .imports(Default::default())
        .expect("imports")
        .is_empty());
    assert!(!project
        .browse()
        .vars(Default::default())
        .expect("vars")
        .is_empty());
    assert!(!project
        .browse()
        .strings(Default::default())
        .expect("strings")
        .is_empty());
    let _ = project.browse().comments(Default::default()).expect("comments");
    assert!(!project
        .browse()
        .args(Default::default())
        .expect("args")
        .is_empty());
    assert!(!project
        .browse()
        .operations(Default::default())
        .expect("operations")
        .is_empty());
    let _ = project.browse().classes(Default::default()).expect("classes");
    assert!(!project
        .browse()
        .refs("request", Default::default())
        .expect("refs")
        .is_empty());
    assert!(!project
        .browse()
        .search("token", Default::default(), usize::MAX)
        .expect("search")
        .is_empty());
    let paths = project
        .browse()
        .paths(bonsai_sdk::PathFilters {
            from: "handle_request",
            to: "run_admin_command",
            ..Default::default()
        })
        .expect("path");
    assert_eq!(paths.from_matches, 1);
    assert_eq!(paths.to_matches, 1);
    assert!(
        paths
            .paths
            .first()
            .is_some_and(|path| path.functions.iter().any(|func| func.name == "update_user")),
        "SDK path should expose the same semantic route as the CLI"
    );
    let slice = project.browse().slices(bonsai_sdk::SliceFilters {
        symbol: "result",
        line: 15,
        file: Some("gateway.py"),
        ..Default::default()
    });
    assert_eq!(slice.candidate_count, 1);
    assert!(
        slice.slices.first().is_some_and(|row| {
            row.function == "handle_request"
                && row.influencing_symbols.iter().any(|symbol| symbol == "token")
                && row.influencing_symbols.iter().any(|symbol| symbol == "action")
        }),
        "SDK slice should expose the same local influences as the CLI"
    );

    assert!(project.dump().hir("handle_request").expect("dump-hir").is_some());
    assert!(project.dump().cfg("handle_request").expect("dump-cfg").is_some());
    assert!(!project.dump().callgraph().is_empty());
    assert!(!project.dump().edges(Default::default()).is_empty());
    assert!(matches!(
        project.dump().ast(Default::default()),
        bonsai_browse::AstOutcome::Dumps(_)
    ));
    assert!(matches!(
        project.dump().resolve("handle_request", Default::default()),
        bonsai_browse::ResolveOutcome::Trace(_)
    ));
    assert!(matches!(
        project.dump().taint(bonsai_browse::TaintFilters {
            source: "handle_request",
            ..Default::default()
        }),
        bonsai_browse::TaintOutcome::Report(_)
    ));

    let native = project
        .export()
        .native_json(bonsai_sdk::NativeExportOptions {
            full_propagations: true,
            complete_chains: false,
        })
        .expect("native export");
    assert!(native["taint_graph"]["functions"]
        .as_array()
        .is_some_and(|rows| !rows.is_empty()));
    assert!(project
        .export()
        .networkx_json()
        .expect("networkx")
        .contains("\"nodes\""));
    assert!(project.export().graphml().expect("graphml").contains("<graphml"));
    assert!(project
        .export()
        .cypher()
        .expect("cypher")
        .contains("CREATE CONSTRAINT bonsai_node_id"));
    assert!(!project.export().graph_projection().nodes.is_empty());

    assert!(!project
        .security()
        .sources(Default::default())
        .expect("sources")
        .is_empty());
    assert!(!project
        .security()
        .source_rows(Default::default())
        .expect("source rows")
        .is_empty());
    assert!(!project
        .security()
        .sinks(Default::default())
        .expect("sinks")
        .is_empty());
    assert!(!project
        .security()
        .sink_rows(Default::default())
        .expect("sink rows")
        .is_empty());
    let _ = project
        .security()
        .sanitizers(Default::default())
        .expect("sanitizers");
    let _ = project
        .security()
        .sanitizer_rows(Default::default())
        .expect("sanitizer rows");
    assert!(!project
        .security()
        .deps(Default::default())
        .expect("deps")
        .rows
        .is_empty());
    assert!(!project
        .security()
        .pack_inventory(Default::default())
        .expect("pack inventory")
        .is_empty());
    assert_eq!(
        project
            .security()
            .pack_audit(None)
            .expect("pack audit")
            .languages
            .len(),
        21
    );
    assert!(!project
        .security()
        .pack_tree(Default::default())
        .expect("pack tree")
        .languages
        .is_empty());
    let sdk = sdk();
    let rootless_pack = sdk.security_pack().expect("rootless security pack");
    assert!(!rootless_pack
        .inventory(Default::default())
        .expect("rootless pack inventory")
        .is_empty());
    assert_eq!(
        rootless_pack
            .audit(None)
            .expect("rootless pack audit")
            .languages
            .len(),
        21
    );
    assert!(!rootless_pack
        .tree(Default::default())
        .expect("rootless pack tree")
        .languages
        .is_empty());
    assert!(!project
        .security()
        .taint_analysis(Default::default())
        .expect("taint analysis")
        .findings
        .is_empty());
    assert!(!project
        .security()
        .source_analysis(Default::default())
        .expect("source analysis")
        .candidates
        .is_empty());

    let trace = project.trace().from("handle_request").expect("trace");
    assert!(!trace.steps.is_empty());
    assert!(project
        .trace()
        .to_json(&trace)
        .expect("trace json")
        .contains("trace_id"));
    assert!(project.trace().to_text(&trace).contains("Trace:"));
    assert!(project.trace().to_dot(&trace).contains("digraph trace"));
    assert!(!project
        .trace()
        .source_to_sink("handle_request", "system")
        .expect("source to sink trace")
        .steps
        .is_empty());

    assert!(!project
        .inspect()
        .matching_decls(Some("handle_request"), false)
        .expect("inspect decls")
        .is_empty());
    assert!(!project
        .inspect()
        .matching_func_ids(Some("handle_request"), false)
        .expect("inspect funcs")
        .is_empty());
    assert!(!project
        .inspect()
        .chains(bonsai_sdk::InspectQuery {
            pattern: Some("handle_request"),
            ..Default::default()
        })
        .expect("inspect chains")
        .is_empty());
}

#[test]
fn security_methods_require_rulepack() {
    let project = bonsai_sdk::Bonsai::new()
        .open_query(python_micro())
        .expect("open query");
    let err = project
        .security()
        .taint_analysis(Default::default())
        .expect_err("missing rulepack should error");
    assert!(err.to_string().contains("with_rulepack"));
}

#[test]
fn security_phase_progress_reports_taint_graph_sidecar_reuse() {
    let root = temp_python_micro("taint-sidecar-progress");
    let sdk = sdk();

    let first = sdk.open_query(&root).expect("open first project");
    let mut first_notes: Vec<(&'static str, String)> = Vec::new();
    let first_report = first
        .security()
        .taint_analysis_with_phase_progress(Default::default(), |event| {
            if let bonsai_sdk::AnalysisProgress::Note { label, detail } = event {
                first_notes.push((label, detail));
            }
        })
        .expect("first taint analysis");
    assert!(
        !first_report.findings.is_empty(),
        "fixture should produce taint findings"
    );
    let stats = first.cache().stats().expect("cache stats after first taint run");
    assert!(
        stats.taint_graph_sidecar_exists && stats.taint_graph_sidecar_bytes > 0,
        "first SDK taint run should write the taint graph sidecar: {stats:#?}"
    );
    assert!(
        stats.validation.taint_graph_ready,
        "SDK taint run should refresh the cache manifest so the sidecar validates as fresh: {stats:#?}"
    );
    assert!(
        first_notes
            .iter()
            .any(|(label, detail)| { *label == "taint-cache" && detail.contains("write-through on") }),
        "SDK progress should report taint graph write-through on first run: {first_notes:#?}"
    );

    let second = sdk.open_query(&root).expect("open second project");
    let mut second_notes: Vec<(&'static str, String)> = Vec::new();
    let second_report = second
        .security()
        .taint_analysis_with_phase_progress(Default::default(), |event| {
            if let bonsai_sdk::AnalysisProgress::Note { label, detail } = event {
                second_notes.push((label, detail));
            }
        })
        .expect("second taint analysis");
    assert_eq!(
        second_report.findings.len(),
        first_report.findings.len(),
        "sidecar reuse must not change SDK taint findings"
    );
    assert!(
        second_notes.iter().any(|(label, detail)| {
            *label == "taint-cache" && detail.contains("disk hit") && !detail.contains("disk_entries=0")
        }),
        "second SDK run should report taint graph disk reuse: {second_notes:#?}"
    );
    let stats = second
        .cache()
        .stats()
        .expect("cache stats after second taint run");
    assert!(
        stats.validation.taint_graph_ready,
        "second SDK taint run should leave the taint sidecar manifest-fresh: {stats:#?}"
    );
}

#[test]
fn security_source_analysis_refreshes_taint_graph_manifest() {
    let root = temp_python_micro("source-taint-sidecar-manifest");
    let project = sdk().open_query(&root).expect("open project");
    let report = project
        .security()
        .source_analysis(Default::default())
        .expect("source analysis");
    assert!(
        !report.candidates.is_empty(),
        "fixture should produce source-analysis candidates"
    );
    let stats = project
        .cache()
        .stats()
        .expect("cache stats after source analysis");
    assert!(
        stats.taint_graph_sidecar_exists && stats.validation.taint_graph_ready,
        "SDK source-analysis should persist and manifest-refresh the taint graph sidecar: {stats:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn source_and_taint_analysis_use_distinct_taint_graph_sidecars() {
    let root = temp_python_micro("source-taint-sidecar-distinct");
    let project = sdk().open_query(&root).expect("open project");

    let source_report = project
        .security()
        .source_analysis(Default::default())
        .expect("source analysis");
    assert!(
        !source_report.candidates.is_empty(),
        "fixture should produce source-analysis candidates"
    );
    let source_stats = project
        .cache()
        .stats()
        .expect("cache stats after source analysis");
    let source_sidecar = source_stats.taint_graph_sidecar.clone();
    assert!(
        source_sidecar.is_file() && source_stats.validation.taint_graph_ready,
        "source-analysis should publish its configured taint graph sidecar: {source_stats:#?}"
    );

    let taint_report = project
        .security()
        .taint_analysis(Default::default())
        .expect("taint analysis");
    assert!(
        !taint_report.findings.is_empty(),
        "fixture should produce taint findings"
    );
    let taint_stats = project.cache().stats().expect("cache stats after taint analysis");
    let taint_sidecar = taint_stats.taint_graph_sidecar.clone();
    assert!(
        taint_sidecar.is_file() && taint_stats.validation.taint_graph_ready,
        "taint-analysis should publish its configured taint graph sidecar: {taint_stats:#?}"
    );
    assert_ne!(
        source_sidecar, taint_sidecar,
        "source-analysis and taint-analysis must not overwrite the same warm sidecar"
    );
    assert!(
        source_sidecar.is_file(),
        "taint-analysis must leave the source-analysis sidecar reusable at {}",
        source_sidecar.display()
    );

    let mut notes: Vec<(&'static str, String)> = Vec::new();
    let _ = project
        .security()
        .source_analysis_with_phase_progress(Default::default(), |event| {
            if let bonsai_sdk::AnalysisProgress::Note { label, detail } = event {
                notes.push((label, detail));
            }
        })
        .expect("second source analysis");
    assert!(
        notes.iter().any(|(label, detail)| {
            *label == "taint-cache" && detail.contains("disk hit") && !detail.contains("disk_entries=0")
        }),
        "source-analysis should reload its own sidecar after taint-analysis runs: {notes:#?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn scoped_security_analysis_does_not_publish_partial_taint_sidecar() {
    let root = temp_python_micro("scoped-taint-sidecar");
    let sdk = sdk();

    let full = sdk.open_query(&root).expect("open full project");
    let full_report = full
        .security()
        .taint_analysis(Default::default())
        .expect("full taint analysis");
    assert!(
        !full_report.findings.is_empty(),
        "fixture should produce full-workspace taint findings"
    );
    let before = full
        .cache()
        .stats()
        .expect("cache stats after full taint analysis");
    assert!(
        before.taint_graph_sidecar_exists && before.validation.taint_graph_ready,
        "full taint run should write a validated taint graph sidecar: {before:#?}"
    );

    let scoped = sdk
        .open_query_filtered_paths(&root, &["gateway.py".to_string()], &[])
        .expect("open scoped project");
    let mut notes: Vec<(&'static str, String)> = Vec::new();
    let _ = scoped
        .security()
        .taint_analysis_with_phase_progress(
            bonsai_sdk::TaintAnalysisOptions {
                files: vec!["gateway.py".to_string()],
                ..Default::default()
            },
            |event| {
                if let bonsai_sdk::AnalysisProgress::Note { label, detail } = event {
                    notes.push((label, detail));
                }
            },
        )
        .expect("scoped taint analysis");
    assert!(
        notes.iter().any(|(label, detail)| {
            *label == "taint-cache"
                && detail.contains("disk skipped")
                && detail.contains("reason=scoped workspace")
        }),
        "scoped security analysis should not touch the shared taint graph sidecar: {notes:#?}"
    );

    let after = sdk
        .cache(&root)
        .stats()
        .expect("cache stats after scoped taint analysis");
    assert_eq!(
        after.taint_graph_sidecar_bytes, before.taint_graph_sidecar_bytes,
        "scoped taint analysis must not overwrite the full-workspace taint graph sidecar"
    );
    assert!(
        after.validation.taint_graph_ready,
        "scoped taint analysis must not stale the full-workspace taint graph manifest: {after:#?}"
    );
    let _ = std::fs::remove_dir_all(root);
}
