use super::*;

fn source_transfer_site(start: u64) -> bonsai_common::Span {
    bonsai_common::Span::new(FileId::new(1), start, start + 1)
}

fn tempdir_for_test(name: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();
    for attempt in 0..100 {
        let path = base.join(format!("{name}-{}-{nanos}-{attempt}", std::process::id()));
        match std::fs::create_dir(&path) {
            Ok(()) => return path,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("create tempdir {}: {e}", path.display()),
        }
    }
    panic!("could not allocate tempdir for {name}");
}

fn db_with_one_file() -> AnalyzerDb {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "app.py".to_string(),
        Arc::<str>::from("def entry(x):\n    return x\n"),
    );
    AnalyzerDb::new(vfs, Arc::new(LanguageRegistry::new()))
}

#[test]
fn cached_source_inputs_match_legacy_workspace_content_fingerprint() {
    let vfs = Arc::new(Vfs::new());
    vfs.write(
        "src/z.py".to_string(),
        Arc::<str>::from("def z(value):\n    return value\n"),
    );
    vfs.write(
        "src/a.py".to_string(),
        Arc::<str>::from("def a(value):\n    return value\n"),
    );
    let db = AnalyzerDb::new(vfs.clone(), Arc::new(LanguageRegistry::new()));
    let source_inputs = vfs
        .all_files()
        .into_iter()
        .map(|file| {
            let path = vfs.path(file).expect("source path");
            let snapshot = vfs.snapshot(file).expect("source snapshot");
            (
                file.raw(),
                path.to_string_lossy().into_owned(),
                bonsai_hash::fnv1a_bytes64(snapshot.text.as_bytes()),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        workspace_content_fingerprint_from_cached_inputs(&db, Some(&source_inputs)),
        crate::cache_fingerprint::workspace_content_fingerprint(&db),
        "validated source-input hashes must reconstruct the legacy byte-hash identity exactly"
    );
}

#[test]
fn cached_source_fingerprint_preserves_path_identity_and_order_stability() {
    let db = db_with_one_file();
    let mut source_inputs = vec![
        (41, "src/z.py".to_string(), 0x0123_4567_89ab_cdef),
        (7, "src/a.py".to_string(), 0xfedc_ba98_7654_3210),
    ];
    let expected = workspace_content_fingerprint_from_cached_inputs(&db, Some(&source_inputs));

    source_inputs.reverse();
    assert_eq!(
        workspace_content_fingerprint_from_cached_inputs(&db, Some(&source_inputs)),
        expected,
        "compiler input enumeration order must not change workspace identity"
    );

    source_inputs[0].1 = "src/renamed.py".to_string();
    assert_ne!(
        workspace_content_fingerprint_from_cached_inputs(&db, Some(&source_inputs)),
        expected,
        "source paths remain part of the exact workspace identity"
    );
}

#[test]
fn missing_cached_source_inputs_fall_back_to_legacy_vfs_hashing() {
    let db = db_with_one_file();
    assert_eq!(
        workspace_content_fingerprint_from_cached_inputs(&db, None),
        crate::cache_fingerprint::workspace_content_fingerprint(&db),
        "a cache miss must preserve the existing exact VFS fingerprint path"
    );
}

#[test]
fn idg_pipeline_hash_tracks_dependency_metadata() {
    let root = tempdir_for_test("bonsai-idg-pipeline-deps");
    std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").expect("write pyproject");
    let db = db_with_one_file();

    let before = idg_workspace_pipeline_hash(&db, Some(&root));
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\ndependencies = [\"flask\"]\n",
    )
    .expect("rewrite pyproject");
    let after = idg_workspace_pipeline_hash(&db, Some(&root));

    assert_ne!(
        before, after,
        "IDG sidecar pipeline hash must change when dependency metadata changes"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn idg_pipeline_hash_tracks_compiler_frontend_abi() {
    let current = compiler_frontend_cache_fingerprint(COMPILER_OBJECT_CACHE_VERSION);
    let next = compiler_frontend_cache_fingerprint(
        COMPILER_OBJECT_CACHE_VERSION
            .checked_add(1)
            .expect("compiler object ABI version overflow"),
    );

    assert_ne!(
        current, next,
        "compiler object ABI changes must invalidate persisted IDG sidecars"
    );
}

#[test]
fn root_only_idg_validation_reconstructs_the_exact_compiler_pipeline() {
    let root = tempdir_for_test("bonsai-idg-root-only-validation");
    let source_path = root.join("app.py");
    let source = "def entry(x):\n    return x\n";
    std::fs::write(&source_path, source).expect("write source");
    let vfs = Arc::new(Vfs::new());
    vfs.write(source_path.display().to_string(), Arc::<str>::from(source));
    let db = AnalyzerDb::new(vfs, Arc::new(LanguageRegistry::new()));
    let pipeline = idg_workspace_pipeline_hash(&db, Some(&root));
    let sidecar = root.join("idg.factstore");
    bonsai_idg::workspace::IdgWorkspace::new()
        .save_to_disk(&sidecar, pipeline)
        .expect("save exact pipeline");
    let source_hash = bonsai_hash::fnv1a_bytes64(source.as_bytes());

    assert!(validate_idg_sidecar_layout_with_source_fingerprints(
        &sidecar,
        &root,
        [(&source_path, source_hash)],
        Vec::<String>::new(),
    )
    .is_ok());
    assert!(
        validate_idg_sidecar_layout_with_source_fingerprints(
            &sidecar,
            &root,
            [(&source_path, source_hash ^ 1)],
            Vec::<String>::new(),
        )
        .is_err(),
        "source content changes must reject the sidecar without parsing"
    );
    assert!(
        validate_idg_sidecar_layout_with_source_fingerprints(
            &sidecar,
            &root,
            [(&source_path, source_hash)],
            ["java"],
        )
        .is_err(),
        "adapter capability changes must reject the sidecar without parsing"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn workspace_generation_reuses_pipeline_identity_until_an_edit() {
    let root = tempdir_for_test("bonsai-idg-pipeline-generation");
    std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").expect("write pyproject");
    let workspace = Workspace::new(Arc::new(LanguageRegistry::new()));
    workspace.apply_edit(&root.join("app.py"), "def entry(x):\n    return x\n".to_string());
    workspace.set_complete_workspace_index(true);
    workspace
        .complete_source_content_hashes()
        .expect("cache exact source inputs");

    let before = workspace.cached_idg_workspace_pipeline_hash(Some(&root));
    std::fs::write(
        root.join("pyproject.toml"),
        "[project]\nname = \"demo\"\ndependencies = [\"flask\"]\n",
    )
    .expect("rewrite pyproject");
    assert_eq!(
        workspace.cached_idg_workspace_pipeline_hash(Some(&root)),
        before,
        "one immutable compiler generation must reuse its validated identity"
    );

    workspace.apply_edit(
        &root.join("app.py"),
        "def entry(x):\n    return (x, x)\n".to_string(),
    );
    assert_ne!(
        workspace.cached_idg_workspace_pipeline_hash(Some(&root)),
        before,
        "a source edit must invalidate the pipeline identity"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn edit_waits_for_active_idg_generation_before_mutating_source() {
    use std::sync::mpsc;
    use std::time::Duration;

    let workspace = Workspace::new(Arc::new(LanguageRegistry::new()));
    let path = std::path::PathBuf::from("/virtual/app.py");
    let file = workspace.apply_edit(&path, "old source".to_string());
    let generation = workspace.inner.idg_build_serial.lock();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let editor = workspace.clone();
    let edit_path = path.clone();
    let thread = std::thread::spawn(move || {
        started_tx.send(()).expect("announce edit");
        editor.apply_edit(&edit_path, "new source".to_string());
        finished_tx.send(()).expect("announce completion");
    });

    started_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("edit thread started");
    assert!(
        finished_rx.recv_timeout(Duration::from_millis(100)).is_err(),
        "edit must wait for the active compiler generation"
    );
    assert_eq!(
        workspace
            .vfs()
            .snapshot(file)
            .expect("old snapshot remains readable")
            .text
            .as_ref(),
        "old source",
        "VFS text must not change before cache-generation ownership transfers"
    );

    drop(generation);
    finished_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("edit completes after generation release");
    thread.join().expect("join editor");
    assert_eq!(
        workspace
            .vfs()
            .snapshot(file)
            .expect("new snapshot")
            .text
            .as_ref(),
        "new source"
    );
}

#[test]
fn idg_transfer_fingerprint_is_order_stable() {
    let left = bonsai_idg::TransferOptions {
        clean_output_overwrites: vec![
            bonsai_idg::CleanOutputOverwriteSpec {
                callee: "z.clean".to_string(),
                output_arg_index: 2,
                value_start_arg_index: 0,
            },
            bonsai_idg::CleanOutputOverwriteSpec {
                callee: "a.clean".to_string(),
                output_arg_index: 1,
                value_start_arg_index: 0,
            },
            bonsai_idg::CleanOutputOverwriteSpec {
                callee: "a.clean".to_string(),
                output_arg_index: 1,
                value_start_arg_index: 0,
            },
        ],
        source_output_args: vec![
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.two".to_string(),
                output_arg_indices: vec![3, 1, 3],
                output_arg_start_index: None,
                resolved_call_sites: vec![source_transfer_site(20)],
            },
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.one".to_string(),
                output_arg_indices: vec![2, 0],
                output_arg_start_index: None,
                resolved_call_sites: vec![source_transfer_site(10)],
            },
        ],
        source_callback_args: vec![
            bonsai_idg::SourceCallbackArgSpec {
                callee: "source.callback".to_string(),
                callback_arg_index: 2,
                source_param_indices: vec![1, 0, 1],
                source_param_indices_from: None,
                resolved_call_sites: vec![source_transfer_site(30)],
            },
            bonsai_idg::SourceCallbackArgSpec {
                callee: "source.callback".to_string(),
                callback_arg_index: 2,
                source_param_indices: vec![0, 1],
                source_param_indices_from: None,
                resolved_call_sites: vec![source_transfer_site(30)],
            },
        ],
        ..bonsai_idg::TransferOptions::default()
    };
    let right = bonsai_idg::TransferOptions {
        clean_output_overwrites: vec![
            bonsai_idg::CleanOutputOverwriteSpec {
                callee: "a.clean".to_string(),
                output_arg_index: 1,
                value_start_arg_index: 0,
            },
            bonsai_idg::CleanOutputOverwriteSpec {
                callee: "z.clean".to_string(),
                output_arg_index: 2,
                value_start_arg_index: 0,
            },
        ],
        source_output_args: vec![
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.one".to_string(),
                output_arg_indices: vec![0, 2],
                output_arg_start_index: None,
                resolved_call_sites: vec![source_transfer_site(10)],
            },
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.two".to_string(),
                output_arg_indices: vec![1, 3],
                output_arg_start_index: None,
                resolved_call_sites: vec![source_transfer_site(20)],
            },
        ],
        source_callback_args: vec![bonsai_idg::SourceCallbackArgSpec {
            callee: "source.callback".to_string(),
            callback_arg_index: 2,
            source_param_indices: vec![0, 1],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_transfer_site(30)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };

    assert_eq!(
        idg_transfer_options_fingerprint(&left),
        idg_transfer_options_fingerprint(&right),
        "equivalent rulepack transfer shapes must reuse the same IDG sidecar"
    );
}

#[test]
fn idg_transfer_fingerprint_tracks_source_callback_shapes() {
    let plain = bonsai_idg::TransferOptions::default();
    let with_callback = bonsai_idg::TransferOptions {
        source_callback_args: vec![bonsai_idg::SourceCallbackArgSpec {
            callee: "source.callback".to_string(),
            callback_arg_index: 1,
            source_param_indices: vec![0],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };

    assert_ne!(
        idg_transfer_options_fingerprint(&plain),
        idg_transfer_options_fingerprint(&with_callback),
        "source-callback semantics change graph edges and must invalidate the transfer sidecar"
    );
}

#[test]
fn idg_transfer_fingerprint_tracks_variadic_source_callback_shapes() {
    let fixed = bonsai_idg::TransferOptions {
        source_callback_args: vec![bonsai_idg::SourceCallbackArgSpec {
            callee: "source.callback".to_string(),
            callback_arg_index: 1,
            source_param_indices: vec![0],
            source_param_indices_from: None,
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };
    let variadic = bonsai_idg::TransferOptions {
        source_callback_args: vec![bonsai_idg::SourceCallbackArgSpec {
            callee: "source.callback".to_string(),
            callback_arg_index: 1,
            source_param_indices: Vec::new(),
            source_param_indices_from: Some(0),
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };

    assert_ne!(
        idg_transfer_options_fingerprint(&fixed),
        idg_transfer_options_fingerprint(&variadic),
        "callback arity semantics change graph edges and must invalidate the transfer sidecar"
    );
}

#[test]
fn idg_transfer_fingerprint_tracks_variadic_source_output_shapes() {
    let fixed = bonsai_idg::TransferOptions {
        source_output_args: vec![bonsai_idg::SourceOutputArgSpec {
            callee: "scanf".to_string(),
            output_arg_indices: vec![1, 2, 3],
            output_arg_start_index: None,
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };
    let variadic = bonsai_idg::TransferOptions {
        source_output_args: vec![bonsai_idg::SourceOutputArgSpec {
            callee: "scanf".to_string(),
            output_arg_indices: Vec::new(),
            output_arg_start_index: Some(1),
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };

    assert_ne!(
        idg_transfer_options_fingerprint(&fixed),
        idg_transfer_options_fingerprint(&variadic),
        "a variadic output tail changes exact graph edges and must invalidate the transfer sidecar"
    );
}

#[test]
fn idg_transfer_fingerprint_tracks_exact_source_transfer_sites() {
    let at_ten = bonsai_idg::TransferOptions {
        source_output_args: vec![bonsai_idg::SourceOutputArgSpec {
            callee: "recv".to_string(),
            output_arg_indices: vec![1],
            output_arg_start_index: None,
            resolved_call_sites: vec![source_transfer_site(10)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };
    let at_twenty = bonsai_idg::TransferOptions {
        source_output_args: vec![bonsai_idg::SourceOutputArgSpec {
            callee: "recv".to_string(),
            output_arg_indices: vec![1],
            output_arg_start_index: None,
            resolved_call_sites: vec![source_transfer_site(20)],
        }],
        ..bonsai_idg::TransferOptions::default()
    };

    assert_ne!(
        idg_transfer_options_fingerprint(&at_ten),
        idg_transfer_options_fingerprint(&at_twenty),
        "matcher-approved source transfer spans change graph edges and must invalidate the sidecar"
    );
}

#[test]
fn idg_transfer_fingerprint_tracks_receiver_result_policy() {
    let plain = bonsai_idg::TransferOptions {
        include_unresolved_receiver_result_passthrough: false,
        ..bonsai_idg::TransferOptions::default()
    };
    let with_receiver_flow = bonsai_idg::TransferOptions {
        include_unresolved_receiver_result_passthrough: true,
        ..bonsai_idg::TransferOptions::default()
    };

    assert_ne!(
        idg_transfer_options_fingerprint(&plain),
        idg_transfer_options_fingerprint(&with_receiver_flow),
        "receiver-result semantics change graph edges and must invalidate the transfer sidecar"
    );
}

#[test]
fn idg_scoped_fingerprints_are_order_independent_and_scope_sensitive() {
    let files_left = [FileId::new(9), FileId::new(2), FileId::new(9)];
    let files_right = [FileId::new(2), FileId::new(9)];
    let funcs_left = [FuncId::new(17), FuncId::new(3), FuncId::new(17)];
    let funcs_right = [FuncId::new(3), FuncId::new(17)];

    assert_eq!(
        idg_file_scope_fingerprint(&files_left),
        idg_file_scope_fingerprint(&files_right)
    );
    assert_eq!(
        idg_func_scope_fingerprint(&funcs_left),
        idg_func_scope_fingerprint(&funcs_right)
    );
    assert_ne!(
        idg_func_scope_fingerprint(&funcs_right),
        idg_func_scope_fingerprint(&[FuncId::new(3)])
    );
}

fn resolved_graph_with_edges(edges: &[(u32, u32, u64)]) -> bonsai_callgraph::ResolvedCallGraph {
    let mut graph = bonsai_callgraph::CallGraph::new();
    for &(from, to, start) in edges {
        graph.add_edge(bonsai_callgraph::CallEdge {
            from: FuncId::new(from),
            to: FuncId::new(to),
            span: bonsai_common::Span::new(FileId::new(1), start, start + 1),
            kind: bonsai_callgraph::EdgeKind::Direct,
            precision: Precision::Exact,
            provenance: bonsai_callgraph::EdgeProvenance::direct_symbol(),
        });
    }
    bonsai_callgraph::ResolvedCallGraph::from_call_graph(graph)
}

#[test]
fn idg_call_graph_fingerprint_is_order_independent_and_edge_sensitive() {
    let left = resolved_graph_with_edges(&[(1, 2, 10), (2, 3, 20)]);
    let reordered = resolved_graph_with_edges(&[(2, 3, 20), (1, 2, 10)]);
    let changed = resolved_graph_with_edges(&[(1, 2, 10), (2, 4, 20)]);

    assert_eq!(
        idg_call_graph_fingerprint(&left),
        idg_call_graph_fingerprint(&reordered),
        "equivalent resolved relations must reuse one scoped IDG"
    );
    assert_ne!(
        idg_call_graph_fingerprint(&left),
        idg_call_graph_fingerprint(&changed),
        "a changed resolved call edge must invalidate the scoped IDG"
    );
}

#[test]
fn idg_scoped_semantics_fingerprint_tracks_optional_graph_inputs() {
    let base = idg_scoped_semantics_fingerprint(1, 2, None, None);
    assert_ne!(
        base,
        idg_scoped_semantics_fingerprint(1, 2, Some(0), None),
        "a function-scoped graph is distinct even when its component hash is zero"
    );
    assert_ne!(
        base,
        idg_scoped_semantics_fingerprint(1, 2, None, Some(0)),
        "a caller-supplied call graph is distinct even when its component hash is zero"
    );
}
