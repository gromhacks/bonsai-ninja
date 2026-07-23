use super::*;

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
fn workspace_generation_reuses_pipeline_identity_until_an_edit() {
    let root = tempdir_for_test("bonsai-idg-pipeline-generation");
    std::fs::write(root.join("pyproject.toml"), "[project]\nname = \"demo\"\n").expect("write pyproject");
    let workspace = Workspace::new(Arc::new(LanguageRegistry::new()));
    workspace.apply_edit(&root.join("app.py"), "def entry(x):\n    return x\n".to_string());

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
            },
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.one".to_string(),
                output_arg_indices: vec![2, 0],
            },
        ],
        source_callback_args: vec![
            bonsai_idg::SourceCallbackArgSpec {
                callee: "source.callback".to_string(),
                callback_arg_index: 2,
                source_param_indices: vec![1, 0, 1],
            },
            bonsai_idg::SourceCallbackArgSpec {
                callee: "source.callback".to_string(),
                callback_arg_index: 2,
                source_param_indices: vec![0, 1],
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
            },
            bonsai_idg::SourceOutputArgSpec {
                callee: "source.two".to_string(),
                output_arg_indices: vec![1, 3],
            },
        ],
        source_callback_args: vec![bonsai_idg::SourceCallbackArgSpec {
            callee: "source.callback".to_string(),
            callback_arg_index: 2,
            source_param_indices: vec![0, 1],
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
