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
        ..bonsai_idg::TransferOptions::default()
    };

    assert_eq!(
        idg_transfer_options_fingerprint(&left),
        idg_transfer_options_fingerprint(&right),
        "equivalent rulepack transfer shapes must reuse the same IDG sidecar"
    );
}
