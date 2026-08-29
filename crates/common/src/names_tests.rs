use std::path::Path;

use super::{
    declaration_qualified_suffix, default_workspace_bonsai_dir, ends_at_qualified_name_boundary,
    ensure_cache_directory_writable, is_bonsai_case_probe_path, normalize_qualified_name,
    qualified_name_owner, qualified_name_prefixes, qualified_names_match, short_qualified_tail,
    split_qualified_name_head_tail, split_qualified_name_owner_tail, starts_at_qualified_name_boundary,
    trim_leading_name_punctuation, writable_default_workspace_bonsai_dir,
};

#[test]
fn default_workspace_cache_is_external_stable_and_namespaced() {
    let cache_root = Path::new("/cache-root");
    let first = default_workspace_bonsai_dir(Path::new("/work/acme project"), Some(cache_root));
    let repeated = default_workspace_bonsai_dir(Path::new("/work/acme project"), Some(cache_root));
    let other = default_workspace_bonsai_dir(Path::new("/other/acme project"), Some(cache_root));

    assert_eq!(first, repeated);
    assert!(first.starts_with(cache_root.join("bonsai-ninja/workspaces")));
    assert!(
        first
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("acme-project-")),
        "{}",
        first.display()
    );
    assert_ne!(first, other, "same basename in a different root must not collide");
    assert!(!first.starts_with("/work/acme project"));
}

#[test]
fn unwritable_default_cache_falls_back_without_global_environment_mutation() {
    let root = std::env::temp_dir().join(format!(
        "bonsai-cache-fallback-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).expect("create test root");
    let unusable = root.join("not-a-directory");
    std::fs::write(&unusable, b"file").expect("create unusable cache root");
    let fallback = root.join("fallback");

    let selected =
        writable_default_workspace_bonsai_dir(Path::new("/work/example"), Some(&unusable), &fallback);

    assert!(selected.starts_with(fallback.join("bonsai-ninja/workspaces")));
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn cache_writability_probe_rejects_a_file_and_cleans_up_after_success() {
    let root = std::env::temp_dir().join(format!(
        "bonsai-cache-probe-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&root).expect("create test root");
    let file = root.join("plain-file");
    std::fs::write(&file, b"not a directory").expect("write fixture");

    assert!(!ensure_cache_directory_writable(&file));
    assert!(ensure_cache_directory_writable(&root));
    let absent = root.join("new-cache");
    assert!(ensure_cache_directory_writable(&absent));
    assert!(
        !absent.exists(),
        "probing an absent cache path must not materialize it"
    );
    assert_eq!(
        std::fs::read_dir(&root)
            .expect("read fixture root")
            .filter_map(Result::ok)
            .filter(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(".bonsai-write-probe-"))
            .count(),
        0,
        "successful probes must not leave cache artifacts"
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn qualified_tail_uses_rightmost_supported_separator() {
    assert_eq!(short_qualified_tail("a.b.c"), "c");
    assert_eq!(short_qualified_tail("std::fs::read"), "read");
    assert_eq!(short_qualified_tail("ptr->call"), "call");
    assert_eq!(short_qualified_tail("Module:function"), "function");
    assert_eq!(short_qualified_tail("App\\Service\\run"), "run");
    assert_eq!(short_qualified_tail("plain"), "plain");
    assert_eq!(short_qualified_tail("Map<Key, Value>"), "Map<Key, Value>");
    assert_eq!(short_qualified_tail("Map<Key, Value>::read"), "read");
}

#[test]
fn single_colon_does_not_split_inside_double_colon_tail() {
    assert_eq!(short_qualified_tail("A::B:C"), "C");
    assert_eq!(short_qualified_tail("A::B::C"), "C");
}

#[test]
fn qualified_name_matching_uses_the_canonical_non_empty_tail() {
    assert!(qualified_names_match("App::Service.run", "run"));
    assert!(qualified_names_match("App\\Service\\run", "Service.run"));
    assert!(!qualified_names_match("App::read", "App::write"));
    assert!(!qualified_names_match("App::", "Other::"));
}

#[test]
fn declaration_suffix_preserves_adapter_emitted_syntax_after_the_concise_name() {
    assert_eq!(
        declaration_qualified_suffix("runAdminCommand", "AuthService.runAdminCommand:action:"),
        Some("runAdminCommand:action:")
    );
    assert_eq!(
        declaration_qualified_suffix("read", "crate::storage::read"),
        Some("read")
    );
    assert_eq!(declaration_qualified_suffix("run", "Owner.runner"), None);
    assert_eq!(declaration_qualified_suffix("", "Owner.run"), None);
}

#[test]
fn vocabulary_free_name_boundaries_cover_compiler_name_shapes() {
    assert!(ends_at_qualified_name_boundary("Owner::"));
    assert!(starts_at_qualified_name_boundary("->member"));
    assert_eq!(qualified_name_owner("Owner::member"), Some("Owner"));
    assert_eq!(
        qualified_name_owner("Map<Key, Value>::read"),
        Some("Map<Key, Value>")
    );
    assert_eq!(trim_leading_name_punctuation("&$value"), "value");
    assert_eq!(normalize_qualified_name("Owner::member"), "Owner.member");
    assert_eq!(normalize_qualified_name("ptr->member"), "ptr.member");
}

#[test]
fn qualified_prefixes_preserve_adapter_punctuation() {
    assert_eq!(
        qualified_name_prefixes("org.example.Service"),
        ["org", "org.example", "org.example.Service"]
    );
    assert_eq!(
        qualified_name_prefixes("crate::storage::Repository"),
        ["crate", "crate::storage", "crate::storage::Repository"]
    );
    assert_eq!(qualified_name_prefixes(":zip.extract"), [":zip", ":zip.extract"]);
    assert_eq!(
        split_qualified_name_head_tail("crate::storage::Repository"),
        Some(("crate", "storage::Repository"))
    );
    assert_eq!(
        split_qualified_name_owner_tail("crate::storage::Repository"),
        Some(("crate::storage", "Repository"))
    );
}

#[test]
fn case_probe_path_matches_only_vfs_temp_shape() {
    assert!(is_bonsai_case_probe_path(Path::new(".bonsai_case_probe_123_456")));
    assert!(is_bonsai_case_probe_path(Path::new(
        "/tmp/.BONSAI_CASE_PROBE_123_456"
    )));
    assert!(!is_bonsai_case_probe_path(Path::new(".bonsai_case_probe_123")));
    assert!(!is_bonsai_case_probe_path(Path::new(
        ".bonsai_case_probe_123_456.py"
    )));
    assert!(!is_bonsai_case_probe_path(Path::new(
        ".bonsai_case_probe_notes.py"
    )));
}
