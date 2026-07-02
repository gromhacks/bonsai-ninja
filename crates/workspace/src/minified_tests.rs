use super::*;
use std::path::PathBuf;

#[test]
fn path_suffix_min_js() {
    assert!(path_looks_minified(&PathBuf::from("app.min.js")));
    assert!(path_looks_minified(&PathBuf::from("jquery-3.6.0.min.js")));
    assert!(path_looks_minified(&PathBuf::from("react.production.min.js")));
}

#[test]
fn path_suffix_min_ts_and_css() {
    assert!(path_looks_minified(&PathBuf::from("lib.min.ts")));
    assert!(path_looks_minified(&PathBuf::from("styles.min.css")));
}

#[test]
fn path_suffix_dash_min() {
    assert!(path_looks_minified(&PathBuf::from("foo-min.js")));
}

#[test]
fn path_node_modules_segment() {
    assert!(path_looks_minified(&PathBuf::from("node_modules/react/index.js")));
    assert!(path_looks_minified(&PathBuf::from(
        "src/node_modules/lodash/debounce.js"
    )));
}

#[test]
fn path_vendor_segment() {
    assert!(path_looks_minified(&PathBuf::from(
        "third_party/vendor/jquery.js"
    )));
}

#[test]
fn path_dist_segment() {
    // The lodash failure mode: `dist/lodash.js` is byte-identical
    // to top-level `lodash.js` (the build literally copies the
    // source). Indexing both indexes the same code twice.
    assert!(path_looks_minified(&PathBuf::from("dist/lodash.js")));
    assert!(path_looks_minified(&PathBuf::from("project/dist/index.js")));
}

#[test]
fn path_build_output_segments() {
    assert!(path_looks_minified(&PathBuf::from("build/output.js")));
    assert!(path_looks_minified(&PathBuf::from("target/release/foo.rs")));
    assert!(path_looks_minified(&PathBuf::from("out/main.js")));
    assert!(path_looks_minified(&PathBuf::from(".next/static/chunk.js")));
    assert!(path_looks_minified(&PathBuf::from(".nuxt/server/app.js")));
}

#[test]
fn root_relative_path_ignores_generated_ancestors_outside_workspace() {
    let root = PathBuf::from("/tmp/repo/target/smoke-workspace");
    assert!(!path_looks_minified_under_root(&root, &root.join("app.py")));
    assert!(path_looks_minified_under_root(
        &root,
        &root.join("target/release/app.py")
    ));
    assert!(path_looks_minified_under_root(
        &root,
        &root.join(".bonsai/cache.py")
    ));
}

#[test]
fn root_relative_source_filters_ignore_generated_ancestors_outside_workspace() {
    let root = PathBuf::from("/tmp/repo/target/smoke-workspace");
    let include_filters = Vec::new();
    let exclude_filters = vec!["target/".to_string()];
    let filter = PathFilterSpec {
        include_filters: &include_filters,
        exclude_filters: &exclude_filters,
    };
    assert!(
        source_path_allowed(&root, &root.join("app.py"), filter),
        "path filters must not exclude the selected workspace because an ancestor is named target"
    );
    assert!(
        !source_path_allowed(&root, &root.join("target/generated.py"), filter),
        "path filters must still exclude matching generated paths inside the selected workspace"
    );
}

#[test]
fn root_relative_source_filters_still_accept_explicit_absolute_paths() {
    let root = PathBuf::from("/tmp/repo/target/smoke-workspace");
    let include_filters = vec![root.join("app.py").to_string_lossy().into_owned()];
    let exclude_filters = Vec::new();
    let filter = PathFilterSpec {
        include_filters: &include_filters,
        exclude_filters: &exclude_filters,
    };
    assert!(source_path_allowed(&root, &root.join("app.py"), filter));
}

#[test]
fn path_workspace_state_dirs() {
    assert!(path_looks_minified(&PathBuf::from(".bonsai/shadow.py")));
    assert!(path_looks_minified(&PathBuf::from(".git/hooks/pre-commit.py")));
}

#[test]
fn path_python_caches() {
    assert!(path_looks_minified(&PathBuf::from(
        "src/pkg/__pycache__/module.cpython-310.pyc"
    )));
    assert!(path_looks_minified(&PathBuf::from(
        ".venv/lib/site-packages/foo.py"
    )));
    assert!(path_looks_minified(&PathBuf::from("venv/lib/foo.py")));
}

#[test]
fn path_coverage_dirs() {
    assert!(path_looks_minified(&PathBuf::from("coverage/index.html")));
    assert!(path_looks_minified(&PathBuf::from(".coverage/lcov.info")));
}

#[test]
fn path_normal_source_not_minified() {
    assert!(!path_looks_minified(&PathBuf::from("src/index.js")));
    assert!(!path_looks_minified(&PathBuf::from("lib/util/parser.ts")));
    assert!(!path_looks_minified(&PathBuf::from("minimum.js"))); // not `.min.`
                                                                 // Substring matches must not false-positive: "build" inside a
                                                                 // longer name is fine, only an exact path segment counts.
    assert!(!path_looks_minified(&PathBuf::from("rebuild_index.rs")));
    assert!(!path_looks_minified(&PathBuf::from("src/distance.rs")));
    assert!(!path_looks_minified(&PathBuf::from("src/output.rs")));
}

#[test]
fn content_detects_long_line() {
    let mut big = String::with_capacity(6_000);
    for _ in 0..6_000 {
        big.push('a');
    }
    assert!(content_looks_minified(&big));
}

#[test]
fn content_leaves_normal_source_alone() {
    let source = "function greet(name) {\n    console.log(`hello ${name}`);\n}\n";
    assert!(!content_looks_minified(source));
}

#[test]
fn content_leaves_multi_line_big_files_alone() {
    // 5 MB of normal-length lines must NOT flag as minified — we only
    // care about single-line size, not total size.
    let mut big = String::with_capacity(5 * 1024 * 1024);
    for _ in 0..50_000 {
        big.push_str("function fn() { return 1; }\n");
    }
    assert!(!content_looks_minified(&big));
}

#[test]
fn content_detects_extreme_structure_nesting() {
    let source = format!("let x = {}0{}", "(".repeat(2_100), ")".repeat(2_100));
    assert!(content_has_extreme_structure_nesting(&source));
}

#[test]
fn content_leaves_normal_structure_nesting_alone() {
    let source = "func f() { let x = [foo(bar(baz()))] }\n";
    assert!(!content_has_extreme_structure_nesting(source));
}
