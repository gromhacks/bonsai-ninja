use super::*;
use crate::scenarios::{Category, Polarity};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

fn taint_tests_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests")
}

fn scenario_file(category: Category, id: &str) -> PathBuf {
    taint_tests_root()
        .join("matrix")
        .join(category.as_str())
        .join(format!("{}.rs", id.to_ascii_lowercase()))
}

fn scenario_test_name(id: &str, lang: &str) -> String {
    format!("fn {}_{}(", id.to_ascii_lowercase(), lang)
}

fn test_body<'a>(body: &'a str, fn_name: &str) -> Option<&'a str> {
    let start = body.find(&format!("fn {fn_name}("))?;
    let rest = &body[start..];
    let next_test = rest
        .get(1..)
        .and_then(|tail| tail.find("\n#[test]").map(|offset| offset + 1))
        .unwrap_or(rest.len());
    Some(&rest[..next_test])
}

fn fixture_file_count(test_body: &str) -> usize {
    const EXTENSIONS: &[&str] = &[
        ".c", ".cc", ".cpp", ".cs", ".cxx", ".dart", ".erl", ".ex", ".go", ".h", ".hh", ".hpp", ".hxx",
        ".java", ".js", ".kt", ".lua", ".m", ".mm", ".php", ".pl", ".pm", ".py", ".rb", ".rs", ".scala",
        ".sol", ".swift", ".ts",
    ];

    let bytes = test_body.as_bytes();
    let mut count = 0;
    let mut idx = 0;
    while let Some(relative) = test_body[idx..].find('(') {
        idx += relative + 1;
        while bytes.get(idx).is_some_and(u8::is_ascii_whitespace) {
            idx += 1;
        }
        if bytes.get(idx) != Some(&b'"') {
            continue;
        }
        idx += 1;
        let path_start = idx;
        while let Some(byte) = bytes.get(idx) {
            match byte {
                b'\\' => idx += 2,
                b'"' => break,
                _ => idx += 1,
            }
        }
        let Some(path_end) = bytes.get(idx).map(|_| idx) else {
            break;
        };
        idx += 1;
        while bytes.get(idx).is_some_and(u8::is_ascii_whitespace) {
            idx += 1;
        }
        if bytes.get(idx) == Some(&b',') {
            let path = &test_body[path_start..path_end];
            if EXTENSIONS.iter().any(|extension| path.ends_with(extension)) {
                count += 1;
            }
        }
    }
    count
}

fn scenario_construct_markers(id: &str) -> Option<&'static [&'static str]> {
    match id {
        "I_18" => Some(&[
            "closure",
            "lambda",
            "proc",
            "function() use",
            "=>",
            "fn ->",
            "fun() ->",
            "^{",
        ]),
        "I_19" => Some(&["lambda", "=>", "var f =", "const f =", "f =", "f :=", "^("]),
        "I_16" => Some(&["match", "case", "when", "switch", "instanceof", " is "]),
        "R_05" => Some(&[
            "new Box",
            "Box::new",
            "class Box",
            "__construct",
            "->new",
            "initWith",
            "alloc",
        ]),
        "R_10" => Some(&["apply_", "callback", "cb"]),
        "R_17" => Some(&[
            "cb",
            "Cb",
            "helper/1",
            "\\&helper",
            "::helper",
            "Action<",
            "(*cb)",
        ]),
        "R_19" => Some(&["*p", "...", "String...", "String*", "vararg", "params ", "@_"]),
        "R_20" => Some(&["name=", "name =", "name:", "Name:"]),
        _ => None,
    }
}

#[test]
fn all_overrides_reference_real_scenarios() {
    for table in [OVERRIDES, COVERAGE_GAP_OVERRIDES] {
        for (_lang, ids, _status) in table {
            for id in *ids {
                assert!(
                    SCENARIOS.iter().any(|s| s.id == *id),
                    "applicability override references unknown scenario id `{id}`"
                );
            }
        }
    }
}

#[test]
fn no_cell_has_conflicting_overrides() {
    let mut seen = BTreeMap::new();
    for table in [OVERRIDES, COVERAGE_GAP_OVERRIDES] {
        for (lang, ids, status) in table {
            for id in *ids {
                let previous = seen.insert((*lang, *id), *status);
                assert!(
                    previous.is_none(),
                    "{lang}/{id} has multiple applicability overrides"
                );
            }
        }
    }
}

#[test]
fn all_overrides_reference_real_languages() {
    for table in [OVERRIDES, COVERAGE_GAP_OVERRIDES] {
        for (lang, _ids, _status) in table {
            assert!(
                LANGUAGES.contains(lang),
                "applicability override references unknown language `{lang}`"
            );
        }
    }
}

#[test]
fn no_cells_remain_adapter_deferred() {
    let mut deferred = Vec::new();
    for &lang in LANGUAGES {
        for scenario in SCENARIOS {
            if status(lang, scenario.id) == Status::AdapterDeferred {
                deferred.push(format!("{}/{}", scenario.id, lang));
            }
        }
    }

    assert!(
        deferred.is_empty(),
        "taint matrix must resolve every cell as Applicable or NotApplicable; deferred cells:\n{}",
        deferred.join("\n")
    );
}

#[test]
fn applicable_cross_file_cells_use_cross_file_fixtures() {
    let mut single_file = Vec::new();
    for scenario in SCENARIOS
        .iter()
        .filter(|scenario| scenario.category == Category::CrossFile)
    {
        let path = scenario_file(scenario.category, scenario.id);
        let body =
            std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for &lang in LANGUAGES {
            if status(lang, scenario.id) != Status::Applicable {
                continue;
            }
            let fn_name = format!("{}_{}", scenario.id.to_ascii_lowercase(), lang);
            let Some(body) = test_body(&body, &fn_name) else {
                continue;
            };
            let file_count = fixture_file_count(body);
            if file_count < 2 {
                single_file.push(format!(
                    "{}/{} is Applicable but {} uses only {file_count} fixture file(s)",
                    scenario.id,
                    lang,
                    path.display()
                ));
            }
        }
    }

    assert!(
        single_file.is_empty(),
        "Cross-file taint matrix cells must exercise cross-file resolution; \
         replace single-file placeholders with real multi-file fixtures or mark the cell deferred:\n{}",
        single_file.join("\n")
    );
}

#[test]
fn applicable_nontrivial_construct_cells_use_semantic_fixtures() {
    let mut placeholders = Vec::new();
    for scenario in SCENARIOS {
        let Some(markers) = scenario_construct_markers(scenario.id) else {
            continue;
        };
        let path = scenario_file(scenario.category, scenario.id);
        let body =
            std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for &lang in LANGUAGES {
            if status(lang, scenario.id) != Status::Applicable {
                continue;
            }
            let fn_name = format!("{}_{}", scenario.id.to_ascii_lowercase(), lang);
            let Some(body) = test_body(&body, &fn_name) else {
                continue;
            };
            if !markers.iter().any(|marker| body.contains(marker)) {
                placeholders.push(format!(
                    "{}/{} is Applicable but {} lacks a fixture marker for {:?}",
                    scenario.id,
                    lang,
                    path.display(),
                    markers
                ));
            }
        }
    }

    assert!(
        placeholders.is_empty(),
        "Nontrivial taint matrix cells must exercise the named semantic construct; \
         replace direct source-to-sink placeholders with real fixtures or mark the cell deferred/n/a:\n{}",
        placeholders.join("\n")
    );
}

#[test]
fn scenario_catalog_matches_declared_totals_and_test_modules() {
    assert_eq!(SCENARIOS.len(), TOTAL_SCENARIOS, "TOTAL_SCENARIOS drifted");
    assert_eq!(LANGUAGES.len(), TOTAL_LANGUAGES, "TOTAL_LANGUAGES drifted");

    let mut ids = HashSet::new();
    let matrix_rs =
        std::fs::read_to_string(taint_tests_root().join("matrix.rs")).expect("read taint matrix aggregator");
    for scenario in SCENARIOS {
        assert!(ids.insert(scenario.id), "duplicate scenario id `{}`", scenario.id);
        let path = scenario_file(scenario.category, scenario.id);
        assert!(
            path.exists(),
            "scenario `{}` is in SCENARIOS but missing {}",
            scenario.id,
            path.display()
        );
        let module_name = scenario.id.to_ascii_lowercase();
        assert!(
            matrix_rs.contains(&format!("mod {module_name};")),
            "scenario `{}` has a fixture file but is not imported by tests/matrix.rs",
            scenario.id
        );
    }
}

#[test]
fn every_applicable_cell_has_an_executable_fixture() {
    let mut missing = Vec::new();
    for scenario in SCENARIOS {
        let path = scenario_file(scenario.category, scenario.id);
        let body =
            std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        for &lang in LANGUAGES {
            if status(lang, scenario.id) == Status::Applicable {
                let name = scenario_test_name(scenario.id, lang);
                if !body.contains(&name) {
                    missing.push(format!(
                        "{}/{} is Applicable but {} lacks `{}`",
                        scenario.id,
                        lang,
                        path.display(),
                        name.trim_end_matches('(')
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "every Applicable taint matrix cell must have a concrete test function; \
         mark truly unsupported cells NotApplicable or unimplemented cells AdapterDeferred:\n{}",
        missing.join("\n")
    );
}

#[test]
fn construct_families_have_positive_and_precision_coverage() {
    let families: &[(&str, &[&str], &[&str])] = &[
        (
            "assignment/data movement",
            &["I_01", "I_03", "I_04", "I_05"],
            &["I_02", "OT_07", "OT_17"],
        ),
        (
            "branching and merges",
            &["I_06", "I_07", "I_08", "I_16", "I_17"],
            &["OT_08"],
        ),
        ("loops and iteration", &["I_09", "I_10", "I_11", "I_12"], &[]),
        ("exceptions", &["I_13", "I_14", "I_15"], &[]),
        (
            "closures and callable values",
            &["I_18", "I_19", "R_09", "R_10", "R_17"],
            &[],
        ),
        (
            "call arguments and returns",
            &["R_01", "R_02", "R_08", "R_13", "R_19", "R_20"],
            &["R_18", "OT_03", "OT_04"],
        ),
        (
            "methods, receivers, constructors, and dispatch",
            &["R_03", "R_04", "R_05", "R_06", "R_14"],
            &["OT_16"],
        ),
        ("async and coroutine flow", &["R_11", "R_12"], &[]),
        (
            "cross-file module resolution",
            &[
                "X_01", "X_02", "X_03", "X_04", "X_05", "X_06", "X_07", "X_08", "X_09", "X_10", "X_12",
                "X_13", "X_14", "X_15", "X_16",
            ],
            &["X_11", "OT_20"],
        ),
        (
            "field, index, and sibling precision",
            &[],
            &["OT_01", "OT_09", "OT_10", "OT_13"],
        ),
        (
            "literal/type/name precision",
            &[],
            &["OT_02", "OT_15", "OT_18", "OT_19"],
        ),
        ("unknown-call boundaries", &[], &["OT_11", "OT_12", "OT_14"]),
        ("native size/copy boundaries", &[], &["OT_05", "OT_06"]),
    ];

    for (family, positive_ids, negative_ids) in families {
        for id in positive_ids.iter().chain(*negative_ids) {
            let scenario = crate::scenarios::scenario(id)
                .unwrap_or_else(|| panic!("{family} references unknown scenario `{id}`"));
            let expected = if positive_ids.contains(id) {
                Polarity::Positive
            } else {
                Polarity::Negative
            };
            assert_eq!(
                scenario.polarity, expected,
                "{family}/{id} has the wrong polarity"
            );
        }

        assert!(
            !positive_ids.is_empty() || !negative_ids.is_empty(),
            "{family} must name at least one semantic scenario"
        );
    }
}

#[test]
fn applicable_count_per_language_matches_doc_estimate() {
    // Lower bounds — sanity check that we don't accidentally mark
    // half the matrix as n/a/deferred. Smaller languages legitimately
    // have fewer applicable cells because they lack exceptions, OO,
    // async, imports, or other scenario families.
    let minimums = BTreeMap::from([("c", 35), ("erlang", 35), ("solidity", 35)]);

    for &lang in LANGUAGES {
        let applicable = SCENARIOS
            .iter()
            .filter(|s| status(lang, s.id) == Status::Applicable)
            .count();
        let minimum = minimums.get(lang).copied().unwrap_or(40);
        assert!(
            applicable >= minimum,
            "{lang}: applicable cell count {applicable} below semantic floor {minimum} — applicability table likely overreached"
        );
    }
}
