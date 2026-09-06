#[test]
fn cpp_compound_guard_rejects_inverted_partial_and_mutated_proofs() {
    use bonsai_diagnostics::DiagnosticSink;
    use bonsai_lang_api::{AdapterContext, LanguageAdapter};
    use bonsai_vfs::Vfs;
    use parking_lot::RwLock;

    let source = r#"#include <set>
#include <string>
static const std::set<std::string> TRUSTED = {"api.example", "hooks.example"};
static bool accepted(const std::string& value, std::string& token) {
  if (value.rfind("https://", 0) != 0) return false;
  auto rest = value.substr(8);
  token = rest.substr(0, rest.find('/'));
  return TRUSTED.count(token) > 0;
}
void fetch(void *client, const std::string& value) {
  std::string token;
  if (!accepted(value, token)) return;
  curl_easy_setopt(client, CURLOPT_URL, value.c_str());
  curl_easy_setopt(client, CURLOPT_FOLLOWLOCATION, 0L);
}
"#;
    let index = |source: &str| {
        let vfs = Vfs::new();
        let file = vfs.write(std::path::Path::new("guard.cpp"), source);
        let diagnostics = RwLock::new(DiagnosticSink::default());
        bonsai_lang_cpp::CppAdapter::new().extract_declarations(
            file,
            &AdapterContext {
                vfs: &vfs,
                diagnostics: &diagnostics,
                tree_provider: None,
                workspace_root: None,
            },
        )
    };
    let has_guard = |source: &str| {
        index(source)
            .compiler_guards
            .iter()
            .any(|guard| guard.capability == "terminal-predicate.compound-static-allowlist")
    };
    assert!(has_guard(source));
    // A caller's variable spelling cannot change the callee's formal slot.
    // Here the output happens to have the name of the callee's input formal.
    let renamed = source
        .replace(
            "void fetch(void *client, const std::string& value)",
            "void fetch(void *client, const std::string& incoming)",
        )
        .replace("std::string token;", "std::string value;")
        .replace("accepted(value, token)", "accepted(incoming, value)")
        .replace("value.c_str()", "incoming.c_str()");
    assert!(index(&renamed).compiler_guards.iter().any(|guard| guard
        .evidence
        .iter()
        .any(|value| value == "guarded-argument:2=predicate-argument:0")));
    let mut incorrect = Vec::new();
    for (label, before, after) in [
        ("inverted prefix", "0) != 0", "0) == 0"),
        ("inverted membership", "count(token) > 0", "count(token) == 0"),
        ("unrelated token offset", "rest.substr(0,", "rest.substr(1,"),
        ("boundary from another value", "rest.find('/')", "value.find('/')"),
        ("mutable collection", "static const std::set", "static std::set"),
        (
            "extra accepting exit",
            "auto rest",
            "if (bypass) return true; auto rest",
        ),
        (
            "conditional guard",
            "if (!accepted(value, token))",
            "if (enabled) if (!accepted(value, token))",
        ),
        (
            "mutated value",
            "curl_easy_setopt(client, CURLOPT_URL",
            "value = source(); curl_easy_setopt(client, CURLOPT_URL",
        ),
        (
            "mutated summary input",
            "auto rest",
            "value = source(); auto rest",
        ),
        (
            "optional membership",
            "return TRUSTED.count(token) > 0;",
            "if (enabled) return TRUSTED.count(token) > 0; return true;",
        ),
    ] {
        if has_guard(&source.replace(before, after)) {
            incorrect.push(label);
        }
    }
    assert!(incorrect.is_empty(), "unproven compound guards: {incorrect:?}");
}
