//! Code manifests are never evaluated or token-searched. The normal adapter
//! lowers a file-local compiler object; full target matching proves each call
//! before its exact static argument values can establish a dependency.

use super::{AHashSet, DependencyManifestLayout, Workspace};
use anyhow::Context;
use bonsai_lang_api::{kit::for_each_flow_event, FlowEvent, LanguageRegistry, StaticScalarValue};
use std::sync::Arc;

pub(super) fn project(
    manifest_path: &std::path::Path,
    text: &str,
    layout: &DependencyManifestLayout,
    parent: Option<&Workspace>,
    output: &mut AHashSet<String>,
) -> anyhow::Result<()> {
    bonsai_common::run_scoped_compiler_phase("dependency-manifest", || {
        project_compiled(manifest_path, text, layout, parent, output)
    })
}

fn project_compiled(
    manifest_path: &std::path::Path,
    text: &str,
    layout: &DependencyManifestLayout,
    parent: Option<&Workspace>,
    output: &mut AHashSet<String>,
) -> anyhow::Result<()> {
    let language = layout
        .adapter
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("code layout requires an adapter"))?;
    let adapter = parent
        .and_then(|ws| {
            ws.registry()
                .all()
                .into_iter()
                .find(|adapter| adapter.language_id().as_str() == language)
        })
        .ok_or_else(|| anyhow::anyhow!("dependency manifest adapter `{language}` is unavailable"))?;
    let extension = adapter
        .file_extensions()
        .first()
        .ok_or_else(|| anyhow::anyhow!("adapter has no source extension"))?;
    let path = format!("dependency-manifest.{extension}");
    let capabilities = adapter.capabilities();
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    // Metadata files may have no compiler source extension (for example a
    // DSL manifest). This isolated VFS does not publish partial sidecars into
    // the parent workspace or execute dependency-manager code.
    let ws = Workspace::new(registry);
    let file = ws.vfs().write(path, text);
    let mut rules = Vec::with_capacity(layout.calls.len());
    for (index, call) in layout.calls.iter().enumerate() {
        let mut rule: crate::rule::Rule = serde_json::from_value(serde_json::json!({
            "id": format!("metadata.dependency.call_{index}"),
            "enabled": true,
            "language": language,
            "description": "Compiler-proven dependency declaration in a code manifest",
            "match": {"kind": "call", "callee": call.callee},
        }))?;
        rule.kind = crate::rule::RuleKind::Typing;
        rules.push(rule);
    }
    let matches = crate::matcher::match_rules_against_facts(&ws, &rules.iter().collect::<Vec<_>>());
    if !matches.is_empty() {
        // A file-local lowering cannot prove the effects of imported first-
        // party code. Keep the real manifest's directory for this check:
        // a synthetic VFS filename must not turn a local provider into an
        // external package. Include unselected files and namespace directories;
        // excluding them from analysis is not proof that they cannot shadow
        // an import at runtime. Ambiguous execution stays explicitly partial.
        for import in ws.db().imports_for(file) {
            let mut local = import.module.starts_with('.');
            for candidate in
                crate::matcher::import_candidate_paths(manifest_path, &import.module, &capabilities)
            {
                if local {
                    break;
                }
                local = parent.is_some_and(|parent| parent.vfs().lookup(&candidate).is_some())
                    || candidate
                        .try_exists()
                        .with_context(|| format!("checking code-manifest import {}", import.module))?;
            }
            anyhow::ensure!(
                !local,
                "code manifest imports workspace-local code; cross-module execution is not modeled"
            );
        }
    }
    let index = ws
        .exact_decl_index_shared(file)
        .ok_or_else(|| anyhow::anyhow!("dependency compiler object is unavailable"))?;
    let diagnostics = ws.parser_incomplete_reasons_for_files(&[file]);
    anyhow::ensure!(
        diagnostics.is_empty(),
        "dependency manifest syntax coverage: {}",
        diagnostics.join(", ")
    );
    let mut call_arguments = ahash::AHashMap::new();
    for declaration in &index.defs {
        // The compiler's synthetic module evaluator owns top-level execution.
        // A same-named ordinary function has a distinct name span. Calls in
        // uninvoked helpers/callback bodies are not installation evidence.
        if declaration.name != bonsai_lang_api::kit::MODULE_DECL_NAME
            || declaration.name_span != declaration.span
            || declaration.parent.is_some()
        {
            continue;
        }
        for_each_flow_event(&declaration.flow_events, &mut |event| {
            if let FlowEvent::Call { span, args, .. } = event {
                call_arguments.insert(*span, args);
            }
        });
    }
    let mut argument_facts = ahash::AHashMap::new();
    for fact in &index.call_argument_values {
        argument_facts.insert((fact.call_span, fact.argument_index), fact);
    }
    for (model, rule) in layout.calls.iter().zip(&rules) {
        let sites: AHashSet<_> = matches
            .iter()
            .filter(|matched| matched.rule_id == rule.id)
            .map(|matched| matched.span)
            .collect();
        for argument in &model.arguments {
            let capture = argument.capture.as_deref().map(regex::Regex::new).transpose()?;
            for site in &sites {
                let args = call_arguments.get(site).ok_or_else(|| {
                    anyhow::anyhow!("dependency declaration needs helper/callback execution evidence")
                })?;
                let position = argument.keyword.as_deref().map_or(argument.index, |keyword| {
                    args.iter().position(|arg| arg.name.as_deref() == Some(keyword))
                });
                let Some(position) = position.filter(|position| *position < args.len()) else {
                    continue;
                };
                let fact = argument_facts
                    .get(&(*site, position))
                    .ok_or_else(|| anyhow::anyhow!("dependency argument has no exact compiler value"))?;
                if argument.sequence {
                    let values = fact
                        .exact_static_sequence_values
                        .as_ref()
                        .ok_or_else(|| anyhow::anyhow!("dependency sequence is not statically known"))?;
                    for value in values {
                        admit_static(value.as_ref(), capture.as_ref(), output)?;
                    }
                } else {
                    admit_static(fact.static_value.as_ref(), capture.as_ref(), output)?;
                }
            }
        }
    }
    Ok(())
}

fn admit_static(
    value: Option<&StaticScalarValue>,
    capture: Option<&regex::Regex>,
    output: &mut AHashSet<String>,
) -> anyhow::Result<()> {
    let Some(StaticScalarValue::String(value)) = value else {
        anyhow::bail!("dependency name is not a static string");
    };
    super::admit(value, capture, output);
    Ok(())
}
