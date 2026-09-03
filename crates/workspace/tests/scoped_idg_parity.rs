use bonsai_common::{FileId, FuncId, Span, SymbolId};
use bonsai_lang_api::LanguageRegistry;
use bonsai_lang_java::JavaAdapter;
use bonsai_taint::{compose_idg_seed_nodes, IdgSeedRequest, TokenSet};
use bonsai_workspace::Workspace;
use std::{fs, path::PathBuf, sync::Arc};

fn java_language_gauntlet_workspace() -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(Arc::new(JavaAdapter::new()));
    let workspace = Workspace::new(registry);
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/java/language_gauntlet/src/main/java");
    let mut pending = vec![root.clone()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in
            fs::read_dir(&directory).unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
        {
            let path = entry.expect("Java gauntlet directory entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "java") {
                files.push(path);
            }
        }
    }
    files.sort();
    for path in files {
        let relative = path.strip_prefix(&root).expect("Java gauntlet relative path");
        let virtual_path = PathBuf::from("/java-language-gauntlet").join(relative);
        let source =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        workspace.vfs().write(virtual_path, Arc::<str>::from(source));
    }
    workspace
}

fn function(global: &bonsai_index::GlobalIndex, name: &str) -> FuncId {
    let symbols = global.find_by_name(name);
    let symbol = symbols
        .iter()
        .copied()
        .find(|symbol| {
            global.decl_of(*symbol).is_some_and(|decl| {
                matches!(
                    decl.kind,
                    bonsai_lang_api::DeclKind::Function
                        | bonsai_lang_api::DeclKind::Method
                        | bonsai_lang_api::DeclKind::Constructor
                )
            })
        })
        .unwrap_or_else(|| panic!("missing function {name}"));
    FuncId::new(symbol.raw())
}

fn call_span(
    workspace: &Workspace,
    global: &bonsai_index::GlobalIndex,
    func: FuncId,
    call_name: &str,
) -> Span {
    let file = global
        .declaring_file(SymbolId::new(func.raw()))
        .expect("function file");
    let body = workspace
        .db()
        .decl_index_remapped_to_headers(global, file)
        .expect("exact compiler body");
    let decl = body
        .defs
        .iter()
        .find(|decl| decl.symbol.raw() == func.raw())
        .expect("function body");
    find_call_span(&decl.flow_events, call_name).unwrap_or_else(|| panic!("missing call {call_name}"))
}

fn find_call_span(events: &[bonsai_lang_api::FlowEvent], call_name: &str) -> Option<Span> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        let nested = match event {
            FlowEvent::Call { span, name, .. } if name == call_name => return Some(*span),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => find_call_span(then_events, call_name).or_else(|| find_call_span(else_events, call_name)),
            FlowEvent::Loop {
                condition_events,
                body,
                update_events,
                ..
            } => find_call_span(condition_events, call_name)
                .or_else(|| find_call_span(body, call_name))
                .or_else(|| find_call_span(update_events, call_name)),
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => find_call_span(body, call_name),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => find_call_span(body, call_name)
                .or_else(|| find_call_span(catch_events, call_name))
                .or_else(|| find_call_span(finally_events, call_name)),
            _ => None,
        };
        if nested.is_some() {
            return nested;
        }
    }
    None
}

fn call_identifier_span(workspace: &Workspace, call_span: Span, identifier: &str) -> Span {
    let source = workspace
        .vfs()
        .snapshot(call_span.file)
        .expect("call source snapshot");
    let call_text = &source.text[call_span.start as usize..call_span.end as usize];
    let offset = call_text
        .rfind(identifier)
        .unwrap_or_else(|| panic!("missing identifier {identifier} inside {call_text:?}"));
    Span::new(
        call_span.file,
        call_span.start + offset as u64,
        call_span.start + offset as u64 + identifier.len() as u64,
    )
}

#[test]
fn file_function_scoped_idg_matches_complete_java_record_flow() {
    let workspace = java_language_gauntlet_workspace();
    let global = workspace.compiler_linkage_index();
    let call_graph = bonsai_taint::build_resolved_call_graph_snapshot(workspace.db());
    let files: Vec<FileId> = global.all_files().collect();
    let funcs: Vec<FuncId> = files
        .iter()
        .flat_map(|file| global.functions_in(*file))
        .map(|decl| FuncId::new(decl.symbol.raw()))
        .collect();
    let options =
        bonsai_idg::TransferOptions::compiler_semantics(workspace.db().complete_field_place_languages());
    let scoped = workspace.build_idg_service_with_transfer_options_for_files_and_call_graph(
        &options,
        &files,
        &funcs,
        &call_graph,
    );

    let handle = function(global.as_ref(), "handle");
    let execute = function(global.as_ref(), "execute");
    let orchestrate = function(global.as_ref(), "orchestrate");
    let record_cmd = global
        .find_by_name("cmd")
        .iter()
        .copied()
        .find(|symbol| {
            global
                .decl_of(*symbol)
                .and_then(|decl| decl.parent)
                .and_then(|parent| global.decl_of(parent))
                .is_some_and(|parent| parent.qualified_name.as_deref() == Some("gauntlet.domain.Envelope"))
        })
        .map(|symbol| FuncId::new(symbol.raw()))
        .expect("record cmd accessor");
    assert!(
        call_graph
            .callees_of(orchestrate)
            .any(|edge| edge.to == record_cmd),
        "typed record-accessor calls are compiler call edges; record_accessor={:?}; outgoing={:?}",
        global.decl_of(SymbolId::new(record_cmd.raw())),
        call_graph.callees_of(orchestrate).collect::<Vec<_>>()
    );
    let source_span = call_identifier_span(
        &workspace,
        call_span(&workspace, global.as_ref(), handle, "request.getParameter"),
        "getParameter",
    );
    let sink_span = call_identifier_span(
        &workspace,
        call_span(&workspace, global.as_ref(), execute, "Runtime.getRuntime().exec"),
        "exec",
    );
    let mut names = TokenSet::default();
    names.insert("raw".to_string());
    names.insert("request.getParameter".to_string());
    let seeds = compose_idg_seed_nodes(
        IdgSeedRequest::rule_match(handle, &names, Some(source_span), &[]),
        global.as_ref(),
        scoped.as_ref(),
    );
    let sink_nodes = scoped.nodes_at_span(execute, sink_span);
    let allowed = funcs
        .iter()
        .copied()
        .filter(|func| {
            global.decl_of(SymbolId::new(func.raw())).is_some_and(|decl| {
                decl.name != "cleanTwin"
                    && !matches!(
                        decl.qualified_name.as_deref(),
                        Some("gauntlet.storage.BaseRepository.run")
                    )
            })
        })
        .collect();
    let relevance = scoped.target_relevance_within_funcs(&sink_nodes, None, &allowed);
    let closure = scoped.forward_closure_evidence_rooted_at_func_within_funcs_and_relevance(
        &seeds,
        handle,
        &allowed,
        Some(&relevance),
    );
    assert!(
        closure.nodes.iter().any(|node| sink_nodes.contains(node)),
        "scoped IDG must preserve the same compiler-proven Java record path as the complete graph; seeds={:?}; targets={:?}; closure={:?}",
        seeds
            .iter()
            .filter_map(|node| scoped.resolve_point(*node))
            .collect::<Vec<_>>(),
        sink_nodes
            .iter()
            .filter_map(|node| scoped.resolve_point(*node))
            .collect::<Vec<_>>(),
        closure
            .nodes
            .iter()
            .filter_map(|node| scoped.resolve_point(*node))
            .collect::<Vec<_>>()
    );
}
