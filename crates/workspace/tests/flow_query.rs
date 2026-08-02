use ahash::AHashSet;
use bonsai_common::{FuncId, SymbolId};
use bonsai_lang_api::{AdapterArc, DeclKind, FlowEvent, LanguageRegistry};
use bonsai_workspace::{
    flow_query::{SyntaxFlowBackend, SyntaxFlowCacheStatus, SyntaxFlowQuery},
    Workspace,
};
use std::sync::Arc;

fn python_ws(source: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    let adapter: AdapterArc = Arc::new(bonsai_lang_python::PythonAdapter::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    ws.vfs().write("/w/app.py".to_string(), Arc::<str>::from(source));
    for file in ws.vfs().all_files() {
        let _ = ws.db().decl_index(file);
    }
    ws
}

fn func_id(ws: &Workspace, name: &str) -> FuncId {
    let global = ws.db().global_index();
    global
        .find_by_name(name)
        .iter()
        .find_map(|sym| {
            global.decl_of(*sym).and_then(|decl| {
                matches!(
                    decl.kind,
                    DeclKind::Function | DeclKind::Method | DeclKind::Constructor
                )
                .then_some(FuncId::new(sym.raw()))
            })
        })
        .unwrap_or_else(|| panic!("missing callable `{name}`"))
}

fn graph_mentions_call(ws: &Workspace, graph: &bonsai_taint::EntryTaintGraph, name: &str) -> bool {
    let global = ws.db().global_index();
    graph.tainted_calls.iter().any(|call| call.name.contains(name))
        || graph.call_records.iter().any(|edge| {
            global
                .decl_of(SymbolId::new(edge.callee.raw()))
                .is_some_and(|decl| decl.name.contains(name))
        })
}

#[test]
fn syntax_flow_query_uses_cached_dataflow_when_idg_is_cold() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    assert!(ws.db().idg_service().is_none(), "fixture starts with cold IDG");

    let result = ws.syntax_flow_graph(SyntaxFlowQuery::new(entry).prefer_warmed_idg(true));

    assert_eq!(result.backend, SyntaxFlowBackend::CachedDataflow);
    assert_eq!(result.plan.backend, SyntaxFlowBackend::CachedDataflow);
    assert_eq!(result.plan.cache_status, SyntaxFlowCacheStatus::MissComputed);
    assert!(result.plan.prefer_warmed_idg);
    assert!(!result.plan.idg_available);
    assert_eq!(result.plan.target_cut_size, None);
    assert!(
        result
            .plan
            .fallback_reasons
            .iter()
            .any(|reason| reason.contains("warmed IDG unavailable")),
        "cold preferred-IDG query should explain why it fell back: {:#?}",
        result.plan
    );
    assert!(
        ws.db().idg_service().is_none(),
        "syntax_flow_graph must not build IDG on the inspect hot path"
    );
    assert!(
        graph_mentions_call(&ws, result.graph.as_ref(), "sink"),
        "cached dataflow backend must preserve the syntax-shaped sink flow"
    );

    let warm_result = ws.syntax_flow_graph(SyntaxFlowQuery::new(entry).prefer_warmed_idg(true));
    assert_eq!(warm_result.backend, SyntaxFlowBackend::CachedDataflow);
    assert_eq!(warm_result.plan.cache_status, SyntaxFlowCacheStatus::Hit);
}

#[test]
fn syntax_flow_query_uses_warmed_idg_target_cut() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    let sink = func_id(&ws, "sink");
    let mut targets = AHashSet::new();
    targets.insert(sink);
    let _ = ws.build_and_seed_idg_service();
    assert!(ws.db().idg_service().is_some(), "IDG should be warmed");
    let idg_linkage = ws
        .db()
        .idg_service()
        .expect("warmed service")
        .global_linkage_index();
    assert!(
        Arc::ptr_eq(&ws.compiler_header_index(), &idg_linkage),
        "syntax queries must reuse the IDG's immutable compiler headers"
    );

    let result = ws.syntax_flow_graph(
        SyntaxFlowQuery::new(entry)
            .target_funcs(Some(&targets))
            .prefer_warmed_idg(true),
    );

    assert_eq!(result.backend, SyntaxFlowBackend::WarmedIdgTargetCut);
    assert_eq!(result.plan.backend, SyntaxFlowBackend::WarmedIdgTargetCut);
    assert_eq!(result.plan.cache_status, SyntaxFlowCacheStatus::Hit);
    assert!(result.plan.idg_available);
    assert_eq!(result.plan.target_cut_size, Some(1));
    assert!(
        result.plan.fallback_reasons.is_empty(),
        "IDG-backed query should not report fallback: {:#?}",
        result.plan
    );
    assert!(
        graph_mentions_call(&ws, result.graph.as_ref(), "sink"),
        "warmed IDG backend must preserve the target-cut sink flow"
    );
}

#[test]
fn syntax_flow_batch_reuses_exact_span_relevance_without_changing_evidence() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    let helper = func_id(&ws, "helper");
    let sink = func_id(&ws, "sink");
    let global = ws.db().global_index();
    let sink_call_span = global
        .decl_of(SymbolId::new(helper.raw()))
        .expect("helper declaration")
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name.ends_with("sink") => Some(*span),
            _ => None,
        })
        .expect("sink call span");
    drop(global);
    let _ = ws.build_and_seed_idg_service();
    let (target_nodes, unresolved) = ws
        .syntax_flow_target_nodes(&[(helper, sink_call_span)])
        .expect("warmed target-node lookup");
    assert!(
        !target_nodes.is_empty(),
        "call syntax must resolve to typed IDG nodes"
    );
    assert!(unresolved.is_empty());
    let lineage: AHashSet<_> = [entry, helper, sink].into_iter().collect();
    let relevance = ws
        .syntax_flow_target_relevance(&target_nodes, &unresolved, Some(&lineage))
        .expect("backward target proof");

    let baseline = ws.syntax_flow_graph(
        SyntaxFlowQuery::new(entry)
            .target_nodes(Some(&target_nodes))
            .lineage_funcs(Some(&lineage))
            .prefer_warmed_idg(true),
    );
    let demanded = ws.syntax_flow_graph(
        SyntaxFlowQuery::new(entry)
            .target_nodes(Some(&target_nodes))
            .lineage_funcs(Some(&lineage))
            .target_relevance(Some(&relevance))
            .prefer_warmed_idg(true),
    );

    assert_eq!(demanded.graph.call_records, baseline.graph.call_records);
    assert_eq!(demanded.graph.tainted_calls, baseline.graph.tainted_calls);
    assert!(graph_mentions_call(&ws, demanded.graph.as_ref(), "sink"));
}

#[test]
fn shared_target_relevance_preserves_independent_owner_evidence() {
    let ws = python_ws(
        "def first(value):\n    sink_one(value)\n\n\
         def second(value):\n    sink_two(value)\n",
    );
    let first = func_id(&ws, "first");
    let second = func_id(&ws, "second");
    let global = ws.db().global_index();
    let call_span = |func: FuncId, suffix: &str| {
        global
            .decl_of(SymbolId::new(func.raw()))
            .expect("owner declaration")
            .flow_events
            .iter()
            .find_map(|event| match event {
                FlowEvent::Call { name, span, .. } if name.ends_with(suffix) => Some(*span),
                _ => None,
            })
            .expect("target call span")
    };
    let first_span = call_span(first, "sink_one");
    let second_span = call_span(second, "sink_two");
    drop(global);
    let _ = ws.build_and_seed_idg_service();
    let (first_targets, first_unresolved) = ws
        .syntax_flow_target_nodes(&[(first, first_span)])
        .expect("first target nodes");
    let (second_targets, second_unresolved) = ws
        .syntax_flow_target_nodes(&[(second, second_span)])
        .expect("second target nodes");
    assert!(first_unresolved.is_empty() && second_unresolved.is_empty());
    let mut union_targets = first_targets.clone();
    union_targets.extend(second_targets.iter().copied());
    union_targets.sort_unstable();
    union_targets.dedup();
    let lineage: AHashSet<_> = [first, second].into_iter().collect();
    let relevance = ws
        .syntax_flow_target_relevance(&union_targets, &AHashSet::new(), Some(&lineage))
        .expect("shared target relevance");

    for (entry, targets, own_sink, other_sink) in [
        (first, first_targets.as_slice(), "sink_one", "sink_two"),
        (second, second_targets.as_slice(), "sink_two", "sink_one"),
    ] {
        let baseline = ws.syntax_flow_graph(
            SyntaxFlowQuery::new(entry)
                .target_nodes(Some(targets))
                .lineage_funcs(Some(&lineage))
                .prefer_warmed_idg(true),
        );
        let demanded = ws.syntax_flow_graph(
            SyntaxFlowQuery::new(entry)
                .target_nodes(Some(targets))
                .lineage_funcs(Some(&lineage))
                .target_relevance(Some(&relevance))
                .prefer_warmed_idg(true),
        );
        assert_eq!(demanded.graph.call_records, baseline.graph.call_records);
        assert_eq!(demanded.graph.tainted_calls, baseline.graph.tainted_calls);
        assert!(graph_mentions_call(&ws, demanded.graph.as_ref(), own_sink));
        assert!(
            !graph_mentions_call(&ws, demanded.graph.as_ref(), other_sink),
            "shared backward demand must not leak another owner's endpoint into exact forward evidence"
        );
    }
}

#[test]
fn syntax_flow_query_uses_one_exact_scoped_session_when_idg_is_cold() {
    let ws = python_ws(
        "def entry(req):\n    helper(req)\n\n\
         def helper(value):\n    sink(value)\n\n\
         def unrelated(value):\n    other(value)\n\n\
         def sink(arg):\n    return arg\n",
    );
    let entry = func_id(&ws, "entry");
    let helper = func_id(&ws, "helper");
    let unrelated = func_id(&ws, "unrelated");
    let sink = func_id(&ws, "sink");
    let global = ws.db().global_index();
    let sink_call_span = global
        .decl_of(SymbolId::new(helper.raw()))
        .expect("helper declaration")
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Call { name, span, .. } if name.ends_with("sink") => Some(*span),
            _ => None,
        })
        .expect("sink call span");
    drop(global);
    let mut targets = AHashSet::new();
    targets.insert(sink);
    let session = ws
        .syntax_flow_session(&[entry], &targets)
        .expect("source-to-target compiler corridor");
    assert!(
        ws.db().idg_service().is_none(),
        "query-scoped IDG must not replace the full-workspace service"
    );
    let (target_nodes, unresolved) = ws
        .syntax_flow_target_nodes_with_session(&[(helper, sink_call_span)], Some(&session))
        .expect("scoped target-node lookup");
    assert!(!target_nodes.is_empty());
    assert!(unresolved.is_empty());
    let lineage: AHashSet<_> = [entry, helper, sink].into_iter().collect();
    let relevance = ws
        .syntax_flow_target_relevance_with_session(&target_nodes, &unresolved, Some(&lineage), Some(&session))
        .expect("scoped backward target proof");
    assert_eq!(
        ws.syntax_flow_relevant_sources_with_session(
            &[unrelated, entry, helper],
            &relevance,
            Some(&session),
        )
        .expect("scoped relevant sources"),
        vec![entry, helper],
        "cold source filtering must use the exact scoped IDG and preserve input order"
    );

    let result = ws.syntax_flow_graph(
        SyntaxFlowQuery::new(entry)
            .target_nodes(Some(&target_nodes))
            .lineage_funcs(Some(&lineage))
            .target_relevance(Some(&relevance))
            .prefer_warmed_idg(true)
            .session(Some(&session)),
    );

    assert_eq!(result.backend, SyntaxFlowBackend::ScopedIdgTargetCut);
    assert_eq!(result.plan.backend, SyntaxFlowBackend::ScopedIdgTargetCut);
    assert_eq!(result.plan.cache_status, SyntaxFlowCacheStatus::Hit);
    assert!(!result.plan.idg_available);
    assert_eq!(result.plan.target_cut_size, Some(target_nodes.len()));
    assert!(
        graph_mentions_call(&ws, result.graph.as_ref(), "sink"),
        "scoped IDG backend must preserve the exact target flow"
    );
    assert!(
        ws.db().idg_service().is_none(),
        "scoped session must remain query-local after execution"
    );
}
