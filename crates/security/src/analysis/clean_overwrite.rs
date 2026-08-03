//! Clean-overwrite false-negative filters.
//!
//! Detects when a tainted target is definitively overwritten with a clean
//! value between its taint point and the sink — same-function and
//! interprocedurally — so the finding is suppressed. Only the LAST write
//! before the sink may kill the flow; conditional/partial writes keep it.
//! Includes the small static evaluators (numeric conditions and ternaries)
//! used to prove a write is clean.

#[allow(clippy::wildcard_imports)]
use super::*;

#[derive(Clone, Copy)]
pub(super) struct CleanOverwritePolicy<'a> {
    ws: &'a Workspace,
    clean_output_overwrites: &'a [CleanOutputOverwrite],
}

impl<'a> CleanOverwritePolicy<'a> {
    pub(super) fn new(ws: &'a Workspace, clean_output_overwrites: &'a [CleanOutputOverwrite]) -> Self {
        Self {
            ws,
            clean_output_overwrites,
        }
    }
}

pub(super) fn tainted_arg_info_from_events(
    events: &[FlowEvent],
    call_span: Span,
    arg: &bonsai_taint::TaintedArgAtCall,
) -> TaintedArgInfo {
    let structured = find_call_arg_at(events, call_span, arg.index);
    TaintedArgInfo {
        index: arg.index,
        value_text: arg.value_text.clone(),
        place: structured.and_then(|call_arg| call_arg.place.clone()),
        source_names: structured
            .map(|call_arg| call_arg.source_names.clone())
            .unwrap_or_default(),
    }
}

pub(super) fn tainted_arg_target_keys(arg: &TaintedArgInfo) -> Vec<String> {
    semantic_target_keys(arg.place.as_deref(), &arg.source_names, &arg.value_text)
}

pub(super) fn call_arg_target_keys(arg: &bonsai_lang_api::CallArg) -> Vec<String> {
    semantic_target_keys(arg.place.as_deref(), &arg.source_names, &arg.value_text)
}

fn semantic_target_keys(place: Option<&str>, source_names: &[String], fallback_text: &str) -> Vec<String> {
    let mut out: Vec<String> = source_names
        .iter()
        .filter_map(|source| clean_overwrite_target_key(source))
        .collect();
    out.extend(place.and_then(clean_overwrite_target_key));
    if out.is_empty() {
        out.extend(clean_overwrite_target_key(fallback_text));
    }
    out.sort();
    out.dedup();
    out
}

pub(super) fn same_function_clean_overwrite_kills_sink_arg(
    policy: CleanOverwritePolicy<'_>,
    src_func: FuncId,
    sink_func: FuncId,
    source_span: Span,
    sink_span: Span,
    tainted_args: &[bonsai_taint::TaintedArgAtCall],
    tainted_receiver: Option<&str>,
) -> bool {
    if src_func != sink_func || (tainted_args.is_empty() && tainted_receiver.is_none()) {
        return false;
    }
    let Some(decl) = policy.ws.exact_decl(SymbolId::new(sink_func.raw())) else {
        return false;
    };
    let mut targets: Vec<String> = tainted_args
        .iter()
        .flat_map(|arg| {
            find_call_arg_at(&decl.flow_events, sink_span, arg.index).map_or_else(
                || clean_overwrite_target_key(&arg.value_text).into_iter().collect(),
                call_arg_target_keys,
            )
        })
        .collect();
    targets.extend(tainted_receiver.and_then(clean_overwrite_target_key));
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return false;
    }
    clean_overwrite_between(
        policy,
        &decl.flow_events,
        &decl.flow_events,
        source_span,
        sink_span,
        &targets,
        true,
    ) || targets.iter().any(|target| {
        clean_assignment_from_clean_inputs_between(
            policy,
            &decl.flow_events,
            &decl.flow_events,
            source_span,
            sink_span,
            target,
        )
    })
}

pub(super) fn interprocedural_clean_overwrite_kills_lineage_arg(
    policy: CleanOverwritePolicy<'_>,
    src_func: FuncId,
    source_span: Span,
    trace_index: &AHashMap<u64, &TaintedCallEdge>,
    terminal_call: &TaintedCall,
) -> bool {
    let Some(records) = lineage_records_for_call_indexed(trace_index, terminal_call) else {
        return false;
    };
    records
        .iter()
        .any(|record| propagation_record_clean_overwrite_kills_edge(policy, src_func, source_span, record))
}

fn propagation_record_clean_overwrite_kills_edge(
    policy: CleanOverwritePolicy<'_>,
    src_func: FuncId,
    source_span: Span,
    record: &TaintedCallEdge,
) -> bool {
    if record.tainted_args.is_empty() {
        return false;
    }
    let Some(decl) = policy.ws.exact_decl(SymbolId::new(record.caller.raw())) else {
        return false;
    };
    if record.caller == src_func && source_span.file != record.call_span.file {
        return false;
    }
    let edge_source_span = if record.caller == src_func {
        source_span
    } else {
        Span::empty(decl.span.file, decl.span.start)
    };
    if record.call_span.file != edge_source_span.file || record.call_span.start <= edge_source_span.start {
        return false;
    }
    record.tainted_args.iter().any(|arg| {
        let targets = clean_overwrite_targets_for_edge_arg(&decl.flow_events, record.call_span, arg);
        if targets.is_empty() {
            return false;
        }
        targets.iter().any(|target| {
            let clean_overwrite = clean_overwrite_between(
                policy,
                &decl.flow_events,
                &decl.flow_events,
                edge_source_span,
                record.call_span,
                std::slice::from_ref(target),
                true,
            );
            let clean_assignment = clean_assignment_from_clean_inputs_between(
                policy,
                &decl.flow_events,
                &decl.flow_events,
                edge_source_span,
                record.call_span,
                target,
            );
            if clean_overwrite || clean_assignment {
                bonsai_diagnostics::debug_log!(
                    "security-taint",
                    "inter_clean_overwrite_edge caller={} callee={} call_span={:?} edge_source_span={:?} arg={:?} target={} clean_overwrite={} clean_assignment={}",
                    record.caller.raw(),
                    record.callee.raw(),
                    record.call_span,
                    edge_source_span,
                    arg,
                    target,
                    clean_overwrite,
                    clean_assignment
                );
            }
            clean_overwrite || clean_assignment
        })
    })
}

fn clean_overwrite_targets_for_edge_arg(
    events: &[bonsai_lang_api::FlowEvent],
    call_span: Span,
    tainted_arg: &bonsai_taint::TaintedArg,
) -> Vec<String> {
    let mut targets = Vec::new();
    if let Some(arg) = find_call_arg_at(events, call_span, tainted_arg.index) {
        targets.extend(call_arg_target_keys(arg));
    }
    if targets.is_empty() {
        targets.extend(clean_overwrite_target_key(&tainted_arg.value_text));
    }
    targets
        .retain(|target| !clean_conditional_helper_identifier(target) && !looks_like_clean_constant(target));
    targets.sort();
    targets.dedup();
    targets
}

fn find_call_arg_at(
    events: &[bonsai_lang_api::FlowEvent],
    call_span: Span,
    arg_index: usize,
) -> Option<&bonsai_lang_api::CallArg> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if *span == call_span || spans_overlap(*span, call_span) {
                    if let Some(arg) = args.get(arg_index) {
                        return Some(arg);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(arg) = find_call_arg_at(then_events, call_span, arg_index)
                    .or_else(|| find_call_arg_at(else_events, call_span, arg_index))
                {
                    return Some(arg);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(arg) = find_call_arg_at(body, call_span, arg_index) {
                    return Some(arg);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(arg) = find_call_arg_at(body, call_span, arg_index)
                    .or_else(|| find_call_arg_at(catch_events, call_span, arg_index))
                    .or_else(|| find_call_arg_at(finally_events, call_span, arg_index))
                {
                    return Some(arg);
                }
            }
            _ => {}
        }
    }
    None
}

fn clean_overwrite_between(
    policy: CleanOverwritePolicy<'_>,
    events: &[bonsai_lang_api::FlowEvent],
    func_events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    sink_span: Span,
    targets: &[String],
    allow_direct_assign: bool,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_names,
                source_call_args,
                value_kind,
                ..
            } => {
                if allow_direct_assign
                    && span.file == source_span.file
                    && span.start > source_span.start
                    && span.end <= sink_span.start
                    && targets.iter().any(|target_key| {
                        clean_overwrite_target_key(target).as_deref() == Some(target_key)
                            && assignment_cleanly_overwrites_target(
                                policy,
                                *span,
                                source_name.as_deref(),
                                source_call.as_deref(),
                                source_names,
                                source_call_args,
                                *value_kind,
                            )
                            // A clean overwrite only kills the sink arg
                            // when it is the LAST write to the target
                            // before the sink. If the target is written
                            // again after this overwrite (e.g.
                            // `cmd = ""; cmd = user_input; sink(cmd)` or a
                            // conditional re-taint), the later write
                            // supersedes it and the IDG closure already
                            // accounts for the live value — suppressing
                            // here would drop a real finding.
                            && !target_written_between(func_events, target_key, *span, sink_span)
                    })
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
                ..
            } => {
                if span.file == source_span.file
                    && span.start > source_span.start
                    && span.end <= sink_span.start
                    && !else_events.is_empty()
                    && targets.iter().any(|target| {
                        if let Some(takes_then) = condition
                            .as_deref()
                            .and_then(|condition| static_numeric_condition_value(policy.ws, *span, condition))
                        {
                            if takes_then {
                                branch_arm_clean_overwrites_target(policy, then_events, target)
                            } else {
                                branch_arm_clean_overwrites_target(policy, else_events, target)
                            }
                        } else {
                            branch_arm_clean_overwrites_target(policy, then_events, target)
                                && branch_arm_clean_overwrites_target(policy, else_events, target)
                        }
                    })
                {
                    return true;
                }
                if clean_overwrite_between(
                    policy,
                    then_events,
                    func_events,
                    source_span,
                    sink_span,
                    targets,
                    false,
                ) || clean_overwrite_between(
                    policy,
                    else_events,
                    func_events,
                    source_span,
                    sink_span,
                    targets,
                    false,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if clean_overwrite_between(
                    policy,
                    body,
                    func_events,
                    source_span,
                    sink_span,
                    targets,
                    allow_direct_assign,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if clean_overwrite_between(
                    policy,
                    finally_events,
                    func_events,
                    source_span,
                    sink_span,
                    targets,
                    allow_direct_assign,
                ) {
                    return true;
                }
                let try_before_sink = span.file == source_span.file && span.end <= sink_span.start;
                let try_after_source =
                    try_before_sink && span.start > source_span.start && span.end <= sink_span.start;
                if try_after_source
                    && targets.iter().any(|target| {
                        try_region_clean_overwrites_target(policy, body, catch_events, finally_events, target)
                    })
                {
                    return true;
                }
                let source_inside_try =
                    try_before_sink && span.start <= source_span.start && source_span.start <= span.end;
                if source_inside_try {
                    for target in targets {
                        let single_target = [target.clone()];
                        let body_cleans_after_source = clean_overwrite_between(
                            policy,
                            body,
                            func_events,
                            source_span,
                            sink_span,
                            &single_target,
                            allow_direct_assign,
                        );
                        let catch_cleans_after_source = clean_overwrite_between(
                            policy,
                            catch_events,
                            func_events,
                            source_span,
                            sink_span,
                            &single_target,
                            allow_direct_assign,
                        );
                        let body_always_clean = branch_arm_clean_overwrites_target(policy, body, target);
                        let catch_always_clean = catch_events.is_empty()
                            || branch_arm_clean_overwrites_target(policy, catch_events, target);
                        if (body_cleans_after_source && catch_always_clean)
                            || (catch_cleans_after_source && body_always_clean)
                        {
                            return true;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn clean_assignment_from_clean_inputs_between(
    policy: CleanOverwritePolicy<'_>,
    events: &[bonsai_lang_api::FlowEvent],
    func_events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    sink_span: Span,
    target_key: &str,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                source_names,
                source_call_args,
                ..
            } => {
                if span.file == source_span.file
                    && span.start > source_span.start
                    && span.end <= sink_span.start
                    && clean_overwrite_target_key(target).as_deref() == Some(target_key)
                    && source_call.is_none()
                    && source_call_args.is_empty()
                    && !target_written_between(func_events, target_key, *span, sink_span)
                    && assignment_source_names_are_clean_before(
                        policy,
                        func_events,
                        source_span,
                        *span,
                        source_names,
                    )
                {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if clean_assignment_from_clean_inputs_between(
                    policy,
                    then_events,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) || clean_assignment_from_clean_inputs_between(
                    policy,
                    else_events,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if clean_assignment_from_clean_inputs_between(
                    policy,
                    body,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if clean_assignment_from_clean_inputs_between(
                    policy,
                    body,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) || clean_assignment_from_clean_inputs_between(
                    policy,
                    catch_events,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) || clean_assignment_from_clean_inputs_between(
                    policy,
                    finally_events,
                    func_events,
                    source_span,
                    sink_span,
                    target_key,
                ) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn assignment_source_names_are_clean_before(
    policy: CleanOverwritePolicy<'_>,
    func_events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    assign_span: Span,
    source_names: &[String],
) -> bool {
    let mut source_keys: Vec<String> = source_names
        .iter()
        .filter_map(|name| clean_overwrite_target_key(name))
        .filter(|name| !looks_like_clean_constant(name))
        .collect();
    source_keys.sort();
    source_keys.dedup();
    !source_keys.is_empty()
        && source_keys.iter().all(|source_key| {
            clean_overwrite_between(
                policy,
                func_events,
                func_events,
                source_span,
                assign_span,
                std::slice::from_ref(source_key),
                true,
            ) || target_only_has_clean_writes_between(
                policy,
                func_events,
                source_span,
                assign_span,
                source_key,
            )
        })
}

fn target_only_has_clean_writes_between(
    policy: CleanOverwritePolicy<'_>,
    events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    limit_span: Span,
    target_key: &str,
) -> bool {
    let mut cleanliness = TargetWriteCleanliness::default();
    collect_target_write_cleanliness(
        policy,
        events,
        source_span,
        limit_span,
        target_key,
        0,
        &mut cleanliness,
    );
    cleanliness.saw_unconditional_clean && !cleanliness.saw_dirty
}

#[derive(Default)]
struct TargetWriteCleanliness {
    saw_clean: bool,
    saw_unconditional_clean: bool,
    saw_dirty: bool,
}

fn collect_target_write_cleanliness(
    policy: CleanOverwritePolicy<'_>,
    events: &[bonsai_lang_api::FlowEvent],
    source_span: Span,
    limit_span: Span,
    target_key: &str,
    conditional_depth: usize,
    out: &mut TargetWriteCleanliness,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_names,
                source_call_args,
                value_kind,
                ..
            } => {
                if span.file == source_span.file
                    && span.start > source_span.start
                    && span.end <= limit_span.start
                    && clean_overwrite_target_key(target).as_deref() == Some(target_key)
                {
                    if assignment_cleanly_overwrites_target(
                        policy,
                        *span,
                        source_name.as_deref(),
                        source_call.as_deref(),
                        source_names,
                        source_call_args,
                        *value_kind,
                    ) {
                        out.saw_clean = true;
                        if conditional_depth == 0 {
                            out.saw_unconditional_clean = true;
                        }
                    } else {
                        out.saw_dirty = true;
                    }
                }
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
                ..
            } => {
                if let Some(takes_then) = condition
                    .as_deref()
                    .and_then(|condition| static_numeric_condition_value(policy.ws, *span, condition))
                {
                    collect_target_write_cleanliness(
                        policy,
                        if takes_then { then_events } else { else_events },
                        source_span,
                        limit_span,
                        target_key,
                        conditional_depth + 1,
                        out,
                    );
                } else {
                    collect_target_write_cleanliness(
                        policy,
                        then_events,
                        source_span,
                        limit_span,
                        target_key,
                        conditional_depth + 1,
                        out,
                    );
                    collect_target_write_cleanliness(
                        policy,
                        else_events,
                        source_span,
                        limit_span,
                        target_key,
                        conditional_depth + 1,
                        out,
                    );
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_target_write_cleanliness(
                    policy,
                    body,
                    source_span,
                    limit_span,
                    target_key,
                    conditional_depth + 1,
                    out,
                );
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_target_write_cleanliness(
                    policy,
                    body,
                    source_span,
                    limit_span,
                    target_key,
                    conditional_depth,
                    out,
                );
                collect_target_write_cleanliness(
                    policy,
                    catch_events,
                    source_span,
                    limit_span,
                    target_key,
                    conditional_depth + 1,
                    out,
                );
                collect_target_write_cleanliness(
                    policy,
                    finally_events,
                    source_span,
                    limit_span,
                    target_key,
                    conditional_depth,
                    out,
                );
            }
            _ => {}
        }
    }
}

/// True when `target_key` is assigned again at a span strictly after
/// `after_span` and at/before the sink. A later write supersedes an
/// earlier clean overwrite of the same variable, so the earlier
/// overwrite is dead and must not be treated as the value that reaches
/// the sink. Recurses through control-flow regions so a conditional
/// re-taint (`v = ""; if c { v = user }; sink(v)`) is also seen as a
/// later write. Scans the whole function body, not just the current
/// statement list, because the later write may live in a nested arm.
fn target_written_between(
    events: &[bonsai_lang_api::FlowEvent],
    target_key: &str,
    after_span: Span,
    sink_span: Span,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    events.iter().any(|event| match event {
        FlowEvent::Assign { span, target, .. } => {
            span.file == after_span.file
                && span.start > after_span.start
                && span.end <= sink_span.start
                && clean_overwrite_target_key(target).as_deref() == Some(target_key)
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            target_written_between(then_events, target_key, after_span, sink_span)
                || target_written_between(else_events, target_key, after_span, sink_span)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            target_written_between(body, target_key, after_span, sink_span)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            target_written_between(body, target_key, after_span, sink_span)
                || target_written_between(catch_events, target_key, after_span, sink_span)
                || target_written_between(finally_events, target_key, after_span, sink_span)
        }
        _ => false,
    })
}

fn assignment_cleanly_overwrites_target(
    policy: CleanOverwritePolicy<'_>,
    span: Span,
    source_name: Option<&str>,
    source_call: Option<&str>,
    source_names: &[String],
    source_call_args: &[String],
    value_kind: Option<AssignValueKind>,
) -> bool {
    (source_call.is_none()
        && source_call_args.is_empty()
        && (value_kind
            .as_ref()
            .is_some_and(|kind| matches!(kind, AssignValueKind::Literal))
            || clean_constant_assignment(source_name, source_names)
            || assignment_rhs_is_clean_conditional(policy.ws, span)))
        || local_call_returns_clean_value(policy, span, source_call)
}

fn local_call_returns_clean_value(
    policy: CleanOverwritePolicy<'_>,
    call_span: Span,
    source_call: Option<&str>,
) -> bool {
    let Some(source_call) = source_call else {
        return false;
    };
    let callee_tail = clean_overwrite_callee_tail(source_call);
    if callee_tail.is_empty() {
        return false;
    }
    let Some(file_index) = policy.ws.exact_decl_index_shared(call_span.file) else {
        return false;
    };
    let candidates: Vec<_> = file_index
        .defs
        .iter()
        .filter(|decl| {
            clean_overwrite_callee_tail(&decl.name) == callee_tail
                && !(call_span.start >= decl.span.start && call_span.start < decl.span.end)
        })
        .collect();
    if candidates.len() != 1 {
        return false;
    }
    function_returns_clean_value(policy, candidates[0])
}

fn function_returns_clean_value(policy: CleanOverwritePolicy<'_>, decl: &bonsai_lang_api::Decl) -> bool {
    let mut returns = Vec::new();
    collect_return_values(&decl.flow_events, &mut returns);
    !returns.is_empty()
        && returns.iter().all(|(span, value_text, value_name)| {
            return_value_is_clean(policy, decl, *span, *value_text, *value_name)
        })
}

fn collect_return_values<'a>(
    events: &'a [bonsai_lang_api::FlowEvent],
    out: &mut Vec<(Span, Option<&'a str>, Option<&'a str>)>,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Return {
                span,
                value_text,
                value_name,
                ..
            } => out.push((*span, value_text.as_deref(), value_name.as_deref())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_values(then_events, out);
                collect_return_values(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_values(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_values(body, out);
                collect_return_values(catch_events, out);
                collect_return_values(finally_events, out);
            }
            _ => {}
        }
    }
}

fn return_value_is_clean(
    policy: CleanOverwritePolicy<'_>,
    decl: &bonsai_lang_api::Decl,
    return_span: Span,
    value_text: Option<&str>,
    value_name: Option<&str>,
) -> bool {
    if value_text.is_some_and(value_part_contains_only_clean_literals) {
        return true;
    }
    let Some(target) = value_name
        .and_then(clean_overwrite_target_key)
        .or_else(|| value_text.and_then(clean_overwrite_target_key))
    else {
        return false;
    };
    let entry_span = Span::empty(return_span.file, decl.span.start);
    clean_overwrite_between(
        policy,
        &decl.flow_events,
        &decl.flow_events,
        entry_span,
        return_span,
        std::slice::from_ref(&target),
        true,
    ) || target_only_has_clean_writes_between(policy, &decl.flow_events, entry_span, return_span, &target)
}

fn branch_arm_clean_overwrites_target(
    policy: CleanOverwritePolicy<'_>,
    events: &[bonsai_lang_api::FlowEvent],
    target: &str,
) -> bool {
    use bonsai_lang_api::FlowEvent;
    events.iter().any(|event| match event {
        FlowEvent::Assign {
            span,
            target: assigned,
            source_name,
            source_call,
            source_names,
            source_call_args,
            value_kind,
            ..
        } => {
            clean_overwrite_target_key(assigned).as_deref() == Some(target)
                && assignment_cleanly_overwrites_target(
                    policy,
                    *span,
                    source_name.as_deref(),
                    source_call.as_deref(),
                    source_names,
                    source_call_args,
                    *value_kind,
                )
        }
        FlowEvent::Branch {
            span,
            condition,
            then_events,
            else_events,
            ..
        } => {
            if let Some(takes_then) = condition
                .as_deref()
                .and_then(|condition| static_numeric_condition_value(policy.ws, *span, condition))
            {
                if takes_then {
                    branch_arm_clean_overwrites_target(policy, then_events, target)
                } else {
                    branch_arm_clean_overwrites_target(policy, else_events, target)
                }
            } else {
                !else_events.is_empty()
                    && branch_arm_clean_overwrites_target(policy, then_events, target)
                    && branch_arm_clean_overwrites_target(policy, else_events, target)
            }
        }
        FlowEvent::Call { name, args, .. } => {
            clean_output_call_overwrites_target(policy.clean_output_overwrites, name, args, target)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            branch_arm_clean_overwrites_target(policy, body, target)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => try_region_clean_overwrites_target(policy, body, catch_events, finally_events, target),
        _ => false,
    })
}

pub(super) fn try_region_clean_overwrites_target(
    policy: CleanOverwritePolicy<'_>,
    body: &[bonsai_lang_api::FlowEvent],
    catch_events: &[bonsai_lang_api::FlowEvent],
    finally_events: &[bonsai_lang_api::FlowEvent],
    target: &str,
) -> bool {
    branch_arm_clean_overwrites_target(policy, finally_events, target)
        || (branch_arm_clean_overwrites_target(policy, body, target)
            && (catch_events.is_empty() || branch_arm_clean_overwrites_target(policy, catch_events, target)))
}

pub(super) fn clean_output_call_overwrites_target(
    clean_output_overwrites: &[CleanOutputOverwrite],
    name: &str,
    args: &[bonsai_lang_api::CallArg],
    target: &str,
) -> bool {
    clean_output_overwrites.iter().any(|shape| {
        if !configured_clean_output_name_matches(&shape.callee, name) {
            return false;
        }
        let Some(output) = args.get(shape.output_arg_index) else {
            return false;
        };
        if clean_overwrite_target_key(&output.value_text).as_deref() != Some(target) {
            return false;
        }
        let Some(value_args) = args.get(shape.value_start_arg_index..) else {
            return false;
        };
        !value_args.is_empty()
            && value_args
                .iter()
                .all(|arg| clean_output_overwrite_arg_is_clean(arg, target))
    })
}

fn configured_clean_output_name_matches(configured: &str, observed: &str) -> bool {
    if let Some(regex) = configured.trim().strip_prefix("regex:") {
        return regex::Regex::new(regex)
            .ok()
            .is_some_and(|matcher| matcher.is_match(observed.trim()));
    }
    let configured = configured
        .trim()
        .replace("::", ".")
        .replace("->", ".")
        .replace(':', ".");
    let observed = observed
        .trim()
        .replace("::", ".")
        .replace("->", ".")
        .replace(':', ".");
    !configured.is_empty()
        && !observed.is_empty()
        && (configured == observed
            || observed.rsplit('.').find(|part| !part.is_empty()) == Some(configured.as_str()))
}

pub(super) fn clean_overwrite_callee_tail(name: &str) -> String {
    name.rsplit(['.', ':'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or(name)
        .trim()
        .to_ascii_lowercase()
}

fn clean_output_overwrite_arg_is_clean(arg: &bonsai_lang_api::CallArg, target: &str) -> bool {
    if arg
        .place
        .as_deref()
        .and_then(clean_overwrite_target_key)
        .as_deref()
        == Some(target)
        || arg.source_names.iter().any(|source| {
            clean_overwrite_target_key(source).as_deref() == Some(target)
                || !looks_like_clean_constant(source)
        })
    {
        return false;
    }
    let trimmed = arg.value_text.trim();
    if trimmed.is_empty() {
        return true;
    }
    if quoted_literal(trimmed) || numeric_literal(trimmed) {
        return true;
    }
    clean_overwrite_target_key(trimmed).as_deref() != Some(target) && looks_like_clean_constant(trimmed)
}

pub(super) fn quoted_literal(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
}

pub(super) fn numeric_literal(value: &str) -> bool {
    let trimmed = value.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '_' | 'x' | 'X' | 'a'..='f' | 'A'..='F'))
        && trimmed.chars().any(|ch| ch.is_ascii_digit())
}

fn clean_constant_assignment(source_name: Option<&str>, source_names: &[String]) -> bool {
    source_name
        .into_iter()
        .chain(source_names.iter().map(String::as_str))
        .all(looks_like_clean_constant)
        && (source_name.is_some() || !source_names.is_empty())
}

fn assignment_rhs_is_clean_conditional(ws: &Workspace, span: Span) -> bool {
    let Some(rhs) = assignment_rhs_syntax_text(ws, span) else {
        return false;
    };
    if clean_conditional_value_part(&rhs).is_some_and(value_part_contains_only_clean_literals) {
        return true;
    }
    if let Some((then_value, condition, else_value)) = split_python_conditional_parts(&rhs) {
        return python_membership_allowlist_condition_cleans_value(condition, then_value)
            && value_part_contains_only_clean_literals(else_value);
    }
    let Some((condition, then_value, else_value)) = split_ternary_parts(&rhs) else {
        return false;
    };
    match static_numeric_condition_value(ws, span, condition) {
        Some(true) => value_part_contains_only_clean_literals(then_value),
        Some(false) => value_part_contains_only_clean_literals(else_value),
        None => false,
    }
}

fn assignment_rhs_syntax_text(ws: &Workspace, span: Span) -> Option<String> {
    let file_index = ws.db().decl_index(span.file)?;
    let snapshot = ws.vfs().snapshot(span.file).ok()?;
    bonsai_lang_api::assignment_value_rendering(&file_index.assignment_values, span, snapshot.text.as_ref())
        .map(|rhs| rhs.trim_end_matches(';').trim().to_string())
}

fn split_ternary_parts(rhs: &str) -> Option<(&str, &str, &str)> {
    let trimmed = rhs.trim();
    let question = find_top_level_char(trimmed, '?')?;
    let colon = find_top_level_char(&trimmed[question + 1..], ':')? + question + 1;
    Some((
        trimmed[..question].trim(),
        trimmed[question + 1..colon].trim(),
        trimmed[colon + 1..].trim(),
    ))
}

fn split_python_conditional_parts(rhs: &str) -> Option<(&str, &str, &str)> {
    let trimmed = rhs.trim();
    let if_idx = find_top_level_keyword(trimmed, "if")?;
    let else_idx = find_top_level_keyword(&trimmed[if_idx + 2..], "else")? + if_idx + 2;
    let then_value = trimmed[..if_idx].trim();
    let condition = trimmed[if_idx + 2..else_idx].trim();
    let else_value = trimmed[else_idx + 4..].trim();
    (!then_value.is_empty() && !condition.is_empty() && !else_value.is_empty())
        .then_some((then_value, condition, else_value))
}

fn python_membership_allowlist_condition_cleans_value(condition: &str, then_value: &str) -> bool {
    let Some(target) = clean_overwrite_target_key(then_value) else {
        return false;
    };
    let condition = strip_balanced_outer_parens(condition);
    if find_top_level_keyword(condition, "not").is_some() {
        return false;
    }
    let Some(in_idx) = find_top_level_keyword(condition, "in") else {
        return false;
    };
    let left = condition[..in_idx].trim();
    let right = condition[in_idx + 2..].trim();
    clean_overwrite_target_key(left).as_deref() == Some(target.as_str())
        && value_part_contains_only_clean_literals(right)
}

fn find_top_level_keyword(text: &str, keyword: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut idx = 0usize;
    while idx < text.len() {
        let ch = text[idx..].chars().next()?;
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            idx += ch.len_utf8();
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && text[idx..].starts_with(keyword) && keyword_has_boundary(text, idx, keyword.len()) {
            return Some(idx);
        }
        idx += ch.len_utf8();
    }
    None
}

fn keyword_has_boundary(text: &str, start: usize, len: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[start + len..].chars().next();
    !before.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        && !after.is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn find_top_level_char(text: &str, needle: char) -> Option<usize> {
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(active) = quote {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == active {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '(' | '[' | '{' => depth = depth.saturating_add(1),
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            _ if ch == needle && depth == 0 => return Some(idx),
            _ => {}
        }
    }
    None
}

fn static_numeric_condition_value(ws: &Workspace, span: Span, condition: &str) -> Option<bool> {
    let vars = numeric_constant_assignments_before_span(ws, span);
    eval_numeric_condition(condition, &vars)
}

fn numeric_constant_assignments_before_span(ws: &Workspace, span: Span) -> AHashMap<String, i64> {
    let Some(file_index) = ws.db().decl_index(span.file) else {
        return AHashMap::new();
    };
    let Ok(snapshot) = ws.vfs().snapshot(span.file) else {
        return AHashMap::new();
    };
    let Some(decl) = file_index
        .defs
        .iter()
        .filter(|decl| span_contains(decl.body_span.unwrap_or(decl.span), span))
        .min_by_key(|decl| decl.span.len())
    else {
        return AHashMap::new();
    };
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let mut constants = AHashMap::new();
    constants_before_span_in_events(
        &decl.flow_events,
        span,
        &assignment_values,
        snapshot.text.as_ref(),
        &mut constants,
    );
    constants
}

/// Execute the compiler-owned flow tree until `target_span`, retaining only
/// integer constants that are identical on every path which can reach it.
/// This is intentionally uncapped: scale comes from one linear walk over the
/// enclosing declaration, not from dropping syntax beyond a byte budget.
fn constants_before_span_in_events(
    events: &[FlowEvent],
    target_span: Span,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
    constants: &mut AHashMap<String, i64>,
) -> bool {
    for event in events {
        let event_span = event.span();
        if event_span == target_span {
            return true;
        }
        if span_contains(event_span, target_span) {
            return constants_before_nested_span(
                event,
                target_span,
                assignment_values,
                source_text,
                constants,
            );
        }
        if event_span.file == target_span.file && event_span.end <= target_span.start {
            apply_constant_event(event, assignment_values, source_text, constants);
        }
    }
    false
}

fn constants_before_nested_span(
    event: &FlowEvent,
    target_span: Span,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
    constants: &mut AHashMap<String, i64>,
) -> bool {
    match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => nested_constants_from_one_of(
            [then_events.as_slice(), else_events.as_slice()],
            target_span,
            assignment_values,
            source_text,
            constants,
        ),
        FlowEvent::Loop { body, .. } => {
            // A target inside a loop may be reached after earlier iterations.
            // Invalidate anything the loop can write before following the
            // target's exact syntactic arm.
            invalidate_written_constants(body, constants);
            constants_before_span_in_events(body, target_span, assignment_values, source_text, constants)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            if events_contain_span(body, target_span) {
                constants_before_span_in_events(body, target_span, assignment_values, source_text, constants)
            } else if events_contain_span(catch_events, target_span) {
                invalidate_written_constants(body, constants);
                constants_before_span_in_events(
                    catch_events,
                    target_span,
                    assignment_values,
                    source_text,
                    constants,
                )
            } else {
                let mut body_state = constants.clone();
                apply_constant_events(body, assignment_values, source_text, &mut body_state);
                let mut catch_state = constants.clone();
                apply_constant_events(catch_events, assignment_values, source_text, &mut catch_state);
                *constants = merge_constant_states([constants.clone(), body_state, catch_state]);
                constants_before_span_in_events(
                    finally_events,
                    target_span,
                    assignment_values,
                    source_text,
                    constants,
                )
            }
        }
        FlowEvent::Defer { body, .. } => {
            // Deferred code executes at scope exit, after arbitrary writes
            // between its declaration and execution. Do not carry a lexical
            // constant state into that later control-flow region.
            constants.clear();
            constants_before_span_in_events(body, target_span, assignment_values, source_text, constants)
        }
        FlowEvent::Using { body, .. } => {
            constants_before_span_in_events(body, target_span, assignment_values, source_text, constants)
        }
        _ => false,
    }
}

fn nested_constants_from_one_of<'a>(
    candidates: impl IntoIterator<Item = &'a [FlowEvent]>,
    target_span: Span,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
    constants: &mut AHashMap<String, i64>,
) -> bool {
    for events in candidates {
        if events_contain_span(events, target_span) {
            return constants_before_span_in_events(
                events,
                target_span,
                assignment_values,
                source_text,
                constants,
            );
        }
    }
    false
}

fn events_contain_span(events: &[FlowEvent], target_span: Span) -> bool {
    events
        .iter()
        .any(|event| event.span() == target_span || span_contains(event.span(), target_span))
}

fn apply_constant_events(
    events: &[FlowEvent],
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
    constants: &mut AHashMap<String, i64>,
) {
    for event in events {
        apply_constant_event(event, assignment_values, source_text, constants);
    }
}

fn apply_constant_event(
    event: &FlowEvent,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
    constants: &mut AHashMap<String, i64>,
) {
    match event {
        FlowEvent::Assign {
            span,
            target,
            value_kind,
            ..
        } => {
            let Some(target) = clean_overwrite_target_key(target) else {
                return;
            };
            let value = value_kind
                .is_some_and(|kind| kind == AssignValueKind::Literal)
                .then(|| assignment_values.rendering(*span, source_text))
                .flatten()
                .and_then(parse_static_integer_literal);
            if let Some(value) = value {
                constants.insert(target, value);
            } else {
                constants.remove(&target);
            }
        }
        FlowEvent::AggregateAssign { target, .. } => {
            if let Some(target) = clean_overwrite_target_key(target) {
                constants.remove(&target);
            }
        }
        FlowEvent::Call { args, .. } => {
            for arg in args {
                if arg.passing_mode != bonsai_lang_api::ArgumentPassingMode::WriteBack {
                    continue;
                }
                if let Some(target) = arg.place.as_deref().and_then(clean_overwrite_target_key) {
                    constants.remove(&target);
                }
            }
        }
        FlowEvent::Branch {
            condition,
            then_events,
            else_events,
            ..
        } => {
            if let Some(takes_then) = condition
                .as_deref()
                .and_then(|condition| eval_numeric_condition(condition, constants))
            {
                apply_constant_events(
                    if takes_then { then_events } else { else_events },
                    assignment_values,
                    source_text,
                    constants,
                );
                return;
            }
            let mut then_state = constants.clone();
            apply_constant_events(then_events, assignment_values, source_text, &mut then_state);
            let mut else_state = constants.clone();
            apply_constant_events(else_events, assignment_values, source_text, &mut else_state);
            *constants = merge_constant_states([then_state, else_state]);
        }
        FlowEvent::Loop { body, .. } => {
            let before = constants.clone();
            let mut after_iteration = before.clone();
            apply_constant_events(body, assignment_values, source_text, &mut after_iteration);
            *constants = merge_constant_states([before, after_iteration]);
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            let before = constants.clone();
            let mut body_state = before.clone();
            apply_constant_events(body, assignment_values, source_text, &mut body_state);
            let mut catch_state = before.clone();
            apply_constant_events(catch_events, assignment_values, source_text, &mut catch_state);
            *constants = merge_constant_states([before, body_state, catch_state]);
            apply_constant_events(finally_events, assignment_values, source_text, constants);
        }
        FlowEvent::Using { body, .. } => {
            apply_constant_events(body, assignment_values, source_text, constants);
        }
        FlowEvent::Defer { .. }
        | FlowEvent::Return { .. }
        | FlowEvent::Throw { .. }
        | FlowEvent::Break { .. }
        | FlowEvent::Continue { .. }
        | FlowEvent::Yield { .. }
        | FlowEvent::Await { .. }
        | FlowEvent::Lifecycle { .. } => {}
    }
}

fn invalidate_written_constants(events: &[FlowEvent], constants: &mut AHashMap<String, i64>) {
    for event in events {
        match event {
            FlowEvent::Assign { target, .. } | FlowEvent::AggregateAssign { target, .. } => {
                if let Some(target) = clean_overwrite_target_key(target) {
                    constants.remove(&target);
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                invalidate_written_constants(then_events, constants);
                invalidate_written_constants(else_events, constants);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                invalidate_written_constants(body, constants);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                invalidate_written_constants(body, constants);
                invalidate_written_constants(catch_events, constants);
                invalidate_written_constants(finally_events, constants);
            }
            FlowEvent::Call { args, .. } => {
                for arg in args {
                    if arg.passing_mode == bonsai_lang_api::ArgumentPassingMode::WriteBack {
                        if let Some(target) = arg.place.as_deref().and_then(clean_overwrite_target_key) {
                            constants.remove(&target);
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn merge_constant_states<const N: usize>(states: [AHashMap<String, i64>; N]) -> AHashMap<String, i64> {
    let Some(first) = states.first() else {
        return AHashMap::new();
    };
    first
        .iter()
        .filter(|(name, value)| {
            states
                .iter()
                .skip(1)
                .all(|state| state.get(*name) == Some(*value))
        })
        .map(|(name, value)| (name.clone(), *value))
        .collect()
}

fn parse_static_integer_literal(text: &str) -> Option<i64> {
    let compact: String = text.trim().chars().filter(|ch| *ch != '_').collect();
    compact.parse().ok()
}

fn eval_numeric_condition(condition: &str, vars: &AHashMap<String, i64>) -> Option<bool> {
    let condition = strip_balanced_outer_parens(condition.trim());
    for op in [">=", "<=", "==", "!=", ">", "<"] {
        if let Some(idx) = find_top_level_operator(condition, op) {
            let left = eval_int_expr(&condition[..idx], vars)?;
            let right = eval_int_expr(&condition[idx + op.len()..], vars)?;
            return Some(match op {
                ">=" => left >= right,
                "<=" => left <= right,
                "==" => left == right,
                "!=" => left != right,
                ">" => left > right,
                "<" => left < right,
                _ => return None,
            });
        }
    }
    None
}

fn find_top_level_operator(text: &str, op: &str) -> Option<usize> {
    let bytes = text.as_bytes();
    let op_bytes = op.as_bytes();
    let mut depth = 0usize;
    let mut idx = 0usize;
    while idx + op_bytes.len() <= bytes.len() {
        match bytes[idx] {
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && &bytes[idx..idx + op_bytes.len()] == op_bytes {
            return Some(idx);
        }
        idx += 1;
    }
    None
}

fn eval_int_expr(expr: &str, vars: &AHashMap<String, i64>) -> Option<i64> {
    let mut parser = IntExprParser::new(expr, vars);
    let value = parser.parse_expr()?;
    parser.skip_ws();
    (parser.peek().is_none()).then_some(value)
}

struct IntExprParser<'a> {
    input: &'a str,
    pos: usize,
    vars: &'a AHashMap<String, i64>,
}

impl<'a> IntExprParser<'a> {
    fn new(input: &'a str, vars: &'a AHashMap<String, i64>) -> Self {
        Self { input, pos: 0, vars }
    }

    fn parse_expr(&mut self) -> Option<i64> {
        let mut value = self.parse_term()?;
        loop {
            self.skip_ws();
            if self.consume('+') {
                value = value.checked_add(self.parse_term()?)?;
            } else if self.consume('-') {
                value = value.checked_sub(self.parse_term()?)?;
            } else {
                return Some(value);
            }
        }
    }

    fn parse_term(&mut self) -> Option<i64> {
        let mut value = self.parse_factor()?;
        loop {
            self.skip_ws();
            if self.consume('*') {
                value = value.checked_mul(self.parse_factor()?)?;
            } else if self.consume('/') {
                let divisor = self.parse_factor()?;
                if divisor == 0 {
                    return None;
                }
                value = value.checked_div(divisor)?;
            } else {
                return Some(value);
            }
        }
    }

    fn parse_factor(&mut self) -> Option<i64> {
        self.skip_ws();
        if self.consume('(') {
            let value = self.parse_expr()?;
            self.skip_ws();
            return self.consume(')').then_some(value);
        }
        if self.consume('-') {
            return self.parse_factor()?.checked_neg();
        }
        if self.peek()?.is_ascii_digit() {
            return self.parse_number();
        }
        self.parse_identifier()
            .and_then(|name| self.vars.get(name).copied())
    }

    fn parse_number(&mut self) -> Option<i64> {
        let start = self.pos;
        while self.peek().is_some_and(|ch| ch.is_ascii_digit() || ch == '_') {
            self.pos += self.peek()?.len_utf8();
        }
        self.input[start..self.pos].replace('_', "").parse().ok()
    }

    fn parse_identifier(&mut self) -> Option<&'a str> {
        let start = self.pos;
        let first = self.peek()?;
        if !(first == '_' || first.is_ascii_alphabetic()) {
            return None;
        }
        self.pos += first.len_utf8();
        while self
            .peek()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            self.pos += self.peek()?.len_utf8();
        }
        Some(&self.input[start..self.pos])
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.pos += self.peek().map(char::len_utf8).unwrap_or(1);
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.pos += expected.len_utf8();
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }
}

fn strip_balanced_outer_parens(mut text: &str) -> &str {
    loop {
        let trimmed = text.trim();
        if !(trimmed.starts_with('(') && trimmed.ends_with(')')) {
            return trimmed;
        }
        let mut depth = 0isize;
        let mut wraps = true;
        for (idx, ch) in trimmed.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 && idx + ch.len_utf8() < trimmed.len() {
                        wraps = false;
                        break;
                    }
                }
                _ => {}
            }
        }
        if wraps {
            text = &trimmed[1..trimmed.len() - 1];
        } else {
            return trimmed;
        }
    }
}

pub(super) fn clean_conditional_value_part(rhs: &str) -> Option<&str> {
    let trimmed = rhs.trim();
    if let Some(question) = trimmed.find('?') {
        if trimmed[question + 1..].contains(':') {
            return Some(&trimmed[question + 1..]);
        }
    }
    if trimmed.starts_with("if ") || trimmed.starts_with("if(") || trimmed.starts_with("if (") {
        if let Some(first_value_block) = trimmed.find('{') {
            return Some(&trimmed[first_value_block..]);
        }
        if let Some(else_idx) = trimmed.find(" else ") {
            return Some(&trimmed[else_idx..]);
        }
    }
    None
}

pub(super) fn value_part_contains_only_clean_literals(value_part: &str) -> bool {
    if !value_part.contains('"') && !value_part.contains('\'') && !value_part.contains('`') {
        return false;
    }
    identifier_tokens_outside_strings(value_part)
        .into_iter()
        .all(|token| clean_conditional_helper_identifier(&token))
}

pub(super) fn clean_conditional_helper_identifier(token: &str) -> bool {
    matches!(
        token,
        "if" | "else"
            | "true"
            | "false"
            | "nil"
            | "null"
            | "None"
            | "none"
            | "to_string"
            | "toString"
            | "to_s"
            | "String"
            | "string"
    )
}

pub(super) fn looks_like_clean_constant(text: &str) -> bool {
    let trimmed = text.trim();
    !trimmed.is_empty()
        && trimmed
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
        && trimmed.chars().any(|ch| ch.is_ascii_uppercase())
}

pub(super) fn clean_overwrite_target_key(text: &str) -> Option<String> {
    let trimmed = text
        .trim()
        .trim_start_matches(&['$', '@', '%', '&', '*'][..])
        .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
    if trimmed.is_empty()
        || trimmed.contains(' ')
        || trimmed.contains('.')
        || trimmed.contains("::")
        || trimmed.contains('(')
        || trimmed.contains('[')
    {
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod numeric_constant_tests {
    use super::*;
    use bonsai_lang_api::{AssignmentValueFact, LoopKind};

    fn span(file: FileId, start: usize, end: usize) -> Span {
        Span::new(file, start as u64, end as u64)
    }

    fn literal_assign(assignment_span: Span, target: &str) -> FlowEvent {
        FlowEvent::Assign {
            span: assignment_span,
            target: target.to_string(),
            source_name: None,
            source_call: None,
            source_call_args: Vec::new(),
            source_names: Vec::new(),
            declares_new_binding: true,
            value_kind: Some(AssignValueKind::Literal),
        }
    }

    fn assignment_fact(assignment_span: Span, target_span: Span, value_span: Span) -> AssignmentValueFact {
        AssignmentValueFact {
            assignment_span,
            target: None,
            target_is_immutable: false,
            target_owner: None,
            target_span: Some(target_span),
            value_span,
            call_sites: Vec::new(),
            value_flow: Default::default(),
            exact_callable_return: None,
            exact_static_call_args: None,
            direct_call_name: None,
            direct_call_receiver: None,
        }
    }

    #[test]
    fn constant_lookup_is_uncapped_and_uses_exact_rhs_fact() {
        let file = FileId::new(0);
        let assignment = "let threshold = 7;";
        let padding = "\n".repeat(8_192);
        let branch = "if threshold > 5 {}";
        let source = format!("{assignment}{padding}{branch}");
        let assignment_span = span(file, 0, assignment.len());
        let target_start = assignment.find("threshold").unwrap();
        let value_start = assignment.find('7').unwrap();
        let target_span = span(file, target_start, target_start + "threshold".len());
        let value_span = span(file, value_start, value_start + 1);
        let branch_start = assignment.len() + padding.len();
        let branch_span = span(file, branch_start, source.len());
        let facts = [assignment_fact(assignment_span, target_span, value_span)];
        let values = bonsai_lang_api::AssignmentValueIndex::new(&facts);
        let events = [
            literal_assign(assignment_span, "threshold"),
            FlowEvent::Branch {
                span: branch_span,
                condition: Some("threshold > 5".to_string()),
                then_events: Vec::new(),
                else_events: Vec::new(),
            },
        ];
        let mut constants = AHashMap::new();

        assert!(constants_before_span_in_events(
            &events,
            branch_span,
            &values,
            &source,
            &mut constants,
        ));
        assert_eq!(constants.get("threshold"), Some(&7));
    }

    #[test]
    fn conditional_write_does_not_become_an_unconditional_constant() {
        let file = FileId::new(0);
        let source = "x = 7;if unknown { x = 8; }if x > 5 {}";
        let first_start = source.find("x = 7").unwrap();
        let conditional_start = source.find("if unknown").unwrap();
        let nested_start = source.find("x = 8").unwrap();
        let target_start = source.find("if x > 5").unwrap();
        let first_span = span(file, first_start, first_start + "x = 7".len());
        let nested_span = span(file, nested_start, nested_start + "x = 8".len());
        let conditional_span = span(file, conditional_start, target_start);
        let target_span = span(file, target_start, source.len());
        let facts = [
            assignment_fact(
                first_span,
                span(file, first_start, first_start + 1),
                span(file, first_start + 4, first_start + 5),
            ),
            assignment_fact(
                nested_span,
                span(file, nested_start, nested_start + 1),
                span(file, nested_start + 4, nested_start + 5),
            ),
        ];
        let values = bonsai_lang_api::AssignmentValueIndex::new(&facts);
        let events = [
            literal_assign(first_span, "x"),
            FlowEvent::Branch {
                span: conditional_span,
                condition: Some("unknown".to_string()),
                then_events: vec![literal_assign(nested_span, "x")],
                else_events: Vec::new(),
            },
            FlowEvent::Branch {
                span: target_span,
                condition: Some("x > 5".to_string()),
                then_events: Vec::new(),
                else_events: Vec::new(),
            },
        ];
        let mut constants = AHashMap::new();

        assert!(constants_before_span_in_events(
            &events,
            target_span,
            &values,
            source,
            &mut constants,
        ));
        assert!(!constants.contains_key("x"));
    }

    #[test]
    fn loop_write_invalidates_a_constant_even_when_the_loop_may_not_run() {
        let file = FileId::new(0);
        let source = "x = 7;while unknown { x = 8; }if x > 5 {}";
        let first_start = source.find("x = 7").unwrap();
        let loop_start = source.find("while unknown").unwrap();
        let nested_start = source.find("x = 8").unwrap();
        let target_start = source.find("if x > 5").unwrap();
        let first_span = span(file, first_start, first_start + "x = 7".len());
        let nested_span = span(file, nested_start, nested_start + "x = 8".len());
        let target_span = span(file, target_start, source.len());
        let facts = [
            assignment_fact(
                first_span,
                span(file, first_start, first_start + 1),
                span(file, first_start + 4, first_start + 5),
            ),
            assignment_fact(
                nested_span,
                span(file, nested_start, nested_start + 1),
                span(file, nested_start + 4, nested_start + 5),
            ),
        ];
        let values = bonsai_lang_api::AssignmentValueIndex::new(&facts);
        let events = [
            literal_assign(first_span, "x"),
            FlowEvent::Loop {
                span: span(file, loop_start, target_start),
                loop_kind: LoopKind::While,
                body: vec![literal_assign(nested_span, "x")],
            },
            FlowEvent::Branch {
                span: target_span,
                condition: Some("x > 5".to_string()),
                then_events: Vec::new(),
                else_events: Vec::new(),
            },
        ];
        let mut constants = AHashMap::new();

        assert!(constants_before_span_in_events(
            &events,
            target_span,
            &values,
            source,
            &mut constants,
        ));
        assert!(!constants.contains_key("x"));
    }
}
