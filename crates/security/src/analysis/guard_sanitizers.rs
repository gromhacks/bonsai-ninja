//! Inline guard / helper-shape sanitizer recognizers.
//!
//! `make_finding` consults these to decide whether a tainted flow is
//! neutralized by a recognizable code shape the rulepack cannot express
//! as a sanitizer rule: dev-only environment guards, URL/SSRF host
//! guards, local escape-helper wrappers, hardened XML factories,
//! char-allowlist append loops, literal-map lookups, and the like.
//! Also owns the low-signal source/sink pairing demotion and the
//! template-interpolation scanner these recognizers share.

#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn source_sink_pair_is_low_signal(source: &FindingMatch, sink_rule: &Rule) -> bool {
    // Inferred entry parameters are untrusted inputs, not confidential
    // values. A precise flow from such an input to an event/log/response
    // can be useful lineage, but it is not evidence of information
    // exposure. Concrete secret/identity source rules remain eligible.
    if sink_rule.tag.as_deref() == Some("information-exposure")
        && source.category.as_deref() == Some("inferred")
    {
        return true;
    }
    if sink_rule.tag.as_deref() != Some("log-injection") || source.trust.as_deref() != Some("local") {
        return false;
    }
    let token = format!(
        "{} {} {}",
        source.rule_id,
        source.text,
        source.category.as_deref().unwrap_or("")
    )
    .to_ascii_lowercase();
    token.contains("getenv") || token.contains("environ")
}

pub(super) fn dev_only_environment_guard_sanitizer(ws: &Workspace, hit: &RuleMatch) -> Option<FindingMatch> {
    if !matches!(hit.language.as_str(), "javascript" | "typescript" | "python") {
        return None;
    }
    let snapshot = ws.vfs().snapshot(hit.span.file).ok()?;
    let entry = ws
        .enclosing_index()
        .enclosing_for(ws.db(), hit.span.file, hit.span.start)?;
    let global = ws.db().global_index();
    let decl = global.decl_of(entry.symbol)?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, hit.span, &mut branches);
    let guard = branches.into_iter().rev().find(|branch| {
        let condition_matches = if hit.language == "python" {
            python_dev_only_env_guard_condition(branch.condition)
        } else {
            js_dev_only_env_guard_condition(branch.condition)
        };
        condition_matches && branch_arm_abruptly_exits(branch.then_events)
    })?;
    finding_for_guard_span(
        hit,
        snapshot.text.as_ref(),
        guard.span,
        "engine.sanitizer.dev_only_env_guard",
        "dev-only-guard",
        "reachability-guard",
    )
}

fn js_dev_only_env_guard_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    let lower = compact.to_ascii_lowercase();
    let reads_node_env = lower.contains("process.env.node_env") || lower.contains("node_env");
    if !reads_node_env || !(compact.contains("!==") || compact.contains("!=")) {
        return false;
    }
    let mentions_dev_env = ["dev", "debug", "test", "local", "internal"]
        .iter()
        .any(|marker| lower.contains(marker));
    mentions_dev_env
}

pub(super) fn python_realpath_containment_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("path-traversal") {
        return None;
    }
    let (candidate, base) = python_realpath_join_target_and_base(ws, sink_func, snk.span)?;
    if sink_tainted_args
        .iter()
        .any(|arg| clean_overwrite_target_key(&arg.value_text).as_deref() == Some(base.as_str()))
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let mut branches = Vec::new();
    collect_following_branches_on_path(&decl.flow_events, snk.span, &mut branches);
    for branch in branches {
        if !python_path_containment_guard_condition(branch.condition, &candidate, &base) {
            continue;
        }
        if !branch_arm_abruptly_exits(branch.then_events) {
            continue;
        }
        return finding_for_guard_span(
            snk,
            snapshot.text.as_ref(),
            branch.span,
            "engine.sanitizer.python_realpath_containment_guard",
            "path-sanitize",
            "realpath-containment-guard",
        );
    }
    None
}

pub(super) fn python_compiled_regex_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("path-traversal") {
        return None;
    }
    if !sanitizer_credits_sink_tag(Some("regex-validate"), sink_rule.tag.as_deref()) {
        return None;
    }
    let mut targets: Vec<String> = sink_tainted_args
        .iter()
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .filter(|target| !clean_conditional_helper_identifier(target) && !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let mut branches = Vec::new();
    collect_completed_branches_on_path(&decl.flow_events, snk.span, &mut branches);
    for branch in branches.into_iter().rev() {
        let Some((regex_name, guarded_target)) =
            python_compiled_regex_guard_condition(branch.condition, &targets)
        else {
            continue;
        };
        if !python_compiled_regex_declared_safe_before(
            ws,
            snk.span.file,
            branch.span,
            &regex_name,
            sink_rule.tag.as_deref(),
        ) {
            continue;
        }
        if !branch_arm_abruptly_exits(branch.then_events) {
            continue;
        }
        return finding_for_guard_span(
            snk,
            snapshot.text.as_ref(),
            branch.span,
            "engine.sanitizer.python_compiled_regex_guard",
            "regex-validate",
            &format!("compiled-regex-guard:{guarded_target}"),
        );
    }
    None
}

fn python_compiled_regex_guard_condition(condition: &str, targets: &[String]) -> Option<(String, String)> {
    let compact = compact_guard_text(condition);
    let call_text = compact
        .strip_prefix("not")
        .or_else(|| compact.strip_suffix("isNone"))
        .or_else(|| compact.strip_suffix("==None"))?;
    let (regex_name, arg) = python_compiled_regex_call_parts(call_text)?;
    let target = clean_overwrite_target_key(arg)?;
    targets
        .iter()
        .any(|candidate| candidate == &target)
        .then_some((regex_name, target))
}

fn python_compiled_regex_call_parts(call_text: &str) -> Option<(String, &str)> {
    for marker in [".fullmatch(", ".match("] {
        let Some(marker_idx) = call_text.find(marker) else {
            continue;
        };
        let receiver = call_text[..marker_idx].trim();
        if !python_identifier_path_like(receiver) {
            continue;
        }
        let args_start = marker_idx + marker.len();
        let args = call_text.get(args_start..call_text.rfind(')')?)?;
        let first_arg = args.split(',').next()?.trim();
        if first_arg.is_empty() {
            continue;
        }
        return Some((receiver.to_string(), first_arg));
    }
    None
}

fn python_compiled_regex_declared_safe_before(
    ws: &Workspace,
    file: FileId,
    guard_span: Span,
    regex_name: &str,
    sink_tag: Option<&str>,
) -> bool {
    let Some(file_index) = ws.db().decl_index(file) else {
        return false;
    };
    let mut assignments = Vec::new();
    for decl in &file_index.defs {
        collect_structured_assignments_before(&decl.flow_events, guard_span, &mut assignments);
    }
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.dedup_by_key(|assignment| assignment.span);
    for assignment in assignments.into_iter().rev() {
        if clean_overwrite_target_key(assignment.target).as_deref() != Some(regex_name) {
            continue;
        }
        if assignment
            .source_call
            .is_none_or(|call| clean_overwrite_callee_tail(call) != "compile")
        {
            continue;
        }
        let Some(pattern) = assignment
            .source_call_args
            .first()
            .and_then(|argument| python_first_string_literal(argument))
        else {
            return false;
        };
        return python_regex_pattern_safe_for_sink(&pattern, sink_tag);
    }
    false
}

fn python_first_string_literal(args: &str) -> Option<String> {
    let mut s = args.trim_start();
    while let Some(first) = s.chars().next() {
        match first {
            'r' | 'R' | 'u' | 'U' | 'b' | 'B' => s = &s[first.len_utf8()..],
            'f' | 'F' => return None,
            _ => break,
        }
    }
    let quote = s.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    let mut escaped = false;
    for ch in s[quote.len_utf8()..].chars() {
        if escaped {
            out.push('\\');
            out.push(ch);
            escaped = false;
            continue;
        }
        if ch == '\\' {
            escaped = true;
            continue;
        }
        if ch == quote {
            return Some(out);
        }
        out.push(ch);
    }
    None
}

fn python_regex_pattern_safe_for_sink(pattern: &str, sink_tag: Option<&str>) -> bool {
    if sink_tag != Some("path-traversal") {
        return false;
    }
    let p = pattern.trim();
    if !p.starts_with('^') || !p.ends_with('$') {
        return false;
    }
    if p.contains("[^")
        || p.contains(".*")
        || p.contains(".+")
        || p.contains("(?")
        || p.contains('/')
        || p.contains("\\\\")
    {
        return false;
    }
    if python_regex_has_unescaped_wildcard_dot(p) {
        return false;
    }
    p.contains('[')
        && p.contains(']')
        && (p.contains("A-Z") || p.contains("a-z") || p.contains("0-9") || p.contains("\\d"))
}

fn python_regex_has_unescaped_wildcard_dot(pattern: &str) -> bool {
    let mut in_class = false;
    let mut escaped = false;
    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '[' if !in_class => in_class = true,
            ']' if in_class => in_class = false,
            '.' if !in_class => return true,
            _ => {}
        }
    }
    false
}

fn python_realpath_join_target_and_base(
    ws: &Workspace,
    sink_func: FuncId,
    sink_span: Span,
) -> Option<(String, String)> {
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let target = containing_realpath_assignment_target(&decl.flow_events, sink_span)?;
    let base = os_path_join_base_arg_at(&decl.flow_events, sink_span)?;
    Some((target, base))
}

fn containing_realpath_assignment_target(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } if span_contains(*span, sink_span)
                && source_call
                    .as_deref()
                    .is_some_and(|call| clean_overwrite_callee_tail(call) == "realpath") =>
            {
                return clean_overwrite_target_key(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(target) = containing_realpath_assignment_target(then_events, sink_span)
                    .or_else(|| containing_realpath_assignment_target(else_events, sink_span))
                {
                    return Some(target);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(target) = containing_realpath_assignment_target(body, sink_span) {
                    return Some(target);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) = containing_realpath_assignment_target(body, sink_span)
                    .or_else(|| containing_realpath_assignment_target(catch_events, sink_span))
                    .or_else(|| containing_realpath_assignment_target(finally_events, sink_span))
                {
                    return Some(target);
                }
            }
            _ => {}
        }
    }
    None
}

fn os_path_join_base_arg_at(events: &[bonsai_lang_api::FlowEvent], sink_span: Span) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. }
                if (*span == sink_span || spans_overlap(*span, sink_span))
                    && name.ends_with("os.path.join") =>
            {
                return args
                    .first()
                    .and_then(|arg| clean_overwrite_target_key(&arg.value_text));
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(base) = os_path_join_base_arg_at(then_events, sink_span)
                    .or_else(|| os_path_join_base_arg_at(else_events, sink_span))
                {
                    return Some(base);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(base) = os_path_join_base_arg_at(body, sink_span) {
                    return Some(base);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(base) = os_path_join_base_arg_at(body, sink_span)
                    .or_else(|| os_path_join_base_arg_at(catch_events, sink_span))
                    .or_else(|| os_path_join_base_arg_at(finally_events, sink_span))
                {
                    return Some(base);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_path_containment_guard_condition(condition: &str, candidate: &str, base: &str) -> bool {
    let compact = compact_guard_text(condition);
    let startswith_sep = format!("not{candidate}.startswith({base}+os.sep)");
    let startswith_slash_single = format!("not{candidate}.startswith({base}+'/')");
    let startswith_slash_double = format!("not{candidate}.startswith({base}+\"/\")");
    compact.contains(&startswith_sep)
        || compact.contains(&startswith_slash_single)
        || compact.contains(&startswith_slash_double)
}

pub(super) fn python_lxml_parser_keyword_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("xxe") {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let parser_arg = find_call_arg_named_at(&decl.flow_events, snk.span, "parser")?;
    let parser_var = clean_overwrite_target_key(&parser_arg.value_text)?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let assignment_span =
        python_hardened_lxml_parser_assignment_span(&decl.flow_events, snk.span, &parser_var)?;
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        assignment_span,
        "engine.sanitizer.python_lxml_hardened_parser_arg",
        "xxe-sanitizer",
        "hardened-parser-argument",
    )
}

fn python_hardened_lxml_parser_assignment_span(
    events: &[FlowEvent],
    before: Span,
    parser_var: &str,
) -> Option<Span> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let mut calls = Vec::new();
    collect_structured_calls(events, &mut calls);
    for assignment in assignments.into_iter().rev() {
        if clean_overwrite_target_key(assignment.target).as_deref() != Some(parser_var) {
            continue;
        }
        let hardened = calls.iter().any(|call| {
            span_contains(assignment.span, call.span)
                && clean_overwrite_callee_tail(call.name) == "xmlparser"
                && call.args.iter().any(|arg| {
                    arg.name.as_deref() == Some("resolve_entities")
                        && arg.value_text.trim().eq_ignore_ascii_case("false")
                })
        });
        if hardened {
            return Some(assignment.span);
        }
    }
    None
}

pub(super) fn java_url_ssrf_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if snk.language != "java" || sink_rule.tag.as_deref() != Some("ssrf") {
        return None;
    }
    if !matches!(snk.rule_id.as_str(), "java.ssrf.url_ctor" | "java.ssrf.uri_ctor") {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let parsed_var = constructor_assignment_target_at(&decl.flow_events, snk.span)?;
    let mut branches = Vec::new();
    collect_following_branches_on_path(&decl.flow_events, snk.span, &mut branches);
    let scheme_guard = branches.iter().find(|branch| {
        java_url_scheme_guard_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let has_host_allowlist = branches.iter().any(|branch| {
        java_url_host_allowlist_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let private_ip_reject = branches.iter().any(|branch| {
        java_private_ip_reject_condition(branch.condition) && branch_arm_abruptly_exits(branch.then_events)
    });
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(snk.span.file, decl.span.end),
        &mut assignments,
    );
    let has_dns_lookup = assignments.iter().any(|assignment| {
        assignment.span.start > snk.span.start
            && assignment
                .source_call
                .is_some_and(|call| clean_overwrite_callee_tail(call) == "getbyname")
            && assignment
                .source_call_args
                .iter()
                .any(|arg| compact_guard_text(arg) == format!("{parsed_var}.getHost()"))
    });
    if !(scheme_guard.is_some() && has_host_allowlist && has_dns_lookup && private_ip_reject) {
        return None;
    }
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        scheme_guard?.span,
        "engine.sanitizer.java_url_ssrf_guard",
        "ssrf-sanitize",
        "url-scheme-host-private-ip-guard",
    )
}

fn java_url_scheme_guard_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains(&format!(
        "!\"https\".equalsIgnoreCase({parsed_var}.getProtocol())"
    )) || compact.contains(&format!(
        "!{parsed_var}.getProtocol().equalsIgnoreCase(\"https\")"
    )) || compact.contains(&format!("!\"https\".equals({parsed_var}.getProtocol())"))
}

fn java_url_host_allowlist_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains(&format!(".contains({parsed_var}.getHost())"))
        && (compact.starts_with('!')
            || compact.starts_with("(!")
            || compact.starts_with("false==")
            || compact.starts_with("(false=="))
}

fn java_private_ip_reject_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    [
        "isLoopbackAddress()",
        "isSiteLocalAddress()",
        "isLinkLocalAddress()",
        "isAnyLocalAddress()",
        "isMulticastAddress()",
    ]
    .iter()
    .filter(|needle| compact.contains(**needle))
    .count()
        >= 3
}

pub(super) fn go_jwt_inline_keyfunc_algorithm_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if snk.language != "go"
        || snk.rule_id != "go.jwt.golang_jwt_parse_tainted_token"
        || sink_rule.tag.as_deref() != Some("jwt")
    {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let parse_call = structured_call_at_match(&calls, snk.span, "parse")?;
    let callback_span = parse_call.args.get(1)?.span;
    let mut branches = Vec::new();
    collect_all_structured_branches(&decl.flow_events, &mut branches);
    let guard = branches.into_iter().find(|branch| {
        span_contains(callback_span, branch.span)
            && go_jwt_algorithm_pin_condition(branch.condition)
            && go_jwt_branch_rejects_mismatch(branch.then_events)
    })?;
    if !go_jwt_callback_returns_key(&decl.flow_events, callback_span, guard.span) {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        guard.span,
        "engine.sanitizer.go_jwt_inline_keyfunc_algorithm_guard",
        "jwt-verify",
        "jwt-algorithm-keyfunc-guard",
    )
}

fn go_jwt_algorithm_pin_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    let lower = compact.to_ascii_lowercase();
    if !compact.contains(".Method.Alg()") || !compact.contains("!=") {
        return false;
    }
    if lower.contains("signingmethodnone")
        || lower.contains("unsafeallownonesignaturetype")
        || lower.contains("\"none\"")
        || lower.contains("'none'")
    {
        return false;
    }
    let Some((_, expected)) = compact.split_once("!=") else {
        return false;
    };
    let expected = expected.trim_matches(|ch| ch == '(' || ch == ')');
    (expected.starts_with('"') && expected.ends_with('"'))
        || (expected.starts_with('\'') && expected.ends_with('\''))
        || expected.contains("SigningMethod")
}

fn go_jwt_branch_rejects_mismatch(events: &[FlowEvent]) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            value_name,
            value_flow,
            ..
        } => {
            value_name.is_none()
                && value_flow.source_names.iter().any(|source| {
                    source.ends_with("ErrSignatureInvalid") || source.ends_with("ErrTokenSignatureInvalid")
                })
        }
        FlowEvent::Call { name, .. } => {
            matches!(clean_overwrite_callee_tail(name).as_str(), "new" | "errorf")
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => go_jwt_branch_rejects_mismatch(then_events) || go_jwt_branch_rejects_mismatch(else_events),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            go_jwt_branch_rejects_mismatch(body)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            go_jwt_branch_rejects_mismatch(body)
                || go_jwt_branch_rejects_mismatch(catch_events)
                || go_jwt_branch_rejects_mismatch(finally_events)
        }
        _ => false,
    }) && branch_arm_abruptly_exits(events)
}

fn go_jwt_callback_returns_key(events: &[FlowEvent], callback_span: Span, reject_span: Span) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Return {
            span,
            value_name,
            value_flow,
            ..
        } => {
            span_contains(callback_span, *span)
                && !span_contains(reject_span, *span)
                && value_name.as_deref().is_some_and(|name| name != "nil")
                && !value_flow.source_names.is_empty()
        }
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => {
            go_jwt_callback_returns_key(then_events, callback_span, reject_span)
                || go_jwt_callback_returns_key(else_events, callback_span, reject_span)
        }
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            go_jwt_callback_returns_key(body, callback_span, reject_span)
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            go_jwt_callback_returns_key(body, callback_span, reject_span)
                || go_jwt_callback_returns_key(catch_events, callback_span, reject_span)
                || go_jwt_callback_returns_key(finally_events, callback_span, reject_span)
        }
        _ => false,
    })
}

pub(super) fn js_ts_local_html_escape_helper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if !matches!(snk.language.as_str(), "javascript" | "typescript")
        || sink_rule.tag.as_deref() != Some("xss")
    {
        return None;
    }
    let global = ws.db().global_index();
    let sink_decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let mut sink_calls = Vec::new();
    collect_structured_calls(&sink_decl.flow_events, &mut sink_calls);
    let sink_call = structured_call_at_match(&sink_calls, snk.span, "")?;
    let tainted_places: Vec<String> = sink_tainted_args
        .iter()
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .collect();
    let helper_call = sink_calls.iter().find(|call| {
        call.span != sink_call.span
            && sink_call
                .args
                .iter()
                .any(|arg| span_contains(arg.span, call.span))
            && call.args.iter().any(|arg| {
                arg.place
                    .as_deref()
                    .and_then(clean_overwrite_target_key)
                    .is_some_and(|place| tainted_places.iter().any(|target| target == &place))
                    || arg.source_names.iter().any(|source| {
                        clean_overwrite_target_key(source)
                            .is_some_and(|source| tainted_places.iter().any(|target| target == &source))
                    })
            })
    })?;
    let helper = callee_spelling_tail(helper_call.name);
    let helper_lower = helper.to_ascii_lowercase();
    if !(helper_lower.contains("escape")
        || helper_lower.contains("encode")
        || helper_lower.contains("sanitize"))
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let file_index = ws.db().decl_index(snk.span.file)?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let helper_decl = global
        .decls_in(snk.span.file)
        .iter()
        .find(|candidate| candidate.name == helper)?;
    let sanitizer_span = js_ts_html_escape_helper_span(
        global.decls_in(snk.span.file),
        helper_decl,
        &assignment_values,
        snapshot.text.as_ref(),
    )?;
    let mut finding = finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        sanitizer_span,
        "engine.sanitizer.js_ts_local_html_escape_helper",
        "html-encode",
        "local-html-escape-helper",
    )?;
    finding.enclosing_fn = Some(helper);
    Some(finding)
}

fn js_ts_html_escape_helper_span(
    file_decls: &[bonsai_lang_api::Decl],
    helper_decl: &bonsai_lang_api::Decl,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> Option<Span> {
    let input = helper_decl.params.first()?;
    let mut calls = Vec::new();
    collect_structured_calls(&helper_decl.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&helper_decl.flow_events, &mut returns);
    calls.into_iter().find_map(|call| {
        if clean_overwrite_callee_tail(call.name) != "replace"
            || call.args.len() < 2
            || !call.name.strip_suffix(".replace").is_some_and(|receiver| {
                clean_overwrite_target_key(receiver).as_deref() == Some(input.as_str())
            })
            || !returns.iter().any(|(span, _)| span_contains(*span, call.span))
        {
            return None;
        }
        let pattern = compact_guard_text(&call.args[0].value_text);
        let covers_html_metacharacters = ['&', '<', '>', '\'', '"']
            .iter()
            .all(|character| pattern.contains(*character));
        if !covers_html_metacharacters {
            return None;
        }
        js_ts_replacement_has_html_entities(file_decls, &call.args[1], assignment_values, source_text)
            .then_some(call.span)
    })
}

fn js_ts_replacement_has_html_entities(
    file_decls: &[bonsai_lang_api::Decl],
    replacement: &bonsai_lang_api::CallArg,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if html_entity_set_is_complete(&replacement.value_text) {
        return true;
    }
    let maps: Vec<String> = replacement
        .source_names
        .iter()
        .filter_map(|source| clean_overwrite_target_key(source))
        .map(|source| source.split('.').next().unwrap_or(&source).to_string())
        .collect();
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(
            &decl.flow_events,
            Span::empty(decl.span.file, decl.span.end),
            &mut assignments,
        );
        assignments.into_iter().any(|assignment| {
            maps.iter()
                .any(|map| clean_overwrite_target_key(assignment.target).as_deref() == Some(map))
                && assignment_values
                    .rendering(assignment.span, source_text)
                    .is_some_and(html_entity_set_is_complete)
        })
    })
}

fn html_entity_set_is_complete(text: &str) -> bool {
    let compact = compact_guard_text(text).to_ascii_lowercase();
    compact.contains("&amp;")
        && compact.contains("&lt;")
        && compact.contains("&gt;")
        && (compact.contains("&quot;") || compact.contains("&#34;") || compact.contains("&#x22;"))
        && (compact.contains("&#39;") || compact.contains("&apos;") || compact.contains("&#x27;"))
}

fn structured_call_at_match<'a>(
    calls: &'a [StructuredCall<'a>],
    matched_span: Span,
    required_tail: &str,
) -> Option<&'a StructuredCall<'a>> {
    calls
        .iter()
        .filter(|call| {
            (required_tail.is_empty() || clean_overwrite_callee_tail(call.name) == required_tail)
                && (spans_overlap(call.span, matched_span)
                    || span_contains(matched_span, call.span)
                    || span_contains(call.span, matched_span))
        })
        .min_by_key(|call| call.span.start.abs_diff(matched_span.start))
}

pub(super) fn java_local_html_escape_helper_return_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "java" || sink_rule.tag.as_deref() != Some("xss") {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let targets: Vec<String> = sink_tainted_args
        .iter()
        .filter_map(|arg| clean_overwrite_target_key(&arg.value_text))
        .filter(|target| !target.is_empty())
        .collect();
    for target in targets {
        let Some(helper) = java_helper_assigned_to_target_before_sink(&decl.flow_events, snk.span, &target)
        else {
            continue;
        };
        let Some((helper_decl, sanitizer_span)) = global
            .decls_in(snk.span.file)
            .iter()
            .filter(|candidate| candidate.name == helper)
            .find_map(|candidate| java_html_sanitizer_return_span(candidate).map(|span| (candidate, span)))
        else {
            continue;
        };
        let location = span_map.line_col(sanitizer_span.start);
        let san_text = snapshot
            .text
            .get(sanitizer_span.start as usize..sanitizer_span.end as usize)?
            .trim()
            .to_string();
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.java_local_html_escape_helper_return".to_string(),
            file: snk.file.clone(),
            line: location.line,
            column: location.column,
            text: san_text,
            enclosing_fn: Some(helper_decl.name.clone()),
            tag: Some("html-encode".to_string()),
            severity: None,
            category: Some("local-html-escape-helper".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

fn java_helper_assigned_to_target_before_sink(
    events: &[FlowEvent],
    before: Span,
    target: &str,
) -> Option<String> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.into_iter().rev().find_map(|assignment| {
        (clean_overwrite_target_key(assignment.target).as_deref() == Some(target))
            .then(|| assignment.source_call.map(callee_spelling_tail))
            .flatten()
    })
}

fn callee_spelling_tail(name: &str) -> String {
    name.rsplit(['.', ':'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or(name)
        .trim()
        .to_string()
}

fn java_html_sanitizer_return_span(decl: &bonsai_lang_api::Decl) -> Option<Span> {
    if decl.params.is_empty() {
        return None;
    }
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(decl.span.file, decl.span.end),
        &mut assignments,
    );
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&decl.flow_events, &mut returns);

    for call in calls {
        if !java_html_sanitizer_call_wraps_param(call.name, call.args, &decl.params) {
            continue;
        }
        if returns
            .iter()
            .any(|(return_span, _)| span_contains(*return_span, call.span))
        {
            return Some(call.span);
        }
        for assignment in &assignments {
            if !span_contains(assignment.span, call.span) {
                continue;
            }
            let Some(target) = clean_overwrite_target_key(assignment.target) else {
                continue;
            };
            if returns.iter().any(|(return_span, value_name)| {
                return_span.start > assignment.span.start
                    && value_name.and_then(clean_overwrite_target_key).as_deref() == Some(target.as_str())
            }) {
                return Some(assignment.span);
            }
        }
    }
    None
}

#[derive(Copy, Clone)]
struct StructuredCall<'a> {
    span: Span,
    name: &'a str,
    args: &'a [bonsai_lang_api::CallArg],
}

fn collect_structured_calls<'a>(events: &'a [FlowEvent], out: &mut Vec<StructuredCall<'a>>) {
    for event in events {
        match event {
            FlowEvent::Call { span, name, args, .. } => out.push(StructuredCall {
                span: *span,
                name,
                args,
            }),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_structured_calls(then_events, out);
                collect_structured_calls(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_structured_calls(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_structured_calls(body, out);
                collect_structured_calls(catch_events, out);
                collect_structured_calls(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_return_bindings<'a>(events: &'a [FlowEvent], out: &mut Vec<(Span, Option<&'a str>)>) {
    for event in events {
        match event {
            FlowEvent::Return { span, value_name, .. } => out.push((*span, value_name.as_deref())),
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_return_bindings(then_events, out);
                collect_return_bindings(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_return_bindings(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_return_bindings(body, out);
                collect_return_bindings(catch_events, out);
                collect_return_bindings(finally_events, out);
            }
            _ => {}
        }
    }
}

fn java_html_sanitizer_call_wraps_param(
    call_name: &str,
    args: &[bonsai_lang_api::CallArg],
    params: &[String],
) -> bool {
    const HTML_SANITIZER_SUFFIXES: &[&str] = &[
        "encodeforhtml",
        "encodeforhtmlattribute",
        "forhtml",
        "forhtmlcontent",
        "forhtmlattribute",
        "escapehtml",
        "htmlescape",
    ];
    let tail = clean_overwrite_callee_tail(call_name);
    HTML_SANITIZER_SUFFIXES.contains(&tail.as_str())
        && args.iter().any(|arg| {
            arg.place
                .as_deref()
                .and_then(clean_overwrite_target_key)
                .is_some_and(|place| params.iter().any(|param| param == &place))
                || arg.source_names.iter().any(|source| {
                    clean_overwrite_target_key(source)
                        .is_some_and(|source| params.iter().any(|param| param == &source))
                })
        })
}

pub(super) fn template_interpolations(value_text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let bytes = value_text.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'$' && bytes[i + 1] == b'{' {
            let start = i + 2;
            let mut depth = 1usize;
            let mut j = start;
            while j < bytes.len() {
                match bytes[j] {
                    b'{' => depth += 1,
                    b'}' => {
                        depth = depth.saturating_sub(1);
                        if depth == 0 {
                            out.push(&value_text[start..j]);
                            i = j;
                            break;
                        }
                    }
                    _ => {}
                }
                j += 1;
            }
        }
        i += 1;
    }
    out
}

pub(super) fn go_xml_decoder_hardening_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if snk.language != "go"
        || snk.rule_id != "go.xxe.xml_newdecoder"
        || sink_rule.tag.as_deref() != Some("xxe")
    {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let decoder_var = assignment_target_for_source_call_at(&decl.flow_events, snk.span, "NewDecoder")?;
    let mut assignments = Vec::new();
    collect_structured_assignments_before(
        &decl.flow_events,
        Span::empty(snk.span.file, decl.span.end),
        &mut assignments,
    );
    let strict_target = format!("{decoder_var}.Strict");
    let strict_true = assignments.iter().any(|assignment| {
        assignment.span.start > snk.span.start
            && assignment.target == strict_target
            && assignment.source_name.is_some_and(|source| source == "true")
    });
    let charset_target = format!("{decoder_var}.CharsetReader");
    let charset_assignment = assignments
        .iter()
        .find(|assignment| assignment.span.start > snk.span.start && assignment.target == charset_target)?;
    let callback = global.decls_in(snk.span.file).iter().find(|candidate| {
        candidate.span.start >= charset_assignment.span.start
            && candidate.span.end <= charset_assignment.span.end
            && candidate.params.len() >= 2
    })?;
    if !(strict_true && go_charset_reader_callback_is_hardened(callback)) {
        return None;
    }
    finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        charset_assignment.span,
        "engine.sanitizer.go_xml_decoder_hardening",
        "xxe-sanitizer",
        "go-xml-decoder-hardening",
    )
}

fn go_charset_reader_callback_is_hardened(callback: &bonsai_lang_api::Decl) -> bool {
    let charset = callback.params.first().map(String::as_str).unwrap_or_default();
    let input = callback.params.get(1).map(String::as_str).unwrap_or_default();
    if charset.is_empty() || input.is_empty() {
        return false;
    }
    let mut branches = Vec::new();
    collect_all_structured_branches(&callback.flow_events, &mut branches);
    let mut calls = Vec::new();
    collect_structured_calls(&callback.flow_events, &mut calls);
    let rejected = branches.iter().any(|branch| {
        let condition = compact_guard_text(branch.condition);
        let negated_lookup = condition.starts_with('!') && condition.contains(&format!("[{charset}]"));
        let returns_error = branch_arm_abruptly_exits(branch.then_events)
            && calls.iter().any(|call| {
                span_contains(branch.span, call.span)
                    && matches!(clean_overwrite_callee_tail(call.name).as_str(), "new" | "errorf")
            });
        negated_lookup && returns_error
    });
    let mut returns = Vec::new();
    collect_return_bindings(&callback.flow_events, &mut returns);
    let returns_input = returns
        .iter()
        .any(|(_, value_name)| value_name.is_some_and(|value| value == input));
    rejected && returns_input
}

pub(super) fn nosql_eq_filter_wrapper_sanitizer(
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink_rule.tag.as_deref() != Some("nosql-injection")
        || !matches!(snk.language.as_str(), "javascript" | "typescript" | "go")
        || sink_tainted_args.is_empty()
    {
        return None;
    }
    let filter_args: Vec<&TaintedArgInfo> = sink_tainted_args
        .iter()
        .filter(|arg| arg.index != usize::MAX)
        .collect();
    if filter_args.is_empty()
        || !filter_args
            .iter()
            .all(|arg| nosql_filter_arg_uses_only_eq_wrappers(&arg.value_text))
    {
        return None;
    }
    Some(FindingMatch {
        rule_id: "engine.sanitizer.nosql_eq_filter_wrapper".to_string(),
        file: snk.file.clone(),
        line: snk.line,
        column: snk.column,
        text: snk.match_text.clone(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("nosql-parameter".to_string()),
        severity: None,
        category: Some("nosql-eq-wrapper".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: sink_tainted_args
            .iter()
            .filter_map(|arg| u32::try_from(arg.index).ok())
            .collect(),
    })
}

fn nosql_filter_arg_uses_only_eq_wrappers(raw: &str) -> bool {
    let compact = compact_guard_text(raw);
    if compact.is_empty()
        || !compact.contains("$eq")
        || compact.contains("...")
        || nosql_filter_contains_banned_operator(&compact)
    {
        return false;
    }
    let Some(inner) = braced_object_inner(raw) else {
        return false;
    };
    let fields = split_top_level_items(inner);
    if fields.is_empty() {
        return false;
    }
    fields.into_iter().all(|field| {
        let Some((_, value)) = split_top_level_once(field, ':') else {
            return false;
        };
        let value = value.trim().trim_end_matches(',');
        nosql_literal_value(value) || nosql_value_is_eq_wrapper(value)
    })
}

fn nosql_filter_contains_banned_operator(compact: &str) -> bool {
    const BANNED: &[&str] = &[
        "$ne",
        "$gt",
        "$gte",
        "$lt",
        "$lte",
        "$in",
        "$nin",
        "$regex",
        "$where",
        "$expr",
        "$or",
        "$and",
        "$nor",
        "$not",
        "$elemMatch",
        "$function",
        "$accumulator",
    ];
    BANNED.iter().any(|operator| compact.contains(operator))
}

fn nosql_literal_value(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(lower.as_str(), "true" | "false" | "null" | "nil" | "undefined")
        || trimmed.starts_with('"')
        || trimmed.starts_with('\'')
        || trimmed
            .chars()
            .all(|ch| ch.is_ascii_digit() || matches!(ch, '.' | '-' | '+'))
}

fn nosql_value_is_eq_wrapper(value: &str) -> bool {
    let Some(inner) = braced_object_inner(value) else {
        return false;
    };
    let fields = split_top_level_items(inner);
    if fields.len() != 1 {
        return false;
    }
    let Some((key, wrapped)) = split_top_level_once(fields[0], ':') else {
        return false;
    };
    let key = key.trim().trim_matches('"').trim_matches('\'').trim();
    key == "$eq" && !wrapped.trim().is_empty()
}

fn braced_object_inner(text: &str) -> Option<&str> {
    let trimmed = text.trim().trim_end_matches(';').trim_end_matches(',');
    let open = trimmed.find('{')?;
    let close = matching_closing_brace(trimmed, open)?;
    if trimmed[close + 1..].trim().is_empty() {
        Some(&trimmed[open + 1..close])
    } else {
        None
    }
}

fn matching_closing_brace(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    if bytes.get(open).copied() != Some(b'{') {
        return None;
    }
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (idx, byte) in bytes.iter().enumerate().skip(open) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if *byte == b'\\' {
                escaped = true;
                continue;
            }
            if *byte == q {
                quote = None;
            }
            continue;
        }
        match *byte {
            b'\'' | b'"' | b'`' => quote = Some(*byte),
            b'{' => depth += 1,
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn split_top_level_items(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut depth = 0isize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let bytes = text.as_bytes();
    for (idx, byte) in bytes.iter().enumerate() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if *byte == b'\\' {
                escaped = true;
                continue;
            }
            if *byte == q {
                quote = None;
            }
            continue;
        }
        match *byte {
            b'\'' | b'"' | b'`' => quote = Some(*byte),
            b'{' | b'[' | b'(' => depth += 1,
            b'}' | b']' | b')' => depth -= 1,
            b',' if depth == 0 => {
                let item = text[start..idx].trim();
                if !item.is_empty() {
                    out.push(item);
                }
                start = idx + 1;
            }
            _ => {}
        }
    }
    let item = text[start..].trim();
    if !item.is_empty() {
        out.push(item);
    }
    out
}

fn split_top_level_once(text: &str, delimiter: char) -> Option<(&str, &str)> {
    let mut depth = 0isize;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' | '`' => quote = Some(ch),
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            _ if ch == delimiter && depth == 0 => {
                return Some((&text[..idx], &text[idx + ch.len_utf8()..]));
            }
            _ => {}
        }
    }
    None
}

#[derive(Copy, Clone)]
struct StructuredAssignment<'a> {
    span: Span,
    target: &'a str,
    source_name: Option<&'a str>,
    source_call: Option<&'a str>,
    source_call_args: &'a [String],
}

#[derive(Copy, Clone)]
struct StructuredBranch<'a> {
    span: Span,
    condition: &'a str,
    then_events: &'a [FlowEvent],
}

fn collect_completed_branches_on_path<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredBranch<'a>>,
) {
    for event in events {
        let event_span = event.span();
        if span_contains(event_span, target) {
            match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if events_contain_target(then_events, target) {
                        collect_completed_branches_on_path(then_events, target, out);
                    } else if events_contain_target(else_events, target) {
                        collect_completed_branches_on_path(else_events, target, out);
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_completed_branches_on_path(body, target, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if events_contain_target(body, target) {
                        collect_completed_branches_on_path(body, target, out);
                    } else if events_contain_target(catch_events, target) {
                        collect_completed_branches_on_path(catch_events, target, out);
                    } else if events_contain_target(finally_events, target) {
                        collect_completed_branches_on_path(finally_events, target, out);
                    }
                }
                _ => {}
            }
            return;
        }
        if event_span.file != target.file || event_span.end > target.start {
            continue;
        }
        if let FlowEvent::Branch {
            span,
            condition: Some(condition),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
                condition,
                then_events,
            });
        }
    }
}

fn collect_all_structured_branches<'a>(events: &'a [FlowEvent], out: &mut Vec<StructuredBranch<'a>>) {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                if let Some(condition) = condition.as_deref() {
                    out.push(StructuredBranch {
                        span: *span,
                        condition,
                        then_events,
                    });
                }
                collect_all_structured_branches(then_events, out);
                collect_all_structured_branches(else_events, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_all_structured_branches(body, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_all_structured_branches(body, out);
                collect_all_structured_branches(catch_events, out);
                collect_all_structured_branches(finally_events, out);
            }
            _ => {}
        }
    }
}

fn collect_following_branches_on_path<'a>(
    events: &'a [FlowEvent],
    target: Span,
    out: &mut Vec<StructuredBranch<'a>>,
) -> bool {
    let mut found_target = false;
    for event in events {
        if !found_target && (event.span() == target || span_contains(event.span(), target)) {
            found_target = match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    if events_contain_target(then_events, target) {
                        collect_following_branches_on_path(then_events, target, out)
                    } else if events_contain_target(else_events, target) {
                        collect_following_branches_on_path(else_events, target, out)
                    } else {
                        true
                    }
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => collect_following_branches_on_path(body, target, out),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    if events_contain_target(body, target) {
                        collect_following_branches_on_path(body, target, out)
                    } else if events_contain_target(catch_events, target) {
                        collect_following_branches_on_path(catch_events, target, out)
                    } else if events_contain_target(finally_events, target) {
                        collect_following_branches_on_path(finally_events, target, out)
                    } else {
                        true
                    }
                }
                _ => true,
            };
            continue;
        }
        if !found_target {
            continue;
        }
        if let FlowEvent::Branch {
            span,
            condition: Some(condition),
            then_events,
            ..
        } = event
        {
            out.push(StructuredBranch {
                span: *span,
                condition,
                then_events,
            });
        }
    }
    found_target
}

fn events_contain_target(events: &[FlowEvent], target: Span) -> bool {
    events
        .iter()
        .any(|event| event.span() == target || span_contains(event.span(), target))
}

fn branch_arm_abruptly_exits(events: &[FlowEvent]) -> bool {
    for event in events {
        match event {
            FlowEvent::Return { .. } | FlowEvent::Throw { .. } => return true,
            FlowEvent::Call { name, .. }
                if matches!(
                    clean_overwrite_callee_tail(name).as_str(),
                    "abort" | "sendstatus" | "exit" | "panic"
                ) =>
            {
                return true;
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if !else_events.is_empty()
                && branch_arm_abruptly_exits(then_events)
                && branch_arm_abruptly_exits(else_events) =>
            {
                return true;
            }
            _ => {}
        }
    }
    false
}

fn finding_for_guard_span(
    hit: &RuleMatch,
    source_text: &str,
    span: Span,
    rule_id: &str,
    tag: &str,
    category: &str,
) -> Option<FindingMatch> {
    let location = bonsai_common::SpanMap::new(source_text).line_col(span.start);
    let text = source_text
        .get(span.start as usize..span.end as usize)?
        .lines()
        .next()
        .unwrap_or_default()
        .trim()
        .to_string();
    Some(FindingMatch {
        rule_id: rule_id.to_string(),
        file: hit.file.clone(),
        line: location.line,
        column: location.column,
        text,
        enclosing_fn: hit.enclosing_fn.clone(),
        tag: Some(tag.to_string()),
        severity: None,
        category: Some(category.to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn collect_structured_assignments_before<'a>(
    events: &'a [FlowEvent],
    before: Span,
    out: &mut Vec<StructuredAssignment<'a>>,
) {
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                ..
            } => {
                if span.file == before.file && span.start < before.start {
                    out.push(StructuredAssignment {
                        span: *span,
                        target,
                        source_name: source_name.as_deref(),
                        source_call: source_call.as_deref(),
                        source_call_args,
                    });
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_structured_assignments_before(then_events, before, out);
                collect_structured_assignments_before(else_events, before, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_structured_assignments_before(body, before, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_structured_assignments_before(body, before, out);
                collect_structured_assignments_before(catch_events, before, out);
                collect_structured_assignments_before(finally_events, before, out);
            }
            _ => {}
        }
    }
}

pub(super) fn local_ldap_escape_helper_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink_rule.tag.as_deref() != Some("ldap-injection")
        || !matches!(
            snk.language.as_str(),
            "python" | "javascript" | "typescript" | "go"
        )
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let file_index = ws.db().decl_index(snk.span.file)?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let targets = ldap_tainted_filter_targets(sink_tainted_args);
    if targets.is_empty() {
        return None;
    }
    let mut assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, snk.span, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    for target in targets {
        for assignment in assignments.iter().rev() {
            if clean_overwrite_target_key(assignment.target).as_deref() != Some(target.as_str()) {
                continue;
            }
            if ldap_assignment_uses_verified_escape(
                global.decls_in(snk.span.file),
                assignment,
                &assignment_values,
                snapshot.text.as_ref(),
            ) {
                let mut finding = finding_for_guard_span(
                    snk,
                    snapshot.text.as_ref(),
                    assignment.span,
                    "engine.sanitizer.local_ldap_escape_helper",
                    "ldap-escape",
                    "local-rfc4515-escape-helper",
                )?;
                finding.sanitised_arg_indices = sink_tainted_args
                    .iter()
                    .filter_map(|arg| u32::try_from(arg.index).ok())
                    .collect();
                return Some(finding);
            }
        }
    }
    None
}

fn ldap_tainted_filter_targets(sink_tainted_args: &[TaintedArgInfo]) -> Vec<String> {
    let mut targets = Vec::new();
    for arg in sink_tainted_args {
        for key in clean_overwrite_target_keys(&arg.value_text) {
            if !matches!(
                key.as_str(),
                "scope"
                    | "sub"
                    | "err"
                    | "ev"
                    | "resolve"
                    | "reject"
                    | "out"
                    | "dn"
                    | "string"
                    | "String"
                    | "objectClass"
                    | "person"
            ) {
                targets.push(key);
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn ldap_assignment_uses_verified_escape(
    file_decls: &[bonsai_lang_api::Decl],
    assignment: &StructuredAssignment<'_>,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if assignment.source_call.is_some_and(|call| {
        ldap_call_uses_verified_escape(file_decls, call, assignment.span, assignment_values, source_text)
    }) {
        return true;
    }
    file_decls.iter().any(|decl| {
        let mut calls = Vec::new();
        collect_structured_calls(&decl.flow_events, &mut calls);
        calls.into_iter().any(|call| {
            span_contains(assignment.span, call.span)
                && ldap_call_uses_verified_escape(
                    file_decls,
                    call.name,
                    assignment.span,
                    assignment_values,
                    source_text,
                )
        })
    })
}

fn ldap_call_uses_verified_escape(
    file_decls: &[bonsai_lang_api::Decl],
    call: &str,
    call_context: Span,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    let tail = clean_overwrite_callee_tail(call);
    if matches!(tail.as_str(), "escape_filter_chars" | "escapefilter")
        || (tail == "filter" && call.to_ascii_lowercase().contains("ldapescape"))
    {
        return true;
    }
    if tail == "replace" {
        let receiver = call
            .rsplit_once('.')
            .map(|(receiver, _)| receiver)
            .unwrap_or_default();
        if !receiver.is_empty() && ldap_replacer_assignment_is_safe(file_decls, receiver, call_context) {
            return true;
        }
    }
    let helper = callee_spelling_tail(call);
    file_decls
        .iter()
        .find(|decl| decl.name == helper)
        .is_some_and(|decl| local_ldap_helper_is_safe(file_decls, decl, assignment_values, source_text))
}

fn local_ldap_helper_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    helper: &bonsai_lang_api::Decl,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    let input = helper.params.first().map(String::as_str).unwrap_or_default();
    if input.is_empty() {
        return false;
    }
    let mut calls = Vec::new();
    collect_structured_calls(&helper.flow_events, &mut calls);
    let mut returns = Vec::new();
    collect_return_bindings(&helper.flow_events, &mut returns);
    let map_lookup_is_safe = calls.iter().any(|lookup| {
        if clean_overwrite_callee_tail(lookup.name) != "get" || lookup.args.len() < 2 {
            return false;
        }
        let Some(map) = lookup.name.rsplit_once('.').map(|(receiver, _)| receiver) else {
            return false;
        };
        let key = lookup.args[0].place.as_deref();
        if key.is_none() || lookup.args[1].place.as_deref() != key {
            return false;
        }
        let helper_consumes_input = calls.iter().any(|call| {
            call.args
                .iter()
                .any(|arg| arg.source_names.iter().any(|source| source == input))
        }) || helper.flow_events.iter().any(|event| match event {
            FlowEvent::Assign { source_names, .. } => source_names.iter().any(|source| source == input),
            _ => false,
        });
        helper_consumes_input
            && returns.iter().any(|(span, _)| span_contains(*span, lookup.span))
            && ldap_escape_map_assignment_is_safe(file_decls, map, assignment_values, source_text)
    });
    map_lookup_is_safe
        || calls.iter().any(|call| {
            clean_overwrite_callee_tail(call.name) == "replace"
                && call
                    .args
                    .iter()
                    .any(|arg| arg.source_names.iter().any(|source| source == input))
                && call.name.rsplit_once('.').is_some_and(|(receiver, _)| {
                    ldap_replacer_assignment_is_safe(file_decls, receiver, helper.span)
                })
                && returns.iter().any(|(span, _)| span_contains(*span, call.span))
        })
}

fn ldap_escape_map_assignment_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    map: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(
            &decl.flow_events,
            Span::empty(decl.span.file, decl.span.end),
            &mut assignments,
        );
        assignments.into_iter().any(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(map)
                && assignment_values
                    .rendering(assignment.span, source_text)
                    .is_some_and(ldap_escape_table_literals_present)
        })
    })
}

fn ldap_replacer_assignment_is_safe(
    file_decls: &[bonsai_lang_api::Decl],
    receiver: &str,
    before: Span,
) -> bool {
    file_decls.iter().any(|decl| {
        let mut assignments = Vec::new();
        collect_structured_assignments_before(&decl.flow_events, before, &mut assignments);
        assignments.into_iter().any(|assignment| {
            clean_overwrite_target_key(assignment.target).as_deref() == Some(receiver)
                && assignment
                    .source_call
                    .is_some_and(|call| clean_overwrite_callee_tail(call) == "newreplacer")
                && ldap_escape_table_literals_present(&assignment.source_call_args.join(" "))
        })
    })
}

fn ldap_escape_table_literals_present(text: &str) -> bool {
    ["\\5c", "\\2a", "\\28", "\\29", "\\00"]
        .iter()
        .all(|needle| text.contains(needle))
}

pub(super) fn go_same_origin_redirect_helper_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "go" || sink_rule.tag.as_deref() != Some("open-redirect") {
        return None;
    }
    let mut targets: Vec<String> = sink_tainted_args
        .iter()
        .filter(|arg| arg.index != usize::MAX)
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .filter(|target| !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let guard = find_go_same_origin_helper_guard(&decl.flow_events, snk.span, &targets)?;
    let helper_decl = global
        .decls_in(snk.span.file)
        .iter()
        .find(|candidate| candidate.name == guard.helper)?;
    if !go_same_origin_helper_is_safe(helper_decl) {
        return None;
    }
    let (file, line, column) = resolve_span_location(ws, guard.span);
    Some(FindingMatch {
        rule_id: "engine.sanitizer.go_same_origin_redirect_helper_guard".to_string(),
        file,
        line,
        column,
        text: guard.condition,
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("same-origin-path".to_string()),
        severity: None,
        category: Some("same-origin-helper-guard".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: sink_tainted_args
            .iter()
            .filter_map(|arg| u32::try_from(arg.index).ok())
            .collect(),
    })
}

struct GoSameOriginGuard {
    span: Span,
    condition: String,
    helper: String,
}

fn find_go_same_origin_helper_guard(
    events: &[FlowEvent],
    sink_span: Span,
    targets: &[String],
) -> Option<GoSameOriginGuard> {
    for event in events {
        match event {
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } if span.file == sink_span.file && span.start < sink_span.start => {
                if let Some(condition) = condition {
                    if let Some((helper, target)) = negated_single_arg_helper_call(condition) {
                        if targets.iter().any(|candidate| candidate == &target)
                            && branch_assigns_literal_to_target(then_events, &target)
                        {
                            return Some(GoSameOriginGuard {
                                span: *span,
                                condition: condition.clone(),
                                helper: helper.to_string(),
                            });
                        }
                    }
                }
                if let Some(found) = find_go_same_origin_helper_guard(then_events, sink_span, targets)
                    .or_else(|| find_go_same_origin_helper_guard(else_events, sink_span, targets))
                {
                    return Some(found);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(found) = find_go_same_origin_helper_guard(body, sink_span, targets) {
                    return Some(found);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(found) = find_go_same_origin_helper_guard(body, sink_span, targets)
                    .or_else(|| find_go_same_origin_helper_guard(catch_events, sink_span, targets))
                    .or_else(|| find_go_same_origin_helper_guard(finally_events, sink_span, targets))
                {
                    return Some(found);
                }
            }
            _ => {}
        }
    }
    None
}

fn negated_single_arg_helper_call(condition: &str) -> Option<(String, String)> {
    let compact = compact_guard_text(condition);
    let inner = compact.strip_prefix('!')?;
    let open = inner.find('(')?;
    let close = inner.rfind(')')?;
    if close + 1 != inner.len() {
        return None;
    }
    let helper = &inner[..open];
    let target = &inner[open + 1..close];
    if helper.is_empty()
        || target.is_empty()
        || !helper.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        || !target.chars().all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
    {
        return None;
    }
    Some((helper.to_string(), target.to_string()))
}

fn branch_assigns_literal_to_target(events: &[FlowEvent], target: &str) -> bool {
    events.iter().any(|event| match event {
        FlowEvent::Assign {
            target: assigned,
            value_kind,
            ..
        } => {
            clean_overwrite_target_key(assigned).as_deref() == Some(target)
                && matches!(value_kind, Some(AssignValueKind::Literal))
        }
        _ => false,
    })
}

fn go_same_origin_helper_is_safe(helper: &bonsai_lang_api::Decl) -> bool {
    let input = helper.params.first().map(String::as_str).unwrap_or_default();
    if input.is_empty() {
        return false;
    }
    helper.flow_events.iter().any(|event| {
        let FlowEvent::Return {
            value_text: Some(value),
            value_flow,
            ..
        } = event
        else {
            return false;
        };
        let first = format!("{input}.0");
        let second = format!("{input}.1");
        if !(value_flow.source_names.iter().any(|source| source == &first)
            && value_flow.source_names.iter().any(|source| source == &second))
        {
            return false;
        }
        let compact = compact_guard_text(value);
        let first_is_slash =
            compact.contains(&format!("{input}[0]=='/'")) || compact.contains(&format!("{input}[0]==\"/\""));
        let second_is_not_slash =
            compact.contains(&format!("{input}[1]!='/'")) || compact.contains(&format!("{input}[1]!=\"/\""));
        let length_checked = compact.contains(&format!("len({input})>0"))
            && (compact.contains(&format!("len({input})==1"))
                || compact.contains(&format!("len({input})>1")));
        first_is_slash && second_is_not_slash && length_checked
    })
}

pub(super) fn python_url_ssrf_guard_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if snk.language != "python" || sink_rule.tag.as_deref() != Some("ssrf") {
        return None;
    }
    let target = sink_tainted_args
        .iter()
        .filter(|arg| arg.index != usize::MAX)
        .find_map(|arg| clean_overwrite_target_key(&arg.value_text))?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let parsed_var = python_urlparse_assignment_var(&decl.flow_events, snk.span, &target)?;
    let mut branches = Vec::new();
    collect_all_structured_branches(&decl.flow_events, &mut branches);
    let relevant_branches: Vec<_> = branches
        .into_iter()
        .filter(|branch| branch.span.start < snk.span.start)
        .collect();
    let scheme_guard = relevant_branches.iter().find(|branch| {
        python_url_scheme_guard_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let host_allowlist = relevant_branches.iter().any(|branch| {
        python_url_host_allowlist_condition(branch.condition, &parsed_var)
            && branch_arm_abruptly_exits(branch.then_events)
    });
    let private_ip_reject = relevant_branches.iter().any(|branch| {
        python_private_ip_reject_condition(branch.condition) && branch_arm_abruptly_exits(branch.then_events)
    });
    let mut calls = Vec::new();
    collect_structured_calls(&decl.flow_events, &mut calls);
    let hostname_place = format!("{parsed_var}.hostname");
    let dns_lookup = calls.iter().any(|call| {
        call.span.start < snk.span.start
            && clean_overwrite_callee_tail(call.name) == "getaddrinfo"
            && call
                .args
                .first()
                .is_some_and(|arg| arg.place.as_deref() == Some(hostname_place.as_str()))
    });
    let redirects_disabled = calls.iter().any(|call| {
        call.span.start < snk.span.start
            && clean_overwrite_callee_tail(call.name) == "asyncclient"
            && call.args.iter().any(|arg| {
                arg.name.as_deref() == Some("follow_redirects")
                    && arg.value_text.trim().eq_ignore_ascii_case("false")
            })
    });
    if !(scheme_guard.is_some() && host_allowlist && dns_lookup && private_ip_reject && redirects_disabled) {
        return None;
    }
    let mut finding = finding_for_guard_span(
        snk,
        snapshot.text.as_ref(),
        scheme_guard?.span,
        "engine.sanitizer.python_url_ssrf_guard",
        "ssrf-sanitize",
        "url-scheme-host-private-ip-guard",
    )?;
    finding.sanitised_arg_indices = sink_tainted_args
        .iter()
        .filter_map(|arg| u32::try_from(arg.index).ok())
        .collect();
    Some(finding)
}

fn python_url_scheme_guard_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains(&format!("{parsed_var}.scheme!=\"https\""))
        || compact.contains(&format!("\"https\"!={parsed_var}.scheme"))
}

fn python_url_host_allowlist_condition(condition: &str, parsed_var: &str) -> bool {
    let compact = compact_guard_text(condition).to_ascii_lowercase();
    compact.contains(&format!("{parsed_var}.hostname").to_ascii_lowercase())
        && (compact.contains("notinallowed") || compact.contains("notinallowed_hosts"))
}

fn python_private_ip_reject_condition(condition: &str) -> bool {
    let compact = compact_guard_text(condition);
    compact.contains("is_private") && compact.contains("is_loopback") && compact.contains("is_link_local")
}

fn python_urlparse_assignment_var(events: &[FlowEvent], before: Span, target: &str) -> Option<String> {
    let mut assignments = Vec::new();
    collect_structured_assignments_before(events, before, &mut assignments);
    assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    assignments.into_iter().rev().find_map(|assignment| {
        let call = assignment.source_call?;
        if clean_overwrite_callee_tail(call) != "urlparse" {
            return None;
        }
        let argument = assignment.source_call_args.first()?;
        (clean_overwrite_target_key(argument).as_deref() == Some(target))
            .then(|| clean_overwrite_target_key(assignment.target))
            .flatten()
    })
}

fn assignment_target_for_source_call_at(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    call_tail: &str,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } if span_contains(*span, sink_span)
                && source_call.as_deref().is_some_and(|call| {
                    clean_overwrite_callee_tail(call) == clean_overwrite_callee_tail(call_tail)
                }) =>
            {
                return clean_overwrite_target_key(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(target) = assignment_target_for_source_call_at(then_events, sink_span, call_tail)
                    .or_else(|| assignment_target_for_source_call_at(else_events, sink_span, call_tail))
                {
                    return Some(target);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(target) = assignment_target_for_source_call_at(body, sink_span, call_tail) {
                    return Some(target);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) = assignment_target_for_source_call_at(body, sink_span, call_tail)
                    .or_else(|| assignment_target_for_source_call_at(catch_events, sink_span, call_tail))
                    .or_else(|| assignment_target_for_source_call_at(finally_events, sink_span, call_tail))
                {
                    return Some(target);
                }
            }
            _ => {}
        }
    }
    None
}

fn constructor_assignment_target_at(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
) -> Option<String> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target,
                source_call,
                ..
            } if span_contains(*span, sink_span)
                && source_call.as_deref().is_some_and(|call| {
                    matches!(clean_overwrite_callee_tail(call).as_str(), "url" | "uri")
                }) =>
            {
                return clean_overwrite_target_key(target);
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(target) = constructor_assignment_target_at(then_events, sink_span)
                    .or_else(|| constructor_assignment_target_at(else_events, sink_span))
                {
                    return Some(target);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(target) = constructor_assignment_target_at(body, sink_span) {
                    return Some(target);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(target) = constructor_assignment_target_at(body, sink_span)
                    .or_else(|| constructor_assignment_target_at(catch_events, sink_span))
                    .or_else(|| constructor_assignment_target_at(finally_events, sink_span))
                {
                    return Some(target);
                }
            }
            _ => {}
        }
    }
    None
}

fn find_call_arg_named_at<'a>(
    events: &'a [bonsai_lang_api::FlowEvent],
    call_span: Span,
    arg_name: &str,
) -> Option<&'a bonsai_lang_api::CallArg> {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Call { span, args, .. } => {
                if *span == call_span || spans_overlap(*span, call_span) {
                    if let Some(arg) = args.iter().find(|arg| arg.name.as_deref() == Some(arg_name)) {
                        return Some(arg);
                    }
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if let Some(arg) = find_call_arg_named_at(then_events, call_span, arg_name)
                    .or_else(|| find_call_arg_named_at(else_events, call_span, arg_name))
                {
                    return Some(arg);
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if let Some(arg) = find_call_arg_named_at(body, call_span, arg_name) {
                    return Some(arg);
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if let Some(arg) = find_call_arg_named_at(body, call_span, arg_name)
                    .or_else(|| find_call_arg_named_at(catch_events, call_span, arg_name))
                    .or_else(|| find_call_arg_named_at(finally_events, call_span, arg_name))
                {
                    return Some(arg);
                }
            }
            _ => {}
        }
    }
    None
}

fn python_dev_only_env_guard_condition(condition: &str) -> bool {
    let lower = condition.trim().to_ascii_lowercase();
    let reads_env = lower.contains("os.environ.get")
        || lower.contains("os.getenv")
        || lower.contains("environ.get")
        || lower.contains("getenv(");
    if !reads_env {
        return false;
    }
    let negated = lower.contains("!=") || lower.contains(" not in ");
    if !negated {
        return false;
    }
    const DEV_LITERALS: &[&str] = &[
        "\"dev\"",
        "'dev'",
        "\"development\"",
        "'development'",
        "\"dev-internal\"",
        "'dev-internal'",
        "\"debug\"",
        "'debug'",
        "\"local\"",
        "'local'",
        "\"test\"",
        "'test'",
    ];
    DEV_LITERALS.iter().any(|literal| lower.contains(literal))
}

pub(super) fn finite_literal_map_lookup_allowlist_sanitizer(
    ws: &Workspace,
    sink: &RuleMatch,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink.language != "python" {
        return None;
    }
    let snapshot = ws.vfs().snapshot(sink.span.file).ok()?;
    let file_index = ws.db().decl_index(sink.span.file)?;
    let assignment_values = bonsai_lang_api::AssignmentValueIndex::new(&file_index.assignment_values);
    let enclosing = ws
        .enclosing_index()
        .enclosing_for(ws.db(), sink.span.file, sink.span.start)?;
    let global = ws.db().global_index();
    let decl = global.decl_of(enclosing.symbol)?;
    let mut file_assignments = Vec::new();
    for candidate in &file_index.defs {
        collect_structured_assignments_before(&candidate.flow_events, sink.span, &mut file_assignments);
    }
    file_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    file_assignments.dedup_by_key(|assignment| assignment.span);
    let mut local_assignments = Vec::new();
    collect_structured_assignments_before(&decl.flow_events, sink.span, &mut local_assignments);
    local_assignments.sort_by_key(|assignment| (assignment.span.start, assignment.span.end));
    let span_map = bonsai_common::cached_span_map_arc(sink.span.file, snapshot.version, &snapshot.text);
    for arg in tainted_args {
        let Some((map_name, key_name)) = python_index_lookup_parts(&arg.value_text) else {
            continue;
        };
        if !python_literal_mapping_declared_before(
            &file_assignments,
            map_name,
            &assignment_values,
            snapshot.text.as_ref(),
        ) {
            continue;
        }
        for assignment in &local_assignments {
            let location = span_map.line_col(assignment.span.start);
            if location.column > sink.column {
                continue;
            }
            if !python_assignment_narrows_key_to_map(
                assignment,
                key_name,
                map_name,
                &assignment_values,
                snapshot.text.as_ref(),
            ) {
                continue;
            }
            let text = snapshot
                .text
                .get(assignment.span.start as usize..assignment.span.end as usize)?
                .trim()
                .to_string();
            return Some(FindingMatch {
                rule_id: "engine.sanitizer.literal_map_key_allowlist".to_string(),
                file: sink.file.clone(),
                line: location.line,
                column: location.column,
                text,
                enclosing_fn: sink.enclosing_fn.clone(),
                tag: Some("allowlist-validate".to_string()),
                severity: None,
                category: Some("finite-map-allowlist".to_string()),
                trust: None,
                payload_types: Vec::new(),
                tainted_args: Vec::new(),
                sanitised_arg_indices: Vec::new(),
            });
        }
    }
    None
}

pub(super) fn guarded_char_append_allowlist_sanitizer(
    ws: &Workspace,
    sink_func: FuncId,
    sink: &RuleMatch,
    sink_tag: Option<&str>,
    tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if sink.language != "go" || sink_tag != Some("header-injection") {
        return None;
    }
    let mut targets: Vec<String> = tainted_args
        .iter()
        .flat_map(|arg| clean_overwrite_target_keys(&arg.value_text))
        .filter(|target| !clean_conditional_helper_identifier(target) && !looks_like_clean_constant(target))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return None;
    }
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    for target in targets {
        let mut scan = GuardedCharAppendScan::default();
        collect_guarded_char_append_writes(&decl.flow_events, sink.span, &target, None, &mut scan);
        if scan.saw_dirty_write {
            continue;
        }
        let Some(span) = scan.sanitizer_span else {
            continue;
        };
        let (file, line, column) = resolve_span_location(ws, span);
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.go_guarded_char_append_allowlist".to_string(),
            file,
            line,
            column,
            text: "guarded append character allowlist".to_string(),
            enclosing_fn: sink.enclosing_fn.clone(),
            tag: Some("char-allowlist".to_string()),
            severity: None,
            category: Some("guarded-char-allowlist".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

#[derive(Default)]
struct GuardedCharAppendScan {
    sanitizer_span: Option<Span>,
    saw_dirty_write: bool,
}

fn collect_guarded_char_append_writes(
    events: &[bonsai_lang_api::FlowEvent],
    sink_span: Span,
    target: &str,
    guard_condition: Option<&str>,
    out: &mut GuardedCharAppendScan,
) {
    use bonsai_lang_api::FlowEvent;
    for event in events {
        match event {
            FlowEvent::Assign {
                span,
                target: assign_target,
                source_call,
                source_names,
                source_call_args,
                value_kind,
                ..
            } => {
                if span.file != sink_span.file || span.start >= sink_span.start {
                    continue;
                }
                if clean_overwrite_target_key(assign_target).as_deref() != Some(target) {
                    continue;
                }
                if guarded_append_assign_is_char_allowlist(
                    source_call.as_deref(),
                    source_call_args,
                    target,
                    guard_condition,
                ) {
                    out.sanitizer_span.get_or_insert(*span);
                    continue;
                }
                if assignment_initializes_clean_buffer(
                    source_call.as_deref(),
                    source_names,
                    source_call_args,
                    *value_kind,
                ) {
                    continue;
                }
                out.saw_dirty_write = true;
            }
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
                ..
            } => {
                if span.file != sink_span.file || span.start >= sink_span.start {
                    continue;
                }
                collect_guarded_char_append_writes(
                    then_events,
                    sink_span,
                    target,
                    condition.as_deref().or(guard_condition),
                    out,
                );
                collect_guarded_char_append_writes(else_events, sink_span, target, guard_condition, out);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                collect_guarded_char_append_writes(body, sink_span, target, guard_condition, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_guarded_char_append_writes(body, sink_span, target, guard_condition, out);
                collect_guarded_char_append_writes(catch_events, sink_span, target, guard_condition, out);
                collect_guarded_char_append_writes(finally_events, sink_span, target, guard_condition, out);
            }
            _ => {}
        }
    }
}

fn guarded_append_assign_is_char_allowlist(
    source_call: Option<&str>,
    source_call_args: &[String],
    target: &str,
    guard_condition: Option<&str>,
) -> bool {
    if source_call.map(str::trim) != Some("append") || source_call_args.len() < 2 {
        return false;
    }
    if clean_overwrite_target_key(&source_call_args[0]).as_deref() != Some(target) {
        return false;
    }
    let appended = source_call_args[1].trim();
    !appended.is_empty()
        && guard_condition.is_some_and(|condition| header_char_allowlist_condition(condition, appended))
}

fn assignment_initializes_clean_buffer(
    source_call: Option<&str>,
    source_names: &[String],
    source_call_args: &[String],
    value_kind: Option<AssignValueKind>,
) -> bool {
    source_call.map(str::trim) == Some("make")
        || (source_names.is_empty()
            && source_call_args.is_empty()
            && matches!(
                value_kind,
                Some(AssignValueKind::Literal | AssignValueKind::Unknown)
            ))
}

pub(super) fn header_char_allowlist_condition(condition: &str, variable: &str) -> bool {
    let variable = variable.trim();
    if variable.is_empty() || !text_mentions_token(condition, variable) {
        return false;
    }
    let compact: String = condition.chars().filter(|ch| !ch.is_whitespace()).collect();
    let printable_floor = [
        format!("{variable}>=0x20"),
        format!("{variable}>0x1f"),
        format!("{variable}>=32"),
        format!("{variable}>31"),
        format!("0x20<={variable}"),
        format!("0x1f<{variable}"),
        format!("32<={variable}"),
        format!("31<{variable}"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    let crlf_excluded = printable_floor
        || (char_guard_excludes(&compact, variable, "'\\r'")
            && char_guard_excludes(&compact, variable, "'\\n'"))
        || (char_guard_excludes(&compact, variable, "\"\\r\"")
            && char_guard_excludes(&compact, variable, "\"\\n\""));
    let del_excluded = [
        format!("{variable}!=0x7f"),
        format!("{variable}<0x7f"),
        format!("{variable}<=0x7e"),
        format!("0x7f!={variable}"),
        format!("0x7f>{variable}"),
        format!("0x7e>={variable}"),
        format!("{variable}!=127"),
        format!("{variable}<127"),
        format!("{variable}<=126"),
    ]
    .into_iter()
    .any(|needle| compact.contains(&needle));
    crlf_excluded && (del_excluded || !printable_floor)
}

fn char_guard_excludes(compact_condition: &str, variable: &str, literal: &str) -> bool {
    compact_condition.contains(&format!("{variable}!={literal}"))
        || compact_condition.contains(&format!("{literal}!={variable}"))
}

fn python_index_lookup_parts(value: &str) -> Option<(&str, &str)> {
    let trimmed = value.trim();
    let open = trimmed.find('[')?;
    if !trimmed.ends_with(']') {
        return None;
    }
    let map_name = trimmed[..open].trim();
    let key_name = trimmed[open + 1..trimmed.len().saturating_sub(1)].trim();
    if python_identifier_path_like(map_name) && python_identifier_like(key_name) {
        Some((map_name, key_name))
    } else {
        None
    }
}

fn python_literal_mapping_declared_before(
    assignments: &[StructuredAssignment<'_>],
    map_name: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    assignments.iter().any(|assignment| {
        clean_overwrite_target_key(assignment.target).as_deref() == Some(map_name)
            && assignment_values
                .rendering(assignment.span, source_text)
                .is_some_and(|rhs| rhs.starts_with('{'))
    })
}

fn python_assignment_narrows_key_to_map(
    assignment: &StructuredAssignment<'_>,
    key_name: &str,
    map_name: &str,
    assignment_values: &bonsai_lang_api::AssignmentValueIndex,
    source_text: &str,
) -> bool {
    if clean_overwrite_target_key(assignment.target).as_deref() != Some(key_name) {
        return false;
    }
    let Some(rhs) = assignment_values.rendering(assignment.span, source_text) else {
        return false;
    };
    if !(rhs.contains(" if ") && rhs.contains(" else ")) {
        return false;
    }
    let membership = format!(" in {map_name}");
    rhs.contains(&membership) && python_conditional_else_is_literal(rhs)
}

fn python_conditional_else_is_literal(rhs: &str) -> bool {
    let Some((_, else_value)) = rhs.rsplit_once(" else ") else {
        return false;
    };
    let else_value = else_value.trim();
    quoted_literal(else_value) || numeric_literal(else_value)
}

fn python_identifier_like(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic()) && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn python_identifier_path_like(value: &str) -> bool {
    !value.is_empty()
        && value
            .split('.')
            .all(|part| !part.is_empty() && python_identifier_like(part))
}

#[cfg(test)]
mod structured_guard_tests {
    use super::*;

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    #[test]
    fn completed_environment_guard_comes_from_branch_facts() {
        let guard_span = span(0, 40);
        let target_span = span(50, 60);
        let events = [
            FlowEvent::Branch {
                span: guard_span,
                condition: Some("process.env.NODE_ENV !== 'development'".to_string()),
                then_events: vec![FlowEvent::Return {
                    span: span(30, 36),
                    value_text: None,
                    value_name: None,
                    value_flow: Default::default(),
                }],
                else_events: Vec::new(),
            },
            FlowEvent::Call {
                span: target_span,
                name: "sink".to_string(),
                receiver: None,
                receiver_types: Vec::new(),
                call_kind: bonsai_lang_api::CallKind::Function,
                args: Vec::new(),
            },
        ];
        let mut branches = Vec::new();

        collect_completed_branches_on_path(&events, target_span, &mut branches);

        assert_eq!(branches.len(), 1);
        assert!(js_dev_only_env_guard_condition(branches[0].condition));
        assert!(branch_arm_abruptly_exits(branches[0].then_events));
    }

    #[test]
    fn python_environment_condition_is_ast_rendering_not_if_line() {
        assert!(python_dev_only_env_guard_condition(
            "os.getenv('APP_ENV') != 'dev'"
        ));
        assert!(!python_dev_only_env_guard_condition(
            "os.getenv('APP_ENV') == 'production'"
        ));
    }
}
