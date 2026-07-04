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
    if matches!(hit.language.as_str(), "javascript" | "typescript") {
        return js_dev_only_environment_guard_sanitizer(ws, hit);
    }
    if hit.language != "python" {
        return None;
    }
    let snapshot = ws.vfs().snapshot(hit.span.file).ok()?;
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let target_idx = usize::try_from(hit.line.checked_sub(1)?).ok()?;
    let target_line = *lines.get(target_idx)?;
    let target_indent = leading_ascii_whitespace(target_line);
    let search_start = target_idx.saturating_sub(12);
    for idx in search_start..target_idx {
        let guard_line = lines[idx];
        if !python_dev_only_env_guard_line(guard_line) {
            continue;
        }
        let guard_indent = leading_ascii_whitespace(guard_line);
        if guard_indent > target_indent {
            continue;
        }
        if !python_guard_exits_before_target(&lines, idx, target_idx, guard_indent, target_indent) {
            continue;
        }
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.dev_only_env_guard".to_string(),
            file: hit.file.clone(),
            line: u32::try_from(idx + 1).ok()?,
            column: u32::try_from(guard_indent + 1).ok()?,
            text: guard_line.trim().to_string(),
            enclosing_fn: hit.enclosing_fn.clone(),
            tag: Some("dev-only-guard".to_string()),
            severity: None,
            category: Some("reachability-guard".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

fn js_dev_only_environment_guard_sanitizer(ws: &Workspace, hit: &RuleMatch) -> Option<FindingMatch> {
    let snapshot = ws.vfs().snapshot(hit.span.file).ok()?;
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let target_idx = usize::try_from(hit.line.checked_sub(1)?).ok()?;
    let target_indent = leading_ascii_whitespace(lines.get(target_idx)?);
    let search_start = target_idx.saturating_sub(12);
    for (idx, guard_line) in lines
        .iter()
        .copied()
        .enumerate()
        .take(target_idx)
        .skip(search_start)
    {
        if !js_dev_only_env_guard_line(guard_line) {
            continue;
        }
        let guard_indent = leading_ascii_whitespace(guard_line);
        if guard_indent > target_indent {
            continue;
        }
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.dev_only_env_guard".to_string(),
            file: hit.file.clone(),
            line: u32::try_from(idx + 1).ok()?,
            column: u32::try_from(guard_indent + 1).ok()?,
            text: guard_line.trim().to_string(),
            enclosing_fn: hit.enclosing_fn.clone(),
            tag: Some("dev-only-guard".to_string()),
            severity: None,
            category: Some("reachability-guard".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

fn js_dev_only_env_guard_line(line: &str) -> bool {
    let compact = compact_guard_text(line);
    let lower = compact.to_ascii_lowercase();
    let reads_node_env = lower.contains("process.env.node_env") || lower.contains("node_env");
    if !reads_node_env || !(compact.contains("!==") || compact.contains("!=")) {
        return false;
    }
    let mentions_dev_env = ["dev", "debug", "test", "local", "internal"]
        .iter()
        .any(|marker| lower.contains(marker));
    mentions_dev_env
        && (lower.contains("return")
            || lower.contains("throw")
            || lower.contains("sendstatus(404")
            || lower.contains("status(404"))
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let search_end = (sink_idx + 14).min(lines.len());
    for idx in sink_idx.saturating_add(1)..search_end {
        let line = lines[idx];
        if !python_path_containment_guard_line(line, &candidate, &base) {
            continue;
        }
        if !python_guard_body_exits(&lines, idx) {
            continue;
        }
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.python_realpath_containment_guard".to_string(),
            file: snk.file.clone(),
            line: u32::try_from(idx + 1).ok()?,
            column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
            text: line.trim().to_string(),
            enclosing_fn: snk.enclosing_fn.clone(),
            tag: Some("path-sanitize".to_string()),
            severity: None,
            category: Some("realpath-containment-guard".to_string()),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let target_line = *lines.get(sink_idx)?;
    let target_indent = leading_ascii_whitespace(target_line);
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let func_start_line = usize::try_from(span_map.line_col(decl.span.start).line.saturating_sub(1))
        .ok()
        .unwrap_or_else(|| sink_idx.saturating_sub(60));
    let search_start = func_start_line.max(sink_idx.saturating_sub(80));
    for idx in search_start..sink_idx {
        let line = lines[idx];
        let guard_indent = leading_ascii_whitespace(line);
        if guard_indent > target_indent {
            continue;
        }
        let Some((regex_name, guarded_target)) = python_compiled_regex_guard_line(line, &targets) else {
            continue;
        };
        if !python_compiled_regex_declared_safe_before(&lines, idx, &regex_name, sink_rule.tag.as_deref()) {
            continue;
        }
        if !python_guard_exits_before_target(&lines, idx, sink_idx, guard_indent, target_indent) {
            continue;
        }
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.python_compiled_regex_guard".to_string(),
            file: snk.file.clone(),
            line: u32::try_from(idx + 1).ok()?,
            column: u32::try_from(guard_indent + 1).ok()?,
            text: line.trim().to_string(),
            enclosing_fn: snk.enclosing_fn.clone(),
            tag: Some("regex-validate".to_string()),
            severity: None,
            category: Some(format!("compiled-regex-guard:{guarded_target}")),
            trust: None,
            payload_types: Vec::new(),
            tainted_args: Vec::new(),
            sanitised_arg_indices: Vec::new(),
        });
    }
    None
}

fn python_compiled_regex_guard_line(line: &str, targets: &[String]) -> Option<(String, String)> {
    let compact = compact_guard_text(line);
    let condition = compact.strip_prefix("if")?.split_once(':')?.0;
    let call_text = condition
        .strip_prefix("not")
        .or_else(|| condition.strip_suffix("isNone"))
        .or_else(|| condition.strip_suffix("==None"))?;
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
    lines: &[&str],
    guard_idx: usize,
    regex_name: &str,
    sink_tag: Option<&str>,
) -> bool {
    let search_start = guard_idx.saturating_sub(160);
    for idx in (search_start..guard_idx).rev() {
        let Some(pattern) = python_re_compile_assignment_pattern(lines[idx], regex_name) else {
            continue;
        };
        return python_regex_pattern_safe_for_sink(&pattern, sink_tag);
    }
    false
}

fn python_re_compile_assignment_pattern(line: &str, regex_name: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let (lhs, rhs) = trimmed.split_once('=')?;
    let lhs_name = lhs.split_once(':').map_or(lhs, |(name, _)| name).trim();
    if lhs_name != regex_name {
        return None;
    }
    let rhs = rhs.trim_start();
    let args = rhs
        .strip_prefix("re.compile(")
        .or_else(|| rhs.strip_prefix("regex.compile("))?;
    python_first_string_literal(args)
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

fn python_path_containment_guard_line(line: &str, candidate: &str, base: &str) -> bool {
    let compact = compact_guard_text(line);
    let startswith_sep = format!("ifnot{candidate}.startswith({base}+os.sep):");
    let startswith_slash_single = format!("ifnot{candidate}.startswith({base}+'/'):");
    let startswith_slash_double = format!("ifnot{candidate}.startswith({base}+\"/\"):");
    compact.contains(&startswith_sep)
        || compact.contains(&startswith_slash_single)
        || compact.contains(&startswith_slash_double)
}

fn python_guard_body_exits(lines: &[&str], guard_idx: usize) -> bool {
    let Some(guard_line) = lines.get(guard_idx) else {
        return false;
    };
    let guard_indent = leading_ascii_whitespace(guard_line);
    if let Some((_, inline_body)) = guard_line.split_once(':') {
        if python_abrupt_exit_line(inline_body) {
            return true;
        }
    }
    for line in lines.iter().skip(guard_idx + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_ascii_whitespace(line);
        if indent <= guard_indent {
            return false;
        }
        return python_abrupt_exit_line(trimmed);
    }
    false
}

fn python_abrupt_exit_line(line: &str) -> bool {
    let trimmed = line.trim();
    let compact = compact_guard_text(trimmed);
    trimmed.starts_with("raise ")
        || trimmed == "raise"
        || trimmed.starts_with("return ")
        || trimmed == "return"
        || trimmed.starts_with("abort(")
        || trimmed.contains("FileNotFoundError(")
        || compact.contains(";return")
        || compact.contains(";raise")
        || compact.contains(";abort(")
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let assign_idx = python_hardened_lxml_parser_assignment_line(&lines, sink_idx, &parser_var)?;
    let line = lines.get(assign_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.python_lxml_hardened_parser_arg".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(assign_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
        text: line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("xxe-sanitizer".to_string()),
        severity: None,
        category: Some("hardened-parser-argument".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn python_hardened_lxml_parser_assignment_line(
    lines: &[&str],
    sink_idx: usize,
    parser_var: &str,
) -> Option<usize> {
    let assignment_prefix = format!("{parser_var}=");
    let search_start = sink_idx.saturating_sub(80);
    for idx in (search_start..sink_idx).rev() {
        let compact_line = compact_guard_text(lines.get(idx)?);
        if !compact_line.starts_with(&assignment_prefix) || !compact_line.contains("etree.XMLParser(") {
            continue;
        }
        let end = (idx + 10).min(sink_idx).min(lines.len());
        let compact_block = compact_guard_text(&lines[idx..end].join("\n"));
        if compact_block.contains("resolve_entities=False")
            && !compact_block.contains("resolve_entities=True")
        {
            return Some(idx);
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let parsed_var = constructor_assignment_target_at(&decl.flow_events, snk.span).or_else(|| {
        lines
            .get(sink_idx)
            .and_then(|line| java_constructor_assignment_target_from_line(line))
    })?;
    let end = (sink_idx + 48).min(lines.len());
    if sink_idx + 1 >= end {
        return None;
    }
    let tail = lines[sink_idx + 1..end].join("\n");
    let compact = compact_guard_text(&tail);
    let scheme_a = format!("!\"https\".equalsIgnoreCase({parsed_var}.getProtocol())");
    let scheme_b = format!("!{parsed_var}.getProtocol().equalsIgnoreCase(\"https\")");
    let scheme_c = format!("!\"https\".equals({parsed_var}.getProtocol())");
    let has_scheme_guard =
        compact.contains(&scheme_a) || compact.contains(&scheme_b) || compact.contains(&scheme_c);
    let host_contains = format!(".contains({parsed_var}.getHost())");
    let has_host_allowlist =
        compact.contains(&host_contains) && (compact.contains("if(!") || compact.contains("if(false=="));
    let dns_lookup = format!("InetAddress.getByName({parsed_var}.getHost())");
    let has_dns_lookup = compact.contains(&dns_lookup) || compact.contains(&format!("java.net.{dns_lookup}"));
    let private_ip_reject = [
        "isLoopbackAddress()",
        "isSiteLocalAddress()",
        "isLinkLocalAddress()",
        "isAnyLocalAddress()",
        "isMulticastAddress()",
    ]
    .iter()
    .filter(|needle| compact.contains(**needle))
    .count()
        >= 3;
    if !(has_scheme_guard
        && has_host_allowlist
        && has_dns_lookup
        && private_ip_reject
        && compact.contains("thrownewSecurityException"))
    {
        return None;
    }
    let guard_idx = lines
        .iter()
        .enumerate()
        .skip(sink_idx + 1)
        .take(end.saturating_sub(sink_idx + 1))
        .find_map(|(idx, line)| line.contains("getProtocol").then_some(idx))?;
    let guard_line = *lines.get(guard_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.java_url_ssrf_guard".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(guard_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(guard_line) + 1).ok()?,
        text: guard_line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("ssrf-sanitize".to_string()),
        severity: None,
        category: Some("url-scheme-host-private-ip-guard".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn java_constructor_assignment_target_from_line(line: &str) -> Option<String> {
    let (lhs, rhs) = line.split_once('=')?;
    if !(rhs.contains("new URL(")
        || rhs.contains("new URI(")
        || rhs.trim_start().starts_with("URL(")
        || rhs.trim_start().starts_with("URI("))
    {
        return None;
    }
    let lhs = lhs.trim();
    let target = lhs.split_whitespace().last()?;
    clean_overwrite_target_key(target)
}

pub(super) fn go_jwt_inline_keyfunc_algorithm_guard_sanitizer(
    ws: &Workspace,
    snk: &RuleMatch,
    sink_rule: &Rule,
) -> Option<FindingMatch> {
    if snk.language != "go"
        || snk.rule_id != "go.jwt.golang_jwt_parse_tainted_token"
        || sink_rule.tag.as_deref() != Some("jwt")
    {
        return None;
    }
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let end = (sink_idx + 32).min(lines.len());
    let block = lines.get(sink_idx..end)?.join("\n");
    let compact = compact_guard_text(&block);
    let parse_idx = compact.find("Parse(")?;
    let after_parse = &compact[parse_idx..];
    if !after_parse.contains(",func(") {
        return None;
    }
    if after_parse.contains("UnsafeAllowNoneSignatureType")
        || after_parse.contains("SigningMethodNone")
        || after_parse.contains("\"none\"")
        || after_parse.contains("\"None\"")
    {
        return None;
    }
    if !go_jwt_inline_keyfunc_has_pinned_algorithm_reject(after_parse) {
        return None;
    }
    let guard_idx = lines
        .iter()
        .enumerate()
        .skip(sink_idx)
        .take(end.saturating_sub(sink_idx))
        .find_map(|(idx, line)| {
            (line.contains("Method.Alg") || line.contains("SigningMethod")).then_some(idx)
        })?;
    let guard_line = *lines.get(guard_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.go_jwt_inline_keyfunc_algorithm_guard".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(guard_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(guard_line) + 1).ok()?,
        text: guard_line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("jwt-verify".to_string()),
        severity: None,
        category: Some("jwt-algorithm-keyfunc-guard".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
}

fn go_jwt_inline_keyfunc_has_pinned_algorithm_reject(compact: &str) -> bool {
    if !(compact.contains(".Method.Alg()!=")
        || compact.contains("!=t.Method.Alg()")
        || compact.contains("!=token.Method.Alg()"))
    {
        return false;
    }
    if !go_jwt_pinned_algorithm_mentioned(compact) {
        return false;
    }
    let rejects_mismatch = compact.contains("returnnil,jwt.ErrSignatureInvalid")
        || compact.contains("returnnil,errors.New(")
        || compact.contains("returnnil,fmt.Errorf(");
    let returns_key_on_success = compact.contains(",nil})") || compact.contains(",nil}");
    rejects_mismatch && returns_key_on_success
}

fn go_jwt_pinned_algorithm_mentioned(compact: &str) -> bool {
    const ALG_LITERALS: &[&str] = &[
        "\"HS256\"",
        "\"HS384\"",
        "\"HS512\"",
        "\"RS256\"",
        "\"RS384\"",
        "\"RS512\"",
        "\"ES256\"",
        "\"ES384\"",
        "\"ES512\"",
        "\"PS256\"",
        "\"PS384\"",
        "\"PS512\"",
        "\"EdDSA\"",
    ];
    const ALG_CONSTANTS: &[&str] = &[
        "SigningMethodHS256",
        "SigningMethodHS384",
        "SigningMethodHS512",
        "SigningMethodRS256",
        "SigningMethodRS384",
        "SigningMethodRS512",
        "SigningMethodES256",
        "SigningMethodES384",
        "SigningMethodES512",
        "SigningMethodPS256",
        "SigningMethodPS384",
        "SigningMethodPS512",
        "SigningMethodEdDSA",
    ];
    ALG_LITERALS.iter().any(|alg| compact.contains(alg))
        || ALG_CONSTANTS.iter().any(|alg| compact.contains(alg))
}

pub(super) fn js_ts_local_html_escape_helper_sanitizer(
    ws: &Workspace,
    snk: &RuleMatch,
    sink_rule: &Rule,
    sink_tainted_args: &[TaintedArgInfo],
) -> Option<FindingMatch> {
    if !matches!(snk.language.as_str(), "javascript" | "typescript")
        || sink_rule.tag.as_deref() != Some("xss")
    {
        return None;
    }
    let helper = sink_tainted_args
        .iter()
        .filter_map(|arg| helper_wrapping_tainted_value(&snk.match_text, &arg.value_text))
        .find(|helper| {
            let lower = helper.to_ascii_lowercase();
            lower.contains("escape") || lower.contains("encode") || lower.contains("sanitize")
        })?;
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let (helper_idx, helper_body) = js_ts_local_function_body(&lines, &helper)?;
    let full_compact = compact_guard_text(&snapshot.text);
    if !js_ts_html_escape_helper_body_is_strong(&helper_body, &full_compact) {
        return None;
    }
    let helper_line = *lines.get(helper_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.js_ts_local_html_escape_helper".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(helper_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(helper_line) + 1).ok()?,
        text: helper_line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("html-encode".to_string()),
        severity: None,
        category: Some("local-html-escape-helper".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let func_start = usize::try_from(span_map.line_col(decl.span.start).line.saturating_sub(1)).ok()?;
    let targets: Vec<String> = sink_tainted_args
        .iter()
        .filter_map(|arg| clean_overwrite_target_key(&arg.value_text))
        .filter(|target| !target.is_empty())
        .collect();
    for target in targets {
        let Some(helper) = java_helper_assigned_to_target_before_sink(&lines, func_start, sink_idx, &target)
        else {
            continue;
        };
        let Some((helper_idx, params, body_lines)) = java_local_method_body(&lines, &helper) else {
            continue;
        };
        let Some((san_line_idx, san_text)) = java_html_sanitizer_return_line(&body_lines, &params) else {
            continue;
        };
        let line_idx = helper_idx.saturating_add(san_line_idx);
        let line = *lines.get(line_idx)?;
        return Some(FindingMatch {
            rule_id: "engine.sanitizer.java_local_html_escape_helper_return".to_string(),
            file: snk.file.clone(),
            line: u32::try_from(line_idx + 1).ok()?,
            column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
            text: san_text,
            enclosing_fn: Some(helper),
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
    lines: &[&str],
    func_start: usize,
    sink_idx: usize,
    target: &str,
) -> Option<String> {
    for line in lines
        .iter()
        .take(sink_idx)
        .skip(func_start)
        .filter_map(|line| line.split("//").next())
    {
        let Some(eq_idx) = line.find('=') else {
            continue;
        };
        let left = &line[..eq_idx];
        if last_identifier_token(left).as_deref() != Some(target) {
            continue;
        }
        let right = line[eq_idx + 1..].trim().trim_end_matches(';').trim();
        let helper = direct_helper_call_name(right)?;
        return Some(helper);
    }
    None
}

fn direct_helper_call_name(expr: &str) -> Option<String> {
    let expr = expr.trim();
    if expr.starts_with("new ") {
        return None;
    }
    let open = expr.find('(')?;
    let callee = expr[..open].trim();
    if callee.is_empty() || callee.contains(' ') {
        return None;
    }
    let helper = callee.rsplit('.').next()?.trim();
    if helper.is_empty()
        || !helper
            .chars()
            .next()
            .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
    {
        return None;
    }
    Some(helper.to_string())
}

fn java_local_method_body(lines: &[&str], helper: &str) -> Option<(usize, Vec<String>, Vec<String>)> {
    let needle = format!("{helper}(");
    for (idx, line) in lines.iter().enumerate() {
        if !line.contains(&needle) || line.trim_end().ends_with(';') {
            continue;
        }
        let mut signature = String::new();
        let mut open_line = None;
        for (offset, sig_line) in lines.iter().enumerate().skip(idx).take(6) {
            signature.push_str(sig_line);
            signature.push('\n');
            if sig_line.contains('{') {
                open_line = Some(offset);
                break;
            }
        }
        let open_line = open_line?;
        let params = java_method_param_names(&signature);
        if params.is_empty() {
            continue;
        }
        let mut depth = 0isize;
        let mut seen_open = false;
        let mut body = Vec::new();
        for line in lines.iter().skip(open_line) {
            for ch in line.chars() {
                match ch {
                    '{' => {
                        depth += 1;
                        seen_open = true;
                    }
                    '}' => depth -= 1,
                    _ => {}
                }
            }
            body.push((*line).to_string());
            if seen_open && depth == 0 {
                break;
            }
        }
        return Some((open_line, params, body));
    }
    None
}

fn java_method_param_names(signature: &str) -> Vec<String> {
    let Some(open) = signature.find('(') else {
        return Vec::new();
    };
    let Some((_, params_text)) = balanced_paren_extent(signature, open) else {
        return Vec::new();
    };
    split_top_level_items(params_text)
        .into_iter()
        .filter_map(last_identifier_token)
        .collect()
}

fn java_html_sanitizer_return_line(body_lines: &[String], params: &[String]) -> Option<(usize, String)> {
    for (idx, line) in body_lines.iter().enumerate() {
        if !java_html_sanitizer_line_wraps_param(line, params) {
            continue;
        }
        let compact = compact_guard_text(line);
        if compact.contains("return") {
            return Some((idx, line.trim().to_string()));
        }
        if let Some(eq_idx) = line.find('=') {
            let assigned = last_identifier_token(&line[..eq_idx])?;
            let return_pattern = format!("return{assigned};");
            if body_lines
                .iter()
                .skip(idx + 1)
                .any(|later| compact_guard_text(later).contains(&return_pattern))
            {
                return Some((idx, line.trim().to_string()));
            }
        }
    }
    None
}

fn java_html_sanitizer_line_wraps_param(line: &str, params: &[String]) -> bool {
    const HTML_SANITIZER_SUFFIXES: &[&str] = &[
        "encodeForHTML",
        "encodeForHTMLAttribute",
        "forHtml",
        "forHtmlContent",
        "forHtmlAttribute",
        "escapeHtml",
        "htmlEscape",
    ];
    let compact = compact_guard_text(line);
    for suffix in HTML_SANITIZER_SUFFIXES {
        let call = format!("{suffix}(");
        let mut search_from = 0usize;
        while let Some(rel) = compact[search_from..].find(&call) {
            let open = search_from + rel + suffix.len();
            search_from = open.saturating_add(1);
            let Some((_, args)) = balanced_paren_extent(&compact, open) else {
                continue;
            };
            if params.iter().any(|param| text_mentions_token(args, param)) {
                return true;
            }
        }
    }
    false
}

fn last_identifier_token(text: &str) -> Option<String> {
    identifier_tokens_outside_strings(text).into_iter().last()
}

fn helper_wrapping_tainted_value(sink_text: &str, value_text: &str) -> Option<String> {
    if let Some(helper) = helper_wrapping_tainted_expression(value_text) {
        return Some(helper);
    }
    let target = clean_overwrite_target_key(value_text)?;
    if target.is_empty() {
        return None;
    }
    for (idx, _) in sink_text.match_indices(&target) {
        if idx > 0 {
            let prev = sink_text.as_bytes().get(idx - 1).copied().unwrap_or_default() as char;
            if prev == '_' || prev == '$' || prev.is_ascii_alphanumeric() {
                continue;
            }
        }
        if let Some(next) = sink_text.as_bytes().get(idx + target.len()).copied() {
            let next = next as char;
            if next == '_' || next == '$' || next.is_ascii_alphanumeric() {
                continue;
            }
        }
        let before = sink_text[..idx].trim_end();
        let Some(prefix) = before.strip_suffix('(') else {
            continue;
        };
        let helper = trailing_js_identifier(prefix)?;
        if !matches!(helper.as_str(), "String" | "Number" | "Boolean" | "BigInt") {
            return Some(helper);
        }
    }
    None
}

fn helper_wrapping_tainted_expression(value_text: &str) -> Option<String> {
    let interpolations = template_interpolations(value_text);
    if !interpolations.is_empty() {
        let mut helper: Option<String> = None;
        for expression in interpolations {
            let current = helper_wrapping_entire_expression(expression.trim())?;
            if helper.as_deref().is_some_and(|existing| existing != current) {
                return None;
            }
            helper = Some(current.to_string());
        }
        return helper;
    }
    helper_wrapping_entire_expression(value_text.trim()).map(str::to_string)
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

fn helper_wrapping_entire_expression(expression: &str) -> Option<&str> {
    let open = expression.find('(')?;
    let helper = expression[..open].trim();
    if !is_js_identifier(helper) {
        return None;
    }
    let lower = helper.to_ascii_lowercase();
    if !(lower.contains("escape") || lower.contains("encode") || lower.contains("sanitize")) {
        return None;
    }
    expression.trim_end().ends_with(')').then_some(helper)
}

fn trailing_js_identifier(text: &str) -> Option<String> {
    let mut chars = Vec::new();
    for ch in text.chars().rev() {
        if ch == '_' || ch == '$' || ch.is_ascii_alphanumeric() {
            chars.push(ch);
        } else {
            break;
        }
    }
    if chars.is_empty() {
        return None;
    }
    chars.reverse();
    let ident: String = chars.into_iter().collect();
    is_js_identifier(&ident).then_some(ident)
}

fn js_ts_local_function_body(lines: &[&str], helper: &str) -> Option<(usize, String)> {
    let function_needle = format!("function{helper}(");
    let const_needle = format!("const{helper}=");
    let let_needle = format!("let{helper}=");
    let var_needle = format!("var{helper}=");
    for (idx, line) in lines.iter().enumerate() {
        let compact = compact_guard_text(line);
        if !(compact.contains(&function_needle)
            || compact.starts_with(&const_needle)
            || compact.starts_with(&let_needle)
            || compact.starts_with(&var_needle)
            || compact.contains(&format!(".{helper}(")))
        {
            continue;
        }
        let mut body = String::new();
        let mut brace_depth = 0isize;
        let mut saw_open = false;
        for line in lines.iter().skip(idx).take(80) {
            body.push_str(line);
            body.push('\n');
            for ch in line.chars() {
                match ch {
                    '{' => {
                        saw_open = true;
                        brace_depth += 1;
                    }
                    '}' if saw_open => {
                        brace_depth -= 1;
                        if brace_depth <= 0 {
                            return Some((idx, body));
                        }
                    }
                    _ => {}
                }
            }
        }
        if saw_open {
            return Some((idx, body));
        }
    }
    None
}

fn js_ts_html_escape_helper_body_is_strong(body: &str, full_compact: &str) -> bool {
    let body_compact = compact_guard_text(body);
    let chained_replace = body_compact.contains(".replace(/&/g")
        && body_compact.contains(".replace(/</g")
        && body_compact.contains(".replace(/>/g");
    let char_class_replace =
        body_compact.contains(".replace(/[&<") && body_compact.contains("]/g") && body_compact.contains("=>");
    if !(chained_replace || char_class_replace) {
        return false;
    }
    let haystack = format!("{body_compact}{full_compact}");
    haystack.contains("&amp;")
        && haystack.contains("&lt;")
        && haystack.contains("&gt;")
        && (haystack.contains("&quot;") || haystack.contains("&#34;") || haystack.contains("&#x22;"))
        && (haystack.contains("&#39;") || haystack.contains("&apos;") || haystack.contains("&#x27;"))
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let decoder_var = assignment_target_for_source_call_at(&decl.flow_events, snk.span, "NewDecoder")
        .or_else(|| {
            lines
                .get(sink_idx)
                .and_then(|line| go_assignment_target_from_call_line(line, "NewDecoder"))
        })?;
    let end = (sink_idx + 48).min(lines.len());
    if sink_idx + 1 >= end {
        return None;
    }
    let tail = lines[sink_idx + 1..end].join("\n");
    let compact = compact_guard_text(&tail);
    let strict_true = compact.contains(&format!("{decoder_var}.Strict=true"));
    let charset_assign = compact.contains(&format!("{decoder_var}.CharsetReader=func("));
    let allowlist_reject = compact.contains("if!")
        && compact.contains("[charset]")
        && (compact.contains("returnnil,errors.New(") || compact.contains("returnnil,fmt.Errorf("));
    let returns_input = compact.contains("returninput,nil");
    if !(strict_true && charset_assign && allowlist_reject && returns_input) {
        return None;
    }
    let guard_idx = lines
        .iter()
        .enumerate()
        .skip(sink_idx + 1)
        .take(end.saturating_sub(sink_idx + 1))
        .find_map(|(idx, line)| line.contains(".CharsetReader").then_some(idx))
        .or_else(|| {
            lines
                .iter()
                .enumerate()
                .skip(sink_idx + 1)
                .take(end.saturating_sub(sink_idx + 1))
                .find_map(|(idx, line)| line.contains(".Strict").then_some(idx))
        })?;
    let guard_line = *lines.get(guard_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.go_xml_decoder_hardening".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(guard_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(guard_line) + 1).ok()?,
        text: guard_line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("xxe-sanitizer".to_string()),
        severity: None,
        category: Some("go-xml-decoder-hardening".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: Vec::new(),
    })
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let global = ws.db().global_index();
    let decl = global.decl_of(SymbolId::new(sink_func.raw()))?;
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let func_start = usize::try_from(span_map.line_col(decl.span.start).line.saturating_sub(1)).ok()?;
    let targets = ldap_tainted_filter_targets(sink_tainted_args);
    if targets.is_empty() {
        return None;
    }
    for target in targets {
        for idx in (func_start..sink_idx).rev() {
            let line = lines.get(idx).copied().unwrap_or_default();
            let Some(rhs) = assignment_rhs_for_target(line, &target, snk.language.as_str()) else {
                continue;
            };
            if ldap_rhs_uses_verified_escape(&snapshot.text, rhs) {
                return Some(FindingMatch {
                    rule_id: "engine.sanitizer.local_ldap_escape_helper".to_string(),
                    file: snk.file.clone(),
                    line: u32::try_from(idx + 1).ok()?,
                    column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
                    text: line.trim().to_string(),
                    enclosing_fn: snk.enclosing_fn.clone(),
                    tag: Some("ldap-escape".to_string()),
                    severity: None,
                    category: Some("local-rfc4515-escape-helper".to_string()),
                    trust: None,
                    payload_types: Vec::new(),
                    tainted_args: Vec::new(),
                    sanitised_arg_indices: sink_tainted_args
                        .iter()
                        .filter_map(|arg| u32::try_from(arg.index).ok())
                        .collect(),
                });
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

fn assignment_rhs_for_target<'a>(line: &'a str, target: &str, language: &str) -> Option<&'a str> {
    let trimmed = line.trim().trim_end_matches(';');
    if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    match language {
        "python" => {
            let (lhs, rhs) = trimmed.split_once('=')?;
            let lhs = lhs.split_once(':').map_or(lhs, |(name, _)| name).trim();
            (lhs == target).then_some(rhs.trim())
        }
        "javascript" | "typescript" => {
            let (lhs, rhs) = trimmed.split_once('=')?;
            let lhs = lhs
                .trim()
                .trim_start_matches("const ")
                .trim_start_matches("let ")
                .trim_start_matches("var ")
                .trim();
            (lhs == target).then_some(rhs.trim())
        }
        "go" => {
            let (lhs, rhs) = trimmed.split_once(":=").or_else(|| trimmed.split_once('='))?;
            let lhs = lhs.split_whitespace().last().unwrap_or_default();
            (lhs == target).then_some(rhs.trim())
        }
        _ => None,
    }
}

fn ldap_rhs_uses_verified_escape(full_text: &str, rhs: &str) -> bool {
    if rhs.contains("escape_filter_chars(")
        || rhs.contains("EscapeFilter(")
        || rhs.contains("escapeFilter(")
        || rhs.contains("ldapEscape.filter(")
    {
        return true;
    }
    if let Some((receiver, _)) = rhs.split_once(".Replace(") {
        let receiver = receiver
            .rsplit(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
            .next()
            .unwrap_or_default();
        if !receiver.is_empty() && ldap_replacer_declared_safe(full_text, receiver) {
            return true;
        }
    }
    call_names_outside_strings(rhs)
        .into_iter()
        .any(|helper| local_ldap_helper_declared_safe(full_text, &helper))
}

fn call_names_outside_strings(text: &str) -> Vec<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    let mut idx = 0usize;
    while idx < bytes.len() {
        let byte = bytes[idx];
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                idx += 1;
                continue;
            }
            if byte == b'\\' {
                escaped = true;
                idx += 1;
                continue;
            }
            if byte == q {
                quote = None;
            }
            idx += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' | b'`' => {
                quote = Some(byte);
                idx += 1;
            }
            b'(' => {
                let prefix = text[..idx].trim_end();
                let name = prefix
                    .rsplit(|ch: char| !(ch == '_' || ch == '$' || ch == '.' || ch.is_ascii_alphanumeric()))
                    .next()
                    .unwrap_or_default()
                    .rsplit('.')
                    .next()
                    .unwrap_or_default();
                if !name.is_empty() && !matches!(name, "String" | "str" | "bytes" | "int" | "float" | "len") {
                    out.push(name.to_string());
                }
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    out.sort();
    out.dedup();
    out
}

fn local_ldap_helper_declared_safe(full_text: &str, helper: &str) -> bool {
    if !ldap_escape_table_literals_present(full_text) {
        return false;
    }
    let compact = compact_guard_text(full_text);
    let helper_defs = [
        format!("def{helper}("),
        format!("function{helper}("),
        format!("func{helper}("),
        format!("const{helper}="),
        format!("let{helper}="),
    ];
    helper_defs.iter().any(|needle| compact.contains(needle))
        && (compact.contains(".get(ch,ch)")
            || compact.contains("ESCAPES[c]??c")
            || compact.contains("_LDAP_ESCAPES.get(ch,ch)")
            || compact.contains("map(c=>")
            || compact.contains("join(\"\")")
            || compact.contains("strings.NewReplacer("))
}

fn ldap_replacer_declared_safe(full_text: &str, receiver: &str) -> bool {
    if !ldap_escape_table_literals_present(full_text) {
        return false;
    }
    let compact = compact_guard_text(full_text);
    compact.contains(&format!("{receiver}=strings.NewReplacer("))
        || compact.contains(&format!("{receiver}:=strings.NewReplacer("))
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
    let snapshot = ws.vfs().snapshot(snk.span.file).ok()?;
    if !go_same_origin_helper_declared(&snapshot.text, &guard.helper) {
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

fn go_same_origin_helper_declared(full_text: &str, helper: &str) -> bool {
    let compact = compact_guard_text(full_text);
    compact.contains(&format!("func{helper}("))
        && (compact.contains("s[0]=='/'") || compact.contains("s[0]==\"/\""))
        && (compact.contains("s[1]!='/'") || compact.contains("s[1]!=\"/\""))
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
    let span_map = bonsai_common::cached_span_map_arc(snk.span.file, snapshot.version, &snapshot.text);
    let func_start = usize::try_from(span_map.line_col(decl.span.start).line.saturating_sub(1)).ok()?;
    let sink_idx = usize::try_from(snk.line.checked_sub(1)?).ok()?;
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let prior = lines.get(func_start..sink_idx)?.join("\n");
    let compact = compact_guard_text(&prior);
    let parsed_var = python_urlparse_assignment_var(&lines, func_start, sink_idx, &target)?;
    let scheme_guard = compact.contains(&format!("{parsed_var}.scheme!=\"https\""))
        || compact.contains(&format!("\"https\"!={parsed_var}.scheme"));
    let host_allowlist = compact.contains(&format!("{parsed_var}.hostname"))
        && (compact.contains("notinALLOWED")
            || compact.contains("notinallowed")
            || compact.contains("notinALLOWED_HOSTS")
            || compact.contains("notinallowed_hosts"));
    let dns_lookup = compact.contains(&format!("getaddrinfo({parsed_var}.hostname"));
    let private_ip_reject = compact.contains("is_private")
        && compact.contains("is_loopback")
        && compact.contains("is_link_local");
    let redirects_disabled = compact.contains("follow_redirects=False");
    if !(scheme_guard && host_allowlist && dns_lookup && private_ip_reject && redirects_disabled) {
        return None;
    }
    let guard_idx = lines
        .iter()
        .enumerate()
        .skip(func_start)
        .take(sink_idx.saturating_sub(func_start))
        .find_map(|(idx, line)| (line.contains(".scheme") && line.contains("https")).then_some(idx))?;
    let line = lines.get(guard_idx)?;
    Some(FindingMatch {
        rule_id: "engine.sanitizer.python_url_ssrf_guard".to_string(),
        file: snk.file.clone(),
        line: u32::try_from(guard_idx + 1).ok()?,
        column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
        text: line.trim().to_string(),
        enclosing_fn: snk.enclosing_fn.clone(),
        tag: Some("ssrf-sanitize".to_string()),
        severity: None,
        category: Some("url-scheme-host-private-ip-guard".to_string()),
        trust: None,
        payload_types: Vec::new(),
        tainted_args: Vec::new(),
        sanitised_arg_indices: sink_tainted_args
            .iter()
            .filter_map(|arg| u32::try_from(arg.index).ok())
            .collect(),
    })
}

fn python_urlparse_assignment_var(lines: &[&str], start: usize, end: usize, target: &str) -> Option<String> {
    for line in lines.iter().take(end).skip(start) {
        let trimmed = line.trim();
        let Some((lhs, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        let lhs = lhs.trim();
        let rhs_compact = compact_guard_text(rhs);
        if rhs_compact == format!("urlparse({target})")
            || rhs_compact == format!("urllib.parse.urlparse({target})")
        {
            return clean_overwrite_target_key(lhs);
        }
    }
    None
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
                && source_call
                    .as_deref()
                    .is_some_and(|call| clean_overwrite_callee_tail(call).ends_with(call_tail)) =>
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

fn go_assignment_target_from_call_line(line: &str, call_tail: &str) -> Option<String> {
    if !line.contains(call_tail) {
        return None;
    }
    let (lhs, _) = line.split_once(":=").or_else(|| line.split_once('='))?;
    clean_overwrite_target_key(lhs.trim())
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
                    matches!(clean_overwrite_callee_tail(call).as_str(), "URL" | "URI")
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

fn python_dev_only_env_guard_line(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with("if ") || !trimmed.ends_with(':') {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
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

fn python_guard_exits_before_target(
    lines: &[&str],
    guard_idx: usize,
    target_idx: usize,
    guard_indent: usize,
    target_indent: usize,
) -> bool {
    let mut saw_exit = false;
    let mut saw_dedent_after_exit = false;
    for line in lines.iter().take(target_idx).skip(guard_idx + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_ascii_whitespace(line);
        if !saw_exit {
            if indent <= guard_indent {
                return false;
            }
            if python_line_exits_scope(trimmed) {
                saw_exit = true;
            }
            continue;
        }
        if indent <= guard_indent {
            saw_dedent_after_exit = true;
            break;
        }
    }
    saw_exit && (saw_dedent_after_exit || target_indent <= guard_indent)
}

fn python_line_exits_scope(trimmed: &str) -> bool {
    let compact = compact_guard_text(trimmed);
    trimmed.starts_with("return")
        || trimmed.starts_with("raise")
        || trimmed.starts_with("abort(")
        || trimmed.starts_with("flask.abort(")
        || compact.contains(";return")
        || compact.contains(";raise")
        || compact.contains(";abort(")
        || compact.contains(";flask.abort(")
}

fn leading_ascii_whitespace(line: &str) -> usize {
    line.as_bytes()
        .iter()
        .take_while(|byte| matches!(byte, b' ' | b'\t'))
        .count()
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
    let lines: Vec<&str> = snapshot.text.lines().collect();
    let target_idx = usize::try_from(sink.line.checked_sub(1)?).ok()?;
    let target_line = *lines.get(target_idx)?;
    let target_indent = leading_ascii_whitespace(target_line);
    for arg in tainted_args {
        let Some((map_name, key_name)) = python_index_lookup_parts(&arg.value_text) else {
            continue;
        };
        if !python_literal_mapping_declared_before(&lines, target_idx, map_name) {
            continue;
        }
        let search_start = target_idx.saturating_sub(30);
        for (idx, line) in lines
            .iter()
            .copied()
            .enumerate()
            .take(target_idx)
            .skip(search_start)
        {
            if leading_ascii_whitespace(line) > target_indent {
                continue;
            }
            if !python_assignment_narrows_key_to_map(line, key_name, map_name) {
                continue;
            }
            return Some(FindingMatch {
                rule_id: "engine.sanitizer.literal_map_key_allowlist".to_string(),
                file: sink.file.clone(),
                line: u32::try_from(idx + 1).ok()?,
                column: u32::try_from(leading_ascii_whitespace(line) + 1).ok()?,
                text: line.trim().to_string(),
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

fn python_literal_mapping_declared_before(lines: &[&str], target_idx: usize, map_name: &str) -> bool {
    let max_idx = target_idx.min(lines.len());
    lines.iter().take(max_idx).any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with(map_name)
            && trimmed.contains('=')
            && trimmed
                .split_once('=')
                .is_some_and(|(_, rhs)| rhs.trim_start().starts_with('{'))
    })
}

fn python_assignment_narrows_key_to_map(line: &str, key_name: &str, map_name: &str) -> bool {
    let trimmed = line.trim();
    let Some((lhs, rhs)) = trimmed.split_once('=') else {
        return false;
    };
    let lhs = lhs.trim();
    let lhs_name = lhs.rsplit_once(':').map_or(lhs, |(name, _)| name).trim();
    if lhs_name != key_name {
        return false;
    }
    let rhs = rhs.trim();
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
