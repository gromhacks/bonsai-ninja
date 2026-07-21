//! Compiler-fact validation for prototype-pollution guards.
//!
//! The matcher deliberately treats dynamic writes and recursive merge calls
//! broadly.  This module suppresses a sink only when the enclosing structured
//! flow proves that every path reaching it passed a denylist barrier (or a
//! preceding `Object.freeze(Object.prototype)` call).  Source lines and
//! enclosing text are never scanned.

#[allow(clippy::wildcard_imports)]
use super::*;

const DANGEROUS_KEYS: &[&str] = &["__proto__", "constructor", "prototype"];

pub(super) fn prototype_pollution_sink_is_guarded(
    ws: &Workspace,
    sink_rule: &Rule,
    sink: &RuleMatch,
) -> bool {
    if sink_rule.tag.as_deref() != Some("prototype-pollution")
        || !matches!(sink.language.as_str(), "javascript" | "typescript")
    {
        return false;
    }
    let Some(file_index) = ws.exact_decl_index(sink.span.file) else {
        return false;
    };
    let Some(decl) = file_index
        .defs
        .iter()
        .filter(|decl| span_contains(decl.body_span.unwrap_or(decl.span), sink.span))
        .min_by_key(|decl| decl.span.len())
    else {
        return false;
    };
    let Some(call) = find_call_event_at(&decl.flow_events, sink.span) else {
        return false;
    };
    let FlowEvent::Call { span: call_span, .. } = call else {
        return false;
    };
    let key_variables = prototype_sink_key_variables(call);
    if key_variables.is_empty() {
        return false;
    }
    let mut guarded = false;
    flow_guard_state_at_sink(&decl.flow_events, *call_span, &key_variables, &mut guarded) && guarded
}

fn prototype_sink_key_variables(call: &FlowEvent) -> AHashSet<String> {
    let FlowEvent::Call { name, args, .. } = call else {
        return AHashSet::new();
    };
    if clean_overwrite_callee_tail(name) == "__setitem__" {
        return args
            .first()
            .into_iter()
            .flat_map(|arg| arg.place.iter().chain(arg.source_names.iter()))
            .filter_map(|name| simple_place_key(name))
            .collect();
    }

    // Recursive merge rules require two indexed arguments.  The adapters
    // expose the index operand as the one simple source name shared by both
    // argument expressions; bases and normalized projections are excluded.
    let mut occurrences: AHashMap<String, usize> = AHashMap::new();
    for arg in args {
        let place = arg.place.as_deref().and_then(clean_overwrite_target_key);
        let base = place.as_deref().and_then(|place| place.split('.').next());
        let mut seen = AHashSet::new();
        for source in &arg.source_names {
            let Some(source) = simple_place_key(source) else {
                continue;
            };
            if Some(source.as_str()) == base || !seen.insert(source.clone()) {
                continue;
            }
            *occurrences.entry(source).or_default() += 1;
        }
    }
    occurrences
        .into_iter()
        .filter_map(|(name, count)| (count >= 2).then_some(name))
        .collect()
}

fn simple_place_key(text: &str) -> Option<String> {
    let key = clean_overwrite_target_key(text)?;
    (!key.contains('.')).then_some(key)
}

fn flow_guard_state_at_sink(
    events: &[FlowEvent],
    sink_span: Span,
    key_variables: &AHashSet<String>,
    guarded: &mut bool,
) -> bool {
    for event in events {
        if event.span() == sink_span {
            return true;
        }
        match event {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } if flow_events_have_exact_span(then_events, sink_span)
                || flow_events_have_exact_span(else_events, sink_span) =>
            {
                let target_events = if flow_events_have_exact_span(then_events, sink_span) {
                    then_events
                } else {
                    else_events
                };
                return flow_guard_state_at_sink(target_events, sink_span, key_variables, guarded);
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. }
                if flow_events_have_exact_span(body, sink_span) =>
            {
                return flow_guard_state_at_sink(body, sink_span, key_variables, guarded);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                for nested in [
                    body.as_slice(),
                    catch_events.as_slice(),
                    finally_events.as_slice(),
                ] {
                    if flow_events_have_exact_span(nested, sink_span) {
                        return flow_guard_state_at_sink(nested, sink_span, key_variables, guarded);
                    }
                }
            }
            _ => {}
        }
        if event.span().start >= sink_span.start {
            continue;
        }
        apply_guard_event(event, key_variables, guarded);
    }
    false
}

fn flow_events_have_exact_span(events: &[FlowEvent], target: Span) -> bool {
    events.iter().any(|event| {
        event.span() == target
            || match event {
                FlowEvent::Branch {
                    then_events,
                    else_events,
                    ..
                } => {
                    flow_events_have_exact_span(then_events, target)
                        || flow_events_have_exact_span(else_events, target)
                }
                FlowEvent::Loop { body, .. }
                | FlowEvent::Defer { body, .. }
                | FlowEvent::Using { body, .. } => flow_events_have_exact_span(body, target),
                FlowEvent::Try {
                    body,
                    catch_events,
                    finally_events,
                    ..
                } => {
                    flow_events_have_exact_span(body, target)
                        || flow_events_have_exact_span(catch_events, target)
                        || flow_events_have_exact_span(finally_events, target)
                }
                _ => false,
            }
    })
}

fn apply_guard_events(events: &[FlowEvent], key_variables: &AHashSet<String>, guarded: &mut bool) {
    for event in events {
        apply_guard_event(event, key_variables, guarded);
    }
}

fn apply_guard_event(event: &FlowEvent, key_variables: &AHashSet<String>, guarded: &mut bool) {
    match event {
        FlowEvent::Call {
            name, receiver, args, ..
        } if clean_overwrite_callee_tail(name) == "freeze"
            && receiver.as_deref() == Some("Object")
            && args.len() == 1
            && args[0].place.as_deref() == Some("Object.prototype") =>
        {
            *guarded = true;
        }
        FlowEvent::Branch {
            condition,
            then_events,
            else_events,
            ..
        } => {
            if condition
                .as_deref()
                .is_some_and(|condition| branch_rejects_dangerous_key(condition, then_events, key_variables))
            {
                *guarded = true;
                return;
            }
            let mut then_guarded = *guarded;
            apply_guard_events(then_events, key_variables, &mut then_guarded);
            let mut else_guarded = *guarded;
            apply_guard_events(else_events, key_variables, &mut else_guarded);
            *guarded = then_guarded && else_guarded;
        }
        FlowEvent::Loop { .. } | FlowEvent::Defer { .. } => {
            // These regions are not guaranteed to execute before a later sink.
        }
        FlowEvent::Using { body, .. } => apply_guard_events(body, key_variables, guarded),
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => {
            let mut body_guarded = *guarded;
            apply_guard_events(body, key_variables, &mut body_guarded);
            let mut catch_guarded = *guarded;
            apply_guard_events(catch_events, key_variables, &mut catch_guarded);
            *guarded = body_guarded && catch_guarded;
            apply_guard_events(finally_events, key_variables, guarded);
        }
        _ => {}
    }
}

fn branch_rejects_dangerous_key(
    condition: &str,
    then_events: &[FlowEvent],
    key_variables: &AHashSet<String>,
) -> bool {
    if !then_events.iter().any(|event| {
        matches!(
            event,
            FlowEvent::Continue { .. } | FlowEvent::Return { .. } | FlowEvent::Throw { .. }
        )
    }) {
        return false;
    }
    let compact: String = condition.chars().filter(|ch| !ch.is_whitespace()).collect();
    key_variables
        .iter()
        .any(|key| prototype_key_denylist_condition(&compact, key))
}

fn prototype_key_denylist_condition(compact: &str, key: &str) -> bool {
    let compares_all = DANGEROUS_KEYS
        .iter()
        .all(|dangerous| prototype_key_compare_present(compact, key, dangerous));
    if compares_all {
        return true;
    }
    DANGEROUS_KEYS.iter().all(|dangerous| {
        compact.contains(&format!(r#""{dangerous}""#)) || compact.contains(&format!("'{dangerous}'"))
    }) && (compact.contains(&format!(".includes({key})")) || compact.contains(&format!(".has({key})")))
}

fn prototype_key_compare_present(compact: &str, key: &str, dangerous: &str) -> bool {
    [
        format!(r#"{key}==="{dangerous}""#),
        format!(r#"{key}=="{dangerous}""#),
        format!(r#""{dangerous}"==={key}"#),
        format!(r#""{dangerous}"=={key}"#),
        format!("{key}==='{dangerous}'"),
        format!("{key}=='{dangerous}'"),
        format!("'{dangerous}'==={key}"),
        format!("'{dangerous}'=={key}"),
    ]
    .iter()
    .any(|needle| compact.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_lang_api::{ArgumentPassingMode, CallArg, CallKind, LoopKind};

    fn span(start: u64, end: u64) -> Span {
        Span::new(FileId::new(0), start, end)
    }

    fn arg(arg_span: Span, value: &str, place: Option<&str>, sources: &[&str]) -> CallArg {
        CallArg {
            span: arg_span,
            passing_mode: ArgumentPassingMode::Value,
            name: None,
            value_text: value.to_string(),
            place: place.map(str::to_string),
            source_names: sources.iter().map(|source| (*source).to_string()).collect(),
        }
    }

    fn call(call_span: Span, name: &str, receiver: Option<&str>, args: Vec<CallArg>) -> FlowEvent {
        FlowEvent::Call {
            span: call_span,
            name: name.to_string(),
            receiver: receiver.map(str::to_string),
            receiver_types: Vec::new(),
            call_kind: CallKind::Method,
            args,
        }
    }

    fn dynamic_write(call_span: Span) -> FlowEvent {
        call(
            call_span,
            "target.__setitem__",
            Some("target"),
            vec![
                arg(
                    span(call_span.start + 1, call_span.start + 2),
                    "key",
                    Some("key"),
                    &["key"],
                ),
                arg(
                    span(call_span.start + 3, call_span.end),
                    "source[key]",
                    Some("source.key"),
                    &["source", "key", "source.key"],
                ),
            ],
        )
    }

    #[test]
    fn denylist_branch_guards_only_its_structured_index_variable() {
        let sink_span = span(80, 100);
        let sink = dynamic_write(sink_span);
        let keys = prototype_sink_key_variables(&sink);
        assert_eq!(keys, AHashSet::from_iter(["key".to_string()]));
        let events = vec![FlowEvent::Loop {
            span: span(0, 110),
            loop_kind: LoopKind::ForEach,
            body: vec![
                FlowEvent::Branch {
                    span: span(10, 70),
                    condition: Some(
                        r#"key === "__proto__" || key === "constructor" || key === "prototype""#.to_string(),
                    ),
                    then_events: vec![FlowEvent::Continue {
                        span: span(60, 68),
                        label: None,
                    }],
                    else_events: Vec::new(),
                },
                sink,
            ],
        }];
        let mut guarded = false;

        assert!(flow_guard_state_at_sink(&events, sink_span, &keys, &mut guarded));
        assert!(guarded);
    }

    #[test]
    fn conditional_freeze_does_not_guard_all_paths() {
        let sink_span = span(80, 100);
        let sink = dynamic_write(sink_span);
        let keys = prototype_sink_key_variables(&sink);
        let freeze = call(
            span(20, 40),
            "Object.freeze",
            Some("Object"),
            vec![arg(
                span(30, 39),
                "Object.prototype",
                Some("Object.prototype"),
                &[],
            )],
        );
        let events = vec![
            FlowEvent::Branch {
                span: span(10, 60),
                condition: Some("flag".to_string()),
                then_events: vec![freeze],
                else_events: Vec::new(),
            },
            sink,
        ];
        let mut guarded = false;

        assert!(flow_guard_state_at_sink(&events, sink_span, &keys, &mut guarded));
        assert!(!guarded);
    }
}
