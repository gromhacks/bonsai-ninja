//! Shared test helpers used by every per-language construct test file.
//!
//! Each `lang_<name>.rs` pulls this in via `#[path = "lang_common.rs"]` so
//! the helpers live in one place. Keep them syntax-agnostic — anything
//! grammar-specific belongs in the adapter's `GrammarHandler` or the per-
//! language test itself.

#![allow(dead_code, unreachable_pub)]

use bonsai_lang_api::{AdapterArc, DeclKind, FlowEvent, LanguageRegistry, LoopKind, RefKind};
use bonsai_workspace::Workspace;
use std::sync::Arc;

/// Build a single-file workspace with the given adapter + ingest one file.
pub fn ws(adapter: AdapterArc, path: &str, src: &str) -> Workspace {
    let registry = Arc::new(LanguageRegistry::new());
    registry.register(adapter);
    let ws = Workspace::new(registry);
    ws.vfs().write(path.to_string(), Arc::<str>::from(src));
    for f in ws.vfs().all_files() {
        let _ = ws.db().decl_index(f);
    }
    ws
}

/// Find the first decl whose short name equals `name`.
pub fn decl(ws: &Workspace, name: &str) -> Option<bonsai_lang_api::Decl> {
    let global = ws.db().global_index();
    global
        .find_by_name(name)
        .iter()
        .find_map(|s| global.decl_of(*s).cloned())
}

pub fn function_exists(ws: &Workspace, name: &str) -> bool {
    decl(ws, name).is_some_and(|d| {
        matches!(
            d.kind,
            DeclKind::Function | DeclKind::Method | DeclKind::Constructor
        )
    })
}

pub fn class_exists(ws: &Workspace, name: &str) -> bool {
    decl(ws, name).is_some_and(|d| {
        matches!(
            d.kind,
            DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
        )
    })
}

pub fn ctor_exists(ws: &Workspace, name: &str) -> bool {
    decl(ws, name).is_some_and(|d| matches!(d.kind, DeclKind::Constructor))
}

/// Walk every function's flow events looking for a specific event type.
fn walk<F: FnMut(&FlowEvent)>(events: &[FlowEvent], f: &mut F) {
    for e in events {
        f(e);
        match e {
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                walk(then_events, f);
                walk(else_events, f);
            }
            FlowEvent::Loop { body, .. } => walk(body, f),
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                walk(body, f);
                walk(catch_events, f);
                walk(finally_events, f);
            }
            FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => walk(body, f),
            _ => {}
        }
    }
}

/// Does `fn_name`'s body contain a Call event whose callee name matches
/// either exactly or as a qualified path tail (`a.b.foo` matches `foo`)?
pub fn has_call(ws: &Workspace, fn_name: &str, target: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Call { name, .. } = e {
            if name == target
                || name.ends_with(&format!(".{target}"))
                || name.ends_with(&format!("::{target}"))
            {
                hit = true;
            }
        }
    });
    hit
}

/// Does `fn_name`'s body contain a call event whose callee name contains
/// the given substring? Useful for fully-qualified assertions where the
/// grammar captures the whole expression (e.g. `os.system`).
pub fn has_call_containing(ws: &Workspace, fn_name: &str, needle: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Call { name, .. } = e {
            if name.contains(needle) {
                hit = true;
            }
        }
    });
    hit
}

pub fn has_branch(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Branch { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn branch_arm_has_call(ws: &Workspace, fn_name: &str, target: &str, want_else: bool) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } = e
        {
            let arm = if want_else { else_events } else { then_events };
            walk(arm, &mut |inner| {
                if let FlowEvent::Call { name, .. } = inner {
                    if name == target
                        || name.ends_with(&format!(".{target}"))
                        || name.ends_with(&format!("::{target}"))
                    {
                        hit = true;
                    }
                }
            });
        }
    });
    hit
}

pub fn has_loop(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Loop { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_loop_of(ws: &Workspace, fn_name: &str, want: LoopKind) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Loop { loop_kind, .. } = e {
            if *loop_kind == want {
                hit = true;
            }
        }
    });
    hit
}

pub fn has_assign(ws: &Workspace, fn_name: &str, target: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Assign { target: t, .. } = e {
            if t == target || t.contains(target) {
                hit = true;
            }
        }
    });
    hit
}

pub fn has_return(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Return { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_throw(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Throw { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_try(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Try { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_catch(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Try { catch_events, .. } = e {
            if !catch_events.is_empty() {
                hit = true;
            }
        }
    });
    hit
}

pub fn has_finally(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if let FlowEvent::Try { finally_events, .. } = e {
            if !finally_events.is_empty() {
                hit = true;
            }
        }
    });
    hit
}

pub fn has_break(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Break { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_continue(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Continue { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_yield(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Yield { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_await(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Await { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_defer(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Defer { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_using(ws: &Workspace, fn_name: &str) -> bool {
    let Some(d) = decl(ws, fn_name) else {
        return false;
    };
    let mut hit = false;
    walk(&d.flow_events, &mut |e| {
        if matches!(e, FlowEvent::Using { .. }) {
            hit = true;
        }
    });
    hit
}

pub fn has_decorator(ws: &Workspace, name: &str) -> bool {
    let global = ws.db().global_index();
    for f in global.all_files() {
        if let Some(idx) = global.file_index(f) {
            for r in &idx.refs {
                if r.kind == RefKind::Decorator && (r.name == name || r.name.contains(name)) {
                    return true;
                }
            }
        }
    }
    false
}

/// Does any file in the workspace carry an import whose module text contains
/// `needle`? Imports are extracted generically from the top-level import/use/
/// include statements, so we match by substring to tolerate quoting and
/// alias syntax.
pub fn has_import(ws: &Workspace, needle: &str) -> bool {
    let global = ws.db().global_index();
    for f in global.all_files() {
        let Ok(parsed) = ws.db().parse(f) else { continue };
        let Some(snap) = ws.vfs().snapshot(f).ok() else {
            continue;
        };
        let imports = bonsai_lang_api::kit::extract_generic_imports(&parsed.tree, f, snap.text.as_bytes());
        if imports.iter().any(|imp| imp.module.contains(needle)) {
            return true;
        }
    }
    false
}

/// Does any import carry the given alias?
pub fn has_import_alias(ws: &Workspace, module_sub: &str, alias: &str) -> bool {
    let global = ws.db().global_index();
    for f in global.all_files() {
        let Ok(parsed) = ws.db().parse(f) else { continue };
        let Some(snap) = ws.vfs().snapshot(f).ok() else {
            continue;
        };
        let imports = bonsai_lang_api::kit::extract_generic_imports(&parsed.tree, f, snap.text.as_bytes());
        if imports
            .iter()
            .any(|imp| imp.module.contains(module_sub) && imp.alias.as_deref() == Some(alias))
        {
            return true;
        }
    }
    false
}

/// Is there a wildcard import that targets the given module substring?
pub fn has_wildcard_import(ws: &Workspace, module_sub: &str) -> bool {
    let global = ws.db().global_index();
    for f in global.all_files() {
        let Ok(parsed) = ws.db().parse(f) else { continue };
        let Some(snap) = ws.vfs().snapshot(f).ok() else {
            continue;
        };
        let imports = bonsai_lang_api::kit::extract_generic_imports(&parsed.tree, f, snap.text.as_bytes());
        if imports
            .iter()
            .any(|imp| imp.is_wildcard && imp.module.contains(module_sub))
        {
            return true;
        }
    }
    false
}

pub fn params_of(ws: &Workspace, fn_name: &str) -> Vec<String> {
    decl(ws, fn_name).map(|d| d.params.clone()).unwrap_or_default()
}

pub fn param_annotations_of(ws: &Workspace, fn_name: &str) -> Vec<Vec<String>> {
    decl(ws, fn_name)
        .map(|d| d.param_annotations.clone())
        .unwrap_or_default()
}
