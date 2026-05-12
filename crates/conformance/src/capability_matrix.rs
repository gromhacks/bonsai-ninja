//! Per-language capability matrix.
//!
//! Spec §31 (engine improvement plan, Phase 0). Enumerates the fact
//! slots each adapter is expected to populate so a single conformance
//! run can show — for every (capability, language) — whether the slot
//! is reliably emitted on a representative fixture. The matrix is the
//! source of truth subsequent phases gate on: phase 1 must move
//! "receiver_types" cells to ✅ for all 21 languages; phase 5 introduces
//! a new "literal_rhs" capability; etc.
//!
//! The matrix runs as a regular `#[test]` (`capability_matrix_report`)
//! that emits a Markdown report at `build/capability-matrix.md` and a
//! JSON shape at `build/capability-matrix.json`. The same module also
//! exposes per-capability assertions so individual fixtures can target
//! a single slot.

use bonsai_lang_api::{Decl, DeclKind, FlowEvent, LanguageAdapter};
use bonsai_workspace::Workspace;
use std::path::PathBuf;
use std::sync::Arc;

/// One slot the adapter is expected to fill. Adding a new variant
/// adds a column to the report; phase rollouts use this to mark
/// "this language must support this capability before merge".
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// `Decl::params` records parameter names for at least one
    /// function in the fixture.
    ParamNames,
    /// `Decl::param_annotations` records at least one annotation on
    /// a parameter in the fixture.
    ParamAnnotations,
    /// `Decl::receiver_param_index` is set on at least one
    /// declaration whose source surface has an explicit `self` /
    /// `this` parameter binding.
    ReceiverParamIndex,
    /// `Decl::bases` is non-empty on at least one subclass.
    Bases,
    /// `Decl::receiver_field_writes` records at least one
    /// `this.field = …` style write.
    ReceiverFieldWrites,
    /// `Decl::implicit_receiver_names` records the language's
    /// implicit-receiver tokens.
    ImplicitReceiverNames,
    /// `Decl::type_aliases` records at least one `let x: T` /
    /// `var x: T` style type binding.
    TypeAliases,
    /// `Decl::has_implicit_returns` is set on at least one fixture
    /// decl in languages where the final expression is the return
    /// value (rust / ruby / scala / kotlin / elixir / lua).
    ImplicitReturns,
    /// At least one `FlowEvent::Call` carries a non-empty
    /// `receiver_types` vec. This is the Phase 1 gate.
    CallReceiverTypes,
    /// At least one `FlowEvent::Assign` records `source_call`,
    /// meaning the adapter recognised the RHS as a call expression.
    AssignSourceCall,
    /// At least one `FlowEvent::Assign` records non-empty
    /// `source_names` for a compound RHS.
    AssignSourceNames,
    /// At least one `FlowEvent::Return` records `value_name` for a
    /// bare-name return.
    ReturnValueName,
    /// `FlowEvent::Branch` emitted at all (if / else / match-style).
    BranchEvents,
    /// `FlowEvent::Loop` emitted at all (for / while / each).
    LoopEvents,
    /// `FlowEvent::Try` emitted on languages with exception handling.
    TryEvents,
}

impl Capability {
    pub const ALL: &'static [Capability] = &[
        Capability::ParamNames,
        Capability::ParamAnnotations,
        Capability::ReceiverParamIndex,
        Capability::Bases,
        Capability::ReceiverFieldWrites,
        Capability::ImplicitReceiverNames,
        Capability::TypeAliases,
        Capability::ImplicitReturns,
        Capability::CallReceiverTypes,
        Capability::AssignSourceCall,
        Capability::AssignSourceNames,
        Capability::ReturnValueName,
        Capability::BranchEvents,
        Capability::LoopEvents,
        Capability::TryEvents,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Capability::ParamNames => "param_names",
            Capability::ParamAnnotations => "param_annotations",
            Capability::ReceiverParamIndex => "receiver_param_index",
            Capability::Bases => "bases",
            Capability::ReceiverFieldWrites => "receiver_field_writes",
            Capability::ImplicitReceiverNames => "implicit_receiver_names",
            Capability::TypeAliases => "type_aliases",
            Capability::ImplicitReturns => "implicit_returns",
            Capability::CallReceiverTypes => "call_receiver_types",
            Capability::AssignSourceCall => "assign_source_call",
            Capability::AssignSourceNames => "assign_source_names",
            Capability::ReturnValueName => "return_value_name",
            Capability::BranchEvents => "branch_events",
            Capability::LoopEvents => "loop_events",
            Capability::TryEvents => "try_events",
        }
    }
}

/// A capability either appears, doesn't, or is intentionally
/// inapplicable for the language (Erlang has no classes, Lua has no
/// `try` keyword, etc.). `NotApplicable` cells aren't gating in CI.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CellStatus {
    Supported,
    Missing,
    NotApplicable,
}

impl CellStatus {
    pub fn glyph(self) -> &'static str {
        match self {
            CellStatus::Supported => "✅",
            CellStatus::Missing => "❌",
            CellStatus::NotApplicable => "—",
        }
    }
}

/// A single (language, capability) report cell.
#[derive(Clone, Debug)]
pub struct Cell {
    pub language: String,
    pub capability: Capability,
    pub status: CellStatus,
}

/// Adapter + fixture text + per-capability inapplicability hints.
/// The hints list lets a language declare "I don't have try" or
/// "Erlang has no classes" so the matrix shows `—` rather than `❌`.
pub struct CapabilityProbe {
    pub adapter: Arc<dyn LanguageAdapter>,
    pub fixture_path: &'static str,
    pub fixture_source: &'static str,
    /// Capabilities that don't apply to this language.
    pub not_applicable: &'static [Capability],
}

/// Probe one adapter against its fixture. Returns one Cell per
/// capability declared on the probe.
pub fn probe(probe: &CapabilityProbe) -> Vec<Cell> {
    let ws = single_file_workspace(probe);
    let global = ws.db().global_index();
    let mut decls: Vec<Decl> = Vec::new();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            decls.push(decl.clone());
        }
    }
    let lang = probe.adapter.language_id().as_str().to_string();
    Capability::ALL
        .iter()
        .copied()
        .map(|cap| {
            let status = if probe.not_applicable.contains(&cap) {
                CellStatus::NotApplicable
            } else if capability_is_supported(cap, &decls) {
                CellStatus::Supported
            } else {
                CellStatus::Missing
            };
            Cell {
                language: lang.clone(),
                capability: cap,
                status,
            }
        })
        .collect()
}

fn single_file_workspace(probe: &CapabilityProbe) -> Workspace {
    let fixtures: Vec<(&str, &str)> = vec![(probe.fixture_path, probe.fixture_source)];
    bonsai_testkit::workspace_with(vec![probe.adapter.clone()], &fixtures)
}

fn capability_is_supported(cap: Capability, decls: &[Decl]) -> bool {
    match cap {
        Capability::ParamNames => decls.iter().any(|d| !d.params.is_empty()),
        Capability::ParamAnnotations => decls
            .iter()
            .any(|d| d.param_annotations.iter().any(|annots| !annots.is_empty())),
        Capability::ReceiverParamIndex => decls.iter().any(|d| d.receiver_param_index.is_some()),
        Capability::Bases => decls
            .iter()
            .any(|d| matches!(d.kind, DeclKind::Class) && !d.bases.is_empty()),
        Capability::ReceiverFieldWrites => decls.iter().any(|d| !d.receiver_field_writes.is_empty()),
        Capability::ImplicitReceiverNames => decls.iter().any(|d| !d.implicit_receiver_names.is_empty()),
        Capability::TypeAliases => decls.iter().any(|d| !d.type_aliases.is_empty()),
        Capability::ImplicitReturns => decls.iter().any(|d| d.has_implicit_returns),
        Capability::CallReceiverTypes => decls
            .iter()
            .any(|d| flow_events_have_call_receiver_types(&d.flow_events)),
        Capability::AssignSourceCall => decls
            .iter()
            .any(|d| flow_events_have_assign_source_call(&d.flow_events)),
        Capability::AssignSourceNames => decls
            .iter()
            .any(|d| flow_events_have_assign_source_names(&d.flow_events)),
        Capability::ReturnValueName => decls
            .iter()
            .any(|d| flow_events_have_return_value_name(&d.flow_events)),
        Capability::BranchEvents => decls
            .iter()
            .any(|d| flow_events_contain(&d.flow_events, |e| matches!(e, FlowEvent::Branch { .. }))),
        Capability::LoopEvents => decls
            .iter()
            .any(|d| flow_events_contain(&d.flow_events, |e| matches!(e, FlowEvent::Loop { .. }))),
        Capability::TryEvents => decls
            .iter()
            .any(|d| flow_events_contain(&d.flow_events, |e| matches!(e, FlowEvent::Try { .. }))),
    }
}

fn flow_events_contain(events: &[FlowEvent], pred: impl Fn(&FlowEvent) -> bool + Copy) -> bool {
    for ev in events {
        if pred(ev) {
            return true;
        }
        if let Some(nested) = nested_event_groups(ev) {
            for group in nested {
                if flow_events_contain(group, pred) {
                    return true;
                }
            }
        }
    }
    false
}

fn flow_events_have_call_receiver_types(events: &[FlowEvent]) -> bool {
    flow_events_contain(events, |e| match e {
        FlowEvent::Call { receiver_types, .. } => !receiver_types.is_empty(),
        _ => false,
    })
}

fn flow_events_have_assign_source_call(events: &[FlowEvent]) -> bool {
    flow_events_contain(events, |e| match e {
        FlowEvent::Assign { source_call, .. } => source_call.is_some(),
        _ => false,
    })
}

fn flow_events_have_assign_source_names(events: &[FlowEvent]) -> bool {
    flow_events_contain(events, |e| match e {
        FlowEvent::Assign { source_names, .. } => !source_names.is_empty(),
        _ => false,
    })
}

fn flow_events_have_return_value_name(events: &[FlowEvent]) -> bool {
    flow_events_contain(events, |e| match e {
        FlowEvent::Return { value_name, .. } => value_name.is_some(),
        _ => false,
    })
}

fn nested_event_groups(event: &FlowEvent) -> Option<Vec<&[FlowEvent]>> {
    match event {
        FlowEvent::Branch {
            then_events,
            else_events,
            ..
        } => Some(vec![then_events.as_slice(), else_events.as_slice()]),
        FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
            Some(vec![body.as_slice()])
        }
        FlowEvent::Try {
            body,
            catch_events,
            finally_events,
            ..
        } => Some(vec![
            body.as_slice(),
            catch_events.as_slice(),
            finally_events.as_slice(),
        ]),
        _ => None,
    }
}

/// Render a matrix to Markdown. Rows are languages, columns are
/// capabilities. The cell glyph mirrors `CellStatus::glyph`.
#[must_use]
pub fn render_markdown(cells: &[Cell]) -> String {
    use std::collections::BTreeMap;
    let mut by_lang: BTreeMap<String, BTreeMap<Capability, CellStatus>> = BTreeMap::new();
    for cell in cells {
        by_lang
            .entry(cell.language.clone())
            .or_default()
            .insert(cell.capability, cell.status);
    }
    let mut out = String::new();
    out.push_str("# Capability Matrix\n\n");
    out.push_str("Generated by `bonsai_conformance::capability_matrix`.\n\n");
    out.push_str("| language |");
    for cap in Capability::ALL {
        out.push(' ');
        out.push_str(cap.label());
        out.push_str(" |");
    }
    out.push('\n');
    out.push('|');
    for _ in 0..=Capability::ALL.len() {
        out.push_str("---|");
    }
    out.push('\n');
    for (lang, row) in &by_lang {
        out.push_str("| ");
        out.push_str(lang);
        out.push_str(" |");
        for cap in Capability::ALL {
            out.push(' ');
            out.push_str(row.get(cap).copied().unwrap_or(CellStatus::Missing).glyph());
            out.push_str(" |");
        }
        out.push('\n');
    }
    out.push('\n');
    out.push_str("**Legend:** ✅ supported · ❌ missing · — not applicable.\n");
    out
}

/// JSON shape for tooling that watches matrix drift.
#[must_use]
pub fn render_json(cells: &[Cell]) -> String {
    use std::collections::BTreeMap;
    let mut by_lang: BTreeMap<String, BTreeMap<&'static str, &'static str>> = BTreeMap::new();
    for cell in cells {
        let entry = by_lang.entry(cell.language.clone()).or_default();
        entry.insert(
            cell.capability.label(),
            match cell.status {
                CellStatus::Supported => "supported",
                CellStatus::Missing => "missing",
                CellStatus::NotApplicable => "not_applicable",
            },
        );
    }
    let mut out = String::new();
    out.push_str("{\n");
    let mut first = true;
    for (lang, row) in &by_lang {
        if !first {
            out.push_str(",\n");
        }
        first = false;
        out.push_str(&format!("  \"{}\": {{", lang));
        let mut col_first = true;
        for (cap, status) in row {
            if !col_first {
                out.push_str(", ");
            }
            col_first = false;
            out.push_str(&format!("\"{}\": \"{}\"", cap, status));
        }
        out.push('}');
    }
    out.push_str("\n}\n");
    out
}

/// Persist the matrix outputs under `build/`. Writes both Markdown
/// and JSON so humans and machines can each consume one.
pub fn write_matrix_to_build(cells: &[Cell]) -> std::io::Result<()> {
    let build_dir = repo_root()?.join("build");
    std::fs::create_dir_all(&build_dir)?;
    std::fs::write(build_dir.join("capability-matrix.md"), render_markdown(cells))?;
    std::fs::write(build_dir.join("capability-matrix.json"), render_json(cells))?;
    Ok(())
}

fn repo_root() -> std::io::Result<PathBuf> {
    let mut p = std::env::current_dir()?;
    // Walk up until we find Cargo.toml that has [workspace].
    for _ in 0..6 {
        let candidate = p.join("Cargo.toml");
        if let Ok(text) = std::fs::read_to_string(&candidate) {
            if text.contains("[workspace]") {
                return Ok(p);
            }
        }
        if !p.pop() {
            break;
        }
    }
    std::env::current_dir()
}
