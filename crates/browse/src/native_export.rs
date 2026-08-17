//! Native JSON export SDK.
//!
//! This module owns the command-independent data shape emitted by
//! `bonsai-ninja export` in its default JSON format. The CLI is only
//! responsible for opening the workspace, cache/stdout handling, and
//! selecting this renderer.

use crate::ClassOut;
use bonsai_common::{FileId, FuncId, Precision, Span, SpanMap, SymbolId};
use bonsai_idg::CrossCallEdge;
use bonsai_lang_api::{AssignValueKind, CallArg, CallKind, DeclKind, ExpressionFlow, FlowEvent, LoopKind};
use bonsai_workspace::{decl_decorator_names, Workspace};
use serde::ser::{SerializeMap, SerializeSeq};
use serde::{Serialize, Serializer};
use std::cell::RefCell;
use std::io::{self, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

#[derive(Copy, Clone, Debug, Default)]
pub struct NativeExportConfig {
    /// Materialize exhaustive interprocedural propagation records.
    /// This is explicit because full-workspace propagation exports
    /// can be much larger than the structural taint graph.
    pub full_propagations: bool,
    /// Keep the complete propagation relation in compiler form rather than
    /// materializing its potentially quadratic per-entry transitive product.
    pub compiled_propagations: bool,
}

#[derive(Copy, Clone, Debug, Serialize)]
struct ExportAnalysisScope {
    semantic_max_precision: &'static str,
    full_propagations: bool,
    complete_chains: bool,
    propagations_mode: &'static str,
}

struct ExportCompleteness {
    complete: bool,
    incomplete_reasons: Vec<String>,
}

#[derive(Serialize)]
struct ExportTaintFunction {
    /// Compiler identity used by bounded file-at-a-time projections. This is
    /// not part of the native export wire format.
    #[serde(skip)]
    file_id: FileId,
    func_id: u32,
    name: String,
    qualified_name: Option<String>,
    file: String,
    line: u32,
    params: Vec<String>,
    kind: String,
}

#[derive(Serialize)]
struct ExportCallEdge<'a> {
    from: u32,
    to: u32,
    kind: &'static str,
    precision: &'static str,
    resolver_stage: &'a str,
    evidence: &'a str,
    confidence: u8,
}

#[derive(Serialize)]
struct ExportReachableFacts {
    func_id: u32,
    function: String,
    /// Tokens keyed by `FactKind` name (`decl`, `call`, `read`,
    /// `write`, `arg`, `string_lit`, `import`, `class`). Flattened
    /// to sorted vectors so the JSON is diff-friendly.
    by_kind: std::collections::BTreeMap<String, Vec<String>>,
}

#[derive(Serialize)]
struct ExportAssignChain {
    func_id: u32,
    function: String,
    /// One entry per parameter: seeding the param name, this is
    /// the full set of identifiers the monotonic assign-chain
    /// pass reaches.
    per_param: Vec<ExportAssignChainParam>,
}

#[derive(Serialize)]
struct ExportAssignChainParam {
    param_index: usize,
    param_name: String,
    tainted: Vec<String>,
}

#[derive(Serialize)]
struct ExportIntraTaint {
    func_id: u32,
    function: String,
    /// Compatibility backend for the block-oriented presentation. The
    /// canonical interprocedural engine is the IDG; block ids currently live
    /// only in the local CFG.
    backend: &'static str,
    /// Per-parameter CFG dataflow results.
    per_param: Vec<ExportIntraTaintParam>,
}

#[derive(Serialize)]
struct ExportIntraTaintParam {
    param_index: usize,
    param_name: String,
    iterations: u32,
    /// One entry per basic block. `block_in` / `block_out` are
    /// the taint set at entry / exit of the block.
    blocks: Vec<ExportIntraBlock>,
}

#[derive(Serialize)]
struct ExportIntraBlock {
    #[serde(rename = "block_id")]
    id: u32,
    #[serde(rename = "block_in")]
    taint_in: Vec<String>,
    #[serde(rename = "block_out")]
    taint_out: Vec<String>,
}

#[derive(Serialize)]
struct ExportChain {
    target_func_id: u32,
    target: String,
    /// One chain per entry: ordered list of FuncIds top-down
    /// (entry first, target last).
    chains: Vec<Vec<u32>>,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation_reason: Option<String>,
}

#[derive(Serialize)]
struct ExportFlowIdLabels {
    func_id: u32,
    function: String,
    labels: Vec<String>,
    truncated: bool,
}

#[derive(Serialize)]
struct ExportFunctionSummary {
    function: String,
    file: String,
    line: u32,
    /// Parameter indices that flow to the function's return value.
    /// `[0, 2]` means taint on param 0 or param 2 produces a tainted
    /// return.
    returns_taint_of: Vec<usize>,
}

#[derive(Serialize)]
struct ExportAliasMap {
    file: String,
    entries: Vec<ExportAliasEntry>,
}

#[derive(Serialize)]
struct ExportAliasEntry {
    local: String,
    /// `member` — local name binds a specific module export
    /// (`import { exec } from "child_process"` → local `exec` →
    /// module `child_process`, member `exec`).
    /// `namespace` — local name binds the whole module (`import os
    /// as o` → local `o` → module `os`, no member).
    target_kind: &'static str,
    module: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    member: Option<String>,
}

#[derive(Serialize)]
struct ExportClassFields {
    class: String,
    file: String,
    line: u32,
    /// Adapter-normalized receiver field/container places that any
    /// method of the class writes from one of its own params.
    tainted_fields: Vec<String>,
}

#[derive(Serialize)]
struct ExportEntryPoint {
    /// Canonical symbol identity from the global index. Names and source
    /// positions are presentation only and may collide across declarations.
    func_id: u32,
    function: String,
    file: String,
    line: u32,
    kind: &'static str,
    params: Vec<String>,
}

#[derive(Serialize)]
struct ExportTaintPropagationsRef<'a> {
    entry: &'a str,
    entry_file: &'a str,
    entry_line: u32,
    /// Worst precision observed across any traversed resolver edge
    /// during the interprocedural pass from this entry.
    precision: &'static str,
    pairs_analyzed: u32,
    records: Vec<&'a ExportTaintRecord>,
}

#[derive(Clone, Serialize)]
struct ExportTaintRecord {
    caller: String,
    callee: String,
    call_line: u32,
    edge_kind: &'static str,
    edge_precision: &'static str,
    /// One entry per positional argument that was tainted at the
    /// call site. Lets consumers correlate caller-local identifiers
    /// to the callee's parameter names they ended up in.
    tainted_args: Vec<ExportTaintedArg>,
}

#[derive(Clone, Serialize)]
struct ExportTaintedArg {
    index: usize,
    value_text: String,
    param_name: String,
}

/// Retained wire shape for the v7 schema's optional concrete flow rows.
/// Production export leaves this empty and publishes the exact relationship
/// through `compressed_callgraph` instead.
#[derive(Serialize)]
struct ExportFlowChain {
    target: String,
    chains: Vec<Vec<String>>,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    truncation_reason: Option<String>,
}

/// One entry per callable decl: its caller/outgoing counts plus a flag
/// indicating whether it's a workspace entry point (no callers).
#[derive(Serialize)]
struct ExportFlowNode<'a> {
    function: &'a str,
    callers: Vec<&'a str>,
    outgoing: Vec<&'a str>,
    entry_point: bool,
}

#[derive(Serialize)]
struct ExportSummary {
    file_count: usize,
    decl_count: usize,
    class_count: usize,
    function_count: usize,
    method_count: usize,
    call_site_count: usize,
    call_edge_count: usize,
    import_count: usize,
    string_count: usize,
    strings_by_category: serde_json::Value,
    languages: Vec<String>,
}

#[derive(Serialize)]
struct ExportFile<'a> {
    path: String,
    language: String,
    decls: Vec<ExportDecl<'a>>,
    /// File-local, flat flow-event table. Declarations reference their root
    /// events by id; every nested event references its parent and region.
    /// This is compiler IR rather than a recursively nested presentation, so
    /// standard JSON consumers can process arbitrary control-flow depth.
    flow_events: Vec<ExportFlowEvent<'a>>,
    imports: Vec<ExportImport>,
    refs: Vec<ExportRef>,
    assignment_values: Vec<ExportAssignmentValue>,
    runtime_type_narrowings: Vec<bonsai_lang_api::RuntimeTypeNarrowingFact>,
    branch_conditions: Vec<bonsai_lang_api::BranchConditionFact>,
    strings: Vec<ExportString>,
}

#[derive(Serialize)]
struct ExportDecl<'a> {
    symbol_id: u32,
    name: &'a str,
    qualified_name: Option<&'a str>,
    kind: String,
    visibility: String,
    line: u32,
    column: u32,
    end_line: u32,
    params: &'a [String],
    /// Root ids in this file's `flow_events` table, in source order.
    flow_event_ids: Vec<u64>,
    parent_symbol_id: Option<u32>,
}

#[derive(Copy, Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExportFlowRegion {
    Root,
    Then,
    Else,
    Body,
    Catch,
    Finally,
}

/// One normalized AST-derived event in a file-local compiler table.
#[derive(Serialize)]
struct ExportFlowEvent<'a> {
    event_id: u64,
    owner_symbol_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    parent_event_id: Option<u64>,
    region: ExportFlowRegion,
    ordinal: usize,
    #[serde(flatten)]
    payload: ExportFlowEventPayload<'a>,
}

/// Recursive child vectors are deliberately absent. All semantic payload
/// fields are borrowed directly from the adapter-produced flow event; child
/// relationships live in `ExportFlowEvent::{parent_event_id,region,ordinal}`.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExportFlowEventPayload<'a> {
    Call {
        span: Span,
        name: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        receiver: Option<&'a str>,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        receiver_types: &'a [String],
        call_kind: CallKind,
        #[serde(skip_serializing_if = "<[CallArg]>::is_empty")]
        args: &'a [CallArg],
    },
    Branch {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        condition: Option<&'a str>,
    },
    Loop {
        span: Span,
        loop_kind: LoopKind,
    },
    Assign {
        span: Span,
        target: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source_call: Option<&'a str>,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        source_call_args: &'a [String],
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        source_names: &'a [String],
        #[serde(skip_serializing_if = "std::ops::Not::not")]
        declares_new_binding: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_kind: Option<AssignValueKind>,
    },
    AggregateAssign {
        span: Span,
        target: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        type_name: Option<&'a str>,
        #[serde(skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: &'a ExpressionFlow,
    },
    Return {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_kind: Option<AssignValueKind>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_text: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_name: Option<&'a str>,
        #[serde(skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: &'a ExpressionFlow,
    },
    Throw {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_name: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        thrown_type: Option<&'a str>,
    },
    Try {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        catch_param: Option<&'a str>,
        #[serde(skip_serializing_if = "<[String]>::is_empty")]
        catch_types: &'a [String],
    },
    Break {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<&'a str>,
    },
    Continue {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        label: Option<&'a str>,
    },
    Yield {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_text: Option<&'a str>,
        #[serde(skip_serializing_if = "ExpressionFlow::is_empty")]
        value_flow: &'a ExpressionFlow,
    },
    Await {
        span: Span,
        #[serde(skip_serializing_if = "Option::is_none")]
        value_name: Option<&'a str>,
    },
    Defer {
        span: Span,
    },
    Using {
        span: Span,
    },
    Lifecycle {
        span: Span,
        name: &'a str,
        transition: &'a str,
    },
}

#[derive(Copy, Clone)]
struct PendingFlowEvent<'a> {
    event: &'a FlowEvent,
    parent_event_id: Option<u64>,
    region: ExportFlowRegion,
    ordinal: usize,
}

fn push_flow_region<'a>(
    stack: &mut Vec<PendingFlowEvent<'a>>,
    events: &'a [FlowEvent],
    parent_event_id: u64,
    region: ExportFlowRegion,
) {
    stack.extend(
        events
            .iter()
            .enumerate()
            .rev()
            .map(|(ordinal, event)| PendingFlowEvent {
                event,
                parent_event_id: Some(parent_event_id),
                region,
                ordinal,
            }),
    );
}

fn flatten_flow_events<'a>(
    events: &'a [FlowEvent],
    owner_symbol_id: u32,
    out: &mut Vec<ExportFlowEvent<'a>>,
) -> Vec<u64> {
    let mut root_ids = Vec::with_capacity(events.len());
    let mut stack: Vec<PendingFlowEvent<'a>> = events
        .iter()
        .enumerate()
        .rev()
        .map(|(ordinal, event)| PendingFlowEvent {
            event,
            parent_event_id: None,
            region: ExportFlowRegion::Root,
            ordinal,
        })
        .collect();

    while let Some(pending) = stack.pop() {
        let event_id = out.len() as u64;
        if pending.parent_event_id.is_none() {
            root_ids.push(event_id);
        }

        let payload = match pending.event {
            FlowEvent::Call {
                span,
                name,
                receiver,
                receiver_types,
                call_kind,
                args,
            } => ExportFlowEventPayload::Call {
                span: *span,
                name,
                receiver: receiver.as_deref(),
                receiver_types,
                call_kind: *call_kind,
                args,
            },
            FlowEvent::Branch {
                span,
                condition,
                then_events,
                else_events,
            } => {
                push_flow_region(&mut stack, else_events, event_id, ExportFlowRegion::Else);
                push_flow_region(&mut stack, then_events, event_id, ExportFlowRegion::Then);
                ExportFlowEventPayload::Branch {
                    span: *span,
                    condition: condition.as_deref(),
                }
            }
            FlowEvent::Loop {
                span,
                loop_kind,
                body,
            } => {
                push_flow_region(&mut stack, body, event_id, ExportFlowRegion::Body);
                ExportFlowEventPayload::Loop {
                    span: *span,
                    loop_kind: *loop_kind,
                }
            }
            FlowEvent::Assign {
                span,
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                declares_new_binding,
                value_kind,
            } => ExportFlowEventPayload::Assign {
                span: *span,
                target,
                source_name: source_name.as_deref(),
                source_call: source_call.as_deref(),
                source_call_args,
                source_names,
                declares_new_binding: *declares_new_binding,
                value_kind: *value_kind,
            },
            FlowEvent::AggregateAssign {
                span,
                target,
                type_name,
                value_flow,
            } => ExportFlowEventPayload::AggregateAssign {
                span: *span,
                target,
                type_name: type_name.as_deref(),
                value_flow,
            },
            FlowEvent::Return {
                span,
                value_kind,
                value_text,
                value_name,
                value_flow,
            } => ExportFlowEventPayload::Return {
                span: *span,
                value_kind: *value_kind,
                value_text: value_text.as_deref(),
                value_name: value_name.as_deref(),
                value_flow,
            },
            FlowEvent::Throw {
                span,
                value_name,
                thrown_type,
            } => ExportFlowEventPayload::Throw {
                span: *span,
                value_name: value_name.as_deref(),
                thrown_type: thrown_type.as_deref(),
            },
            FlowEvent::Try {
                span,
                body,
                catch_events,
                finally_events,
                catch_param,
                catch_types,
            } => {
                push_flow_region(&mut stack, finally_events, event_id, ExportFlowRegion::Finally);
                push_flow_region(&mut stack, catch_events, event_id, ExportFlowRegion::Catch);
                push_flow_region(&mut stack, body, event_id, ExportFlowRegion::Body);
                ExportFlowEventPayload::Try {
                    span: *span,
                    catch_param: catch_param.as_deref(),
                    catch_types,
                }
            }
            FlowEvent::Break { span, label } => ExportFlowEventPayload::Break {
                span: *span,
                label: label.as_deref(),
            },
            FlowEvent::Continue { span, label } => ExportFlowEventPayload::Continue {
                span: *span,
                label: label.as_deref(),
            },
            FlowEvent::Yield {
                span,
                value_text,
                value_flow,
            } => ExportFlowEventPayload::Yield {
                span: *span,
                value_text: value_text.as_deref(),
                value_flow,
            },
            FlowEvent::Await { span, value_name } => ExportFlowEventPayload::Await {
                span: *span,
                value_name: value_name.as_deref(),
            },
            FlowEvent::Defer { span, body } => {
                push_flow_region(&mut stack, body, event_id, ExportFlowRegion::Body);
                ExportFlowEventPayload::Defer { span: *span }
            }
            FlowEvent::Using { span, body } => {
                push_flow_region(&mut stack, body, event_id, ExportFlowRegion::Body);
                ExportFlowEventPayload::Using { span: *span }
            }
            FlowEvent::Lifecycle {
                span,
                name,
                transition,
            } => ExportFlowEventPayload::Lifecycle {
                span: *span,
                name,
                transition,
            },
        };
        out.push(ExportFlowEvent {
            event_id,
            owner_symbol_id,
            parent_event_id: pending.parent_event_id,
            region: pending.region,
            ordinal: pending.ordinal,
            payload,
        });
    }
    root_ids
}

#[derive(Serialize)]
struct ExportImport {
    module: String,
    alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    original_name: Option<String>,
    is_wildcard: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    line: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    local_bindings: Vec<String>,
}

#[derive(Serialize)]
struct ExportRef {
    name: String,
    kind: String,
    line: u32,
    column: u32,
    resolved_symbol_id: Option<u32>,
}

#[derive(Serialize)]
struct ExportAssignmentValue {
    #[serde(rename = "assignment_start_byte")]
    assignment_start: u64,
    #[serde(rename = "assignment_end_byte")]
    assignment_end: u64,
    #[serde(rename = "target_start_byte", skip_serializing_if = "Option::is_none")]
    target_start: Option<u64>,
    #[serde(rename = "target_end_byte", skip_serializing_if = "Option::is_none")]
    target_end: Option<u64>,
    #[serde(rename = "value_start_byte")]
    value_start: u64,
    #[serde(rename = "value_end_byte")]
    value_end: u64,
    call_sites: Vec<Span>,
    value_flow: bonsai_lang_api::ExpressionFlow,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_call_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    direct_call_receiver: Option<String>,
}

#[derive(Serialize)]
struct ExportString {
    text: String,
    category: String,
    line: u32,
    column: u32,
}

#[derive(Serialize)]
struct CallEdgeOut<'a> {
    caller: &'a str,
    caller_file: &'a str,
    caller_line: u32,
    callee: &'a str,
    callee_kind: &'static str,
    call_site_line: u32,
    call_site_column: u32,
    precision: &'static str,
    resolver_stage: &'a str,
    evidence: &'a str,
    confidence: u8,
}

/// Per-export cache of `(path, SpanMap)` keyed on FileId. We
/// build each file's span-map once at export start and reuse it
/// for every span we render — large workspaces would otherwise
/// rebuild the same maps thousands of times.
struct ExportSpanCache {
    files: ahash::AHashMap<FileId, (String, SpanMap)>,
}

impl ExportSpanCache {
    fn new(ws: &Workspace) -> Self {
        let mut files = ahash::AHashMap::default();
        for file in ws.db().vfs().all_files() {
            let path = ws.vfs().path(file).map_or_else(
                |_| "<unknown>".to_string(),
                |path| crate::workspace_relative_path(ws, &path.display().to_string()),
            );
            if let Ok(snap) = ws.vfs().snapshot(file) {
                files.insert(file, (path, SpanMap::new(snap.text.as_ref())));
            }
        }
        Self { files }
    }

    /// Resolve `span` to `(path, line, column)`. Falls back to
    /// `("<unknown>", 0, 0)` if the file's snapshot wasn't readable
    /// at cache-build time.
    fn format(&self, span: Span) -> (String, u32, u32) {
        let Some((path, map)) = self.files.get(&span.file) else {
            return ("<unknown>".to_string(), 0, 0);
        };
        let line_col = map.line_col(span.start);
        (path.clone(), line_col.line, line_col.column)
    }

    fn line_col(&self, span: Span) -> (u32, u32) {
        let Some((_, map)) = self.files.get(&span.file) else {
            return (0, 0);
        };
        let line_col = map.line_col(span.start);
        (line_col.line, line_col.column)
    }

    fn path(&self, file: FileId) -> &str {
        self.files
            .get(&file)
            .map(|(path, _)| path.as_str())
            .unwrap_or("<unknown>")
    }

    fn end_line(&self, span: Span) -> u32 {
        let Some((_, map)) = self.files.get(&span.file) else {
            return 0;
        };
        let end = if span.end > span.start {
            span.end.saturating_sub(1)
        } else {
            span.start
        };
        map.line_col(end).line
    }
}

/// Build the native `export` JSON value from an indexed workspace.
pub fn native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<serde_json::Value> {
    native_export_json_with_config(
        ws,
        root,
        NativeExportConfig {
            full_propagations,
            compiled_propagations: false,
        },
    )
}

/// Build the native `export` JSON value with explicit renderer
/// options.
pub fn native_export_json_with_config(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
) -> serde_json::Result<serde_json::Value> {
    let mut bytes = Vec::new();
    write_native_export_streaming(ws, root, config, &mut bytes)?;
    serde_json::from_slice(&bytes)
}

/// Render the native `export` JSON document from an indexed workspace.
pub fn render_native_export_json(
    ws: &Workspace,
    root: &Path,
    full_propagations: bool,
) -> serde_json::Result<String> {
    render_native_export_json_with_config(
        ws,
        root,
        NativeExportConfig {
            full_propagations,
            compiled_propagations: false,
        },
    )
}

/// Render the native `export` JSON document with explicit renderer
/// options.
pub fn render_native_export_json_with_config(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
) -> serde_json::Result<String> {
    let mut bytes = Vec::new();
    write_native_export_streaming(ws, root, config, &mut bytes)?;
    String::from_utf8(bytes).map_err(|error| {
        serde_json::Error::io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("JSON serializer emitted invalid UTF-8: {error}"),
        ))
    })
}

/// Stream the native `export` JSON document to a writer. This serializes
/// top-level sections as they are produced so large structural and taint
/// sections are not retained together in one full export object.
pub fn write_native_export_json_with_config<W: Write + ?Sized>(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
    writer: &mut W,
) -> serde_json::Result<()> {
    write_native_export_streaming(ws, root, config, writer)
}

fn write_native_export_streaming<W: Write + ?Sized>(
    ws: &Workspace,
    root: &Path,
    config: NativeExportConfig,
    writer: &mut W,
) -> serde_json::Result<()> {
    let total_started = Instant::now();
    // Export owns one compiler representation at a time. A prior SDK query
    // may have left an IDG service resident; release it before rendering the
    // structural graph and file-local compiler objects.
    ws.release_idg_service_cache();
    let global = ws.compiler_header_index();
    let spans = ExportSpanCache::new(ws);

    let mut serializer = serde_json::Serializer::new(writer);
    let mut map = serializer.serialize_map(None)?;

    map.serialize_entry("schema", "bonsai-native-export")?;
    map.serialize_entry("schema_version", &7_u32)?;
    map.serialize_entry("engine_version", env!("CARGO_PKG_VERSION"))?;
    map.serialize_entry("workspace_root", &root.display().to_string())?;
    map.serialize_entry("generated_at_unix_ms", &generated_at_unix_ms())?;
    map.serialize_entry("analysis_scope", &export_analysis_scope(config))?;

    let structural = build_export_structural_metadata(ws, global.as_ref(), &spans, &total_started)?;
    map.serialize_entry("summary", &structural.summary)?;
    map.serialize_entry("classes", &structural.classes)?;
    map.serialize_entry(
        "callgraph",
        &ExportStructuralCallgraphStreaming {
            ws,
            global: global.as_ref(),
            spans: &spans,
        },
    )?;
    drop(structural);

    let phase_started = Instant::now();
    let flow_sections = build_export_flow_sections();
    export_phase_log(format_args!(
        "flow sections: {:.3}s chains={} truncated_targets={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        flow_sections.flow_chains.len(),
        flow_sections.flow_chains_truncated_targets,
        flow_sections.flow_chains_mode
    ));
    map.serialize_entry("flow_chains", &flow_sections.flow_chains)?;
    map.serialize_entry("flow_chains_complete", &flow_sections.flow_chains_complete)?;
    map.serialize_entry("flow_chains_mode", &flow_sections.flow_chains_mode)?;
    map.serialize_entry(
        "flow_chains_truncated_targets",
        &flow_sections.flow_chains_truncated_targets,
    )?;
    if let Some(reason) = &flow_sections.flow_chains_incomplete_reason {
        map.serialize_entry("flow_chains_incomplete_reason", &reason)?;
    }
    map.serialize_entry(
        "flow_graph",
        &ExportFlowGraphStreaming {
            ws,
            global: global.as_ref(),
        },
    )?;
    drop(flow_sections);

    // Completeness and entry-point inference consume file-local compiler
    // bodies. Finish those exact frontend passes before retaining the large
    // chain/flow-label presentation projection.
    let completeness_started = Instant::now();
    let workspace_incomplete_reasons = export_workspace_incomplete_reasons(ws);
    export_phase_log(format_args!(
        "workspace completeness: {:.3}s reasons={}",
        completeness_started.elapsed().as_secs_f64(),
        workspace_incomplete_reasons.len()
    ));
    let entry_points = export_entry_points(ws, &spans);

    let phase_started = Instant::now();
    let functions = export_taint_functions(global.as_ref(), &spans);
    let chain_rows = export_taint_chains_and_flow_labels();
    let completeness = export_analysis_completeness(config, &workspace_incomplete_reasons);

    // Structural graph projections are complete. Release the partition reader
    // before opening adapter-lowered bodies; the numeric taint relation is
    // streamed from the same exact sidecar later instead of retaining another
    // multi-million-edge vector.
    ws.release_resolved_call_graph_cache();
    map.serialize_entry("files", &ExportFilesStreaming { ws, spans: &spans })?;
    drop(global);
    ws.release_compiler_linkage_cache();
    map.serialize_entry("analysis_complete", &completeness.complete)?;
    map.serialize_entry("analysis_incomplete_reasons", &completeness.incomplete_reasons)?;
    let taint_graph = ExportTaintGraphStreaming {
        ws,
        spans: &spans,
        functions,
        entry_points: RefCell::new(Some(entry_points)),
        chain_rows: RefCell::new(Some(chain_rows)),
        config,
    };
    map.serialize_entry("taint_graph", &taint_graph)?;
    export_phase_log(format_args!(
        "taint graph: {:.3}s total={:.3}s",
        phase_started.elapsed().as_secs_f64(),
        total_started.elapsed().as_secs_f64()
    ));
    SerializeMap::end(map)
}

struct ExportStructuralMetadata {
    summary: ExportSummary,
    classes: Vec<ClassOut>,
}

fn build_export_structural_metadata(
    ws: &Workspace,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
    total_started: &Instant,
) -> serde_json::Result<ExportStructuralMetadata> {
    let mut classes = Vec::new();
    let mut languages_set: ahash::AHashSet<String> = ahash::AHashSet::new();
    let mut function_count = 0usize;
    let mut method_count = 0usize;
    let mut call_site_count = 0usize;
    let mut import_count = 0usize;
    let mut string_count = 0usize;
    let mut decl_count = 0usize;
    // BTreeMap (not ahash) so the serialised JSON object has a
    // deterministic key order across runs — `serde_json::to_value`
    // on an `AHashMap` would expose the per-process random seed
    // and break Stable-IDs-From-Content for `export` JSON.
    let mut by_cat: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    let all_files = export_files_in_path_order(ws);
    let file_count = all_files.len();
    for (file, path) in all_files {
        let language = ws
            .db()
            .adapter_for(file)
            .map(|a| a.language_id().as_str().to_string())
            .unwrap_or_default();
        if !language.is_empty() {
            languages_set.insert(language.clone());
        }

        let Some(idx) = ws.exact_decl_index_shared(file) else {
            continue;
        };

        for d in &idx.defs {
            decl_count += 1;
            match d.kind {
                DeclKind::Function => function_count += 1,
                DeclKind::Method | DeclKind::Constructor => method_count += 1,
                _ => {}
            }
            let (_, line, _) = spans.format(d.name_span);
            count_call_sites_for_export(&d.flow_events, &mut call_site_count);
            if matches!(
                d.kind,
                DeclKind::Class | DeclKind::Struct | DeclKind::Trait | DeclKind::Interface | DeclKind::Enum
            ) {
                let methods: Vec<String> = idx
                    .defs
                    .iter()
                    .filter(|m| {
                        matches!(
                            m.kind,
                            DeclKind::Method | DeclKind::Constructor | DeclKind::Function
                        )
                    })
                    .filter(|m| m.parent == Some(d.symbol))
                    .map(|m| m.name.clone())
                    .collect();
                classes.push(ClassOut {
                    name: d.name.clone(),
                    kind: format!("{:?}", d.kind).to_lowercase(),
                    file: path.clone(),
                    line,
                    method_count: methods.len(),
                    methods,
                });
            }
        }

        let imports_vec = export_import_specs(ws, file);
        import_count += imports_vec.iter().filter(|imp| !imp.scope.is_local()).count();
        for string in &idx.strings {
            let category = format!("{:?}", string.category).to_lowercase();
            *by_cat.entry(category).or_insert(0) += 1;
            string_count += 1;
        }
    }
    export_phase_log(format_args!(
        "files/classes/callgraph: {:.3}s files={} decls={} calls={}",
        total_started.elapsed().as_secs_f64(),
        file_count,
        decl_count,
        call_site_count
    ));

    let call_edge_count = export_structural_callgraph_count(ws, global);

    let mut languages: Vec<String> = languages_set.into_iter().collect();
    languages.sort();
    let summary = ExportSummary {
        file_count,
        decl_count,
        class_count: classes.len(),
        function_count,
        method_count,
        call_site_count,
        call_edge_count,
        import_count,
        string_count,
        strings_by_category: serde_json::to_value(&by_cat)?,
        languages,
    };

    Ok(ExportStructuralMetadata { summary, classes })
}

fn export_files_in_path_order(ws: &Workspace) -> Vec<(FileId, String)> {
    let mut files: Vec<_> = ws
        .vfs()
        .all_files()
        .into_iter()
        .map(|file| {
            let path = ws.vfs().path(file).map_or_else(
                |_| "<unknown>".to_string(),
                |path| crate::workspace_relative_path(ws, &path.display().to_string()),
            );
            (file, path)
        })
        .collect();
    files.sort_by(|left, right| left.1.cmp(&right.1));
    files
}

fn export_import_specs(ws: &Workspace, file: FileId) -> Vec<bonsai_lang_api::ImportSpec> {
    ws.db().imports_for_uncached(file)
}

struct ExportFilesStreaming<'a> {
    ws: &'a Workspace,
    spans: &'a ExportSpanCache,
}

impl Serialize for ExportFilesStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let files = export_files_in_path_order(self.ws);
        let mut sequence = serializer.serialize_seq(Some(files.len()))?;
        for (file, path) in files {
            let index = self.ws.exact_decl_index_shared(file);
            let export_file = build_export_file(self.ws, index.as_deref(), self.spans, file, path);
            sequence.serialize_element(&export_file)?;
        }
        SerializeSeq::end(sequence)
    }
}

fn build_export_file<'a>(
    ws: &Workspace,
    index: Option<&'a bonsai_lang_api::DeclIndex>,
    spans: &ExportSpanCache,
    file: FileId,
    path: String,
) -> ExportFile<'a> {
    let language = ws
        .db()
        .adapter_for(file)
        .map(|adapter| adapter.language_id().as_str().to_string())
        .unwrap_or_default();
    let Some(index) = index else {
        return ExportFile {
            path,
            language,
            decls: Vec::new(),
            flow_events: Vec::new(),
            imports: Vec::new(),
            refs: Vec::new(),
            assignment_values: Vec::new(),
            runtime_type_narrowings: Vec::new(),
            branch_conditions: Vec::new(),
            strings: Vec::new(),
        };
    };

    let mut flow_events = Vec::new();
    let decls = index
        .defs
        .iter()
        .map(|decl| {
            let (_, line, column) = spans.format(decl.name_span);
            let flow_event_ids = flatten_flow_events(&decl.flow_events, decl.symbol.raw(), &mut flow_events);
            ExportDecl {
                symbol_id: decl.symbol.raw(),
                name: &decl.name,
                qualified_name: decl.qualified_name.as_deref(),
                kind: format!("{:?}", decl.kind).to_lowercase(),
                visibility: format!("{:?}", decl.visibility).to_lowercase(),
                line,
                column,
                end_line: spans.end_line(decl.body_span.unwrap_or(decl.span)),
                params: &decl.params,
                flow_event_ids,
                parent_symbol_id: decl.parent.map(SymbolId::raw),
            }
        })
        .collect();

    let imports_vec = export_import_specs(ws, file);
    let mut local_bindings_by_span: ahash::AHashMap<u64, Vec<String>> = ahash::AHashMap::default();
    for import in &imports_vec {
        if !import.scope.is_local() {
            continue;
        }
        let Some(name) = import.alias.as_deref().or(import.original_name.as_deref()) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        let bindings = local_bindings_by_span.entry(import.span.start).or_default();
        if !bindings.iter().any(|existing| existing == name) {
            bindings.push(name.to_string());
        }
    }
    let imports = imports_vec
        .iter()
        .filter(|import| !import.scope.is_local())
        .map(|import| {
            let (_, line, _) = spans.format(import.span);
            ExportImport {
                module: import.module.clone(),
                alias: import.alias.clone(),
                original_name: import.original_name.clone(),
                is_wildcard: import.is_wildcard,
                scope: (!import.scope.is_module()).then(|| format!("{:?}", import.scope).to_lowercase()),
                line,
                local_bindings: local_bindings_by_span
                    .get(&import.span.start)
                    .cloned()
                    .unwrap_or_default(),
            }
        })
        .collect();
    let refs = index
        .refs
        .iter()
        .map(|reference| {
            let (_, line, column) = spans.format(reference.span);
            ExportRef {
                name: reference.name.clone(),
                kind: format!("{:?}", reference.kind).to_lowercase(),
                line,
                column,
                resolved_symbol_id: reference.resolved.map(SymbolId::raw),
            }
        })
        .collect();
    let assignment_values = index
        .assignment_values
        .iter()
        .map(|fact| ExportAssignmentValue {
            assignment_start: fact.assignment_span.start,
            assignment_end: fact.assignment_span.end,
            target_start: fact.target_span.map(|span| span.start),
            target_end: fact.target_span.map(|span| span.end),
            value_start: fact.value_span.start,
            value_end: fact.value_span.end,
            call_sites: fact.call_sites.clone(),
            value_flow: fact.value_flow.clone(),
            direct_call_name: fact.direct_call_name.clone(),
            direct_call_receiver: fact.direct_call_receiver.clone(),
        })
        .collect();
    let strings = index
        .strings
        .iter()
        .map(|string| {
            let (_, line, column) = spans.format(string.span);
            ExportString {
                text: string.text.clone(),
                category: format!("{:?}", string.category).to_lowercase(),
                line,
                column,
            }
        })
        .collect();

    ExportFile {
        path,
        language,
        decls,
        flow_events,
        imports,
        refs,
        assignment_values,
        runtime_type_narrowings: index.runtime_type_narrowings.clone(),
        branch_conditions: index.branch_conditions.clone(),
        strings,
    }
}

/// Wall-clock unix-ms timestamp for the export header. Falls back
/// to `0` rather than panicking on systems with a clock before
/// the Unix epoch.
fn generated_at_unix_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis())
}

fn export_phase_enabled() -> bool {
    bonsai_diagnostics::debug::is_enabled("export-phase")
}

fn export_phase_log(args: std::fmt::Arguments<'_>) {
    if export_phase_enabled() {
        let message = bonsai_diagnostics::debug::render_message(&args.to_string());
        eprintln!("[export-phase] {message}");
    }
}

const EXPORT_SEMANTIC_FLOW_MAX_PRECISION: Precision = Precision::Narrowed;
const COMPRESSED_CHAIN_ROWS_REASON: &str = "concrete path rows are not materialized in compressed_callgraph mode; the complete semantic chain language is represented by the exported function and resolved call-edge graph";
const COMPRESSED_FLOW_ID_ROWS_REASON: &str = "concrete flow-id label rows are not materialized in compressed_callgraph mode; the complete semantic flow relation is represented by the exported function and resolved call-edge graph";

/// Reuse the canonical compiler IDG for native export projections.
///
/// Adapter capability metadata selects symbolic versus eager field places in
/// the workspace builder. Export does not maintain a second seed/graph policy.
fn export_projection_idg_service(ws: &Workspace) -> Arc<bonsai_idg::IdgQueryService> {
    ws.build_and_seed_idg_service()
}

fn export_analysis_scope(config: NativeExportConfig) -> ExportAnalysisScope {
    ExportAnalysisScope {
        semantic_max_precision: export_precision_label(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
        full_propagations: config.full_propagations,
        // The wire field is retained for schema compatibility. Native export
        // always emits the exact compressed relation; there is no capped path
        // materialization mode.
        complete_chains: true,
        propagations_mode: propagation_mode(config),
    }
}

fn export_analysis_completeness(
    config: NativeExportConfig,
    workspace_incomplete_reasons: &[String],
) -> ExportCompleteness {
    let mut incomplete_reasons = workspace_incomplete_reasons.to_vec();
    if let Some(reason) = propagation_omitted_reason(config) {
        incomplete_reasons.push(format!("taint_graph.propagations: {reason}"));
    }
    ExportCompleteness {
        complete: incomplete_reasons.is_empty(),
        incomplete_reasons,
    }
}

fn export_workspace_incomplete_reasons(ws: &Workspace) -> Vec<String> {
    let mut reasons = ws.parser_incomplete_reasons_for_files(&ws.vfs().all_files());
    reasons.extend(crate::resolution::resolution_incomplete_reasons(ws));
    reasons.sort();
    reasons.dedup();
    reasons
}

#[allow(clippy::struct_field_names)] // Serialized field names intentionally mirror export JSON keys.
struct ExportFlowSections {
    flow_chains: Vec<ExportFlowChain>,
    flow_chains_complete: bool,
    flow_chains_mode: &'static str,
    flow_chains_truncated_targets: usize,
    flow_chains_incomplete_reason: Option<String>,
}

fn build_export_flow_sections() -> ExportFlowSections {
    // The exact semantic relation is the exported resolved callgraph. Simple
    // path enumeration can be exponential even for a small cyclic graph, so
    // native export has no alternate capped/prefix representation.
    ExportFlowSections {
        flow_chains: Vec::new(),
        flow_chains_complete: false,
        flow_chains_mode: "compressed_callgraph",
        flow_chains_truncated_targets: 0,
        flow_chains_incomplete_reason: Some(COMPRESSED_CHAIN_ROWS_REASON.to_string()),
    }
}

/// Deterministic flow graph serialization that owns only one rendered row at
/// a time. The compact `FuncId` order vector is the external-sort index; caller
/// and callee names remain canonical linkage facts and are never duplicated
/// for the whole workspace in memory.
struct ExportFlowGraphStreaming<'a> {
    ws: &'a Workspace,
    global: &'a bonsai_index::GlobalIndex,
}

impl Serialize for ExportFlowGraphStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let function_count = self
            .global
            .all_files()
            .flat_map(|file| {
                self.global
                    .functions_in(file)
                    .map(|decl| FuncId::new(decl.symbol.raw()))
            })
            .count();
        let mut sequence = serializer.serialize_seq(Some(function_count))?;
        let mut serialization_error = None;
        let partition_result = self.ws.visit_persisted_callgraph_partitions(
            |file, _nodes, outgoing_edges, incoming_edges, _unresolved| {
                if serialization_error.is_some() {
                    return;
                }
                let mut funcs = self
                    .global
                    .functions_in(file)
                    .map(|decl| FuncId::new(decl.symbol.raw()))
                    .collect::<Vec<_>>();
                funcs.sort_by(|left, right| {
                    linkage_func_display_name(self.global, *left)
                        .cmp(linkage_func_display_name(self.global, *right))
                        .then_with(|| left.raw().cmp(&right.raw()))
                });
                let mut callers_by_func = ahash::AHashMap::<FuncId, Vec<&str>>::new();
                for edge in incoming_edges {
                    callers_by_func
                        .entry(edge.to)
                        .or_default()
                        .push(linkage_func_display_name(self.global, edge.from));
                }
                let mut outgoing_by_func = ahash::AHashMap::<FuncId, Vec<&str>>::new();
                for edge in outgoing_edges {
                    outgoing_by_func
                        .entry(edge.from)
                        .or_default()
                        .push(linkage_func_display_name(self.global, edge.to));
                }
                for func in funcs {
                    let mut callers = callers_by_func.remove(&func).unwrap_or_default();
                    callers.sort_unstable();
                    callers.dedup();
                    let mut outgoing = outgoing_by_func.remove(&func).unwrap_or_default();
                    outgoing.sort_unstable();
                    outgoing.dedup();
                    if let Err(error) = sequence.serialize_element(&ExportFlowNode {
                        entry_point: callers.is_empty(),
                        function: linkage_func_display_name(self.global, func),
                        callers,
                        outgoing,
                    }) {
                        serialization_error = Some(error);
                        break;
                    }
                }
            },
        );
        if let Some(error) = serialization_error {
            return Err(error);
        }
        match partition_result {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(<S::Error as serde::ser::Error>::custom(error)),
            None => {
                let graph = self.ws.cached_resolved_call_graph();
                let mut funcs = self
                    .global
                    .all_files()
                    .flat_map(|file| {
                        self.global
                            .functions_in(file)
                            .map(|decl| FuncId::new(decl.symbol.raw()))
                    })
                    .collect::<Vec<_>>();
                funcs.sort_by(|left, right| {
                    linkage_func_display_name(self.global, *left)
                        .cmp(linkage_func_display_name(self.global, *right))
                        .then_with(|| left.raw().cmp(&right.raw()))
                });
                for func in funcs {
                    let mut callers = graph
                        .callers_of(func)
                        .map(|edge| linkage_func_display_name(self.global, edge.from))
                        .collect::<Vec<_>>();
                    callers.sort_unstable();
                    callers.dedup();
                    let mut outgoing = graph
                        .callees_of(func)
                        .map(|edge| linkage_func_display_name(self.global, edge.to))
                        .collect::<Vec<_>>();
                    outgoing.sort_unstable();
                    outgoing.dedup();
                    sequence.serialize_element(&ExportFlowNode {
                        entry_point: callers.is_empty(),
                        function: linkage_func_display_name(self.global, func),
                        callers,
                        outgoing,
                    })?;
                }
            }
        }
        SerializeSeq::end(sequence)
    }
}

fn linkage_func_display_name(global: &bonsai_index::GlobalIndex, func: FuncId) -> &str {
    global
        .decl_of(SymbolId::new(func.raw()))
        .map(|decl| decl.name.as_str())
        .unwrap_or("<unknown>")
}

struct ExportTaintGraphStreaming<'a> {
    ws: &'a Workspace,
    spans: &'a ExportSpanCache,
    functions: Vec<ExportTaintFunction>,
    entry_points: RefCell<Option<Vec<ExportEntryPoint>>>,
    chain_rows: RefCell<Option<ExportTaintChainsAndFlowLabels>>,
    config: NativeExportConfig,
}

impl Serialize for ExportTaintGraphStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;

        let functions = self.functions.as_slice();
        map.serialize_entry("functions", functions)?;

        map.serialize_entry("call_edges", &ExportTaintCallEdgesStreaming { ws: self.ws })?;

        // Chain rows are presentation projections computed from the complete
        // callgraph. Serialize and release them before opening the multi-
        // gigabyte IDG so the two exact representations never overlap.
        {
            let chain_rows = self.chain_rows.borrow();
            let chain_rows = chain_rows
                .as_ref()
                .expect("native export chain rows are serialized once");
            map.serialize_entry("chains", &chain_rows.chains)?;
            map.serialize_entry("chains_complete", &chain_rows.chains_complete)?;
            map.serialize_entry("chains_mode", &chain_rows.chains_mode)?;
            map.serialize_entry("chains_truncated_targets", &chain_rows.chains_truncated_targets)?;
            if let Some(reason) = &chain_rows.chains_incomplete_reason {
                map.serialize_entry("chains_incomplete_reason", &reason)?;
            }
            map.serialize_entry("flow_id_labels", &chain_rows.flow_id_labels)?;
            map.serialize_entry("flow_id_labels_complete", &chain_rows.flow_id_labels_complete)?;
            map.serialize_entry("flow_id_labels_mode", &chain_rows.flow_id_labels_mode)?;
            map.serialize_entry(
                "flow_id_labels_truncated_functions",
                &chain_rows.flow_id_labels_truncated_functions,
            )?;
            if let Some(reason) = &chain_rows.flow_id_labels_incomplete_reason {
                map.serialize_entry("flow_id_labels_incomplete_reason", &reason)?;
            }
        }
        self.chain_rows.borrow_mut().take();
        self.ws.flow_ids().release_resident_ids();

        // These compiler projections consume file-local typed bodies but not
        // the IDG. Finish them while the IDG is closed, then release exact-body
        // caches before entering the graph phase.
        map.serialize_entry(
            "reachable_facts",
            &ExportReachableFactsStreaming {
                ws: self.ws,
                functions,
            },
        )?;
        map.serialize_entry(
            "intra_taint",
            &ExportIntraTaintStreaming {
                ws: self.ws,
                functions,
            },
        )?;
        let alias_maps = export_alias_maps(self.ws);
        map.serialize_entry("alias_maps", &alias_maps)?;
        drop(alias_maps);
        let class_fields = export_class_fields(self.ws, self.spans);
        map.serialize_entry("class_fields", &class_fields)?;
        drop(class_fields);
        {
            let entry_points = self.entry_points.borrow();
            map.serialize_entry(
                "entry_points",
                entry_points
                    .as_deref()
                    .expect("native export entry points are serialized once"),
            )?;
        }
        if !self.config.full_propagations {
            self.entry_points.borrow_mut().take();
        }
        self.ws.release_exact_body_cache();
        self.ws.release_compiler_header_cache();

        let projection_idg = export_projection_idg_service(self.ws);
        let summary_funcs: Vec<FuncId> = functions
            .iter()
            .map(|function| FuncId::new(function.func_id))
            .collect();
        let return_taint_by_func = projection_idg.return_taint_param_indices_for_funcs_with_max_precision(
            &summary_funcs,
            Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
        );
        export_phase_log(format_args!(
            "taint.numeric_function_summaries: funcs={} rows={}",
            summary_funcs.len(),
            return_taint_by_func.len()
        ));
        let function_summaries = export_function_summaries(&return_taint_by_func, functions);
        map.serialize_entry("function_summaries", &function_summaries)?;
        drop(function_summaries);
        drop(return_taint_by_func);
        drop(summary_funcs);
        if !self.config.full_propagations {
            projection_idg.release_query_indexes();
        }
        map.serialize_entry(
            "assign_chains",
            &ExportAssignChainsStreaming {
                idg: &projection_idg,
                functions,
            },
        )?;

        {
            let entry_points = self.entry_points.borrow();
            let propagation_rows = ExportTaintPropagationsStreaming {
                ws: self.ws,
                spans: self.spans,
                idg: &projection_idg,
                entry_points: entry_points.as_deref().unwrap_or(&[]),
                full_propagations: self.config.full_propagations,
            };
            map.serialize_entry("propagations", &propagation_rows)?;
        }
        map.serialize_entry("propagations_complete", &self.config.full_propagations)?;
        map.serialize_entry("propagations_mode", propagation_mode(self.config))?;
        if let Some(reason) = propagation_omitted_reason(self.config) {
            map.serialize_entry("propagations_omitted_reason", &reason)?;
        }
        self.entry_points.borrow_mut().take();
        drop(projection_idg);
        self.ws.release_idg_service_cache();

        map.end()
    }
}

struct ExportTaintPropagationsStreaming<'a> {
    ws: &'a Workspace,
    spans: &'a ExportSpanCache,
    idg: &'a bonsai_idg::IdgQueryService,
    entry_points: &'a [ExportEntryPoint],
    full_propagations: bool,
}

impl Serialize for ExportTaintPropagationsStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        if !self.full_propagations {
            let seq = serializer.serialize_seq(Some(0))?;
            export_phase_log(format_args!(
                "taint.propagations: {:.3}s count=0 complete=false",
                phase_started.elapsed().as_secs_f64()
            ));
            return serde::ser::SerializeSeq::end(seq);
        }

        let global = self.idg.global_linkage_index();
        let mut render_cache = ExportTaintRecordRenderCache::default();
        let mut seq = serializer.serialize_seq(None)?;
        let mut count = 0usize;
        let progress_stride = self.entry_points.len().div_ceil(100).max(1);
        for ep in self.entry_points {
            let entry_func = FuncId::new(ep.func_id);
            let row_started = Instant::now();
            bonsai_diagnostics::debug_log!(
                "export-row",
                "taint propagation start index={} func={} name={}",
                count,
                ep.func_id,
                ep.function
            );
            {
                let row = export_taint_propagation_row_ref(
                    self.ws,
                    self.spans,
                    global.as_ref(),
                    self.idg,
                    &mut render_cache,
                    ep,
                    entry_func,
                );
                serde::ser::SerializeSeq::serialize_element(&mut seq, &row)?;
            }
            count += 1;
            bonsai_diagnostics::debug_log!(
                "export-row",
                "taint propagation complete index={} func={} name={} elapsed={:.6}s",
                count - 1,
                ep.func_id,
                ep.function,
                row_started.elapsed().as_secs_f64()
            );
            if count % progress_stride == 0 || count == self.entry_points.len() {
                export_phase_log(format_args!(
                    "taint.propagations progress={}/{} elapsed={:.3}s",
                    count,
                    self.entry_points.len(),
                    phase_started.elapsed().as_secs_f64()
                ));
            }
        }
        let result = serde::ser::SerializeSeq::end(seq);
        export_phase_log(format_args!(
            "taint.propagations: {:.3}s count={} complete=true",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        result
    }
}

struct ExportTaintChainsAndFlowLabels {
    chains: Vec<ExportChain>,
    chains_complete: bool,
    chains_mode: &'static str,
    chains_truncated_targets: usize,
    chains_incomplete_reason: Option<String>,
    flow_id_labels: Vec<ExportFlowIdLabels>,
    flow_id_labels_complete: bool,
    flow_id_labels_mode: &'static str,
    flow_id_labels_truncated_functions: usize,
    flow_id_labels_incomplete_reason: Option<String>,
}

fn export_taint_functions(
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
) -> Vec<ExportTaintFunction> {
    // ---- functions: FuncId → display name mapping (the single
    // authoritative table other sections reference by `func_id`). ----
    let mut functions: Vec<ExportTaintFunction> = Vec::new();
    let phase_started = Instant::now();
    for file in global.all_files() {
        for decl in global.decls_in(file) {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            let (path, line, _) = spans.format(decl.name_span);
            functions.push(ExportTaintFunction {
                file_id: file,
                func_id: decl.symbol.raw(),
                name: decl.name.clone(),
                qualified_name: decl.qualified_name.clone(),
                file: path,
                line,
                params: decl.params.clone(),
                kind: format!("{:?}", decl.kind).to_lowercase(),
            });
        }
    }
    functions.sort_by_key(|f| f.func_id);
    export_phase_log(format_args!(
        "taint.functions: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        functions.len()
    ));
    functions
}

fn export_structural_callgraph_count(ws: &Workspace, global: &bonsai_index::GlobalIndex) -> usize {
    let mut count = 0usize;
    if let Some(Ok(())) =
        ws.visit_persisted_callgraph_partitions(|_file, _nodes, outgoing, _incoming, _unresolved| {
            count += outgoing
                .iter()
                .filter(|edge| edge.precision.is_semantic())
                .filter(|edge| {
                    global.decl_of(SymbolId::new(edge.from.raw())).is_some()
                        && global.decl_of(SymbolId::new(edge.to.raw())).is_some()
                })
                .count();
        })
    {
        return count;
    }
    ws.cached_resolved_call_graph()
        .inner()
        .edges
        .iter()
        .filter(|edge| edge.precision.is_semantic())
        .filter(|edge| {
            global.decl_of(SymbolId::new(edge.from.raw())).is_some()
                && global.decl_of(SymbolId::new(edge.to.raw())).is_some()
        })
        .count()
}

struct ExportStructuralCallgraphStreaming<'a> {
    ws: &'a Workspace,
    global: &'a bonsai_index::GlobalIndex,
    spans: &'a ExportSpanCache,
}

impl Serialize for ExportStructuralCallgraphStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        let count = export_structural_callgraph_count(self.ws, self.global);
        let mut sequence = serializer.serialize_seq(Some(count))?;
        let mut serialization_error = None;
        let partition_result = self.ws.visit_persisted_callgraph_partitions(
            |_file, _nodes, outgoing, _incoming, _unresolved| {
                if serialization_error.is_some() {
                    return;
                }
                for edge in outgoing.iter().filter(|edge| edge.precision.is_semantic()) {
                    let Some(caller_decl) = self.global.decl_of(SymbolId::new(edge.from.raw())) else {
                        continue;
                    };
                    let Some(callee_decl) = self.global.decl_of(SymbolId::new(edge.to.raw())) else {
                        continue;
                    };
                    let (caller_line, _) = self.spans.line_col(caller_decl.name_span);
                    let (call_site_line, call_site_column) = self.spans.line_col(edge.span);
                    if let Err(error) = sequence.serialize_element(&CallEdgeOut {
                        caller: caller_decl.name.as_str(),
                        caller_file: self.spans.path(caller_decl.name_span.file),
                        caller_line,
                        callee: callee_decl.name.as_str(),
                        callee_kind: export_decl_kind_label(callee_decl.kind),
                        call_site_line,
                        call_site_column,
                        precision: export_precision_label(edge.precision),
                        resolver_stage: edge.provenance.resolver_stage(),
                        evidence: edge.provenance.evidence(),
                        confidence: edge.provenance.confidence(),
                    }) {
                        serialization_error = Some(error);
                        break;
                    }
                }
            },
        );
        if let Some(error) = serialization_error {
            return Err(error);
        }
        match partition_result {
            Some(Ok(())) => {}
            Some(Err(error)) => return Err(<S::Error as serde::ser::Error>::custom(error)),
            None => {
                let resolved = self.ws.cached_resolved_call_graph();
                for edge in resolved
                    .inner()
                    .edges
                    .iter()
                    .filter(|edge| edge.precision.is_semantic())
                {
                    let Some(caller_decl) = self.global.decl_of(SymbolId::new(edge.from.raw())) else {
                        continue;
                    };
                    let Some(callee_decl) = self.global.decl_of(SymbolId::new(edge.to.raw())) else {
                        continue;
                    };
                    let (caller_line, _) = self.spans.line_col(caller_decl.name_span);
                    let (call_site_line, call_site_column) = self.spans.line_col(edge.span);
                    sequence.serialize_element(&CallEdgeOut {
                        caller: caller_decl.name.as_str(),
                        caller_file: self.spans.path(caller_decl.name_span.file),
                        caller_line,
                        callee: callee_decl.name.as_str(),
                        callee_kind: export_decl_kind_label(callee_decl.kind),
                        call_site_line,
                        call_site_column,
                        precision: export_precision_label(edge.precision),
                        resolver_stage: edge.provenance.resolver_stage(),
                        evidence: edge.provenance.evidence(),
                        confidence: edge.provenance.confidence(),
                    })?;
                }
            }
        }
        export_phase_log(format_args!(
            "structural.callgraph: {:.3}s count={}",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        SerializeSeq::end(sequence)
    }
}

struct ExportTaintCallEdgesStreaming<'a> {
    ws: &'a Workspace,
}

impl Serialize for ExportTaintCallEdgesStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        let mut count = 0usize;
        let count_result = self.ws.visit_persisted_callgraph_partitions(
            |_file, _nodes, outgoing, _incoming, _unresolved| {
                count += outgoing
                    .iter()
                    .filter(|edge| edge.precision.is_semantic())
                    .count();
            },
        );
        let persisted = matches!(count_result, Some(Ok(())));
        let fallback_graph = (!persisted).then(|| self.ws.cached_resolved_call_graph());
        if let Some(graph) = fallback_graph.as_ref() {
            count = graph
                .inner()
                .edges
                .iter()
                .filter(|edge| edge.precision.is_semantic())
                .count();
        }
        let mut sequence = serializer.serialize_seq(Some(count))?;
        let mut serialization_error = None;
        if persisted {
            let visit_result = self.ws.visit_persisted_callgraph_partitions(
                |_file, _nodes, outgoing, _incoming, _unresolved| {
                    if serialization_error.is_some() {
                        return;
                    }
                    for edge in outgoing.iter().filter(|edge| edge.precision.is_semantic()) {
                        if let Err(error) = sequence.serialize_element(&ExportCallEdge {
                            from: edge.from.raw(),
                            to: edge.to.raw(),
                            kind: export_edge_kind_label(edge.kind),
                            precision: export_taint_precision_label(edge.precision),
                            resolver_stage: edge.provenance.resolver_stage(),
                            evidence: edge.provenance.evidence(),
                            confidence: edge.provenance.confidence(),
                        }) {
                            serialization_error = Some(error);
                            break;
                        }
                    }
                },
            );
            if let Some(error) = serialization_error {
                return Err(error);
            }
            match visit_result {
                Some(Ok(())) => {}
                Some(Err(error)) => return Err(<S::Error as serde::ser::Error>::custom(error)),
                None => {
                    return Err(<S::Error as serde::ser::Error>::custom(
                        "persisted callgraph disappeared during native export",
                    ));
                }
            }
        } else if let Some(graph) = fallback_graph.as_ref() {
            for edge in graph
                .inner()
                .edges
                .iter()
                .filter(|edge| edge.precision.is_semantic())
            {
                sequence.serialize_element(&ExportCallEdge {
                    from: edge.from.raw(),
                    to: edge.to.raw(),
                    kind: export_edge_kind_label(edge.kind),
                    precision: export_taint_precision_label(edge.precision),
                    resolver_stage: edge.provenance.resolver_stage(),
                    evidence: edge.provenance.evidence(),
                    confidence: edge.provenance.confidence(),
                })?;
            }
        }
        export_phase_log(format_args!(
            "taint.call_edges: {:.3}s count={}",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        SerializeSeq::end(sequence)
    }
}

fn export_function_summaries(
    return_taint_by_func: &ahash::AHashMap<FuncId, Vec<u32>>,
    functions: &[ExportTaintFunction],
) -> Vec<ExportFunctionSummary> {
    // ---- function_summaries: G1 return-value taint ----
    let phase_started = Instant::now();
    let mut function_summaries: Vec<ExportFunctionSummary> = functions
        .iter()
        .filter_map(|f| {
            let func = FuncId::new(f.func_id);
            let returns_taint_of: Vec<usize> = return_taint_by_func
                .get(&func)?
                .iter()
                .copied()
                .take_while(|idx| (*idx as usize) < f.params.len())
                .map(|idx| idx as usize)
                .collect();
            if returns_taint_of.is_empty() {
                return None;
            }
            Some(ExportFunctionSummary {
                function: f.name.clone(),
                file: f.file.clone(),
                line: f.line,
                returns_taint_of,
            })
        })
        .collect();
    function_summaries.sort_by(|a, b| a.function.cmp(&b.function));
    export_phase_log(format_args!(
        "taint.function_summaries: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        function_summaries.len()
    ));
    function_summaries
}

struct ExportReachableFactsStreaming<'a> {
    ws: &'a Workspace,
    functions: &'a [ExportTaintFunction],
}

impl Serialize for ExportReachableFactsStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        let mut sequence = serializer.serialize_seq(None)?;
        let mut count = 0usize;
        for functions in functions_by_file(self.functions) {
            let Some(index) = self.ws.exact_decl_index_shared(functions[0].file_id) else {
                continue;
            };
            let positions: ahash::AHashMap<u32, usize> = index
                .defs
                .iter()
                .enumerate()
                .map(|(position, decl)| (decl.symbol.raw(), position))
                .collect();
            for function in functions {
                let Some(decl) = positions
                    .get(&function.func_id)
                    .and_then(|position| index.defs.get(*position))
                else {
                    continue;
                };
                let kinded = bonsai_taint::name_reachable_through_decl_kinded(decl, &index);
                if kinded.by_kind.is_empty() {
                    continue;
                }
                let mut by_kind = std::collections::BTreeMap::new();
                for (kind, tokens) in kinded.by_kind {
                    let mut values: Vec<String> = tokens.into_iter().collect();
                    values.sort();
                    by_kind.insert(format!("{kind:?}").to_lowercase(), values);
                }
                sequence.serialize_element(&ExportReachableFacts {
                    func_id: function.func_id,
                    function: function.name.clone(),
                    by_kind,
                })?;
                count += 1;
            }
        }
        export_phase_log(format_args!(
            "taint.reachable_facts: {:.3}s count={}",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        SerializeSeq::end(sequence)
    }
}

struct ExportAssignChainsStreaming<'a> {
    idg: &'a bonsai_idg::IdgQueryService,
    functions: &'a [ExportTaintFunction],
}

impl Serialize for ExportAssignChainsStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        let funcs: Vec<FuncId> = self
            .functions
            .iter()
            .map(|function| FuncId::new(function.func_id))
            .collect();
        let functions_by_id: ahash::AHashMap<u32, &ExportTaintFunction> = self
            .functions
            .iter()
            .map(|function| (function.func_id, function))
            .collect();
        let mut sequence = serializer.serialize_seq(None)?;
        let mut count = 0usize;
        self.idg
            .try_visit_local_storage_taint_by_param_for_funcs_with_max_precision(
                &funcs,
                Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
                |func, storage_by_param| {
                    let Some(function) = functions_by_id.get(&func.raw()).copied() else {
                        return Ok(());
                    };
                    let mut per_param = Vec::new();
                    for (index, param) in function.params.iter().enumerate() {
                        if param.is_empty() {
                            continue;
                        }
                        let mut tainted: ahash::AHashSet<String> = storage_by_param
                            .get(index)
                            .into_iter()
                            .flatten()
                            .cloned()
                            .collect();
                        tainted.insert(param.clone());
                        if tainted.len() <= 1 {
                            continue;
                        }
                        let mut names: Vec<String> = tainted.into_iter().collect();
                        names.sort();
                        per_param.push(ExportAssignChainParam {
                            param_index: index,
                            param_name: param.clone(),
                            tainted: names,
                        });
                    }
                    if !per_param.is_empty() {
                        sequence.serialize_element(&ExportAssignChain {
                            func_id: function.func_id,
                            function: function.name.clone(),
                            per_param,
                        })?;
                        count += 1;
                    }
                    Ok(())
                },
            )?;
        export_phase_log(format_args!(
            "taint.assign_chains: {:.3}s count={}",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        SerializeSeq::end(sequence)
    }
}

struct ExportIntraTaintStreaming<'a> {
    ws: &'a Workspace,
    functions: &'a [ExportTaintFunction],
}

impl Serialize for ExportIntraTaintStreaming<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let phase_started = Instant::now();
        let mut sequence = serializer.serialize_seq(None)?;
        let mut count = 0usize;
        for functions in functions_by_file(self.functions) {
            let Some(index) = self.ws.exact_decl_index_shared(functions[0].file_id) else {
                continue;
            };
            let positions: ahash::AHashMap<u32, usize> = index
                .defs
                .iter()
                .enumerate()
                .map(|(position, decl)| (decl.symbol.raw(), position))
                .collect();
            for function in functions {
                let Some(decl) = positions
                    .get(&function.func_id)
                    .and_then(|position| index.defs.get(*position))
                else {
                    continue;
                };
                if let Some(row) = export_intra_taint_for_decl(decl) {
                    sequence.serialize_element(&row)?;
                    count += 1;
                }
            }
        }
        export_phase_log(format_args!(
            "taint.intra_taint: {:.3}s count={}",
            phase_started.elapsed().as_secs_f64(),
            count
        ));
        SerializeSeq::end(sequence)
    }
}

fn functions_by_file(functions: &[ExportTaintFunction]) -> impl Iterator<Item = &[ExportTaintFunction]> {
    let mut remaining = functions;
    std::iter::from_fn(move || {
        let first = remaining.first()?;
        let end = remaining
            .iter()
            .position(|function| function.file_id != first.file_id)
            .unwrap_or(remaining.len());
        let (group, tail) = remaining.split_at(end);
        remaining = tail;
        Some(group)
    })
}

fn export_intra_taint_for_decl(decl: &bonsai_lang_api::Decl) -> Option<ExportIntraTaint> {
    if decl.params.is_empty() {
        return None;
    }
    let cfg = bonsai_cfg::build_cfg_from_flow(&decl.name, &decl.flow_events);
    let mut per_param: Vec<ExportIntraTaintParam> = Vec::new();
    for (idx, param) in decl.params.iter().enumerate() {
        if param.is_empty() {
            continue;
        }
        let mut seed = bonsai_taint::TokenSet::default();
        seed.insert(param.clone());
        let cfg_config = bonsai_taint::TaintConfig { sources: seed };
        let result = bonsai_taint::intraprocedural_taint(&cfg, &cfg_config);
        let mut blocks: Vec<ExportIntraBlock> = Vec::new();
        let mut block_ids: Vec<u32> = cfg.blocks.iter().map(|block| block.id.raw()).collect();
        block_ids.sort_unstable();
        for bid_raw in block_ids {
            let bid = bonsai_common::BasicBlockId::new(bid_raw);
            let block_in = result.block_in.get(&bid).cloned().unwrap_or_default();
            let block_out = result.block_out.get(&bid).cloned().unwrap_or_default();
            if block_in.is_empty() && block_out.is_empty() {
                continue;
            }
            let mut in_vec: Vec<String> = block_in.into_iter().collect();
            let mut out_vec: Vec<String> = block_out.into_iter().collect();
            in_vec.sort();
            out_vec.sort();
            blocks.push(ExportIntraBlock {
                id: bid_raw,
                taint_in: in_vec,
                taint_out: out_vec,
            });
        }
        if !blocks.is_empty() {
            per_param.push(ExportIntraTaintParam {
                param_index: idx,
                param_name: param.clone(),
                iterations: result.iterations,
                blocks,
            });
        }
    }
    (!per_param.is_empty()).then(|| ExportIntraTaint {
        func_id: decl.symbol.raw(),
        function: decl.name.clone(),
        backend: "cfg_local",
        per_param,
    })
}

fn export_alias_maps(ws: &Workspace) -> Vec<ExportAliasMap> {
    let db = ws.db();

    // ---- alias_maps: per-file alias resolution ----
    let phase_started = Instant::now();
    let mut alias_maps: Vec<ExportAliasMap> = Vec::new();
    for file in ws.vfs().all_files() {
        let Some(imports) = db.import_index_uncached(file) else {
            continue;
        };
        let map = bonsai_lang_api::kit::alias_map_from_imports(&imports);
        if map.is_empty() {
            continue;
        }
        let path = ws.vfs().path(file).map_or_else(
            |_| "<unknown>".to_string(),
            |path| crate::workspace_relative_path(ws, &path.display().to_string()),
        );
        let mut entries: Vec<ExportAliasEntry> = map
            .into_iter()
            .map(|(local, target)| match target {
                bonsai_lang_api::AliasTarget::Member { module, member } => ExportAliasEntry {
                    local,
                    target_kind: "member",
                    module,
                    member: Some(member),
                },
                bonsai_lang_api::AliasTarget::Namespace { module } => ExportAliasEntry {
                    local,
                    target_kind: "namespace",
                    module,
                    member: None,
                },
                bonsai_lang_api::AliasTarget::Type { type_name } => ExportAliasEntry {
                    local,
                    target_kind: "type",
                    module: type_name,
                    member: None,
                },
            })
            .collect();
        entries.sort_by(|a, b| a.local.cmp(&b.local));
        alias_maps.push(ExportAliasMap { file: path, entries });
    }
    alias_maps.sort_by(|a, b| a.file.cmp(&b.file));
    export_phase_log(format_args!(
        "taint.alias_maps: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        alias_maps.len()
    ));
    alias_maps
}

fn export_class_fields(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportClassFields> {
    // ---- class_fields: per-class G3 field-taint ----
    let phase_started = Instant::now();
    let mut class_fields: Vec<ExportClassFields> = Vec::new();
    for file in ws.vfs().all_files() {
        let Some(index) = ws.exact_decl_index_shared(file) else {
            continue;
        };
        let decls = &index.defs;
        let classes: Vec<&bonsai_lang_api::Decl> = decls
            .iter()
            .filter(|d| {
                matches!(
                    d.kind,
                    DeclKind::Class
                        | DeclKind::Struct
                        | DeclKind::Trait
                        | DeclKind::Interface
                        | DeclKind::Enum
                )
            })
            .collect();
        for class in &classes {
            let mut tainted: ahash::AHashSet<String> = ahash::AHashSet::default();
            for decl in decls.iter() {
                if !matches!(
                    decl.kind,
                    DeclKind::Method | DeclKind::Constructor | DeclKind::Function
                ) {
                    continue;
                }
                let method_inside_class = decl.parent == Some(class.symbol);
                if !method_inside_class {
                    continue;
                }
                tainted.extend(
                    decl.receiver_field_writes
                        .iter()
                        .map(|write| write.target.clone()),
                );
            }
            if tainted.is_empty() {
                continue;
            }
            let (path, line, _) = spans.format(class.name_span);
            let mut fields: Vec<String> = tainted.into_iter().collect();
            fields.sort();
            class_fields.push(ExportClassFields {
                class: class.name.clone(),
                file: path,
                line,
                tainted_fields: fields,
            });
        }
    }
    class_fields.sort_by(|a, b| a.class.cmp(&b.class));
    export_phase_log(format_args!(
        "taint.class_fields: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        class_fields.len()
    ));
    class_fields
}

fn export_entry_points(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportEntryPoint> {
    // ---- entry_points: inferred source seeds used by security ----
    let phase_started = Instant::now();
    let mut entry_points = infer_entry_points_for_export(ws, spans);
    entry_points.sort_by(|a, b| {
        a.function
            .cmp(&b.function)
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.file.cmp(&b.file))
            .then_with(|| a.func_id.cmp(&b.func_id))
    });
    export_phase_log(format_args!(
        "taint.entry_points: {:.3}s count={}",
        phase_started.elapsed().as_secs_f64(),
        entry_points.len()
    ));
    entry_points
}

fn propagation_mode(config: NativeExportConfig) -> &'static str {
    if config.full_propagations {
        "materialized_entries"
    } else if config.compiled_propagations {
        "compiled_idg"
    } else {
        "omitted"
    }
}

fn propagation_omitted_reason(config: NativeExportConfig) -> Option<String> {
    (propagation_mode(config) == "omitted").then(|| {
        "interprocedural propagation records are omitted by default; rerun export --full-propagations for exhaustive propagation records".to_string()
    })
}

#[derive(Clone)]
struct ExportFuncRender {
    name: String,
    params: Vec<String>,
}

#[derive(Default)]
struct ExportTaintRecordRenderCache {
    records: ahash::AHashMap<CrossCallEdge, Option<ExportTaintRecord>>,
    funcs: ahash::AHashMap<FuncId, Option<ExportFuncRender>>,
    call_lines: ahash::AHashMap<Span, u32>,
    call_arg_texts: ahash::AHashMap<FuncId, Option<CallArgTextBySite>>,
}

type CallArgTextBySite = ahash::AHashMap<(Span, u32), String>;

fn export_taint_propagation_row_ref<'a>(
    ws: &Workspace,
    spans: &ExportSpanCache,
    global: &bonsai_index::GlobalIndex,
    idg: &bonsai_idg::IdgQueryService,
    render_cache: &'a mut ExportTaintRecordRenderCache,
    ep: &'a ExportEntryPoint,
    entry_func: bonsai_common::FuncId,
) -> ExportTaintPropagationsRef<'a> {
    let seed_nodes = canonical_token_seed_nodes(idg, entry_func, &ep.params, global);
    let mut cross_calls = idg.cross_call_edges_in_closure_with_max_precision(
        &seed_nodes,
        Some(EXPORT_SEMANTIC_FLOW_MAX_PRECISION),
    );
    sort_cross_call_edges_for_export(&mut cross_calls);
    let aggregate_precision =
        crate::taint::aggregate_flow_precision(cross_calls.iter().map(|ce| ce.precision));
    let unique_pairs: ahash::AHashSet<(bonsai_common::FuncId, bonsai_common::FuncId)> =
        cross_calls.iter().map(|ce| (ce.caller, ce.callee)).collect();
    let pairs_analyzed = std::cmp::max(1, unique_pairs.len());
    cross_calls.retain(|ce| ensure_cached_export_taint_record(render_cache, ce, global, spans, ws));
    let records: Vec<&ExportTaintRecord> = cross_calls
        .iter()
        .filter_map(|ce| render_cache.records.get(ce).and_then(Option::as_ref))
        .collect();
    ExportTaintPropagationsRef {
        entry: &ep.function,
        entry_file: &ep.file,
        entry_line: ep.line,
        precision: export_precision_label(aggregate_precision),
        pairs_analyzed: u32::try_from(pairs_analyzed).unwrap_or(u32::MAX),
        records,
    }
}

fn canonical_token_seed_nodes(
    idg: &bonsai_idg::IdgQueryService,
    entry_func: bonsai_common::FuncId,
    names: &[String],
    global: &bonsai_index::GlobalIndex,
) -> Vec<bonsai_idg::WsNodeId> {
    let seeds: bonsai_taint::TokenSet = names.iter().cloned().collect();
    bonsai_taint::compose_idg_seed_nodes(
        bonsai_taint::IdgSeedRequest::token_api(entry_func, &seeds),
        global,
        idg,
    )
}

fn sort_cross_call_edges_for_export(cross_calls: &mut [CrossCallEdge]) {
    cross_calls.sort_unstable_by_key(|ce| {
        (
            ce.caller.raw(),
            ce.callee.raw(),
            ce.call_span.file.raw(),
            ce.call_span.start,
            export_edge_kind_rank(ce.call_kind),
            export_precision_rank(ce.precision),
            ce.arg_idx,
            ce.param_idx,
        )
    });
}

fn ensure_cached_export_taint_record(
    cache: &mut ExportTaintRecordRenderCache,
    edge: &CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
    ws: &Workspace,
) -> bool {
    if let Some(cached) = cache.records.get(edge) {
        return cached.is_some();
    }
    let rendered = export_taint_record_from_cross_call(cache, edge, global, spans, ws);
    let present = rendered.is_some();
    cache.records.insert(*edge, rendered);
    present
}

fn export_taint_record_from_cross_call(
    cache: &mut ExportTaintRecordRenderCache,
    edge: &CrossCallEdge,
    global: &bonsai_index::GlobalIndex,
    spans: &ExportSpanCache,
    ws: &Workspace,
) -> Option<ExportTaintRecord> {
    if !edge.relation.is_renderable_call() {
        return None;
    }
    let caller = cached_export_func_render(cache, global, edge.caller)?;
    let callee = cached_export_func_render(cache, global, edge.callee)?;
    let call_line = cached_export_call_line(cache, spans, edge.call_span);
    let param_name = callee
        .params
        .get(edge.param_idx as usize)
        .cloned()
        .unwrap_or_default();
    let tainted_args = if edge.arg_idx != u32::MAX {
        vec![ExportTaintedArg {
            index: edge.arg_idx as usize,
            value_text: cached_export_call_arg_text(cache, ws, edge.caller, edge.call_span, edge.arg_idx)
                .unwrap_or_default(),
            param_name,
        }]
    } else if matches!(
        edge.relation,
        bonsai_idg::CrossCallRelation::Argument | bonsai_idg::CrossCallRelation::Capture
    ) {
        if let Some(receiver) = cached_export_call_arg_text(cache, ws, edge.caller, edge.call_span, u32::MAX)
            .filter(|receiver| !receiver.trim().is_empty())
        {
            vec![ExportTaintedArg {
                index: usize::MAX,
                value_text: receiver,
                param_name,
            }]
        } else if edge.relation == bonsai_idg::CrossCallRelation::Capture && edge.param_idx != u32::MAX {
            vec![ExportTaintedArg {
                index: edge.param_idx as usize,
                value_text: param_name.clone(),
                param_name,
            }]
        } else {
            Vec::new()
        }
    } else if edge.relation == bonsai_idg::CrossCallRelation::Callback && edge.param_idx != u32::MAX {
        vec![ExportTaintedArg {
            index: edge.param_idx as usize,
            value_text: param_name.clone(),
            param_name,
        }]
    } else {
        Vec::new()
    };

    Some(ExportTaintRecord {
        caller: caller.name,
        callee: callee.name,
        call_line,
        edge_kind: export_edge_kind_label(edge.call_kind),
        edge_precision: export_precision_label(edge.precision),
        tainted_args,
    })
}

fn cached_export_func_render(
    cache: &mut ExportTaintRecordRenderCache,
    global: &bonsai_index::GlobalIndex,
    func: FuncId,
) -> Option<ExportFuncRender> {
    if !cache.funcs.contains_key(&func) {
        let rendered = global
            .decl_of(SymbolId::new(func.raw()))
            .map(|decl| ExportFuncRender {
                name: decl.name.clone(),
                params: decl.params.clone(),
            });
        cache.funcs.insert(func, rendered);
    }
    cache.funcs.get(&func).and_then(Clone::clone)
}

fn cached_export_call_line(
    cache: &mut ExportTaintRecordRenderCache,
    spans: &ExportSpanCache,
    span: Span,
) -> u32 {
    if let Some(line) = cache.call_lines.get(&span) {
        return *line;
    }
    let (line, _) = spans.line_col(span);
    cache.call_lines.insert(span, line);
    line
}

fn cached_export_call_arg_text(
    cache: &mut ExportTaintRecordRenderCache,
    ws: &Workspace,
    caller: FuncId,
    call_span: Span,
    arg_idx: u32,
) -> Option<String> {
    if !cache.call_arg_texts.contains_key(&caller) {
        let rendered = export_call_arg_texts_for_func(ws, caller);
        cache.call_arg_texts.insert(caller, rendered);
    }
    cache
        .call_arg_texts
        .get(&caller)
        .and_then(Option::as_ref)
        .and_then(|arg_texts| arg_texts.get(&(call_span, arg_idx)).cloned())
}

fn export_call_arg_texts_for_func(
    ws: &Workspace,
    func: FuncId,
) -> Option<ahash::AHashMap<(Span, u32), String>> {
    let decl = ws.exact_decl(SymbolId::new(func.raw()))?;
    let mut arg_texts = ahash::AHashMap::default();
    collect_export_call_arg_texts(&decl.flow_events, &mut arg_texts);
    Some(arg_texts)
}

fn collect_export_call_arg_texts(events: &[FlowEvent], out: &mut ahash::AHashMap<(Span, u32), String>) {
    for event in events {
        match event {
            FlowEvent::Call {
                span, receiver, args, ..
            } => {
                if let Some(receiver) = receiver
                    .as_deref()
                    .map(str::trim)
                    .filter(|receiver| !receiver.is_empty())
                {
                    out.insert((*span, u32::MAX), receiver.to_string());
                }
                for (idx, arg) in args.iter().enumerate() {
                    let Ok(idx) = u32::try_from(idx) else {
                        continue;
                    };
                    out.insert((*span, idx), arg.value_text.clone());
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                collect_export_call_arg_texts(then_events, out);
                collect_export_call_arg_texts(else_events, out);
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                collect_export_call_arg_texts(body, out);
                collect_export_call_arg_texts(catch_events, out);
                collect_export_call_arg_texts(finally_events, out);
            }
            FlowEvent::Loop { body, .. } => {
                collect_export_call_arg_texts(body, out);
            }
            _ => {}
        }
    }
}

fn export_edge_kind_label(kind: bonsai_callgraph::EdgeKind) -> &'static str {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => "direct",
        bonsai_callgraph::EdgeKind::Virtual => "virtual",
        bonsai_callgraph::EdgeKind::Indirect => "indirect",
        bonsai_callgraph::EdgeKind::Unknown => "unknown",
    }
}

fn export_edge_kind_rank(kind: bonsai_callgraph::EdgeKind) -> u8 {
    match kind {
        bonsai_callgraph::EdgeKind::Direct => 0,
        bonsai_callgraph::EdgeKind::Virtual => 1,
        bonsai_callgraph::EdgeKind::Indirect => 2,
        bonsai_callgraph::EdgeKind::Unknown => 3,
    }
}

fn export_decl_kind_label(kind: DeclKind) -> &'static str {
    match kind {
        DeclKind::Module => "module",
        DeclKind::Namespace => "namespace",
        DeclKind::Function => "function",
        DeclKind::Method => "method",
        DeclKind::Constructor => "constructor",
        DeclKind::Class => "class",
        DeclKind::Struct => "struct",
        DeclKind::Trait => "trait",
        DeclKind::Interface => "interface",
        DeclKind::Enum => "enum",
        DeclKind::EnumVariant => "enumvariant",
        DeclKind::TypeAlias => "typealias",
        DeclKind::Global => "global",
        DeclKind::Const => "const",
        DeclKind::Static => "static",
        DeclKind::Import => "import",
        DeclKind::Field => "field",
        DeclKind::Other => "other",
    }
}

/// Preserve the original native taint-edge wire spelling, which predates the
/// hyphenated presentation label used by structural callgraph rows.
fn export_taint_precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "overapproximate",
        Precision::Unknown => "unknown",
    }
}

fn export_precision_label(precision: Precision) -> &'static str {
    match precision {
        Precision::Exact => "exact",
        Precision::Narrowed => "narrowed",
        Precision::OverApproximate => "over-approximate",
        Precision::Unknown => "unknown",
    }
}

fn export_precision_rank(precision: Precision) -> u8 {
    match precision {
        Precision::Exact => 0,
        Precision::Narrowed => 1,
        Precision::OverApproximate => 2,
        Precision::Unknown => 3,
    }
}

fn export_taint_chains_and_flow_labels() -> ExportTaintChainsAndFlowLabels {
    let phase_started = Instant::now();
    export_phase_log(format_args!(
        "taint.chains: {:.3}s count={} truncated_targets={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        0,
        0,
        "compressed_callgraph"
    ));
    let phase_started = Instant::now();
    export_phase_log(format_args!(
        "taint.flow_id_labels: {:.3}s count={} truncated_functions={} mode={}",
        phase_started.elapsed().as_secs_f64(),
        0,
        0,
        "compressed_callgraph"
    ));

    ExportTaintChainsAndFlowLabels {
        chains: Vec::new(),
        chains_complete: false,
        chains_mode: "compressed_callgraph",
        chains_truncated_targets: 0,
        chains_incomplete_reason: Some(COMPRESSED_CHAIN_ROWS_REASON.to_string()),
        flow_id_labels: Vec::new(),
        flow_id_labels_complete: false,
        flow_id_labels_mode: "compressed_callgraph",
        flow_id_labels_truncated_functions: 0,
        flow_id_labels_incomplete_reason: Some(COMPRESSED_FLOW_ID_ROWS_REASON.to_string()),
    }
}

fn infer_entry_points_for_export(ws: &Workspace, spans: &ExportSpanCache) -> Vec<ExportEntryPoint> {
    type EntryParamMap = std::collections::BTreeMap<u32, (String, String, u32, Vec<String>, &'static str)>;

    let headers = ws.compiler_header_index();
    let functions = headers
        .all_files()
        .flat_map(|file| {
            headers
                .functions_in(file)
                .map(|decl| FuncId::new(decl.symbol.raw()))
        })
        .collect::<Vec<_>>();
    let callees_seen = ws.functions_with_semantic_callers(&functions);
    drop(functions);
    drop(headers);

    let class_field_writes = collect_class_field_taints_for_entries(ws);
    let mut entry_params: EntryParamMap = std::collections::BTreeMap::new();

    for file in ws.vfs().all_files() {
        let Some(index) = ws.exact_decl_index_shared(file) else {
            continue;
        };
        for decl in &index.defs {
            if !matches!(
                decl.kind,
                DeclKind::Function | DeclKind::Method | DeclKind::Constructor
            ) {
                continue;
            }
            if is_generated_callable_name(&decl.name) {
                continue;
            }
            let has_callers = callees_seen.contains(&FuncId::new(decl.symbol.raw()));
            let decorator_entry = detect_framework_decorator(ws, &index, file, decl.span, decl.name_span);
            let entry_kind = if decorator_entry {
                Some("decorator")
            } else if !has_callers && matches!(decl.kind, DeclKind::Function | DeclKind::Method) {
                Some("unreferenced")
            } else {
                None
            };
            if let Some(kind) = entry_kind {
                let (file_path, line, _) = spans.format(decl.name_span);
                let entry = entry_params
                    .entry(decl.symbol.raw())
                    .or_insert_with(|| (decl.name.clone(), file_path, line, Vec::new(), kind));
                for (idx, param) in decl.params.iter().enumerate() {
                    if decl.receiver_param_index == Some(idx) {
                        continue;
                    }
                    if !entry.3.iter().any(|p| p == param) {
                        entry.3.push(param.clone());
                    }
                }
                if kind == "decorator" {
                    entry.4 = "decorator";
                }
            }

            let class_symbol = decl.parent;
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let Some(fields) = class_field_writes.get(&class_symbol) else {
                continue;
            };
            let mut sorted: Vec<&String> = fields.iter().collect();
            sorted.sort();
            for field_name in sorted {
                if !flow_reads_token(&decl.flow_events, field_name) {
                    continue;
                }
                let (file_path, line, _) = spans.format(decl.name_span);
                let entry = entry_params
                    .entry(decl.symbol.raw())
                    .or_insert_with(|| (decl.name.clone(), file_path, line, Vec::new(), "class_field"));
                if !entry.3.iter().any(|p| p == field_name) {
                    entry.3.push(field_name.clone());
                }
                if entry.4 != "decorator" {
                    entry.4 = "class_field";
                }
            }
        }
    }

    entry_params
        .into_iter()
        .filter(|(_func_id, (function, _file, _line, _params, _kind))| !is_generated_callable_name(function))
        .map(
            |(func_id, (function, file, line, params, kind))| ExportEntryPoint {
                func_id,
                function,
                file,
                line,
                kind,
                params,
            },
        )
        .collect()
}

/// True when `name` looks like an adapter-synthesised pseudo-name
/// (`<lambda>`, `<closure>`) rather than a real user-declared
/// function. We exclude these from entry-point inference because
/// they're never the entry to a real chain.
fn is_generated_callable_name(name: &str) -> bool {
    name.starts_with('<') && name.ends_with('>')
}

fn flow_reads_token(events: &[FlowEvent], token: &str) -> bool {
    for event in events {
        match event {
            FlowEvent::Call { receiver, args, .. } => {
                if receiver.as_deref() == Some(token)
                    || args
                        .iter()
                        .any(|arg| arg.place.as_deref() == Some(token) || arg.value_text.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Assign {
                source_name,
                source_names,
                source_call_args,
                ..
            } => {
                if source_name.as_deref() == Some(token)
                    || source_names.iter().any(|name| name == token)
                    || source_call_args.iter().any(|arg| arg.trim() == token)
                {
                    return true;
                }
            }
            FlowEvent::Return {
                value_text,
                value_name,
                ..
            } => {
                if value_text.as_deref() == Some(token) || value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Throw { value_name, .. } => {
                if value_name.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Yield { value_text, .. } => {
                if value_text.as_deref() == Some(token) {
                    return true;
                }
            }
            FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                if flow_reads_token(then_events, token) || flow_reads_token(else_events, token) {
                    return true;
                }
            }
            FlowEvent::Loop { body, .. } | FlowEvent::Defer { body, .. } | FlowEvent::Using { body, .. } => {
                if flow_reads_token(body, token) {
                    return true;
                }
            }
            FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                if flow_reads_token(body, token)
                    || flow_reads_token(catch_events, token)
                    || flow_reads_token(finally_events, token)
                {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn collect_class_field_taints_for_entries(
    ws: &Workspace,
) -> ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> {
    let mut out: ahash::AHashMap<bonsai_common::SymbolId, ahash::AHashSet<String>> =
        ahash::AHashMap::default();
    for file in ws.vfs().all_files() {
        let Some(index) = ws.exact_decl_index_shared(file) else {
            continue;
        };
        for decl in &index.defs {
            if !matches!(
                decl.kind,
                DeclKind::Method | DeclKind::Constructor | DeclKind::Function
            ) {
                continue;
            }
            let class_symbol = decl.parent;
            let Some(class_symbol) = class_symbol else {
                continue;
            };
            let entry = out.entry(class_symbol).or_default();
            entry.extend(
                decl.receiver_field_writes
                    .iter()
                    .map(|write| write.target.clone()),
            );
        }
    }
    out
}

/// True when a Decorator ref is statically attached to `decl_span`.
///
/// Keep this routed through the same helper as `defs --has-decorator`
/// so export entrypoint inference cannot drift into a broader
/// file-scoped or gap-only heuristic.
fn detect_framework_decorator(
    ws: &Workspace,
    index: &bonsai_lang_api::DeclIndex,
    file: FileId,
    decl_span: Span,
    decl_name_span: Span,
) -> bool {
    !decl_decorator_names(ws, file, index, decl_span, decl_name_span).is_empty()
}

fn count_call_sites_for_export(events: &[bonsai_lang_api::FlowEvent], call_site_count: &mut usize) {
    for e in events {
        match e {
            bonsai_lang_api::FlowEvent::Call { .. }
            | bonsai_lang_api::FlowEvent::Assign {
                source_call: Some(_), ..
            } => *call_site_count += 1,
            bonsai_lang_api::FlowEvent::Branch {
                then_events,
                else_events,
                ..
            } => {
                count_call_sites_for_export(then_events, call_site_count);
                count_call_sites_for_export(else_events, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Loop { body, .. } => {
                count_call_sites_for_export(body, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Try {
                body,
                catch_events,
                finally_events,
                ..
            } => {
                count_call_sites_for_export(body, call_site_count);
                count_call_sites_for_export(catch_events, call_site_count);
                count_call_sites_for_export(finally_events, call_site_count);
            }
            bonsai_lang_api::FlowEvent::Defer { body, .. }
            | bonsai_lang_api::FlowEvent::Using { body, .. } => {
                count_call_sites_for_export(body, call_site_count);
            }
            _ => {}
        }
    }
}

#[cfg(test)]
#[path = "native_export_tests.rs"]
mod tests;
