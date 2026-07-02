//! Shared edge taxonomy for whole-program data-flow and taint.
//!
//! The taxonomy is deliberately language-neutral. Adapters lower syntax into
//! [`crate::FlowEvent`] and [`crate::Operation`] facts; engine crates then
//! project those facts into IDG, resolver, rulepack, and reporting surfaces.
//! This module names the user-visible propagation classes so tests and docs
//! can assert coverage without baking language-specific logic into the core.

use serde::{Deserialize, Serialize};

/// One language-neutral propagation class in the whole-program flow model.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FlowEdgeKind {
    /// `x = y`.
    LocalAssign,
    /// `z = x + y`, string interpolation, casts, or other expression RHS.
    ExprPropagation,
    /// Definition of a variable to a later use of that same variable.
    DefUse,
    /// Caller argument flows into callee formal parameter.
    ArgToParam,
    /// Method receiver object flows into the callee receiver binding.
    ReceiverToThis,
    /// Callee return flows into the caller call-result slot.
    ReturnToCaller,
    /// Value is written into an object/record/member field.
    FieldWrite,
    /// Value is read from an object/record/member field.
    FieldRead,
    /// Value is written through an array/subscript/index projection.
    IndexWrite,
    /// Value is read through an array/subscript/index projection.
    IndexRead,
    /// Constructor inputs flow into the constructed object or receiver state.
    ObjectConstruction,
    /// Pattern/destructuring/unpacking input flows into bound names.
    Destructuring,
    /// Outer-scope value is captured by a nested function/closure.
    ClosureCapture,
    /// Global or module-scope storage is read/written across scopes.
    GlobalAccess,
    /// Exported/imported symbol binding across files or modules.
    ImportExport,
    /// Alias/reference assignment preserves identity through another name.
    Alias,
    /// Pointer/reference/borrow/dereference projection.
    Dereference,
    /// Value is stored in an allocated object or heap cell.
    HeapStore,
    /// Value is loaded from an allocated object or heap cell.
    HeapLoad,
    /// Value is stored into container contents.
    ContainerStore,
    /// Value is loaded from container contents.
    ContainerLoad,
    /// Iterable contents flow into loop variables or iterator callbacks.
    Iteration,
    /// Yielded value flows out of a generator/coroutine.
    Yield,
    /// Thrown value flows into a catch/rescue/except binding.
    ThrowToCatch,
    /// Future/promise/task result flows into an await consumer.
    AwaitResolution,
    /// Value flows through a callback registration/invocation boundary.
    CallbackInvocation,
    /// Event/message payload flows into a handler parameter.
    EventDispatch,
    /// Dynamic property/member access such as `obj[key]` or reflection.
    DynamicPropertyAccess,
    /// Object/value flows into a serialized representation.
    Serialize,
    /// Serialized representation flows into an object/value.
    Deserialize,
    /// Tainted input flows through a rulepack-declared sanitizer output.
    Sanitize,
    /// Value flows into a rulepack-declared dangerous operation.
    Sink,
    /// Condition controls whether another statement executes.
    ControlDependence,
    /// Tainted condition influences an assigned value without direct value flow.
    ImplicitFlow,
    /// Any propagation crosses a source file or module boundary.
    InterFile,
    /// Any propagation crosses a package/library boundary.
    InterPackage,
}

impl FlowEdgeKind {
    /// Stable machine name used in JSON/docs/tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalAssign => "LOCAL_ASSIGN",
            Self::ExprPropagation => "EXPR_PROPAGATION",
            Self::DefUse => "DEF_USE",
            Self::ArgToParam => "ARG_TO_PARAM",
            Self::ReceiverToThis => "RECEIVER_TO_THIS",
            Self::ReturnToCaller => "RETURN_TO_CALLER",
            Self::FieldWrite => "FIELD_WRITE",
            Self::FieldRead => "FIELD_READ",
            Self::IndexWrite => "INDEX_WRITE",
            Self::IndexRead => "INDEX_READ",
            Self::ObjectConstruction => "OBJECT_CONSTRUCTION",
            Self::Destructuring => "DESTRUCTURING",
            Self::ClosureCapture => "CLOSURE_CAPTURE",
            Self::GlobalAccess => "GLOBAL_ACCESS",
            Self::ImportExport => "IMPORT_EXPORT",
            Self::Alias => "ALIAS",
            Self::Dereference => "DEREFERENCE",
            Self::HeapStore => "HEAP_STORE",
            Self::HeapLoad => "HEAP_LOAD",
            Self::ContainerStore => "CONTAINER_STORE",
            Self::ContainerLoad => "CONTAINER_LOAD",
            Self::Iteration => "ITERATION",
            Self::Yield => "YIELD",
            Self::ThrowToCatch => "THROW_TO_CATCH",
            Self::AwaitResolution => "AWAIT_RESOLUTION",
            Self::CallbackInvocation => "CALLBACK_INVOCATION",
            Self::EventDispatch => "EVENT_DISPATCH",
            Self::DynamicPropertyAccess => "DYNAMIC_PROPERTY_ACCESS",
            Self::Serialize => "SERIALIZE",
            Self::Deserialize => "DESERIALIZE",
            Self::Sanitize => "SANITIZE",
            Self::Sink => "SINK",
            Self::ControlDependence => "CONTROL_DEPENDENCE",
            Self::ImplicitFlow => "IMPLICIT_FLOW",
            Self::InterFile => "INTER_FILE",
            Self::InterPackage => "INTER_PACKAGE",
        }
    }

    /// Stable list of every taxonomy entry. Keep append-only unless a public
    /// edge class is deliberately retired and docs/tests are updated.
    pub const ALL: &'static [Self] = &[
        Self::LocalAssign,
        Self::ExprPropagation,
        Self::DefUse,
        Self::ArgToParam,
        Self::ReceiverToThis,
        Self::ReturnToCaller,
        Self::FieldWrite,
        Self::FieldRead,
        Self::IndexWrite,
        Self::IndexRead,
        Self::ObjectConstruction,
        Self::Destructuring,
        Self::ClosureCapture,
        Self::GlobalAccess,
        Self::ImportExport,
        Self::Alias,
        Self::Dereference,
        Self::HeapStore,
        Self::HeapLoad,
        Self::ContainerStore,
        Self::ContainerLoad,
        Self::Iteration,
        Self::Yield,
        Self::ThrowToCatch,
        Self::AwaitResolution,
        Self::CallbackInvocation,
        Self::EventDispatch,
        Self::DynamicPropertyAccess,
        Self::Serialize,
        Self::Deserialize,
        Self::Sanitize,
        Self::Sink,
        Self::ControlDependence,
        Self::ImplicitFlow,
        Self::InterFile,
        Self::InterPackage,
    ];
}

/// Where a taxonomy entry is implemented in the static analysis pipeline.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlowEdgeSupport {
    /// Native IDG reachability edge.
    NativeIdg,
    /// Syntax/operation fact that is exposed but not always a taint edge.
    OperationFact,
    /// Resolver/callgraph/import/export fact.
    ResolverFact,
    /// Rulepack-configured source/sink/sanitizer/API transfer.
    RulepackFact,
    /// CFG/control fact used for path pruning or inspection, not direct taint.
    ControlFact,
    /// Best-effort static approximation for inherently dynamic behavior.
    StaticBestEffort,
}

impl FlowEdgeSupport {
    /// Stable display string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NativeIdg => "native_idg",
            Self::OperationFact => "operation_fact",
            Self::ResolverFact => "resolver_fact",
            Self::RulepackFact => "rulepack_fact",
            Self::ControlFact => "control_fact",
            Self::StaticBestEffort => "static_best_effort",
        }
    }
}

/// Audit metadata for one taxonomy entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FlowEdgeSpec {
    /// Taxonomy entry.
    pub kind: FlowEdgeKind,
    /// Primary implementation location.
    pub support: FlowEdgeSupport,
    /// Shared facts or engine mechanisms that carry the edge.
    pub carriers: &'static [&'static str],
}

impl FlowEdgeSpec {
    /// Stable machine name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.kind.as_str()
    }
}

/// Complete static-analysis taxonomy contract.
pub const FLOW_EDGE_TAXONOMY: &[FlowEdgeSpec] = &[
    FlowEdgeSpec {
        kind: FlowEdgeKind::LocalAssign,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["FlowEvent::Assign", "IdgEdgeKind::IntraAssign"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ExprPropagation,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "FlowEvent::Assign::source_names",
            "CallArg::source_names",
            "template interpolation",
            "IdgEdgeKind::IntraAssign",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::DefUse,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["TransferCtx::last_writer", "IdgEdgeKind::IntraRead"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ArgToParam,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["Place::CallArg", "Place::Param", "IdgEdgeKind::InterCallArg"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ReceiverToThis,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "FlowEvent::Call::receiver",
            "Decl::receiver_param_index",
            "CallArg(u8::MAX)",
            "IdgEdgeKind::InterCallArg",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ReturnToCaller,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["Place::Return", "Place::CallRet", "IdgEdgeKind::InterReturn"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::FieldWrite,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "Decl::receiver_field_writes",
            "Place::Write.path",
            "IdgEdgeKind::IntraFieldWrite",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::FieldRead,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "Place::Read.path",
            "IdgEdgeKind::IntraFieldRead",
            "IdgEdgeKind::IntraRead",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::IndexWrite,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "kit::qualified",
            "Place::Write.path",
            "IdgEdgeKind::IntraFieldWrite",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::IndexRead,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "kit::qualified",
            "Place::Read.path",
            "IdgEdgeKind::IntraFieldRead",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ObjectConstruction,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "CallKind::Constructor",
            "Decl::receiver_field_writes",
            "constructor receiver stitching",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Destructuring,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "FlowEvent::Assign::source_names",
            "pattern bindings",
            "ImportScope::Local",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ClosureCapture,
        support: FlowEdgeSupport::StaticBestEffort,
        carriers: &[
            "FlowEvent tree nesting",
            "callback binding analysis",
            "capture tests",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::GlobalAccess,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "unrooted Place::Read",
            "module/global DeclKind",
            "TransferCtx::bridge_read",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ImportExport,
        support: FlowEdgeSupport::ResolverFact,
        carriers: &[
            "ImportSpec",
            "AliasTarget",
            "module_export_aliases",
            "ResolvedCallGraph",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Alias,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["FlowEvent::Assign", "AliasTarget", "sigil alias commits"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Dereference,
        support: FlowEdgeSupport::OperationFact,
        carriers: &[
            "OperationKind::Deref",
            "CallArg::place",
            "pointer/reference normalized places",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::HeapStore,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "receiver field writes",
            "constructor stitching",
            "Place::Write.path",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::HeapLoad,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "field projections",
            "return field projections",
            "Place::Read.path",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ContainerStore,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "container_field_initializers",
            "collection append calls",
            "Place::Write.path",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ContainerLoad,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "subscript normalization",
            "field-sensitive seed expansion",
            "Place::Read.path",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Iteration,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "LoopKind::ForEach",
            "FlowEvent::Yield",
            "collection callback tests",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Yield,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["FlowEvent::Yield", "Place::Yield", "IdgEdgeKind::IntraYield"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ThrowToCatch,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "FlowEvent::Throw",
            "FlowEvent::Try",
            "Place::Throw",
            "Place::Catch",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::AwaitResolution,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["FlowEvent::Await", "Place::Await", "IdgEdgeKind::IntraAwait"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::CallbackInvocation,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &[
            "CalleeResolver::callback_bindings",
            "SourceCallbackArgSpec",
            "IdgEdgeKind::InterCallArg",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::EventDispatch,
        support: FlowEdgeSupport::RulepackFact,
        carriers: &[
            "SourceCallbackArgSpec",
            "source_callback_args",
            "framework source rules",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::DynamicPropertyAccess,
        support: FlowEdgeSupport::StaticBestEffort,
        carriers: &[
            "kit::qualified",
            "OperationKind::Index",
            "subscript field-path fallback",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Serialize,
        support: FlowEdgeSupport::RulepackFact,
        carriers: &[
            "taint_semantics passthrough",
            "call_result_passthrough_args",
            "source/sink rules",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Deserialize,
        support: FlowEdgeSupport::RulepackFact,
        carriers: &[
            "taint_semantics passthrough",
            "call_result_passthrough_args",
            "source/sink rules",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Sanitize,
        support: FlowEdgeSupport::RulepackFact,
        carriers: &["sanitizers rules", "FindingStatus", "sanitizer_credit"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::Sink,
        support: FlowEdgeSupport::RulepackFact,
        carriers: &["sinks rules", "TaintedCall", "Finding"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ControlDependence,
        support: FlowEdgeSupport::ControlFact,
        carriers: &[
            "FlowEvent::Branch::condition",
            "OperationKind::BranchCondition",
            "CFG branch pruning",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::ImplicitFlow,
        support: FlowEdgeSupport::ControlFact,
        carriers: &[
            "FlowEvent::Branch::condition",
            "reported as control fact; not default taint propagation",
        ],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::InterFile,
        support: FlowEdgeSupport::NativeIdg,
        carriers: &["CrossFileEdges", "ResolvedCallGraph", "workspace IDG stitching"],
    },
    FlowEdgeSpec {
        kind: FlowEdgeKind::InterPackage,
        support: FlowEdgeSupport::ResolverFact,
        carriers: &[
            "WorkspaceSemanticContext",
            "dependency metadata",
            "package-gated rule evidence",
        ],
    },
];

/// Lookup audit metadata for a taxonomy entry.
#[must_use]
pub fn flow_edge_spec(kind: FlowEdgeKind) -> &'static FlowEdgeSpec {
    FLOW_EDGE_TAXONOMY
        .iter()
        .find(|spec| spec.kind == kind)
        .expect("every FlowEdgeKind has a taxonomy spec")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_edge_kind_has_one_spec() {
        let names: BTreeSet<_> = FLOW_EDGE_TAXONOMY.iter().map(|spec| spec.kind.as_str()).collect();
        let all: BTreeSet<_> = FlowEdgeKind::ALL.iter().map(|kind| kind.as_str()).collect();
        assert_eq!(names, all);
        assert_eq!(FLOW_EDGE_TAXONOMY.len(), FlowEdgeKind::ALL.len());
    }

    #[test]
    fn spec_carriers_are_non_empty() {
        for spec in FLOW_EDGE_TAXONOMY {
            assert!(!spec.name().is_empty());
            assert!(
                !spec.carriers.is_empty(),
                "{} must name at least one shared carrier",
                spec.name()
            );
            assert!(!spec.support.as_str().is_empty());
        }
    }
}
