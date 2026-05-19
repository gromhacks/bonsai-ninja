//! Control-flow graph derived from the `FlowEvent` tree an adapter emits.
//!
//! Every function's flow events already encode a structured CFG
//! implicitly (branch then/else arms, loop bodies, try/catch/finally
//! regions, early terminators). [`build_cfg_from_flow`] makes that
//! structure explicit: one [`BasicBlock`] per contiguous run of
//! sequential events, one block per branch arm, one block per loop
//! header / body / after, one block per try / catch / finally region,
//! with edges threaded through them.
//!
//! The resulting CFG is consumed by:
//!
//! - `bonsai_abstract_interp` — intraprocedural trace stepping.
//! - `bonsai-ninja dump-cfg` — the CLI debug dump.
//! - (future) `bonsai_taint` — directionality check for sanitizer
//!   attachment in security mode.

// `builder` is internal; consumers use `bonsai_cfg::build_cfg_from_flow`.
pub(crate) mod builder;

pub use builder::build_cfg_from_flow;

use bonsai_common::{BasicBlockId, Span};
use bonsai_lang_api::FlowEvent;
use serde::{Deserialize, Serialize};

fn analysis_complete_default() -> bool {
    false
}

/// One function's control-flow graph.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cfg {
    /// CFG construction is exact for the emitted HIR. This mirrors the
    /// completeness contract exposed by other debug and export commands.
    #[serde(default = "analysis_complete_default")]
    pub analysis_complete: bool,
    #[serde(default)]
    pub analysis_incomplete_reasons: Vec<String>,
    /// The decl this CFG was built for — carried for rendering / debug
    /// output. `""` for synthetic / empty CFGs.
    pub function: String,
    pub entry: BasicBlockId,
    pub exit: BasicBlockId,
    pub blocks: Vec<BasicBlock>,
}

impl Default for Cfg {
    fn default() -> Self {
        Self {
            analysis_complete: false,
            analysis_incomplete_reasons: vec!["cfg unavailable: empty default graph".to_string()],
            function: String::new(),
            entry: BasicBlockId::default(),
            exit: BasicBlockId::default(),
            blocks: Vec::new(),
        }
    }
}

impl Cfg {
    #[must_use]
    pub fn block(&self, id: BasicBlockId) -> Option<&BasicBlock> {
        self.blocks.get(id.raw() as usize)
    }
}

/// One basic block — a contiguous run of sequential flow events with
/// explicit successor edges. `label` is a short human-readable tag
/// (`entry` / `exit` / `then@<byte>` / `loop-header@<byte>` / …)
/// that makes `dump-cfg` output readable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BasicBlock {
    pub id: BasicBlockId,
    pub label: String,
    /// Structured role for builder-created shape blocks. Consumers
    /// use this instead of parsing `label`, so debug labels can
    /// change without changing CFG semantics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthetic_kind: Option<SyntheticBlockKind>,
    /// Sequential flow events that execute when control reaches this
    /// block. The block's terminator event (if any) is the last
    /// entry — `Return` / `Throw` / `Break` / `Continue` — or the
    /// block falls through to its successors.
    pub events: Vec<FlowEvent>,
    /// Basic blocks this one may transfer control to. At most two in
    /// practice (branch then/else, loop header vs after), but
    /// represented as a `Vec` for future extension and JSON simplicity.
    pub successors: Vec<BasicBlockId>,
    /// [`Terminator`] reflects how the block ends so consumers don't
    /// have to re-inspect `events`. `Fallthrough` means "transfer to
    /// the successors"; the specific terminators name the flow event
    /// that caused control to leave.
    pub terminator: Terminator,
    /// Span covering the first event in the block (or the whole
    /// function when the block is empty). Used by `dump-cfg` for
    /// location rendering and by `abstract_interp` for trace spans.
    pub span: Span,
}

/// CFG-shape block emitted by the builder rather than by source
/// statements. Kept separate from labels so pruning and downstream
/// analyses don't rely on string prefixes such as `join@` or
/// `loop-`.
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SyntheticBlockKind {
    Entry,
    Exit,
    BranchJoin,
    BranchThen,
    BranchElse,
    LoopHeader,
    LoopBody,
    LoopAfter,
    TryFork,
    TryBody,
    Catch,
    Finally,
    Unreachable,
}

/// How a [`BasicBlock`] transfers control. Kept structurally distinct
/// from `successors` so consumers (the abstract interpreter, security
/// taint) can distinguish "implicit fallthrough" from "explicit
/// return" even though both may have zero successors.
#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq, Eq)]
pub enum Terminator {
    /// The block falls through to its `successors`. Default for
    /// straight-line sequences and joins.
    #[default]
    Fallthrough,
    /// Conditional branch at the end of the block. `successors` =
    /// `[then_bb, else_bb]`.
    Branch,
    /// Loop header at the end of the block. `successors` =
    /// `[body_bb, after_bb]`.
    LoopHeader,
    /// Try-region fork. `successors` = `[try_body_bb, catch_bb]`.
    /// Distinct from `Branch` so the abstract interpreter doesn't
    /// charge try/catch forks against the user-facing
    /// `max_branches` budget — an exception edge is structurally a
    /// fork, but it isn't a conditional decision the user wrote.
    TryFork,
    /// Function-level `Return`. Usually no successors; may point at
    /// synthetic `finally` cleanup blocks before reaching function exit.
    Return,
    /// `Throw` / `raise` / `panic`. Usually no successors; may point at
    /// synthetic `finally` cleanup blocks before reaching function exit.
    Throw,
    /// `Break` / `last` — transfers to the enclosing loop's `after`
    /// block, represented as a successor to that block.
    Break,
    /// `Continue` / `next` — transfers to the enclosing loop's header,
    /// represented as a successor.
    Continue,
    /// Dead-code placeholder emitted after a `Return` / `Throw` /
    /// `Break` / `Continue` when more events follow in source order.
    /// No successors.
    Unreachable,
}
