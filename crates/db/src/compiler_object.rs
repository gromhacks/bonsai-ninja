//! Immutable, content-addressed compiler objects.
//!
//! Tree-sitter remains the syntax authority. This module persists the exact
//! language-adapter IR produced from one immutable source snapshot so later
//! compiler phases can stream that typed object instead of reparsing the same
//! file. Objects are accepted only when their strong source digest,
//! workspace-relative path/module context, selected language, and explicit
//! frontend semantic ABI all match.

use crate::AnalyzerDb;
use ahash::AHashSet;
use bonsai_common::{wire, workspace_bonsai_dir, FileId, Span, SymbolId, MATCHER_POLICY_FINGERPRINT};
use bonsai_diagnostics::{Diagnostic, DiagnosticSink, Severity};
use bonsai_factstore::{
    FactStoreError, FactStoreReader, FactStoreWriter, PreparedFactStoreEntry, PreparedFactStorePayload,
};
use bonsai_hash::fnv1a_bytes64;
use bonsai_lang_api::{
    CompilerAttribution, CompilerBrowseHeader, CompilerFunctionAttribution, CompilerSyntaxHeader, Decl,
    DeclIndex, ImportIndex,
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

/// Current per-file compiler-object wire and semantic ABI.
///
/// Bump this whenever adapter lowering, [`DeclIndex`], [`ImportIndex`],
/// [`CompilerSyntaxHeader`], [`CompilerBrowseHeader`], [`CompilerAttribution`],
/// or the object validation contract changes in a way that can alter compiler
/// facts.
// v171: aggregate assignment lowering commits the enclosing root overwrite
// before installing Tree-sitter-derived field and spread writes. Cached v170
// objects can emit those operations in the inverse order and immediately
// kill the exact descendant writers.
// v170: persisted call-site stitch facts retain the adapter-emitted receiver
// role so resolved property/getter projections forward exact fields without
// mapping the complete receiver root. Cached v169 payloads lack that role.
// v169: pseudo property/getter receivers carry a projection role so
// assignment lowering distinguishes field syntax from an ordinary receiver
// method. Cached v168 objects classify every pseudo receiver as a value.
// v168: Swift terminal property getters own the complete assignment value
// even when their receiver contains a nested call. Cached v167 objects can
// attribute that value to the inner call and lose the getter projection.
// v167: callable assignments prefer their complete adapter-lowered place
// before pattern bindings. Cached v166 objects can collapse `app.init` to
// `app` and lose exact method-family ownership.
// v166: parent-expression operands stop at callable scope boundaries, and
// Rust formatting captures attach only to their nearest parsed callable.
// Cached v165 objects can leak closure-local bindings into an outer value.
// v165: PHP terminal compound predicates retain a direct negated-call guard
// when the call itself is the unary operand. Cached v164 objects can omit the
// exact guard because descendant traversal excludes the operand root.
// v164: Perl filehandles participate in the adapter's generic parsed-reference
// inventory instead of a security-oriented special-name subset. Cached v163
// objects can omit ordinary filehandles or contain duplicate selected refs.
// v163: anonymous callables stored under exact static aggregate fields retain
// the field's Tree-sitter-proven structural name without falling back to
// rendered-text tokenization. Cached v162 objects can leave those callables
// anonymous and disconnect rule-owned external callback-map contracts.
// v160: adapters no longer synthesize external reflection/callback edges or
// runtime type hierarchies from provider spellings; Go character/prefix
// guards retain exact Tree-sitter-derived domains instead of sink-specific
// character/path policy. Cached v159 objects can therefore contain guessed
// call edges, invented supertypes, or policy-narrowed compiler facts.
// v158: JavaScript/TypeScript assignments distinguish compiler-proven
// whole-value selection (`||`, `&&`, `??`, and conditional expressions) from
// combining compound expressions. Cached v157 objects cannot safely decide
// whether a selected aggregate remains a complete root for later projections.
// v157: C arguments distinguish the address of a complete aggregate from
// scalar and byte-buffer addresses; Lua concatenations retain exact string
// composition facts; and JavaScript/TypeScript assignments retain parsed
// declaration-vs-mutation scope. Cached v156 objects can therefore omit or
// misclassify facts consumed by rule constraints and lexical-capture flow.
// v156: JavaScript/TypeScript member and subscript values retain property-read
// identity, and root bindings of compiler-proven property values remain
// complete addressable values for later exact projections. Cached v155
// objects can disconnect `file = req.files.avatar; file.name`.
// v155: Perl `<HANDLE>` assignment expressions retain their exact parsed
// filehandle value as an assignment input. Cached v154 objects can match a
// filehandle read without connecting that value to its assigned carrier.
// v154: Swift navigation expressions retain their exact property-read value
// kind alongside the adapter-emitted getter pseudo-call. Cached v153 objects
// can omit the projected storage producer from argument and assignment flow.
// v153: Rust assigned-match arms no longer lower their value expressions as
// enclosing-function returns, and explicitly typed immediately invoked
// closures retain the nominal receiver result used by rule-owned transfer
// summaries. Cached v152 objects can terminate the CFG before later calls or
// omit that exact receiver-type fact.
// v147: declaration-name identifiers are excluded from flat parameter
// fallback lowering, and exact higher-order callback environments retain
// lexical capture inputs at their compiler-proven registration site.
// v146: Go selector values retain property-read identity when their receiver
// is a nested call, and call-argument read edges retain the exact argument
// span. Cached v145 objects can collapse `c.Request().Body` to the nested
// `Request()` call result and disconnect exact read sources from the outer
// call boundary.
// v133: Dart switch-local breaks are resolved from exact Tree-sitter ancestry
// and no longer terminate the enclosing function after structured switch
// lowering. Cached v132 objects can prune every post-switch fact.
// v132: Dart collection-literal cascade initializers consume their exact
// post-cascade receiver state instead of replaying the bare literal as a clean
// overwrite. Cached v131 objects can erase a preceding cascade mutation.
// v131: Dart collection-literal locals retain their language-defined nominal
// receiver type even through cascades, enabling rule-owned core collection
// transfer summaries without method-name guesses. Cached v130 objects omit
// that exact receiver evidence.
// v130: C++ switch-targeted breaks are resolved from exact Tree-sitter
// ancestry and no longer terminate the enclosing function after structured
// switch lowering. Cached v129 objects can prune every post-switch fact.
// v129: C++ structured-binding declarators lower one exact positional
// call-result assignment per parsed binding. Cached v128 objects can retain
// the tuple-producing call while omitting every bound local value.
// v128: receiver typing preserves the qualified outer generic constructor
// while excluding nested type arguments from method-owner identity. Cached
// v127 objects can retain malformed/truncated generic receiver strings and
// miss an otherwise exact typed call rule.
// v127: C++ file-scope type aliases and unambiguous TU-private template
// instantiations refine generic local/receiver types from exact syntax. Cached
// v126 objects retain only the template-parameter placeholder and can suppress
// rule-owned typed transfer summaries inside an otherwise resolved body.
// v126: Go `select` communication cases retain mutually exclusive branch
// structure and returned-channel sends expose exact yield endpoints; Erlang
// assigned branch expressions no longer manufacture function termination;
// Kotlin terminal property reads and nested data-class copies retain their
// exact value facts; and Rust nested struct initializers retain canonical call
// facts. Cached v125 objects can flatten a terminating select arm over its
// live send sibling or omit these adapter-lowered transfers.
// v122: source ingestion preserves byte coordinates while admitting legacy
// bytes only in grammar-proven comments, and C-family parser-cache identity
// includes exact reachable preprocessor context. Cached v121 objects can
// reject otherwise valid translation units or replay recovery derived from a
// stale header snapshot.
// v121: fact-backed parser recovery mechanisms are evaluated independently;
// declaration identity remains stable when recovery masks preprocessing
// metadata outside the exact name/body anchors. Cached v120 objects can retain
// avoidable syntax damage or disagree with streamed body identities.
// v120: anonymous function-expression syntax is lowered as its own callable
// even when a grammar also lists that node kind among named functions;
// callable-valued arguments no longer absorb captured names as scalar host
// operands; and TypeScript retains exact aggregate/callable syntax instead of
// fabricating provider-specific dispatch calls. Cached v119 objects can drop
// callback bodies, mix closure captures into host arguments, or contain
// synthetic framework edges that were not proved by compiler facts.
// v119: Elixir `do_block` syntax is retained as a block argument rather than
// synthesized as an anonymous callable declaration. Cached v118 objects can
// fabricate module-definition call edges and hide real entrypoints.
// v118: Kotlin's transparent `annotated_lambda` wrapper no longer emits a
// second declaration beside its executable `lambda_literal`. Cached v117
// objects can contain duplicate symbols for one callback span.
// v117: call-argument lambdas retain independent callable declarations;
// passing a callable no longer inlines or executes its body in the caller.
// Cached v116 objects have the former mixed-scope callback lowering.
// v116: exception regions retain ordered, arm-local catch bindings and static
// types. Cached v115 objects flatten sibling handlers into one lossy binding
// and type union, which can connect a thrown value to an incompatible arm.
// v115: post-adapter event normalization preserves evaluator order for calls
// recovered by grammar-specific syntax passes, and IDG transfer consumes the
// canonical executable/defer-normalized control tree. Cached v114 objects may
// reverse nested calls or retain events after unconditional terminators.
// v113: typed branch operands retain an exact direct-call-result span. Rule
// semantics may now distinguish equality against a call result from an
// arithmetic or concatenation expression that merely contains a call.
// v112: character-constraint facts retain whether the adapter proved exact
// runtime predicate semantics or requires independently rule-declared source
// payload evidence. Cached v111 objects cannot represent that distinction.
// v110: Scala generator bindings preserve exact enumerator execution order;
// Dart awaited selector results and constructor cascades retain their direct
// value identity; Swift guard bindings and Kotlin primary constructors retain
// their complete adapter-lowered value flow. Cached v109 objects can omit or
// misorder those facts and must not feed callgraph or IDG sidecars.
// v108: direct-call assignment facts retain complete adapter-decoded static
// scalar arguments. Receiver/factory-state rules can consume exact constructor
// configuration without reparsing source; cached v107 bodies always omit it.
// v107: call-argument headers retain the adapter-proven exact scalar returned
// by a complete inline callback. Older objects cannot safely satisfy rules
// that distinguish accept-all callbacks from rejecting or mixed callbacks.
// v106: compact assignment-alias and factory-call headers retain their exact
// owner and assignment spans. Workspace call-result typing can now enforce
// lexical scope and shadowing without reopening compiler bodies; cached v105
// headers cannot safely answer that question.
// v105: compact return headers retain exact assignment-RHS spans for returned
// local bindings. Broad return-rule planning can now schedule a body from
// compiler-proven assignment evidence without scanning unrelated source text;
// cached v104 headers omit those spans and can suppress valid return matches.
// v103: Objective-C executable methods retain exact multipart selectors in
// their qualified semantic identity. Cached v102 objects only carry the first
// selector piece and can therefore merge distinct selector families.
// v102: Objective-C interface method prototypes remain declaration syntax but
// no longer lower as executable callable bodies beside their implementation.
// Cached v101 objects can therefore contain duplicate callable headers and
// ambiguous selector edges that the current frontend must reject.
// v101: call-argument facts and compact syntax headers retain inline callbacks
// nested beneath exact static aggregate-field paths. Rulepack typing can bind
// a configuration callback without parsing source text or assigning an API
// name in shared compiler code. Cached v100 objects omit that relationship.
// v98: Python keyed reads nested inside arbitrary call arguments no longer
// rewrite the outer call's assignment target. Exact keyed selections remain
// compiler projections when they are the value expression itself; resolved
// argument/parameter and return facts own every call boundary.
// v97: ERB host projection emits exact synthetic statement boundaries at
// closing tags, including trim-mode tags, so adjacent expressions on one HTML
// line cannot merge into a different Ruby program. Cached v96 templates can
// retain false syntax diagnostics or malformed embedded flow facts.
// v96: adapter-owned host-language normalization runs before Tree-sitter, and
// Ruby ERB/RHTML diagnostics and lowering share that exact same-width Ruby
// projection. Cached v95 objects can carry raw-HTML syntax diagnostics or
// differ from the parser-coverage snapshot used to certify completeness.
// v95: the C# adapter recovers file-based-program `#:` compiler directives as
// exact same-width metadata masks. Cached v94 objects can carry false syntax
// diagnostics or omit top-level declarations and flow facts after a directive.
// v94: the TypeScript adapter recovers valid import-type queries that the
// upstream TS/TSX grammar damages when an array suffix participates in a
// function type, and compiler syntax headers retain exact class-like direct
// bases for independently streamed receiver ancestry. Cached v93 objects can
// carry false syntax diagnostics, omit declaration/type facts after the
// damaged span, or require a workspace-sized declaration table for ancestry.
// v93: exact projected receiver aliases take precedence over their containing
// object type, and Rust module-private items retain lexical ModuleTree scope.
// Cached v92 objects can dispatch a tuple/newtype field back to its wrapper or
// reject a valid descendant-module call.
// v92: Rust retains the AST-proven `impl Type` receiver type on methods even
// when the type declaration is in another module, and workspace-qualifies
// rooted crate/self/super imports and calls. Cached v91 objects can omit exact
// split-impl call edges or reuse a rooted path from the wrong Cargo package.
// v91: tree-sitter-language-pack v1.15.0 refreshes the pinned grammars. Swift
// accepts additional concurrency syntax directly, and Scala corrects operator
// precedence and associativity. Cached v90 objects were lowered by the v1.8.0
// grammar set and are not semantically interchangeable.
// v90: the Swift adapter normalizes the valid unparenthesized conditional-cast
// plus nil-coalescing form before lowering. Cached v89 objects can retain a
// grammar diagnostic and omit the cast operand from exact value flow.
// v89: tree-sitter-language-pack v1.8.0 supplies the complete six-platform
// parser bundle matrix and updates the pinned grammar set. Erlang remote-call
// arguments now follow their exact nested call wrapper; modern Dart unnamed
// libraries and Kotlin multiplatform declarations parse without recovery.
// Cached v88 objects were lowered by the v1.6.1 grammar set and are not
// semantically interchangeable.
// v88: C++ ownership proof derives exclusive syntax from the C and C++
// Tree-sitter grammar inventories, with an exact structural distinction for
// their shared compound-literal node. Cached v87 objects used a finite C++
// node-kind list and can retain the generic C frontend for other valid C++
// header syntax.
// v86: exact adapter recovery covers an unnamed Dart library declaration,
// Kotlin KDoc before a multiplatform `actual` class, branch-free conditional
// regions, modern Swift concurrency/unit syntax, and Objective-C declaration
// macros. Hidden grammar-missing symbols retain a non-zero damage score;
// grammar-owned C++/Objective-C evidence disambiguates shared headers and
// excludes specialized superset grammars when their syntax is absent.
// Cached v85 objects can preserve stale diagnostics, parser coverage, or
// declarations for otherwise valid source.
// v85: ECMAScript assignment lowering resolves immutable function-valued
// bindings as exact callable aliases. Cached v84 objects can omit those
// assigned method edges.
// v84: ECMAScript adapters mark simple `const name = value` places immutable
// from exact lexical-declaration syntax. Cached v83 objects leave those
// places mutable/unknown and cannot support configured-receiver proofs.
// v83: the independently decodable syntax header retains exact
// adapter-lowered return targets and their exact AST spans so broad rule
// planning can reject impossible files without decoding bodies. Cached v82
// headers omit those targets.
// v82: branch adapters declare unfielded discriminant wrappers and every
// direct arm kind; nested lambda wrappers unwrap to the executable callback
// body. Cached v81 objects can omit switch/default/when and Kotlin callback
// calls.
// v81: shared control-flow lowering retains every adapter-declared branch arm
// and lowers expression-bodied callbacks as complete expressions. PHP
// parameter attribute lists are also declared explicitly by its adapter.
// Cached v80 objects can omit those calls and parameter annotations.
// v80: Lua static bracket writes retain the grammar-declared key field, and
// Ruby unbound identifier receivers materialize their zero-argument call
// result before a chained member call. Cached v79 objects can omit both.
// v79: PHP append assignments lower their index-less subscript target to the
// parsed aggregate place. Cached v78 objects can omit the aggregate mutation
// and disconnect values collected with `$items[] = value` from later reads.
// v78: calls retain the exact receiver node selected by the owning adapter;
// cached v77 objects can omit scoped receivers whose source punctuation is
// not the canonical dotted IR delimiter.
// v77: C++ same-type direct-list initialization retains whole-object copy
// semantics, and parsed template specializations bind to their base callable
// declaration identity. Cached v76 objects can misproject one copied object
// into its first aggregate field or leave template calls unresolved.
// v76: assignment targets may use an adapter-owned assignment-place decoder
// when their grammar reuses call-shaped syntax for a writable property.
// Cached v75 objects can omit those exact writes and must not feed matcher,
// callgraph, or IDG sidecars.
// v75: adapter-lowered dataflow retains exact destructuring carriers,
// indirect-place write-back operands, callable-reference arguments, tuple
// result slots, inline constructed-receiver types, and yield-result bindings
// across the supported grammars. Cached v74 objects can omit or weaken those
// compiler facts and must not feed callgraph or IDG sidecars.
// v74: assignment, return, and call-argument compiler facts carry exact
// adapter-owned value shape, and literal/string/runtime-guard classification
// is selected solely from the active grammar's inventories. Clean-overwrite
// and endpoint attribution can distinguish literals from dynamic values
// without parsing rendered text, guessing from identifier capitalization, or
// consulting a shared cross-language token table. Cached v73 objects omit
// these semantic facts.
// v73: Kotlin constructors include only their actual executable regions:
// direct property initializers/delegates and anonymous init blocks for the
// primary constructor, plus exact this/super delegation and the block for a
// directly owned secondary constructor. Classes that declare only secondary
// constructors no longer receive a fabricated implicit primary. Cached v72
// objects can retain computed/sibling members, mis-own nested constructors,
// or omit secondary-constructor delegation.
// v72: Swift designated constructors include only their exact executable
// instance-property initializer prefixes; static properties and sibling
// callable bodies are excluded, and superclass inheritance is known before
// implicit-initializer synthesis. Cached v71 objects can retain the earlier
// constructor body boundary.
// v71: adapter construction/call semantics use exact declaration and CST
// evidence across Kotlin field initialization, Lua dot calls, and Ruby
// temporary constructed receivers. Cached v70 bodies can omit or misclassify
// those call edges.
// v70: declaration headers retain adapter-proven receiver-field direct-call
// initializers. Sparse callgraph/IDG builds can resolve a field's constructed
// type across files after constructor bodies are evicted, without restoring
// capitalization heuristics or reparsing source.
// v69: compact syntax headers retain exact inline-callback argument bindings
// and typed callable bindings. Rulepack-declared external callback signatures
// can therefore participate in broad rule planning without decoding bodies
// or placing provider API identities in language adapters.
// v68: Rust tuple-struct fields lower directly from Tree-sitter's ordered
// field type nodes, preserving positional receiver types such as `self.0`.
// Cached v67 objects can omit those projected receiver/call edges.
// v67: Rust scoped call targets are receiver-less path calls, and visible
// `use` bindings retain their declaration-level facade/target identity.
// Module and type ownership is resolved semantically instead of being lowered
// as an instance receiver or inferred from a physical filename.
// v66: Rust named-struct field declarations and item-macro-wrapped impls
// propagate exact receiver/callable facts; qualified receiver identities no
// longer replay a weaker same-named bare type; enum methods participate in
// receiver typing. Cached v64 objects can omit or misresolve those edges.
// v64: Erlang `fun name/arity` and Perl `\&name` call arguments retain an
// adapter-proven exact callable place. Cached v63 objects can omit callback
// edges after the callgraph correctly rejects compound data expressions.
// v63: Python annotated assignment fields and typing-wrapper payloads retain
// their AST-derived receiver types. Cached v62 objects can mis-type a
// constructed field from one of its constructor arguments.
// v62: call-argument facts retain adapter-lowered inline callback parameter
// bindings. Configured source-callback delivery can therefore enter an
// inlined callback body without parsing rendered lambda text or inventing a
// synthetic callable declaration.
// v61: Java compilation units without a package declaration use the unnamed
// package rather than a filename-derived namespace; Perl, Ruby, and Rust
// structured control facts track their current Tree-sitter grammar nodes.
// v60: Go interpreted strings assemble exact byte/octal escapes before UTF-8
// conversion, retaining valid multi-byte static scalar values while invalid
// byte strings still fail closed.
// v59: Python finite-map and character-substitution binding checks resolve
// lexical owners, nested closures, and global/nonlocal directives instead of
// treating same-spelled names across a file as one binding.
// v58: configured Go transformer bindings are keyed by callable ownership, so
// same-spelled locals in independent functions cannot suppress or inherit one
// another's facts. Cached v57 objects used file-wide textual write counts.
// v57: exact aggregate fields survive unrelated dynamic leaves; configured
// Go character transforms retain decoded substitution maps and lexical binding
// ownership; Go qualified composite receivers, Java constructor-local scope,
// nested receiver-call operands, and Python finite-map membership use their
// corrected adapter IR. Cached v55/v56 objects cannot represent or reliably
// reproduce all of those facts.
// v55: synthesized Swift computed-property declarations retain the same
// AST-derived receiver-state sources as ordinary callable lowering.
// v54: Ruby ERB/RHTML compiler objects retain Tree-sitter-proven instance
// variables as implicit inputs of the synthetic template module. Cached v53
// bodies cannot prove template-context values reaching a sink.
// v53: C++ direct initialization (`Type value(args)`) retains the
// Tree-sitter `init_declarator` as a constructor call. Cached v52 bodies omit
// that call boundary and cannot preserve constructor state/return flow;
// constructor field dependencies also use exact expression-operand facts.
// v52: C# expression-bodied property getters retain exact receiver-field
// return projections. Cached v51 bodies may expose only the scalar return and
// cannot satisfy a field-specific IDG target demand.
// v51: direct-call assignment lowering follows only the immediate operand of
// adapter-declared transparent CST wrappers. Cached v50 bodies may otherwise
// retain an unrelated nested helper call as the value-producing RHS.
// v50: PHP callable literals are classified by the PHP adapter, Go nested
// aggregate call arguments retain exact field dependencies, and file-derived
// semantic identities use canonical dotted compiler IR. Cached v49 bodies
// must not replay the former shared text interpretation or qualified names.
// v49: Java non-static field initializer targets use the adapter's canonical
// implicit-receiver place, matching later field receiver calls without a
// shared-language alias rule.
// v48: Ruby class/module and singleton-method ownership is lowered directly
// from the adapter's declared Tree-sitter grammar contexts. Cached declarations
// must not replay the earlier function taxonomy for class-owned methods.
// v47: PHP's adapter types sigiled implicit receivers from their enclosing
// class/base declarations so streamed bodies and persisted compiler objects
// resolve `$this` calls from the same syntax facts.
// v141: call-argument value facts classify only adapter-proven callable-value
// syntax as `CallableReference`; callgraph resolution no longer has to infer
// that role from a rendered qualified value.
// v142: Lua receiver-writing factories that return that receiver are exact
// constructor declarations, enabling persisted IDG receiver-state projection.
// v143: exact adapter-lowered assignment aliases inherit unambiguous local
// receiver types. Cached v142 bodies can omit those derived receiver facts and
// therefore lose alias-mediated method call and IDG boundaries.
// v144: qualified Perl packages separate their terminal declaration name from
// the owning module path while retaining the complete qualified identity.
// Cached v143 objects can fail exact typed dispatch across package files.
// v145: fact-backed parse recovery may replace one exact damaged descendant
// subtree while preserving every disjoint compiler node. TypeScript import
// type queries and qualified Java record patterns therefore lower cleanly;
// cached v144 objects can retain syntax diagnostics or omit those facts.
// v46: Perl conditional and postfix-conditional expression nodes lower to
// explicit branch IR instead of being flattened into unconditional events.
// v45: JavaScript `super(...)` retains constructor dispatch kind.
// v44: Java bare call receivers proven by lexical binding to be current-class
// instance fields are qualified to the adapter's current receiver place;
// shadowing locals and static fields remain unqualified.
// v43: Elixir map/struct results nested beneath control expressions merge
// exact field dependencies across result branches, including map-update
// syntax, without treating call target names as value sources.
// v42: Elixir `try` assignment results lower from the body and each
// rescue/catch/else clause's final expression; `after` remains side-effect
// only and cannot become the expression result.
// v41: Elixir `cond` assignment results lower from each clause body's final
// expression rather than surviving as an unresolved macro call result.
// v40: assignment/value lowering now carries exact adapter-owned generator,
// aggregate, receiver projection, constructor-delegation, and Elixir
// value-field facts introduced by the unified IDG compiler pipeline. Cached
// v39 bodies must not replay the former pseudo-call/phantom-assignment IR.
// v38: runtime type-guard operator/call spellings are adapter declarations;
// compiler objects no longer inherit a cross-language builtin/operator union.
// v37: provider-bound character/same-origin facts and compiler-guard evidence
// carry exact adapter syntax identity for rule-selected interpretation;
// typed branch conditions also preserve runtime-truth operands.
// v36: Go final-pass call arguments include adapter-added if-init/range/index
// calls plus adapter-decoded static values, and exact adapter guard facts
// include proven relative-path boundary helpers.
// v20: imported namespace/type qualifiers are classified in receiver facts,
// preventing call resolution syntax from becoming a runtime data receiver.
// v19: exact browse/search candidate terms became an independently decodable
// projection. Candidate-index construction no longer inflates declaration and
// flow bodies for every file.
// v151: Objective-C scalar lowering retains the language-defined `nil`/`Nil`
// null sentinels as exact static call arguments. Cached v150 objects cannot
// prove finite variadic Foundation collection construction.
// v150: finite literal-selection and exact write-transfer lowering changed
// across language adapters; invalidate every derived compiler object.
// v149: assignment value facts retain exact static callback-map field paths
// and callback declaration spans for rule-declared external dispatch.
// v148: Perl foreach lowering distinguishes split-pattern regex syntax from
// executable match operations, preserving exact loop binding evaluation
// order in the compiler IR and every derived callgraph/IDG sidecar.
// v17: compiler attribution is stored as independently compressed function
// frames behind a small span index. A function-scoped query never decodes the
// attribution for every sibling method in a large source file.
// v16: exact call/write attribution became an independently decodable per-file
// projection beside the full declaration/flow body.
// v15: standalone lambdas and named local callables retain their nearest
// Tree-sitter lexical callable parent; Perl package modules own their
// declarations and `Package::sub(...)` lowers as a static function call.
// v13: nested class-like declarations retain their exact lexical parent, so
// member qualified identities include every enclosing AST owner.
// v14: receiver-less constructor events inherit the enclosing declaration
// type only when the language adapter declares that exact constructor syntax.
// v12: independently decodable imports/syntax projections live in one
// per-file factstore entry instead of the generation metadata. Opening a
// 30k-file generation now retains only compact path/digest descriptors;
// candidate queries hydrate headers and bodies for selected FileIds lazily.
// v159: compact per-function call attribution retains adapter-decoded named
// argument labels. Sparse taint-lineage rendering can now recover the same
// actual-to-formal mapping as IDG stitching without reparsing source or
// misattributing projected argument fields to a static receiver.
// v172: Perl data-reference construction and nested scalar dereference
// dependencies are retained as exact adapter-lowered call-argument places.
// Cached v171 bodies can omit the complete argument vector for `\@array`.
// v173: Perl finite-literal selection facts retain exact value replacement
// through a non-mutating map/grep collection transform. Cached v172 bodies
// can incorrectly retain the dynamic selection key as a value dependency.
// v174: loop events retain adapter-lowered lexical labels and abrupt loop
// transfers retain a typed label/lexical-level target. Cached v173 bodies
// route every break/continue to the nearest loop.
// v179: compact function linkage retains adapter-lowered simple assignment
// aliases so cold reverse callback planning can discover exact consumers
// without hydrating unrelated workspace bodies.
// v180: declaration deduplication preserves variadic and owning-symbol facts;
// reference scopes and immutable assignment owners follow the retained symbol.
// TypeScript retains qualified type/base identities and class-owned readonly
// facts; constructor parameter transfers require syntax, not decorator text.
// v181: Python finite selections prove the complete RHS including defaults, reject
// dynamic/mutable map values, and preserve exact docstring/regex constraints.
// v182: PHP compound guards prove exact polarity, local ownership, finite
// values, and straight-line configuration order before emitting evidence.
// v183: C guard evidence requires exact checked values, comparison polarity,
// nonnegative lengths, and uninterrupted control-flow/configuration order.
// v184: C++ compound guards retain complete local control, exact parameter
// slots, immutable collection types, and typed operation/projection evidence.
// v185: C++ declaration ownership and privacy are exact-span facts; qualified
// local types keep distinct aggregate construction separate from copy flow.
// v186: Ruby guards retain their own branch polarity and lexical value proof;
// overridable method names are not unconditional throws. Lua retains exact
// nil comparisons and distinguishes dynamic subscripts from literal fields.
// v187: condition operands use the canonical compiler callee span, preserving
// exact predicate identity independently of full expression/wrapper spans.
// v188: parallel Go index assignments retain every RHS value; only the
// second result of a single comma-ok lookup is a non-value boolean.
// v189: callable type predicates retain canonical callee identity separately
// from grammar-owned runtime type operators.
// v190: Dart flattened selector predicates preserve exact Boolean structure.
// v191: exact Objective-C initializer signatures, parameter bindings, and dictionary values.
// v192: C# catch bindings, IDG constructor delegation, and unescaped local configuration.
// v193: Elixir module-owned finite guard values and exact callable scope/identity.
// v194: Kotlin qualified bases; Kotlin/Swift selections reject dynamic strings.
// v195: Java guarded-value fallback must return unconditionally in its own scope.
// v196: Java direct ancestry and lexical field identities; exact projection typing.
// v197: Perl compound guards require dominance, exact predicates, and stable state.
// v198: reject generations admitted through the retired v11 IR relabeling path.
// v199: JavaScript/TypeScript module identity strips one source extension only.
pub const COMPILER_OBJECT_CACHE_VERSION: u32 = 199;
#[cfg(test)]
const LEGACY_COMPILER_OBJECT_CACHE_VERSION: u32 = 11;

const COMPILER_OBJECT_TABLE_ID: u32 = 105;
const METADATA_KEY: u64 = 0;
const COMPILER_OBJECT_COMPRESSION_LEVEL: i32 = 1;
// Keep several units available per worker so compiler threads never wait for
// the dispatcher between ordinary files. This changes scheduling only and
// never the admitted file set or canonical logical metadata order.
const COMPILER_OBJECT_PREFETCH_PER_WORKER: usize = 4;
const ATTRIBUTION_PAYLOAD_MAGIC: [u8; 8] = *b"BNSATTR1";
const ATTRIBUTION_PAYLOAD_PREFIX_BYTES: usize = 8 + 4 + 32;
const DECLARATION_PAYLOAD_MAGIC: [u8; 8] = *b"BNSDECL1";
const DECLARATION_PAYLOAD_PREFIX_BYTES: usize = 8 + 4 + 32;

/// Exact typed compiler output for one source file.
///
/// This is the persistent equivalent of a relocatable compiler object: all
/// syntax interpretation remains in the language adapter, while workspace
/// symbol identities are assigned later by the linker/global index.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledFileObject {
    /// Stable file id within the immutable workspace generation.
    pub file: FileId,
    /// Workspace-relative path used by adapters for module identity.
    pub path: String,
    /// Language adapter selected for this exact snapshot.
    pub language: Option<String>,
    /// SHA-256 of the complete source bytes.
    pub source_digest: [u8; 32],
    /// Adapter-lowered declarations, references, flow events, and browse
    /// facts. `None` only when no registered adapter owns the file.
    pub declarations: Option<DeclIndex>,
    /// Adapter-lowered imports for the same syntax tree.
    pub imports: Option<ImportIndex>,
    /// Parser/adapter diagnostics emitted while lowering this exact file.
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceDescriptor {
    file: FileId,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    source_hash: u64,
    source_bytes: u64,
    version: u64,
}

struct PreparedCompilerObject {
    compressed: Vec<u8>,
    payload_digest: [u8; 32],
    payload_len: u32,
    header_compressed: Vec<u8>,
    header_payload_digest: [u8; 32],
    header_payload_len: u32,
    attribution_compressed: Vec<u8>,
    attribution_payload_digest: [u8; 32],
    attribution_payload_len: u32,
    browse_compressed: Vec<u8>,
    browse_payload_digest: [u8; 32],
    browse_payload_len: u32,
    declaration_compressed: Vec<u8>,
    declaration_payload_digest: [u8; 32],
    declaration_payload_len: u32,
    lines_compressed: Vec<u8>,
    lines_payload_digest: [u8; 32],
    lines_payload_len: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectHeader {
    imports: Option<ImportIndex>,
    imports_digest: [u8; 32],
    syntax: Option<CompilerSyntaxHeader>,
    syntax_digest: [u8; 32],
}

/// Independently decoded directory for the function frames in one compiler
/// attribution payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompilerAttributionIndex {
    pub file: FileId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frames: Vec<CompilerAttributionFrame>,
    /// Absolute offset of the frame blob relative to the fact-store payload.
    /// This is container metadata reconstructed from the fixed prefix and is
    /// intentionally not serialized inside the semantic index.
    #[serde(skip)]
    frames_payload_offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompilerAttributionFrame {
    declaration_span: Span,
    relative_offset: u64,
    compressed_len: u32,
    compressed_digest: [u8; 32],
}

impl CompilerAttributionIndex {
    fn frame_at_span(&self, span: Span) -> Option<&CompilerAttributionFrame> {
        let key = |value: Span| (value.file.raw(), value.start, value.end);
        let wanted = key(span);
        let index = self
            .frames
            .binary_search_by_key(&wanted, |frame| key(frame.declaration_span))
            .ok()?;
        self.frames.get(index)
    }
}

/// Directory of one file's declaration frames: every declaration of the
/// deduplicated declaration index, in index order, as an independently
/// addressable compressed frame. `local_symbol` lets one frame be remapped to
/// the header symbol table without decoding its siblings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompilerDeclarationIndex {
    pub file: FileId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    frames: Vec<CompilerDeclarationFrame>,
    #[serde(skip)]
    frames_payload_offset: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct CompilerDeclarationFrame {
    declaration_span: Span,
    local_symbol: SymbolId,
    relative_offset: u64,
    compressed_len: u32,
    compressed_digest: [u8; 32],
}

impl CompilerDeclarationIndex {
    /// Local symbols of every framed declaration, in index order.
    pub(crate) fn local_symbols(&self) -> Vec<SymbolId> {
        self.frames.iter().map(|frame| frame.local_symbol).collect()
    }
}

#[derive(Debug)]
struct CachedCompilerDeclarationIndex {
    index: Arc<CompilerDeclarationIndex>,
    estimated_bytes: u64,
}

#[derive(Debug)]
struct CompilerDeclarationIndexCache {
    entries: lru::LruCache<FileId, CachedCompilerDeclarationIndex>,
    estimated_bytes: u64,
}

impl Default for CompilerDeclarationIndexCache {
    fn default() -> Self {
        Self {
            entries: lru::LruCache::unbounded(),
            estimated_bytes: 0,
        }
    }
}

fn estimated_compiler_declaration_index_bytes(index: &CompilerDeclarationIndex) -> u64 {
    u64::try_from(std::mem::size_of::<CompilerDeclarationIndex>())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(index.frames.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(
                    u64::try_from(std::mem::size_of::<CompilerDeclarationFrame>()).unwrap_or(u64::MAX),
                ),
        )
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectMetadata {
    version: u32,
    semantic_fingerprint: u64,
    generation_digest: [u8; 32],
    files: Vec<CompilerObjectFileMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CompilerObjectFileMetadata {
    file: u32,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    source_hash: u64,
    payload_digest: [u8; 32],
    payload_len: u32,
    /// Digest/length of the independently decodable imports/syntax projection.
    /// The projection itself is keyed by FileId in the factstore so opening a
    /// generation is O(number of compact descriptors), not O(all header AST
    /// facts).
    header_payload_digest: [u8; 32],
    header_payload_len: u32,
    /// Digest/length of exact adapter-lowered call/write attribution. This
    /// payload is separate from both the broad syntax header and full body so
    /// a path query decodes only the facts it consumes.
    attribution_payload_digest: [u8; 32],
    attribution_payload_len: u32,
    /// Digest/length of exact file-local browse candidate terms. Kept apart
    /// from syntax targets and bodies so either consumer decodes only its own
    /// compiler projection.
    browse_payload_digest: [u8; 32],
    browse_payload_len: u32,
    declaration_payload_digest: [u8; 32],
    declaration_payload_len: u32,
    lines_payload_digest: [u8; 32],
    lines_payload_len: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ParallelVisitOrder {
    Completion,
    Input,
}

/// Run a bounded continuous worklist and visit results in the requested
/// physical order.
///
/// Physical payload order is not semantic: FactStore sorts its key index and
/// validates each payload independently. Visiting completion order therefore
/// removes head-of-line stalls while callers retain canonical logical metadata
/// by the supplied item index. The bounded queues and caller-owned memory
/// permits keep encoded payloads independent of workspace size.
fn try_visit_parallel<T, R>(
    items: &[T],
    worker_count: usize,
    max_in_flight: usize,
    visit_order: ParallelVisitOrder,
    work: impl Fn(usize, &T) -> std::io::Result<R> + Sync,
    mut visit: impl FnMut(usize, R) -> std::io::Result<()>,
) -> std::io::Result<()>
where
    T: Sync,
    R: Send,
{
    if items.is_empty() {
        return Ok(());
    }
    let worker_count = worker_count.max(1).min(items.len());
    let max_in_flight = max_in_flight.max(worker_count).min(items.len());
    let (work_tx, work_rx) = std::sync::mpsc::sync_channel::<usize>(max_in_flight);
    let (result_tx, result_rx) = std::sync::mpsc::sync_channel::<(usize, std::io::Result<R>)>(worker_count);
    let work_rx = std::sync::Mutex::new(work_rx);
    let cancelled = AtomicBool::new(false);

    // Seed the complete bounded window before workers start. This makes the
    // first canonical item immediately available without a dispatcher thread.
    let mut next_to_schedule = 0usize;
    while next_to_schedule < max_in_flight {
        work_tx
            .send(next_to_schedule)
            .map_err(|_| std::io::Error::other("compiler work queue disconnected"))?;
        next_to_schedule += 1;
    }

    std::thread::scope(|scope| {
        for worker in 0..worker_count {
            let result_tx = result_tx.clone();
            let work_rx = &work_rx;
            let work = &work;
            let cancelled = &cancelled;
            std::thread::Builder::new()
                .name(format!("bonsai-compiler-object-{worker}"))
                .stack_size(bonsai_common::compiler_worker_stack_bytes())
                .spawn_scoped(scope, move || loop {
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    let index = {
                        let receiver = work_rx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        match receiver.recv() {
                            Ok(index) => index,
                            Err(_) => break,
                        }
                    };
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    let result =
                        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(index, &items[index])))
                            .unwrap_or_else(|_| {
                                Err(std::io::Error::other(format!(
                                    "compiler worker panicked for item {index}"
                                )))
                            });
                    if result_tx.send((index, result)).is_err() {
                        break;
                    }
                })
                .unwrap_or_else(|error| panic!("failed to spawn compiler-object worker {worker}: {error}"));
        }
        drop(result_tx);

        let outcome = (|| {
            let mut completed = vec![false; items.len()];
            let mut published_count = 0usize;
            let mut next_to_publish = 0usize;
            let mut reorder = std::collections::BTreeMap::new();
            while published_count < items.len() {
                let (index, result) = result_rx
                    .recv()
                    .map_err(|_| std::io::Error::other("compiler result queue disconnected"))?;
                if index >= items.len() || std::mem::replace(&mut completed[index], true) {
                    return Err(invalid_data("duplicate or stale compiler work result"));
                }
                match visit_order {
                    ParallelVisitOrder::Completion => {
                        visit(index, result?)?;
                        published_count += 1;
                        if next_to_schedule < items.len() {
                            work_tx
                                .send(next_to_schedule)
                                .map_err(|_| std::io::Error::other("compiler work queue disconnected"))?;
                            next_to_schedule += 1;
                        }
                    }
                    ParallelVisitOrder::Input => {
                        if reorder.insert(index, result?).is_some() {
                            return Err(invalid_data("duplicate compiler reorder result"));
                        }
                        while let Some(result) = reorder.remove(&next_to_publish) {
                            visit(next_to_publish, result)?;
                            next_to_publish += 1;
                            published_count += 1;
                            if next_to_schedule < items.len() {
                                work_tx
                                    .send(next_to_schedule)
                                    .map_err(|_| std::io::Error::other("compiler work queue disconnected"))?;
                                next_to_schedule += 1;
                            }
                        }
                    }
                }
            }
            Ok(())
        })();
        if outcome.is_err() {
            cancelled.store(true, Ordering::Release);
        }
        drop(work_tx);
        drop(result_rx);
        outcome
    })
}

fn append_prepared_compiler_object(
    prepared: &mut PreparedFactStorePayload,
    prepared_entries: &mut Vec<PreparedFactStoreEntry>,
    descriptor: &SourceDescriptor,
    encoded: PreparedCompilerObject,
) -> std::io::Result<CompilerObjectFileMetadata> {
    let (payload_offset, persisted_len) = prepared.append(&encoded.compressed).map_err(factstore_io)?;
    debug_assert_eq!(encoded.payload_len, persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: object_key(descriptor.file),
        body_hash: object_body_hash(descriptor),
        payload_offset,
        payload_len: encoded.payload_len,
    });
    let (header_payload_offset, header_persisted_len) = prepared
        .append(&encoded.header_compressed)
        .map_err(factstore_io)?;
    debug_assert_eq!(encoded.header_payload_len, header_persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: header_key(descriptor.file),
        body_hash: header_body_hash(descriptor),
        payload_offset: header_payload_offset,
        payload_len: encoded.header_payload_len,
    });
    let (attribution_payload_offset, attribution_persisted_len) = prepared
        .append(&encoded.attribution_compressed)
        .map_err(factstore_io)?;
    debug_assert_eq!(encoded.attribution_payload_len, attribution_persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: attribution_key(descriptor.file),
        body_hash: attribution_body_hash(descriptor),
        payload_offset: attribution_payload_offset,
        payload_len: encoded.attribution_payload_len,
    });
    let (browse_payload_offset, browse_persisted_len) = prepared
        .append(&encoded.browse_compressed)
        .map_err(factstore_io)?;
    debug_assert_eq!(encoded.browse_payload_len, browse_persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: browse_key(descriptor.file),
        body_hash: browse_body_hash(descriptor),
        payload_offset: browse_payload_offset,
        payload_len: encoded.browse_payload_len,
    });
    let (declaration_payload_offset, declaration_persisted_len) = prepared
        .append(&encoded.declaration_compressed)
        .map_err(factstore_io)?;
    debug_assert_eq!(encoded.declaration_payload_len, declaration_persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: declaration_key(descriptor.file),
        body_hash: declaration_body_hash(descriptor),
        payload_offset: declaration_payload_offset,
        payload_len: encoded.declaration_payload_len,
    });
    let (lines_payload_offset, lines_persisted_len) =
        prepared.append(&encoded.lines_compressed).map_err(factstore_io)?;
    debug_assert_eq!(encoded.lines_payload_len, lines_persisted_len);
    prepared_entries.push(PreparedFactStoreEntry {
        key: lines_key(descriptor.file),
        body_hash: lines_body_hash(descriptor),
        payload_offset: lines_payload_offset,
        payload_len: encoded.lines_payload_len,
    });
    Ok(CompilerObjectFileMetadata {
        file: descriptor.file.raw(),
        path: descriptor.path.clone(),
        language: descriptor.language.clone(),
        source_digest: descriptor.source_digest,
        source_hash: descriptor.source_hash,
        payload_digest: encoded.payload_digest,
        payload_len: encoded.payload_len,
        header_payload_digest: encoded.header_payload_digest,
        header_payload_len: encoded.header_payload_len,
        attribution_payload_digest: encoded.attribution_payload_digest,
        attribution_payload_len: encoded.attribution_payload_len,
        browse_payload_digest: encoded.browse_payload_digest,
        browse_payload_len: encoded.browse_payload_len,
        declaration_payload_digest: encoded.declaration_payload_digest,
        declaration_payload_len: encoded.declaration_payload_len,
        lines_payload_digest: encoded.lines_payload_digest,
        lines_payload_len: encoded.lines_payload_len,
    })
}

/// v11 stored every per-file import/syntax projection inside one monolithic
/// metadata record. Keep this wire fixture only to prove it cannot bypass
/// current frontend compilation, even when all source fingerprints match.
#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyCompilerObjectMetadataV11 {
    version: u32,
    semantic_fingerprint: u64,
    generation_digest: [u8; 32],
    files: Vec<LegacyCompilerObjectFileMetadataV11>,
}

#[cfg(test)]
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyCompilerObjectFileMetadataV11 {
    file: u32,
    path: String,
    language: Option<String>,
    source_digest: [u8; 32],
    source_hash: u64,
    payload_digest: [u8; 32],
    payload_len: u32,
    imports: Option<ImportIndex>,
    imports_digest: [u8; 32],
    syntax: Option<CompilerSyntaxHeader>,
    syntax_digest: [u8; 32],
}

/// Read-only compiler-object generation. A generation may be globally stale
/// after one edit while still supplying exact content-addressed objects for
/// every unchanged file.
pub(crate) struct CompilerObjectStore {
    reader: FactStoreReader,
    metadata: CompilerObjectMetadata,
    attribution_indexes: parking_lot::Mutex<CompilerAttributionIndexCache>,
    attribution_index_budget_bytes: u64,
    declaration_indexes: parking_lot::Mutex<CompilerDeclarationIndexCache>,
    /// Keeps a scoped compiler session's directory alive until the last
    /// reader is dropped. Persistent workspace sidecars leave this empty.
    _temporary_root: Option<Arc<tempfile::TempDir>>,
}

#[derive(Debug)]
struct CachedCompilerAttributionIndex {
    index: Arc<CompilerAttributionIndex>,
    estimated_bytes: u64,
}

#[derive(Debug)]
struct CompilerAttributionIndexCache {
    entries: lru::LruCache<FileId, CachedCompilerAttributionIndex>,
    estimated_bytes: u64,
}

impl Default for CompilerAttributionIndexCache {
    fn default() -> Self {
        Self {
            entries: lru::LruCache::unbounded(),
            estimated_bytes: 0,
        }
    }
}

fn compiler_attribution_index_cache_budget_bytes() -> u64 {
    const DEFAULT_BYTES: u64 = 16 * 1024 * 1024;
    const MIN_BYTES: u64 = 1024 * 1024;
    const MAX_BYTES: u64 = 64 * 1024 * 1024;
    bonsai_common::effective_memory_limit_bytes()
        .map(|limit| (limit / 256).clamp(MIN_BYTES, MAX_BYTES))
        .unwrap_or(DEFAULT_BYTES)
}

fn estimated_compiler_attribution_index_bytes(index: &CompilerAttributionIndex) -> u64 {
    u64::try_from(std::mem::size_of::<CompilerAttributionIndex>())
        .unwrap_or(u64::MAX)
        .saturating_add(
            u64::try_from(index.frames.capacity())
                .unwrap_or(u64::MAX)
                .saturating_mul(
                    u64::try_from(std::mem::size_of::<CompilerAttributionFrame>()).unwrap_or(u64::MAX),
                ),
        )
}

impl CompilerObjectStore {
    pub(crate) fn open_reusable(workspace_root: &Path) -> std::io::Result<Self> {
        let path = compiler_object_sidecar_path(workspace_root);
        Self::open_at(&path, None)
    }

    fn open_at(path: &Path, temporary_root: Option<Arc<tempfile::TempDir>>) -> std::io::Result<Self> {
        let reader = FactStoreReader::open_relaxed(path).map_err(factstore_io)?;
        if reader.header().table_id != COMPILER_OBJECT_TABLE_ID {
            return Err(invalid_data("compiler-object factstore table mismatch"));
        }
        let hit = reader
            .get(METADATA_KEY)
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object metadata is missing"))?;
        if hit.body_hash != u64::from(COMPILER_OBJECT_CACHE_VERSION) {
            return Err(invalid_data("compiler-object metadata version mismatch"));
        }
        let metadata: CompilerObjectMetadata = wire::decode(&hit.payload).map_err(invalid_wire)?;
        if metadata.version != COMPILER_OBJECT_CACHE_VERSION
            || metadata.semantic_fingerprint != compiler_frontend_semantic_fingerprint()
        {
            return Err(invalid_data("compiler-object semantic ABI mismatch"));
        }
        if reader.header().pipeline_hash != metadata_pipeline_hash(&metadata) {
            return Err(invalid_data("compiler-object pipeline fingerprint mismatch"));
        }
        Ok(Self {
            reader,
            metadata,
            attribution_indexes: parking_lot::Mutex::new(CompilerAttributionIndexCache::default()),
            attribution_index_budget_bytes: compiler_attribution_index_cache_budget_bytes(),
            declaration_indexes: parking_lot::Mutex::new(CompilerDeclarationIndexCache::default()),
            _temporary_root: temporary_root,
        })
    }

    fn covers(&self, descriptors: &[SourceDescriptor]) -> bool {
        descriptors
            .iter()
            .all(|descriptor| self.metadata_for(descriptor).is_some())
    }

    fn metadata_for(&self, descriptor: &SourceDescriptor) -> Option<&CompilerObjectFileMetadata> {
        let metadata = self
            .metadata
            .files
            .binary_search_by_key(&descriptor.file.raw(), |file| file.file)
            .ok()
            .map(|index| &self.metadata.files[index])?;
        (metadata.path == descriptor.path
            && metadata.language == descriptor.language
            && metadata.source_digest == descriptor.source_digest
            && metadata.source_hash == descriptor.source_hash)
            .then_some(metadata)
    }

    fn load(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompiledFileObject>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_object_payload(descriptor, metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let object: CompiledFileObject = wire::decode(&decoded).map_err(invalid_wire)?;
        validate_object(&object, descriptor)?;
        Ok(Some(object))
    }

    fn compressed_payload(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<PreparedCompilerObject>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_object_payload(descriptor, metadata)?;
        Ok(Some(PreparedCompilerObject {
            compressed,
            payload_digest: metadata.payload_digest,
            payload_len: metadata.payload_len,
            header_compressed: self.compressed_header_payload(metadata)?,
            header_payload_digest: metadata.header_payload_digest,
            header_payload_len: metadata.header_payload_len,
            attribution_compressed: self.compressed_attribution_payload(metadata)?,
            attribution_payload_digest: metadata.attribution_payload_digest,
            attribution_payload_len: metadata.attribution_payload_len,
            browse_compressed: self.compressed_browse_payload(metadata)?,
            browse_payload_digest: metadata.browse_payload_digest,
            browse_payload_len: metadata.browse_payload_len,
            declaration_compressed: self.compressed_declaration_payload(metadata)?,
            declaration_payload_digest: metadata.declaration_payload_digest,
            declaration_payload_len: metadata.declaration_payload_len,
            lines_compressed: self.compressed_lines_payload(metadata)?,
            lines_payload_digest: metadata.lines_payload_digest,
            lines_payload_len: metadata.lines_payload_len,
        }))
    }

    fn compressed_object_payload(
        &self,
        descriptor: &SourceDescriptor,
        metadata: &CompilerObjectFileMetadata,
    ) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(object_key(descriptor.file))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object payload is missing"))?;
        if hit.body_hash != object_body_hash(descriptor) {
            return Err(invalid_data("compiler-object body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.payload_len)
        {
            return Err(invalid_data("compiler-object payload digest mismatch"));
        }
        Ok(hit.payload)
    }

    fn compressed_header_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(header_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object header payload is missing"))?;
        if hit.body_hash != header_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object header body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.header_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.header_payload_len)
        {
            return Err(invalid_data("compiler-object header payload digest mismatch"));
        }
        Ok(hit.payload)
    }

    fn compressed_attribution_payload(
        &self,
        metadata: &CompilerObjectFileMetadata,
    ) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(attribution_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object attribution payload is missing"))?;
        if hit.body_hash != attribution_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object attribution body fingerprint mismatch",
            ));
        }
        if digest_bytes(&hit.payload) != metadata.attribution_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.attribution_payload_len)
        {
            return Err(invalid_data(
                "compiler-object attribution payload digest mismatch",
            ));
        }
        Ok(hit.payload)
    }

    fn compressed_browse_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(browse_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object browse payload is missing"))?;
        if hit.body_hash != browse_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object browse body fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.browse_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.browse_payload_len)
        {
            return Err(invalid_data("compiler-object browse payload digest mismatch"));
        }
        Ok(hit.payload)
    }

    fn compressed_lines_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(lines_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object line table is missing"))?;
        if hit.body_hash != lines_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data("compiler-object line table fingerprint mismatch"));
        }
        if digest_bytes(&hit.payload) != metadata.lines_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.lines_payload_len)
        {
            return Err(invalid_data("compiler-object line table digest mismatch"));
        }
        Ok(hit.payload)
    }

    /// Line-start table recorded for the exact source; `None` when the
    /// generation predates line tables (migrated objects) or the entry is
    /// absent, in which case callers derive it from the text.
    fn load_line_starts(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<Vec<u32>>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_lines_payload(metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let line_starts: Vec<u32> = wire::decode(&decoded).map_err(invalid_wire)?;
        Ok((!line_starts.is_empty()).then_some(line_starts))
    }

    fn compressed_declaration_payload(
        &self,
        metadata: &CompilerObjectFileMetadata,
    ) -> std::io::Result<Vec<u8>> {
        let hit = self
            .reader
            .get(declaration_key(FileId::new(metadata.file)))
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object declaration payload is missing"))?;
        if hit.body_hash != declaration_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object declaration body fingerprint mismatch",
            ));
        }
        if digest_bytes(&hit.payload) != metadata.declaration_payload_digest
            || u32::try_from(hit.payload.len()).ok() != Some(metadata.declaration_payload_len)
        {
            return Err(invalid_data(
                "compiler-object declaration payload digest mismatch",
            ));
        }
        Ok(hit.payload)
    }

    fn declaration_payload_range(
        &self,
        metadata: &CompilerObjectFileMetadata,
        relative_offset: u64,
        length: u64,
    ) -> std::io::Result<Vec<u8>> {
        let mut reader = self
            .reader
            .payload_range_reader(
                declaration_key(FileId::new(metadata.file)),
                relative_offset,
                length,
            )
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object declaration payload is missing"))?;
        if reader.body_hash != declaration_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object declaration body fingerprint mismatch",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(length) {
            return Err(invalid_data("compiler-object declaration range is truncated"));
        }
        Ok(bytes)
    }

    /// The declaration frame directory of one file (cached per file).
    fn load_declaration_index(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<Arc<CompilerDeclarationIndex>>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if let Some(index) = self
            .declaration_indexes
            .lock()
            .entries
            .get(&descriptor.file)
            .map(|entry| Arc::clone(&entry.index))
        {
            return Ok(Some(index));
        }
        if metadata.declaration_payload_len < DECLARATION_PAYLOAD_PREFIX_BYTES as u32 {
            return Err(invalid_data("compiler-object declaration payload is truncated"));
        }
        let prefix = self.declaration_payload_range(metadata, 0, DECLARATION_PAYLOAD_PREFIX_BYTES as u64)?;
        if prefix[..8] != DECLARATION_PAYLOAD_MAGIC {
            return Err(invalid_data("compiler-object declaration payload magic mismatch"));
        }
        let index_len = u32::from_le_bytes(prefix[8..12].try_into().expect("fixed declaration index length"));
        let frames_payload_offset = u64::try_from(DECLARATION_PAYLOAD_PREFIX_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(index_len));
        if frames_payload_offset > u64::from(metadata.declaration_payload_len) {
            return Err(invalid_data("compiler-object declaration index exceeds payload"));
        }
        let index_bytes = self.declaration_payload_range(
            metadata,
            DECLARATION_PAYLOAD_PREFIX_BYTES as u64,
            u64::from(index_len),
        )?;
        if digest_bytes(&index_bytes) != prefix[12..44] {
            return Err(invalid_data("compiler-object declaration index digest mismatch"));
        }
        let mut index: CompilerDeclarationIndex = wire::decode(&index_bytes).map_err(invalid_wire)?;
        index.frames_payload_offset = frames_payload_offset;
        validate_compiler_declaration_index(&index, metadata)?;
        let index = Arc::new(index);
        let estimated_bytes = estimated_compiler_declaration_index_bytes(&index);
        if self.attribution_index_budget_bytes != 0 && estimated_bytes <= self.attribution_index_budget_bytes
        {
            let mut cache = self.declaration_indexes.lock();
            if let Some(existing) = cache.entries.get(&descriptor.file) {
                return Ok(Some(Arc::clone(&existing.index)));
            }
            cache.estimated_bytes = cache.estimated_bytes.saturating_add(estimated_bytes);
            if let Some((_file, replaced)) = cache.entries.push(
                descriptor.file,
                CachedCompilerDeclarationIndex {
                    index: Arc::clone(&index),
                    estimated_bytes,
                },
            ) {
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(replaced.estimated_bytes);
            }
            while cache.estimated_bytes > self.attribution_index_budget_bytes {
                let Some((_file, evicted)) = cache.entries.pop_lru() else {
                    break;
                };
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(evicted.estimated_bytes);
            }
        }
        Ok(Some(index))
    }

    /// One declaration of a file, by its position in the deduplicated
    /// declaration index, decoded from its own frame.
    fn load_declaration_frame(
        &self,
        descriptor: &SourceDescriptor,
        index: &CompilerDeclarationIndex,
        position: usize,
    ) -> std::io::Result<Option<Decl>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if index.file != descriptor.file {
            return Err(invalid_data(
                "compiler-object declaration index identity mismatch",
            ));
        }
        let Some(frame) = index.frames.get(position) else {
            return Ok(None);
        };
        let relative_offset = index
            .frames_payload_offset
            .checked_add(frame.relative_offset)
            .ok_or_else(|| invalid_data("compiler-object declaration frame offset overflow"))?;
        let compressed =
            self.declaration_payload_range(metadata, relative_offset, u64::from(frame.compressed_len))?;
        if digest_bytes(&compressed) != frame.compressed_digest {
            return Err(invalid_data("compiler-object declaration frame digest mismatch"));
        }
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let decl: Decl = wire::decode(&decoded).map_err(invalid_wire)?;
        if decl.span != frame.declaration_span || decl.symbol != frame.local_symbol {
            return Err(invalid_data(
                "compiler-object declaration frame identity mismatch",
            ));
        }
        Ok(Some(decl))
    }

    fn load_header(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerObjectHeader>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_header_payload(metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let header: CompilerObjectHeader = wire::decode(&decoded).map_err(invalid_wire)?;
        // `compressed_header_payload` has already bound this exact payload to
        // the source/front-end body hash and verified its stored length and
        // SHA-256 digest. The typed MessagePack decode above is the remaining
        // structural check. Re-encoding both decoded projections merely to
        // reproduce their construction-time digests doubled broad-header
        // work (and allocations) without adding an independent integrity
        // boundary: both digests lived inside the already-verified payload.
        Ok(Some(header))
    }

    fn load_imports(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<ImportIndex>> {
        Ok(self.load_header(descriptor)?.and_then(|header| header.imports))
    }

    fn load_syntax(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerSyntaxHeader>> {
        Ok(self.load_header(descriptor)?.and_then(|header| header.syntax))
    }

    fn load_browse(&self, descriptor: &SourceDescriptor) -> std::io::Result<Option<CompilerBrowseHeader>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        let compressed = self.compressed_browse_payload(metadata)?;
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let browse: CompilerBrowseHeader = wire::decode(&decoded).map_err(invalid_wire)?;
        Ok(Some(browse))
    }

    fn attribution_payload_range(
        &self,
        metadata: &CompilerObjectFileMetadata,
        relative_offset: u64,
        length: u64,
    ) -> std::io::Result<Vec<u8>> {
        let mut reader = self
            .reader
            .payload_range_reader(
                attribution_key(FileId::new(metadata.file)),
                relative_offset,
                length,
            )
            .map_err(factstore_io)?
            .ok_or_else(|| invalid_data("compiler-object attribution payload is missing"))?;
        if reader.body_hash != attribution_body_hash_from_digest(metadata.source_digest) {
            return Err(invalid_data(
                "compiler-object attribution body fingerprint mismatch",
            ));
        }
        let mut bytes = Vec::with_capacity(usize::try_from(length).unwrap_or(0));
        reader.read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).ok() != Some(length) {
            return Err(invalid_data("compiler-object attribution range is truncated"));
        }
        Ok(bytes)
    }

    fn load_attribution_index(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<Arc<CompilerAttributionIndex>>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if let Some(index) = self
            .attribution_indexes
            .lock()
            .entries
            .get(&descriptor.file)
            .map(|entry| Arc::clone(&entry.index))
        {
            return Ok(Some(index));
        }
        if metadata.attribution_payload_len < ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u32 {
            return Err(invalid_data("compiler-object attribution payload is truncated"));
        }
        let prefix = self.attribution_payload_range(metadata, 0, ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u64)?;
        if prefix[..8] != ATTRIBUTION_PAYLOAD_MAGIC {
            return Err(invalid_data("compiler-object attribution payload magic mismatch"));
        }
        let index_len = u32::from_le_bytes(prefix[8..12].try_into().expect("fixed attribution index length"));
        let frames_payload_offset = u64::try_from(ATTRIBUTION_PAYLOAD_PREFIX_BYTES)
            .unwrap_or(u64::MAX)
            .saturating_add(u64::from(index_len));
        if frames_payload_offset > u64::from(metadata.attribution_payload_len) {
            return Err(invalid_data("compiler-object attribution index exceeds payload"));
        }
        let index_bytes = self.attribution_payload_range(
            metadata,
            ATTRIBUTION_PAYLOAD_PREFIX_BYTES as u64,
            u64::from(index_len),
        )?;
        if digest_bytes(&index_bytes) != prefix[12..44] {
            return Err(invalid_data("compiler-object attribution index digest mismatch"));
        }
        let mut index: CompilerAttributionIndex = wire::decode(&index_bytes).map_err(invalid_wire)?;
        index.frames_payload_offset = frames_payload_offset;
        validate_compiler_attribution_index(&index, metadata)?;
        let index = Arc::new(index);
        let estimated_bytes = estimated_compiler_attribution_index_bytes(&index);
        if self.attribution_index_budget_bytes != 0 && estimated_bytes <= self.attribution_index_budget_bytes
        {
            let mut cache = self.attribution_indexes.lock();
            if let Some(existing) = cache.entries.get(&descriptor.file) {
                return Ok(Some(Arc::clone(&existing.index)));
            }
            cache.estimated_bytes = cache.estimated_bytes.saturating_add(estimated_bytes);
            if let Some((_file, replaced)) = cache.entries.push(
                descriptor.file,
                CachedCompilerAttributionIndex {
                    index: Arc::clone(&index),
                    estimated_bytes,
                },
            ) {
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(replaced.estimated_bytes);
            }
            while cache.estimated_bytes > self.attribution_index_budget_bytes {
                let Some((_file, evicted)) = cache.entries.pop_lru() else {
                    break;
                };
                cache.estimated_bytes = cache.estimated_bytes.saturating_sub(evicted.estimated_bytes);
            }
        }
        Ok(Some(index))
    }

    fn load_function_attribution(
        &self,
        descriptor: &SourceDescriptor,
        index: &CompilerAttributionIndex,
        declaration_span: Span,
    ) -> std::io::Result<Option<CompilerFunctionAttribution>> {
        let Some(metadata) = self.metadata_for(descriptor) else {
            return Ok(None);
        };
        if index.file != descriptor.file {
            return Err(invalid_data(
                "compiler-object attribution index identity mismatch",
            ));
        }
        let Some(frame) = index.frame_at_span(declaration_span) else {
            return Ok(None);
        };
        let relative_offset = index
            .frames_payload_offset
            .checked_add(frame.relative_offset)
            .ok_or_else(|| invalid_data("compiler-object attribution frame offset overflow"))?;
        let compressed =
            self.attribution_payload_range(metadata, relative_offset, u64::from(frame.compressed_len))?;
        if digest_bytes(&compressed) != frame.compressed_digest {
            return Err(invalid_data("compiler-object attribution frame digest mismatch"));
        }
        let decoded = zstd::stream::decode_all(Cursor::new(compressed))?;
        let attribution: CompilerFunctionAttribution = wire::decode(&decoded).map_err(invalid_wire)?;
        if attribution.declaration_span != declaration_span {
            return Err(invalid_data(
                "compiler-object attribution frame identity mismatch",
            ));
        }
        Ok(Some(attribution))
    }

    fn load_attribution(
        &self,
        descriptor: &SourceDescriptor,
    ) -> std::io::Result<Option<CompilerAttribution>> {
        let Some(index) = self.load_attribution_index(descriptor)? else {
            return Ok(None);
        };
        let mut functions = Vec::with_capacity(index.frames.len());
        for frame in &index.frames {
            functions.push(
                self.load_function_attribution(descriptor, &index, frame.declaration_span)?
                    .ok_or_else(|| invalid_data("compiler-object attribution frame is missing"))?,
            );
        }
        Ok(Some(CompilerAttribution {
            file: descriptor.file,
            functions,
        }))
    }

    fn validate_payload(&self, metadata: &CompilerObjectFileMetadata) -> std::io::Result<()> {
        validate_streamed_payload(
            &self.reader,
            object_key(FileId::new(metadata.file)),
            object_body_hash_from_digest(metadata.source_digest),
            metadata.payload_len,
            metadata.payload_digest,
            "compiler-object",
        )?;
        validate_streamed_payload(
            &self.reader,
            header_key(FileId::new(metadata.file)),
            header_body_hash_from_digest(metadata.source_digest),
            metadata.header_payload_len,
            metadata.header_payload_digest,
            "compiler-object header",
        )?;
        validate_streamed_payload(
            &self.reader,
            attribution_key(FileId::new(metadata.file)),
            attribution_body_hash_from_digest(metadata.source_digest),
            metadata.attribution_payload_len,
            metadata.attribution_payload_digest,
            "compiler-object attribution",
        )?;
        validate_streamed_payload(
            &self.reader,
            browse_key(FileId::new(metadata.file)),
            browse_body_hash_from_digest(metadata.source_digest),
            metadata.browse_payload_len,
            metadata.browse_payload_digest,
            "compiler-object browse projection",
        )?;
        validate_streamed_payload(
            &self.reader,
            declaration_key(FileId::new(metadata.file)),
            declaration_body_hash_from_digest(metadata.source_digest),
            metadata.declaration_payload_len,
            metadata.declaration_payload_digest,
            "compiler-object declaration frames",
        )?;
        validate_streamed_payload(
            &self.reader,
            lines_key(FileId::new(metadata.file)),
            lines_body_hash_from_digest(metadata.source_digest),
            metadata.lines_payload_len,
            metadata.lines_payload_digest,
            "compiler-object line table",
        )?;
        Ok(())
    }
}

impl AnalyzerDb {
    /// Attach the immutable compiler-object generation for one file-local
    /// query only when its path and current full-workspace identity agree.
    ///
    /// The generation metadata is integrity-checked here. The selected
    /// object's path, language, content hash, and SHA-256 digest are checked
    /// again when its payload is consumed. The caller derives `selected_file`
    /// from the current source set; stale metadata must never choose the
    /// identity of a source whose ordinal changed after an addition/removal.
    pub fn load_compiler_object_store_for_selected_file(
        &self,
        workspace_root: &Path,
        selected_file: FileId,
        selected_path: &Path,
    ) -> std::io::Result<bool> {
        if !self.inner.load_compiler_object_sidecar {
            return Ok(false);
        }
        let store = CompilerObjectStore::open_reusable(workspace_root)?;
        if store.reader.len() != compiler_object_entry_count(store.metadata.files.len()) {
            return Err(invalid_data("compiler-object entry count mismatch"));
        }
        let canonical_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        let relative = selected_path
            .strip_prefix(&canonical_root)
            .or_else(|_| selected_path.strip_prefix(workspace_root))
            .unwrap_or(selected_path)
            .to_string_lossy()
            .replace('\\', "/");
        let matches = store
            .metadata
            .files
            .iter()
            .any(|metadata| metadata.path == relative && metadata.file == selected_file.raw());
        if matches {
            *self.inner.compiler_object_store.write() = Some(Arc::new(store));
            self.inner
                .compiler_object_store_requires_repair
                .store(false, std::sync::atomic::Ordering::Release);
        }
        Ok(matches)
    }

    /// Attach a complete immutable compiler-object generation to a scoped
    /// query after the caller has validated the full source fingerprint set.
    ///
    /// Scoped workspaces normally compile their selected files directly
    /// because renumbered local [`FileId`] values cannot address a
    /// whole-workspace generation safely. Exact-worklist queries preserve the
    /// original ids and pass every workspace source hash here, allowing lazy
    /// per-file object reuse without loading unrelated payloads.
    pub fn load_compiler_object_store_for_source_fingerprints<I, P>(
        &self,
        workspace_root: &Path,
        fingerprints: I,
    ) -> std::io::Result<usize>
    where
        I: IntoIterator<Item = (P, u64)>,
        P: AsRef<Path>,
    {
        if !self.inner.load_compiler_object_sidecar {
            return Ok(0);
        }
        let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
        let files = store.metadata.files.len();
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        self.inner
            .compiler_object_store_requires_repair
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(files)
    }

    /// Load one exact compiler object from the current content-addressed
    /// generation, or compile it from Tree-sitter when no valid object exists.
    /// The result is not retained in the database: broad phases stream one
    /// object at a time so resident memory follows active work, not project
    /// size.
    #[must_use]
    pub fn compiler_file_object_uncached(&self, file: FileId) -> Option<CompiledFileObject> {
        let descriptor = source_descriptor(self, file)?;
        let mut loaded = None;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load(&descriptor) {
                Ok(Some(object)) => loaded = Some(object),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler object miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        let object = loaded.unwrap_or_else(|| self.compile_fresh_file_object(descriptor));
        self.publish_compiler_diagnostics(&object);
        Some(object)
    }

    /// Load only a persisted declaration body when the selected source has an
    /// exact content-addressed object. `None` is a normal cache miss; callers
    /// then invoke the adapter directly without compiling unrelated import
    /// projections merely to satisfy a file-local view.
    pub(crate) fn compiler_decl_index_from_store(&self, file: FileId) -> Option<DeclIndex> {
        let descriptor = source_descriptor(self, file)?;
        let store = self.inner.compiler_object_store.read().as_ref().cloned()?;
        match store.load(&descriptor) {
            Ok(Some(object)) => {
                self.publish_compiler_diagnostics(&object);
                object.declarations
            }
            Ok(None) => None,
            Err(error) => {
                self.inner
                    .compiler_object_store_requires_repair
                    .store(true, std::sync::atomic::Ordering::Release);
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler declaration body miss for {}: {}",
                    descriptor.path,
                    error
                );
                None
            }
        }
    }

    /// Return whether this exact source snapshot has already completed the
    /// canonical compiler-object diagnostic pass in the current process.
    ///
    /// The marker includes successful files with zero diagnostics. Broad
    /// completion audits use it to avoid recompiling syntax headers that an
    /// earlier command phase already lowered. File invalidation removes the
    /// marker together with that file's published diagnostics.
    #[must_use]
    pub fn compiler_diagnostics_are_current(&self, file: FileId) -> bool {
        let Some(descriptor) = source_descriptor(self, file) else {
            return false;
        };
        self.inner
            .compiler_diagnostics_published
            .read()
            .contains(&(file, descriptor.source_digest))
    }

    /// Parse one exact source snapshot and retain only its syntax diagnostics.
    ///
    /// This deliberately does not build a declaration index, import index, or
    /// flow body. Broad analyses use it for their final completeness audit so
    /// files rejected by exact rule planning still receive Tree-sitter parser
    /// coverage without materializing unrelated semantic IR.
    #[must_use]
    pub fn parser_diagnostics_uncached(&self, file: FileId) -> Option<Arc<[Diagnostic]>> {
        let key = (file, self.inner.vfs.file_version(file).ok()?);
        if let Some(diagnostics) = self.inner.parser_diagnostics.read().get(&key).cloned() {
            return Some(diagnostics);
        }

        let diagnostics = if self.adapter_for(file).is_none() {
            Vec::new()
        } else {
            match self.parse(file) {
                Ok(parsed) => parsed.diagnostics.clone(),
                Err(error) => vec![Diagnostic::new(
                    Span::new(file, 0, self.inner.vfs.text_len(file).unwrap_or(u64::MAX)),
                    Severity::Error,
                    format!("source parsing failed: {error}"),
                )
                .with_code("parse-failed")],
            }
        };
        self.release_syntax(file);
        let diagnostics: Arc<[Diagnostic]> = diagnostics.into();
        let mut cached = self.inner.parser_diagnostics.write();
        Some(
            cached
                .entry(key)
                .or_insert_with(|| Arc::clone(&diagnostics))
                .clone(),
        )
    }

    /// Visit parser diagnostics for a deterministic file sequence through a
    /// bounded source-weighted worklist. Parsing is exact and exhaustive;
    /// scheduling changes storage pressure only, never the audited file set.
    pub fn visit_parser_diagnostics_uncached(
        &self,
        files: &[FileId],
        mut visit: impl FnMut(FileId, Option<Arc<[Diagnostic]>>),
    ) {
        let source_bytes = files
            .iter()
            .map(|file| self.inner.vfs.text_len(*file).unwrap_or(0))
            .collect::<Vec<_>>();
        let workers =
            bonsai_common::syntax_worker_count_for_sources(&source_bytes, compiler_object_cpu_workers());
        let max_in_flight = workers
            .saturating_mul(COMPILER_OBJECT_PREFETCH_PER_WORKER)
            .max(1)
            .min(files.len().max(1));
        let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
        let next_memory_admission = std::sync::Mutex::new(0usize);
        let memory_admission_ready = std::sync::Condvar::new();
        try_visit_parallel(
            files,
            workers,
            max_in_flight,
            ParallelVisitOrder::Input,
            |index, file| {
                let source_bytes = self.inner.vfs.text_len(*file).unwrap_or(0);
                // Ordered output retains completed units until every earlier
                // result has been published. Admit their memory in the same
                // canonical order so later files can never consume the whole
                // pool while the head file is still waiting to start.
                let mut next = next_memory_admission
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while *next != index {
                    next = memory_admission_ready
                        .wait(next)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let permit = memory_permits.acquire(source_bytes);
                *next += 1;
                memory_admission_ready.notify_all();
                drop(next);
                Ok((*file, self.parser_diagnostics_uncached(*file), permit))
            },
            |_, (file, diagnostics, _permit)| {
                visit(file, diagnostics);
                Ok(())
            },
        )
        .expect("bounded parser-diagnostic worklist failed");
    }

    /// Load the independently decodable import header for one exact source
    /// snapshot. A valid compiler-object generation answers without
    /// decompressing declaration bodies or flow events; a cache miss falls
    /// back to the canonical Tree-sitter compiler object.
    #[must_use]
    pub fn compiler_import_index_uncached(&self, file: FileId) -> Option<ImportIndex> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_imports(&descriptor) {
                Ok(Some(imports)) => return Some(imports),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler import header miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        // Import-only callers do not require declarations or flow bodies.
        // On a sidecar miss, run the owning adapter's exact import pass over
        // the canonical Tree-sitter tree instead of compiling a complete
        // object. This preserves the language frontend contract and keeps
        // package-gated planning lightweight on a cold workspace.
        self.build_import_index_with_diagnostics(file, &self.inner.diagnostics)
    }

    /// Span → line/column map for `file`. A loaded text builds it directly;
    /// a lazily interned source uses the line table its compiler object
    /// recorded, so rendering locations never forces a read.
    #[must_use]
    pub fn span_map(&self, file: FileId) -> Option<Arc<bonsai_common::SpanMap>> {
        let version = self.inner.vfs.file_version(file).ok()?;
        if self.inner.vfs.lazy_identity(file).is_some() {
            if let Some(map) = bonsai_common::cached_span_map_from_line_starts(
                self.inner.vfs.instance_id(),
                file,
                version,
                || self.compiler_line_starts_uncached(file),
            ) {
                return Some(map);
            }
        }
        let snapshot = self.inner.vfs.snapshot(file).ok()?;
        Some(bonsai_common::cached_span_map_arc(
            file,
            snapshot.version,
            &snapshot.text,
        ))
    }

    /// Line-start table of `file` from the persisted compiler object, when
    /// the current generation recorded one for this exact source.
    #[must_use]
    pub fn compiler_line_starts_uncached(&self, file: FileId) -> Option<Vec<u32>> {
        let descriptor = source_descriptor(self, file)?;
        let store = self.inner.compiler_object_store.read().as_ref().cloned()?;
        match store.load_line_starts(&descriptor) {
            Ok(lines) => lines,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler line table miss for {}: {}",
                    descriptor.path,
                    error
                );
                None
            }
        }
    }

    /// Load the independently decodable syntax-target header for one exact
    /// source snapshot. The header is an adapter-IR projection and therefore
    /// cannot introduce matches: it only avoids inflating a body when every
    /// requested target is structurally impossible.
    #[must_use]
    pub fn compiler_syntax_header_uncached(&self, file: FileId) -> Option<CompilerSyntaxHeader> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_syntax(&descriptor) {
                Ok(Some(syntax)) => return Some(syntax),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler syntax header miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        self.compiler_file_object_uncached(file)?
            .declarations
            .as_ref()
            .map(CompilerSyntaxHeader::from_decl_index)
    }

    /// Load exact normalized browse candidates without decompressing the
    /// declaration/flow body or unrelated syntax-target header.
    ///
    /// A missing or damaged persisted projection falls back to the canonical
    /// Tree-sitter object and derives the identical terms. This changes only
    /// storage and scheduling; it cannot admit a candidate that the owning
    /// adapter did not lower.
    #[must_use]
    pub fn compiler_browse_header_uncached(&self, file: FileId) -> Option<CompilerBrowseHeader> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_browse(&descriptor) {
                Ok(Some(browse)) => return Some(browse),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler browse projection miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        let object = self.compiler_file_object_uncached(file)?;
        Some(CompilerBrowseHeader::from_indexes(
            object.declarations.as_ref(),
            object.imports.as_ref(),
        ))
    }

    /// Load exact adapter-lowered call/write attribution for one source file
    /// without decompressing its declaration and flow body.
    ///
    /// The content-addressed payload is a projection of the same compiler IR,
    /// not a heuristic index. A missing or invalid sidecar falls back to one
    /// canonical Tree-sitter lowering and derives the identical projection.
    #[must_use]
    pub fn compiler_attribution_uncached(&self, file: FileId) -> Option<CompilerAttribution> {
        let descriptor = source_descriptor(self, file)?;
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_attribution(&descriptor) {
                Ok(Some(attribution)) => return Some(attribution),
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler attribution miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        self.compiler_file_object_uncached(file)?
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)
    }

    /// One declaration of `file` by its position in the deduplicated
    /// declaration index, decoded from its persisted frame together with the
    /// file's local symbols in index order (for remapping to header ids).
    /// `None` when no persisted generation covers the file: callers then
    /// fall back to the whole-file declaration index.
    pub fn compiler_declaration_frame_uncached(
        &self,
        file: FileId,
        position: usize,
    ) -> Option<(Decl, Vec<SymbolId>)> {
        let descriptor = source_descriptor(self, file)?;
        let store = self.inner.compiler_object_store.read().as_ref().cloned()?;
        let index = match store.load_declaration_index(&descriptor) {
            Ok(Some(index)) => index,
            Ok(None) => return None,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler declaration index miss for {}: {}",
                    descriptor.path,
                    error
                );
                return None;
            }
        };
        match store.load_declaration_frame(&descriptor, &index, position) {
            Ok(Some(decl)) => Some((decl, index.local_symbols())),
            Ok(None) => None,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler declaration frame miss for {}: {}",
                    descriptor.path,
                    error
                );
                None
            }
        }
    }

    /// Load one exact function's adapter attribution frame.
    ///
    /// The persisted path reads a small span directory and one independently
    /// compressed function frame. It never decodes sibling functions or the
    /// full compiler body. Cache damage falls back to the canonical
    /// Tree-sitter object and therefore affects speed only.
    #[must_use]
    pub fn compiler_function_attribution_uncached(
        &self,
        file: FileId,
        declaration_span: Span,
    ) -> Option<CompilerFunctionAttribution> {
        self.compiler_function_attributions_uncached(file, &[declaration_span])
            .pop()
            .flatten()
    }

    /// Load an exact set of function attribution frames from one source file.
    ///
    /// The per-file directory is validated once and shared by every requested
    /// span. Only those frames are read and decompressed; unrequested sibling
    /// functions remain on disk. Results preserve input order, including a
    /// `None` for a span not owned by the file. Any damaged persisted frame
    /// falls back to one canonical Tree-sitter lowering for the complete
    /// batch, so storage failure changes performance rather than semantics.
    #[must_use]
    pub fn compiler_function_attributions_uncached(
        &self,
        file: FileId,
        declaration_spans: &[Span],
    ) -> Vec<Option<CompilerFunctionAttribution>> {
        if declaration_spans.is_empty() {
            return Vec::new();
        }
        let Some(descriptor) = source_descriptor(self, file) else {
            return vec![None; declaration_spans.len()];
        };
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            match store.load_attribution_index(&descriptor) {
                Ok(Some(index)) => {
                    let mut attributions = Vec::with_capacity(declaration_spans.len());
                    let mut failure = None;
                    for &declaration_span in declaration_spans {
                        match store.load_function_attribution(&descriptor, &index, declaration_span) {
                            Ok(attribution) => attributions.push(attribution),
                            Err(error) => {
                                failure = Some(error);
                                break;
                            }
                        }
                    }
                    if let Some(error) = failure {
                        self.inner
                            .compiler_object_store_requires_repair
                            .store(true, std::sync::atomic::Ordering::Release);
                        bonsai_diagnostics::debug_log!(
                            "compiler-object",
                            "compiler function attribution miss for {}: {}",
                            descriptor.path,
                            error
                        );
                    } else {
                        return attributions;
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    self.inner
                        .compiler_object_store_requires_repair
                        .store(true, std::sync::atomic::Ordering::Release);
                    bonsai_diagnostics::debug_log!(
                        "compiler-object",
                        "compiler function attribution miss for {}: {}",
                        descriptor.path,
                        error
                    );
                }
            }
        }
        let attribution = self.compiler_file_object_uncached(file).and_then(|object| {
            object
                .declarations
                .as_ref()
                .map(CompilerAttribution::from_decl_index)
        });
        declaration_spans
            .iter()
            .map(|&span| {
                attribution
                    .as_ref()
                    .and_then(|projection| projection.function_at_span(span))
                    .cloned()
            })
            .collect()
    }

    /// Visit exact compiler objects for a deterministic file sequence using
    /// a bounded source-weighted worklist.
    ///
    /// `visit` is called in `files` order exactly once per requested file.
    /// Completed results retain their source-size permit until a bounded
    /// reorder window publishes them in input order. Memory availability
    /// changes only how many independent Tree-sitter units are in flight; it
    /// never changes the file set or compiler facts.
    pub fn visit_compiler_file_objects_uncached(
        &self,
        files: &[FileId],
        mut visit: impl FnMut(FileId, Option<CompiledFileObject>),
    ) {
        let source_bytes = files
            .iter()
            .map(|file| self.inner.vfs.text_len(*file).unwrap_or(0))
            .collect::<Vec<_>>();
        let workers =
            bonsai_common::syntax_worker_count_for_sources(&source_bytes, compiler_object_cpu_workers());
        let max_in_flight = workers
            .saturating_mul(COMPILER_OBJECT_PREFETCH_PER_WORKER)
            .max(1)
            .min(files.len().max(1));
        let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
        let next_memory_admission = std::sync::Mutex::new(0usize);
        let memory_admission_ready = std::sync::Condvar::new();
        try_visit_parallel(
            files,
            workers,
            max_in_flight,
            ParallelVisitOrder::Input,
            |index, file| {
                let source_bytes = self.inner.vfs.text_len(*file).unwrap_or(0);
                // A later completed object retains its permit in the reorder
                // map. Canonical admission guarantees that such objects cannot
                // starve the earlier object whose publication releases them.
                let mut next = next_memory_admission
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while *next != index {
                    next = memory_admission_ready
                        .wait(next)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let permit = memory_permits.acquire(source_bytes);
                *next += 1;
                memory_admission_ready.notify_all();
                drop(next);
                Ok((*file, self.compiler_file_object_uncached(*file), permit))
            },
            |_, (file, object, _permit)| {
                visit(file, object);
                Ok(())
            },
        )
        .expect("bounded compiler-object worklist failed");
    }

    /// Attach the existing immutable compiler-object generation when it
    /// exactly covers a scoped compiler worklist.
    ///
    /// This is a read-only planning operation: it never creates a scoped
    /// generation and never lowers a declaration/flow body. Every selected
    /// file is bound by stable [`FileId`], workspace-relative path, adapter,
    /// fast content hash, and SHA-256 source digest before the store becomes
    /// visible. A retrieval-scoped workspace with renumbered or stale inputs
    /// therefore fails closed and continues through its canonical
    /// Tree-sitter fallback.
    pub fn attach_reusable_compiler_object_store_for_files(&self, files: &[FileId]) -> std::io::Result<bool> {
        if !self.inner.load_compiler_object_sidecar {
            return Ok(false);
        }
        if files.is_empty() {
            return Ok(true);
        }
        use rayon::prelude::*;
        let mut descriptors = files
            .par_iter()
            .filter_map(|file| source_descriptor(self, *file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        if descriptors.len() != files.iter().copied().collect::<AHashSet<_>>().len() {
            return Ok(false);
        }
        if self
            .inner
            .compiler_object_store
            .read()
            .as_ref()
            .is_some_and(|store| store.covers(&descriptors))
        {
            return Ok(true);
        }
        let Some(root) = self.workspace_root() else {
            return Ok(false);
        };
        let store = CompilerObjectStore::open_reusable(&root)?;
        if store.reader.len() != compiler_object_entry_count(store.metadata.files.len())
            || !store.covers(&descriptors)
        {
            return Ok(false);
        }
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        self.inner
            .compiler_object_store_requires_repair
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(true)
    }

    /// Persist a complete immutable compiler-object generation. Existing
    /// objects are validated and reused entry-by-entry without decoding;
    /// stale, corrupt, or missing entries are recompiled from the registered
    /// language adapter.
    pub fn save_compiler_object_sidecar(&self, workspace_root: &Path) -> std::io::Result<usize> {
        self.save_compiler_object_sidecar_inner(workspace_root, None)
    }

    /// Persist the complete compiler-object generation and report one tick
    /// after each exact source unit has been prepared for publication.
    ///
    /// The callback observes completed units only; it cannot alter scheduling,
    /// admitted files, payload order, or compiler error handling.
    pub fn save_compiler_object_sidecar_with_progress<F>(
        &self,
        workspace_root: &Path,
        on_file: F,
    ) -> std::io::Result<usize>
    where
        F: Fn() + Sync,
    {
        self.save_compiler_object_sidecar_inner(workspace_root, Some(&on_file))
    }

    fn save_compiler_object_sidecar_inner(
        &self,
        workspace_root: &Path,
        on_file: Option<&(dyn Fn() + Sync)>,
    ) -> std::io::Result<usize> {
        let _generation_guard = self.inner.compiler_object_generation_build.lock();
        let path = compiler_object_sidecar_path(workspace_root);
        let _sidecar_guard = CompilerObjectSidecarWriteGuard::acquire(&path)?;
        let descriptors = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        self.write_compiler_object_generation(&path, descriptors, None, on_file)
    }

    /// Ensure that exact compiler objects for `files` are reusable for the
    /// lifetime of this database without publishing a partial generation
    /// under the analyzed workspace.
    ///
    /// The first caller lowers missing Tree-sitter units into a scoped
    /// disk-backed factstore. Later compiler phases stream validated objects
    /// from that immutable session, so declarations never accumulate in RAM
    /// and the same source is not reparsed for package, matcher, and taint
    /// phases. Existing persistent or scoped objects are copied as compressed
    /// payloads; only genuinely missing or changed files are lowered.
    pub fn ensure_compiler_object_session(&self, files: &[FileId]) -> std::io::Result<usize> {
        self.ensure_compiler_object_session_inner(files, None)
    }

    /// Ensure an exact compiler-object session while reporting completed
    /// source units. The callback observes scheduling only and cannot change
    /// the admitted files, compiler facts, or canonical metadata order.
    pub fn ensure_compiler_object_session_with_progress<F>(
        &self,
        files: &[FileId],
        on_file: F,
    ) -> std::io::Result<usize>
    where
        F: Fn() + Sync,
    {
        self.ensure_compiler_object_session_inner(files, Some(&on_file))
    }

    fn ensure_compiler_object_session_inner(
        &self,
        files: &[FileId],
        on_file: Option<&(dyn Fn() + Sync)>,
    ) -> std::io::Result<usize> {
        if files.is_empty() {
            return Ok(0);
        }
        let _generation_guard = self.inner.compiler_object_generation_build.lock();
        let mut descriptors = files
            .iter()
            .copied()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        if self
            .inner
            .compiler_object_store
            .read()
            .as_ref()
            .is_some_and(|store| store.covers(&descriptors))
        {
            return Ok(0);
        }

        // Scoped query workspaces intentionally do not open the complete
        // compiler-object metadata during their lightweight syntax phase.
        // Once a semantic consumer requests exact bodies, try that immutable
        // generation before compiling a temporary session. `covers` binds
        // every selected stable FileId to its adapter, path, and strong source
        // digest, so a dense/local scoped id or changed file cannot become a
        // false cache hit. This keeps path-filtered security scans on the
        // already-published Tree-sitter IR without making syntax-only commands
        // pay to hydrate unrelated compiler metadata.
        if self.inner.load_compiler_object_sidecar {
            if let Some(root) = self.workspace_root() {
                if let Ok(store) = CompilerObjectStore::open_reusable(&root) {
                    if store.covers(&descriptors) {
                        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
                        self.inner
                            .compiler_object_store_requires_repair
                            .store(false, std::sync::atomic::Ordering::Release);
                        return Ok(0);
                    }
                }
            }
        }

        // Preserve every still-exact object from a previous scoped session.
        // This makes successive rule-language batches monotonic without
        // widening the first pass to files that no active rule can consume.
        if let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() {
            for metadata in &store.metadata.files {
                let Some(descriptor) = source_descriptor(self, FileId::new(metadata.file)) else {
                    continue;
                };
                if store.metadata_for(&descriptor).is_some() {
                    descriptors.push(descriptor);
                }
            }
            descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
            descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        }

        let temporary_root = Arc::new(
            tempfile::Builder::new()
                .prefix("bonsai-compiler-session-")
                .tempdir()?,
        );
        let path = temporary_root.path().join("compiler-objects.factstore");
        self.write_compiler_object_generation(&path, descriptors, Some(temporary_root), on_file)
    }

    fn write_compiler_object_generation(
        &self,
        path: &Path,
        mut descriptors: Vec<SourceDescriptor>,
        temporary_root: Option<Arc<tempfile::TempDir>>,
        on_file: Option<&(dyn Fn() + Sync)>,
    ) -> std::io::Result<usize> {
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        descriptors.dedup_by_key(|descriptor| descriptor.file.raw());
        let generation_digest = generation_digest(&descriptors);
        let mut prepared = PreparedFactStorePayload::create_near(path).map_err(factstore_io)?;
        let mut prepared_entries = Vec::with_capacity(descriptors.len().saturating_mul(4));
        let mut files = (0..descriptors.len()).map(|_| None).collect::<Vec<_>>();
        let cpu_workers = compiler_object_cpu_workers();
        let source_bytes = descriptors
            .iter()
            .map(|descriptor| descriptor.source_bytes)
            .collect::<Vec<_>>();
        let parallel_width = bonsai_common::syntax_worker_count_for_sources(&source_bytes, cpu_workers);
        let max_in_flight = parallel_width
            .saturating_mul(COMPILER_OBJECT_PREFETCH_PER_WORKER)
            .max(1)
            .min(descriptors.len().max(1));
        let memory_permits = bonsai_common::SyntaxMemoryPermitPool::for_current_process();
        bonsai_diagnostics::debug_log!(
            "compiler-object",
            "continuous generation files={} workers={} max_in_flight={}",
            descriptors.len(),
            parallel_width,
            max_in_flight
        );
        try_visit_parallel(
            &descriptors,
            parallel_width,
            max_in_flight,
            ParallelVisitOrder::Completion,
            |_, descriptor| {
                let permit = memory_permits.acquire(descriptor.source_bytes);
                prepare_compiler_object(self, descriptor).map(|encoded| (encoded, permit))
            },
            |index, (encoded, _permit)| {
                let metadata = append_prepared_compiler_object(
                    &mut prepared,
                    &mut prepared_entries,
                    &descriptors[index],
                    encoded,
                )?;
                if files[index].replace(metadata).is_some() {
                    return Err(invalid_data("duplicate compiler-object metadata"));
                }
                if let Some(on_file) = on_file {
                    on_file();
                }
                Ok(())
            },
        )?;
        let files = files
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| invalid_data("missing compiler-object metadata"))?;
        let metadata = CompilerObjectMetadata {
            version: COMPILER_OBJECT_CACHE_VERSION,
            semantic_fingerprint: compiler_frontend_semantic_fingerprint(),
            generation_digest,
            files,
        };
        let writer = FactStoreWriter::create_from_prepared(
            path,
            COMPILER_OBJECT_TABLE_ID,
            metadata_pipeline_hash(&metadata),
            prepared,
            prepared_entries,
        )
        .map_err(factstore_io)?;
        writer
            .add_owned(
                METADATA_KEY,
                u64::from(COMPILER_OBJECT_CACHE_VERSION),
                wire::encode_struct_map(&metadata).map_err(invalid_wire)?,
            )
            .map_err(factstore_io)?;
        let _entries = writer.finish().map_err(factstore_io)?;
        let file_count = metadata.files.len();
        let store = CompilerObjectStore::open_at(path, temporary_root)?;
        *self.inner.compiler_object_store.write() = Some(Arc::new(store));
        self.inner
            .compiler_object_store_requires_repair
            .store(false, std::sync::atomic::Ordering::Release);
        Ok(file_count)
    }

    /// Cheap exact-generation check used before a complete compiler phase.
    ///
    /// This compares the immutable generation header with the current VFS
    /// snapshot but deliberately does not hash every compressed payload.
    /// Individual object reads still verify their payload digest; a corrupt
    /// hit marks the store for repair and the orchestrator republishes it
    /// after the exact fallback compile completes.
    #[must_use]
    pub fn compiler_object_generation_matches_current_snapshot(&self) -> bool {
        if self
            .inner
            .compiler_object_store_requires_repair
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }
        let Some(store) = self.inner.compiler_object_store.read().as_ref().cloned() else {
            return false;
        };
        let mut descriptors = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        store.metadata.generation_digest == generation_digest(&descriptors)
            && store.metadata.files.len() == descriptors.len()
            && store.reader.len() == compiler_object_entry_count(descriptors.len())
            && store.covers(&descriptors)
    }

    /// Validate that the complete compiler-object generation matches the
    /// current immutable VFS snapshot without decoding every object payload.
    #[must_use]
    pub fn compiler_object_sidecar_is_current(&self, workspace_root: &Path) -> bool {
        let Ok(store) = CompilerObjectStore::open_reusable(workspace_root) else {
            return false;
        };
        let mut descriptors = self
            .inner
            .vfs
            .all_files()
            .into_iter()
            .filter_map(|file| source_descriptor(self, file))
            .collect::<Vec<_>>();
        descriptors.sort_unstable_by_key(|descriptor| descriptor.file.raw());
        if store.metadata.generation_digest != generation_digest(&descriptors)
            || store.metadata.files.len() != descriptors.len()
            || store.reader.len() != compiler_object_entry_count(descriptors.len())
        {
            return false;
        }
        descriptors
            .iter()
            .zip(&store.metadata.files)
            .all(|(descriptor, metadata)| {
                metadata.file == descriptor.file.raw()
                    && metadata.path == descriptor.path
                    && metadata.language == descriptor.language
                    && metadata.source_digest == descriptor.source_digest
                    && metadata.source_hash == descriptor.source_hash
                    && store.validate_payload(metadata).is_ok()
            })
    }

    fn compile_fresh_file_object(&self, descriptor: SourceDescriptor) -> CompiledFileObject {
        if descriptor.language.is_none() {
            return CompiledFileObject {
                file: descriptor.file,
                path: descriptor.path,
                language: None,
                source_digest: descriptor.source_digest,
                declarations: None,
                imports: None,
                diagnostics: Vec::new(),
            };
        }
        let mut parser_diagnostics = match self.parse(descriptor.file) {
            Ok(parsed) => parsed.diagnostics.clone(),
            Err(error) => vec![Diagnostic::new(
                Span::new(descriptor.file, 0, descriptor.source_bytes),
                Severity::Error,
                format!("source parsing failed: {error}"),
            )
            .with_code("parse-failed")],
        };
        let diagnostics = parking_lot::RwLock::new(DiagnosticSink::new());
        let mut declarations = self.build_decl_index_with_diagnostics(descriptor.file, &diagnostics);
        let imports = self.build_import_index_with_diagnostics(descriptor.file, &diagnostics);
        if let (Some(declarations), Some(imports)) = (&mut declarations, &imports) {
            bonsai_lang_api::mark_namespace_call_receivers(declarations, imports);
        }
        self.release_syntax(descriptor.file);
        parser_diagnostics.extend(diagnostics.read().snapshot());
        CompiledFileObject {
            file: descriptor.file,
            path: descriptor.path,
            language: descriptor.language,
            source_digest: descriptor.source_digest,
            declarations,
            imports,
            diagnostics: parser_diagnostics,
        }
    }

    fn publish_compiler_diagnostics(&self, object: &CompiledFileObject) {
        let key = (object.file, object.source_digest);
        let _gate = self.inner.compiler_diagnostics_gate.lock();
        if !self.inner.compiler_diagnostics_published.write().insert(key) {
            return;
        }
        if !object.diagnostics.is_empty() {
            self.inner
                .diagnostics
                .write()
                .extend(object.diagnostics.iter().cloned());
        }
    }
}

/// Conventional compiler-object generation path in the external workspace cache.
#[must_use]
pub fn compiler_object_sidecar_path(workspace_root: &Path) -> PathBuf {
    workspace_bonsai_dir(workspace_root).join(format!(
        "compiler-objects.v{COMPILER_OBJECT_CACHE_VERSION}.factstore"
    ))
}

/// Cross-process ownership and bounded retention for compiler-object
/// generations.
///
/// Schema versions use distinct immutable targets. The current target lock
/// serializes publication, while each older target is removed only after a
/// non-blocking lock proves that no peer compiler owns it.
struct CompilerObjectSidecarWriteGuard {
    lock_file: File,
    target: PathBuf,
}

impl CompilerObjectSidecarWriteGuard {
    fn acquire(target: &Path) -> std::io::Result<Self> {
        let lock_file = open_compiler_object_lock_file(target)?;
        lock_file.lock_exclusive()?;
        cleanup_compiler_object_temp_files(target)?;
        prune_obsolete_compiler_object_sidecars(target)?;
        Ok(Self {
            lock_file,
            target: target.to_path_buf(),
        })
    }
}

impl Drop for CompilerObjectSidecarWriteGuard {
    fn drop(&mut self) {
        if let Err(error) = FileExt::unlock(&self.lock_file) {
            bonsai_diagnostics::debug_log!(
                "compiler-object",
                "compiler-object sidecar writer lock release failed: path={} error={error}",
                self.target.display()
            );
        }
    }
}

fn open_compiler_object_lock_file(target: &Path) -> std::io::Result<File> {
    let mut lock_path = target.as_os_str().to_os_string();
    lock_path.push(".lock");
    let lock_path = PathBuf::from(lock_path);
    if let Some(parent) = lock_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)
}

fn compiler_object_sidecar_version(name: &str) -> Option<u32> {
    name.strip_prefix("compiler-objects.v")?
        .strip_suffix(".factstore")?
        .parse()
        .ok()
}

fn compiler_object_writer_suffix_is_valid(suffix: &str) -> bool {
    let mut parts = suffix.split('.');
    parts.next().is_some_and(|pid| pid.parse::<u32>().is_ok())
        && parts.next().is_some_and(|counter| counter.parse::<u64>().is_ok())
        && parts.next().is_none()
}

fn compiler_object_temp_target_name(name: &str) -> Option<(&str, u32)> {
    let (target, suffix) = name.rsplit_once(".tmp.")?;
    if !compiler_object_writer_suffix_is_valid(suffix) {
        return None;
    }
    Some((target, compiler_object_sidecar_version(target)?))
}

fn cleanup_compiler_object_temp_files(target: &Path) -> std::io::Result<usize> {
    let Some(parent) = target.parent() else {
        return Ok(0);
    };
    let Some(file_name) = target.file_name().and_then(|name| name.to_str()) else {
        return Ok(0);
    };
    let prefix = format!("{file_name}.tmp.");
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut removed = 0usize;
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(suffix) = name.to_str().and_then(|name| name.strip_prefix(&prefix)) else {
            continue;
        };
        if !compiler_object_writer_suffix_is_valid(suffix) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(removed)
}

fn prune_obsolete_compiler_object_sidecars(current_target: &Path) -> std::io::Result<usize> {
    let Some(parent) = current_target.parent() else {
        return Ok(0);
    };
    let Some(current_version) = current_target
        .file_name()
        .and_then(|name| name.to_str())
        .and_then(compiler_object_sidecar_version)
    else {
        return Ok(0);
    };
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    };
    let mut obsolete = Vec::new();
    let mut obsolete_temps = Vec::new();
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if compiler_object_sidecar_version(name).is_some_and(|version| version < current_version) {
            obsolete.push(entry.path());
        } else if let Some((target_name, version)) = compiler_object_temp_target_name(name) {
            if version < current_version {
                obsolete_temps.push((parent.join(target_name), entry.path()));
            }
        }
    }
    obsolete.sort();
    obsolete_temps.sort();
    let mut removed = 0usize;
    for (target, temp) in obsolete_temps {
        let lock_file = match try_acquire_compiler_object_lock(&target) {
            Ok(Some(lock_file)) => lock_file,
            Ok(None) => continue,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "skipping superseded compiler-object staging cleanup: path={} error={error}",
                    temp.display()
                );
                continue;
            }
        };
        match std::fs::remove_file(&temp) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => bonsai_diagnostics::debug_log!(
                "compiler-object",
                "superseded compiler-object staging cleanup failed: path={} error={error}",
                temp.display()
            ),
        }
        unlock_compiler_object_cleanup(&lock_file, &target);
    }
    for target in obsolete {
        let lock_file = match try_acquire_compiler_object_lock(&target) {
            Ok(Some(lock_file)) => lock_file,
            Ok(None) => continue,
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "skipping superseded compiler-object sidecar cleanup: path={} error={error}",
                    target.display()
                );
                continue;
            }
        };
        match std::fs::remove_file(&target) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => bonsai_diagnostics::debug_log!(
                "compiler-object",
                "superseded compiler-object sidecar cleanup failed: path={} error={error}",
                target.display()
            ),
        }
        unlock_compiler_object_cleanup(&lock_file, &target);
    }
    Ok(removed)
}

fn try_acquire_compiler_object_lock(target: &Path) -> std::io::Result<Option<File>> {
    let file = open_compiler_object_lock_file(target)?;
    match file
        .try_lock_exclusive()
        .map_err(bonsai_common::normalize_advisory_lock_error)
    {
        Ok(()) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(error),
    }
}

fn unlock_compiler_object_cleanup(lock_file: &File, target: &Path) {
    if let Err(error) = FileExt::unlock(lock_file) {
        bonsai_diagnostics::debug_log!(
            "compiler-object",
            "compiler-object cleanup lock release failed: path={} error={error}",
            target.display()
        );
    }
}

/// Compatibility hook for the retired v11 container migration.
///
/// Source identity alone cannot prove that old adapter lowering matches the
/// current frontend ABI. Always return `Ok(None)` so callers perform normal
/// compiler ingestion; never rewrite old IR with a current generation header.
pub fn migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints<I, P>(
    _workspace_root: &Path,
    _fingerprints: I,
) -> std::io::Result<Option<usize>>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    Ok(None)
}

/// Validate the compiler-object container and semantic ABI without opening a
/// workspace or decoding every file payload. Exact source identity is checked
/// separately by [`AnalyzerDb::compiler_object_sidecar_is_current`] whenever a
/// workspace is available.
pub fn validate_compiler_object_sidecar_layout(workspace_root: &Path) -> std::io::Result<usize> {
    let store = CompilerObjectStore::open_reusable(workspace_root)?;
    if store.reader.len() != compiler_object_entry_count(store.metadata.files.len()) {
        return Err(invalid_data("compiler-object entry count mismatch"));
    }
    let mut previous_file = None;
    for file in &store.metadata.files {
        if previous_file.is_some_and(|previous| previous >= file.file) {
            return Err(invalid_data("compiler-object metadata is not uniquely sorted"));
        }
        store.validate_payload(file)?;
        previous_file = Some(file.file);
    }
    Ok(store.metadata.files.len())
}

/// Exhaustively validate a compiler-object generation against the current
/// supported source set without opening a compiler workspace.
///
/// The supplied hashes are the same streaming content fingerprints used by
/// callgraph/linkage cache inspection. Object payloads remain bound to the
/// stronger SHA-256 digest recorded in each immutable object; this projection
/// lets cache orchestration prove that the generation covers exactly the
/// current paths before advertising it as reusable.
pub fn validate_compiler_object_sidecar_file_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    for file in &store.metadata.files {
        store.validate_payload(file)?;
    }
    Ok(store.metadata.files.len())
}

/// Validate compiler-object schema and exact source coverage without hashing
/// every compressed object payload.
///
/// This is the cache-planning contract. Every object payload is still bound
/// to SHA-256 metadata and verified on read; the exhaustive validator above
/// remains available for an explicit integrity audit.
pub fn validate_compiler_object_sidecar_metadata_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<usize>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    Ok(store.metadata.files.len())
}

/// Return the exact adapter languages recorded by a validated compiler-object
/// generation without decoding any per-file header or declaration body.
///
/// Root-only cache validation uses this compact compiler metadata to recreate
/// capability-dependent semantic fingerprints. It must not guess languages
/// from extensions: ambiguous compiler extensions are resolved from the
/// Tree-sitter parse when the object generation is built.
pub fn compiler_object_languages_with_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<Vec<String>>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = compiler_object_store_for_source_fingerprints(workspace_root, fingerprints)?;
    let mut languages = store
        .metadata
        .files
        .iter()
        .filter_map(|file| file.language.clone())
        .collect::<Vec<_>>();
    languages.sort();
    languages.dedup();
    Ok(languages)
}

fn compiler_object_store_for_source_fingerprints<I, P>(
    workspace_root: &Path,
    fingerprints: I,
) -> std::io::Result<CompilerObjectStore>
where
    I: IntoIterator<Item = (P, u64)>,
    P: AsRef<Path>,
{
    let store = CompilerObjectStore::open_reusable(workspace_root)?;
    if store.reader.len() != compiler_object_entry_count(store.metadata.files.len()) {
        return Err(invalid_data("compiler-object entry count mismatch"));
    }
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    let mut current = fingerprints
        .into_iter()
        .map(|(path, hash)| {
            let path = path.as_ref();
            let relative = path
                .strip_prefix(&canonical_root)
                .or_else(|_| path.strip_prefix(workspace_root))
                .unwrap_or(path);
            (relative.to_string_lossy().replace('\\', "/"), hash)
        })
        .collect::<Vec<_>>();
    current.sort();
    let mut recorded = store
        .metadata
        .files
        .iter()
        .map(|file| (file.path.clone(), file.source_hash))
        .collect::<Vec<_>>();
    recorded.sort();
    if current != recorded {
        let first_difference = current
            .iter()
            .zip(&recorded)
            .position(|(left, right)| left != right)
            .unwrap_or_else(|| current.len().min(recorded.len()));
        return Err(invalid_data(format!(
            "compiler-object sidecar source fingerprint mismatch: current_files={} recorded_files={} first_difference={first_difference}",
            current.len(),
            recorded.len()
        )));
    }
    Ok(store)
}

fn source_descriptor(db: &AnalyzerDb, file: FileId) -> Option<SourceDescriptor> {
    let path = db.inner.vfs.path(file).ok()?;
    let version = db.inner.vfs.file_version(file).ok()?;
    // A lazily interned source carries the identity of the exact text the
    // loader returns; the descriptor comes from it without reading the file.
    let (source_digest, source_hash, source_bytes) = match db.inner.vfs.lazy_identity(file) {
        Some(identity) => (identity.digest, identity.hash, identity.len),
        None => {
            let snapshot = db.inner.vfs.snapshot(file).ok()?;
            (
                digest_bytes(snapshot.text.as_bytes()),
                fnv1a_bytes64(snapshot.text.as_bytes()),
                u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX),
            )
        }
    };
    let root = db.workspace_root();
    let relative = root
        .as_deref()
        .and_then(|root| path.strip_prefix(root).ok())
        .unwrap_or(path.as_path());
    let path = relative.to_string_lossy().replace('\\', "/");
    let language = db
        .adapter_for(file)
        .map(|adapter| adapter.language_id().as_str().to_string());
    Some(SourceDescriptor {
        file,
        path,
        language,
        source_digest,
        source_hash,
        source_bytes,
        version,
    })
}

fn prepare_compiler_object(
    db: &AnalyzerDb,
    descriptor: &SourceDescriptor,
) -> std::io::Result<PreparedCompilerObject> {
    ensure_source_version(db, descriptor)?;
    if let Some(store) = db.inner.compiler_object_store.read().as_ref().cloned() {
        match store.compressed_payload(descriptor) {
            Ok(Some(prepared)) => {
                ensure_source_version(db, descriptor)?;
                return Ok(prepared);
            }
            Ok(None) => {}
            Err(error) => {
                bonsai_diagnostics::debug_log!(
                    "compiler-object",
                    "compiler object rebuild for {}: {}",
                    descriptor.path,
                    error
                );
            }
        }
    }
    let object = db.compile_fresh_file_object(descriptor.clone());
    ensure_source_version(db, descriptor)?;
    validate_object(&object, descriptor)?;
    let imports = object.imports.clone();
    let imports_digest = import_index_digest(imports.as_ref());
    let syntax = object
        .declarations
        .as_ref()
        .map(CompilerSyntaxHeader::from_decl_index);
    let attribution = object
        .declarations
        .as_ref()
        .map(CompilerAttribution::from_decl_index)
        .unwrap_or_else(|| CompilerAttribution {
            file: descriptor.file,
            functions: Vec::new(),
        });
    let browse = CompilerBrowseHeader::from_indexes(object.declarations.as_ref(), object.imports.as_ref());
    let syntax_digest = compiler_syntax_header_digest(syntax.as_ref());
    let header = CompilerObjectHeader {
        imports,
        imports_digest,
        syntax,
        syntax_digest,
    };
    let encoded = wire::encode_struct_map(&object).map_err(invalid_wire)?;
    let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let payload_digest = digest_bytes(&compressed);
    let payload_len =
        u32::try_from(compressed.len()).map_err(|_| invalid_data("compiler-object payload exceeds 4 GiB"))?;
    let header_encoded = wire::encode_struct_map(&header).map_err(invalid_wire)?;
    let header_compressed =
        zstd::stream::encode_all(Cursor::new(header_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let header_payload_digest = digest_bytes(&header_compressed);
    let header_payload_len = u32::try_from(header_compressed.len())
        .map_err(|_| invalid_data("compiler-object header payload exceeds 4 GiB"))?;
    let attribution_compressed = encode_compiler_attribution_payload(&attribution)?;
    let attribution_payload_digest = digest_bytes(&attribution_compressed);
    let attribution_payload_len = u32::try_from(attribution_compressed.len())
        .map_err(|_| invalid_data("compiler-object attribution payload exceeds 4 GiB"))?;
    let browse_encoded = wire::encode_struct_map(&browse).map_err(invalid_wire)?;
    let browse_compressed =
        zstd::stream::encode_all(Cursor::new(browse_encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
    let browse_payload_digest = digest_bytes(&browse_compressed);
    let browse_payload_len = u32::try_from(browse_compressed.len())
        .map_err(|_| invalid_data("compiler-object browse payload exceeds 4 GiB"))?;
    let declaration_compressed =
        encode_compiler_declaration_payload(descriptor.file, object.declarations.as_ref())?;
    let declaration_payload_digest = digest_bytes(&declaration_compressed);
    let declaration_payload_len = u32::try_from(declaration_compressed.len())
        .map_err(|_| invalid_data("compiler-object declaration payload exceeds 4 GiB"))?;
    // The exact text is resident while compiling; its line table lets every
    // later process map spans to lines without reading the file.
    let line_starts = db
        .inner
        .vfs
        .snapshot(descriptor.file)
        .map(|snapshot| line_starts_of(&snapshot.text))
        .unwrap_or_default();
    let lines_compressed = encode_line_starts_payload(&line_starts)?;
    let lines_payload_digest = digest_bytes(&lines_compressed);
    let lines_payload_len = u32::try_from(lines_compressed.len())
        .map_err(|_| invalid_data("compiler-object line table exceeds 4 GiB"))?;
    Ok(PreparedCompilerObject {
        compressed,
        payload_digest,
        payload_len,
        header_compressed,
        header_payload_digest,
        header_payload_len,
        attribution_compressed,
        attribution_payload_digest,
        attribution_payload_len,
        browse_compressed,
        browse_payload_digest,
        browse_payload_len,
        declaration_compressed,
        declaration_payload_digest,
        declaration_payload_len,
        lines_compressed,
        lines_payload_digest,
        lines_payload_len,
    })
}

fn ensure_source_version(db: &AnalyzerDb, descriptor: &SourceDescriptor) -> std::io::Result<()> {
    let (version, source_bytes, source_digest) = match db.inner.vfs.lazy_identity(descriptor.file) {
        // Still on disk: the identity is the text the loader will verify.
        Some(identity) => (
            db.inner
                .vfs
                .file_version(descriptor.file)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?,
            identity.len,
            identity.digest,
        ),
        None => {
            let snapshot = db
                .inner
                .vfs
                .snapshot(descriptor.file)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::Interrupted, error))?;
            (
                snapshot.version,
                u64::try_from(snapshot.text.len()).unwrap_or(u64::MAX),
                digest_bytes(snapshot.text.as_bytes()),
            )
        }
    };
    if version != descriptor.version
        || source_bytes != descriptor.source_bytes
        || source_digest != descriptor.source_digest
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            format!(
                "source changed while compiling immutable object `{}`",
                descriptor.path
            ),
        ));
    }
    Ok(())
}

fn compiler_object_cpu_workers() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
        .max(1);
    std::env::var("BONSAI_COMPILER_JOBS")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(available)
        .clamp(1, available)
}

fn validate_object(object: &CompiledFileObject, descriptor: &SourceDescriptor) -> std::io::Result<()> {
    if object.file != descriptor.file
        || object.path != descriptor.path
        || object.language != descriptor.language
        || object.source_digest != descriptor.source_digest
        || object
            .declarations
            .as_ref()
            .is_some_and(|index| index.file != descriptor.file)
        || object
            .imports
            .as_ref()
            .is_some_and(|index| index.file != descriptor.file)
        || object
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.span.file != descriptor.file)
    {
        return Err(invalid_data("compiler-object identity mismatch"));
    }
    Ok(())
}

fn generation_digest(descriptors: &[SourceDescriptor]) -> [u8; 32] {
    generation_digest_with_semantic_fingerprint(descriptors, compiler_frontend_semantic_fingerprint())
}

#[cfg(test)]
fn legacy_generation_digest_v11(descriptors: &[SourceDescriptor]) -> [u8; 32] {
    generation_digest_with_semantic_fingerprint(
        descriptors,
        legacy_compiler_frontend_semantic_fingerprint_v11(),
    )
}

fn generation_digest_with_semantic_fingerprint(
    descriptors: &[SourceDescriptor],
    semantic_fingerprint: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bonsai-compiler-generation-v1\0");
    hasher.update(semantic_fingerprint.to_le_bytes());
    for descriptor in descriptors {
        hasher.update(descriptor.file.raw().to_le_bytes());
        hasher.update(descriptor.path.as_bytes());
        hasher.update([0]);
        if let Some(language) = &descriptor.language {
            hasher.update(language.as_bytes());
        }
        hasher.update([0]);
        hasher.update(descriptor.source_digest);
        hasher.update(descriptor.source_hash.to_le_bytes());
    }
    hasher.finalize().into()
}

fn digest_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn import_index_digest(imports: Option<&ImportIndex>) -> [u8; 32] {
    let encoded = wire::encode_struct_map(&imports).expect("ImportIndex wire encoding is infallible");
    digest_bytes(&encoded)
}

fn compiler_syntax_header_digest(syntax: Option<&CompilerSyntaxHeader>) -> [u8; 32] {
    let encoded = wire::encode_struct_map(&syntax).expect("CompilerSyntaxHeader wire encoding is infallible");
    digest_bytes(&encoded)
}

fn encode_compiler_attribution_payload(attribution: &CompilerAttribution) -> std::io::Result<Vec<u8>> {
    let mut frames = Vec::with_capacity(attribution.functions.len());
    let mut frame_bytes = Vec::new();
    for function in &attribution.functions {
        let encoded = wire::encode_struct_map(function).map_err(invalid_wire)?;
        let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
        let compressed_len = u32::try_from(compressed.len())
            .map_err(|_| invalid_data("compiler-object attribution frame exceeds 4 GiB"))?;
        frames.push(CompilerAttributionFrame {
            declaration_span: function.declaration_span,
            relative_offset: u64::try_from(frame_bytes.len()).unwrap_or(u64::MAX),
            compressed_len,
            compressed_digest: digest_bytes(&compressed),
        });
        frame_bytes.extend_from_slice(&compressed);
    }
    let index = CompilerAttributionIndex {
        file: attribution.file,
        frames,
        frames_payload_offset: 0,
    };
    let index_bytes = wire::encode_struct_map(&index).map_err(invalid_wire)?;
    let index_len = u32::try_from(index_bytes.len())
        .map_err(|_| invalid_data("compiler-object attribution index exceeds 4 GiB"))?;
    let total_len = ATTRIBUTION_PAYLOAD_PREFIX_BYTES
        .checked_add(index_bytes.len())
        .and_then(|len| len.checked_add(frame_bytes.len()))
        .ok_or_else(|| invalid_data("compiler-object attribution payload length overflow"))?;
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&ATTRIBUTION_PAYLOAD_MAGIC);
    payload.extend_from_slice(&index_len.to_le_bytes());
    payload.extend_from_slice(&digest_bytes(&index_bytes));
    payload.extend_from_slice(&index_bytes);
    payload.extend_from_slice(&frame_bytes);
    Ok(payload)
}

/// Encode every declaration of the deduplicated index as its own compressed
/// frame behind a directory, so one declaration can be read without decoding
/// the file. Deduplication mirrors header construction exactly, keeping frame
/// positions aligned with the header symbol table.
fn encode_compiler_declaration_payload(
    file: FileId,
    declarations: Option<&DeclIndex>,
) -> std::io::Result<Vec<u8>> {
    let deduped = declarations.map(|index| {
        let mut index = index.clone();
        bonsai_index::dedup_decl_index_defs(&mut index);
        index
    });
    let decls: &[Decl] = deduped.as_ref().map_or(&[], |index| index.defs.as_slice());
    let mut frames = Vec::with_capacity(decls.len());
    let mut frame_bytes = Vec::new();
    for decl in decls {
        let encoded = wire::encode_struct_map(decl).map_err(invalid_wire)?;
        let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)?;
        let compressed_len = u32::try_from(compressed.len())
            .map_err(|_| invalid_data("compiler-object declaration frame exceeds 4 GiB"))?;
        frames.push(CompilerDeclarationFrame {
            declaration_span: decl.span,
            local_symbol: decl.symbol,
            relative_offset: u64::try_from(frame_bytes.len()).unwrap_or(u64::MAX),
            compressed_len,
            compressed_digest: digest_bytes(&compressed),
        });
        frame_bytes.extend_from_slice(&compressed);
    }
    let index = CompilerDeclarationIndex {
        file,
        frames,
        frames_payload_offset: 0,
    };
    let index_bytes = wire::encode_struct_map(&index).map_err(invalid_wire)?;
    let index_len = u32::try_from(index_bytes.len())
        .map_err(|_| invalid_data("compiler-object declaration index exceeds 4 GiB"))?;
    let total_len = DECLARATION_PAYLOAD_PREFIX_BYTES
        .checked_add(index_bytes.len())
        .and_then(|len| len.checked_add(frame_bytes.len()))
        .ok_or_else(|| invalid_data("compiler-object declaration payload length overflow"))?;
    let mut payload = Vec::with_capacity(total_len);
    payload.extend_from_slice(&DECLARATION_PAYLOAD_MAGIC);
    payload.extend_from_slice(&index_len.to_le_bytes());
    payload.extend_from_slice(&digest_bytes(&index_bytes));
    payload.extend_from_slice(&index_bytes);
    payload.extend_from_slice(&frame_bytes);
    Ok(payload)
}

fn validate_compiler_declaration_index(
    index: &CompilerDeclarationIndex,
    metadata: &CompilerObjectFileMetadata,
) -> std::io::Result<()> {
    if index.file.raw() != metadata.file {
        return Err(invalid_data(
            "compiler-object declaration index identity mismatch",
        ));
    }
    let frames_bytes = u64::from(metadata.declaration_payload_len)
        .checked_sub(index.frames_payload_offset)
        .ok_or_else(|| invalid_data("compiler-object declaration frame directory exceeds payload"))?;
    let mut expected_offset = 0_u64;
    for frame in &index.frames {
        if frame.relative_offset != expected_offset {
            return Err(invalid_data(
                "compiler-object declaration frames are not contiguous",
            ));
        }
        expected_offset = expected_offset
            .checked_add(u64::from(frame.compressed_len))
            .ok_or_else(|| invalid_data("compiler-object declaration frame length overflow"))?;
        if expected_offset > frames_bytes {
            return Err(invalid_data("compiler-object declaration frame exceeds payload"));
        }
    }
    if expected_offset != frames_bytes {
        return Err(invalid_data(
            "compiler-object declaration frames do not fill the payload",
        ));
    }
    Ok(())
}

fn validate_compiler_attribution_index(
    index: &CompilerAttributionIndex,
    metadata: &CompilerObjectFileMetadata,
) -> std::io::Result<()> {
    if index.file.raw() != metadata.file {
        return Err(invalid_data(
            "compiler-object attribution index identity mismatch",
        ));
    }
    let frames_bytes = u64::from(metadata.attribution_payload_len)
        .checked_sub(index.frames_payload_offset)
        .ok_or_else(|| invalid_data("compiler-object attribution frame directory exceeds payload"))?;
    let mut previous_span = None;
    let mut expected_offset = 0_u64;
    for frame in &index.frames {
        let span_key = (
            frame.declaration_span.file.raw(),
            frame.declaration_span.start,
            frame.declaration_span.end,
        );
        if frame.declaration_span.file != index.file
            || previous_span.is_some_and(|previous| previous >= span_key)
            || frame.relative_offset != expected_offset
        {
            return Err(invalid_data("compiler-object attribution index is not canonical"));
        }
        expected_offset = expected_offset
            .checked_add(u64::from(frame.compressed_len))
            .ok_or_else(|| invalid_data("compiler-object attribution frame range overflow"))?;
        if expected_offset > frames_bytes {
            return Err(invalid_data("compiler-object attribution frame exceeds payload"));
        }
        previous_span = Some(span_key);
    }
    if expected_offset != frames_bytes {
        return Err(invalid_data(
            "compiler-object attribution payload has unindexed bytes",
        ));
    }
    Ok(())
}

fn compiler_frontend_semantic_fingerprint() -> u64 {
    let policy = MATCHER_POLICY_FINGERPRINT;
    (policy as u64)
        ^ ((policy >> 64) as u64)
        ^ u64::from(COMPILER_OBJECT_CACHE_VERSION)
        ^ 0x434F_4D50_494C_4552
}

#[cfg(test)]
fn legacy_compiler_frontend_semantic_fingerprint_v11() -> u64 {
    let policy = MATCHER_POLICY_FINGERPRINT;
    (policy as u64)
        ^ ((policy >> 64) as u64)
        ^ u64::from(LEGACY_COMPILER_OBJECT_CACHE_VERSION)
        ^ 0x434F_4D50_494C_4552
}

fn metadata_pipeline_hash(metadata: &CompilerObjectMetadata) -> u64 {
    u64::from_le_bytes(
        metadata.generation_digest[..8]
            .try_into()
            .expect("fixed SHA-256 prefix"),
    ) ^ metadata.semantic_fingerprint
        ^ u64::from(metadata.version)
}

#[cfg(test)]
fn legacy_metadata_pipeline_hash_v11(metadata: &LegacyCompilerObjectMetadataV11) -> u64 {
    u64::from_le_bytes(
        metadata.generation_digest[..8]
            .try_into()
            .expect("fixed SHA-256 prefix"),
    ) ^ metadata.semantic_fingerprint
        ^ u64::from(metadata.version)
}

fn object_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(1)
}

#[cfg(test)]
fn legacy_object_key_v11(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_add(1)
}

fn header_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(2)
}

fn attribution_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(3)
}

fn browse_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(4)
}

fn declaration_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(5)
}

/// Line-start table of the exact source text: span → line/column without
/// reading the file.
fn lines_key(file: FileId) -> u64 {
    u64::from(file.raw()).saturating_mul(6).saturating_add(6)
}

fn compiler_object_entry_count(files: usize) -> usize {
    files.saturating_mul(6).saturating_add(1)
}

fn object_body_hash(descriptor: &SourceDescriptor) -> u64 {
    object_body_hash_from_digest(descriptor.source_digest)
}

fn object_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    u64::from_le_bytes(source_digest[..8].try_into().expect("fixed SHA-256 prefix"))
        ^ compiler_frontend_semantic_fingerprint()
}

#[cfg(test)]
fn legacy_object_body_hash_from_digest_v11(source_digest: [u8; 32]) -> u64 {
    u64::from_le_bytes(source_digest[..8].try_into().expect("fixed SHA-256 prefix"))
        ^ legacy_compiler_frontend_semantic_fingerprint_v11()
}

fn header_body_hash(descriptor: &SourceDescriptor) -> u64 {
    header_body_hash_from_digest(descriptor.source_digest)
}

fn header_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4845_4144_4552_5f31
}

fn attribution_body_hash(descriptor: &SourceDescriptor) -> u64 {
    attribution_body_hash_from_digest(descriptor.source_digest)
}

fn attribution_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4154_5452_4942_5f31
}

fn browse_body_hash(descriptor: &SourceDescriptor) -> u64 {
    browse_body_hash_from_digest(descriptor.source_digest)
}

fn browse_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4252_4f57_5345_5f31
}

fn lines_body_hash(descriptor: &SourceDescriptor) -> u64 {
    lines_body_hash_from_digest(descriptor.source_digest)
}

fn lines_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4c49_4e45_5354_5254
}

/// Byte offsets of every line start in `text` (`[0]` is always 0), the
/// exact table `bonsai_common::SpanMap` builds from the same text.
fn line_starts_of(text: &str) -> Vec<u32> {
    let mut starts = Vec::with_capacity(text.len() / 40 + 1);
    starts.push(0);
    for (idx, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(u32::try_from(idx + 1).unwrap_or(u32::MAX));
        }
    }
    starts
}

fn encode_line_starts_payload(line_starts: &[u32]) -> std::io::Result<Vec<u8>> {
    let encoded = wire::encode(&line_starts.to_vec()).map_err(invalid_wire)?;
    zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)
}

fn declaration_body_hash(descriptor: &SourceDescriptor) -> u64 {
    declaration_body_hash_from_digest(descriptor.source_digest)
}

fn declaration_body_hash_from_digest(source_digest: [u8; 32]) -> u64 {
    object_body_hash_from_digest(source_digest) ^ 0x4445_434c_4652_4d31
}

fn validate_streamed_payload(
    reader: &FactStoreReader,
    key: u64,
    body_hash: u64,
    expected_len: u32,
    expected_digest: [u8; 32],
    label: &'static str,
) -> std::io::Result<()> {
    let mut payload = reader
        .payload_reader(key)
        .map_err(factstore_io)?
        .ok_or_else(|| invalid_data("compiler-object payload is missing"))?;
    if payload.body_hash != body_hash {
        return Err(invalid_data("compiler-object body fingerprint mismatch"));
    }
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = payload.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total = total.saturating_add(read as u64);
    }
    if total != u64::from(expected_len) || <[u8; 32]>::from(hasher.finalize()) != expected_digest {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{label} payload digest mismatch"),
        ));
    }
    Ok(())
}

fn invalid_wire(error: impl std::error::Error + Send + Sync + 'static) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

fn invalid_data(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.into())
}

fn factstore_io(error: FactStoreError) -> std::io::Error {
    match error {
        FactStoreError::Io(error) => error,
        other => std::io::Error::new(std::io::ErrorKind::InvalidData, other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bonsai_factstore::{Header, IndexEntry, HEADER_SIZE, INDEX_ENTRY_SIZE};
    use bonsai_lang_api::LanguageRegistry;
    use bonsai_vfs::Vfs;
    use std::io::{Read, Seek, SeekFrom, Write};

    #[test]
    fn parallel_visit_crosses_slow_head_and_preserves_every_index() {
        let items = (0usize..16).collect::<Vec<_>>();
        let release_head = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut visited = Vec::new();

        try_visit_parallel(
            &items,
            3,
            9,
            ParallelVisitOrder::Completion,
            {
                let release_head = Arc::clone(&release_head);
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                move |index, value| {
                    let now_active = active.fetch_add(1, Ordering::AcqRel) + 1;
                    max_active.fetch_max(now_active, Ordering::AcqRel);
                    if index == 0 {
                        let (lock, ready) = &*release_head;
                        let released = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (released, timeout) = ready
                            .wait_timeout_while(released, std::time::Duration::from_secs(2), |released| {
                                !*released
                            })
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if !*released || timeout.timed_out() {
                            active.fetch_sub(1, Ordering::AcqRel);
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "continuous workers did not cross the slow head",
                            ));
                        }
                    }
                    active.fetch_sub(1, Ordering::AcqRel);
                    Ok(*value)
                }
            },
            |index, value| {
                visited.push(value);
                if index >= 9 {
                    let (lock, ready) = &*release_head;
                    *lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                    ready.notify_all();
                }
                Ok(())
            },
        )
        .expect("continuous parallel visit");

        assert_ne!(
            visited[0], 0,
            "a slow canonical head must not block physical publication"
        );
        visited.sort_unstable();
        assert_eq!(
            visited, items,
            "every scheduled item must be published exactly once"
        );
        assert!(
            max_active.load(Ordering::Acquire) <= 3,
            "the configured worker ceiling must remain authoritative"
        );
    }

    #[test]
    fn ordered_parallel_visit_crosses_the_first_worker_batch() {
        let items = (0usize..8).collect::<Vec<_>>();
        let later_started = Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
        let mut visited = Vec::new();

        try_visit_parallel(
            &items,
            2,
            4,
            ParallelVisitOrder::Input,
            {
                let later_started = Arc::clone(&later_started);
                move |index, value| {
                    let (lock, ready) = &*later_started;
                    if index == 0 {
                        let started = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        let (started, timeout) = ready
                            .wait_timeout_while(started, std::time::Duration::from_secs(2), |started| {
                                !*started
                            })
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if !*started || timeout.timed_out() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                "ordered worklist stopped at a per-worker batch barrier",
                            ));
                        }
                    } else if index == 2 {
                        *lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
                        ready.notify_all();
                    }
                    Ok(*value)
                }
            },
            |_, value| {
                visited.push(value);
                Ok(())
            },
        )
        .expect("ordered continuous parallel visit");

        assert_eq!(visited, items, "ordered publication must remain deterministic");
    }

    #[test]
    fn parallel_visit_bounds_workers_and_propagates_errors() {
        let items = (0usize..12).collect::<Vec<_>>();
        let active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_active = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut visited = Vec::new();
        try_visit_parallel(
            &items,
            2,
            4,
            ParallelVisitOrder::Completion,
            {
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                move |_, value| {
                    let now_active = active.fetch_add(1, Ordering::AcqRel) + 1;
                    max_active.fetch_max(now_active, Ordering::AcqRel);
                    std::thread::yield_now();
                    active.fetch_sub(1, Ordering::AcqRel);
                    Ok(*value)
                }
            },
            |_, value| {
                visited.push(value);
                Ok(())
            },
        )
        .expect("bounded parallel visit");
        visited.sort_unstable();
        assert_eq!(visited, items);
        assert!(
            max_active.load(Ordering::Acquire) <= 2,
            "the worker bound must remain authoritative"
        );

        let error = try_visit_parallel(
            &items,
            3,
            6,
            ParallelVisitOrder::Completion,
            |index, value| {
                if index == 3 {
                    Err(std::io::Error::other("injected compiler failure"))
                } else {
                    Ok(*value)
                }
            },
            |_, _| Ok(()),
        )
        .expect_err("worker errors must abort publication");
        assert_eq!(error.to_string(), "injected compiler failure");
    }

    #[test]
    fn compiler_object_cache_maintenance_is_versioned_and_lock_safe() {
        let dir = tempfile::tempdir().expect("tempdir");
        let current = dir.path().join(format!(
            "compiler-objects.v{COMPILER_OBJECT_CACHE_VERSION}.factstore"
        ));
        let old = dir.path().join(format!(
            "compiler-objects.v{}.factstore",
            COMPILER_OBJECT_CACHE_VERSION - 1
        ));
        let active_old = dir.path().join(format!(
            "compiler-objects.v{}.factstore",
            COMPILER_OBJECT_CACHE_VERSION - 2
        ));
        let newer = dir.path().join(format!(
            "compiler-objects.v{}.factstore",
            COMPILER_OBJECT_CACHE_VERSION + 1
        ));
        let manual = dir.path().join(format!(
            "compiler-objects.v{}.factstore.before-audit",
            COMPILER_OBJECT_CACHE_VERSION - 3
        ));
        let abandoned = PathBuf::from(format!("{}.tmp.1234.5", current.display()));
        let old_abandoned = PathBuf::from(format!("{}.tmp.1234.6", old.display()));
        for path in [
            &current,
            &old,
            &active_old,
            &newer,
            &manual,
            &abandoned,
            &old_abandoned,
        ] {
            std::fs::write(path, b"fixture").expect("write cache fixture");
        }
        let active_lock = open_compiler_object_lock_file(&active_old).expect("open active old lock");
        active_lock.try_lock_exclusive().expect("own old generation");

        let guard = CompilerObjectSidecarWriteGuard::acquire(&current).expect("own current generation");
        assert!(!old.exists(), "unowned obsolete generation should be reclaimed");
        assert!(
            active_old.exists(),
            "an obsolete generation owned by another writer must remain"
        );
        assert!(newer.exists(), "a newer generation must never be reclaimed");
        assert!(
            manual.exists(),
            "unrecognized manual artifacts must not be guessed at"
        );
        assert!(
            !abandoned.exists(),
            "abandoned current-writer staging should be reclaimed"
        );
        assert!(
            !old_abandoned.exists(),
            "abandoned obsolete staging should be reclaimed"
        );

        drop(guard);
        FileExt::unlock(&active_lock).expect("release old generation");
    }

    #[test]
    fn compiler_object_generation_round_trips_and_rejects_changed_source() {
        let root = tempfile::tempdir().expect("tempdir");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write("src/input.fixture".to_string(), Arc::<str>::from("first"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());

        assert_eq!(
            db.save_compiler_object_sidecar(root.path())
                .expect("save objects"),
            1
        );
        assert!(db.compiler_object_sidecar_is_current(root.path()));
        let object = db.compiler_file_object_uncached(file).expect("load object");
        assert_eq!(object.source_digest, digest_bytes(b"first"));
        assert!(object.diagnostics.is_empty());

        vfs.write("src/input.fixture".to_string(), Arc::<str>::from("second"));
        assert!(!db.compiler_object_sidecar_is_current(root.path()));
        let object = db.compiler_file_object_uncached(file).expect("recompile object");
        assert_eq!(object.source_digest, digest_bytes(b"second"));
    }

    #[test]
    fn compiler_object_records_the_line_table_and_lazy_sources_map_spans_without_reading() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        let text = "a\nbb\n\nccc";
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from(text));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        assert_eq!(
            db.save_compiler_object_sidecar(root.path())
                .expect("save objects"),
            1
        );
        assert_eq!(db.compiler_line_starts_uncached(file), Some(vec![0, 2, 5, 6]));
        let loaded_map = db.span_map(file).expect("span map from loaded text");
        assert_eq!(
            (loaded_map.line_col(3).line, loaded_map.line_col(3).column),
            (2, 2)
        );

        // A second process interns the same source by identity; its span map
        // comes from the recorded line table and the loader is never asked.
        let lazy_vfs = Arc::new(Vfs::new());
        let lazy_file = lazy_vfs.write_lazy(
            source.to_string_lossy().into_owned(),
            bonsai_vfs::SourceIdentity {
                len: text.len() as u64,
                hash: fnv1a_bytes64(text.as_bytes()),
                digest: digest_bytes(text.as_bytes()),
            },
        );
        lazy_vfs.set_lazy_loader(Arc::new(|path: &Path, _: &bonsai_vfs::SourceIdentity| {
            Err(std::io::Error::other(format!(
                "span mapping must not read {}",
                path.display()
            )))
        }));
        let lazy_db = AnalyzerDb::new(Arc::clone(&lazy_vfs), Arc::new(LanguageRegistry::new()));
        lazy_db.set_workspace_root(root.path().to_path_buf());
        lazy_db
            .load_compiler_object_store_for_source_fingerprints(
                root.path(),
                std::iter::once((&source, fnv1a_bytes64(text.as_bytes()))),
            )
            .expect("load persisted generation");
        let lazy_map = lazy_db.span_map(lazy_file).expect("span map from the line table");
        assert_eq!((lazy_map.line_col(6).line, lazy_map.line_col(6).column), (4, 1));
        assert_eq!((lazy_map.line_col(8).line, lazy_map.line_col(8).column), (4, 3));
        assert_eq!(lazy_vfs.lazy_source_counts(), (1, 0), "no source was read");
    }

    #[test]
    fn lazy_span_maps_are_isolated_across_workspace_instances() {
        // Both databases allocate FileId(0), version 0 on this thread, but
        // their compiler line tables describe different source layouts.
        for text in ["a\nbb\n\nccc", "aaaaaaaaa", "a\nbb\n\nccc"] {
            let root = tempfile::tempdir().expect("tempdir");
            let source = root.path().join("input.fixture");
            let vfs = Arc::new(Vfs::new());
            let file = vfs.write(source.clone(), text);
            let db = AnalyzerDb::new(vfs, Arc::new(LanguageRegistry::new()));
            db.set_workspace_root(root.path().to_path_buf());
            db.save_compiler_object_sidecar(root.path())
                .expect("save objects");

            let lazy_vfs = Arc::new(Vfs::new());
            let lazy_file = lazy_vfs.write_lazy(
                source.clone(),
                bonsai_vfs::SourceIdentity {
                    len: text.len() as u64,
                    hash: fnv1a_bytes64(text.as_bytes()),
                    digest: digest_bytes(text.as_bytes()),
                },
            );
            assert_eq!(file, lazy_file);
            let lazy_db = AnalyzerDb::new(Arc::clone(&lazy_vfs), Arc::new(LanguageRegistry::new()));
            lazy_db.set_workspace_root(root.path().to_path_buf());
            let expected = bonsai_common::SpanMap::new(text);
            let actual = lazy_db.span_map(lazy_file).expect("persisted line table");
            for byte in 0..=text.len() as u64 {
                assert_eq!(actual.line_col(byte), expected.line_col(byte), "source {text:?}");
            }
            assert_eq!(lazy_vfs.lazy_source_counts(), (1, 0), "must remain lazy");
        }
    }

    #[test]
    fn compiler_object_identity_is_workspace_relative() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());

        let object = db.compiler_file_object_uncached(file).expect("compile object");
        assert_eq!(object.path, "src/input.fixture");
    }

    #[test]
    fn root_validator_binds_generation_to_exact_source_paths_and_hashes() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        let vfs = Arc::new(Vfs::new());
        vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");

        assert_eq!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(&source, fnv1a_bytes64(b"source"))],
            )
            .expect("exact source generation"),
            1
        );
        assert!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(&source, fnv1a_bytes64(b"changed"))],
            )
            .is_err(),
            "same path with changed content must reject the generation"
        );
        assert!(
            validate_compiler_object_sidecar_file_with_source_fingerprints(
                root.path(),
                [(root.path().join("src/other.fixture"), fnv1a_bytes64(b"source"))],
            )
            .is_err(),
            "same content under a different module path must reject the generation"
        );
    }

    #[test]
    fn bulk_compiler_objects_preserve_requested_order_and_complete_coverage() {
        let vfs = Arc::new(Vfs::new());
        let first = vfs.write("src/first.fixture".to_string(), Arc::<str>::from("first"));
        let second = vfs.write("src/second.fixture".to_string(), Arc::<str>::from("second"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));

        let requested = [second, first, second];
        let mut objects = Vec::new();
        db.visit_compiler_file_objects_uncached(&requested, |file, object| {
            objects.push((file, object));
        });

        assert_eq!(
            objects.iter().map(|(file, _)| *file).collect::<Vec<_>>(),
            requested,
            "memory-aware scheduling must not reorder or omit compiler units"
        );
        assert_eq!(
            objects
                .iter()
                .map(|(_, object)| object.as_ref().map(|object| object.source_digest))
                .collect::<Vec<_>>(),
            vec![
                Some(digest_bytes(b"second")),
                Some(digest_bytes(b"first")),
                Some(digest_bytes(b"second")),
            ]
        );
    }

    #[test]
    fn compiler_object_validation_rejects_same_size_payload_corruption() {
        let root = tempfile::tempdir().expect("tempdir");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write("src/input.fixture".to_string(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");

        let path = compiler_object_sidecar_path(root.path());
        let mut sidecar = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open compiler-object sidecar");
        let mut header_bytes = [0_u8; HEADER_SIZE];
        sidecar.read_exact(&mut header_bytes).expect("read header");
        let header = Header::from_bytes(&header_bytes).expect("valid factstore header");
        sidecar
            .seek(SeekFrom::Start(header.index_offset))
            .expect("seek index");
        let mut object_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == object_key(file) {
                object_entry = Some(entry);
                break;
            }
        }
        let entry = object_entry.expect("compiler-object entry");
        sidecar
            .seek(SeekFrom::Start(entry.payload_offset))
            .expect("seek object payload");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read object payload");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(entry.payload_offset))
            .expect("rewind object payload");
        sidecar.write_all(&byte).expect("corrupt object payload");
        sidecar.sync_all().expect("flush object corruption");

        assert!(validate_compiler_object_sidecar_layout(root.path()).is_err());
        assert!(!db.compiler_object_sidecar_is_current(root.path()));
    }

    #[test]
    fn function_attribution_batch_preserves_requested_span_order() {
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(
            "src/input.py".to_string(),
            Arc::<str>::from(
                "def first(payload):\n    left(payload)\n\ndef second(other):\n    right(other)\n",
            ),
        );
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
        let index = db.decl_index_uncached(file).expect("Python compiler IR");
        let first = index
            .defs
            .iter()
            .find(|decl| decl.name == "first")
            .expect("first function")
            .span;
        let second = index
            .defs
            .iter()
            .find(|decl| decl.name == "second")
            .expect("second function")
            .span;
        let missing = Span::new(file, second.end.saturating_add(1), second.end.saturating_add(2));

        let batch = db.compiler_function_attributions_uncached(file, &[second, missing, first]);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].as_ref().expect("second frame").calls[0].name, "right");
        assert!(batch[1].is_none());
        assert_eq!(batch[2].as_ref().expect("first frame").calls[0].name, "left");
        assert_eq!(
            db.compiler_function_attribution_uncached(file, first),
            batch[2],
            "the single-frame facade must preserve batch semantics"
        );
    }

    #[test]
    fn compiler_attribution_decodes_without_opening_corrupt_full_body() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.py");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(
            source.to_string_lossy().into_owned(),
            Arc::<str>::from("def route(payload):\n    repo.send(payload)\n    return payload\n"),
        );
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
        db.set_workspace_root(root.path().to_path_buf());
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let object = db.compile_fresh_file_object(descriptor.clone());
        let expected = object
            .declarations
            .as_ref()
            .map(CompilerAttribution::from_decl_index)
            .expect("python attribution");
        assert_eq!(expected.functions.len(), 1);
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");

        let path = compiler_object_sidecar_path(root.path());
        let mut sidecar = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open compiler-object sidecar");
        let mut header_bytes = [0_u8; HEADER_SIZE];
        sidecar.read_exact(&mut header_bytes).expect("read header");
        let header = Header::from_bytes(&header_bytes).expect("valid factstore header");
        sidecar
            .seek(SeekFrom::Start(header.index_offset))
            .expect("seek index");
        let mut body_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == object_key(file) {
                body_entry = Some(entry);
                break;
            }
        }
        let body_entry = body_entry.expect("compiler body entry");
        sidecar
            .seek(SeekFrom::Start(body_entry.payload_offset))
            .expect("seek body payload");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read body payload");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(body_entry.payload_offset))
            .expect("rewind body payload");
        sidecar.write_all(&byte).expect("corrupt body payload");
        sidecar.sync_all().expect("flush corruption");

        let store = CompilerObjectStore::open_reusable(root.path()).expect("open generation metadata");
        assert_eq!(
            store
                .load_attribution(&descriptor)
                .expect("independent attribution payload"),
            Some(expected),
            "attribution lookup must not touch the unrelated full-body payload"
        );
        assert!(
            store.load(&descriptor).is_err(),
            "test must corrupt only the full body"
        );
    }

    #[test]
    fn function_attribution_range_does_not_decode_corrupt_sibling_frame() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.py");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(
            source.to_string_lossy().into_owned(),
            Arc::<str>::from(
                "def first(payload):\n    sink(payload)\n\ndef second(other):\n    sink(other)\n",
            ),
        );
        let registry = Arc::new(LanguageRegistry::new());
        registry.register(Arc::new(bonsai_lang_python::PythonAdapter::new()));
        let db = AnalyzerDb::new(Arc::clone(&vfs), registry);
        db.set_workspace_root(root.path().to_path_buf());
        db.save_compiler_object_sidecar(root.path())
            .expect("save objects");
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let original = CompilerObjectStore::open_reusable(root.path()).expect("open store");
        let index = original
            .load_attribution_index(&descriptor)
            .expect("load frame index")
            .expect("frame index");
        let reused_index = original
            .load_attribution_index(&descriptor)
            .expect("reuse frame index")
            .expect("cached frame index");
        assert!(
            Arc::ptr_eq(&index, &reused_index),
            "immutable frame directories should decode once per live compiler generation"
        );
        assert_eq!(index.frames.len(), 2);
        let first_span = index.frames[0].declaration_span;
        let second_span = index.frames[1].declaration_span;

        let path = compiler_object_sidecar_path(root.path());
        let mut sidecar = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open sidecar");
        let mut header_bytes = [0_u8; HEADER_SIZE];
        sidecar.read_exact(&mut header_bytes).expect("read header");
        let header = Header::from_bytes(&header_bytes).expect("valid header");
        sidecar
            .seek(SeekFrom::Start(header.index_offset))
            .expect("seek index");
        let mut attribution_entry = None;
        for _ in 0..header.index_count {
            let mut entry_bytes = [0_u8; INDEX_ENTRY_SIZE];
            sidecar.read_exact(&mut entry_bytes).expect("read index entry");
            let entry = IndexEntry::from_bytes(&entry_bytes).expect("valid index entry");
            if entry.key == attribution_key(file) {
                attribution_entry = Some(entry);
                break;
            }
        }
        let attribution_entry = attribution_entry.expect("attribution entry");
        let corrupt_offset = attribution_entry
            .payload_offset
            .saturating_add(index.frames_payload_offset)
            .saturating_add(index.frames[1].relative_offset);
        sidecar
            .seek(SeekFrom::Start(corrupt_offset))
            .expect("seek second frame");
        let mut byte = [0_u8; 1];
        sidecar.read_exact(&mut byte).expect("read second frame");
        byte[0] ^= 0xff;
        sidecar
            .seek(SeekFrom::Start(corrupt_offset))
            .expect("rewind second frame");
        sidecar.write_all(&byte).expect("corrupt second frame");
        sidecar.sync_all().expect("flush corruption");

        let store = CompilerObjectStore::open_reusable(root.path()).expect("reopen store");
        let index = store
            .load_attribution_index(&descriptor)
            .expect("uncorrupted index")
            .expect("index");
        assert!(store
            .load_function_attribution(&descriptor, &index, first_span)
            .expect("first frame remains independently readable")
            .is_some());
        assert!(
            store
                .load_function_attribution(&descriptor, &index, second_span)
                .is_err(),
            "the selected corrupt sibling must still fail integrity validation"
        );
        assert!(validate_compiler_object_sidecar_layout(root.path()).is_err());
    }

    #[test]
    fn legacy_v11_generation_cannot_be_relabelled_as_current_frontend_ir() {
        let root = tempfile::tempdir().expect("tempdir");
        let source = root.path().join("src/input.fixture");
        std::fs::create_dir_all(source.parent().expect("source parent")).expect("source directory");
        std::fs::write(&source, "source").expect("source file");
        let vfs = Arc::new(Vfs::new());
        let file = vfs.write(source.to_string_lossy().into_owned(), Arc::<str>::from("source"));
        let db = AnalyzerDb::new(Arc::clone(&vfs), Arc::new(LanguageRegistry::new()));
        db.set_workspace_root(root.path().to_path_buf());
        let descriptor = source_descriptor(&db, file).expect("source descriptor");
        let object = db.compile_fresh_file_object(descriptor.clone());
        let encoded = wire::encode_struct_map(&object).expect("encode legacy object");
        let compressed = zstd::stream::encode_all(Cursor::new(encoded), COMPILER_OBJECT_COMPRESSION_LEVEL)
            .expect("compress legacy object");
        let payload_digest = digest_bytes(&compressed);
        let payload_len = u32::try_from(compressed.len()).expect("legacy payload length");
        let imports = object.imports.clone();
        let syntax = object
            .declarations
            .as_ref()
            .map(CompilerSyntaxHeader::from_decl_index);
        let legacy_metadata = LegacyCompilerObjectMetadataV11 {
            version: LEGACY_COMPILER_OBJECT_CACHE_VERSION,
            semantic_fingerprint: legacy_compiler_frontend_semantic_fingerprint_v11(),
            generation_digest: legacy_generation_digest_v11(std::slice::from_ref(&descriptor)),
            files: vec![LegacyCompilerObjectFileMetadataV11 {
                file: file.raw(),
                path: descriptor.path.clone(),
                language: descriptor.language.clone(),
                source_digest: descriptor.source_digest,
                source_hash: descriptor.source_hash,
                payload_digest,
                payload_len,
                imports: imports.clone(),
                imports_digest: import_index_digest(imports.as_ref()),
                syntax: syntax.clone(),
                syntax_digest: compiler_syntax_header_digest(syntax.as_ref()),
            }],
        };
        let legacy_path = workspace_bonsai_dir(root.path()).join(format!(
            "compiler-objects.v{LEGACY_COMPILER_OBJECT_CACHE_VERSION}.factstore"
        ));
        let mut prepared =
            PreparedFactStorePayload::create_near(&legacy_path).expect("prepare legacy payload");
        let (payload_offset, persisted_len) = prepared.append(&compressed).expect("append legacy object");
        assert_eq!(persisted_len, payload_len);
        let writer = FactStoreWriter::create_from_prepared(
            &legacy_path,
            COMPILER_OBJECT_TABLE_ID,
            legacy_metadata_pipeline_hash_v11(&legacy_metadata),
            prepared,
            vec![PreparedFactStoreEntry {
                key: legacy_object_key_v11(file),
                body_hash: legacy_object_body_hash_from_digest_v11(descriptor.source_digest),
                payload_offset,
                payload_len,
            }],
        )
        .expect("legacy writer");
        writer
            .add_owned(
                METADATA_KEY,
                u64::from(LEGACY_COMPILER_OBJECT_CACHE_VERSION),
                wire::encode_struct_map(&legacy_metadata).expect("encode legacy metadata"),
            )
            .expect("legacy metadata");
        assert_eq!(writer.finish().expect("finish legacy sidecar"), 2);

        assert_eq!(
            migrate_legacy_compiler_object_sidecar_v11_with_source_fingerprints(
                root.path(),
                [(&source, descriptor.source_hash)],
            )
            .expect("incompatible generation requires normal rebuild"),
            None
        );
        assert!(
            !compiler_object_sidecar_path(root.path()).exists(),
            "old IR must not become a current generation"
        );
        assert!(
            legacy_path.is_file(),
            "rebuild selection must not delete the old input"
        );
        db.save_compiler_object_sidecar(root.path())
            .expect("normal compiler rebuild");
        let rebuilt = CompilerObjectStore::open_reusable(root.path()).expect("fresh generation");
        assert_eq!(rebuilt.metadata.version, COMPILER_OBJECT_CACHE_VERSION);
        assert_eq!(rebuilt.load(&descriptor).expect("fresh body"), Some(object));
    }
}
