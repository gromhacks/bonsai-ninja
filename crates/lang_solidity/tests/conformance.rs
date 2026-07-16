use bonsai_diagnostics::DiagnosticSink;
use bonsai_lang_api::{AdapterContext, DeclKind, FlowEvent, LanguageAdapter};
use bonsai_vfs::Vfs;
use parking_lot::RwLock;

#[test]
fn solidity_adapter_populates_parameter_type_aliases() {
    let adapter = bonsai_lang_solidity::SolidityAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Vault.sol"),
        "contract Vault { function execute(address target, bytes memory payload) public { target.call(payload); } }",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let execute = idx
        .defs
        .iter()
        .find(|decl| decl.name == "execute")
        .expect("execute decl");
    assert!(
        execute
            .type_aliases
            .iter()
            .any(|alias| alias.name == "target" && alias.type_name == "address"),
        "Solidity receiver-sensitive analysis needs target: address, got {:?}",
        execute.type_aliases
    );
    assert!(
        execute
            .type_aliases
            .iter()
            .any(|alias| alias.name == "payload" && alias.type_name == "bytes"),
        "Solidity receiver-sensitive analysis needs payload: bytes, got {:?}",
        execute.type_aliases
    );
}

#[test]
fn solidity_adapter_call_result_assignment_uses_call_metadata_only() {
    let adapter = bonsai_lang_solidity::SolidityAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Shape.sol"),
        "contract Shape { \
           function entry(uint256 x) public returns (uint256) { uint256 z = f(x); return z; } \
           function f(uint256 a) internal pure returns (uint256) { return a; } \
         }",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl");

    let assign = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "z" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("assignment to z present");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("f"));
    assert_eq!(assign.2.as_slice(), ["x"]);
    assert!(
        assign.3.is_empty(),
        "call-result assignment should not duplicate callee/arg sources; events: {:?}",
        entry.flow_events
    );
}

#[test]
fn solidity_adapter_method_call_result_preserves_receiver_source_name() {
    let adapter = bonsai_lang_solidity::SolidityAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("Vault.sol"),
        "contract Vault { \
           function entry(address target, bytes memory payload) public returns (bool) { \
             bool ok = target.call(payload); return ok; \
           } \
         }",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let entry = idx
        .defs
        .iter()
        .find(|decl| decl.name == "entry")
        .expect("entry decl");

    let assign = entry
        .flow_events
        .iter()
        .find_map(|event| match event {
            FlowEvent::Assign {
                target,
                source_name,
                source_call,
                source_call_args,
                source_names,
                ..
            } if target == "ok" => Some((source_name, source_call, source_call_args, source_names)),
            _ => None,
        })
        .expect("assignment to ok present");

    assert_eq!(assign.0.as_deref(), None);
    assert_eq!(assign.1.as_deref(), Some("target.call"));
    assert_eq!(assign.2.as_slice(), ["payload"]);
    assert_eq!(assign.3.as_slice(), ["target"]);
}

#[test]
fn solidity_modifier_definition_is_not_a_method_entry() {
    let adapter = bonsai_lang_solidity::SolidityAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("App.sol"),
        "contract App { \
           modifier audit(bytes calldata data) { _; } \
           function handle(bytes calldata data) external audit(data) {} \
         }",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let audit = idx
        .defs
        .iter()
        .find(|decl| decl.name == "audit")
        .expect("audit modifier decl");
    let handle = idx
        .defs
        .iter()
        .find(|decl| decl.name == "handle")
        .expect("handle method decl");

    assert_eq!(audit.kind, DeclKind::Function);
    assert_eq!(handle.kind, DeclKind::Method);
}

#[test]
fn solidity_emit_and_yul_args_preserve_ast_value_facts() {
    let adapter = bonsai_lang_solidity::SolidityAdapter::new();
    let vfs = Vfs::new();
    let file = vfs.write(
        std::path::Path::new("AstArgs.sol"),
        "contract AstArgs {\n\
           struct Envelope { bytes command; }\n\
           event Action(bytes value);\n\
           function log(Envelope memory env, bool enabled) public returns (bytes memory) { if (enabled) { emit Action(env.command); } return env.command; }\n\
           function raw(address target) public { assembly { pop(call(gas(), target, 0, 0, 0, 0, 0)) } }\n\
         }",
    );
    let diagnostics = RwLock::new(DiagnosticSink::default());
    let ctx = AdapterContext {
        vfs: &vfs,
        diagnostics: &diagnostics,
        tree_provider: None,
        workspace_root: None,
    };
    let idx = adapter.extract_declarations(file, &ctx);
    let log = idx.defs.iter().find(|decl| decl.name == "log").expect("log decl");
    let branch = log.flow_events.iter().find_map(|event| match event {
        FlowEvent::Branch { then_events, .. } => Some(then_events),
        _ => None,
    });
    let branch = branch.unwrap_or_else(|| panic!("emit branch: {:?}", log.flow_events));
    let emit_arg = branch.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "emit" => args.first(),
        _ => None,
    });
    let emit_arg = emit_arg.unwrap_or_else(|| panic!("emit call: {:?}", log.flow_events));
    assert_eq!(
        emit_arg.place.as_deref(),
        Some("env.command"),
        "emit argument should retain its AST place: {:?}",
        log.flow_events
    );
    assert!(emit_arg.source_names.iter().any(|name| name == "env.command"));
    assert!(matches!(log.flow_events.last(), Some(FlowEvent::Return { .. })));

    let raw = idx.defs.iter().find(|decl| decl.name == "raw").expect("raw decl");
    let target_arg = raw.flow_events.iter().find_map(|event| match event {
        FlowEvent::Call { name, args, .. } if name == "call" => {
            args.iter().find(|arg| arg.value_text == "target")
        }
        _ => None,
    });
    let target_arg = target_arg.unwrap_or_else(|| panic!("Yul call: {:?}", raw.flow_events));
    assert_eq!(target_arg.place.as_deref(), Some("target"));
    assert!(target_arg.source_names.iter().any(|name| name == "target"));
}
