use bonsai_diagnostics::DiagnosticSink;
use bonsai_lang_api::{AdapterContext, LanguageAdapter};
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
