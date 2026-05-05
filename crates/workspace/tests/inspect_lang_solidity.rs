#[path = "inspect_harness.rs"]
mod h;

use h::*;
use std::sync::Arc;

fn sol() -> bonsai_lang_api::AdapterArc {
    Arc::new(bonsai_lang_solidity::SolidityAdapter::new())
}

#[test]
fn cross_contract_chain() {
    let w = ws_multi(
        sol(),
        &[
            (
                "/w/Gateway.sol",
                "pragma solidity ^0.8.0;\n\
                 import \"./UserService.sol\";\n\
                 contract Gateway {\n\
                   UserService svc;\n\
                   function handleRequest(bytes32 t) public { svc.updateUser(t); }\n\
                 }\n",
            ),
            (
                "/w/UserService.sol",
                "pragma solidity ^0.8.0;\n\
                 import \"./Auth.sol\";\n\
                 contract UserService {\n\
                   Auth auth;\n\
                   function updateUser(bytes32 t) public { auth.runAdminCommand(t); }\n\
                 }\n",
            ),
            (
                "/w/Auth.sol",
                "pragma solidity ^0.8.0;\n\
                 contract Auth {\n\
                   function runAdminCommand(bytes32 cmd) external { require(cmd != bytes32(0)); }\n\
                 }\n",
            ),
        ],
    );
    assert_chain_from_to(&w, "handleRequest", "runAdminCommand");
}

#[test]
fn chain_through_if_for_while() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             contract A {\n\
               function entry(uint256 x) public {\n\
                 if (x > 0) { a(); } else { b(); }\n\
                 for (uint256 i = 0; i < 3; i++) { step(); }\n\
                 while (cond()) { d(); }\n\
               }\n\
               function a() internal { sink(); }\n\
               function b() internal { sink(); }\n\
               function step() internal { sink(); }\n\
               function cond() internal returns (bool) { return false; }\n\
               function d() internal { sink(); }\n\
               function sink() internal {}\n\
             }\n",
        )],
    );
    let chains = enumerate_chains(&w, "sink", 32);
    for via in ["a", "b", "step", "d"] {
        assert!(
            chains.iter().any(|ch| ch.contains(&via.to_string())),
            "missing {via} path: {chains:?}"
        );
    }
}

#[test]
fn modifier_is_indexed() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             contract A {\n\
               address owner;\n\
               modifier onlyOwner() { require(msg.sender == owner); _; }\n\
               function admin() public onlyOwner { }\n\
             }\n",
        )],
    );
    // `modifier onlyOwner() { ... }` indexes as a decl via the
    // `modifier_definition` kind in fn_kinds.
    let h = query_hits(&w, "onlyOwner");
    assert!(h.has_decl("onlyOwner"), "onlyOwner modifier decl missing: {h:?}");
    assert_chain_from_to(&w, "admin", "onlyOwner");
}

#[test]
fn fallback_and_receive_are_indexed() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             contract A {\n\
               receive() external payable { sink(); }\n\
               fallback() external { sink(); }\n\
               function sink() internal {}\n\
             }\n",
        )],
    );
    assert_function_named(&w, "receive");
    assert_function_named(&w, "fallback");
    assert_chain_from_to(&w, "receive", "sink");
    assert_chain_from_to(&w, "fallback", "sink");
}

#[test]
fn import_is_surfaced_as_import() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             import \"@openzeppelin/contracts/access/Ownable.sol\";\n\
             import {SafeMath as SM} from \"./safe.sol\";\n\
             contract A { }\n",
        )],
    );
    assert!(query_hits(&w, "Ownable").has_import("Ownable"));
    // Selective `{X as Y} from "src"` form: alias resolves via the
    // module path's tail and the alias text both surface.
    assert!(query_hits(&w, "safe.sol").has_import("safe"));
}

#[test]
fn regex_query_on_solidity_decls() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             contract A {\n\
               function runAdminCommand() public {}\n\
               function runUserCommand() public {}\n\
               function handle() public {}\n\
             }\n",
        )],
    );
    let h = query_hits_regex(&w, "^run[A-Z].*Command$");
    assert!(h.has_decl("runAdminCommand"));
    assert!(h.has_decl("runUserCommand"));
}

#[test]
fn inspect_filter_from_to_through_branches() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/a.sol",
            "pragma solidity ^0.8.0;\n\
             contract A {\n\
               function entry(uint256 c) public {\n\
                 if (c > 0) { happy(); } else { recover(); }\n\
               }\n\
               function happy() internal { sink(); }\n\
               function recover() internal { sink(); }\n\
               function sink() internal {}\n\
             }\n",
        )],
    );
    for via in ["happy", "recover"] {
        assert_filters_keep(
            &w,
            "sink",
            "sink",
            InspectFilters {
                from: Some(via),
                to: Some("sink"),
                ..Default::default()
            },
        );
    }
}

#[test]
fn solidity_fuzzy_from_across_node_types() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/h.sol",
            "pragma solidity ^0.8.0;\n\
             contract H {\n\
               function process(bytes32 s) internal {}\n\
               function handleRequest(bytes32 q) public {\n\
                 bytes32 requestUrl = \"/api/request\";\n\
                 process(requestUrl);\n\
               }\n\
             }\n",
        )],
    );
    assert_function_named(&w, "handleRequest");
    assert_function_named(&w, "process");
    assert_fuzzy_substring("handleRequest", "req");
    assert_fuzzy_substring("handleRequest", "REQUEST");
    assert_hit_text_match("/api/request", "req");
}

#[test]
fn solidity_filter_rejects_unrelated_hits() {
    let w = ws_multi(
        sol(),
        &[(
            "/w/m.sol",
            "pragma solidity ^0.8.0;\n\
             contract M { function entry() public { require(true); } }\n",
        )],
    );
    assert_function_named(&w, "entry");
    assert_filter_rejects_unrelated(&w, "entry", "require", "nowhere", "nothere");
}
