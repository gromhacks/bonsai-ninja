// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Language-specific syntax audit (Solidity).
// Tests delegatecall on a tainted address — the source is
// block.timestamp (proposer-influenceable). The sink shape is
// `<addr>.delegatecall(data)`, which solidity tree-sitter parses
// as a member-method call on `addr`.
contract App {
    function handle() external {
        // POSITIVE: timestamp-derived target into delegatecall.
        address t = address(uint160(block.timestamp));
        t.delegatecall("");
    }
}
