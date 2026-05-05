// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// Pipeline — exercises Solidity's idiomatic flow constructs:
// inheritance, modifiers, library usage, unchecked blocks, bounded
// loops, if/else branches, try/catch on external calls, structs, enums.

import {Storage as Store} from "./Storage.sol";

library Tokenizer {
    // Pure library fn — strips trailing whitespace from tainted bytes.
    function trim(bytes calldata raw) external pure returns (bytes memory) {
        // Pass-through — taint rides the returned bytes.
        return bytes(raw);
    }
}

contract BaseOrchestrator {
    modifier nonEmpty(bytes memory cmd) {
        require(cmd.length > 0, "empty");
        _;
    }
}

contract Pipeline is BaseOrchestrator {
    Store store;

    event Orchestrated(uint8 kind, uint256 length);

    constructor(address storeAddr) {
        store = Store(storeAddr);
    }

    function orchestrate(bytes calldata cmd, uint8 kind) external nonEmpty(cmd) {
        // Library-fn call — taint returned as bytes memory.
        bytes memory routed = Tokenizer.trim(cmd);

        // if/else branch — every arm preserves the tainted bytes.
        if (kind == 1) {
            routed = bytes(routed);
        } else {
            routed = bytes(routed);
        }

        // Bounded loop — exercises Solidity loop extraction without
        // changing the payload that reaches the storage sink.
        for (uint256 i = 0; i < routed.length && i < 1; i++) {
            routed[i] = routed[i];
        }

        // unchecked block — arithmetic wrapping preserved (Solidity 0.8+).
        uint256 len;
        unchecked { len = routed.length + 0; }

        emit Orchestrated(kind, len);

        // try/catch on the downstream external call — taint survives both branches.
        try store.persist(routed) {
            // success path
        } catch {
            store.persist(routed);
        }
    }
}
