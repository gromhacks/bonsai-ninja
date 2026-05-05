// Assignment-chain audit fixture (Solidity).
// Solidity flow model is state-mutation rather than command-injection.
// Source: block.timestamp (block-context, attacker-influenceable).
// Sink: delegatecall(...) — tainted target == arbitrary takeover.
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract App {
    address constant CONST_OK = address(0xdead);
    address[] public targets;

    function passthrough(address x) internal pure returns (address) {
        return x;
    }

    function chainSimple() public {
        // POSITIVE: timestamp-derived target into delegatecall.
        address t = address(uint160(block.timestamp));
        t.delegatecall("");
    }

    function chainMultiHop() public {
        // POSITIVE: multi-hop chain.
        address t1 = address(uint160(block.timestamp));
        address t2 = passthrough(t1);
        address t3 = passthrough(t2);
        t3.delegatecall("");
    }

    function chainBranchJoin(bool cond) public {
        // POSITIVE: tainted leg fires; clean leg is twin.
        address t;
        if (cond) {
            t = address(uint160(block.timestamp));
        } else {
            t = CONST_OK;
        }
        t.delegatecall("");
    }

    function chainLoopCarried(uint256 n) public {
        // POSITIVE: loop-carried target.
        address t = address(uint160(block.timestamp));
        for (uint256 i = 0; i < n; i++) {
            t = passthrough(t);
        }
        t.delegatecall("");
    }

    function chainFieldWrite(uint256 idx) public {
        // POSITIVE: state-write then state-read into sink.
        targets.push(address(uint160(block.timestamp)));
        address t = targets[idx];
        t.delegatecall("");
    }

    function chainCleanConstant() public {
        // NEGATIVE: timestamp read, sink uses constant.
        uint256 _unused = block.timestamp;
        CONST_OK.delegatecall("");
    }
}
