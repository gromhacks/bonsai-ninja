// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Storage {
    address public target;
    mapping(bytes => bool) public seen;

    constructor(address t) {
        target = t;
    }

    function persist(bytes calldata cmd) external {
        // SINK — low-level .call(raw) · solidity.reentrancy.low_level_call · CWE-284/841
        (bool ok, ) = target.call(cmd);
        require(ok, "call failed");
        seen[cmd] = true;
    }

    function cleanTwin() external {
        // NEGATIVE — same sink kind with a constant argument must not report.
        (bool ok, ) = target.call(hex"");
        require(ok, "clean failed");
    }
}
