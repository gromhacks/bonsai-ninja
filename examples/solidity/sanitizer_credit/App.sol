// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract App {
    address constant SAFE = address(0xdead);
    function unsanitized() external {
        address t = address(uint160(block.timestamp));
        t.delegatecall("");
    }
    function sanitized(address t) external {
        // require() acts as the canonical solidity sanitizer.
        require(t == SAFE, "not allowed");
        t.delegatecall("");
    }
}
