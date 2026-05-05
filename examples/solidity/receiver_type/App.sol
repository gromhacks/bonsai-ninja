// Receiver-type audit fixture (Solidity).
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract App {
    function handle() external {
        // POSITIVE: instance address.delegatecall — receiver-type
        // resolution required to know `target` is `address`.
        address target = address(uint160(block.timestamp));
        target.delegatecall("");
    }
}
