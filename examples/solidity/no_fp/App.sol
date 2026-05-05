// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract App {
    address constant CONST_OK = address(0xdead);
    function decoy() external {
        uint256 _unused = block.timestamp;
        CONST_OK.delegatecall("");
    }
    function unrelatedChain() external pure returns (uint256) {
        uint256 a = 1;
        return a + 1;
    }
}
