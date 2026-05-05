// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract App {
    address constant CONST_OK = address(0xdead);
    function taintOneLeg(bool cond) external {
        address t;
        if (cond) { t = address(uint160(block.timestamp)); }
        else { t = CONST_OK; }
        t.delegatecall("");
    }
    function taintOverwritten(bool cond) external {
        address t = address(uint160(block.timestamp));
        if (cond) { t = CONST_OK; }
        else { t = CONST_OK; }
        t.delegatecall("");
    }
}
