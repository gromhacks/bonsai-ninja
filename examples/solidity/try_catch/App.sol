// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface I { function get() external returns (address); }
contract App {
    address t;
    function taintedThroughTry(I target) external {
        try target.get() returns (address r) {
            t = r;
        } catch {
            t = address(0xdead);
        }
        t.delegatecall("");
    }
}
