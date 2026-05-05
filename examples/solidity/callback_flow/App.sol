// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract App {
    function execute(address t) external {
        t.delegatecall("");
    }
    function run_cb(function(address) external cb, address value) internal {
        cb(value);
    }
    function pass_to_callback() external {
        address t = address(uint160(block.timestamp));
        run_cb(this.execute, t);
    }
}
