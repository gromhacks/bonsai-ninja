// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Executor {
    function execute(address cmd) external {
        // POSITIVE (terminal cross-file sink)
        cmd.delegatecall("");
    }
}
