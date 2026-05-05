// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Executor.sol";

contract Transformer {
    Executor public executor;

    constructor(address e) {
        executor = Executor(e);
    }

    function transformAndForward(address value) external {
        executor.execute(value);
    }
}
