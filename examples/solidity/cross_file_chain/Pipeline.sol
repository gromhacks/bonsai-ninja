// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Transformer.sol";

contract Pipeline {
    Transformer public transformer;

    constructor(address t) {
        transformer = Transformer(t);
    }

    function runPipeline(address payload) external {
        transformer.transformAndForward(payload);
    }
}
