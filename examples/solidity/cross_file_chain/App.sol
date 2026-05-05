// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Pipeline.sol";

contract App {
    Pipeline public pipeline;

    constructor(address p) {
        pipeline = Pipeline(p);
    }

    function handler() external {
        // POSITIVE: source = block.timestamp; sink three contracts away.
        address t = address(uint160(block.timestamp));
        pipeline.runPipeline(t);
    }
}
