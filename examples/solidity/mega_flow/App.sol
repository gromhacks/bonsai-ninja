// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

// mega_flow Solidity entry — msg.data is the tainted SOURCE (external
// call data), threaded through a pipeline that exercises every
// idiomatic Solidity flow construct (inheritance, modifiers, events,
// structs, enums, mappings, payable fns, try/catch, unchecked blocks).

import {Pipeline as FlowPipeline} from "./Pipeline.sol";

abstract contract Auditable {
    event Audited(address indexed user, uint256 indexed length);

    modifier audit(bytes calldata data) {
        emit Audited(msg.sender, data.length);
        _;
    }
}

contract App is Auditable {
    enum Kind { Run, Eval }

    struct Envelope {
        Kind kind;
        bytes cmd;
        address user;
        uint256 length;
    }

    FlowPipeline pipeline;

    constructor(address pipelineAddr) {
        pipeline = FlowPipeline(pipelineAddr);
    }

    // SOURCE — external call data.
    function handle(bytes calldata raw) external payable audit(raw) {
        Envelope memory envelope = Envelope({
            kind: Kind.Run,
            cmd: raw,
            user: msg.sender,
            length: raw.length
        });
        pipeline.orchestrate(envelope.cmd, uint8(envelope.kind));
    }
}
