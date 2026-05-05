// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Advanced {
    mapping(address => uint256) balances;
    address owner;
    bool paused;

    event AdminAction(address indexed who, bytes32 what);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    modifier whenNotPaused() {
        require(!paused, "paused");
        _;
    }

    function findBalance(address user) public view returns (uint256) {
        if (balances[user] > 0) {
            return balances[user];
        }
        return 0;
    }

    function loadAll(address[] calldata users) external onlyOwner {
        for (uint256 i = 0; i < users.length; i++) {
            balances[users[i]] = 100;
        }
    }

    function dispatchToken(bytes32 token) internal {
        if (token == bytes32(0)) {
            return;
        }
        if (token[0] == bytes1("a")) {
            runAdmin(token);
        } else {
            runUser(token);
        }
    }

    function processBatch(bytes32[] calldata tokens) external whenNotPaused {
        for (uint256 i = 0; i < tokens.length; i++) {
            dispatchToken(tokens[i]);
        }
    }

    function runAdmin(bytes32 token) internal onlyOwner {
        emit AdminAction(msg.sender, token);
    }

    function runUser(bytes32 token) internal {
        emit AdminAction(msg.sender, token);
    }
}
