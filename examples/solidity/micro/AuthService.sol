// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuthService {
    address owner;
    mapping(address => uint256) balances;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    function verifyToken(bytes32 token) public pure returns (uint256) {
        // sink: token is used without validation as lookup key
        bytes32 t = token;
        if (t == bytes32(0)) {
            return 0;
        }
        return 1;
    }

    function runAdminCommand(uint256 userId, bytes32 action) public returns (bool) {
        // sink: privileged action triggered by untrusted action parameter
        require(userId > 0, "bad user");
        balances[msg.sender] = userId;
        emit Action(userId, action);
        return true;
    }

    event Action(uint256 indexed userId, bytes32 indexed action);
}
