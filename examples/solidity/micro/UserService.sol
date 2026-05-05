// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./AuthService.sol";

contract UserService {
    AuthService auth;

    constructor(address authAddr) {
        auth = AuthService(authAddr);
    }

    function getUser(bytes32 token) public returns (uint256) {
        return auth.verifyToken(token);
    }

    function updateUser(bytes32 token, bytes32 action) public returns (bool) {
        uint256 userId = auth.verifyToken(token);
        if (userId > 0) {
            return auth.runAdminCommand(userId, action);
        }
        return false;
    }
}
