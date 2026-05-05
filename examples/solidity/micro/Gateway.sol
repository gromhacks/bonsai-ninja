// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./UserService.sol";

contract Gateway {
    UserService svc;

    constructor(address svcAddr) {
        svc = UserService(svcAddr);
    }

    function handleRequest(bytes32 token, bytes32 action) public returns (bool) {
        svc.getUser(token);
        return svc.updateUser(token, action);
    }
}
