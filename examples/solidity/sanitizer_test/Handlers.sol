// SPDX-License-Identifier: MIT
// Solidity sanitizer-fixture — parallel handlers exercising
// privileged sinks with/without the canonical guards (require /
// onlyOwner / nonReentrant).
pragma solidity ^0.8.0;

interface IToken {
    function mint(address to, uint256 amount) external;
    function burn(address from, uint256 amount) external;
    function transferOwnership(address newOwner) external;
}

contract Handlers {
    address public owner;
    IToken public token;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(address t) {
        owner = msg.sender;
        token = IToken(t);
    }

    // --- Privileged external calls (RAW) -------------------------------

    function mintRaw(address to, uint256 amount) external {
        token.mint(to, amount);
    }

    function burnRaw(address from, uint256 amount) external {
        token.burn(from, amount);
    }

    function transferOwnershipRaw(address newOwner) external {
        token.transferOwnership(newOwner);
    }

    function selfdestructRaw(address payable dest) external {
        selfdestruct(dest);
    }

    // --- Same sinks with onlyOwner + require (SAFE) --------------------

    function mintSafe(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero addr");
        token.mint(to, amount);
    }

    function burnSafe(address from, uint256 amount) external onlyOwner {
        require(amount > 0, "zero amount");
        token.burn(from, amount);
    }

    function transferOwnershipSafe(address newOwner) external onlyOwner {
        require(newOwner != address(0), "zero addr");
        token.transferOwnership(newOwner);
    }

    function selfdestructSafe(address payable dest) external onlyOwner {
        require(dest != address(0), "zero addr");
        selfdestruct(dest);
    }
}
