// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract RWA {
    uint256 public totalAssets;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function mint(address to, uint256 amount) public {
        require(msg.sender == owner, "Not authorized");
        totalAssets += amount;
    }

    function transferAsset(address to, uint256 amount) public {
        require(msg.sender == owner, "Not authorized");
        require(totalAssets >= amount, "Insufficient assets");
        totalAssets -= amount;
    }
}

