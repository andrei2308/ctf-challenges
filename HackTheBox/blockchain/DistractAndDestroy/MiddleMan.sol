// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

contract Middleman {
    address public target = 0xffffffffffffffffffffffffffffff; // replace with actual contract address

    function attack(uint256 _damage) external {
        (bool success, bytes memory result) = target.call(abi.encodeWithSignature("attack(uint256)", _damage));
        require(success, string(result));
    }
}