// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/hash/PoseidonHashLib.sol";
import "./crypto/hash/MiMC7.sol";

contract PoseidonHasher {
    function hashPoseidonTwoToOne(uint256 x, uint256 y) public pure returns (uint256) {
        return PoseidonHashLib._hash(x, y);
    }

    function hashPoseidonSingle(uint256 x) public pure returns (uint256) {
        return PoseidonHashLib._hash(x, 0);
    }

    function hashKeccak(uint256 x, uint256 y) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(x, y)));
    }

    function hashMiMC7(uint256 x, uint256 y) public pure returns (uint256) {
        return uint256(MiMC7._hash(bytes32(x), bytes32(y)));
    }
}
