// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/hash/PoseidonHashLib.sol";
import "./crypto/hash/MiMC7.sol";

contract PoseidonHasher {
    function hashPoseidon(uint256[] memory input) public pure returns (uint256) {
        return PoseidonHashLib._hash(input);
    }

    function hashKeccak(uint256[] memory input) public pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(input)));
    }

    function hashMiMC7(uint256[] memory input) public pure returns (uint256) {
        return uint256(MiMC7._hash(bytes32(input[0]), bytes32(input[0])));
    }
}
