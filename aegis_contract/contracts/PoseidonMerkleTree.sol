// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/utils/BaseMerkleTree.sol";
import "./crypto/hash/PoseidonHashLib.sol";

contract PoseidonMerkleTree is BaseMerkleTree {
    constructor(uint256 _depth) initializer {
        __BaseMerkleTree_init(_depth);
    }

   function _hash(
        bytes32 left,
        bytes32 right
    ) internal pure override returns (bytes32) {
        return bytes32(PoseidonHashLib._hash(uint256(left), uint256(right)));
    }

    function insert_cm(uint256 cm) public returns (uint256) {
        _insert(bytes32(cm));
        bytes32 root = _recomputeRoot(1);
        return uint256(root);
    }

    function insert_two_element(uint256 cm1, uint256 cm2) public returns (uint256) {
        _insert_two_element(bytes32(cm1), bytes32(cm2));
        bytes32 root = _recomputeRoot(1);
        return uint256(root);
    }

    function convertUintToBytes(uint256 u) public pure returns (bytes32) {
        return bytes32(u);
    }

    function getRoot() public view returns (bytes32) {
        return _get_root();
    }
}