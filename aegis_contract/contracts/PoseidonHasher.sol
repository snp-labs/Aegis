// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/hash/PoseidonLib.sol";
import "./crypto/hash/PoseidonAsmLib.sol";
import "./crypto/hash/ArkConstants.sol";
import "./crypto/hash/MiMC7.sol";

contract PoseidonHasher {
    uint256 public fullRounds;
    uint256 public partialRounds;
    uint256 public alpha;
    uint256[3][3] public mds;
    uint256[3][] public ark;

    constructor() {
        fullRounds = ArkConstants.getFullRounds();
        partialRounds = ArkConstants.getPartialRounds();
        alpha = ArkConstants.getAlpha();
        mds = ArkConstants.getMds();
        ark = ArkConstants.getArk();
    }

    uint256[] digest_list;

    function hash(uint256[] memory inputs) public returns (uint256) {
        uint256 digest;
        for(uint i = 0; i < 1; i++) {
            digest = PoseidonLib._hash(inputs, mds, ark, alpha, fullRounds, partialRounds);
            digest_list.push(digest);
        }
        return digest;
    }

    function hashAsm(uint256[] memory inputs) public returns (uint256) {
        uint256 digest;
        for(uint i = 0; i < 1; i++) {
            digest = PoseidonAsmLib._hash(inputs, mds, ark, alpha, fullRounds, partialRounds);
            digest_list.push(digest);
        }
        return digest;
    }

    function hashKeccak(uint256[] memory input) public returns (uint256) {
        uint256 digest;
        for(uint i = 0; i < 1; i++) {
            digest = uint256(keccak256(abi.encodePacked(input)));
            digest_list.push(digest);
        }
        return digest;
    }

    function hashMiMC7(uint256[] memory input) public returns (uint256) {
        uint256 digest;
        for(uint i = 0; i < 1; i++) {
            digest = uint256(MiMC7._hash(bytes32(input[0]), bytes32(input[0])));
            digest_list.push(digest);
        }
        return digest;
    }
}
