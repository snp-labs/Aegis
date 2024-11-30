// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/hash/PoseidonLib.sol";
import "./crypto/hash/ArkConstants.sol";

contract PoseidonHasher {
    uint256 public fullRounds;
    uint256 public partialRounds;
    uint256 public alpha;
    uint256[3][3] public mds;
    uint256[][] public ark;

    constructor() {
        fullRounds = ArkConstants.getFullRounds();
        partialRounds = ArkConstants.getPartialRounds();
        alpha = ArkConstants.getAlpha();
        mds = ArkConstants.getMds();
        ark = ArkConstants.getArk();
    }

    function hash(uint256[] memory inputs) public view returns (uint256) {
        return PoseidonLib._hash(inputs, mds, ark, alpha, fullRounds, partialRounds);
    }
}
