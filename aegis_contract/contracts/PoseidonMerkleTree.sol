// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.0;

// import "./crypto/utils/BaseMerkleTree.sol";
// import "./crypto/hash/PoseidonLib.sol";
// import "./crypto/hash/ArkConstants.sol";

// contract PoseidonMerkleTree is BaseMerkleTree {
//     uint256 public fullRounds;
//     uint256 public partialRounds;
//     uint256 public alpha;
//     uint256[3][3] public mds;
//     uint256[3][] public ark;

//     constructor(uint256 _depth) initializer {
//         fullRounds = ArkConstants.getFullRounds();
//         partialRounds = ArkConstants.getPartialRounds();
//         alpha = ArkConstants.getAlpha();
//         mds = ArkConstants.getMds();
//         ark = ArkConstants.getArk();
//         __BaseMerkleTree_init(_depth);
//     }

//    function _hash(
//         bytes32 left,
//         bytes32 right
//     ) internal view override returns (bytes32) {
//         uint256[2] memory inputs;
//         inputs[0] = uint256(left);
//         inputs[1] = uint256(right);
//         return bytes32(PoseidonLib._hashTwoToOne(inputs, mds, ark, alpha, fullRounds, partialRounds));
//     }

//     function insert_cm(uint256 cm) public returns (uint256) {
//         _insert(bytes32(cm));
//         bytes32 root = _recomputeRoot(1);
//         return uint256(root);
//     }

//     function insert_two_element(uint256 cm1, uint256 cm2) public returns (uint256) {
//         _insert_two_element(bytes32(cm1), bytes32(cm2));
//         bytes32 root = _recomputeRoot(1);
//         return uint256(root);
//     }

//     function convertUintToBytes(uint256 u) public pure returns (bytes32) {
//         return bytes32(u);
//     }

//     function getRoot() public view returns (bytes32) {
//         return _get_root();
//     }
// }