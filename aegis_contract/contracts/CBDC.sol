// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./crypto/utils/Bn128.sol";
import "./crypto/utils/BaseMerkleTree.sol";
import "./crypto/groth16/Groth16AltBN128.sol";
import "./crypto/hash/PoseidonLib.sol";
import "./crypto/hash/ArkConstants.sol";
import "hardhat/console.sol";

contract CBDC is BaseMerkleTree {
    enum TransactionType {
        Register,
        Send,
        Exchange,
        Receive
    }

    uint256[] public register_vk;
    uint256[] public send_vk;
    uint256[] public receive_vk;
    uint256[] public exchange_vk;

    uint256[] public list_rt;
    uint256[] public list_sn;
    uint256[] public list_cm;
    uint256[] public list_addr_d;
    mapping(uint256 => Bn128.G1Point) public list_cm_d;

    Bn128.G1Point public apk;
    Bn128.G1Point[] public ck;

    uint256 public fullRounds;
    uint256 public partialRounds;
    uint256 public alpha;
    uint256[3][3] public mds;
    uint256[][] public ark;

    constructor(
        uint256 _depth,
        uint256[] memory _register_vk,
        uint256[] memory _send_vk,
        uint256[] memory _receive_vk,
        uint256[] memory _exchange_vk,
        uint256[] memory _apk,
        uint256[] memory _ck
    ) initializer {
        __BaseMerkleTree_init(_depth);
        register_vk = _register_vk;
        send_vk = _send_vk;
        receive_vk = _receive_vk;
        exchange_vk = _exchange_vk;
        apk = Bn128.G1Point(_apk[0], _apk[1]);
        ck.push(Bn128.G1Point(_ck[0], _ck[1]));
        ck.push(Bn128.G1Point(_ck[2], _ck[3]));
        fullRounds = ArkConstants.getFullRounds();
        partialRounds = ArkConstants.getPartialRounds();
        alpha = ArkConstants.getAlpha();
        mds = ArkConstants.getMds();
        ark = ArkConstants.getArk();
    }

    function _hash(
        bytes32 left,
        bytes32 right
    ) internal view override returns (bytes32) {
        uint256[2] memory inputs;
        inputs[0] = uint256(left);
        inputs[1] = uint256(right);
        return bytes32(PoseidonLib._hashTwoToOne(inputs, mds, ark, alpha, fullRounds, partialRounds));
    }

    function _verify(
        uint256[] storage vk,
        uint256[] memory proof,
        uint256[] memory input
    ) internal returns (bool) {
        return Groth16AltBN128._verify(vk, proof, input);
        // return true;
    }

    function _isin(
        uint256[] storage list,
        uint256 value
    ) internal view returns (bool) {
        for (uint256 i = 0; i < list.length; i++) {
            if (list[i] == value) {
                return true;
            }
        }
        return false;
    }

    function isin_list_rt(uint256 root) public view returns (bool) {
        return _isin(list_rt, root);
    }

    function isin_list_sn(uint256 sn) public view returns (bool) {
        return _isin(list_sn, sn);
    }

    function isin_list_cm(uint256 cm) public view returns (bool) {
        return _isin(list_cm, cm);
    }

    function isin_list_addr_d(uint256 addr_d) public view returns (bool) {
        return _isin(list_addr_d, addr_d);
    }

    function insert_cm(uint256 cm) public returns (uint256) {
        list_cm.push(cm);
        _insert(bytes32(cm));
        bytes32 root = _recomputeRoot(1);
        list_rt.push(uint256(root));
        return uint256(root);
    }

    function insert_cm_new_cm_v(
        uint256 cm_new,
        uint256 cm_v
    ) internal returns (uint256) {
        list_cm.push(cm_new);
        list_cm.push(cm_v);
        _insert(bytes32(cm_new));
        _insert(bytes32(cm_v));
        bytes32 root = _recomputeRoot(2);
        return uint256(root);
    }

    function insert_two_element(uint256 cm1, uint256 cm2) public returns (uint256) {
        list_cm.push(cm1);
        list_cm.push(cm2);
        _insert_two_element(bytes32(cm1), bytes32(cm2));
        bytes32 root = _recomputeRoot(1);
        list_rt.push(uint256(root));
        return uint256(root);
    }

    function get_roots() public view returns (uint256[] memory) {
        return list_rt;
    }

    function get_num_leaves() public view returns (uint256) {
        return _get_num_leaves();
    }

    function compute_tag(uint256[] memory ct) internal view returns (uint256) {
        bytes32 _tag = bytes32(ct[0]);
        for (uint256 i = 1; i < ct.length; i++) {
            _tag = _hash(_tag, bytes32(ct[i]));
        }
        return uint256(_tag);
    }

    function insert_rt(uint256 root) public {
        list_rt.push(root);
    }

    function insert_sn(uint256 sn) public {
        list_sn.push(sn);
    }

    function register(uint256 cm, uint256[] memory ct_bar, uint256[] memory ct_key, uint256[] memory proof) external {
        require(isin_list_cm(cm), "cm is already in the list_cm");

        uint256[] memory input = new uint256[](ct_bar.length + ct_key.length + 3);
        input[0] = cm;
        for (uint256 i = 0; i < ct_bar.length; i++) {
            input[i + 1] = ct_bar[i];
        }
        input[8] = apk.X;
        input[9] = apk.Y;
        for (uint256 i = 0; i < ct_key.length; i++) {
            input[i + 3 + ct_bar.length] = ct_key[i];
        }
        require(_verify(register_vk, proof, input), "Invalid proof");
        uint256 rt = insert_cm(cm);
        list_rt.push(rt);
    }

    function send(
        uint256 root,
        uint256 sn_cur,
        uint256 cm_new,
        uint256 cm_v,
        uint256[] memory ct_bar,
        uint256[] memory ct_key,
        uint256[] memory ct,
        uint256 auth,
        uint256[] memory proof
    ) external {
        require(isin_list_rt(root), "root is not in the list_rt");
        require(isin_list_sn(sn_cur), "sn_cur is in the list_sn");
        require(isin_list_cm(cm_v), "cm_v is in the list_cm");

        uint256 tag = compute_tag(ct);

        uint256[] memory input = new uint256[](8 + ct_bar.length + ct_key.length);

        input[0] = sn_cur;
        input[1] = cm_new;
        input[2] = cm_v;
        input[3] = root;
        input[4] = tag;
        input[5] = auth;
        input[6] = apk.X;
        input[7] = apk.Y;
        for (uint256 i = 0; i < ct_bar.length; i++) {
            input[i + 8] = ct_bar[i];
        }
        for (uint256 i = 0; i < ct_key.length; i++) {
            input[i + 8 + ct_bar.length] = ct_key[i];
        }

        require(_verify(send_vk, proof, input), "Invalid proof");

        uint256 new_root = insert_cm_new_cm_v(cm_new, cm_v);
        list_rt.push(new_root);
        list_sn.push(sn_cur);
    }

    function receive(
        uint256 sn_v,
        uint256 sn_cur,
        uint256 cm_new,
        uint256 root,
        uint256[] memory ct_key,
        uint256[] memory ct,
        uint256[] memory proof
    ) external {
        require(isin_list_rt(root), "root is not in the list_rt");
        require(isin_list_sn(sn_cur), "sn_cur is in the list_sn");
        require(isin_list_sn(sn_v), "sn_v is in the list_sn");
        require(isin_list_cm(cm_new), "cm_new is in the list_cm");

        uint256[] memory input = new uint256[](6 + ct_key.length  + ct.length);

        input[0] = apk.X;
        input[1] = apk.Y;
        input[2] = sn_v;
        input[3] = sn_cur;
        input[4] = cm_new;
        input[5] = root;
        for (uint256 i = 0; i < ct_key.length; i++) {
            input[i + 6] = ct_key[i];
        }
        for (uint256 i = 0; i < ct.length; i++) {
            input[i + 6 + ct_key.length] = ct[i];
        }


        require(_verify(receive_vk, proof, input), "Invalid proof");

        uint256 new_root = insert_cm(cm_new);
        list_rt.push(new_root);
        list_sn.push(sn_cur);
        list_sn.push(sn_v);
    }

    function exchange(
        uint256 root,
        uint256 addr_d,
        uint256 sn_cur,
        uint256 cm_new,
        Bn128.G1Point memory cm_new_d,
        Bn128.G1Point memory cm_v_d,
        uint256[] memory ct_bar,
        uint256[] memory ct_key,
        uint256[] memory proof
    ) external {
        require(isin_list_addr_d(addr_d), "addr_d is not in the list_cm_d");
        require(isin_list_rt(root), "root is not in the list_rt");
        require(isin_list_sn(sn_cur), "sn_cur is not in the list_sn");
        require(isin_list_cm(cm_new), "cm_new is not in the list_cm");

        uint256[] memory input = new uint256[](
            ct_bar.length + ct_key.length + 14
        );
        input[0] = root;
        input[1] = ck[0].X;
        input[2] = ck[0].Y;
        input[3] = ck[1].X;
        input[4] = ck[1].Y;
        input[5] = addr_d;
        input[6] = sn_cur;
        input[7] = cm_new;
        input[8] = cm_new_d.X;
        input[9] = cm_new_d.Y;
        input[10] = cm_v_d.X;
        input[11] = cm_v_d.Y;
        for (uint256 i = 0; i < ct_bar.length; i++) {
            input[i + 12] = ct_bar[i];
        }
        input[18] = apk.X;
        input[19] = apk.Y;
        for (uint256 i = 0; i < ct_key.length; i++) {
            input[i + 20] = ct_key[i];
        }

        require(_verify(exchange_vk, proof, input), "Invalid proof");
        uint256 new_root = insert_cm(cm_new);
        list_rt.push(new_root);
        list_sn.push(sn_cur);
        // list_cm_d[addr_d] = Bn128.add(list_cm_d[addr_d], cm_v_d);
        list_cm_d[addr_d] = cm_new_d;
    }

    function register_addr_d(uint256 addr_d, uint256[] memory _cm_d) public {
        list_addr_d.push(addr_d);
        Bn128.G1Point memory cm_d = Bn128.G1Point(_cm_d[0], _cm_d[1]);
        list_cm_d[addr_d] = cm_d;
    }

    function get_cm_d(uint256 addr_d) public view returns (uint256, uint256) {
        return (list_cm_d[addr_d].X, list_cm_d[addr_d].Y);
    }
}
