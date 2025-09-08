// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "./crypto/groth16/ccGroth16VerifyBn128.sol";
import "./crypto/utils/Bn128.sol";
import './crypto/utils/BatchBn128.sol';
import "hardhat/console.sol";


contract Aegis is AccessControl {
    bytes32 public constant VALIDATOR_ROLE = keccak256("VALIDATOR_ROLE");

    // set user balance using cm
    mapping(address => Bn128.G1Point) public _CMList;

    // rawTx struct except proof
    struct TradeData {
        address[] userAddress;
        address[] contractAddress;
        Bn128.G1Point[] deltaCm;
    }

    // vrs
    struct vrs {
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    // event setCMList
    event CMListInitialized(address userAddress, uint256 x, uint256 y);
    event SignitureValid(address indexed signer);

    uint256[] vk;
    uint256[] dbt_ck;
    uint256 batch_size;

    constructor(
        uint256[] memory _vk,
        uint256[] memory _ck,
        uint256 _batch_size
    ) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // CHECK : change msg.sender to address(this)
        _grantRole(VALIDATOR_ROLE, msg.sender);

        // check vk length
        require(_vk.length == 18, "vk length is failed");
        require(
            _ck.length == 0 || _ck.length == 4,
            "Invalid Committing Key Size"
        );
        vk = _vk;
        dbt_ck = _ck;
        batch_size = _batch_size;
    }

    function grantValidatorRole(
        address contractAddress
    ) public onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(VALIDATOR_ROLE, contractAddress);
    }

    function setCM(
        address userAddress,
        Bn128.G1Point calldata cm
    ) public onlyRole(VALIDATOR_ROLE) {
        uint256 slot;
        uint256 x = cm.X;
        uint256 y = cm.Y;

        assembly {
            slot := _CMList.slot
        }

        bytes32 location = keccak256(abi.encode(userAddress, uint256(slot)));

        assembly {
            sstore(add(location, 0), x)
            sstore(add(location, 1), y)
        }

        emit CMListInitialized(userAddress, cm.X, cm.Y);
    }

    function getCM(
        address userAddress
    ) external view returns (Bn128.G1Point memory) {
        uint256 slot;
        uint256 x;
        uint256 y;

        assembly {
            slot := _CMList.slot
        }

        bytes32 location = keccak256(abi.encode(userAddress, uint256(slot)));

        assembly {
            x := sload(add(location, 0))
            y := sload(add(location, 1))
        }

        return Bn128.G1Point(x, y);
    }

    function concatCMList(
        Bn128.G1Point[] memory deltaCm,
        Bn128.G1Point[] memory updatedCMList
    ) public pure returns (Bn128.G1Point[] memory) {
        uint256 len = deltaCm.length;
        Bn128.G1Point[] memory arr = new Bn128.G1Point[](len * 2);

        assembly {
            for {
                let i := 1
            } lt(i, add(len, 1)) {
                i := add(i, 1)
            } {
                mstore(add(arr, mul(i, 32)), mload(add(deltaCm, mul(i, 32))))
                mstore(add(arr, mul(i, 32)), mload(add(deltaCm, mul(i, 32))))
            }

            for {
                let i := 1
            } lt(i, add(len, 1)) {
                i := add(i, 1)
            } {
                let j := add(len, i)

                mstore(
                    add(arr, mul(j, 32)),
                    mload(add(updatedCMList, mul(i, 32)))
                )
                mstore(
                    add(arr, mul(j, 32)),
                    mload(add(updatedCMList, mul(i, 32)))
                )
            }
        }

        return arr;
    }

    function verify(
        uint256[] memory proof,
        TradeData calldata txs
    ) public onlyRole(VALIDATOR_ROLE) returns (bool) {
        require(proof.length == 10, "proof length is failed");

        uint256[2] memory d = [proof[8], proof[9]];

        // find exist (address => cm) and add delta cmlist
        Bn128.G1Point[] memory updatedCMList = new Bn128.G1Point[](batch_size);

        for (uint32 i = 0; i < batch_size; i++) {
            address userAddress = txs.userAddress[i];
            Bn128.G1Point memory cm = _CMList[userAddress]; // prev
            updatedCMList[i] = Bn128.add(cm, txs.deltaCm[i]); // prev + delta = cur
        }

        // updatedCMList follows deltacm // length = 2 * batch_size
        Bn128.G1Point[] memory concatedCMList = concatCMList(
            updatedCMList, // cur
            txs.deltaCm // delta
        );

        // concatedCMList to uint256[]
        uint256[] memory commitments = new uint256[](batch_size * 4);
        for (uint32 i = 0; i < batch_size * 2; i+=1) {
            commitments[2*i] = concatedCMList[i].X;
            commitments[2*i + 1] = concatedCMList[i].Y;
        }

        BatchBn128.Interval[] memory intervals = new BatchBn128.Interval[](1);
        intervals[0] = BatchBn128.Interval({ begin: batch_size, end: batch_size * 2});

        uint256[] memory input = new uint256[](0);

        uint256 tau = BatchBn128._retrieveTau(
        input,
        commitments,
        intervals,
        d
        );

        d = BatchBn128._updateProofD(dbt_ck, input, commitments, d, tau);
        proof[8] = d[0];
        proof[9] = d[1];

        uint256[] memory inputs = new uint256[](1);
        inputs[0] = tau;
        require(ccGroth16VerifyBn128._verify(vk, inputs, proof), "verify is failed");

        return true;
    }

    function checkSignature(
        vrs[] calldata _vrs,
        uint256[] calldata proofs,
        TradeData calldata txs
    ) public onlyRole(VALIDATOR_ROLE) returns (bool) {
        uint256 len = _vrs.length;
        // REMOVE : check whether sig length is equal to participated bank or not
        // require(true, 'ABank: invalid signiture count');

        bytes32 signedDataHash = keccak256(abi.encode(proofs, txs));

        bytes32 _hash = MessageHashUtils.toEthSignedMessageHash(
            signedDataHash
        );
        for (uint32 i = 0; i < len; i++) {

            address signer = ECDSA.recover(
                _hash,
                _vrs[i].v,
                _vrs[i].r,
                _vrs[i].s
            );

            require(hasRole(VALIDATOR_ROLE, signer), "ABank: invalid sig");
            emit SignitureValid(signer);
        }

        return true;
    }

    // check signiture and update cmlist of every bank cmlist
    function updateCommitment(
        vrs[] calldata _vrs,
        uint256[] calldata proofs,
        TradeData calldata txs
    ) public onlyRole(VALIDATOR_ROLE) returns (bool) {
        require(
            txs.deltaCm.length == batch_size,
            "ABank: txs length is failed"
        );

        // verify sign
        checkSignature(_vrs, proofs, txs);

        require(verify(proofs, txs), "ccGroth16 is failed");

        // after check all sig valid, update cm
        for (uint32 i = 0; i < batch_size; i++) {
            bool success;
            address contractAddress = txs.contractAddress[i];

            (success, ) = contractAddress.call(
                abi.encodeWithSignature(
                    "mint(address,(uint256,uint256))",
                    txs.userAddress[i],
                    txs.deltaCm[i]
                )
            );
            require(success, "ABank: cmlist not updated");
        }

        return true;
    }

    // allow other validated bank update cmlist
    function mint(
        address userAddress,
        Bn128.G1Point calldata deltaCm
    ) public onlyRole(VALIDATOR_ROLE) {
        require(
            _CMList[userAddress].X != 0 && _CMList[userAddress].Y != 0,
            "ABank: customer address is not exist"
        );

        _CMList[userAddress] = Bn128.add(_CMList[userAddress], deltaCm);
    }

    function bn_add(Bn128.G1Point memory a,Bn128.G1Point memory b) public view returns (Bn128.G1Point memory) {
        return Bn128.add(a, b);
    }
}