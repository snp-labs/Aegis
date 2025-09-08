// SPDX-License-Identifier: LGPL-3.0+
pragma solidity >=0.8.0;

import "./Bn128.sol";
import "hardhat/console.sol";

// Batch module for ccGroth16
library BatchBn128 {
    struct Interval {
        uint256 begin;
        uint256 end;
    }

    function _retrieveTau(
        uint256[] memory inputs,
        uint256[] memory commitments,
        Interval[] memory interval,
        uint256[2] memory d
    ) internal pure returns (uint256 tau) {
        uint256 ord = Bn128.curveOrder;
        // tau generation
        assembly {
            let transcript := mload(0x40)
            let trs := transcript

            // Load the Inputs
            for {
                let i_ptr := add(inputs, 0x20)
                let i_end := add(i_ptr, shl(0x05, mload(inputs)))
            } lt(i_ptr, i_end) {
                i_ptr := add(i_ptr, 0x20)
                trs := add(trs, 0x20)
            } {
                mstore(trs, mload(i_ptr))
            }

            // Load the Commitments
            for {
                let i_ptr := add(interval, 0x20)
                let i_end := add(i_ptr, shl(0x05, mload(interval)))
                let base := add(commitments, 0x20)
            } lt(i_ptr, i_end) {
                i_ptr := add(i_ptr, 0x20)
            } {
                let itv := mload(i_ptr)
                let begin := mload(itv)
                let end := mload(add(itv, 0x20))
                for {
                    let c_ptr := add(base, shl(0x06, begin)) // commitments.begin
                    let c_end := add(base, shl(0x06, end)) // commitments.end = commitments.begin + commitments.length * 32 (bytes)
                } lt(c_ptr, c_end) {
                    c_ptr := add(c_ptr, 0x40)
                    trs := add(trs, 0x40)
                } {
                    mstore(trs, mload(c_ptr))
                    mstore(add(trs, 0x20), mload(add(c_ptr, 0x20)))
                }
            }

            // Load Proof D
            mstore(trs, mload(d))
            mstore(add(trs, 0x20), mload(add(d, 0x20)))
            trs := add(trs, 0x40)

            // Retrieve tau
            tau := mod(keccak256(transcript, sub(trs, transcript)), ord)
        }
    }

    function _updateProofD(
        uint256[] storage ck,
        uint256[] memory inputs,
        uint256[] memory commitments,
        uint256[2] memory d,
        uint256 tau
    ) internal view returns (uint256[2] memory result) {
        bool success = true;
        uint256 ord = Bn128.curveOrder;
        uint256[5] memory io; // [sum.X, sum.Y, base.X, base.Y, scalar]
        if (ck.length == 2) {
            io[2] = ck[0];
            io[3] = ck[1];
        }
        assembly {
            // Calculate powers of tau
            let scalar := tau
            let io_mul := add(io, 0x40)

            // Aggregate the inputs
            let aggr := 0
            for {
                let ptr := add(inputs, 0x20) // inputs.begin
                let end := add(ptr, shl(0x05, mload(inputs))) // inputs.end = inputs.begin + inputs.length * 32 (bytes)
            } lt(ptr, end) {
                scalar := mulmod(scalar, tau, ord)
                ptr := add(ptr, 0x20)
            } {
                // i'th input
                let x := mload(ptr)
                if not(iszero(x)) {
                    aggr := addmod(aggr, mulmod(x, scalar, ord), ord)
                }
            }
            mstore(add(io_mul, 0x40), aggr)
            success := and(
                success,
                staticcall(gas(), 0x07, io_mul, 0x60, io, 0x40)
            )

            // Aggregate the commitments
            for {
                let ptr := add(commitments, 0x20) // commitments.begin
                let end := add(ptr, shl(0x05, mload(commitments))) // commitments.end = commitments.begin + commitments.length * 32 (bytes)
            } lt(ptr, end) {
                scalar := mulmod(scalar, tau, ord)
                ptr := add(ptr, 0x40)
            } {
                /* mul scalar */
                // Store cm.x and cm.y in memory
                mstore(io_mul, mload(ptr))
                mstore(add(io_mul, 0x20), mload(add(ptr, 0x20)))

                // Store scalar in memory
                mstore(add(io_mul, 0x40), scalar)

                // Precompiled contract ecMul (0x07)
                // base.x, base.y, scalar
                success := and(
                    success,
                    staticcall(gas(), 0x07, io_mul, 0x60, io_mul, 0x40)
                )

                // Precompiled contract ecAdd (0x06)
                // sum.x, sum.y, point.x, point.y
                success := and(
                    success,
                    staticcall(gas(), 0x06, io, 0x80, io, 0x40)
                )
            }
            // result = acc + d
            mstore(add(io, 0x40), mload(d))
            mstore(add(io, 0x60), mload(add(d, 0x20)))
            success := and(
                success,
                staticcall(gas(), 0x06, io, 0x80, result, 0x40)
            )
        }
        require(success, "BatchBn128: failed with Bn128 operations");
    }
}