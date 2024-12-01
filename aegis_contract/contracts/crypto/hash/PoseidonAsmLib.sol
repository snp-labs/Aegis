// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library PoseidonAsmLib {
    /**
     * Poseidon Hash Parameters:
     * - rate: Number of elements processed per absorption step.
     * - capacity: Security parameter defining unused state size.
     * For this implementation:
     * - rate = 2
     * - capacity = 1
     * - width = rate + capacity = 3
     *
     * Customizable Parameters(user define):
     * - ark: AddRoundConstants used in each round.
     * - mds: Maximally Distance Separating (MDS) matrix for state mixing.
     * - alpha: Exponent used in the S-box for non-linear transformation.
     * - fullRounds: Number of full S-box rounds applied to all state elements.
     * - partialRounds: Number of partial S-box rounds applied to a single state element.
     */
    uint256 constant p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function applyARC(
        uint256[3] memory state,
        uint256[3] memory roundConstants
    ) internal pure returns (uint256[3] memory) {
        assembly {
            let state0 := add(state, 0)
            let state1 := add(state, 32)
            let state2 := add(state, 64)

            let rc0 := add(roundConstants, 0)
            let rc1 := add(roundConstants, 32)
            let rc2 := add(roundConstants, 64)

            mstore(state0, addmod(mload(state0), mload(rc0), p))
            mstore(state1, addmod(mload(state1), mload(rc1), p))
            mstore(state2, addmod(mload(state2), mload(rc2), p))
        }
        return state;
    }


    function applySbox(uint256 x, uint256 alpha) internal pure returns (uint256 result) {
        assembly {
            result := 1

            let base := mod(x, p)

            for { } gt(alpha, 0) { } {
                if eq(and(alpha, 1), 1) {
                    result := mulmod(result, base, p)
                }
                base := mulmod(base, base, p)
                alpha := shr(1, alpha)
            }
        }
    }


    function applyMDS(
        uint256[3] memory state,
        uint256[3][3] memory mds
    ) internal pure returns (uint256[3] memory newState) {
        assembly {
            let newStatePtr := newState

            let mdsPtr := add(mds, 0x60)

            let s0 := mload(state)
            let s1 := mload(add(state, 0x20))
            let s2 := mload(add(state, 0x40))

            // newState[0]: (s0*m00 + s1*m01 + s2*m02) mod p
            let ns0 := 0
            ns0 := addmod(ns0, mulmod(s0, mload(mdsPtr), p), p)            // s0 * m00
            ns0 := addmod(ns0, mulmod(s1, mload(add(mdsPtr, 0x20)), p), p) // s1 * m01
            ns0 := addmod(ns0, mulmod(s2, mload(add(mdsPtr, 0x40)), p), p) // s2 * m02

            // newState[1]: (s0*m10 + s1*m11 + s2*m12) mod p
            let ns1 := 0
            ns1 := addmod(ns1, mulmod(s0, mload(add(mdsPtr, 0x60)), p), p) // s0 * m10
            ns1 := addmod(ns1, mulmod(s1, mload(add(mdsPtr, 0x80)), p), p) // s1 * m11
            ns1 := addmod(ns1, mulmod(s2, mload(add(mdsPtr, 0xA0)), p), p) // s2 * m12

            // newState[2]: (s0*m20 + s1*m21 + s2*m22) mod p
            let ns2 := 0
            ns2 := addmod(ns2, mulmod(s0, mload(add(mdsPtr, 0xC0)), p), p) // s0 * m20
            ns2 := addmod(ns2, mulmod(s1, mload(add(mdsPtr, 0xE0)), p), p) // s1 * m21
            ns2 := addmod(ns2, mulmod(s2, mload(add(mdsPtr, 0x100)), p), p) // s2 * m22

            // store to newState
            mstore(newStatePtr, ns0)
            mstore(add(newStatePtr, 0x20), ns1)
            mstore(add(newStatePtr, 0x40), ns2)
        }
    }
    

    function permute(
        uint256[3] memory state,
        uint256[3][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) internal pure returns (uint256[3] memory) {
        // First full rounds
        state = applyFullRounds(state, ark, mds, alpha, 0, fullRounds);

        // Partial rounds
        state = applyPartialRounds(state, ark, mds, alpha, fullRounds, fullRounds + partialRounds);

        // Final full rounds
        state = applyFullRounds(state, ark, mds, alpha, fullRounds + partialRounds, fullRounds + partialRounds + fullRounds);

        return state;
    }

    // TODO: Assembly version of absorb
    function absorb(
        uint256[3] memory state,
        uint256[][] memory chunks,
        uint256[3][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) internal pure returns (uint256[3] memory) {
        for (uint256 i = 0; i < chunks.length; i++) {
            for (uint256 j = 0; j < 2; j++) {
                state[j + 1] = addmod(state[j + 1], chunks[i][j], p);
            }
            state = permute(state, ark, mds, alpha, fullRounds, partialRounds);
        }
        return state;
    }


    function squeeze(
        uint256[3] memory state
    ) internal pure returns (uint256) {
        return state[1];
    }

    function applyFullRounds(
        uint256[3] memory state,
        uint256[3][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 startRound,
        uint256 endRound
    ) internal pure returns (uint256[3] memory) {
        for (uint256 i = startRound; i < endRound; i++) {
            state = applyARC(state, ark[i]); // ARC
            state = applySboxFull(state, alpha); // S-box
            state = applyMDS(state, mds); // MDS
        }
        return state;
    }

    function applyPartialRounds(
        uint256[3] memory state,
        uint256[3][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 startRound,
        uint256 endRound
    ) internal pure returns (uint256[3] memory) {
        for (uint256 i = startRound; i < endRound; i++) {
            state = applyARC(state, ark[i]); // ARC
            state[0] = applySbox(state[0], alpha); // S-box to the first element
            state = applyMDS(state, mds); // MDS
        }
        return state;
    }

    function applySboxFull(uint256[3] memory state, uint256 alpha) internal pure returns (uint256[3] memory) {
        for (uint256 i = 0; i < 3; i++) {
            state[i] = applySbox(state[i], alpha);
        }
        return state;
    }

    // TODO: Assembly version of splitAndPad
    function splitAndPad(uint256[] memory input, uint256 rate) internal pure returns (uint256[][] memory) {
        uint256 inputLength = input.length;
        uint256 chunkCount = (inputLength + rate - 1) / rate;
        uint256[][] memory chunks = new uint256[][](chunkCount);

        for (uint256 i = 0; i < chunkCount; i++) {
            chunks[i] = new uint256[](rate);
            for (uint256 j = 0; j < rate; j++) {
                uint256 index = i * rate + j;
                if (index < inputLength) {
                    chunks[i][j] = input[index];
                } else {
                    chunks[i][j] = 0;
                }
            }
        }
        
        return chunks;
    }

    // TODO: Assembly version of splitAndPadTwoToOne
    function splitAndPadTwoToOne(uint256[2] memory input, uint256 rate) internal pure returns (uint256[][] memory) {
        uint256 inputLength = input.length;
        uint256 chunkCount = (inputLength + rate - 1) / rate;
        uint256[][] memory chunks = new uint256[][](chunkCount);

        for (uint256 i = 0; i < chunkCount; i++) {
            chunks[i] = new uint256[](rate);
            for (uint256 j = 0; j < rate; j++) {
                uint256 index = i * rate + j;
                if (index < inputLength) {
                    chunks[i][j] = input[index];
                } else {
                    chunks[i][j] = 0;
                }
            }
        }
        
        return chunks;
    }

    function _hash(
        uint256[] memory inputs,
        uint256[3][3] memory mds,
        uint256[3][] memory ark,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) public pure returns (uint256) {
        require(inputs.length > 0, "Input cannot be empty");

        uint256[3] memory state;
        uint256[][] memory chunks = splitAndPad(inputs, 2);

        state = absorb(state, chunks, ark, mds, alpha, fullRounds, partialRounds);

        return squeeze(state);
    }

    function _hashTwoToOne(
        uint256[2] memory inputs,
        uint256[3][3] memory mds,
        uint256[3][] memory ark,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) public pure returns (uint256) {
        require(inputs.length > 0, "Input cannot be empty");

        uint256[3] memory state;
        uint256[][] memory chunks = splitAndPadTwoToOne(inputs, 2);

        state = absorb(state, chunks, ark, mds, alpha, fullRounds, partialRounds);

        return squeeze(state);
    }
}