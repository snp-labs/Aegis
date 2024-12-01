// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library PoseidonLib {
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
        for (uint256 i = 0; i < 3; i++) {
            state[i] = addmod(state[i], roundConstants[i], p);
        }
        return state;
    }

    function applySbox(uint256 x, uint256 alpha) internal pure returns (uint256) {
        uint256 result = 1;
        uint256 base = x % p;

        while (alpha > 0) {
            if (alpha % 2 == 1) {
                result = mulmod(result, base, p);
            }
            base = mulmod(base, base, p);
            alpha /= 2;
        }

        return result;
    }

    function applyMDS(
        uint256[3] memory state,
        uint256[3][3] memory mds
    ) internal pure returns (uint256[3] memory) {
        uint256[3] memory newState;
        for (uint256 i = 0; i < 3; i++) {
            for (uint256 j = 0; j < 3; j++) {
                newState[i] = addmod(newState[i], mulmod(state[j], mds[i][j], p), p);
            }
        }
        return newState;
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
        uint256[3] memory state,
        uint256[3][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) internal pure returns (uint256) {
        uint256 rateIndex = 0;

        for (uint256 i = 0; i < 2; i++) {
            if (rateIndex < 2) {
                return state[1 + rateIndex];
            }

            state = permute(state, ark, mds, alpha, fullRounds, partialRounds);
            rateIndex = 0;
        }

        revert("Squeeze failed");
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

        return squeeze(state, ark, mds, alpha, fullRounds, partialRounds);
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

        return squeeze(state, ark, mds, alpha, fullRounds, partialRounds);
    }
}
