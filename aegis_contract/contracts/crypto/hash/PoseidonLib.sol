// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library PoseidonLib {
    uint256 constant p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function applyARC(
        uint256[3] memory state,
        uint256[] memory roundConstants
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
            newState[i] = 0;
            for (uint256 j = 0; j < 3; j++) {
                newState[i] = addmod(newState[i], mulmod(state[j], mds[i][j], p), p);
            }
        }
        return newState;
    }

    function permute(
        uint256[3] memory state,
        uint256[][] memory ark,
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
        uint256[][] memory ark,
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
        uint256[][] memory ark,
        uint256[3][3] memory mds,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) internal pure returns (uint256[] memory) {
        uint256 numOutputs = 1;
        uint256[] memory outputs = new uint256[](numOutputs);
        uint256 rateIndex = 0;
        uint256 outputCount = 0;

        while (outputCount < numOutputs) {
            while (rateIndex < 2 && outputCount < numOutputs) {
                outputs[outputCount] = state[1 + rateIndex];
                rateIndex++;
                outputCount++;
            }

            if (outputCount < numOutputs) {
                state = permute(state, ark, mds, alpha, fullRounds, partialRounds);
                rateIndex = 0;
            }
        }

        return outputs;
    }

    function applyFullRounds(
        uint256[3] memory state,
        uint256[][] memory ark,
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
        uint256[][] memory ark,
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

    function _hash(
        uint256[] memory inputs,
        uint256[3][3] memory mds,
        uint256[][] memory ark,
        uint256 alpha,
        uint256 fullRounds,
        uint256 partialRounds
    ) public pure returns (uint256[] memory) {
        require(inputs.length > 0, "Input cannot be empty");

        uint256[3] memory state;
        uint256[][] memory chunks = splitAndPad(inputs, 2); // Rate = 2

        state = absorb(state, chunks, ark, mds, alpha, fullRounds, partialRounds);

        return squeeze(state, ark, mds, alpha, fullRounds, partialRounds);
    }
}
