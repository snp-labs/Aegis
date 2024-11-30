// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./ArkConstants.sol";

library Poseidon {
    uint256 constant p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    function applyARC(uint256[3] memory state, uint256[] memory roundConstants) internal pure returns (uint256[3] memory) {
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

    function applyMDS(uint256[3] memory state, uint256[3][3] memory mds) internal pure returns (uint256[3] memory) {
        uint256[3] memory newState;
        for (uint256 i = 0; i < 3; i++) {
            newState[i] = 0;
            for (uint256 j = 0; j < 3; j++) {
                newState[i] = addmod(newState[i], mulmod(state[j], mds[i][j], p), p);
            }
        }
        return newState;
    }
}


contract PoseidonHash {
    uint256 public fullRounds;
    uint256 public partialRounds;
    uint256 public alpha;
    uint256[3][3] public mds;
    uint256[][] public ark;
    uint256 public rate = 2;
    uint256 public capacity = 1;

    uint256 constant p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    constructor() {
        fullRounds = ArkConstants.getFullRounds();
        partialRounds = ArkConstants.getPartialRounds();
        alpha = ArkConstants.getAlpha();
        mds = ArkConstants.getMds();
        ark = ArkConstants.getArk();
    }

    function poseidon(uint256[] memory inputs) public view returns (uint256[] memory) {
        uint256[3] memory state;
        uint256[][] memory chunks = splitAndPad(inputs);
        state = absorb(chunks, state);
        uint256 outputLength = 1;
        return squeeze(state, outputLength);
    }

    function absorb(uint256[][] memory chunks, uint256[3] memory state) internal view returns (uint256[3] memory) {
        for (uint256 i = 0; i < chunks.length; i++) {
            state[1] = addmod(state[1], chunks[i][0], p);
            state[2] = addmod(state[2], chunks[i][1], p);
            state = permute(state);
        }
        return state;
    }

    function squeeze(uint256[3] memory state, uint256 numOutputs) internal view returns (uint256[] memory) {
        uint256[] memory outputs = new uint256[](numOutputs);
        uint256 rateIndex = 0;
        uint256 outputCount = 0;

        while (outputCount < numOutputs) {
            while (rateIndex < rate && outputCount < numOutputs) {
                outputs[outputCount] = state[capacity + rateIndex];
                rateIndex++;
                outputCount++;
            }

            if (outputCount < numOutputs) {
                state = permute(state);
                rateIndex = 0;
            }
        }

        return outputs;
    }

    function permute(uint256[3] memory state) internal view returns (uint256[3] memory) {
        // First full rounds
        state = applyFullRounds(state, 0, fullRounds);

        // Partial rounds
        state = applyPartialRounds(state);

        // Final full rounds
        state = applyFullRounds(state, fullRounds + partialRounds, fullRounds + partialRounds + fullRounds);

        return state;
    }

    function applyFullRounds(uint256[3] memory state, uint256 startRound, uint256 endRound) internal view returns (uint256[3] memory) {
        for (uint256 i = startRound; i < endRound; i++) {
            state = Poseidon.applyARC(state, ark[i]); // ARC
            state = applySboxFull(state);            // S-box
            state = Poseidon.applyMDS(state, mds);   // MDS
        }
        return state;
    }

    function applyPartialRounds(uint256[3] memory state) internal view returns (uint256[3] memory) {
        for (uint256 i = fullRounds; i < fullRounds + partialRounds; i++) {
            state = Poseidon.applyARC(state, ark[i]); // ARC
            state[0] = Poseidon.applySbox(state[0], alpha); // S-box to the first element
            state = Poseidon.applyMDS(state, mds);         // MDS
        }
        return state;
    }

    function applySboxFull(uint256[3] memory state) internal view returns (uint256[3] memory) {
        for (uint256 i = 0; i < 3; i++) {
            state[i] = Poseidon.applySbox(state[i], alpha);
        }
        return state;
    }

    function splitAndPad(uint256[] memory input) public view returns (uint256[][] memory) {
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
}
