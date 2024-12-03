import { ethers } from "hardhat";
import { expect } from "chai";
import { PoseidonHasher, PoseidonHasher__factory, PoseidonHashLib__factory } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";


describe("Poseidon Hasher", () => {
    let poseidonHasher: PoseidonHasher;
    let signer: SignerWithAddress;

    beforeEach(async() => {
        [signer] = await ethers.getSigners();

        const poseidonHashLib = await new PoseidonHashLib__factory(signer).deploy();
        const poseidonHashLibAddress = await poseidonHashLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonHashLib.sol:PoseidonHashLib": poseidonHashLibAddress
        };

        poseidonHasher = await new PoseidonHasher__factory(libraryAddresses, signer).deploy();
    });

    it("should deploy and verify", async() => {
        expect(await poseidonHasher.getAddress()).to.be.properAddress;
    });

    it("should return the correct hash [PoseidonHashLib]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest = await poseidonHasher.hashPoseidon([input]);
        console.log(digest);
    });

    it("should return the correct hash [Keccack]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest= await poseidonHasher.hashKeccak([input]);
        console.log(digest);
    });

    it("should return the correct hash [MiMC7]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest= await poseidonHasher.hashMiMC7([input]);
        console.log(digest);
    });

    it("should measure gas cost : [PoseidonLib]", async() => {
        const input = ethers.toBigInt("11235");
        const PoseidonHashLibGasCost = await poseidonHasher.hashPoseidon.estimateGas([input]);
        const MiMC7GasCost = await poseidonHasher.hashMiMC7.estimateGas([input]);
        const KeccakGasCost = await poseidonHasher.hashKeccak.estimateGas([input]);
        console.log("[MiMC7]: ", MiMC7GasCost.toString());
        console.log("[Keccak]: ", KeccakGasCost.toString());
        console.log("[Poseidon]: ", PoseidonHashLibGasCost.toString());
    });
});