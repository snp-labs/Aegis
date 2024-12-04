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

    it.only("should return the correct hash [PoseidonHashLib]", async() => {
        const input = ethers.toBigInt("13426023570019593411025966325317987258055918306904482401598026097290337983680");
        const digest = await poseidonHasher.hashPoseidon([input]);
        const digest_expected = ethers.toBigInt("919503531753078779876520987165713340315120209391397874144021196597115396594");
        console.log("digest: ", digest);
        console.log("digest_expected: ", digest_expected);
        expect(digest).to.be.equal(digest_expected);
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

    it.only("should measure gas cost : [PoseidonLib]", async() => {
        const input = ethers.toBigInt("11235");
        const PoseidonHashLibGasCost = await poseidonHasher.hashPoseidon.estimateGas([input]);
        const MiMC7GasCost = await poseidonHasher.hashMiMC7.estimateGas([input]);
        const KeccakGasCost = await poseidonHasher.hashKeccak.estimateGas([input]);
        console.log("[MiMC7]: ", MiMC7GasCost.toString());
        console.log("[Keccak]: ", KeccakGasCost.toString());
        console.log("[Poseidon]: ", PoseidonHashLibGasCost.toString());
    });
});