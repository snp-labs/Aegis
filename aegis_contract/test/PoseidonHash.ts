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
        const input1 = ethers.toBigInt("19933809757920020759955474368277437557688215414721001481155398693244893563064");
        const input2 = ethers.toBigInt("8388539055774977664058499614800672349209703707994793864989619367039077778209");
        const digest = await poseidonHasher.hashPoseidonTwoToOne(input1, input2);
        const digest_expected = ethers.toBigInt("4366155491452329913680757329953861545146738755768024031653723098266737219231");
        console.log("digest: ", digest);
        console.log("digest_expected: ", digest_expected);
        expect(digest).to.be.equal(digest_expected);
    });

    it("should return the correct hash [Keccack]", async() => {
        const input1 = ethers.toBigInt("19933809757920020759955474368277437557688215414721001481155398693244893563064");
        const input2 = ethers.toBigInt("8388539055774977664058499614800672349209703707994793864989619367039077778209");
        const digest= await poseidonHasher.hashKeccak(input1, input2);
        console.log(digest);
    });

    it("should return the correct hash [MiMC7]", async() => {
        const input1 = ethers.toBigInt("19933809757920020759955474368277437557688215414721001481155398693244893563064");
        const input2 = ethers.toBigInt("8388539055774977664058499614800672349209703707994793864989619367039077778209");
        const digest= await poseidonHasher.hashMiMC7(input1, input2);
        console.log(digest);
    });

    it.only("should measure gas cost : [PoseidonLib]", async() => {
        const input1 = ethers.toBigInt("19933809757920020759955474368277437557688215414721001481155398693244893563064");
        const input2 = ethers.toBigInt("8388539055774977664058499614800672349209703707994793864989619367039077778209");
        const PoseidonHashLibGasCost = await poseidonHasher.hashPoseidonTwoToOne.estimateGas(input1, input2);
        const MiMC7GasCost = await poseidonHasher.hashMiMC7.estimateGas(input1, input2);
        const KeccakGasCost = await poseidonHasher.hashKeccak.estimateGas(input1, input2);
        console.log("[MiMC7]: ", MiMC7GasCost.toString());
        console.log("[Keccak]: ", KeccakGasCost.toString());
        console.log("[Poseidon]: ", PoseidonHashLibGasCost.toString());
    });
});