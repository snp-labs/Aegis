import { ethers } from "hardhat";
import { expect } from "chai";
import { PoseidonHasher, PoseidonHasher__factory, PoseidonLib__factory, PoseidonAsmLib__factory } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";


describe("Poseidon Hasher", () => {
    let poseidonHasher: PoseidonHasher;
    let signer: SignerWithAddress;

    beforeEach(async() => {
        [signer] = await ethers.getSigners();

        const poseidonLib = await new PoseidonLib__factory(signer).deploy();
        const poseidonLibAddress = await poseidonLib.getAddress();

        const poseidonAsmLib = await new PoseidonAsmLib__factory(signer).deploy();
        const poseidonAsmLibAddress = await poseidonAsmLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonLib.sol:PoseidonLib": poseidonLibAddress,
            "contracts/crypto/hash/PoseidonAsmLib.sol:PoseidonAsmLib": poseidonAsmLibAddress,
        };

        poseidonHasher = await new PoseidonHasher__factory(libraryAddresses, signer).deploy();
    });

    it("should deploy and verify", async() => {
        expect(await poseidonHasher.getAddress()).to.be.properAddress;
    });

    it("should return the correct hash [PoseidonAsmLib]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest = await poseidonHasher.hashAsm([input]);
        await digest.wait();
    });

    it("should return the correct hash [PoseidonLib]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest= await poseidonHasher.hash([input]);
        await digest.wait();
    });

    it("should return the correct hash [Keccack]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest= await poseidonHasher.hashKeccak([input]);
        await digest.wait();
    });

    it("should return the correct hash [MiMC7]", async() => {
        const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
        const digest= await poseidonHasher.hashMiMC7([input]);
        await digest.wait();
    });

    // it("should compare gas costs between PoseidonLib and PoseidonAsmLib", async() => {
    //     const input = ethers.toBigInt("7524178265202101577084604334552339139954807715757712981859874388306919542679");
    // });
});