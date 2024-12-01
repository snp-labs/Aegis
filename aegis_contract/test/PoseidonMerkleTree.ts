import { ethers } from "hardhat";
import { expect } from "chai";
import { PoseidonMerkleTree, PoseidonMerkleTreeAsm,  PoseidonMerkleTree__factory, PoseidonMerkleTreeAsm__factory, PoseidonLib__factory, PoseidonAsmLib, PoseidonAsmLib__factory } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("PoseidonMerkleTree with PoseidonLib", () => {
    let poseidonMerkleTree: PoseidonMerkleTree;
    let signer: SignerWithAddress;

    beforeEach(async () => {
        [signer] = await ethers.getSigners();

        const poseidonLib = await new PoseidonLib__factory(signer).deploy();
        const poseidonLibAddress = await poseidonLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonLib.sol:PoseidonLib": poseidonLibAddress,
        };

        const HEIGHT = 32;
        poseidonMerkleTree = await new PoseidonMerkleTree__factory(libraryAddresses, signer).deploy(HEIGHT);
    });

    it("should deploy and verify", async () => {
        expect(await poseidonMerkleTree.getAddress()).to.be.properAddress;
    });

    it("should return the correct root", async() => {
        const cm = ethers.toBigInt("1234543212345");
        const before_root = await poseidonMerkleTree.getRoot();
        const startTime = Date.now();
        const tx = await poseidonMerkleTree.insert_cm(cm);
        const receipt = await tx.wait();
        const endTime = Date.now();
        const after_root = await poseidonMerkleTree.getRoot();
        const durationInSeconds = (endTime - startTime) / 1000;

        if (!receipt) {
            throw new Error("Transaction receipt is null. Something went wrong.");
        }
    
        const gasUsed = receipt.gasUsed;

        console.log("cm: ", cm);
        console.log("before_root: ", before_root);
        console.log("after_root: ", after_root);
        console.log("durationInSeconds: ", durationInSeconds);
        console.log("Gas used:", gasUsed.toString());

        const root_expected = ethers.toBigInt("0x20b6c38f1cfec609b3fea446519531cc14966cae320a3fb92fc67ce2db329b7e");
        expect(after_root).to.equal(root_expected);

    })
});


describe.only("PoseidonMerkleTree with PoseidonLibAsm", () => {
    let poseidonMerkleTreeAsm: PoseidonMerkleTreeAsm;
    let signer: SignerWithAddress;

    beforeEach(async () => {
        [signer] = await ethers.getSigners();

        const poseidonAsmLib = await new PoseidonAsmLib__factory(signer).deploy();
        const poseidonAsmLibAddress = await poseidonAsmLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonAsmLib.sol:PoseidonAsmLib": poseidonAsmLibAddress,
        };

        const HEIGHT = 32;
        poseidonMerkleTreeAsm = await new PoseidonMerkleTreeAsm__factory(libraryAddresses, signer).deploy(HEIGHT);
    });
    it("should deploy and verify", async () => {
        expect(await poseidonMerkleTreeAsm.getAddress()).to.be.properAddress;
    });

    it("should return the correct root", async() => {
        const cm = ethers.toBigInt("17796833287728466774051672880075403978897722235263613935738030145357528427335");
        const before_root = await poseidonMerkleTreeAsm.getRoot();
        const startTime = Date.now();
        const tx = await poseidonMerkleTreeAsm.insert_cm(cm);
        const receipt = await tx.wait();
        const endTime = Date.now();
        const after_root = await poseidonMerkleTreeAsm.getRoot();
        const durationInSeconds = (endTime - startTime) / 1000;

        if (!receipt) {
            throw new Error("Transaction receipt is null. Something went wrong.");
        }
    

        console.log("durationInSeconds: ", durationInSeconds);
        console.log("cm: ", cm);
        const root_expected = ethers.toBigInt("3457169297512285440471441514282379916812558370395473465723471569650428734507");
        console.log("root_expected: ", root_expected);
        expect(after_root).to.equal(root_expected);

    })
});