import { ethers } from "hardhat";
import { expect } from "chai";
import { PoseidonMerkleTree, PoseidonMerkleTree__factory, PoseidonHashLib__factory, } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

describe("PoseidonMerkleTree with poseidonHashLib", () => {
    let poseidonMerkleTree: PoseidonMerkleTree;
    let signer: SignerWithAddress;

    beforeEach(async () => {
        [signer] = await ethers.getSigners();

        const poseidonHashLib = await new PoseidonHashLib__factory(signer).deploy();
        const poseidonHashLibAddress = await poseidonHashLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonHashLib.sol:PoseidonHashLib": poseidonHashLibAddress,
        };

        const HEIGHT = 32;
        poseidonMerkleTree = await new PoseidonMerkleTree__factory(libraryAddresses, signer).deploy(HEIGHT);
    });

    it("should deploy and verify", async () => {
        expect(await poseidonMerkleTree.getAddress()).to.be.properAddress;
    });

    it("should return the correct root", async() => {
        const cm = ethers.toBigInt("17796833287728466774051672880075403978897722235263613935738030145357528427335");
        const startTime = Date.now();
        const tx = await poseidonMerkleTree.insert_cm(cm);
        const receipt = await tx.wait();
        const endTime = Date.now();
        const after_root = await poseidonMerkleTree.getRoot();
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