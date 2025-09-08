import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { Aegis, Aegis__factory } from "../typechain-types";
import { ethers } from "hardhat";
import batch1024 from "../result/dbtData";
import { Bn128 } from "../typechain-types/contracts/Aegis";

describe("Aegis", () => {
  let Aegis: Aegis;
  let signer: SignerWithAddress;
  let vrsStruct: Aegis.VrsStruct;

  const batch = batch1024;
  const BATCH_SIZE = batch.batchSize;
  const addresses = createAddress(BATCH_SIZE);
  let deltacm1: Bn128.G1PointStruct = {
    X: batch.dbt.cm[0],
    Y: batch.dbt.cm[1],
  };
  let deltacm2: Bn128.G1PointStruct = {
    X: batch.dbt.cm[2],
    Y: batch.dbt.cm[3],
  };
  let deltaCommitments: Bn128.G1PointStruct[] = [];
  for (let i = 0; i < BATCH_SIZE / 2; i++) {
    deltaCommitments.push(deltacm1);
    deltaCommitments.push(deltacm2);
  }

  const txs: Aegis.TradeDataStruct = makeTsx([], addresses, deltaCommitments);

  beforeEach(async () => {
    [signer] = await ethers.getSigners();
    Aegis = await new Aegis__factory(signer).deploy(batch.vk, batch.ck, BATCH_SIZE);

    const prevCm: Bn128.G1PointStruct = {
      X: batch.prevCm[0],
      Y: batch.prevCm[1],
    };

    for (let i = 0; i < BATCH_SIZE; i++) {
      await Aegis.setCM(addresses[i], prevCm);
    }
  });

  it("verify", async () => {
    await Aegis.verify(batch.dbt.proof, txs);
  });

  it("updateCommitment", async () => {
    console.log("Batch size: ", BATCH_SIZE);
    const txs: Aegis.TradeDataStruct = makeTsx(
      addresses,
      addresses,
      deltaCommitments
    );

    const [owner] = await ethers.getSigners();

    const abicoder = ethers.AbiCoder.defaultAbiCoder();

    const encodedDeltaCm = abicoder.encode(
      ["uint256[]", "tuple(address[],address[],tuple(uint256,uint256)[])"],
      [
        batch.dbt.proof,
        [
          txs.userAddress,
          txs.contractAddress,
          txs.deltaCm.map((value: Bn128.G1PointStruct) => [value.X, value.Y]),
        ],
      ]
    );

    const messageHash = ethers.keccak256(encodedDeltaCm);

    const messageHashBinary = ethers.getBytes(messageHash);
    const signature = await owner.signMessage(messageHashBinary);

    vrsStruct = {
      v: ethers.Signature.from(signature).v,
      r: ethers.Signature.from(signature).r,
      s: ethers.Signature.from(signature).s,
    };

    let vrsStructs = [];

    for (let i = 0; i < BATCH_SIZE; i++) {
      vrsStructs.push(vrsStruct);
    }

    await Aegis.updateCommitment(vrsStructs, batch.dbt.proof, txs);
  });

  it("updateCommitment - tps", async () => {
    const txs: Aegis.TradeDataStruct = makeTsx(
      addresses,
      addresses,
      deltaCommitments
    );
    
    const [owner] = await ethers.getSigners();
    
    const abicoder = ethers.AbiCoder.defaultAbiCoder();
    
    const encodedDeltaCm = abicoder.encode(
      ["uint256[]", "tuple(address[],address[],tuple(uint256,uint256)[])"],
      [
        batch.dbt.proof,
        [
          txs.userAddress,
          txs.contractAddress,
          txs.deltaCm.map((value: Bn128.G1PointStruct) => [value.X, value.Y]),
        ],
      ]
    );
    
    const messageHash = ethers.keccak256(encodedDeltaCm);
    
    const messageHashBinary = ethers.getBytes(messageHash);
    const signature = await owner.signMessage(messageHashBinary);
    
    vrsStruct = {
      v: ethers.Signature.from(signature).v,
      r: ethers.Signature.from(signature).r,
      s: ethers.Signature.from(signature).s,
    };
    
    let vrsStructs = [];
    
    for (let i = 0; i < 8; i++) {
      vrsStructs.push(vrsStruct);
    }
    
    const numTransactions = 10;
    const txPromises = [];
    const startTime = Date.now();
    
    for (let i = 0; i < numTransactions; i++) {
      txPromises.push(Aegis.updateCommitment(vrsStructs, batch.dbt.proof, txs));
    }

    // 모든 트랜잭션이 처리될 때까지 대기
    await Promise.all(txPromises);

    const endTime = Date.now();
    const durationInSeconds = (endTime - startTime) / 1000;
    const tps = numTransactions / durationInSeconds;
    const oneTransactionTime = durationInSeconds / numTransactions;

    console.log(
      `Sent a total of ${numTransactions} transactions in ${durationInSeconds} seconds.`
    );
    console.log(`TPS: ${tps}`);
    console.log(`Time per transaction: ${oneTransactionTime} seconds`);
  });

  it("bn-add", async () => {
    const cm: Bn128.G1PointStruct = {
      X: batch.dbt.cm[0],
      Y: batch.dbt.cm[1],
    };

    let tx = await Aegis.bn_add(cm, cm);
  });
});

function createAddress(n: number): Array<string> {
  let address: Array<string> = [];
  for (let i = 0; i < n; i++) {
    const wallet = ethers.Wallet.createRandom();
    address.push(wallet.address);
  }
  return address;
}

function makeTsx(
  contractAddress: string[],
  userAddress: string[],
  deltaCm: Bn128.G1PointStruct[]
): Aegis.TradeDataStruct {
  return {
    contractAddress: contractAddress,
    userAddress: userAddress,
    deltaCm: deltaCm,
  };
}