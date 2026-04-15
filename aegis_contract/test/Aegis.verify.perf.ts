import fs from "fs";
import path from "path";
import { ethers } from "hardhat";
import { Aegis, Aegis__factory } from "../typechain-types";
import { Bn128 } from "../typechain-types/contracts/Aegis";

type BatchArtifact = {
  batchSize: number;
  vk: string[];
  ck: string[];
  dbt: {
    cm: string[];
    proof: string[];
  };
  prevCm: string[];
};

type PerfRow = {
  batchSize: number;
  iterations: number;
  avgTimeLabel: string;
  avgGas: bigint;
};

function formatAvgTime(avgTimeMs: number): string {
  if (avgTimeMs >= 1000) {
    return `${(avgTimeMs / 1000).toFixed(2)} s`;
  }
  return `${avgTimeMs.toFixed(2)} ms`;
}

function readBatchArtifacts(): BatchArtifact[] {
  const resultDir = path.resolve(__dirname, "../result");
  if (!fs.existsSync(resultDir)) {
    throw new Error(`Result directory not found: ${resultDir}`);
  }

  const files = fs
    .readdirSync(resultDir)
    .filter((f) => /^dbtData\.batch_\d+\.json$/.test(f))
    .sort((a, b) => {
      const ai = Number(a.match(/\d+/)?.[0] ?? 0);
      const bi = Number(b.match(/\d+/)?.[0] ?? 0);
      return ai - bi;
    });

  if (files.length === 0) {
    throw new Error("No batch json files found. Generate from aegis_circuit first.");
  }

  const selected = process.env.BATCHES
    ? new Set(process.env.BATCHES.split(",").map((x) => Number(x.trim())))
    : null;

  return files
    .map((f) => {
      const raw = fs.readFileSync(path.join(resultDir, f), "utf-8");
      return JSON.parse(raw) as BatchArtifact;
    })
    .filter((a) => (selected ? selected.has(a.batchSize) : true));
}

function createAddresses(n: number): string[] {
  const addresses: string[] = [];
  for (let i = 0; i < n; i++) {
    addresses.push(ethers.Wallet.createRandom().address);
  }
  return addresses;
}

function makeDeltaCommitments(cm: string[], batchSize: number): Bn128.G1PointStruct[] {
  if (cm.length < 2) {
    throw new Error("dbt.cm must contain at least one G1 point");
  }
  const cm1: Bn128.G1PointStruct = { X: cm[0], Y: cm[1] };
  const cm2: Bn128.G1PointStruct = cm.length >= 4 ? { X: cm[2], Y: cm[3] } : cm1;

  const delta: Bn128.G1PointStruct[] = [];
  for (let i = 0; i < Math.floor(batchSize / 2); i++) {
    delta.push(cm1, cm2);
  }
  if (batchSize % 2 === 1) {
    delta.push(cm1);
  }
  return delta;
}

describe("Aegis Verify Performance By Batch", function () {
  this.timeout(0);

  const artifacts = readBatchArtifacts();
  const iterations = Number(process.env.VERIFY_ITERS ?? "3");
  const maxBatch = Number(process.env.MAX_VERIFY_BATCH ?? "32768");
  const txGasLimit = process.env.VERIFY_TX_GAS_LIMIT
    ? BigInt(process.env.VERIFY_TX_GAS_LIMIT)
    : undefined;
  const rows: PerfRow[] = [];

  after(() => {
    const csvPath = path.resolve(__dirname, "../result/verify_perf.csv");
    const header = "batch_size,iterations,avg_time,avg_gas";
    const lines = rows.map((r) =>
      [
        r.batchSize,
        r.iterations,
        r.avgTimeLabel,
        r.avgGas.toString(),
      ].join(",")
    );
    fs.writeFileSync(csvPath, [header, ...lines].join("\n"));
    console.log(`[verify] csv written: ${csvPath}`);
  });

  for (const artifact of artifacts) {
    it(`verify gas (batch=${artifact.batchSize})`, async function () {
      if (artifact.batchSize > maxBatch) {
        this.skip();
      }

      const [signer] = await ethers.getSigners();
      const contract: Aegis = await new Aegis__factory(signer).deploy(
        artifact.vk,
        artifact.ck,
        artifact.batchSize
      );
      await contract.waitForDeployment();

      const addresses = createAddresses(artifact.batchSize);
      const prevCm: Bn128.G1PointStruct = {
        X: artifact.prevCm[0],
        Y: artifact.prevCm[1],
      };
      for (let i = 0; i < artifact.batchSize; i++) {
        await contract.setCM(addresses[i], prevCm);
      }

      const txs: Aegis.TradeDataStruct = {
        contractAddress: [],
        userAddress: addresses,
        deltaCm: makeDeltaCommitments(artifact.dbt.cm, artifact.batchSize),
      };

      let totalGasUsed = 0n;
      const start = Date.now();
      for (let i = 0; i < iterations; i++) {
        const tx = await contract.verify([...artifact.dbt.proof], txs, {
          gasLimit: txGasLimit,
        });
        const receipt = await tx.wait();
        totalGasUsed += receipt?.gasUsed ?? 0n;
      }
      const end = Date.now();
      const totalTimeSec = (end - start) / 1000;
      const avgTimeMs = (totalTimeSec * 1000) / iterations;
      const avgTimeLabel = formatAvgTime(avgTimeMs);
      const avgGas = totalGasUsed / BigInt(iterations);

      rows.push({
        batchSize: artifact.batchSize,
        iterations,
        avgTimeLabel,
        avgGas,
      });

      console.log(
        `[verify] batch=${artifact.batchSize}, iter=${iterations}, totalTimeSec=${totalTimeSec.toFixed(
          3
        )}, avgTime=${avgTimeLabel}, avgGas=${avgGas.toString()}`
      );
    });
  }
});
