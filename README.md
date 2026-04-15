# Aegis: Scalable Privacy-preserving CBDC Framework with Dynamic Proof of Liabilities

<p align="center">
  <a href="https://eprint.iacr.org/2025/539">
    <img src="https://img.shields.io/badge/IACR%20ePrint-2025%2F539-informational.svg" alt="IACR ePrint 2025/539">
  </a>
  &nbsp;
  <a href="https://github.com/arkworks-rs/groth16/blob/master/LICENSE-MIT">
    <img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT License">
  </a>
</p>

> ℹ️ **Note:**
> This repository contains an implementation of [**Aegis**](https://eprint.iacr.org/2025/539).

> ⚠️ **Warning:**
> Do not use this project in production.

## Abstract

## Quick Start

> This repository contains both Rust/arkworks circuits and Hardhat-based smart contracts.  
> Follow the steps below to reproduce the full testing pipeline locally.

### 0. Environments

- Rust (stable): `cargo`
- Node.js (LTS): `npm`
- Git, bash

### 1. Clone & Install

```bash
git clone https://github.com/snp-labs/Aegis.git
cd Aegis
```

### 2. Environment Setup

Before running circuit tests, copy the circuit environment file:

```bash
cp aegis_circuit/.env.example aegis_circuit/.env
```

Make sure to adjust required values in `aegis_circuit/.env` according to your setup.

### 3. Circuit Tests

```bash
cd aegis_circuit/src/tests
sh run_tests.sh
```

Generated outputs:

- `aegis_circuit/src/tests/circuit_result.csv`
  - columns: `thread,batch_size,constraints,setup,commit,prover,aggregate,verifier`
- `aegis_contract/result/dbtData.batch_<N>.json`
  - per-batch contract artifact (`vk`, `ck`, `proof`, `cm`, `prevCm`)

### 4. Smart Contract Tests

Install dependencies first:

```bash
cd aegis_contract
npm install
```

#### 4.1 Functional Test (`test/Aegis.ts`)

Use one batch artifact via `AEGIS_BATCH`:

```bash
AEGIS_BATCH=1024 npx hardhat test test/Aegis.ts
```

#### 4.2 Verify Performance Benchmark (`test/Aegis.verify.perf.ts`)

Run verify benchmark across generated `dbtData.batch_*.json` artifacts:

```bash
npx hardhat test test/Aegis.verify.perf.ts
```

Optional filters:

```bash
BATCHES=64,128,256 VERIFY_ITERS=3 MAX_VERIFY_BATCH=4096 npx hardhat test test/Aegis.verify.perf.ts
```

Benchmark outputs:

- Console: average verify time + gas per batch
- File: `aegis_contract/result/verify_perf.csv`

### 5. Optional: Enable Gas Reporter

Gas reporter is disabled by default and enabled only when requested:

```bash
REPORT_GAS=true npx hardhat test
```
