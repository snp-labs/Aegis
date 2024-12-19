import { CBDC, CBDC__factory, PoseidonHashLib__factory } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";
import * as fs from "fs";
import { preprocessedVK, preprocessedInput, preprocessedProof, preprocessedRegisterInstance, preprocessedSendInstance, preprocessedReceiveInstance, preprocessedExchangeInstance } from "./utils";

import REGISTER_VK from "../result/register/register.vk.json";
import REGISTER_INPUT from "../result/register/register.input.json";
import REGISTER_PROOF from "../result/register/register.proof.json";
import SEND_VK from "../result/send/send.vk.json";
import SEND_INPUT from "../result/send/send.input.json";
import SEND_PROOF from "../result/send/send.proof.json";
import RECEIVE_VK from "../result/receive/receive.vk.json";
import RECEIVE_INPUT from "../result/receive/receive.input.json";
import RECEIVE_PROOF from "../result/receive/receive.proof.json";
import EXCHANGE_VK from "../result/exchange/exchange.vk.json";
import EXCHANGE_INPUT from "../result/exchange/exchange.input.json";
import EXCHANGE_PROOF from "../result/exchange/exchange.proof.json";
import { expect } from "chai";

const register_vk = preprocessedVK(REGISTER_VK);
const register_input = preprocessedInput(REGISTER_INPUT);
const register_instance = preprocessedRegisterInstance(register_input);
const register_proof = preprocessedProof(REGISTER_PROOF);
const send_vk = preprocessedVK(SEND_VK);
const send_input = preprocessedInput(SEND_INPUT);
const send_instance = preprocessedSendInstance(send_input);
const send_proof = preprocessedProof(SEND_PROOF);
const receive_vk = preprocessedVK(RECEIVE_VK);
const receive_input = preprocessedInput(RECEIVE_INPUT);
const receive_instance = preprocessedReceiveInstance(receive_input);
const receive_proof = preprocessedProof(RECEIVE_PROOF);
const exchange_vk = preprocessedVK(EXCHANGE_VK);
const exchange_input = preprocessedInput(EXCHANGE_INPUT);
const exchange_instance = preprocessedExchangeInstance(exchange_input);
const exchange_proof = preprocessedProof(EXCHANGE_PROOF);
const MT_DEPTH = 31;
const APK = [
  send_instance.apk[0],
  send_instance.apk[1],
  receive_instance.apk[0],
  receive_instance.apk[1],
  exchange_instance.apk[0],
  exchange_instance.apk[1],
  register_instance.apk[0],
  register_instance.apk[0],
];

describe("register", () => {
  let CBDC: CBDC;
  let signer: SignerWithAddress;

  beforeEach(async () => {
    [signer] = await ethers.getSigners();
    const poseidonHashLib = await new PoseidonHashLib__factory(signer).deploy();
    const poseidonHashLibAddr = await poseidonHashLib.getAddress();

    const libraryAddresses = {
        "contracts/crypto/hash/PoseidonHashLib.sol:PoseidonHashLib": poseidonHashLibAddr,
    };

    const vk = preprocessedVK(REGISTER_VK);
    const input = preprocessedInput(REGISTER_INPUT);
    const instance = preprocessedRegisterInstance(input);

    const mockVk = [1];
    const apk = instance.apk;
    const MT_DEPTH = 31;
    const mockCK = [1, 1, 1, 1];

    CBDC = await new CBDC__factory(libraryAddresses, signer).deploy(
      MT_DEPTH,
      vk,
      mockVk,
      mockVk,
      mockVk,
      apk,
      mockCK
    );
  });

  it.only("register-gas consumption", async () => {
    const input = preprocessedInput(REGISTER_INPUT);
    const instance = preprocessedRegisterInstance(input);
    const proof = preprocessedProof(REGISTER_PROOF);

    await CBDC.insert_cm(instance.cm);

    await CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof);
  });

  it("register-tps", async () => {
    const input = preprocessedInput(REGISTER_INPUT);
    const instance = preprocessedRegisterInstance(input);
    const proof = preprocessedProof(REGISTER_PROOF);

    await CBDC.insert_cm(instance.cm);

    await CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof);

    const numTransactions = 100;
    const txPromises = [];
    const startTime = Date.now();

    for (let i = 0; i < numTransactions; i++) {
      txPromises.push(
        CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof)
      );
    }

    // 모든 트랜잭션이 처리될 때까지 대기
    await Promise.all(txPromises);

    const endTime = Date.now();
    const durationInSeconds = (endTime - startTime) / 1000;
    const tps = numTransactions / durationInSeconds;
    const oneTransactionTime = durationInSeconds / numTransactions;

    console.log(
      `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
    );
    console.log(`TPS: ${tps}`);
    console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
  });
});

describe("send", () => {
  let CBDC: CBDC;
  let signer: SignerWithAddress;

  beforeEach(async () => {
    [signer] = await ethers.getSigners();
    const poseidonHashLib = await new PoseidonHashLib__factory(signer).deploy();
    const poseidonHashLibAddr = await poseidonHashLib.getAddress();

    const libraryAddresses = {
        "contracts/crypto/hash/PoseidonHashLib.sol:PoseidonHashLib": poseidonHashLibAddr,
    };

    const vk = preprocessedVK(SEND_VK);
    const input = preprocessedInput(SEND_INPUT);
    const instance = preprocessedSendInstance(input);

    const mockVk = [1];
    const apk = instance.apk;
    const MT_DEPTH = 31;
    const mockCK = [1, 1, 1, 1];

    CBDC = await new CBDC__factory(libraryAddresses, signer).deploy(
      MT_DEPTH,
      mockVk,
      vk,
      mockVk,
      mockVk,
      apk,
      mockCK
    );
  });

  it.only("send-gas consumption", async () => {
    const input = preprocessedInput(SEND_INPUT);
    const instance = preprocessedSendInstance(input);
    const proof = preprocessedProof(SEND_PROOF);

    // this cm used in register step.
    // make rt for send.
    await CBDC.insert_cm(
      "8014028253815006770497752673435832929565893020002757511111383677682508243356"
    );

    await CBDC.insert_rt(instance.rt);
    await CBDC.insert_sn(instance.sn_cur);
    await CBDC.insert_cm(instance.cm_v);

    console.log("ct_bar.length: ", instance.ct_bar.length);
    await CBDC.send(
      instance.rt,
      instance.sn_cur,
      instance.cm_new,
      instance.cm_v,
      instance.ct_bar,
      instance.ct_key,
      instance.ct,
      instance.auth,
      proof
    );
  });

  it("send-tps", async () => {
    const input = preprocessedInput(SEND_INPUT);
    const instance = preprocessedSendInstance(input);
    const proof = preprocessedProof(SEND_PROOF);

    // this cm used in register step.
    // make rt for send.
    await CBDC.insert_cm(
      "8014028253815006770497752673435832929565893020002757511111383677682508243356"
    );
    await CBDC.insert_rt(instance.rt);
    await CBDC.insert_sn(instance.sn_cur);
    await CBDC.insert_cm(instance.cm_v);

    await CBDC.send(
      instance.rt,
      instance.sn_cur,
      instance.cm_new,
      instance.cm_v,
      instance.ct_bar,
      instance.ct_key,
      instance.ct,
      instance.auth,
      proof
    );

    const numTransactions = 100;
    const txPromises = [];
    const startTime = Date.now();

    for (let i = 0; i < numTransactions; i++) {
      txPromises.push(
        CBDC.send(
          instance.rt,
          instance.sn_cur,
          instance.cm_new,
          instance.cm_v,
          instance.ct_bar,
          instance.ct_key,
          instance.ct,
          instance.auth,
          proof
        )
      );
    }

    // 모든 트랜잭션이 처리될 때까지 대기
    await Promise.all(txPromises);

    const endTime = Date.now();
    const durationInSeconds = (endTime - startTime) / 1000;
    const tps = numTransactions / durationInSeconds;
    const oneTransactionTime = durationInSeconds / numTransactions;

    console.log(
      `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
    );
    console.log(`TPS: ${tps}`);
    console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
  });
});


