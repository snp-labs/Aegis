import { 
    CBDC, CBDC__factory,
    PoseidonMerkleTreeAsm, PoseidonMerkleTreeAsm__factory,
    PoseidonAsmLib, PoseidonAsmLib__factory 
} from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import { ethers } from "hardhat";

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
import DBT_VK from "../result/dbt/dbt.vk.json";
import batch1024 from "../result/dbt/dbtData";

import { expect } from "chai";


describe("Setup", () => {
    it("measure TPS for contract deployments", async() => {
        let CBDC: CBDC;
        let signer: SignerWithAddress;
        let poseidonMerkleTreeAsm: PoseidonMerkleTreeAsm;

        const BATCH_SIZE = 1024;
        const batch = batch1024;

        [signer] = await ethers.getSigners();

        const poseidonAsmLib = await new PoseidonAsmLib__factory(signer).deploy();
        const poseidonAsmLibAddress = await poseidonAsmLib.getAddress();

        const libraryAddresses = {
            "contracts/crypto/hash/PoseidonAsmLib.sol:PoseidonAsmLib": poseidonAsmLibAddress,
        };

        const HEIGHT = 32;
        poseidonMerkleTreeAsm = await new PoseidonMerkleTreeAsm__factory(libraryAddresses, signer).deploy(HEIGHT);
        

        const register_vk = preprocessedVK(REGISTER_VK);
        const send_vk = preprocessedVK(SEND_VK);
        const receive_vk = preprocessedVK(RECEIVE_VK);
        const exchange_vk = preprocessedVK(EXCHANGE_VK);

        const register_input = preprocessedInput(REGISTER_INPUT);
        const register_instance = preprocessedRegisterInstance(register_input);
        const send_input = preprocessedInput(REGISTER_INPUT);
        const send_instance = preprocessedSendInstance(send_input);
        const receive_input = preprocessedInput(REGISTER_INPUT);
        const receive_instance = preprocessedReceiveInstance(receive_input);
        const exchange_input = preprocessedInput(REGISTER_INPUT);
        const exchange_instance = preprocessedExchangeInstance(exchange_input);

        const apk = register_instance.apk;

        const numTransactions = 1;
        const txPromises = [];
        const startTime = Date.now();
    });
})


describe("register", () => {
  let CBDC: CBDC;
  let signer: SignerWithAddress;
  let poseidonMerkleTreeAsm: PoseidonMerkleTreeAsm;

  beforeEach(async () => {
    [signer] = await ethers.getSigners();
    const poseidonAsmLib = await new PoseidonAsmLib__factory(signer).deploy();
    const poseidonAsmLibAddress = await poseidonAsmLib.getAddress();

    const libraryAddresses = {
        "contracts/crypto/hash/PoseidonAsmLib.sol:PoseidonAsmLib": poseidonAsmLibAddress,
    };

    const vk = preprocessedVK(REGISTER_VK);
    const input = preprocessedInput(REGISTER_INPUT);
    const instance = preprocessedRegisterInstance(input);

    const mockVk = [1];
    const apk = instance.apk;
    const MT_DEPTH = 32;
    const mockCK = [1, 1, 1, 1];

    CBDC = await new CBDC__factory(libraryAddresses, signer).deploy(
      MT_DEPTH,
      mockVk,
      mockVk,
      mockVk,
      mockVk,
      apk,
      mockCK
    );
  });

  // it("register-gas consumption", async () => {
  //   const input = preprocessedInput(REGISTER_INPUT);
  //   const instance = preprocessedRegisterInstance(input);
  //   const proof = preprocessedProof(REGISTER_PROOF);

  //   await CBDC.insert_cm(instance.cm);

  //   await CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof);
  // });

  // it("register-tps", async () => {
  //   const input = preprocessedInput(REGISTER_INPUT);
  //   const instance = preprocessedRegisterInstance(input);
  //   const proof = preprocessedProof(REGISTER_PROOF);

  //   await CBDC.insert_cm(instance.cm);

  //   await CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof);

  //   const numTransactions = 1000;
  //   const txPromises = [];
  //   const startTime = Date.now();

  //   for (let i = 0; i < numTransactions; i++) {
  //     txPromises.push(
  //       CBDC.register(instance.cm, instance.ct_bar, instance.ct_key, proof)
  //     );
  //   }

  //   // 모든 트랜잭션이 처리될 때까지 대기
  //   await Promise.all(txPromises);

  //   const endTime = Date.now();
  //   const durationInSeconds = (endTime - startTime) / 1000;
  //   const tps = numTransactions / durationInSeconds;
  //   const oneTransactionTime = durationInSeconds / numTransactions;

  //   console.log(
  //     `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
  //   );
  //   console.log(`TPS: ${tps}`);
  //   console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
  // });

  // it("hash-test", async () => {
  //   const left = "1111";
  //   const right = "2222";

  //   let result = await CBDC.hash(left, right);
  //   console.log(result);
  // });
});

// describe("exchange", () => {
//   let CBDC: CBDC;
//   let signer: SignerWithAddress;

//   beforeEach(async () => {
//     [signer] = await ethers.getSigners();
//     const vk = preprocessedVK(EXCHANGE_VK);
//     const exchange_input = preprocessedInput(EXCHANGE_INPUT);
//     const exchange_instance = preprocessedExchangeInstance(exchange_input);
//     const mockVk = [1];
//     const apk = exchange_instance.apk;
//     const ck = exchange_instance.ck;
//     const MT_DEPTH = 31;

//     CBDC = await new CBDC__factory(signer).deploy(
//       MT_DEPTH,
//       mockVk,
//       mockVk,
//       mockVk,
//       vk,
//       DBT_VK.vk,
//       apk,
//       ck
//     );
//   });

//   it("exchange-gas consumption", async () => {
//     const exchange_input = preprocessedInput(EXCHANGE_INPUT);
//     const exchange_instance = preprocessedExchangeInstance(exchange_input);

//     const proof = preprocessedProof(EXCHANGE_PROOF);
//     const addr_d = exchange_instance.addr_d;

//     await CBDC.register_addr_d(addr_d, [
//       "13625107635562226780748047873302316074995727226145894150643945342841230032499",
//       "11449127362176692264979541020041522177404679311286906351407764389475552064184",
//     ]);
//     await CBDC.insert_rt(exchange_instance.rt);
//     await CBDC.insert_sn(exchange_instance.sn_cur);
//     await CBDC.insert_cm(exchange_instance.cm_new);

//     let cm_d_before = await CBDC.get_cm_d(addr_d);
//     console.log("before cm_d: ", cm_d_before);
//     await CBDC.exchange(
//       exchange_instance.rt,
//       exchange_instance.addr_d,
//       exchange_instance.sn_cur,
//       exchange_instance.cm_new,
//       exchange_instance.cm_new_d,
//       exchange_instance.cm_v_d,
//       exchange_instance.ct_bar,
//       exchange_instance.ct_bar_key,
//       proof
//     );
//     let cm_d_after = await CBDC.get_cm_d(addr_d);
//     console.log("cm_new_d : ", exchange_instance.cm_new_d);
//     console.log("after cm_d: ", cm_d_after);

//     expect(await CBDC.isin_list_sn(exchange_instance.sn_cur)).to.be.true;
//   });

//   it("exchange-tps", async () => {
//     const input = preprocessedInput(EXCHANGE_INPUT);
//     const instance = preprocessedExchangeInstance(input);
//     const proof = preprocessedProof(EXCHANGE_PROOF);

//     const addr_d = instance.addr_d;
//     await CBDC.register_addr_d(addr_d, [
//       "13625107635562226780748047873302316074995727226145894150643945342841230032499",
//       "11449127362176692264979541020041522177404679311286906351407764389475552064184",
//     ]);
//     await CBDC.insert_rt(instance.rt);
//     await CBDC.insert_sn(instance.sn_cur);
//     await CBDC.insert_cm(instance.cm_new);

//     await CBDC.exchange(
//       instance.rt,
//       instance.addr_d,
//       instance.sn_cur,
//       instance.cm_new,
//       instance.cm_new_d,
//       instance.cm_v_d,
//       instance.ct_bar,
//       instance.ct_bar_key,
//       proof
//     );

//     const numTransactions = 10000;
//     const txPromises = [];
//     const startTime = Date.now();

//     for (let i = 0; i < numTransactions; i++) {
//       txPromises.push(
//         CBDC.exchange(
//           instance.rt,
//           instance.addr_d,
//           instance.sn_cur,
//           instance.cm_new,
//           instance.cm_new_d,
//           instance.cm_v_d,
//           instance.ct_bar,
//           instance.ct_bar_key,
//           proof
//         )
//       );
//     }

//     // 모든 트랜잭션이 처리될 때까지 대기
//     await Promise.all(txPromises);

//     const endTime = Date.now();
//     const durationInSeconds = (endTime - startTime) / 1000;
//     const tps = numTransactions / durationInSeconds;
//     const oneTransactionTime = durationInSeconds / numTransactions;

//     console.log(
//       `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
//     );
//     console.log(`TPS: ${tps}`);
//     console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
//   });
// });

// describe("send", () => {
//   let CBDC: CBDC;
//   let signer: SignerWithAddress;

//   beforeEach(async () => {
//     [signer] = await ethers.getSigners();
//     const vk = preprocessedVK(SEND_VK);
//     const input = preprocessedInput(SEND_INPUT);
//     const instance = preprocessedSendInstance(input);

//     const mockVk = [1];
//     const apk = instance.apk;
//     const MT_DEPTH = 31;
//     const mockCK = [1, 1, 1, 1];

//     CBDC = await new CBDC__factory(signer).deploy(
//       MT_DEPTH,
//       mockVk,
//       vk,
//       mockVk,
//       mockVk,
//       DBT_VK.vk,
//       apk,
//       mockCK
//     );
//   });

//   it("send-gas consumption", async () => {
//     const input = preprocessedInput(SEND_INPUT);
//     const instance = preprocessedSendInstance(input);
//     const proof = preprocessedProof(SEND_PROOF);

//     // this cm used in register step.
//     // make rt for send.
//     await CBDC.insert_cm(
//       "8014028253815006770497752673435832929565893020002757511111383677682508243356"
//     );

//     await CBDC.insert_rt(instance.rt);
//     await CBDC.insert_sn(instance.sn_cur);
//     await CBDC.insert_cm(instance.cm_v);

//     await CBDC.send(
//       instance.rt,
//       instance.sn_cur,
//       instance.cm_new,
//       instance.cm_v,
//       instance.ct_bar,
//       instance.ct_key,
//       instance.ct,
//       instance.auth,
//       proof
//     );
//   });

//   it("send-tps", async () => {
//     const input = preprocessedInput(SEND_INPUT);
//     const instance = preprocessedSendInstance(input);
//     const proof = preprocessedProof(SEND_PROOF);

//     // this cm used in register step.
//     // make rt for send.
//     await CBDC.insert_cm(
//       "8014028253815006770497752673435832929565893020002757511111383677682508243356"
//     );
//     await CBDC.insert_rt(instance.rt);
//     await CBDC.insert_sn(instance.sn_cur);
//     await CBDC.insert_cm(instance.cm_v);

//     await CBDC.send(
//       instance.rt,
//       instance.sn_cur,
//       instance.cm_new,
//       instance.cm_v,
//       instance.ct_bar,
//       instance.ct_key,
//       instance.ct,
//       instance.auth,
//       proof
//     );

//     const numTransactions = 1000;
//     const txPromises = [];
//     const startTime = Date.now();

//     for (let i = 0; i < numTransactions; i++) {
//       txPromises.push(
//         CBDC.send(
//           instance.rt,
//           instance.sn_cur,
//           instance.cm_new,
//           instance.cm_v,
//           instance.ct_bar,
//           instance.ct_key,
//           instance.ct,
//           instance.auth,
//           proof
//         )
//       );
//     }

//     // 모든 트랜잭션이 처리될 때까지 대기
//     await Promise.all(txPromises);

//     const endTime = Date.now();
//     const durationInSeconds = (endTime - startTime) / 1000;
//     const tps = numTransactions / durationInSeconds;
//     const oneTransactionTime = durationInSeconds / numTransactions;

//     console.log(
//       `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
//     );
//     console.log(`TPS: ${tps}`);
//     console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
//   });
// });

// describe("receive", () => {
//   let CBDC: CBDC;
//   let signer: SignerWithAddress;

//   beforeEach(async () => {
//     [signer] = await ethers.getSigners();
//     const vk = preprocessedVK(RECEIVE_VK);
//     const input = preprocessedInput(RECEIVE_INPUT);
//     const instance = preprocessedReceiveInstance(input);

//     const mockVk = [1];
//     const apk = instance.apk;
//     const MT_DEPTH = 31;
//     const mockCK = [1, 1, 1, 1];

//     CBDC = await new CBDC__factory(signer).deploy(
//       MT_DEPTH,
//       mockVk,
//       mockVk,
//       vk,
//       mockVk,
//       DBT_VK.vk,
//       apk,
//       mockCK
//     );
//   });

//   it("receive-gas consumption", async () => {
//     const input = preprocessedInput(RECEIVE_INPUT);
//     const instance = preprocessedReceiveInstance(input);
//     const proof = preprocessedProof(RECEIVE_PROOF);

//     await CBDC.insert_two_element(
//       "16162629506693925027798233622706919065647496598554375377130816968730781634566",
//       "19754860774445696082831547942186449042970925069334241888307803281142883616633"
//     );
//     await CBDC.insert_rt(instance.rt);
//     await CBDC.insert_sn(instance.sn_v);
//     await CBDC.insert_sn(instance.sn_cur);
//     await CBDC.insert_cm(instance.cm_new);

//     await CBDC.receive(
//       instance.sn_v,
//       instance.sn_cur,
//       instance.cm_new,
//       instance.rt,
//       instance.ct_key,
//       instance.ct,
//       proof
//     );
//   });

//   it("receive-tps", async () => {
//     const input = preprocessedInput(RECEIVE_INPUT);
//     const instance = preprocessedReceiveInstance(input);
//     const proof = preprocessedProof(RECEIVE_PROOF);

//     // this cm used in register step.
//     // make rt for send.
//     await CBDC.insert_two_element(
//       "16162629506693925027798233622706919065647496598554375377130816968730781634566",
//       "19754860774445696082831547942186449042970925069334241888307803281142883616633"
//     );
//     await CBDC.insert_rt(instance.rt);
//     await CBDC.insert_sn(instance.sn_v);
//     await CBDC.insert_sn(instance.sn_cur);
//     await CBDC.insert_cm(instance.cm_new);
//     await CBDC.receive(
//       instance.sn_v,
//       instance.sn_cur,
//       instance.cm_new,
//       instance.rt,
//       instance.ct_key,
//       instance.ct,
//       proof
//     );

//     const numTransactions = 1000;
//     const txPromises = [];
//     const startTime = Date.now();

//     for (let i = 0; i < numTransactions; i++) {
//       txPromises.push(
//         CBDC.receive(
//           instance.sn_v,
//           instance.sn_cur,
//           instance.cm_new,
//           instance.rt,
//           instance.ct_key,
//           instance.ct,
//           proof
//         )
//       );
//     }

//     // 모든 트랜잭션이 처리될 때까지 대기
//     await Promise.all(txPromises);

//     const endTime = Date.now();
//     const durationInSeconds = (endTime - startTime) / 1000;
//     const tps = numTransactions / durationInSeconds;
//     const oneTransactionTime = durationInSeconds / numTransactions;

//     console.log(
//       `총 ${numTransactions}개의 트랜잭션을 ${durationInSeconds}초에 전송했습니다.`
//     );
//     console.log(`TPS: ${tps}`);
//     console.log(`한 트랜잭션당 소요 시간: ${oneTransactionTime}초`);
//   });
// });

function preprocessedVK(vk: any): string[] {
  let result = [
    ...vk.alpha_g1,
    ...vk.beta_g2_neg,
    ...vk.gamma_g2_neg,
    ...vk.delta_g2_neg,
    ...vk.gamma_abc_g1,
  ] as string[];
  return result;
}

function preprocessedProof(proof: any): string[] {
  let result = [...proof.a, ...proof.b, ...proof.c] as string[];
  return result;
}

function preprocessedInput(input: any): string[] {
  let result = [...input] as string[];
  return result;
}

function preprocessedSendInstance(input: string[]) {
  let ct_bar = [];
  let ct_key = [];
  let ct = [];
  for (let i = 7; i < 14; i++) {
    ct_bar.push(input[i]);
  }
  for (let i = 14; i < 17; i++) {
    ct_key.push(input[i]);
  }
  for (let i = 17; i < input.length; i++) {
    ct.push(input[i]);
  }
  let result = {
    sn_cur: input[0],
    cm_new: input[1],
    cm_v: input[2],
    rt: input[3],
    auth: input[4],
    apk: [input[5], input[6]],
    ct_bar: ct_bar,
    ct_key: ct_key,
    ct: ct,
  };
  return result;
}

function preprocessedExchangeInstance(input: string[]) {
  let ct_bar = [];
  let ct_bar_key = [];
  let ck = [];

  for (let i = 12; i < 18; i++) {
    ct_bar.push(input[i]);
  }

  for (let i = 1; i < 5; i++) {
    ck.push(input[i]);
  }

  for (let i = 20; i < input.length; i++) {
    ct_bar_key.push(input[i]);
  }

  let result = {
    rt: input[0],
    ck: ck,
    addr_d: input[5],
    sn_cur: input[6],
    cm_new: input[7],
    cm_new_d: { X: input[8], Y: input[9] },
    cm_v_d: { X: input[10], Y: input[11] },
    ct_bar: ct_bar,
    apk: [input[18], input[19]],
    ct_bar_key: ct_bar_key,
  };
  return result;
}

function preprocessedRegisterInstance(input: string[]) {
  const cm = input[0];
  let ct_bar = [];
  let apk = [input[8], input[9]];
  let ct_key = [];
  for (let i = 1; i < 8; i++) {
    ct_bar.push(input[i]);
  }
  for (let i = 10; i < input.length; i++) {
    ct_key.push(input[i]);
  }
  let result = {
    cm: cm,
    ct_bar: ct_bar,
    apk: apk,
    ct_key: ct_key,
  };
  return result;
}

function preprocessedReceiveInstance(input: string[]) {
  let ct = [];
  let ct_key = [];
  for (let i = 6; i < 12; i++) {
    ct_key.push(input[i]);
  }
  for (let i = 12; i < input.length; i++) {
    ct.push(input[i]);
  }

  let result = {
    apk: [input[0], input[1]],
    sn_v: input[2],
    sn_cur: input[3],
    cm_new: input[4],
    rt: input[5],
    ct_key: ct_key,
    ct: ct,
  };
  return result;
}