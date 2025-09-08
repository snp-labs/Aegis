
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

    for (let i = 7; i < 13; i++) {
      ct_bar.push(input[i]);
    }
    for (let i = 13; i < 17; i++) {
      ct_key.push(input[i]);
    }
    for (let i = 17; i < 21; i++) {
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
  
  async function transactionPerformance(
    transactionFunction: (...args: any[]) => Promise<any>,
    iter: number = 1000,
    ...args: any[]
  ): Promise<void> {
    let totalGasUsed: bigint = BigInt(0);
    let startTime: number = Date.now();
  
    for (let i = 0; i < iter; i++) {
      let tx = await transactionFunction(...args);
      const receipt = await tx.wait();
      if (receipt) {
        totalGasUsed += BigInt(receipt.gasUsed);
      }
    }
  
    let endTime: number = Date.now();
    const totalTime: number = (endTime - startTime) / 1000;
    const tps: number = iter / totalTime;
  
    console.log(`Total gas used: ${totalGasUsed.toString()}`);
    console.log(`Total execution time: ${totalTime} seconds`);
    console.log(`TPS: ${tps}`);
    console.log(`Time per transaction: ${totalTime / iter} seconds`);
    console.log(`Gas used per transaction: ${totalGasUsed / BigInt(iter)}`);
  }

export { preprocessedVK, preprocessedProof, preprocessedInput, preprocessedSendInstance, preprocessedExchangeInstance, preprocessedRegisterInstance, preprocessedReceiveInstance, transactionPerformance };