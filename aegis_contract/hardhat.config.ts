import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: "0.8.27",
  networks: {
    hardhat: {
      chainId: 1337,
      blockGasLimit: 1000000000,
      accounts: {
        accountsBalance: '10500000000000000000'
      },
    }
  },
  gasReporter: {
    enabled: true,
  }
};

export default config;
