import {
  Hex,
  PublicClient,
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";

export const ARBITRUM_STYLUS_CHAIN = {
  id: 13331371,
  name: "Arbitrum Stylus Testnet",
  network: "arbitrumStylusTestnet",
  nativeCurrency: {
    decimals: 18,
    name: "Arbitrum Stylus Testnet",
    symbol: "ETH",
  },
  rpcUrls: {
    default: {
      http: [process.env.RPC_URL || "https://stylusv2.arbitrum.io/rpc"],
    },
  },
  blockExplorers: {
    default: {
      name: "Aribtrum Stylus Testnet",
      url: "https://stylusv2-explorer.arbitrum.io/",
    },
  },
  testnet: true,
};

export const getPublicClient = (): PublicClient => {
  const chain = getChain();
  return createPublicClient({
    chain,
    transport: http(),
  });
};

export const getChain = () => defineChain(ARBITRUM_STYLUS_CHAIN);

export const getAccount = () =>
  privateKeyToAccount((process.env.PRIVATE_KEY as Hex) || "0x0");

export const getWalletClient = () => {
  const account = getAccount();
  const chain = getChain();
  return createWalletClient({
    account,
    chain,
    transport: http(),
  });
};
