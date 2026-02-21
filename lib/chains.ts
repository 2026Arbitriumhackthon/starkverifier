import { defineChain } from "thirdweb/chains";

/**
 * Arbitrum Sepolia Testnet Configuration
 * Chain ID: 421614
 */
export const arbitrumSepolia = defineChain({
  id: 421614,
  name: "Arbitrum Sepolia",
  nativeCurrency: {
    name: "Arbitrum Sepolia Ether",
    symbol: "ETH",
    decimals: 18,
  },
  rpc: "https://sepolia-rollup.arbitrum.io/rpc",
  blockExplorers: [
    {
      name: "Arbiscan",
      url: "https://sepolia.arbiscan.io",
    },
  ],
  testnet: true,
});

/**
 * Arbitrum One Mainnet Configuration
 * Chain ID: 42161
 * Used for fetching real GMX trade data.
 */
export const arbitrumOne = defineChain({
  id: 42161,
  name: "Arbitrum One",
  nativeCurrency: {
    name: "Ether",
    symbol: "ETH",
    decimals: 18,
  },
  rpc: "https://arb1.arbitrum.io/rpc",
  blockExplorers: [
    {
      name: "Arbiscan",
      url: "https://arbiscan.io",
    },
  ],
});

/**
 * Supported chains for the application
 */
export const supportedChains = [arbitrumSepolia, arbitrumOne];
