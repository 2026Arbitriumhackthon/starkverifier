/**
 * Gas Utilities for Arbitrum Transaction Analysis
 */

import { arbitrumSepolia } from "./chains";

export interface ArbitrumTransactionReceipt {
  gasUsed: bigint;
  gasUsedForL1?: bigint;
  l1BlockNumber?: string;
  transactionHash: string;
}

/**
 * Fetch Arbitrum transaction receipt with L1 gas breakdown
 * using raw RPC call to get gasUsedForL1 field
 */
export async function getArbitrumReceiptWithL1Gas(
  txHash: string,
  rpcUrl?: string
): Promise<ArbitrumTransactionReceipt | null> {
  const url = rpcUrl || arbitrumSepolia.rpc;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "eth_getTransactionReceipt",
        params: [txHash],
      }),
    });

    const data = await response.json();

    if (data.error || !data.result) {
      console.error("RPC error:", data.error);
      return null;
    }

    const receipt = data.result;

    return {
      gasUsed: BigInt(receipt.gasUsed),
      gasUsedForL1: receipt.gasUsedForL1 ? BigInt(receipt.gasUsedForL1) : undefined,
      l1BlockNumber: receipt.l1BlockNumber,
      transactionHash: receipt.transactionHash,
    };
  } catch (error) {
    console.error("Failed to fetch Arbitrum receipt:", error);
    return null;
  }
}

/**
 * Format gas value for display
 */
export function formatGas(gas: bigint | number): string {
  const value = typeof gas === "bigint" ? Number(gas) : gas;

  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)}M`;
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(1)}K`;
  }
  return value.toLocaleString();
}
