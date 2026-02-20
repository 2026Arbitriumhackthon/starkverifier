/**
 * Static bot metadata and types for the Agent Dashboard.
 */

export interface BotProfile {
  id: "a" | "b";
  name: string;
  strategy: string;
  tradeCount: number;
  totalReturnBps: number;
  sharpeSqScaled: number;
  sharpeDisplay: string;
  riskLevel: "High" | "Medium" | "Low";
  description: string;
}

export type PipelinePhase =
  | "idle"
  | "loading-wasm"
  | "proving"
  | "sending-tx"
  | "confirming";

export interface ProofProgress {
  stage: string;
  detail: string;
  percent: number;
}

export interface VerificationRecord {
  botId: "a" | "b";
  botName: string;
  txHash: string;
  verified: boolean;
  gasUsed: bigint;
  timestamp: number;
}

export const NUM_QUERIES = 4;

export const ARBISCAN_TX_URL = "https://sepolia.arbiscan.io/tx";

export const BOT_A: BotProfile = {
  id: "a",
  name: "Aggressive ETH Trader",
  strategy: "Long/Short ETH with high leverage",
  tradeCount: 15,
  totalReturnBps: 3000,
  sharpeSqScaled: 60000,
  sharpeDisplay: "2.45",
  riskLevel: "High",
  description: "15 trades with pattern [100, 200, 300] bps returns. Sharpe^2 * 10000 = 60000.",
};

export const BOT_B: BotProfile = {
  id: "b",
  name: "Conservative Hedger",
  strategy: "Delta-neutral hedging positions",
  tradeCount: 23,
  totalReturnBps: 3000,
  sharpeSqScaled: 18750,
  sharpeDisplay: "1.37",
  riskLevel: "Low",
  description: "23 trades: 15 profitable (200bps) + 8 breakeven. Sharpe^2 * 10000 = 18750.",
};

export const BOTS: BotProfile[] = [BOT_A, BOT_B];
