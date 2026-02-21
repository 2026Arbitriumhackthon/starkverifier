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
  | "fetching-trades"
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
  botId: string;
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

/* ── Pipeline Visualization Types ─────────────────────────── */

export type PipelineStepStatus = "pending" | "active" | "done" | "error";

export interface PipelineStep {
  id: number;
  title: string;
  subtitle: string;
  activeDetail: string;
  status: PipelineStepStatus;
}

const PIPELINE_STEP_DEFS: Omit<PipelineStep, "status">[] = [
  { id: 1, title: "Load WASM", subtitle: "Initialize prover module", activeDetail: "Loading WASM prover..." },
  { id: 2, title: "Generate Trace", subtitle: "Sharpe ratio execution trace", activeDetail: "Computing trace polynomials..." },
  { id: 3, title: "Commit & Compose", subtitle: "Polynomial commitments + composition", activeDetail: "Running Fiat-Shamir protocol..." },
  { id: 4, title: "FRI Protocol", subtitle: "Low-degree testing & query proofs", activeDetail: "Generating FRI query proofs..." },
  { id: 5, title: "On-Chain Verify", subtitle: "Submit & confirm on Arbitrum", activeDetail: "Waiting for on-chain confirmation..." },
];

/** 6-step pipeline for Live Wallet mode (includes trade fetching step) */
export const WALLET_PIPELINE_STEP_DEFS: Omit<PipelineStep, "status">[] = [
  { id: 1, title: "Fetch Trades", subtitle: "GMX PositionDecrease events", activeDetail: "Scanning Arbitrum blocks..." },
  { id: 2, title: "Load WASM", subtitle: "Initialize prover module", activeDetail: "Loading WASM prover..." },
  { id: 3, title: "Generate Trace", subtitle: "Sharpe ratio execution trace", activeDetail: "Computing trace polynomials..." },
  { id: 4, title: "Commit & Compose", subtitle: "Polynomial commitments + composition", activeDetail: "Running Fiat-Shamir protocol..." },
  { id: 5, title: "FRI Protocol", subtitle: "Low-degree testing & query proofs", activeDetail: "Generating FRI query proofs..." },
  { id: 6, title: "On-Chain Verify", subtitle: "Submit & confirm on Arbitrum", activeDetail: "Waiting for on-chain confirmation..." },
];

/**
 * Derive 6-step pipeline for wallet mode.
 */
export function deriveWalletPipelineSteps(
  phase: PipelinePhase,
  progress: ProofProgress | null,
  error: string | null,
  errorAtStep?: number,
): PipelineStep[] {
  let activeStep = 0;
  if (phase === "fetching-trades") activeStep = 1;
  else if (phase === "loading-wasm") activeStep = 2;
  else if (phase === "proving") {
    if (progress) {
      const stage = progress.stage;
      if (stage === "trace") activeStep = 3;
      else if (stage === "commit" || stage === "compose") activeStep = 4;
      else if (stage === "fri") activeStep = 5;
      else if (stage === "done") activeStep = 6;
      else activeStep = 3;
    } else {
      activeStep = 3;
    }
  } else if (phase === "sending-tx" || phase === "confirming") activeStep = 6;

  return WALLET_PIPELINE_STEP_DEFS.map((def) => {
    let status: PipelineStepStatus = "pending";

    if (error && errorAtStep && def.id === errorAtStep) {
      status = "error";
    } else if (error && errorAtStep && def.id < errorAtStep) {
      status = "done";
    } else if (def.id < activeStep) {
      status = "done";
    } else if (def.id === activeStep) {
      status = error && !errorAtStep ? "error" : "active";
    }

    let activeDetail = def.activeDetail;
    if (def.id === activeStep && phase === "proving" && progress) {
      activeDetail = progress.detail;
    } else if (def.id === 6 && phase === "sending-tx") {
      activeDetail = "Sending transaction...";
    } else if (def.id === 6 && phase === "confirming") {
      activeDetail = "Waiting for on-chain confirmation...";
    }

    return { ...def, activeDetail, status };
  });
}

/**
 * Pure function: maps (phase, progress, error, errorAtStep) → 5 PipelineStep[] with correct statuses.
 */
export function derivePipelineSteps(
  phase: PipelinePhase,
  progress: ProofProgress | null,
  error: string | null,
  errorAtStep?: number,
): PipelineStep[] {
  // Map current state to the active step number (1-5), 0 = idle
  let activeStep = 0;
  if (phase === "loading-wasm") activeStep = 1;
  else if (phase === "proving") {
    if (progress) {
      const stage = progress.stage;
      if (stage === "trace") activeStep = 2;
      else if (stage === "commit" || stage === "compose") activeStep = 3;
      else if (stage === "fri") activeStep = 4;
      else if (stage === "done") activeStep = 5;
      else activeStep = 2; // unknown stage defaults to trace
    } else {
      activeStep = 2; // proving started but no progress yet
    }
  } else if (phase === "sending-tx" || phase === "confirming") activeStep = 5;

  return PIPELINE_STEP_DEFS.map((def) => {
    let status: PipelineStepStatus = "pending";

    // Show error on the step where it occurred, even after phase resets to idle
    if (error && errorAtStep && def.id === errorAtStep) {
      status = "error";
    } else if (error && errorAtStep && def.id < errorAtStep) {
      status = "done";
    } else if (def.id < activeStep) {
      status = "done";
    } else if (def.id === activeStep) {
      status = error && !errorAtStep ? "error" : "active";
    }

    // Use live detail from prover when available
    let activeDetail = def.activeDetail;
    if (def.id === activeStep && phase === "proving" && progress) {
      activeDetail = progress.detail;
    } else if (def.id === 5 && phase === "sending-tx") {
      activeDetail = "Sending transaction...";
    } else if (def.id === 5 && phase === "confirming") {
      activeDetail = "Waiting for on-chain confirmation...";
    }

    return { ...def, activeDetail, status };
  });
}
