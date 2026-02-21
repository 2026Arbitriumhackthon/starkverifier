"use client";

import { useState, useCallback } from "react";
import { useActiveAccount } from "thirdweb/react";
import { prepareContractCall, sendTransaction, waitForReceipt } from "thirdweb";
import { toast } from "sonner";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Download,
  BarChart3,
  GitCommitHorizontal,
  Layers,
  Globe,
  FileSearch,
  Shield,
  Check,
  Loader2,
  AlertCircle,
  ExternalLink,
  Wallet,
  TrendingUp,
} from "lucide-react";
import {
  deriveWalletPipelineSteps,
  type PipelinePhase,
  type ProofProgress,
  type PipelineStepStatus,
  NUM_QUERIES,
  ARBISCAN_TX_URL,
} from "@/lib/bot-data";
import { formatGas } from "@/lib/gas-utils";
import { fetchReceiptHashes } from "@/lib/receipt-proof";
import { fetchWalletTrades, type WalletTradeResult } from "@/lib/gmx-trades";
import {
  loadWasmProver,
  generateSharpeProofWithCommitment,
} from "@/lib/wasm-prover";
import { getStarkVerifierContract } from "@/lib/contracts";
import type { StarkProofJSON } from "@/lib/contracts";
import { client } from "@/lib/client";
import { arbitrumSepolia } from "@/lib/chains";

/* ── Network Config ──────────────────────────────── */

interface NetworkConfig {
  id: string;
  name: string;
  rpcUrl: string;
  explorerTxUrl: string;
  gmxSupported: boolean;
}

const NETWORKS: NetworkConfig[] = [
  {
    id: "arbitrum-one",
    name: "Arbitrum One",
    rpcUrl: "https://arb1.arbitrum.io/rpc",
    explorerTxUrl: "https://arbiscan.io/tx",
    gmxSupported: true,
  },
  {
    id: "arbitrum-sepolia",
    name: "Arbitrum Sepolia",
    rpcUrl: "https://sepolia-rollup.arbitrum.io/rpc",
    explorerTxUrl: "https://sepolia.arbiscan.io/tx",
    gmxSupported: false,
  },
];

/* ── Step Icons ──────────────────────────────────── */

const WALLET_STEP_ICONS = [
  Download,      // 1. Fetch Trades
  FileSearch,    // 2. Receipt Proof
  Download,      // 3. Load WASM
  BarChart3,     // 4. Generate Trace
  GitCommitHorizontal, // 5. Commit & Compose
  Layers,        // 6. FRI Protocol
  Globe,         // 7. On-Chain Verify
];

/* ── Sub-components ──────────────────────────────── */

function StepIcon({
  status,
  stepIndex,
}: {
  status: PipelineStepStatus;
  stepIndex: number;
}) {
  const Icon = WALLET_STEP_ICONS[stepIndex] ?? Shield;

  if (status === "done") {
    return (
      <div className="flex items-center justify-center w-9 h-9 rounded-full bg-green-500/20 border-2 border-green-500 shrink-0">
        <Check className="h-4 w-4 text-green-500" />
      </div>
    );
  }
  if (status === "active") {
    return (
      <div className="flex items-center justify-center w-9 h-9 rounded-full bg-orange-500/20 border-2 border-orange-500 animate-pulse shrink-0">
        <Loader2 className="h-4 w-4 text-orange-500 animate-spin" />
      </div>
    );
  }
  if (status === "error") {
    return (
      <div className="flex items-center justify-center w-9 h-9 rounded-full bg-red-500/20 border-2 border-red-500 shrink-0">
        <AlertCircle className="h-4 w-4 text-red-500" />
      </div>
    );
  }
  return (
    <div className="flex items-center justify-center w-9 h-9 rounded-full bg-muted border-2 border-muted-foreground/20 shrink-0">
      <Icon className="h-4 w-4 text-muted-foreground/50" />
    </div>
  );
}

/* ── Main Component ──────────────────────────────── */

export function WalletProver() {
  const account = useActiveAccount();

  // Form state
  const [selectedNetwork, setSelectedNetwork] = useState<string>("arbitrum-one");
  const [walletAddress, setWalletAddress] = useState("");

  // Pipeline state
  const [phase, setPhase] = useState<PipelinePhase>("idle");
  const [progress, setProgress] = useState<ProofProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorAtStep, setErrorAtStep] = useState<number | undefined>();
  const [isRunning, setIsRunning] = useState(false);

  // Trade data state (shown after fetch)
  const [tradeData, setTradeData] = useState<WalletTradeResult | null>(null);

  // Result state
  const [result, setResult] = useState<{
    txHash: string;
    verified: boolean;
    gasUsed: bigint;
    commitment: string;
    tradeCount: number;
    totalReturnBps: number;
    receiptCount: number;
  } | null>(null);

  const network = NETWORKS.find((n) => n.id === selectedNetwork)!;

  const isValidAddress =
    walletAddress.startsWith("0x") && walletAddress.length === 42;

  const getActiveStep = useCallback(
    (p: PipelinePhase, prog: ProofProgress | null): number => {
      if (p === "fetching-trades") return 1;
      if (p === "fetching-receipt-proof") return 2;
      if (p === "loading-wasm") return 3;
      if (p === "proving") {
        if (!prog) return 4;
        const s = prog.stage;
        if (s === "trace") return 4;
        if (s === "commit" || s === "compose") return 5;
        if (s === "fri") return 6;
        if (s === "done") return 7;
        return 4;
      }
      if (p === "sending-tx" || p === "confirming") return 7;
      return 0;
    },
    []
  );

  const handleRun = useCallback(async () => {
    if (!account) {
      toast.error("Please connect your wallet first");
      return;
    }
    if (!isValidAddress) {
      toast.error("Please enter a valid wallet address (0x... 42 chars)");
      return;
    }
    if (!network.gmxSupported) {
      toast.error(`GMX V2 is not available on ${network.name}. Please use Arbitrum One.`);
      return;
    }

    setIsRunning(true);
    setPhase("idle");
    setProgress(null);
    setError(null);
    setErrorAtStep(undefined);
    setResult(null);
    setTradeData(null);

    let currentPhase: PipelinePhase = "idle";
    let currentProgress: ProofProgress | null = null;

    try {
      // Step 1: Fetch GMX trades for the wallet
      currentPhase = "fetching-trades";
      setPhase(currentPhase);
      const trades = await fetchWalletTrades(
        network.rpcUrl,
        walletAddress,
        network.id,
      );
      setTradeData(trades);

      // Step 2: Fetch receipt hashes for ALL trade transactions
      currentPhase = "fetching-receipt-proof";
      setPhase(currentPhase);
      const { receiptHashes, aggregateCommitment } = await fetchReceiptHashes(
        network.rpcUrl,
        trades.txHashes,
      );

      // Step 3: Load WASM
      currentPhase = "loading-wasm";
      setPhase(currentPhase);
      await loadWasmProver();

      // Step 4-6: Generate STARK proof with aggregate commitment
      currentPhase = "proving";
      setPhase(currentPhase);
      const proof: StarkProofJSON = await generateSharpeProofWithCommitment(
        trades.returnsBps,
        aggregateCommitment,
        NUM_QUERIES,
        (p) => {
          currentProgress = p;
          setProgress(p);
        }
      );

      // Step 7: On-chain verification with commitment binding
      // Phase A: only receipt hashes (N x 32B) go on-chain — no large calldata
      currentPhase = "sending-tx";
      setPhase(currentPhase);
      const contract = getStarkVerifierContract();

      // Convert receipt hashes (Uint8Array[]) to BigInt[] for on-chain U256[]
      const receiptHashesBigInt = receiptHashes.map((h) => {
        let val = BigInt(0);
        for (const byte of h) {
          val = (val << BigInt(8)) | BigInt(byte);
        }
        return val;
      });

      const starkU256Count =
        proof.publicInputs.length + proof.commitments.length +
        proof.oodValues.length + proof.friFinalPoly.length +
        proof.queryValues.length + proof.queryPaths.length +
        proof.queryMetadata.length;
      const totalCalldataEst = (starkU256Count + receiptHashesBigInt.length) * 32;
      console.log(
        `[ProofPipeline] Phase A calldata: STARK=${starkU256Count * 32}B, ` +
        `receiptHashes=${receiptHashesBigInt.length * 32}B, Total=${totalCalldataEst}B`
      );

      const tx = prepareContractCall({
        contract,
        method: "verifySharpeWithCommitment",
        params: [
          proof.publicInputs.map(BigInt),
          proof.commitments.map(BigInt),
          proof.oodValues.map(BigInt),
          proof.friFinalPoly.map(BigInt),
          proof.queryValues.map(BigInt),
          proof.queryPaths.map(BigInt),
          proof.queryMetadata.map(BigInt),
          receiptHashesBigInt,
        ],
      });

      const txResult = await sendTransaction({
        transaction: tx,
        account,
      });

      currentPhase = "confirming";
      setPhase(currentPhase);
      const receipt = await waitForReceipt({
        client,
        chain: arbitrumSepolia,
        transactionHash: txResult.transactionHash,
      });

      setResult({
        txHash: receipt.transactionHash,
        verified: receipt.status === "success",
        gasUsed: receipt.gasUsed,
        commitment: aggregateCommitment,
        tradeCount: trades.tradeCount,
        totalReturnBps: trades.totalReturnBps,
        receiptCount: receiptHashes.length,
      });

      if (receipt.status === "success") {
        toast.success(
          `Wallet verified! ${trades.tradeCount} trades, ${receiptHashes.length} receipts, Gas: ${formatGas(receipt.gasUsed)}`
        );
      } else {
        toast.error("Verification transaction reverted");
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Unknown error occurred";
      setError(message);
      setErrorAtStep(getActiveStep(currentPhase, currentProgress));
      toast.error(`Failed: ${message}`);
    } finally {
      setIsRunning(false);
      setPhase("idle");
      setProgress(null);
    }
  }, [account, walletAddress, network, isValidAddress, getActiveStep]);

  const steps = deriveWalletPipelineSteps(phase, progress, error, errorAtStep);

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Network Selector */}
      <div className="grid grid-cols-2 gap-3">
        {NETWORKS.map((net) => (
          <button
            key={net.id}
            onClick={() => !isRunning && setSelectedNetwork(net.id)}
            disabled={isRunning}
            className={`relative rounded-lg border p-4 text-left transition-all ${
              selectedNetwork === net.id
                ? "border-transparent bg-gradient-to-r from-orange-500/10 to-purple-600/10 ring-2 ring-orange-500/50"
                : "border-muted-foreground/15 hover:border-muted-foreground/30"
            } ${isRunning ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`flex items-center justify-center w-8 h-8 rounded-md ${
                  net.id === "arbitrum-one"
                    ? "bg-blue-500/10"
                    : "bg-orange-500/10"
                }`}
              >
                <Globe
                  className={`h-4 w-4 ${
                    net.id === "arbitrum-one"
                      ? "text-blue-500"
                      : "text-orange-500"
                  }`}
                />
              </div>
              <div>
                <p className="text-sm font-medium">{net.name}</p>
                <p className="text-xs text-muted-foreground">
                  {net.id === "arbitrum-one" ? "Mainnet" : "Testnet"}
                  {!net.gmxSupported && " (No GMX)"}
                </p>
              </div>
            </div>
          </button>
        ))}
      </div>

      {/* Wallet Address Input */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base flex items-center gap-2">
            <Wallet className="h-4 w-4" />
            Trader Wallet Address
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">
            Enter a GMX V2 trader&apos;s wallet address on {network.name}.
            We&apos;ll fetch their trade history, compute Sharpe ratio, and verify it on-chain.
          </p>
          <input
            type="text"
            placeholder="0x..."
            value={walletAddress}
            onChange={(e) => setWalletAddress(e.target.value.trim())}
            disabled={isRunning}
            className="w-full rounded-md border bg-background px-3 py-2 text-sm font-mono placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-orange-500/50 disabled:opacity-50"
          />
          {walletAddress && !isValidAddress && (
            <p className="text-xs text-red-500">
              Invalid address format. Must be 0x followed by 40 hex characters.
            </p>
          )}
          {!network.gmxSupported && (
            <p className="text-xs text-orange-500">
              GMX V2 is only available on Arbitrum One. Please switch networks.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Trade Data Summary (after fetch) */}
      {tradeData && (
        <Card className="border-blue-500/20 bg-blue-500/5">
          <CardContent className="pt-4">
            <div className="flex items-center gap-2 mb-3">
              <TrendingUp className="h-4 w-4 text-blue-500" />
              <span className="text-sm font-medium">Fetched Trade Data</span>
              <Badge variant="outline" className="text-xs">
                {tradeData.tradeCount} trades
                {tradeData.totalEventsFound > tradeData.tradeCount &&
                  ` (of ${tradeData.totalEventsFound} total)`}
              </Badge>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <span className="text-muted-foreground">Total Return</span>
                <p className={`font-mono font-medium ${
                  tradeData.totalReturnBps >= 0 ? "text-green-500" : "text-red-500"
                }`}>
                  {tradeData.totalReturnBps >= 0 ? "+" : ""}{tradeData.totalReturnBps} bps
                </p>
              </div>
              <div>
                <span className="text-muted-foreground">Block Range</span>
                <p className="font-mono text-xs">
                  {tradeData.fromBlock.toLocaleString()} ~ {tradeData.toBlock.toLocaleString()}
                </p>
              </div>
              <div>
                <span className="text-muted-foreground">TX Count</span>
                <p className="font-mono">{tradeData.txHashes.length}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Avg Return</span>
                <p className={`font-mono ${
                  tradeData.totalReturnBps / tradeData.tradeCount >= 0
                    ? "text-green-500"
                    : "text-red-500"
                }`}>
                  {Math.round(tradeData.totalReturnBps / tradeData.tradeCount)} bps/trade
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Pipeline Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">
            Wallet Proof Pipeline
            <Badge variant="outline" className="ml-2 text-xs">
              7 Steps
            </Badge>
          </CardTitle>
        </CardHeader>
        <CardContent>
          {steps.map((step, i) => (
            <div key={step.id} className="flex gap-4">
              <div className="flex flex-col items-center">
                <StepIcon status={step.status} stepIndex={i} />
                {i < steps.length - 1 && (
                  <div
                    className={`w-0.5 flex-1 my-1 ${
                      step.status === "done"
                        ? "bg-green-500/40"
                        : "bg-muted-foreground/15"
                    }`}
                  />
                )}
              </div>
              <div className={i < steps.length - 1 ? "pb-6" : ""}>
                <p
                  className={`text-sm font-medium ${
                    step.status === "active"
                      ? "text-foreground"
                      : step.status === "done"
                        ? "text-green-500"
                        : step.status === "error"
                          ? "text-red-500"
                          : "text-muted-foreground/60"
                  }`}
                >
                  {step.title}
                </p>
                <p className="text-xs text-muted-foreground">{step.subtitle}</p>
                {step.status === "active" && (
                  <p className="text-xs text-orange-500 mt-1">
                    {step.activeDetail}
                  </p>
                )}
                {step.status === "error" && (
                  <p className="text-xs text-red-500 mt-1">
                    Failed at this step
                  </p>
                )}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Run Button */}
      <Button
        onClick={handleRun}
        disabled={isRunning || !isValidAddress || !network.gmxSupported}
        className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
        size="lg"
      >
        {isRunning ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Running Pipeline...
          </>
        ) : (
          <>
            <Shield className="h-4 w-4" />
            Verify Wallet Trades
          </>
        )}
      </Button>

      {/* Error Display */}
      {error && !isRunning && (
        <div className="p-4 rounded-lg border border-red-500/20 bg-red-500/5 text-red-500 text-sm">
          {error}
        </div>
      )}

      {/* Result Card */}
      {result && !isRunning && (
        <Card
          className={
            result.verified
              ? "border-green-500/20 bg-green-500/5"
              : "border-red-500/20 bg-red-500/5"
          }
        >
          <CardContent className="pt-4 space-y-3">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className={
                  result.verified
                    ? "bg-green-500/10 text-green-500 border-green-500/20"
                    : "bg-red-500/10 text-red-500 border-red-500/20"
                }
              >
                {result.verified ? "Verified" : "Failed"}
              </Badge>
              <Badge variant="outline" className="text-xs">
                {result.tradeCount} Trades
              </Badge>
              <Badge variant="outline" className="text-xs bg-green-500/10 text-green-500 border-green-500/20">
                Commitment On-Chain ({result.receiptCount} receipts)
              </Badge>
            </div>

            <div className="space-y-2 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Wallet</span>
                <span className="font-mono text-xs">
                  {walletAddress.slice(0, 10)}...{walletAddress.slice(-6)}
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Total Return</span>
                <span className={`font-mono ${
                  result.totalReturnBps >= 0 ? "text-green-500" : "text-red-500"
                }`}>
                  {result.totalReturnBps >= 0 ? "+" : ""}{result.totalReturnBps} bps
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Commitment</span>
                <span className="font-mono text-xs">
                  {result.commitment.slice(0, 14)}...
                </span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Gas Used</span>
                <span className="font-mono">{formatGas(result.gasUsed)}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Proof TX</span>
                <a
                  href={`${ARBISCAN_TX_URL}/${result.txHash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors font-mono"
                >
                  {result.txHash.slice(0, 10)}...
                  <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
