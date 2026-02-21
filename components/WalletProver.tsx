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
  Loader2,
  Search,
  Shield,
  TrendingUp,
  TrendingDown,
  AlertCircle,
  Check,
  Download,
  BarChart3,
  GitCommitHorizontal,
  Layers,
  Globe,
  ExternalLink,
} from "lucide-react";
import {
  fetchGmxTrades,
  tradesToReturnBps,
  type GmxTradeResult,
  type GmxFetchProgress,
} from "@/lib/gmx-fetcher";
import { loadWasmProver, generateSharpeProofFromReturns } from "@/lib/wasm-prover";
import { getStarkVerifierContract } from "@/lib/contracts";
import type { StarkProofJSON } from "@/lib/contracts";
import { formatGas, getArbitrumReceiptWithL1Gas } from "@/lib/gas-utils";
import { client } from "@/lib/client";
import { arbitrumSepolia } from "@/lib/chains";
import {
  NUM_QUERIES,
  ARBISCAN_TX_URL,
  deriveWalletPipelineSteps,
  type PipelinePhase,
  type ProofProgress,
  type VerificationRecord,
  type PipelineStepStatus,
} from "@/lib/bot-data";

const STEP_ICONS = [Search, Download, BarChart3, GitCommitHorizontal, Layers, Globe];

function StepIcon({ status, stepIndex }: { status: PipelineStepStatus; stepIndex: number }) {
  const Icon = STEP_ICONS[stepIndex] ?? Globe;

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

interface WalletProverProps {
  records: VerificationRecord[];
  onRecordAdd: (record: VerificationRecord) => void;
}

export function WalletProver({ records, onRecordAdd }: WalletProverProps) {
  const account = useActiveAccount();
  const [walletInput, setWalletInput] = useState("");
  const [trades, setTrades] = useState<GmxTradeResult[]>([]);
  const [fetchProgress, setFetchProgress] = useState<GmxFetchProgress | null>(null);
  const [phase, setPhase] = useState<PipelinePhase>("idle");
  const [progress, setProgress] = useState<ProofProgress | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [errorAtStep, setErrorAtStep] = useState<number | undefined>();

  const walletAddress = walletInput || account?.address || "";
  const isProcessing = phase !== "idle";

  const handleFetchTrades = useCallback(async () => {
    if (!walletAddress) {
      toast.error("Please enter a wallet address");
      return;
    }

    setTrades([]);
    setError(null);
    setErrorAtStep(undefined);
    setPhase("fetching-trades");

    try {
      const result = await fetchGmxTrades(walletAddress, setFetchProgress);
      setTrades(result);
      setPhase("idle");

      if (result.length === 0) {
        toast.error("No GMX trades found for this wallet");
      } else {
        toast.success(`Found ${result.length} GMX trades`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to fetch trades";
      setError(message);
      setErrorAtStep(1);
      setPhase("idle");
      toast.error(message);
    } finally {
      setFetchProgress(null);
    }
  }, [walletAddress]);

  const handleProveAndVerify = useCallback(async () => {
    if (!account) {
      toast.error("Please connect your wallet first");
      return;
    }
    if (trades.length < 2) {
      toast.error("Need at least 2 trades for Sharpe ratio proof");
      return;
    }

    setError(null);
    setErrorAtStep(undefined);
    setProgress(null);

    try {
      // Phase 1: Load WASM
      setPhase("loading-wasm");
      await loadWasmProver();

      // Phase 2: Generate proof
      setPhase("proving");
      const returnsBps = tradesToReturnBps(trades);
      const proof: StarkProofJSON = await generateSharpeProofFromReturns(
        returnsBps,
        NUM_QUERIES,
        (p) => setProgress(p)
      );

      // Phase 3: Send transaction
      setPhase("sending-tx");
      const contract = getStarkVerifierContract();
      const tx = prepareContractCall({
        contract,
        method: "verifySharpeProof",
        params: [
          proof.publicInputs.map(BigInt),
          proof.commitments.map(BigInt),
          proof.oodValues.map(BigInt),
          proof.friFinalPoly.map(BigInt),
          proof.queryValues.map(BigInt),
          proof.queryPaths.map(BigInt),
          proof.queryMetadata.map(BigInt),
        ],
      });

      const txResult = await sendTransaction({
        transaction: tx,
        account,
      });

      // Phase 4: Wait for confirmation
      setPhase("confirming");
      const receipt = await waitForReceipt({
        client,
        chain: arbitrumSepolia,
        transactionHash: txResult.transactionHash,
      });

      const arbReceipt = await getArbitrumReceiptWithL1Gas(
        receipt.transactionHash
      );
      const gasUsed = arbReceipt?.gasUsed ?? receipt.gasUsed;

      const record: VerificationRecord = {
        botId: `${walletAddress.slice(0, 6)}...${walletAddress.slice(-4)}`,
        botName: `GMX Wallet`,
        txHash: receipt.transactionHash,
        verified: receipt.status === "success",
        gasUsed,
        timestamp: Date.now(),
      };

      onRecordAdd(record);

      if (receipt.status === "success") {
        toast.success(`Wallet verified! Gas: ${formatGas(gasUsed)}`);
      } else {
        toast.error("Verification transaction reverted");
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : "Unknown error occurred";
      setError(message);
      // Determine which step failed
      if (phase === "loading-wasm") setErrorAtStep(2);
      else if (phase === "proving") setErrorAtStep(3);
      else if (phase === "sending-tx") setErrorAtStep(6);
      else if (phase === "confirming") setErrorAtStep(6);
      toast.error(`Verification failed: ${message}`);
    } finally {
      setPhase("idle");
      setProgress(null);
    }
  }, [account, trades, walletAddress, onRecordAdd, phase]);

  const totalReturnBps = trades.reduce((sum, t) => sum + t.returnBps, 0);
  const steps = deriveWalletPipelineSteps(phase, progress, error, errorAtStep);

  // Wallet record for display
  const latestRecord = records.find(
    (r) => r.botName === "GMX Wallet"
  );

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Wallet Address Input */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">GMX Wallet Address</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex gap-3">
            <input
              type="text"
              value={walletInput}
              onChange={(e) => setWalletInput(e.target.value)}
              placeholder={account?.address || "0x..."}
              disabled={isProcessing}
              className="flex-1 rounded-lg border border-muted-foreground/20 bg-background px-4 py-2 text-sm font-mono placeholder:text-muted-foreground/40 focus:outline-none focus:ring-2 focus:ring-orange-500/50 disabled:opacity-50"
            />
            <Button
              onClick={handleFetchTrades}
              disabled={isProcessing || !walletAddress}
              className="bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
            >
              {phase === "fetching-trades" ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Fetching...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Fetch Trades
                </>
              )}
            </Button>
          </div>

          {/* Fetch Progress */}
          {fetchProgress && phase === "fetching-trades" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="text-muted-foreground">{fetchProgress.detail}</span>
                <span className="font-mono text-muted-foreground">
                  {fetchProgress.tradesFound} trades found
                </span>
              </div>
              <div className="h-2 rounded-full bg-muted overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-orange-500 to-purple-600 transition-all duration-300"
                  style={{
                    width: `${
                      fetchProgress.totalBlocks > 0
                        ? (fetchProgress.blocksProcessed / fetchProgress.totalBlocks) * 100
                        : 0
                    }%`,
                  }}
                />
              </div>
            </div>
          )}

          {account?.address && !walletInput && (
            <p className="text-xs text-muted-foreground">
              Using connected wallet address. Enter a different address above to analyze another trader.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Trade Summary */}
      {trades.length > 0 && (
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">Trade Summary</CardTitle>
              <Badge
                variant="outline"
                className="bg-blue-500/10 text-blue-500 border-blue-500/20"
              >
                {trades.length} trades
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {/* Stats */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-1">
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <TrendingUp className="h-3 w-3" />
                  Total Return
                </div>
                <p
                  className={`text-xl font-bold ${
                    totalReturnBps >= 0 ? "text-green-500" : "text-red-500"
                  }`}
                >
                  {totalReturnBps >= 0 ? "+" : ""}
                  {(totalReturnBps / 100).toFixed(1)}%
                </p>
              </div>
              <div className="space-y-1">
                <div className="flex items-center gap-1 text-xs text-muted-foreground">
                  <BarChart3 className="h-3 w-3" />
                  Win Rate
                </div>
                <p className="text-xl font-bold">
                  {((trades.filter((t) => t.returnBps > 0).length / trades.length) * 100).toFixed(0)}%
                </p>
              </div>
            </div>

            {/* Individual trades (scrollable) */}
            <div className="max-h-48 overflow-y-auto space-y-1 rounded-lg border border-muted-foreground/10 p-2">
              {trades.map((trade, i) => (
                <div
                  key={`${trade.txHash}-${i}`}
                  className="flex items-center justify-between text-xs py-1 px-2 rounded hover:bg-muted/50"
                >
                  <div className="flex items-center gap-2">
                    {trade.returnBps >= 0 ? (
                      <TrendingUp className="h-3 w-3 text-green-500" />
                    ) : (
                      <TrendingDown className="h-3 w-3 text-red-500" />
                    )}
                    <span className="text-muted-foreground">
                      #{i + 1} {trade.isLong ? "Long" : "Short"}
                    </span>
                  </div>
                  <span
                    className={`font-mono ${
                      trade.returnBps >= 0 ? "text-green-500" : "text-red-500"
                    }`}
                  >
                    {trade.returnBps >= 0 ? "+" : ""}
                    {trade.returnBps} bps
                  </span>
                </div>
              ))}
            </div>

            {trades.length > 100 && (
              <p className="text-xs text-yellow-500">
                Large dataset ({trades.length} trades). Proof generation may take a few minutes.
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Pipeline Timeline */}
      {(isProcessing || error || latestRecord) && (
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-base">Proof Pipeline</CardTitle>
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
                    <p className="text-xs text-orange-500 mt-1">{step.activeDetail}</p>
                  )}
                  {step.status === "error" && (
                    <p className="text-xs text-red-500 mt-1">Failed at this step</p>
                  )}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {/* Error Display */}
      {error && (
        <div className="p-4 rounded-lg border border-red-500/20 bg-red-500/5 text-red-500 text-sm">
          {error}
        </div>
      )}

      {/* Prove & Verify Button */}
      {trades.length >= 2 && (
        <Button
          onClick={handleProveAndVerify}
          disabled={isProcessing || !account}
          className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
          size="lg"
        >
          {isProcessing && phase !== "fetching-trades" ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {phase === "loading-wasm"
                ? "Loading WASM..."
                : phase === "proving"
                  ? "Generating Proof..."
                  : phase === "sending-tx"
                    ? "Sending Transaction..."
                    : "Confirming..."}
            </>
          ) : (
            <>
              <Shield className="h-4 w-4" />
              Generate Proof & Verify On-Chain
            </>
          )}
        </Button>
      )}

      {/* Latest verification result */}
      {!isProcessing && latestRecord && (
        <Card className="border-green-500/20 bg-green-500/5">
          <CardContent className="pt-4 space-y-3">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className={
                  latestRecord.verified
                    ? "bg-green-500/10 text-green-500 border-green-500/20"
                    : "bg-red-500/10 text-red-500 border-red-500/20"
                }
              >
                {latestRecord.verified ? "Verified" : "Failed"}
              </Badge>
              <span className="text-sm text-muted-foreground">
                {latestRecord.botId} — {latestRecord.botName}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Gas Used</span>
              <span className="font-mono">{formatGas(latestRecord.gasUsed)}</span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Transaction</span>
              <a
                href={`${ARBISCAN_TX_URL}/${latestRecord.txHash}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors font-mono"
              >
                {latestRecord.txHash.slice(0, 10)}...
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
