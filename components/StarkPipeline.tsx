"use client";

import { useState, useCallback } from "react";
import {
  useActiveAccount,
  useActiveWalletConnectionStatus,
} from "thirdweb/react";
import { prepareContractCall, prepareTransaction, sendAndConfirmTransaction, encode } from "thirdweb";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  getStarkVerifierContract,
  STARK_VERIFIER_V4_ADDRESS,
  type StarkProofJSON,
} from "@/lib/contracts";
import { client } from "@/lib/client";
import { arbitrumSepolia } from "@/lib/chains";
import { useGas } from "@/lib/gas-context";
import { getArbitrumReceiptWithL1Gas, formatGas } from "@/lib/gas-utils";
import { toast } from "@/components/ui/sonner";
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Zap,
  Shield,
  ExternalLink,
  FileDown,
  Code2,
  Send,
} from "lucide-react";

interface PipelineStage {
  name: string;
  label: string;
  icon: React.ReactNode;
  status: "pending" | "running" | "done" | "error";
  detail?: string;
  timeMs?: number;
}

const makeInitialStages = (): PipelineStage[] => [
  { name: "load", label: "Load Proof", icon: <FileDown className="h-4 w-4" />, status: "pending" },
  { name: "encode", label: "Encode Calldata", icon: <Code2 className="h-4 w-4" />, status: "pending" },
  { name: "verify", label: "On-chain Verify", icon: <Send className="h-4 w-4" />, status: "pending" },
];

interface ProofSummary {
  fibN: number;
  claimedResult: number;
  numQueries: number;
  numFriLayers: number;
  logTraceLen: number;
  numCommitments: number;
  numOodValues: number;
  numQueryValues: number;
  numQueryPaths: number;
  calldataBytes: number;
}

interface GasBreakdown {
  totalGas: bigint;
  l1Gas: bigint;
  l2Gas: bigint;
  effectiveGasPrice: bigint;
  ethCost: string;
}

export function StarkPipeline() {
  const account = useActiveAccount();
  const connectionStatus = useActiveWalletConnectionStatus();
  const [stages, setStages] = useState<PipelineStage[]>(makeInitialStages());
  const [isRunning, setIsRunning] = useState(false);
  const [result, setResult] = useState<{
    valid: boolean;
    gasUsed: bigint;
    txHash: string;
  } | null>(null);
  const [proofSummary, setProofSummary] = useState<ProofSummary | null>(null);
  const [gasBreakdown, setGasBreakdown] = useState<GasBreakdown | null>(null);

  const { addMeasurement } = useGas();

  const updateStage = useCallback((name: string, update: Partial<PipelineStage>) => {
    setStages((prev) =>
      prev.map((s) => (s.name === name ? { ...s, ...update } : s))
    );
  }, []);

  const runPipeline = async () => {
    if (!account?.address) return;

    setIsRunning(true);
    setResult(null);
    setProofSummary(null);
    setGasBreakdown(null);
    setStages(makeInitialStages());

    try {
      // Step 1: Load pre-generated proof
      const t0 = performance.now();
      updateStage("load", { status: "running", detail: "Fetching pre-generated proof..." });

      let proof: StarkProofJSON;
      try {
        const resp = await fetch("/proof.json");
        if (!resp.ok) throw new Error("No proof available");
        proof = await resp.json();
      } catch {
        updateStage("load", { status: "error", detail: "proof.json not found. Run prover CLI first." });
        toast.error("Proof Not Found", {
          description: "Place proof.json in /public by running: cargo run --release -p stark-prover -- --fib-n 8 --num-queries 4",
        });
        setIsRunning(false);
        return;
      }

      // Extract proof metadata
      const numQueries = Number(BigInt(proof.queryMetadata[0]));
      const numFriLayers = Number(BigInt(proof.queryMetadata[1]));
      const logTraceLen = Number(BigInt(proof.queryMetadata[2]));
      const claimedResult = Number(BigInt(proof.publicInputs[2]));
      // fib(8) = 34 = 0x22, derive fibN from trace length
      const fibN = (1 << logTraceLen);

      const summary: ProofSummary = {
        fibN,
        claimedResult,
        numQueries,
        numFriLayers,
        logTraceLen,
        numCommitments: proof.commitments.length,
        numOodValues: proof.oodValues.length,
        numQueryValues: proof.queryValues.length,
        numQueryPaths: proof.queryPaths.length,
        calldataBytes: 0, // filled in next step
      };

      const t1 = performance.now();
      updateStage("load", {
        status: "done",
        timeMs: t1 - t0,
        detail: `fib(${fibN}) = ${claimedResult}, ${numQueries} queries, ${numFriLayers} FRI layers`,
      });

      // Step 2: Encode calldata
      updateStage("encode", { status: "running", detail: "ABI-encoding verifyStarkProof calldata..." });

      const contract = getStarkVerifierContract();
      const toBigInts = (arr: string[]) => arr.map((v) => BigInt(v));

      const encodeTx = prepareContractCall({
        contract,
        method: "verifyStarkProof",
        params: [
          toBigInts(proof.publicInputs),
          toBigInts(proof.commitments),
          toBigInts(proof.oodValues),
          toBigInts(proof.friFinalPoly),
          toBigInts(proof.queryValues),
          toBigInts(proof.queryPaths),
          toBigInts(proof.queryMetadata),
        ],
      } as Parameters<typeof prepareContractCall>[0]);

      const calldata = await encode(encodeTx);
      const calldataBytes = calldata.length / 2 - 1; // hex string → bytes (minus 0x prefix)
      summary.calldataBytes = calldataBytes;
      setProofSummary(summary);

      const t2 = performance.now();
      updateStage("encode", {
        status: "done",
        timeMs: t2 - t1,
        detail: `${calldataBytes.toLocaleString()} bytes calldata`,
      });

      // Step 3: Submit on-chain
      updateStage("verify", { status: "running", detail: "Submitting to Arbitrum Sepolia..." });

      const tx = prepareTransaction({
        client,
        chain: arbitrumSepolia,
        to: STARK_VERIFIER_V4_ADDRESS,
        data: calldata,
        gas: BigInt(40_000_000),
        maxFeePerGas: BigInt(100_000_000), // 0.1 gwei
        maxPriorityFeePerGas: BigInt(1_000_000),
      });

      const receipt = await sendAndConfirmTransaction({
        account: account!,
        transaction: tx,
      });

      const gasUsed = receipt.gasUsed;
      const t3 = performance.now();

      // Fetch L1/L2 gas breakdown from Arbitrum RPC
      const effectiveGasPrice = receipt.effectiveGasPrice ?? BigInt(0);
      let gasInfo: GasBreakdown = {
        totalGas: gasUsed,
        l1Gas: BigInt(0),
        l2Gas: gasUsed,
        effectiveGasPrice,
        ethCost: formatEthCost(gasUsed, effectiveGasPrice),
      };

      try {
        const arbReceipt = await getArbitrumReceiptWithL1Gas(receipt.transactionHash);
        if (arbReceipt?.gasUsedForL1) {
          gasInfo = {
            totalGas: arbReceipt.gasUsed,
            l1Gas: arbReceipt.gasUsedForL1,
            l2Gas: arbReceipt.gasUsed - arbReceipt.gasUsedForL1,
            effectiveGasPrice,
            ethCost: formatEthCost(arbReceipt.gasUsed, effectiveGasPrice),
          };
        }
      } catch {
        // L1/L2 breakdown unavailable, use totals
      }

      setGasBreakdown(gasInfo);

      updateStage("verify", {
        status: "done",
        timeMs: t3 - t2,
        detail: `Total: ${formatGas(gasInfo.totalGas)} gas`,
      });

      setResult({
        valid: receipt.status === "success",
        gasUsed: gasInfo.totalGas,
        txHash: receipt.transactionHash,
      });

      addMeasurement({
        type: "stylus",
        operation: "stark",
        depth: 0,
        gasUsed: gasInfo.totalGas,
        txHash: receipt.transactionHash,
        timestamp: Date.now(),
        starkParams: {
          fibN,
          numQueries,
          numFriLayers,
        },
      });

      toast.success("STARK Proof Verified On-Chain", {
        description: `Gas: ${formatGas(gasInfo.totalGas)} | Cost: ${gasInfo.ethCost}`,
      });
    } catch (error: unknown) {
      const errorMsg = error instanceof Error ? error.message : "Unknown error";

      setStages((prev) => {
        const running = prev.find((s) => s.status === "running");
        if (running) {
          return prev.map((s) =>
            s.name === running.name ? { ...s, status: "error" as const, detail: errorMsg.slice(0, 80) } : s
          );
        }
        return prev;
      });

      if (errorMsg.includes("rejected") || errorMsg.includes("denied")) {
        toast.warning("Transaction Rejected");
      } else {
        toast.error("Pipeline Failed", { description: errorMsg.slice(0, 100) });
      }
    } finally {
      setIsRunning(false);
    }
  };

  if (!account) {
    return (
      <Card className="border-dashed">
        <CardContent className="flex flex-col items-center justify-center py-12 text-center">
          <div className="rounded-full bg-muted p-4 mb-4">
            <Shield className="h-8 w-8 text-muted-foreground" />
          </div>
          <h3 className="font-semibold text-lg mb-2">Connect Your Wallet</h3>
          <p className="text-muted-foreground text-sm max-w-sm">
            Connect your wallet to verify STARK proofs on-chain
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5 text-orange-500" />
          STARK Proof Pipeline
        </CardTitle>
        <CardDescription>
          Load a pre-generated STARK proof and verify it on Arbitrum Stylus
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Verify Button */}
        <Button
          onClick={runPipeline}
          disabled={isRunning || (connectionStatus === "disconnected" && !account?.address)}
          className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700"
          size="lg"
        >
          {isRunning ? (
            <>
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              Running Pipeline...
            </>
          ) : (
            <>
              <Zap className="mr-2 h-4 w-4" />
              Load Proof &amp; Verify On-Chain
            </>
          )}
        </Button>

        {/* Pipeline Stages */}
        <div className="space-y-3">
          {stages.map((stage, i) => (
            <div
              key={stage.name}
              className={`flex items-center justify-between p-3 rounded-lg border ${
                stage.status === "running"
                  ? "border-orange-500/50 bg-orange-500/5"
                  : stage.status === "done"
                    ? "border-green-500/30 bg-green-500/5"
                    : stage.status === "error"
                      ? "border-red-500/30 bg-red-500/5"
                      : "border-border"
              }`}
            >
              <div className="flex items-center gap-3">
                <span className="text-sm font-mono text-muted-foreground w-5">
                  {i + 1}
                </span>
                <div>
                  <div className="text-sm font-medium flex items-center gap-2">
                    {stage.icon}
                    {stage.label}
                  </div>
                  {stage.detail && (
                    <div className="text-xs text-muted-foreground mt-0.5">{stage.detail}</div>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-2">
                {stage.timeMs !== undefined && (
                  <span className="text-xs font-mono text-muted-foreground">
                    {stage.timeMs < 1000
                      ? `${Math.round(stage.timeMs)}ms`
                      : `${(stage.timeMs / 1000).toFixed(1)}s`}
                  </span>
                )}
                {stage.status === "running" && (
                  <Loader2 className="h-4 w-4 animate-spin text-orange-500" />
                )}
                {stage.status === "done" && (
                  <CheckCircle2 className="h-4 w-4 text-green-500" />
                )}
                {stage.status === "error" && (
                  <XCircle className="h-4 w-4 text-red-500" />
                )}
                {stage.status === "pending" && (
                  <div className="h-4 w-4 rounded-full border-2 border-muted-foreground/30" />
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Proof Summary */}
        {proofSummary && (
          <div className="rounded-lg border p-4 space-y-3">
            <h4 className="text-sm font-semibold">Proof Structure</h4>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-xs">
              <div className="flex justify-between">
                <span className="text-muted-foreground">Fibonacci</span>
                <span className="font-mono">fib({proofSummary.fibN}) = {proofSummary.claimedResult}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">FRI Queries</span>
                <span className="font-mono">{proofSummary.numQueries}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">FRI Layers</span>
                <span className="font-mono">{proofSummary.numFriLayers}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Trace Length</span>
                <span className="font-mono">2^{proofSummary.logTraceLen} = {1 << proofSummary.logTraceLen}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Commitments</span>
                <span className="font-mono">{proofSummary.numCommitments} roots</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">OOD Evaluations</span>
                <span className="font-mono">{proofSummary.numOodValues} values</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Query Values</span>
                <span className="font-mono">{proofSummary.numQueryValues} elements</span>
              </div>
              <div className="flex justify-between">
                <span className="text-muted-foreground">Merkle Paths</span>
                <span className="font-mono">{proofSummary.numQueryPaths} hashes</span>
              </div>
              <div className="col-span-2 flex justify-between border-t pt-2 mt-1">
                <span className="text-muted-foreground">Calldata Size</span>
                <span className="font-mono">{(proofSummary.calldataBytes / 1024).toFixed(1)} KB ({proofSummary.calldataBytes.toLocaleString()} bytes)</span>
              </div>
            </div>
          </div>
        )}

        {/* Result */}
        {result && (
          <div
            className={`rounded-lg border p-4 space-y-3 ${
              result.valid
                ? "border-green-500/30 bg-green-500/10"
                : "border-red-500/30 bg-red-500/10"
            }`}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {result.valid ? (
                  <CheckCircle2 className="h-5 w-5 text-green-500" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-500" />
                )}
                <span className="font-semibold">
                  {result.valid ? "Proof Valid" : "Proof Invalid"}
                </span>
              </div>
              <Badge variant="outline" className="font-mono">
                {formatGas(result.gasUsed)} gas
              </Badge>
            </div>

            {/* Gas Breakdown */}
            {gasBreakdown && (
              <div className="grid grid-cols-3 gap-3 text-xs">
                <div className="rounded-md bg-background/50 p-2 text-center">
                  <div className="text-muted-foreground">Total Gas</div>
                  <div className="font-mono font-semibold">{formatGas(gasBreakdown.totalGas)}</div>
                </div>
                <div className="rounded-md bg-background/50 p-2 text-center">
                  <div className="text-muted-foreground">L2 Execution</div>
                  <div className="font-mono font-semibold">{formatGas(gasBreakdown.l2Gas)}</div>
                </div>
                <div className="rounded-md bg-background/50 p-2 text-center">
                  <div className="text-muted-foreground">L1 Data</div>
                  <div className="font-mono font-semibold">{formatGas(gasBreakdown.l1Gas)}</div>
                </div>
              </div>
            )}

            {/* TX Hash & Cost */}
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              <div className="flex items-center gap-2">
                <span className="font-mono">{result.txHash.slice(0, 18)}...</span>
                <a
                  href={`https://sepolia.arbiscan.io/tx/${result.txHash}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-blue-500 hover:underline flex items-center gap-1"
                >
                  <ExternalLink className="h-3 w-3" />
                  Arbiscan
                </a>
              </div>
              {gasBreakdown && (
                <span className="font-mono">{gasBreakdown.ethCost} ETH</span>
              )}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function formatEthCost(gas: bigint, gasPrice: bigint): string {
  if (gasPrice === BigInt(0)) return "~0";
  const weiCost = gas * gasPrice;
  const ethCost = Number(weiCost) / 1e18;
  if (ethCost < 0.0001) return "<0.0001";
  return ethCost.toFixed(4);
}
