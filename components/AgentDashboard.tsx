"use client";

import { useState, useCallback } from "react";
import { useActiveAccount } from "thirdweb/react";
import { prepareContractCall, sendTransaction, waitForReceipt } from "thirdweb";
import { toast } from "sonner";
import { ExternalLink, LayoutDashboard, GitBranch, Wallet } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { AgentCard } from "@/components/AgentCard";
import { ProofPipeline } from "@/components/ProofPipeline";
import { WalletProver } from "@/components/WalletProver";
import { getStarkVerifierContract } from "@/lib/contracts";
import type { StarkProofJSON } from "@/lib/contracts";
import { formatGas, getArbitrumReceiptWithL1Gas } from "@/lib/gas-utils";
import { loadWasmProver, generateSharpeProof } from "@/lib/wasm-prover";
import {
  BOTS,
  NUM_QUERIES,
  ARBISCAN_TX_URL,
  type BotProfile,
  type PipelinePhase,
  type ProofProgress,
  type VerificationRecord,
} from "@/lib/bot-data";
import { client } from "@/lib/client";
import { arbitrumSepolia } from "@/lib/chains";

export function AgentDashboard() {
  const account = useActiveAccount();
  const [verifyingBotId, setVerifyingBotId] = useState<string | null>(null);
  const [phase, setPhase] = useState<PipelinePhase>("idle");
  const [progress, setProgress] = useState<ProofProgress | null>(null);
  const [records, setRecords] = useState<VerificationRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [errorAtStep, setErrorAtStep] = useState<number | undefined>(undefined);

  // Map phase to step number for error tracking
  const getActiveStep = useCallback((p: PipelinePhase, prog: ProofProgress | null): number => {
    if (p === "loading-wasm") return 1;
    if (p === "proving") {
      if (!prog) return 2;
      const s = prog.stage;
      if (s === "trace") return 2;
      if (s === "commit" || s === "compose") return 3;
      if (s === "fri") return 4;
      if (s === "done") return 5;
      return 2;
    }
    if (p === "sending-tx" || p === "confirming") return 5;
    return 0;
  }, []);

  const handleVerify = useCallback(
    async (bot: BotProfile) => {
      if (!account) {
        toast.error("Please connect your wallet first");
        return;
      }

      setVerifyingBotId(bot.id);
      setPhase("idle");
      setProgress(null);
      setError(null);
      setErrorAtStep(undefined);

      let currentPhase: PipelinePhase = "idle";
      let currentProgress: ProofProgress | null = null;

      try {
        // Phase 1: Load WASM
        currentPhase = "loading-wasm";
        setPhase(currentPhase);
        await loadWasmProver();

        // Phase 2: Generate proof
        currentPhase = "proving";
        setPhase(currentPhase);
        const proof: StarkProofJSON = await generateSharpeProof(
          bot.id,
          NUM_QUERIES,
          (p) => {
            currentProgress = p;
            setProgress(p);
          }
        );

        // Phase 3: Send transaction
        currentPhase = "sending-tx";
        setPhase(currentPhase);
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
        currentPhase = "confirming";
        setPhase(currentPhase);
        const receipt = await waitForReceipt({
          client,
          chain: arbitrumSepolia,
          transactionHash: txResult.transactionHash,
        });

        // Fetch Arbitrum gas details
        const arbReceipt = await getArbitrumReceiptWithL1Gas(
          receipt.transactionHash
        );

        const gasUsed = arbReceipt?.gasUsed ?? receipt.gasUsed;

        const record: VerificationRecord = {
          botId: bot.id,
          botName: bot.name,
          txHash: receipt.transactionHash,
          verified: receipt.status === "success",
          gasUsed,
          timestamp: Date.now(),
        };

        setRecords((prev) => [record, ...prev]);

        if (receipt.status === "success") {
          toast.success(
            `Bot ${bot.id.toUpperCase()} verified! Gas: ${formatGas(gasUsed)}`
          );
        } else {
          toast.error(`Verification transaction reverted`);
        }
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Unknown error occurred";
        setError(message);
        setErrorAtStep(getActiveStep(currentPhase, currentProgress));
        toast.error(`Verification failed: ${message}`);
      } finally {
        setVerifyingBotId(null);
        setPhase("idle");
        setProgress(null);
      }
    },
    [account, getActiveStep]
  );

  return (
    <section className="container mx-auto px-4 py-12 space-y-8">
      <div className="text-center space-y-2">
        <h3 className="text-2xl font-bold">ProofScore Dashboard</h3>
        <p className="text-muted-foreground">
          Select a trading agent and verify its Sharpe ratio on-chain with STARK proofs.
        </p>
      </div>

      {error && (
        <div className="max-w-2xl mx-auto p-4 rounded-lg border border-red-500/20 bg-red-500/5 text-red-500 text-sm">
          {error}
        </div>
      )}

      <Tabs defaultValue="dashboard" className="max-w-4xl mx-auto">
        <TabsList className="mx-auto">
          <TabsTrigger value="dashboard">
            <LayoutDashboard className="h-4 w-4" />
            Agent Dashboard
          </TabsTrigger>
          <TabsTrigger value="pipeline">
            <GitBranch className="h-4 w-4" />
            Proof Pipeline
          </TabsTrigger>
          <TabsTrigger value="wallet">
            <Wallet className="h-4 w-4" />
            Live Wallet
          </TabsTrigger>
        </TabsList>

        <TabsContent value="dashboard" className="space-y-8 mt-6">
          {/* Bot Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {BOTS.map((bot) => (
              <AgentCard
                key={bot.id}
                bot={bot}
                isVerifying={verifyingBotId === bot.id}
                phase={verifyingBotId === bot.id ? phase : "idle"}
                progress={verifyingBotId === bot.id ? progress : null}
                onVerify={() => handleVerify(bot)}
              />
            ))}
          </div>

          {/* Verification History */}
          {records.length > 0 && (
            <div className="space-y-4">
              <h4 className="text-lg font-semibold">Verification History</h4>
              <div className="rounded-lg border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Bot</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Gas Used</TableHead>
                      <TableHead>Time</TableHead>
                      <TableHead>Transaction</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {records.map((rec, i) => (
                      <TableRow key={i}>
                        <TableCell className="font-medium">
                          Bot {rec.botId.toUpperCase()} — {rec.botName}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={rec.verified ? "default" : "destructive"}
                            className={
                              rec.verified
                                ? "bg-green-500/10 text-green-500 border-green-500/20"
                                : ""
                            }
                          >
                            {rec.verified ? "Verified" : "Failed"}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono">
                          {formatGas(rec.gasUsed)}
                        </TableCell>
                        <TableCell className="text-muted-foreground">
                          {new Date(rec.timestamp).toLocaleTimeString()}
                        </TableCell>
                        <TableCell>
                          <a
                            href={`${ARBISCAN_TX_URL}/${rec.txHash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground transition-colors"
                          >
                            {rec.txHash.slice(0, 10)}...
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </div>
          )}
        </TabsContent>

        <TabsContent value="pipeline" className="mt-6">
          <ProofPipeline
            phase={verifyingBotId ? phase : "idle"}
            progress={verifyingBotId ? progress : null}
            error={error}
            errorAtStep={errorAtStep}
            records={records}
            verifyingBotId={verifyingBotId}
            onVerify={handleVerify}
          />
        </TabsContent>

        <TabsContent value="wallet" className="mt-6">
          <WalletProver
            records={records}
            onRecordAdd={(record) => setRecords((prev) => [record, ...prev])}
          />
        </TabsContent>
      </Tabs>
    </section>
  );
}
