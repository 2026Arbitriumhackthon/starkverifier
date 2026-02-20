"use client";

import { useState } from "react";
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
  Check,
  Loader2,
  AlertCircle,
  ExternalLink,
  Shield,
  TrendingUp,
} from "lucide-react";
import {
  BOTS,
  ARBISCAN_TX_URL,
  derivePipelineSteps,
  type BotProfile,
  type PipelinePhase,
  type ProofProgress,
  type VerificationRecord,
  type PipelineStepStatus,
} from "@/lib/bot-data";
import { formatGas } from "@/lib/gas-utils";

const STEP_ICONS = [Download, BarChart3, GitCommitHorizontal, Layers, Globe];

interface ProofPipelineProps {
  phase: PipelinePhase;
  progress: ProofProgress | null;
  error: string | null;
  records: VerificationRecord[];
  verifyingBotId: string | null;
  onVerify: (bot: BotProfile) => void;
}

function StepIcon({ status, stepIndex }: { status: PipelineStepStatus; stepIndex: number }) {
  const Icon = STEP_ICONS[stepIndex];

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
  // pending
  return (
    <div className="flex items-center justify-center w-9 h-9 rounded-full bg-muted border-2 border-muted-foreground/20 shrink-0">
      <Icon className="h-4 w-4 text-muted-foreground/50" />
    </div>
  );
}

function PipelineStepRow({
  status,
  title,
  subtitle,
  activeDetail,
  stepIndex,
  isLast,
}: {
  status: PipelineStepStatus;
  title: string;
  subtitle: string;
  activeDetail: string;
  stepIndex: number;
  isLast: boolean;
}) {
  return (
    <div className="flex gap-4">
      {/* Left column: icon + connector */}
      <div className="flex flex-col items-center">
        <StepIcon status={status} stepIndex={stepIndex} />
        {!isLast && (
          <div
            className={`w-0.5 flex-1 my-1 ${
              status === "done" ? "bg-green-500/40" : "bg-muted-foreground/15"
            }`}
          />
        )}
      </div>

      {/* Right column: text */}
      <div className={`pb-6 ${isLast ? "pb-0" : ""}`}>
        <p
          className={`text-sm font-medium ${
            status === "active"
              ? "text-foreground"
              : status === "done"
                ? "text-green-500"
                : status === "error"
                  ? "text-red-500"
                  : "text-muted-foreground/60"
          }`}
        >
          {title}
        </p>
        <p className="text-xs text-muted-foreground">{subtitle}</p>
        {status === "active" && (
          <p className="text-xs text-orange-500 mt-1">{activeDetail}</p>
        )}
        {status === "error" && (
          <p className="text-xs text-red-500 mt-1">Failed at this step</p>
        )}
      </div>
    </div>
  );
}

function TxResultCard({ record }: { record: VerificationRecord }) {
  return (
    <Card className="border-green-500/20 bg-green-500/5">
      <CardContent className="pt-4 space-y-3">
        <div className="flex items-center gap-2">
          <Badge
            variant="outline"
            className={
              record.verified
                ? "bg-green-500/10 text-green-500 border-green-500/20"
                : "bg-red-500/10 text-red-500 border-red-500/20"
            }
          >
            {record.verified ? "Verified" : "Failed"}
          </Badge>
          <span className="text-sm text-muted-foreground">
            Bot {record.botId.toUpperCase()} — {record.botName}
          </span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Gas Used</span>
          <span className="font-mono">{formatGas(record.gasUsed)}</span>
        </div>
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Transaction</span>
          <a
            href={`${ARBISCAN_TX_URL}/${record.txHash}`}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors font-mono"
          >
            {record.txHash.slice(0, 10)}...
            <ExternalLink className="h-3 w-3" />
          </a>
        </div>
      </CardContent>
    </Card>
  );
}

export function ProofPipeline({
  phase,
  progress,
  error,
  records,
  verifyingBotId,
  onVerify,
}: ProofPipelineProps) {
  const [selectedBotId, setSelectedBotId] = useState<"a" | "b">("a");
  const selectedBot = BOTS.find((b) => b.id === selectedBotId)!;
  const isVerifying = verifyingBotId !== null;

  const steps = derivePipelineSteps(phase, progress, error);

  // Find the latest record for the selected bot (shown after verification completes)
  const latestRecord = records.find((r) => r.botId === selectedBotId);

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* Bot Selector */}
      <div className="grid grid-cols-2 gap-3">
        {BOTS.map((bot) => (
          <button
            key={bot.id}
            onClick={() => !isVerifying && setSelectedBotId(bot.id)}
            disabled={isVerifying}
            className={`relative rounded-lg border p-4 text-left transition-all ${
              selectedBotId === bot.id
                ? "border-transparent bg-gradient-to-r from-orange-500/10 to-purple-600/10 ring-2 ring-orange-500/50"
                : "border-muted-foreground/15 hover:border-muted-foreground/30"
            } ${isVerifying ? "cursor-not-allowed opacity-60" : "cursor-pointer"}`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`flex items-center justify-center w-8 h-8 rounded-md ${
                  bot.id === "a" ? "bg-orange-500/10" : "bg-purple-500/10"
                }`}
              >
                {bot.id === "a" ? (
                  <TrendingUp className="h-4 w-4 text-orange-500" />
                ) : (
                  <Shield className="h-4 w-4 text-purple-500" />
                )}
              </div>
              <div>
                <p className="text-sm font-medium">Bot {bot.id.toUpperCase()}</p>
                <p className="text-xs text-muted-foreground">{bot.name}</p>
              </div>
            </div>
            <div className="mt-2 flex items-center gap-3 text-xs text-muted-foreground">
              <span>Sharpe: {bot.sharpeDisplay}</span>
              <span>{bot.tradeCount} trades</span>
            </div>
          </button>
        ))}
      </div>

      {/* Pipeline Timeline */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Proof Pipeline</CardTitle>
        </CardHeader>
        <CardContent>
          {steps.map((step, i) => (
            <PipelineStepRow
              key={step.id}
              status={step.status}
              title={step.title}
              subtitle={step.subtitle}
              activeDetail={step.activeDetail}
              stepIndex={i}
              isLast={i === steps.length - 1}
            />
          ))}
        </CardContent>
      </Card>

      {/* Verify Button */}
      <Button
        onClick={() => onVerify(selectedBot)}
        disabled={isVerifying}
        className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
        size="lg"
      >
        {isVerifying ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" />
            Verifying...
          </>
        ) : (
          <>
            <Shield className="h-4 w-4" />
            Verify Bot {selectedBotId.toUpperCase()} On-Chain
          </>
        )}
      </Button>

      {/* Result Card — show latest record for selected bot */}
      {!isVerifying && latestRecord && <TxResultCard record={latestRecord} />}
    </div>
  );
}
