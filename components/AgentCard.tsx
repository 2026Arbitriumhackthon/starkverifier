"use client";

import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  TrendingUp,
  ArrowUpRight,
  Activity,
  Shield,
  Loader2,
} from "lucide-react";
import type { BotProfile, PipelinePhase, ProofProgress } from "@/lib/bot-data";

const PHASE_LABELS: Record<PipelinePhase, string> = {
  idle: "",
  "loading-wasm": "Loading WASM prover...",
  proving: "Generating STARK proof...",
  "sending-tx": "Sending transaction...",
  confirming: "Waiting for confirmation...",
};

const RISK_COLORS: Record<string, string> = {
  High: "bg-red-500/10 text-red-500 border-red-500/20",
  Medium: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
  Low: "bg-green-500/10 text-green-500 border-green-500/20",
};

interface AgentCardProps {
  bot: BotProfile;
  isVerifying: boolean;
  phase: PipelinePhase;
  progress: ProofProgress | null;
  onVerify: () => void;
}

export function AgentCard({
  bot,
  isVerifying,
  phase,
  progress,
  onVerify,
}: AgentCardProps) {
  const totalReturnPercent = (bot.totalReturnBps / 100).toFixed(1);
  const isActive = isVerifying && phase !== "idle";

  return (
    <Card className="relative overflow-hidden">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div
              className={`flex items-center justify-center w-10 h-10 rounded-lg ${
                bot.id === "a"
                  ? "bg-orange-500/10"
                  : "bg-purple-500/10"
              }`}
            >
              {bot.id === "a" ? (
                <TrendingUp className="h-5 w-5 text-orange-500" />
              ) : (
                <Shield className="h-5 w-5 text-purple-500" />
              )}
            </div>
            <div>
              <CardTitle className="text-lg">Bot {bot.id.toUpperCase()}</CardTitle>
              <CardDescription>{bot.name}</CardDescription>
            </div>
          </div>
          <Badge
            variant="outline"
            className={RISK_COLORS[bot.riskLevel]}
          >
            {bot.riskLevel} Risk
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <p className="text-sm text-muted-foreground">{bot.strategy}</p>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <Activity className="h-3 w-3" />
              Sharpe
            </div>
            <p className="text-xl font-bold">{bot.sharpeDisplay}</p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <ArrowUpRight className="h-3 w-3" />
              Return
            </div>
            <p className="text-xl font-bold text-green-500">
              +{totalReturnPercent}%
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-1 text-xs text-muted-foreground">
              <TrendingUp className="h-3 w-3" />
              Trades
            </div>
            <p className="text-xl font-bold">{bot.tradeCount}</p>
          </div>
        </div>

        {/* Progress Section */}
        {isActive && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">
                {phase === "proving" && progress
                  ? progress.detail
                  : PHASE_LABELS[phase]}
              </span>
              {phase === "proving" && progress && (
                <span className="font-mono">
                  {Math.round(progress.percent)}%
                </span>
              )}
            </div>
            <div className="h-2 rounded-full bg-muted overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-orange-500 to-purple-600 transition-all duration-300"
                style={{
                  width: `${
                    phase === "proving" && progress
                      ? progress.percent
                      : phase === "loading-wasm"
                        ? 10
                        : phase === "sending-tx"
                          ? 80
                          : phase === "confirming"
                            ? 90
                            : 0
                  }%`,
                }}
              />
            </div>
          </div>
        )}

        {/* Verify Button */}
        <Button
          onClick={onVerify}
          disabled={isVerifying}
          className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
          size="lg"
        >
          {isActive ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" />
              {PHASE_LABELS[phase]}
            </>
          ) : (
            <>
              <Shield className="h-4 w-4" />
              Verify On-Chain
            </>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}
