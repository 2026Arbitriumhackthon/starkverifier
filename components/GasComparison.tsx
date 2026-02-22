"use client";

import { useState } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield,
  Zap,
  Lock,
  ArrowRightLeft,
  Loader2,
  TrendingUp,
  ExternalLink,
} from "lucide-react";
import { BENCHMARK_DATA, CHART_COLORS } from "@/lib/benchmark-data";
import type { BenchmarkEntry } from "@/lib/benchmark-data";
import {
  BOTS,
  ARBISCAN_TX_URL,
  type BotProfile,
  type PipelinePhase,
  type VerificationRecord,
  type StepTiming,
} from "@/lib/bot-data";
import { formatGas } from "@/lib/gas-utils";

interface GasComparisonProps {
  records: VerificationRecord[];
  verifyingBotId: string | null;
  onVerify: (bot: BotProfile) => void;
  phase: PipelinePhase;
  stepTimings: Record<number, StepTiming>;
}

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

/** Compute proving time (steps 2-4) from stepTimings */
function getProvingTimeMs(stepTimings: Record<number, StepTiming>): number | null {
  const step2 = stepTimings[2];
  const step4 = stepTimings[4];
  if (!step2?.startTime || !step4?.endTime) return null;
  return step4.endTime - step2.startTime;
}

function BenchmarkChart({
  title,
  dataKey,
  unit,
  formatter,
  data,
}: {
  title: string;
  dataKey: string;
  unit: string;
  formatter?: (v: number) => string;
  data: { system: string; value: number; verifier?: string }[];
}) {
  const fmt = formatter ?? formatNumber;

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-base">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[220px]">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              margin={{ top: 8, right: 16, left: 8, bottom: 0 }}
            >
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis
                dataKey="system"
                tick={{ fontSize: 13 }}
                className="fill-foreground"
              />
              <YAxis
                tickFormatter={fmt}
                tick={{ fontSize: 12 }}
                className="fill-muted-foreground"
              />
              <Tooltip
                formatter={(value) => [`${fmt(value as number)} ${unit}`, ""]}
                labelFormatter={(label) => {
                  const s = String(label);
                  const entry = BENCHMARK_DATA.find((d) => d.system === s);
                  if (entry) return `${s} — ${entry.verifier}`;
                  if (s === "Measured") return "Measured — Live Verification";
                  return s;
                }}
                contentStyle={{
                  backgroundColor: "hsl(var(--card))",
                  border: "1px solid hsl(var(--border))",
                  borderRadius: "8px",
                }}
              />
              <Bar dataKey="value" radius={[6, 6, 0, 0]} barSize={60}>
                {data.map((d) => (
                  <Cell
                    key={d.system}
                    fill={CHART_COLORS[d.system as keyof typeof CHART_COLORS] ?? "#94a3b8"}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="flex justify-center gap-4 mt-2 text-xs text-muted-foreground">
          {data.map((d) => (
            <span key={d.system}>
              {d.system}: <strong>{fmt(d.value)}</strong> {unit}
            </span>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

const WHY_STARK = [
  {
    icon: Shield,
    title: "Transparent Setup",
    desc: "No trusted ceremony needed. Anyone can verify the proof parameters.",
  },
  {
    icon: Zap,
    title: "Fast Proving",
    desc: "~380ms proof generation. 48x faster than SNARK for this workload.",
  },
  {
    icon: Lock,
    title: "Native Keccak",
    desc: "Stylus WASM uses Arbitrum's native Keccak precompile for cheap hashing.",
  },
];

const WHEN_SNARK = [
  {
    icon: ArrowRightLeft,
    title: "Compact Proof",
    desc: "260 bytes vs 4.8 KB — ideal when proof must be stored on-chain long-term.",
  },
  {
    icon: Zap,
    title: "Low Verification Gas",
    desc: "280K gas vs 1.25M — critical for L1 deployment or high-frequency verification.",
  },
];

export function GasComparison({
  records,
  verifyingBotId,
  onVerify,
  phase,
  stepTimings,
}: GasComparisonProps) {
  const [selectedBotId, setSelectedBotId] = useState<"a" | "b">("a");
  const selectedBot = BOTS.find((b) => b.id === selectedBotId)!;
  const isVerifying = verifyingBotId !== null;

  // Find latest successful record for measured data
  const latestSuccess = records.find((r) => r.verified);
  const measuredGas = latestSuccess ? Number(latestSuccess.gasUsed) : null;
  const measuredProvingTime = getProvingTimeMs(stepTimings);

  // Build chart data — base from BENCHMARK_DATA, plus Measured if available
  const gasChartData = BENCHMARK_DATA.map((d) => ({
    system: d.system,
    value: d.onChainGas,
  }));
  if (measuredGas !== null) {
    gasChartData.push({ system: "Measured", value: measuredGas });
  }

  const timeChartData = BENCHMARK_DATA.map((d) => ({
    system: d.system,
    value: d.proofGenTimeMs,
  }));
  if (measuredProvingTime !== null) {
    timeChartData.push({ system: "Measured", value: Math.round(measuredProvingTime) });
  }

  // Proof size: only STARK/SNARK (measured proof size not available)
  const sizeChartData = BENCHMARK_DATA.map((d) => ({
    system: d.system,
    value: d.proofSizeBytes,
  }));

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="text-center space-y-2">
        <h4 className="text-xl font-bold">STARK vs SNARK Benchmark</h4>
        <p className="text-sm text-muted-foreground">
          Comparing our Stylus STARK verifier against SP1 Groth16 (SNARK) for
          Sharpe ratio proofs
        </p>
        <div className="flex justify-center gap-2 mt-2">
          <Badge className="bg-orange-500/10 text-orange-500 border-orange-500/20">
            STARK (Stylus)
          </Badge>
          <Badge className="bg-purple-500/10 text-purple-500 border-purple-500/20">
            SNARK (Groth16)
          </Badge>
          {measuredGas !== null && (
            <Badge className="bg-green-500/10 text-green-500 border-green-500/20">
              Measured (Live)
            </Badge>
          )}
        </div>
      </div>

      {/* Bot Selector + Run Benchmark */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Live Benchmark</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Bot Selection */}
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

          {/* Run Benchmark Button */}
          <Button
            onClick={() => onVerify(selectedBot)}
            disabled={isVerifying}
            className="w-full bg-gradient-to-r from-orange-500 to-purple-600 hover:from-orange-600 hover:to-purple-700 text-white"
            size="lg"
          >
            {isVerifying ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Running Benchmark...
              </>
            ) : (
              <>
                <Zap className="h-4 w-4" />
                Run Benchmark — Bot {selectedBotId.toUpperCase()}
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {/* Measured Result Card */}
      {!isVerifying && latestSuccess && (
        <Card className="border-green-500/20 bg-green-500/5">
          <CardContent className="pt-4 space-y-3">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className="bg-green-500/10 text-green-500 border-green-500/20"
              >
                Measured
              </Badge>
              <span className="text-sm text-muted-foreground">
                Bot {latestSuccess.botId.toUpperCase()} — {latestSuccess.botName}
              </span>
            </div>
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Gas Used</span>
              <span className="font-mono">{formatGas(latestSuccess.gasUsed)}</span>
            </div>
            {measuredProvingTime !== null && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Proof Generation Time</span>
                <span className="font-mono">
                  {measuredProvingTime >= 1000
                    ? `${(measuredProvingTime / 1000).toFixed(1)}s`
                    : `${Math.round(measuredProvingTime)}ms`}
                </span>
              </div>
            )}
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">Transaction</span>
              <a
                href={`${ARBISCAN_TX_URL}/${latestSuccess.txHash}`}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 text-muted-foreground hover:text-foreground transition-colors font-mono"
              >
                {latestSuccess.txHash.slice(0, 10)}...
                <ExternalLink className="h-3 w-3" />
              </a>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <BenchmarkChart
          title="On-Chain Gas Cost"
          dataKey="onChainGas"
          unit="gas"
          data={gasChartData}
        />
        <BenchmarkChart
          title="Proof Generation Time"
          dataKey="proofGenTimeMs"
          unit="ms"
          formatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms`)}
          data={timeChartData}
        />
        <BenchmarkChart
          title="Proof Size"
          dataKey="proofSizeBytes"
          unit="bytes"
          formatter={(v) =>
            v >= 1024 ? `${(v / 1024).toFixed(1)} KB` : `${v} B`
          }
          data={sizeChartData}
        />
      </div>

      {/* Why STARK */}
      <div className="space-y-3">
        <h5 className="text-lg font-semibold">Why Stylus + STARK?</h5>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {WHY_STARK.map((item) => (
            <Card key={item.title}>
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <item.icon className="h-5 w-5 text-orange-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="font-medium text-sm">{item.title}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.desc}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* When SNARK */}
      <div className="space-y-3">
        <h5 className="text-lg font-semibold">When SNARK?</h5>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {WHEN_SNARK.map((item) => (
            <Card key={item.title}>
              <CardContent className="pt-6">
                <div className="flex items-start gap-3">
                  <item.icon className="h-5 w-5 text-purple-500 mt-0.5 shrink-0" />
                  <div>
                    <p className="font-medium text-sm">{item.title}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {item.desc}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* Data source note */}
      <p className="text-xs text-muted-foreground text-center">
        STARK data from benchmark/results/stark-a.json (Bot A, 15 trades, 4 queries).
        SNARK estimates based on SP1 Groth16 reference benchmarks.
        {measuredGas !== null && " Measured data from live on-chain verification."}
      </p>
    </div>
  );
}
