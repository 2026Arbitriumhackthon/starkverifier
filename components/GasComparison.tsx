"use client";

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
import { Shield, Zap, Lock, ArrowRightLeft } from "lucide-react";
import { BENCHMARK_DATA, CHART_COLORS } from "@/lib/benchmark-data";

function formatNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toString();
}

function BenchmarkChart({
  title,
  dataKey,
  unit,
  formatter,
}: {
  title: string;
  dataKey: keyof (typeof BENCHMARK_DATA)[0];
  unit: string;
  formatter?: (v: number) => string;
}) {
  const data = BENCHMARK_DATA.map((d) => ({
    system: d.system,
    value: d[dataKey] as number,
    verifier: d.verifier,
  }));
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
                  return entry ? `${s} — ${entry.verifier}` : s;
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
                    fill={CHART_COLORS[d.system as keyof typeof CHART_COLORS]}
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

export function GasComparison() {
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
        </div>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <BenchmarkChart
          title="On-Chain Gas Cost"
          dataKey="onChainGas"
          unit="gas"
        />
        <BenchmarkChart
          title="Proof Generation Time"
          dataKey="proofGenTimeMs"
          unit="ms"
          formatter={(v) => (v >= 1000 ? `${(v / 1000).toFixed(1)}s` : `${v}ms`)}
        />
        <BenchmarkChart
          title="Proof Size"
          dataKey="proofSizeBytes"
          unit="bytes"
          formatter={(v) =>
            v >= 1024 ? `${(v / 1024).toFixed(1)} KB` : `${v} B`
          }
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
      </p>
    </div>
  );
}
