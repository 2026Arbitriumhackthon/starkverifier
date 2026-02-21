import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";
import { Toaster } from "@/components/ui/sonner";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ProofScore | On-Chain Agent Evaluation",
  description:
    "STARK-verified trading agent evaluation on Arbitrum Stylus. Sharpe ratio proofs with zero-knowledge guarantees.",
  keywords: [
    "STARK",
    "Stylus",
    "Arbitrum",
    "Keccak256",
    "Sharpe Ratio",
    "ZK",
    "Agent Evaluation",
  ],
  authors: [{ name: "hodduk" }],
  openGraph: {
    title: "ProofScore | On-Chain Agent Evaluation",
    description: "STARK-verified trading agent evaluation on Arbitrum Stylus",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased min-h-screen bg-background`}
      >
        <Providers>{children}</Providers>
        <Toaster position="top-right" richColors closeButton />
      </body>
    </html>
  );
}
