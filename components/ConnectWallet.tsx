"use client";

import dynamic from "next/dynamic";
import { ConnectButton } from "thirdweb/react";
import { createWallet } from "thirdweb/wallets";
import { client } from "@/lib/client";
import { arbitrumSepolia } from "@/lib/chains";

const wallets = [
  createWallet("io.metamask"),
  createWallet("com.coinbase.wallet"),
  createWallet("io.rabby"),
  createWallet("walletConnect"),
];

function ConnectWalletInner() {
  return (
    <ConnectButton
      client={client}
      chain={arbitrumSepolia}
      wallets={wallets}
      connectButton={{
        label: "Connect Wallet",
        className:
          "!bg-gradient-to-r !from-orange-500 !to-purple-600 hover:!from-orange-600 hover:!to-purple-700 !text-white !font-semibold !rounded-xl !px-6 !py-3 !transition-all !duration-200 !shadow-lg hover:!shadow-xl",
      }}
      connectModal={{
        size: "compact",
        title: "Connect to STARK Verifier",
        showThirdwebBranding: false,
      }}
      detailsButton={{
        className:
          "!bg-gradient-to-r !from-orange-500 !to-purple-600 !text-white !font-semibold !rounded-xl !px-4 !py-2",
      }}
    />
  );
}

export const ConnectWallet = dynamic(() => Promise.resolve(ConnectWalletInner), {
  ssr: false,
});
