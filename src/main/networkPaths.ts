/**
 * Pure network->path/flag resolution (no Electron imports so vitest can
 * exercise the matrix). 'stressnet' is the FCMP++/CARROT beta stressnet —
 * a fork of the Monero testnet running seraphis-migration builds, so it
 * uses the --testnet daemon flag with a dedicated binary and wallet dir.
 *
 * Mainnet and stagenet intentionally keep sharing the legacy 'wallets' dir
 * (pre-existing behavior; a wallet can only be open on one network at a
 * time). Stressnet gets a hard-separated dir so experimental chain state
 * can never touch real wallets.
 */

export type MoneroNetwork = 'mainnet' | 'stagenet' | 'stressnet';

export function getWalletDirName(network: string): string {
  return network === 'stressnet' ? 'wallets-stressnet' : 'wallets';
}

/** Folder under resources/bin that holds monero-wallet-rpc for this network. */
export function getRpcFolderName(network: string): string {
  return network === 'stressnet' ? 'rpc-stressnet' : 'rpc-core';
}

/** CLI network flag for monero-wallet-rpc (null = mainnet, no flag). */
export function getNetworkFlag(network: string): string | null {
  if (network === 'stagenet') return '--stagenet';
  if (network === 'testnet' || network === 'stressnet') return '--testnet';
  return null;
}

/** Header badge text shown in the renderer. Empty string = no badge. */
export function getNetworkLabel(network: string): string {
  if (network === 'stagenet') return 'STAGENET';
  if (network === 'stressnet') return 'FCMP++ STRESSNET';
  return '';
}

export interface BinCapabilities {
  stressnet: boolean;
}

/** Missing or corrupt manifest must fail SAFE: hide stressnet. */
export function parseCapabilities(raw: string | null | undefined): BinCapabilities {
  if (!raw) return { stressnet: false };
  try {
    const data = JSON.parse(raw);
    return { stressnet: data?.stressnet === true };
  } catch {
    return { stressnet: false };
  }
}
