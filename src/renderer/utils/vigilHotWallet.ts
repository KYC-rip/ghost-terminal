/**
 * Module-level mirror (same pattern as networkMode.ts): VigilProvider keeps
 * this current from live engine state; VaultContext.lock() reads it at call
 * time to decide whether the wallet-rpc wallet stays open behind the locked
 * UI. True only while an EJECT vigil is armed/executing — the one case where
 * the engine must spend XMR unattended. Never persisted; dies with the
 * process.
 */

let keepOpen = false;

export function setVigilKeepsWalletOpen(v: boolean) {
  keepOpen = v;
}

export function vigilKeepsWalletOpen(): boolean {
  return keepOpen;
}
