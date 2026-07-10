/**
 * Vigil strike wallet — a deliberately small EVM burner wallet used to
 * auto-fund SNIPE trades when a price trigger fires.
 *
 * - One key per identity, generated locally, AES-GCM-encrypted with the
 *   vault password, persisted via IPC (main process stores opaque blobs).
 * - All RPC traffic goes through the renderer fetch stack, which already
 *   follows the app-wide Tor/system proxy session settings.
 * - This is intentionally NOT the Monero vault: pre-fund only what you
 *   plan to deploy.
 */
import { ethers } from 'ethers';
import { EvmStealthEngine } from '@kyc-rip/stealth-engines/evm';
import type { StealthEnvironment } from '@kyc-rip/stealth-engines';
import { getTokenConfig, isNativeEVM, getRpcUrl } from '@kyc-rip/stealth-engines/chains';
import { createTrade } from './swap';
import { encryptStrikeKey, decryptStrikeKey } from '../utils/strikeKeyCrypto';

export interface StrikeBalances {
  eth: string;
  tokens: Record<string, string>; // ticker -> formatted balance
}

export interface GasCheck {
  ok: boolean;
  requiredEth: string;
  haveEth: string;
  missingEth?: string;
}

// Typed wrapper (not a cast): if either side's signature drifts, this stops compiling.
const createTradeForEngine: StealthEnvironment['createTrade'] = (params) =>
  createTrade({
    id: params.id,
    amountFrom: params.amountFrom,
    amountTo: params.amountTo,
    fromTicker: params.fromTicker,
    fromNetwork: params.fromNetwork,
    toTicker: params.toTicker,
    toNetwork: params.toNetwork,
    destinationAddress: params.destinationAddress,
    provider: params.provider,
    engine: params.engine,
    // Engines pass free-form sources; the desktop API accepts a known union
    source: (params.source ?? 'ghost') as Parameters<typeof createTrade>[0]['source'],
    fixed: params.fixed,
  });

const desktopStealthEnv: StealthEnvironment = {
  createTrade: createTradeForEngine,
  getTokenConfig,
  isNativeEVM,
  // The engine never derives HD seeds on desktop (keys are imported), but
  // give it real storage so future engine paths never hit the throwing stub.
  // (Guarded for non-browser contexts like vitest.)
  storage: typeof localStorage !== 'undefined' ? localStorage : undefined,
};

export type StrikeLogger = (msg: string, type?: 'info' | 'success' | 'warn' | 'process' | 'error') => void;

export class StrikeWallet {
  private engine: EvmStealthEngine;
  private network: string;
  private identityId: string;

  private constructor(engine: EvmStealthEngine, network: string, identityId: string) {
    this.engine = engine;
    this.network = network;
    this.identityId = identityId;
  }

  /**
   * Load the identity's strike key (decrypting with the vault password) or
   * generate + persist a fresh one. Returns the wallet plus whether it was
   * newly created (callers should prompt for a key backup on creation).
   */
  static async createOrLoad(
    identityId: string,
    vaultPassword: string,
    network: string,
    logger: StrikeLogger = () => { }
  ): Promise<{ wallet: StrikeWallet; address: string; created: boolean }> {
    const rpcUrl = getRpcUrl(network);
    let privateKey: string;
    let created = false;

    const blob = await window.api.vigilGetStrikeKey(identityId);
    if (blob) {
      privateKey = await decryptStrikeKey(blob, vaultPassword);
    } else {
      try {
        privateKey = ethers.Wallet.createRandom().privateKey;
      } catch (e: any) {
        throw new Error(`Failed to generate strike key (entropy source unavailable?): ${e.message}`);
      }
      const newBlob = await encryptStrikeKey(privateKey, vaultPassword);
      const res = await window.api.vigilSaveStrikeKey(identityId, newBlob);
      if (!res.success) throw new Error(res.error || 'Failed to persist strike key');
      created = true;
    }

    const engine = new EvmStealthEngine(logger, desktopStealthEnv);
    const address = await engine.init(rpcUrl, privateKey);
    return { wallet: new StrikeWallet(engine, network, identityId), address, created };
  }

  getAddress(): string {
    return this.engine.getAddress();
  }

  async getBalances(tickers: string[]): Promise<StrikeBalances> {
    const { total: eth } = await this.engine.getBalance();
    const tokens: Record<string, string> = {};
    for (const ticker of tickers) {
      if (isNativeEVM(ticker)) continue;
      const cfg = getTokenConfig(ticker, this.network);
      tokens[ticker] = cfg ? await this.engine.getTokenBalance(cfg.address) : '0';
    }
    return { eth, tokens };
  }

  /** Check the burner holds enough ETH for gas (with the engine's volatility buffer). */
  async checkGas(): Promise<GasCheck> {
    const requiredEth = await this.engine.getEstimatedGasBuffer();
    const { total: haveEth } = await this.engine.getBalance();
    const ok = parseFloat(haveEth) >= parseFloat(requiredEth);
    return {
      ok,
      requiredEth,
      haveEth,
      missingEth: ok ? undefined : (parseFloat(requiredEth) - parseFloat(haveEth)).toFixed(6),
    };
  }

  /** Send `amount` of `ticker` to a swap deposit address. Waits 1 confirmation. */
  async sendToken(toAddress: string, amount: number, ticker: string): Promise<string> {
    return this.engine.transfer(toAddress, amount, ticker, this.network);
  }

  /** Sweep leftovers (token + remaining ETH minus gas) to a user address. */
  async refund(toAddress: string, ticker?: string): Promise<string> {
    const tokenInfo = ticker && !isNativeEVM(ticker)
      ? { address: getTokenConfig(ticker, this.network)?.address, ticker }
      : undefined;
    return this.engine.sweep(toAddress, tokenInfo);
  }

  /** Re-authenticate and reveal the raw private key for backup/export. */
  async exportKey(vaultPassword: string): Promise<string> {
    const blob = await window.api.vigilGetStrikeKey(this.identityId);
    if (!blob) throw new Error('No strike key stored for this identity');
    return decryptStrikeKey(blob, vaultPassword);
  }
}

/**
 * Re-encrypt the strike key under a new vault password, keeping the burner
 * recoverable. NOTE: the app currently has NO vault password-change flow
 * (passwords are fixed at identity creation; neither SettingsView nor any
 * IPC calls monero-wallet-rpc change_wallet_password). This function is the
 * mandatory hook for that flow — if a password change feature is ever added,
 * it MUST call this with both passwords or the strike key becomes
 * unrecoverable under the new password.
 */
export async function reencryptStrikeKey(identityId: string, oldPassword: string, newPassword: string): Promise<boolean> {
  const blob = await window.api.vigilGetStrikeKey(identityId);
  if (!blob) return false;
  const privateKey = await decryptStrikeKey(blob, oldPassword);
  const newBlob = await encryptStrikeKey(privateKey, newPassword);
  const res = await window.api.vigilSaveStrikeKey(identityId, newBlob);
  if (!res.success) throw new Error(res.error || 'Failed to re-encrypt strike key');
  return true;
}
