/* eslint-disable @typescript-eslint/no-explicit-any */
import { useState, useEffect, useRef, useCallback } from 'react';
import { createTrade, getTradeStatus, type ComplianceState, type ExchangeRoute } from '../services/swap';
import { getApiBase } from '../services/client';
import { useFiatValue } from './useFiatValue';
import { useVault } from './useVault';
import { usePriceWatcher, getKrakenMonitoringPair, type PriceTrigger } from './usePriceWatcher';
import { StrikeWallet, type StrikeBalances, type GasCheck } from '../services/strikeWallet';
import { setVigilKeepsWalletOpen } from '../utils/vigilHotWallet';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EngineState = 'IDLE' | 'WATCHING' | 'TRIGGERED' | 'EXECUTING' | 'PAUSED_LOCKED' | 'POLLING' | 'COMPLETED' | 'ERROR';

export interface VigilSession {
  mode: 'SNIPE' | 'EJECT';
  config: {
    triggerPrice: string;
    stopPrice?: string;
    amount: string;
    targetAddress: string;
    memo?: string;
    inputCurrency?: { ticker: string; network: string; memo?: boolean };
    outputCurrency?: { ticker: string; network: string; memo?: boolean };
    compliance: ComplianceState;
  };
  state: EngineState;
}

/** Persisted snapshot (schema v1). Never contains key material. */
export interface PersistedVigilSession {
  version: 1;
  identityId: string;
  mode: 'SNIPE' | 'EJECT';
  phase: 'ARMED' | 'EXECUTING' | 'POLLING';
  triggers: PriceTrigger[];
  config: VigilSession['config'];
  tradeId?: string;
  txHash?: string;
  createdAt: number;
}

export const VIGIL_SESSION_VERSION = 1;

interface TriggerPayload {
  provider: string;
  engine: string;
  amount_to: number;
  krakenPrice: number;
  triggerId: string;
}

interface LogEntry {
  id: number;
  time: string;
  text: string;
  type: 'info' | 'success' | 'warn' | 'process' | 'error';
}

interface EstimateResponse {
  amount_to: number;
  routes: ExchangeRoute[];
}

// ---------------------------------------------------------------------------
// Compliance Mapping
// ---------------------------------------------------------------------------

const kycMap: Record<string, string> = { 'STRICT': 'A', 'STANDARD': 'B', 'ANY': 'D' };
const logMap: Record<string, string> = { 'STRICT': 'A', 'STANDARD': 'B', 'ANY': 'C' };

const getPrivacyParams = (c: ComplianceState) => ({
  kyc: kycMap[c.kyc] || 'D',
  log: logMap[c.log] || 'C',
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * sendXmr failures meaning the wallet-rpc wallet is not open (deep-lock race,
 * rpc restart) — these fall back to PAUSED_LOCKED instead of ERROR. String
 * matching is fragile by nature, but this is a fallback path: an unmatched
 * message still lands safely in ERROR+Retry.
 */
const isWalletClosedError = (msg: string) =>
  /no wallet file|wallet is closed|econnrefused|connection refused/i.test(msg || '');

const currencyDefaults = (session: VigilSession) => ({
  fromTicker: session.config.inputCurrency?.ticker || (session.mode === 'SNIPE' ? 'USDT' : 'XMR'),
  fromNetwork: session.config.inputCurrency?.network || (session.mode === 'SNIPE' ? 'ERC20' : 'Mainnet'),
  toTicker: session.config.outputCurrency?.ticker || (session.mode === 'SNIPE' ? 'XMR' : 'USDT'),
  toNetwork: session.config.outputCurrency?.network || (session.mode === 'SNIPE' ? 'Mainnet' : 'ERC20'),
});

export function buildTriggers(mode: 'SNIPE' | 'EJECT', triggerPrice: string, stopPrice?: string): PriceTrigger[] {
  const triggers: PriceTrigger[] = [];
  const pMain = parseFloat(triggerPrice || '0');
  const pStop = parseFloat(stopPrice || '0');

  if (mode === 'SNIPE') {
    if (pMain > 0) triggers.push({ id: 'BUY_DIP', operator: '<=', price: pMain });
    if (pStop > 0) triggers.push({ id: 'BUY_BREAKOUT', operator: '>=', price: pStop });
  } else {
    if (pMain > 0) triggers.push({ id: 'TAKE_PROFIT', operator: '>=', price: pMain });
    if (pStop > 0) triggers.push({ id: 'STOP_LOSS', operator: '<=', price: pStop });
  }
  return triggers;
}

/** Validates a persisted session blob; returns null for anything unusable. */
export function loadPersistedSession(raw: any, identityId: string): PersistedVigilSession | null {
  if (!raw || typeof raw !== 'object') return null;
  if (raw.version !== VIGIL_SESSION_VERSION) {
    console.warn(`[Vigil] Ignoring session with unsupported version ${raw.version} (created by a newer app?)`);
    return null;
  }
  if (raw.identityId !== identityId) return null;
  if (!['SNIPE', 'EJECT'].includes(raw.mode)) return null;
  if (!['ARMED', 'EXECUTING', 'POLLING'].includes(raw.phase)) return null;
  if (!Array.isArray(raw.triggers)) return null;
  return raw as PersistedVigilSession;
}

// Status polling cadence
const POLL_BASE_MS = 10_000;
const POLL_MAX_MS = 60_000;
const POLL_DEADLINE_MS = 24 * 60 * 60 * 1000;

const STATUS_PROGRESS: Record<string, number> = {
  WAITING: 20, CONFIRMING: 35, EXCHANGING: 60, SENDING: 85, FINISHED: 100,
};

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

export function useVigilEngine() {
  // --- Core state ---
  const [state, setState] = useState<EngineState>('IDLE');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [executionStatus, setExecutionStatus] = useState<string>('');
  const [progress, setProgress] = useState<number>(0);
  const [activeSession, setActiveSession] = useState<VigilSession | null>(null);
  const [completedTrade, setCompletedTrade] = useState<{
    id: string;
    amount: string;
    txHash?: string;
    inputCurrency: any;
    outputCurrency: any;
  } | null>(null);

  // Restart recovery: a persisted session found on mount, awaiting user action
  const [pendingSession, setPendingSession] = useState<PersistedVigilSession | null>(null);

  // --- Strike wallet (SNIPE funding) ---
  const strikeRef = useRef<StrikeWallet | null>(null);
  const [strikeAddress, setStrikeAddress] = useState<string>('');
  const [strikeBalances, setStrikeBalances] = useState<StrikeBalances | null>(null);
  const [strikeGas, setStrikeGas] = useState<GasCheck | null>(null);
  const [strikeCreated, setStrikeCreated] = useState(false); // true right after first key generation

  const isVerifyingRef = useRef(false);
  const sessionRef = useRef<VigilSession | null>(null);
  const stateRef = useRef<EngineState>('IDLE');
  const pollAbortRef = useRef(false);
  const retryPayloadRef = useRef<TriggerPayload | null>(null);
  // EJECT trigger that fired while the vault was locked: trade exists,
  // XMR dispatch is held until unlock (PAUSED_LOCKED).
  const pausedDispatchRef = useRef<{ tradeId: string; depositAddress: string; amount: number } | null>(null);

  useEffect(() => { sessionRef.current = activeSession; }, [activeSession]);
  useEffect(() => { stateRef.current = state; }, [state]);

  const vault = useVault();
  const identityId = vault.activeId;

  // Hot-wallet contract with VaultContext.lock(): while an EJECT is armed,
  // the wallet stays open behind a locked UI so the order executes
  // unattended. When the vigil leaves its active states while still locked,
  // close the wallet ourselves (same IPC call lock() would have made;
  // closing an already-closed wallet is a harmless no-op).
  const wasHotRef = useRef(false);
  useEffect(() => {
    const hot = activeSession?.mode === 'EJECT'
      && ['WATCHING', 'TRIGGERED', 'EXECUTING', 'POLLING', 'PAUSED_LOCKED'].includes(state);
    setVigilKeepsWalletOpen(hot);
    if (wasHotRef.current && !hot && vault.isLocked) {
      window.api.walletAction('close', {}).catch((e: any) =>
        console.warn('[Vigil] Deferred wallet close failed:', e));
    }
    wasHotRef.current = hot;
  }, [state, activeSession, vault.isLocked]);

  // Fiat price fallback for the idle config screen
  const { fiatText: fiatPrice } = useFiatValue('XMR', 1, false);

  const API_BASE = getApiBase();

  // ---------------------------------------------------------------------------
  // Logger
  // ---------------------------------------------------------------------------

  const logger = useCallback((text: string, type: LogEntry['type'] = 'info') => {
    const now = new Date();
    const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
    setLogs(prev => [...prev.slice(-50), { id: Date.now() + Math.random(), time: timeStr, text, type }]);

    if (type === 'process' || type === 'error') {
      setExecutionStatus(text);
    }
  }, []);

  // ---------------------------------------------------------------------------
  // Desktop notifications (renderer Notification API, no permission prompt in
  // Electron). Deduped per key within 60s so price oscillation around the
  // trigger can't spam; execution itself is already guarded by isVerifyingRef.
  // ---------------------------------------------------------------------------

  const notifiedAtRef = useRef<Map<string, number>>(new Map());
  const notify = useCallback((key: string, title: string, body: string) => {
    const last = notifiedAtRef.current.get(key) || 0;
    if (Date.now() - last < 60_000) return;
    notifiedAtRef.current.set(key, Date.now());
    try {
      new Notification(title, { body });
    } catch (e) {
      console.warn('[Vigil] Notification unavailable:', e);
    }
  }, []);

  // ---------------------------------------------------------------------------
  // Session persistence (config snapshots only — never key material)
  // ---------------------------------------------------------------------------

  const persistSession = useCallback(async (
    session: VigilSession,
    phase: PersistedVigilSession['phase'],
    extra?: { tradeId?: string; txHash?: string }
  ) => {
    if (!identityId) return;
    const snapshot: PersistedVigilSession = {
      version: VIGIL_SESSION_VERSION,
      identityId,
      mode: session.mode,
      phase,
      triggers: buildTriggers(session.mode, session.config.triggerPrice, session.config.stopPrice),
      config: session.config,
      createdAt: Date.now(),
      ...extra,
    };
    const res = await window.api.vigilSaveSession(identityId, snapshot);
    if (!res.success) console.warn('[Vigil] Failed to persist session:', res.error);
  }, [identityId]);

  const clearPersistedSession = useCallback(async () => {
    if (!identityId) return;
    await window.api.vigilClearSession(identityId).catch((e: any) =>
      console.warn('[Vigil] Failed to clear persisted session:', e));
  }, [identityId]);

  // Identity switch invalidates the in-memory strike wallet — the new
  // identity has its own key (and its own vault password).
  useEffect(() => {
    strikeRef.current = null;
    setStrikeAddress('');
    setStrikeBalances(null);
    setStrikeGas(null);
    setStrikeCreated(false);
  }, [identityId]);

  // PAUSED_LOCKED -> recovery on unlock (fallback path; the common case now
  // executes while locked thanks to the hot wallet). Two tiers:
  //   1. trade still live  -> dispatch the ORIGINAL deposit address (fast,
  //      no re-estimate);
  //   2. trade expired/dead -> re-verify the trigger condition against a
  //      FRESH estimate and re-create automatically — the user's standing
  //      intent is the armed order; nobody should babysit a Retry button.
  //      If the condition no longer holds, resume WATCHING.
  // The price watcher stayed alive the whole time (provider sits above the
  // lock gate), so watcher.price is current.
  useEffect(() => {
    if (vault.isLocked || stateRef.current !== 'PAUSED_LOCKED') return;
    const held = pausedDispatchRef.current;
    const session = sessionRef.current;
    if (!held || !session) return;
    (async () => {
      try {
        setState('EXECUTING');
        logger('Vault unlocked — validating held trade...', 'process');
        const status = await getTradeStatus(held.tradeId);
        const st = (status.status || '').toUpperCase();

        if (!['EXPIRED', 'FAILED', 'REFUNDED'].includes(st)) {
          logger('Dispatching held XMR send...', 'process');
          const txHash = await vault.sendXmr(held.depositAddress, held.amount);
          logger(`TX Broadcasted: ${txHash || 'pending'}`, 'success');
          pausedDispatchRef.current = null;
          await persistSession(session, 'POLLING', { tradeId: held.tradeId, txHash });
          await pollTradeStatus(held.tradeId, txHash, session);
          return;
        }

        // Tier 2: the held trade died while locked — re-verify + re-create
        logger(`Trade ${held.tradeId} is ${st} — re-verifying the trigger for a fresh order...`, 'warn');
        pausedDispatchRef.current = null;
        const triggers = buildTriggers(session.mode, session.config.triggerPrice, session.config.stopPrice);
        const payload = retryPayloadRef.current;
        const trig = triggers.find(t => t.id === payload?.triggerId) ?? triggers[0];
        const livePrice = watcher.price;
        if (trig && livePrice) {
          setState('WATCHING'); // re-opens executeStrike's reentrancy gate
          await verifyAndExecute(livePrice, trig);
        }
        // verifyAndExecute only executes if the condition still holds at the
        // live price; otherwise (or with no live price yet) resume watching.
        if (stateRef.current === 'WATCHING') {
          const { fromTicker, toTicker } = currencyDefaults(session);
          watcher.watch(getKrakenMonitoringPair(session.mode, fromTicker, toTicker), triggers);
          await persistSession(session, 'ARMED');
          logger('Condition no longer met at the live price — resumed watching.', 'info');
        }
      } catch (e: any) {
        logger(`Held dispatch failed: ${e.message}`, 'error');
        setState('ERROR');
      }
    })();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vault.isLocked]);

  // Monero network switch (mainnet<->stagenet) reloads the whole engine and
  // invalidates routes/addresses captured at arm time — disarm and drop the
  // strike state rather than risk firing against the wrong chain.
  const stagenetRef = useRef(vault.isStagenet);
  useEffect(() => {
    if (stagenetRef.current === vault.isStagenet) return;
    stagenetRef.current = vault.isStagenet;
    if (stateRef.current !== 'IDLE') {
      logger('Network changed — disarming vigil (re-arm on the new network).', 'warn');
      abortRef.current?.();
    }
    strikeRef.current = null;
    setStrikeAddress('');
    setStrikeBalances(null);
    setStrikeGas(null);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vault.isStagenet]);

  // Load any persisted session for this identity on mount / identity switch
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (!identityId || identityId === 'primary') return;
      const raw = await window.api.vigilGetSession(identityId).catch(() => null);
      if (cancelled) return;
      const session = loadPersistedSession(raw, identityId);
      if (session && stateRef.current === 'IDLE') {
        setPendingSession(session);
      }
    })();
    return () => { cancelled = true; };
  }, [identityId]);

  // ---------------------------------------------------------------------------
  // Status polling (after the swap order exists)
  // ---------------------------------------------------------------------------

  const pollTradeStatus = useCallback(async (tradeId: string, txHash: string | undefined, session: VigilSession) => {
    setState('POLLING');
    pollAbortRef.current = false;

    const startedAt = Date.now();
    let interval = POLL_BASE_MS;
    let consecutiveErrors = 0;

    logger(`Tracking swap ${tradeId}...`, 'process');

    while (!pollAbortRef.current) {
      if (Date.now() - startedAt > POLL_DEADLINE_MS) {
        logger(`Tracking timed out after 24h. Check the provider manually (trade ${tradeId}).`, 'error');
        setState('ERROR');
        return;
      }

      try {
        const status = await getTradeStatus(tradeId);
        consecutiveErrors = 0;
        interval = POLL_BASE_MS;

        const s = (status.status || '').toUpperCase();
        setProgress(STATUS_PROGRESS[s] ?? 20);
        setExecutionStatus(`SWAP ${s || 'PENDING'}`);

        if (s === 'FINISHED') {
          setCompletedTrade({
            id: tradeId,
            amount: session.config.amount,
            txHash: (status as any).tx_out || txHash,
            inputCurrency: session.config.inputCurrency,
            outputCurrency: session.config.outputCurrency,
          });
          logger('Swap finished. Funds delivered.', 'success');
          notify(`done:${tradeId}`, 'Vigil complete', `Swap ${tradeId} finished — funds delivered.`);
          setState('COMPLETED');
          setActiveSession(null);
          await clearPersistedSession();
          return;
        }
        if (['FAILED', 'REFUNDED', 'EXPIRED'].includes(s)) {
          logger(`Swap ended with status ${s}. Check the provider for details (trade ${tradeId}).`, 'error');
          setState('ERROR');
          return;
        }
      } catch (e: any) {
        consecutiveErrors++;
        interval = Math.min(POLL_BASE_MS * 2 ** consecutiveErrors, POLL_MAX_MS);
        console.warn(`[Vigil] Status poll failed (${consecutiveErrors}x), backing off to ${interval / 1000}s:`, e.message);
      }

      await new Promise(r => setTimeout(r, interval));
    }
  }, [logger, clearPersistedSession]);

  // ---------------------------------------------------------------------------
  // Execute Strike
  // ---------------------------------------------------------------------------

  const executeStrike = useCallback(async (payload: TriggerPayload) => {
    if (stateRef.current === 'EXECUTING' || stateRef.current === 'TRIGGERED') return;

    const session = sessionRef.current;
    if (!session) return;

    retryPayloadRef.current = payload;
    setState('TRIGGERED');
    logger(`Target hit at $${payload.krakenPrice} [${payload.triggerId}]`, 'warn');
    notify(`trigger:${payload.triggerId}`, 'Vigil trigger hit', `${payload.triggerId} at $${payload.krakenPrice} — executing ${session.mode}`);

    await new Promise(r => setTimeout(r, 500));
    setState('EXECUTING');
    await persistSession(session, 'EXECUTING');
    logger('Executing strike...', 'process');

    try {
      const { fromTicker, fromNetwork, toTicker, toNetwork } = currencyDefaults(session);

      const amount = parseFloat(session.config.amount);
      if (amount <= 0) throw new Error('Invalid amount');

      // SNIPE: receive address is the vault subaddress; EJECT: user-provided target
      const destinationAddress = session.config.targetAddress;

      logger('Creating swap order...', 'process');

      const trade = await createTrade({
        id: `vigil_${Date.now()}`,
        amountFrom: amount,
        amountTo: 0,
        fromTicker,
        fromNetwork,
        toTicker,
        toNetwork,
        destinationAddress,
        provider: payload.provider,
        engine: payload.engine,
        // Plain swaps, not ghost-bridge legs — name them for what they are
        source: session.mode === 'SNIPE' ? 'vigil-snipe' : 'vigil-eject',
        fixed: false,
      });

      const depositAddress = trade.address_provider || trade.deposit_address;
      if (!depositAddress) throw new Error('Failed to get deposit address from provider');

      const tradeId = trade.trade_id || trade.id || '';
      logger(`Order created. ID: ${tradeId}`, 'success');

      let txHash: string | undefined;

      if (session.mode === 'EJECT') {
        // The wallet stays hot behind a locked UI for armed EJECTs (see the
        // hot-wallet effect), so this executes unattended even at 3am. If the
        // wallet is somehow NOT open (deep-lock race, wallet-rpc restart),
        // fall back to PAUSED_LOCKED — the unlock effect recovers: it
        // dispatches the original trade if still live, or re-creates it.
        // A failed send never sweeps; unmatched errors land in ERROR+Retry.
        logger('Sending XMR from vault...', 'process');
        try {
          txHash = await vault.sendXmr(depositAddress, amount);
        } catch (sendErr: any) {
          if (isWalletClosedError(sendErr?.message)) {
            pausedDispatchRef.current = { tradeId, depositAddress, amount };
            await persistSession(session, 'EXECUTING', { tradeId });
            setState('PAUSED_LOCKED');
            logger('Wallet is not open — unlock to dispatch (auto-recovers, re-creating the trade if it expires).', 'warn');
            notify(`paused:${tradeId}`, 'Vigil: unlock to dispatch', 'EJECT trigger fired but the wallet was closed — unlock Ripley to dispatch. The order auto-recovers even if this trade expires.');
            return;
          }
          throw sendErr;
        }
        logger(`TX Broadcasted: ${txHash || 'pending'}`, 'success');
      } else {
        // SNIPE: auto-fund from the strike wallet
        const strike = strikeRef.current;
        if (!strike) throw new Error('Strike wallet not unlocked');

        const gas = await strike.checkGas();
        if (!gas.ok) throw new Error(`Strike wallet is short ~${gas.missingEth} ETH for gas`);

        const depositAmount = trade.deposit_amount || amount;
        logger(`Funding swap: ${depositAmount} ${fromTicker} from strike wallet...`, 'process');
        txHash = await strike.sendToken(depositAddress, depositAmount, fromTicker);
        logger(`Strike TX confirmed: ${txHash}`, 'success');
      }

      await persistSession(session, 'POLLING', { tradeId, txHash });
      retryPayloadRef.current = null;
      await pollTradeStatus(tradeId, txHash, session);
    } catch (e: any) {
      logger(`Execution failed: ${e.message}`, 'error');
      setState('ERROR');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logger, vault.sendXmr, persistSession, pollTradeStatus]);

  const executeStrikeRef = useRef(executeStrike);
  useEffect(() => { executeStrikeRef.current = executeStrike; }, [executeStrike]);

  // ---------------------------------------------------------------------------
  // Price feed + trigger verification
  // ---------------------------------------------------------------------------

  const verifyAndExecute = useCallback(async (currentPrice: number, activeTrigger: PriceTrigger) => {
    if (isVerifyingRef.current) return;
    isVerifyingRef.current = true;

    const session = sessionRef.current;
    if (!session) { isVerifyingRef.current = false; return; }

    try {
      console.log(`[Vigil] Trigger [${activeTrigger.id}] hit at $${currentPrice}. Verifying route...`);

      const { fromTicker, fromNetwork, toTicker, toNetwork } = currencyDefaults(session);
      const { kyc, log } = getPrivacyParams(session.config.compliance);
      const query = new URLSearchParams({
        from: fromTicker,
        from_net: fromNetwork,
        to: toTicker,
        to_net: toNetwork,
        amount: session.config.amount,
        kyc,
        log,
      });

      const baseUrl = API_BASE.endsWith('/') ? API_BASE.slice(0, -1) : API_BASE;
      const res = await fetch(`${baseUrl}/v2/exchange/estimate?${query.toString()}`);
      if (!res.ok) throw new Error(`Estimate request failed: ${res.status}`);

      const data: EstimateResponse = await res.json();

      // Bail if the watcher was disarmed while verifying
      if (!watcher.hasTriggers()) {
        console.warn('[Vigil] Verification cancelled (engine stopped).');
        return;
      }

      // Re-check trigger against live price (slippage guard)
      let isConfirmed = false;
      if (activeTrigger.operator === '>=' && currentPrice >= activeTrigger.price) isConfirmed = true;
      if (activeTrigger.operator === '<=' && currentPrice <= activeTrigger.price) isConfirmed = true;

      if (!isConfirmed) {
        console.log(`[Vigil] Slippage prevented trigger [${activeTrigger.id}].`);
        return;
      }

      if (!data.routes || data.routes.length === 0) {
        console.warn('[Vigil] No routes available. Skipping execution.');
        return;
      }

      const bestRoute = data.routes.reduce((a, b) => (a.amount_to > b.amount_to ? a : b));
      console.log(`[Vigil] Route verified. Provider: ${bestRoute.provider}. Executing...`);

      // Stop watching before executing
      watcher.stop();

      executeStrikeRef.current({
        provider: bestRoute.provider,
        engine: (bestRoute as any).engine || bestRoute.provider,
        amount_to: bestRoute.amount_to,
        krakenPrice: currentPrice,
        triggerId: activeTrigger.id,
      });
    } catch (e: any) {
      console.error('[Vigil] Verification failed:', e);
    } finally {
      isVerifyingRef.current = false;
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [API_BASE]);

  const watcher = usePriceWatcher(verifyAndExecute);

  // ---------------------------------------------------------------------------
  // Strike wallet management (SNIPE)
  // ---------------------------------------------------------------------------

  const refreshStrike = useCallback(async (session?: VigilSession | null) => {
    const strike = strikeRef.current;
    if (!strike) return;
    const ticker = (session || sessionRef.current)?.config.inputCurrency?.ticker;
    const tickers = ticker ? [ticker] : ['USDT', 'USDC'];
    try {
      const [balances, gas] = await Promise.all([strike.getBalances(tickers), strike.checkGas()]);
      setStrikeBalances(balances);
      setStrikeGas(gas);
    } catch (e: any) {
      console.warn('[Vigil] Strike balance refresh failed:', e.message);
    }
  }, []);

  /**
   * Verify the vault password and load (or create) this identity's strike
   * wallet. Must be called before arming a SNIPE.
   */
  const unlockStrike = useCallback(async (vaultPassword: string, network: string) => {
    if (!identityId || identityId === 'primary') {
      throw new Error('Vigil needs a named identity — create one in Settings before using the strike wallet');
    }

    // Verify the password against the real vault before trusting it for
    // key encryption (same pattern as the dispatch password gate).
    const res = await window.api.walletAction('open', { name: identityId, pwd: vaultPassword });
    if (!res.success) throw new Error(res.error || 'Invalid password');

    const { wallet, address, created } = await StrikeWallet.createOrLoad(identityId, vaultPassword, network, logger);
    strikeRef.current = wallet;
    setStrikeAddress(address);
    setStrikeCreated(created);
    logger(created ? '✨ Strike wallet generated. Back up the key before funding!' : `⚡ Strike wallet loaded: ${address.slice(0, 8)}...`, created ? 'warn' : 'info');
    await refreshStrike();
    return { address, created };
  }, [identityId, logger, refreshStrike]);

  const exportStrikeKey = useCallback(async (vaultPassword: string) => {
    const strike = strikeRef.current;
    if (!strike) throw new Error('Strike wallet not unlocked');
    return strike.exportKey(vaultPassword);
  }, []);

  /**
   * Burner rotation for forward privacy: archive the current key (kept
   * recoverable forever in the retired bucket) and mint a fresh one.
   * Refused while a vigil is active or while the burner still holds funds —
   * 'Sweep leftovers' first. The fresh key re-triggers the backup prompt.
   */
  const regenerateStrike = useCallback(async (vaultPassword: string, network: string, selectedTicker?: string) => {
    if (!identityId || identityId === 'primary') throw new Error('No active identity');
    if (stateRef.current !== 'IDLE' && stateRef.current !== 'COMPLETED' && stateRef.current !== 'ERROR') {
      throw new Error('Disarm the vigil before rotating the burner');
    }
    const strike = strikeRef.current;
    if (!strike) throw new Error('Unlock the strike wallet first');

    // Zero-balance gate: no confirm dialog protects funds like refusing does.
    // Checks the common SNIPE stables PLUS whatever ticker is currently
    // selected in the config — a burner funded with e.g. DAI must not pass
    // unseen. Tokens outside this set can't be detected (registry lookup is
    // per-ticker); the sweep UI handles arbitrary tickers, so sweep first.
    // Any token balance at all blocks; ETH allows true dust below sweepable.
    const tickers = [...new Set(['USDT', 'USDC', selectedTicker?.toUpperCase()].filter(Boolean))] as string[];
    const balances = await strike.getBalances(tickers);
    const hasToken = Object.values(balances.tokens).some(b => parseFloat(b || '0') > 0);
    if (hasToken || parseFloat(balances.eth || '0') > 0.0005) {
      throw new Error('Burner still holds funds — sweep leftovers before rotating');
    }

    const res = await window.api.walletAction('open', { name: identityId, pwd: vaultPassword });
    if (!res.success) throw new Error(res.error || 'Invalid password');

    const archived = await window.api.vigilArchiveStrikeKey(identityId);
    if (!archived.success) throw new Error(archived.error || 'Failed to archive the old key');

    const { wallet, address, created } = await StrikeWallet.createOrLoad(identityId, vaultPassword, network, logger);
    strikeRef.current = wallet;
    setStrikeAddress(address);
    setStrikeCreated(created); // fresh key -> backup prompt fires again
    logger(`🔄 Burner rotated. New address: ${address.slice(0, 10)}… — back up the new key.`, 'warn');
    await refreshStrike();
    return { address };
  }, [identityId, logger, refreshStrike]);

  const refundStrike = useCallback(async (toAddress: string, ticker?: string) => {
    const strike = strikeRef.current;
    if (!strike) throw new Error('Strike wallet not unlocked');
    // No active session when sweeping from the idle config screen — the
    // panel passes the selected input ticker so the token sweep still runs.
    const sweepTicker = ticker ?? sessionRef.current?.config.inputCurrency?.ticker;
    logger('Refunding strike wallet leftovers...', 'process');
    const txHash = await strike.refund(toAddress, sweepTicker);
    logger(`Refund sent: ${txHash}`, 'success');
    await refreshStrike();
    return txHash;
  }, [logger, refreshStrike]);

  // ---------------------------------------------------------------------------
  // Arm
  // ---------------------------------------------------------------------------

  const arm = useCallback(async (mode: 'SNIPE' | 'EJECT', config: VigilSession['config']) => {
    try {
      if (mode === 'SNIPE') {
        const strike = strikeRef.current;
        if (!strike) throw new Error('Unlock the strike wallet before arming a SNIPE');

        // Funding preconditions: token balance covers the order, ETH covers gas
        const ticker = config.inputCurrency?.ticker || 'USDT';
        const balances = await strike.getBalances([ticker]);
        const have = parseFloat(balances.tokens[ticker] ?? balances.eth);
        if (have < parseFloat(config.amount)) {
          throw new Error(`Strike wallet holds ${have} ${ticker}, order needs ${config.amount}`);
        }
        const gas = await strike.checkGas();
        if (!gas.ok) throw new Error(`Strike wallet is short ~${gas.missingEth} ETH for gas`);
      }

      const session: VigilSession = { mode, config, state: 'WATCHING' };
      setActiveSession(session);
      setCompletedTrade(null);
      setPendingSession(null);
      setProgress(0);
      setExecutionStatus('');
      setLogs([]);

      const triggers = buildTriggers(mode, config.triggerPrice, config.stopPrice);
      if (triggers.length === 0) throw new Error('No valid trigger price');

      const { fromTicker, toTicker } = currencyDefaults(session);
      const krakenPair = getKrakenMonitoringPair(mode, fromTicker, toTicker);

      setState('WATCHING');
      logger(`Engine armed in ${mode} mode. Pair: ${krakenPair}. Triggers: ${triggers.map(t => `${t.id} ${t.operator} $${t.price}`).join(' | ')}`, 'info');

      watcher.watch(krakenPair, triggers);
      await persistSession(session, 'ARMED');
    } catch (e: any) {
      logger(`Arming failed: ${e.message}`, 'error');
      setState('ERROR');
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logger, persistSession]);

  // ---------------------------------------------------------------------------
  // Restart recovery
  // ---------------------------------------------------------------------------

  /**
   * Resume a persisted session. ARMED (and EXECUTING, which cannot be safely
   * re-fired) re-arm the watcher; POLLING resumes status tracking. SNIPE
   * sessions need the strike wallet unlocked first.
   */
  const rearmPendingSession = useCallback(async () => {
    const pending = pendingSession;
    if (!pending) return;

    if (pending.mode === 'SNIPE' && !strikeRef.current && pending.phase !== 'POLLING') {
      throw new Error('Unlock the strike wallet first');
    }

    const session: VigilSession = { mode: pending.mode, config: pending.config, state: 'WATCHING' };
    setActiveSession(session);
    setPendingSession(null);

    if (pending.phase === 'POLLING' && pending.tradeId) {
      logger(`Resuming swap tracking (${pending.tradeId})...`, 'info');
      await pollTradeStatus(pending.tradeId, pending.txHash, session);
      return;
    }

    if (pending.phase === 'EXECUTING') {
      logger('Previous trigger fired but execution did not complete. Re-arming watcher — review the provider before retrying.', 'warn');
    }

    await arm(pending.mode, pending.config);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pendingSession, arm, pollTradeStatus, logger]);

  const discardPendingSession = useCallback(async () => {
    setPendingSession(null);
    await clearPersistedSession();
  }, [clearPersistedSession]);

  // ---------------------------------------------------------------------------
  // Retry (after an execution error)
  // ---------------------------------------------------------------------------

  const retry = useCallback(async () => {
    const payload = retryPayloadRef.current;
    const session = sessionRef.current;
    if (!payload || !session) return;
    logger('Retrying execution...', 'process');
    // executeStrike refuses to run while state is TRIGGERED/EXECUTING (its
    // reentrancy guard); stepping back to WATCHING is what re-opens the gate.
    setState('WATCHING');
    await executeStrikeRef.current(payload);
  }, [logger]);

  // ---------------------------------------------------------------------------
  // Abort / Reset
  // ---------------------------------------------------------------------------

  // Ref avoids a stale closure on abort inside the network-switch effect
  const abortRef = useRef<(() => void) | null>(null);
  const abort = useCallback(() => {
    logger('Aborting vigil...', 'warn');
    pollAbortRef.current = true;
    watcher.stop();
    setActiveSession(null);
    setState('IDLE');
    setExecutionStatus('');
    setProgress(0);
    clearPersistedSession();
    logger('Vigil disarmed.', 'info');
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [logger, clearPersistedSession]);
  useEffect(() => { abortRef.current = abort; }, [abort]);

  const reset = useCallback(() => {
    pollAbortRef.current = true;
    watcher.stop();
    setActiveSession(null);
    setState('IDLE');
    setLogs([]);
    setExecutionStatus('');
    setProgress(0);
    setCompletedTrade(null);
    retryPayloadRef.current = null;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Stop polling on unmount (the WS is cleaned up inside usePriceWatcher)
  useEffect(() => () => { pollAbortRef.current = true; }, []);

  // ---------------------------------------------------------------------------
  // Derived price: prefer live WS price, fallback to fiat API
  // ---------------------------------------------------------------------------

  const finalPrice = watcher.price ?? (parseFloat(fiatPrice || '0') || null);

  return {
    state,
    logs,
    executionStatus,
    progress,
    arm,
    abort,
    reset,
    retry,
    price: finalPrice,
    wsConnected: watcher.connected,
    wsDegraded: watcher.degraded,
    priceHistory: watcher.priceHistory,
    reconnectFeed: watcher.reconnect,
    activeSession,
    completedTrade,
    // Restart recovery
    pendingSession,
    rearmPendingSession,
    discardPendingSession,
    // Strike wallet
    strikeAddress,
    strikeBalances,
    strikeGas,
    strikeCreated,
    strikeUnlocked: !!strikeAddress,
    unlockStrike,
    exportStrikeKey,
    regenerateStrike,
    refundStrike,
    refreshStrike,
  };
}
