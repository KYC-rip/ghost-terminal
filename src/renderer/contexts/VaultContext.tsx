import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { WalletService, Transaction } from '../services/walletService';

export interface Identity { id: string; name: string; created: number; }
export interface SubaddressInfo { index: number; address: string; label: string; balance: string; unlockedBalance: string; isUsed: boolean; }
export interface LogEntry { msg: string; timestamp: number; type?: 'info' | 'success' | 'warning' | 'process' | 'error'; }
export type MoneroAccount = {
  "index": number
  "label": string,
  "balance": string,
  "unlockedBalance": string,
  "baseAddress": string
}

export interface VaultContextType {
  accounts: MoneroAccount[];
  selectedAccountIndex: number;
  balance: { total: string; unlocked: string };
  address: string;
  subaddresses: SubaddressInfo[];
  status: string;
  logs: LogEntry[];
  txs: Transaction[];
  currentHeight: number;
  totalHeight: number;
  syncPercent: number;
  nodeLabel: string;
  requestedAction: string | null;
  setRequestedAction: (action: string | null) => void;
  isAppLoading: boolean;
  isInitializing: boolean;
  isLocked: boolean;
  isSending: boolean;
  hasVaultFile: boolean;
  identities: Identity[];
  activeId: string;
  isStagenet: boolean;
  outputs: any[];
  setSelectedAccountIndex: (index: number) => void;
  createAccount: (label: string) => Promise<void>;
  unlock: (password: string, newIdentityName?: string, restoreSeed?: string, restoreHeight?: number, seedLanguage?: string) => Promise<void>;
  lock: () => void;
  sendXmr: (address: string, amount: number, accountIndex?: number, priority?: number) => Promise<string | undefined>;
  sendMulti: (destinations: { address: string; amount: number }[], subaddrIndices?: number[], priority?: number) => Promise<string | undefined>;
  purgeIdentity: (id: string) => Promise<void>;
  switchIdentity: (id: string) => Promise<void>;
  refresh: () => Promise<void>;
  getFeeEstimates: () => Promise<{ fees: string[] } | undefined>;
  createSubaddress: (label?: string) => Promise<string | undefined>;
  getTxKey: (txid: string) => Promise<string | undefined>;
  getTxProof: (txid: string, address: string, message?: string) => Promise<string | undefined>;
  checkTxKey: (txid: string, txKey: string, address: string) => Promise<any>;
  checkTxProof: (txid: string, address: string, message: string, signature: string) => Promise<any>;
  renameIdentity: (id: string, name: string) => Promise<void>;
  renameAccount: (accountIndex: number, newLabel: string) => Promise<void>;
  churn: () => Promise<void>;
  splinter: (fragments: number) => Promise<void>;
  vanishCoin: (keyImage: string) => Promise<void>;
  vanishSubaddress: (subaddressIndex: number) => Promise<void>;
  setSubaddressLabel: (index: number, label: string) => Promise<void>;
  rescan: (height: number) => Promise<void>;
  addLog: (msg: string, type?: LogEntry['type']) => void;

  deepLinkData: {
    address?: string;
    amount?: string;
    description?: string;
    name?: string;
    returnUrl?: string;
  } | null;
  setDeepLinkData: (data: any) => void;
  clearDeepLinkData: () => void;

  // 🛡️ XMR402 Challenge Support
  monero402Challenge: {
    id: string;
    address: string;
    amount: string;
    message: string;
    type: 'agent' | 'deep-link';
    returnUrl?: string;
  } | null;
  clearMonero402Challenge: () => void;
}

const VaultContext = createContext<VaultContextType | undefined>(undefined);

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [selectedAccountIndex, setSelectedAccountIndex] = useState(0);
  const [accounts, setAccounts] = useState<MoneroAccount[]>([]);
  const [balance, setBalance] = useState({ total: '0.0000', unlocked: '0.0000' });
  const [address, setAddress] = useState('');
  const [subaddresses, setSubaddresses] = useState<SubaddressInfo[]>([]);
  const [txs, setTxs] = useState<Transaction[]>([]);
  const [currentHeight, setCurrentHeight] = useState<number>(0);
  const [totalHeight, setTotalHeight] = useState<number>(0);
  const [status, setStatus] = useState<string>('READY');
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [syncPercent, setSyncPercent] = useState(0);
  const [nodeLabel, setNodeLabel] = useState('');
  const [isAppLoading, setIsAppLoading] = useState(true);
  const [isInitializing, setIsInitializing] = useState(false);
  const [isLocked, setIsLocked] = useState(true);
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [activeId, setActiveId] = useState<string>("primary");
  const [hasVaultFile, setHasVaultFile] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [isStagenet, setIsStagenet] = useState(false);
  const [outputs, setOutputs] = useState<any[]>([]);
  const [requestedAction, setRequestedAction] = useState<string | null>(null);
  const [deepLinkData, setDeepLinkData] = useState<any>(null);
  const [monero402Challenge, setMonero402Challenge] = useState<any>(null);
  const lastHeightRef = useRef<number>(0);
  const daemonHeightRef = useRef<number>(0);
  const isRefreshing = useRef<boolean>(false);

  const determineSyncStatus = useCallback((height: number, daemonH: number) => {
    if (daemonH > 0) {
      const blocksLeft = daemonH - height;
      if (blocksLeft > 5) {
        return { status: 'SYNCING', percent: Math.min((height / daemonH) * 100, 99.9) };
      } else {
        return { status: 'SYNCED', percent: 100 };
      }
    }
    return { status: 'SYNCING', percent: 0 };
  }, []);

  const clearDeepLinkData = useCallback(() => setDeepLinkData(null), []);
  const clearMonero402Challenge = useCallback(() => setMonero402Challenge(null), []);

  const addLog = useCallback((msg: string, type: any = 'info') => {
    setLogs(prev => [{ msg, timestamp: Date.now(), type }, ...prev].slice(0, 100));
  }, []);

  const refresh = useCallback(async () => {
    if (isLocked || isInitializing) return;
    // Concurrency guard: skip if another refresh is already in-flight
    if (isRefreshing.current) return;
    isRefreshing.current = true;

    try {
      // During active sync, only fetch accounts + balance — skip heavy calls
      // (transfers, subaddresses, outputs) that compete with padded sync RPC
      const isSyncActive = daemonHeightRef.current > 0 &&
        (daemonHeightRef.current - lastHeightRef.current) > 5;

      const allAccs = await WalletService.getAccounts().catch(() => null);
      if (allAccs) {
        setAccounts(allAccs);
        const currentAcc = allAccs.find(a => a.index === selectedAccountIndex);
        if (currentAcc) {
          setBalance({
            total: currentAcc.balance,
            unlocked: currentAcc.unlockedBalance
          });
        }
      }

      if (isSyncActive) {
        // Lightweight: only height check during sync, rest comes via wallet-events
        const heightRes = await WalletService.getHeight(selectedAccountIndex).catch(() => null);
        if (heightRes) {
          setCurrentHeight(heightRes);
          lastHeightRef.current = heightRes;
          const { status: s, percent: p } = determineSyncStatus(heightRes, daemonHeightRef.current);
          setStatus(s);
          setSyncPercent(p);
        }
      } else {
        // Full refresh when synced — all 5 calls in parallel
        const results = await Promise.allSettled([
          WalletService.getBalance(selectedAccountIndex),
          WalletService.getHeight(selectedAccountIndex),
          WalletService.getTransactions(selectedAccountIndex),
          WalletService.getSubaddresses(selectedAccountIndex),
          WalletService.getOutputs(selectedAccountIndex)
        ]);

        const [balRes, heightRes, txsRes, addrRes, outsRes] = results;

        if (balRes.status === 'fulfilled') setBalance(balRes.value);
        if (heightRes.status === 'fulfilled') {
          const h = heightRes.value;
          setCurrentHeight(h);
          lastHeightRef.current = h;
          const { status: s, percent: p } = determineSyncStatus(h, daemonHeightRef.current);
          setStatus(s);
          setSyncPercent(p);
        }
        if (txsRes.status === 'fulfilled') setTxs(txsRes.value);
        if (addrRes.status === 'fulfilled') {
          setSubaddresses(addrRes.value);
          setAddress(addrRes.value[0]?.address || '');
        }
        if (outsRes.status === 'fulfilled') setOutputs(outsRes.value);
      }
    } catch (e: any) {
      console.warn("Sync gap detected:", e.message);
    } finally {
      isRefreshing.current = false;
    }
  }, [isLocked, isInitializing, selectedAccountIndex, determineSyncStatus]);

  // 🔄 Initial & Periodic Refresh
  // During sync: lightweight poll every 45s. After sync: full refresh every 10s.
  useEffect(() => {
    if (!isLocked && !isInitializing) {
      refresh();
      const isSyncing = status === 'SYNCING';
      const interval = isSyncing ? 45000 : 10000;
      const timer = setInterval(refresh, interval);
      return () => clearInterval(timer);
    }
  }, [isLocked, isInitializing, refresh, status]);

  useEffect(() => {
    console.log("🔌 Initializing Core Log Listener...");
    if (window.api.onCoreLog) {
      const cleanup = window.api.onCoreLog((data) => {
        // SYNC_DATA / TOR_STATUS are machine channels piggybacked on core-log
        // (consumed by onWalletEvent / onTorStatus). Don't show them as logs.
        if (data.source === 'SYNC_DATA' || data.source === 'TOR_STATUS') return;

        // Backend data usually looks like { source: 'TOR', level: 'info', message: '...' }
        const typeMap: Record<string, string> = {
          'info': 'info',
          'error': 'error',
          'warn': 'warning',
          'success': 'success'
        };

        const displayMsg = `[${data.source}] ${data.message}`;
        addLog(displayMsg, typeMap[data.level] || 'info');

        if (data.level === 'error') {
          console.error("CORE_FATAL:", data.message);
        }
      });

      return () => cleanup(); // Auto-cleanup listener on unmount to prevent leaks
    }
  }, [addLog]);

  // 🔄 Wallet Event Listener (Real-time updates from SyncWatcher)
  useEffect(() => {
    if (window.api.onWalletEvent) {
      const cleanup = window.api.onWalletEvent((event) => {
        if (event.type === 'SYNC_UPDATE' && event.payload?.height) {
          const newHeight = event.payload.height;
          const daemonH = event.payload.daemonHeight || 0;
          setCurrentHeight(newHeight);
          lastHeightRef.current = newHeight;

          if (daemonH > 0) {
            daemonHeightRef.current = daemonH;
            setTotalHeight(daemonH);
          }

          const { status: s, percent: p } = determineSyncStatus(newHeight, daemonHeightRef.current);
          setStatus(s);
          setSyncPercent(p);
          // Track connected node name (Tauri scanner reports it in the event payload)
          if (event.payload.nodeLabel) setNodeLabel(event.payload.nodeLabel);
        }
        if (event.type === 'BALANCE_CHANGED' && event.payload?.balance !== undefined) {
          // During sync, just update balance inline instead of triggering a full
          // refresh (5 RPC calls) that competes with padded sync for the wallet-rpc
          const isSyncing = daemonHeightRef.current > 0 &&
            (daemonHeightRef.current - lastHeightRef.current) > 5;
          if (isSyncing) {
            const pico = event.payload.balance;
            const unlocked = event.payload.unlocked ?? pico;
            const fmt = (v: number) => {
              if (v < 0) return '0.0000';
              const w = Math.floor(v / 1e12);
              const f = v % 1e12;
              return `${w}.${f.toString().padStart(12, '0')}`;
            };
            setBalance({ total: fmt(pico), unlocked: fmt(unlocked) });
          } else {
            refresh();
          }
        }
      });
      return () => cleanup();
    }
  }, [refresh, determineSyncStatus, selectedAccountIndex]);

  // 🛡️ XMR402 Challenge Listeners
  useEffect(() => {
    const cleanupAgent = window.api.onAgentPay402?.((data: any) => {
      console.log('[VaultContext] Received Agent XMR402 challenge:', data);
      setMonero402Challenge({ ...data, type: 'agent' });
    });

    const cleanupDeep = window.api.onXmr402Challenge?.((url: string) => {
      console.log('[VaultContext] Received DeepLink XMR402 challenge:', url);
      try {
        const u = new URL(url.replace('xmr402://', 'http://402/'));
        const address = u.pathname.replace('/', '');
        let amount = u.searchParams.get('amount') || '';
        const message = u.searchParams.get('message') || u.searchParams.get('nonce') || '';
        const returnUrl = u.searchParams.get('return_url') || undefined;
        
        // 🛡️ Amount Normalization: XMR vs Piconero
        // If amount is a large integer (> 1M), assume it's atomic units (piconero)
        if (amount && /^\d+$/.test(amount)) {
          const num = BigInt(amount);
          if (num >= BigInt(1000000)) {
            // Convert to XMR string: divide by 1e12
            const whole = num / BigInt(1e12);
            const frac = num % BigInt(1e12);
            amount = `${whole}.${frac.toString().padStart(12, '0')}`.replace(/\.?0+$/, "");
          }
        }

        setMonero402Challenge({
          id: 'deep-link',
          address,
          amount,
          message,
          type: 'deep-link',
          returnUrl
        });
      } catch (e) {
        console.error('Failed to parse XMR402 deep link', e);
      }
    });

    return () => {
      cleanupAgent?.();
      cleanupDeep?.();
    };
  }, []);


  const unlock = useCallback(async (
    password: string,
    newIdentityName?: string,
    restoreSeed?: string,
    restoreHeight?: number,
    seedLanguage?: string
  ) => {
    setIsInitializing(true);
    addLog("🛡️ Waiting for darknet uplink to stabilize...", "process");
    try {
      // 🔄 1. Await background network readiness (Tor + Proxy + Node Discovery)

      // Initial check: if engine is paralyzed, attempt forced restart
      let uplink = await window.api.getUplinkStatus();
      if (uplink.status === 'ERROR') {
        addLog("🔄 Engine is currently paralyzed. Attempting reboot...", "warning");
        await window.api.retryEngine();
        await new Promise(r => setTimeout(r, 3000)); // Give engine some buffer time to change state
      }

      for (let i = 0; i < 20; i++) {
        uplink = await window.api.getUplinkStatus();
        if (uplink.status === 'ONLINE') break;
        if (uplink.status === 'ERROR') throw new Error(uplink.error || "Engine failed to start.");

        addLog(`⏳ Uplink bootstrapping... (Attempt ${i + 1}/20)`, "warning");
        await new Promise(r => setTimeout(r, 3000));
      }

      if (!uplink || uplink.status !== 'ONLINE') {
        throw new Error("UPLINK_TIMEOUT: Could not establish secure route.");
      }

      // Determine ID for the current operation
      let targetId = activeId;
      if (!newIdentityName && !targetId) {
        targetId = await window.api.getActiveIdentity();
      }

      setIsStagenet(uplink.isStagenet);

      // 🛡️ 2. Identity management and RPC interaction
      if (newIdentityName) {
        const randomId = Math.random().toString(36).substring(2, 9);
        const newId = `vault_${Date.now()}_${randomId}`;

        if (restoreSeed) {
          addLog(`🌅 Restoring identity from seed: ${newIdentityName}...`, 'process');
        } else {
          addLog(`🆕 Constructing fresh identity: ${newIdentityName}...`, 'process');
        }

        const res = await window.api.walletAction('create', {
          name: newId,
          pwd: password,
          seed: restoreSeed,
          height: restoreHeight,
          language: seedLanguage
        });

        if (!res.success) throw new Error(res.error);

        const newIdentity = { id: newId, name: newIdentityName, created: Date.now() };
        const updated = [...identities, newIdentity];

        await window.api.saveIdentities(updated);
        await window.api.setActiveIdentity(newId);

        setIdentities(updated);
        setActiveId(newId);
        targetId = newId;
      } else {
        if (!targetId || targetId === 'primary') {
          throw new Error("Please create a new identity first.");
        }

        addLog(`🌅 Opening vault: ${targetId}...`, 'process');

        // --- 🛡️ RPC CONNECTION RESILIENCE ---
        let res: any = null;
        for (let retry = 0; retry < 5; retry++) {
          try {
            res = await window.api.walletAction('open', { name: targetId, pwd: password });
            if (res.success) break;

            // If it's a specific "No wallet file" error, don't retry, just throw
            if (res.error?.includes('No wallet file')) throw new Error(res.error);

            throw new Error(res.error || 'Unknown RPC error');
          } catch (error: any) {
            const isConnErr = error.message?.includes('CONNECTION_REFUSED') || error.message?.includes('ECONNREFUSED');

            if (isConnErr && retry < 4) {
              addLog(`⏳ RPC Uplink initializing... (Retry ${retry + 1}/5)`, 'warning');
              await new Promise(r => setTimeout(r, 2000));
              continue;
            }
            throw error;
          }
        }
        // --- ---------------------------- ---

        if (!res?.success) throw new Error(res?.error || 'Failed to establish vault session.');

        // 🛡️ [SOFT UNLOCK OPTIMIZATION]
        // If the backend already had the wallet open (Soft Lock state), it returns a snapshot.
        // We populate the UI instantly instead of waiting for the next polling cycle.
        if (res.isSoft && res.snapshot) {
          const snapshot = res.snapshot;
          const formatPico = (v: number) => {
            if (v < 0) return '0.0000';
            const whole = Math.floor(v / 1e12);
            const frac = v % 1e12;
            return `${whole}.${frac.toString().padStart(12, '0')}`;
          };
          setBalance(prev => ({
            total: snapshot.balance > -1 ? formatPico(snapshot.balance) : prev.total,
            unlocked: prev.unlocked
          }));
          if (snapshot.height > -1) setCurrentHeight(snapshot.height);
          addLog("⚡ Vault session resumed instantly. Background sync was continuous.", "success");
        }
      }

      setHasVaultFile(true);
      setIsLocked(false);
      setIsInitializing(false);
      addLog("✅ Vault unlocked. Synchronizing with network...", "success");

    } catch (e: any) {
      addLog(`❌ FATAL: ${e.message}`, 'error');
      setIsInitializing(false);
      setIsLocked(true);
      throw e;
    }
  }, [activeId, identities, addLog]);

  const lock = useCallback(async () => {
    // 1. 🟢 Immediate UI update (instant lock manifestation)
    setIsLocked(true);
    addLog("🔒 Vault Secured. Background sync continues...", 'warning');

    // 2. 🧹 Purge sensitive state
    setAddress('');
    setBalance({ total: '0.0000', unlocked: '0.0000' });
    setSubaddresses([]);
    setTxs([]);
    setOutputs([]);
    setStatus('READY');

    // 3. ⏳ Soft-lock the backend. On Tauri this ALWAYS runs (unlike Electron
    // which skips the close for an armed EJECT) — the Rust soft-lock is the
    // single source of truth: state.lock() zeroes the spend key UNLESS the
    // vigil_hot flag is set (an armed EJECT, mirrored via set_vigil_hot), in
    // which case it keeps the spend key resident so the order dispatches
    // unattended. The view key + scanner always stay alive for background sync.
    window.api.walletAction('close', {}).catch(() => { });

  }, [addLog]);

  const sendXmr = useCallback(async (destination: string, amount: number, accountIndex?: number, priority: number = 0) => {
    setIsSending(true);
    addLog(`💸 Preparing transfer of ${amount} XMR (Priority: ${priority})...`, 'process');
    try {
      const targetAcc = accountIndex ?? selectedAccountIndex;
      const txHash = await WalletService.sendTransaction(destination, amount, targetAcc, priority);
      if (!txHash) throw new Error("EMPTY_TX_HASH: Daemon accepted but returned no ID.");

      addLog(`✅ Transaction dispatched: ${txHash}`, 'success');
      await refresh();
      return txHash;
    } catch (e: any) {
      addLog(`❌ SEND_ERROR: ${e.message}`, 'error');
      throw e; // Rethrow to let UI handle failure
    } finally {
      setIsSending(false);
    }
  }, [refresh, addLog]);

  const createSubaddress = useCallback(async (label?: string, accountIndex?: number) => {
    try {
      const address = await WalletService.createSubaddress(label || '', accountIndex || 0);
      await refresh();
      return address;
    } catch (e) { console.warn('[Vault] Subaddress creation failed:', e); }
  }, [refresh]);

  const purgeIdentity = useCallback(async (id: string) => {
    try {
      // Always attempt to close the wallet via RPC first — the wallet-rpc process
      // holds a file lock on .keys files, preventing deletion
      await window.api.walletAction('close', {}).catch(() => { });

      // Physically delete .keys and cache files from disk
      const res = await window.api.deleteIdentityFiles(id);
      if (!res.success) {
        throw new Error(res.error || 'Failed to delete wallet files');
      }

      // Refresh identity list and reload
      const updated = identities.filter(i => i.id !== id);
      setIdentities(updated);
      location.reload();
    } catch (e: any) {
      addLog(`❌ PURGE_FAILED: ${e.message}`, 'error');
      alert(`PURGE_FAILED: ${e.message}`);
    }
  }, [identities, addLog]);

  const renameIdentity = useCallback(async (id: string, name: string) => {
    const nameExists = identities.some(i => i.id !== id && i.name.toLowerCase() === name.toLowerCase());
    if (nameExists) throw new Error(`CONFLICT: Name "${name}" is already in use.`);
    await window.api.renameIdentity(id, name);
    const ids = await window.api.getIdentities();
    setIdentities(ids);
  }, [identities]);

  const createAccount = useCallback(async (label: string) => {
    try {
      addLog(`Generating new account: ${label}...`, 'info');
      const newAcc = await WalletService.createAccount(label);

      setSelectedAccountIndex(newAcc.index);

      await refresh();

      addLog(`Account #${newAcc.index} initialized.`, 'success');
    } catch (e: any) {
      addLog(`Account generation failed: ${e.message}`, 'error');
    }
  }, [refresh, addLog]);

  // Boot Sequence
  useEffect(() => {
    const loadIdentities = async () => {
      try {
        const [ids, current] = await Promise.all([
          window.api.getIdentities(),
          window.api.getActiveIdentity()
        ]);
        const validIds = ids || [];
        setIdentities(validIds);
        const nextActiveId = current || (validIds.length > 0 ? validIds[0].id : '');
        setActiveId(nextActiveId);
        setHasVaultFile(validIds.length > 0 && !!nextActiveId);
      } catch (err) { console.warn('[Vault] Failed to load identities:', err); } finally {
        setIsAppLoading(false);
      }
    };
    loadIdentities();
  }, []);

  const rescan = useCallback(async (height: number) => {
    await WalletService.rescan(height);
    await refresh();
  }, [refresh]);

  const renameAccount = useCallback(async (accountIndex: number, newLabel: string) => {
    await WalletService.renameAccount(accountIndex, newLabel);
    await refresh();
  }, [refresh]);

  const churn = useCallback(async (accountIndex?: number) => {
    await WalletService.churn(accountIndex || selectedAccountIndex);
    refresh();
  }, [selectedAccountIndex, refresh]);

  const splinter = useCallback(async (fragments: number) => {
    await WalletService.splinter(selectedAccountIndex, fragments);
    refresh();
  }, [selectedAccountIndex, refresh]);

  const vanishCoin = useCallback(async (keyImage: string) => {
    const txHash = await WalletService.vanishCoin(keyImage, selectedAccountIndex);
    if (txHash) {
      addLog(`✅ Single UTXO vanished! TXID: ${txHash}`, 'success');
    }
    await refresh();
  }, [selectedAccountIndex, refresh, addLog]);

  const vanishSubaddress = useCallback(async (subaddressIndex: number) => {
    const result = await WalletService.vanishSubaddress(subaddressIndex, selectedAccountIndex);
    if (result.txHash) {
      addLog(`✅ Subaddress #${subaddressIndex} vanished → new address. TXID: ${result.txHash}`, 'success');
    }
    await refresh();
  }, [selectedAccountIndex, refresh, addLog]);

  const setSubaddressLabel = useCallback(async (index: number, label: string, accountIndex?: number) => {
    await WalletService.setSubaddressLabel(index, label, accountIndex || selectedAccountIndex);
    await refresh();
  }, [selectedAccountIndex, refresh]);

  const switchIdentity = useCallback(async (id: string) => {
    await window.api.setActiveIdentity(id);
    location.reload();
  }, []);

  const sendMulti = useCallback(async (destinations: { address: string; amount: number }[], subaddrIndices?: number[], priority: number = 0) => {
    setIsSending(true);
    try {
      const res = await WalletService.sendMulti(destinations, selectedAccountIndex, subaddrIndices, priority);
      const txHash = res.tx_hash_list?.[0] || res.tx_hash;

      addLog(`✅ Multi-send dispatched: ${destinations.length} recipient(s)`, 'success');
      await refresh();
      return txHash;
    } catch (e: any) {
      addLog(`❌ MULTI_SEND_ERROR: ${e.message}`, 'error');
      throw e;
    } finally {
      setIsSending(false);
    }
  }, [selectedAccountIndex, refresh, addLog]);

  const getFeeEstimates = useCallback(async () => {
    try {
      return await WalletService.getFeeEstimates();
    } catch (e: any) {
      console.error('[VaultContext] getFeeEstimates failed:', e.message);
      return undefined;
    }
  }, []);

  const getTxKey = useCallback(async (txid: string) => {
    try {
      return await WalletService.getTxKey(txid);
    } catch (e: any) {
      addLog(`❌ Failed to fetch TX Key: ${e.message}`, 'error');
      return undefined;
    }
  }, [addLog]);

  const getTxProof = useCallback(async (txid: string, address: string, message: string = "") => {
    try {
      return await WalletService.getTxProof(txid, address, message);
    } catch (e: any) {
      addLog(`❌ Failed to generate TX Proof: ${e.message}`, 'error');
      return undefined;
    }
  }, [addLog]);

  const checkTxKey = useCallback(async (txid: string, txKey: string, address: string) => {
    try {
      return await WalletService.checkTxKey(txid, txKey, address);
    } catch (e: any) {
      addLog(`❌ Verification failed: ${e.message}`, 'error');
      return undefined;
    }
  }, [addLog]);

  const checkTxProof = useCallback(async (txid: string, address: string, message: string, signature: string) => {
    try {
      return await WalletService.checkTxProof(txid, address, message, signature);
    } catch (e: any) {
      addLog(`❌ Verification failed: ${e.message}`, 'error');
      return undefined;
    }
  }, [addLog]);
  // ⌨️ Tactical Shortcut: Cmd+L to Lock
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'l') {
        e.preventDefault();
        if (!isLocked) {
          addLog("⌨️ Tactical lock triggered via Cmd+L.", "process");
          lock();
        }
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isLocked, lock, addLog]);

  const value = React.useMemo(() => ({
    accounts, selectedAccountIndex,
    balance, address, subaddresses, status, logs, txs, currentHeight, totalHeight, syncPercent, nodeLabel,
    isAppLoading, isInitializing, isLocked, isSending, hasVaultFile, identities, activeId, isStagenet,
    unlock, lock, purgeIdentity, sendXmr, refresh, createSubaddress, renameIdentity, outputs, setSelectedAccountIndex, addLog,
    rescan, renameAccount, churn, splinter, vanishCoin, vanishSubaddress, setSubaddressLabel, switchIdentity,
    createAccount, sendMulti, getFeeEstimates,
    getTxKey, getTxProof, checkTxKey, checkTxProof,
    requestedAction, setRequestedAction,
    deepLinkData, setDeepLinkData, clearDeepLinkData,
    monero402Challenge, clearMonero402Challenge
  }), [
    accounts, selectedAccountIndex, balance, address, subaddresses, status, logs, txs,
    currentHeight, totalHeight, syncPercent, nodeLabel, isAppLoading, isInitializing, isLocked,
    isSending, hasVaultFile, identities, activeId, isStagenet, outputs,
    unlock, lock, purgeIdentity, sendXmr, refresh, createSubaddress, renameIdentity, setSelectedAccountIndex, addLog,
    rescan, renameAccount, churn, splinter, vanishCoin, vanishSubaddress, setSubaddressLabel, switchIdentity,
    createAccount, sendMulti, getFeeEstimates, requestedAction, setRequestedAction,
    getTxKey, getTxProof, checkTxKey, checkTxProof,
    deepLinkData, setDeepLinkData, clearDeepLinkData,
    monero402Challenge, clearMonero402Challenge
  ]);

  return <VaultContext.Provider value={value}>{children}</VaultContext.Provider>;
}

export function useVault() {
  const context = useContext(VaultContext);
  if (!context) throw new Error('useVault must be used within VaultProvider');
  return context;
}