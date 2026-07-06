/**
 * Tauri Bridge — compatibility shim that maps window.api.* (Electron preload)
 * to Tauri's invoke() / listen() APIs.
 *
 * This allows the entire React frontend to work unchanged during migration.
 */
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

const isTauri = !!(window as any).__TAURI_INTERNALS__;

function createTauriApi() {
  return {
    // ── Config ──
    getConfig: () => invoke('get_config'),
    saveConfigAndReload: (config: any) =>
      invoke('save_config_and_reload', { config })
        .then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    saveConfigOnly: (config: any) =>
      invoke('save_config_only', { config })
        .then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: String(e) })),

    // ── Identity ──
    getIdentities: () => invoke('get_identities'),
    detectLegacyWallets: () => invoke('detect_legacy_wallets'),
    // Fetch an external URL through the configured uplink (Tor/SOCKS/clearnet) so
    // the renderer never leaks the user's IP with a direct clearnet fetch.
    proxiedGet: (url: string) => invoke('proxied_get', { url }),
    saveIdentities: async (ids: any) => {
      // The frontend sends the full identity list after modifications.
      // We need to persist this since Rust commands also manage identities.
      try {
        await invoke('save_identities', { ids });
      } catch {
        // save_identities command may not exist yet — identities managed by create/delete
      }
    },
    getActiveIdentity: async () => {
      try {
        // Reads the persisted active_identity file (backend falls back to the
        // first identity if it's missing/stale). Must NOT just return ids[0],
        // or switching wallets would never stick across reload.
        return (await invoke('get_active_identity')) as string;
      } catch {
        return '';
      }
    },
    setActiveIdentity: (id: string) => invoke('switch_identity', { id }),
    renameIdentity: (id: string, name: string) => invoke('rename_identity', { id, name }),
    deleteIdentityFiles: (id: string) => invoke('delete_identity', { id }).then(() => ({ success: true })),

    // ── Wallet Actions ──
    walletAction: async (action: string, payload?: any) => {
      try {
        switch (action) {
          case 'create': {
            const result = await invoke('create_wallet', {
              name: payload.name,
              password: payload.pwd,
              seed: payload.seed || null,
              restoreHeight: payload.height || null,
            });
            // Auto-open the wallet after creation (Electron RPC does this implicitly)
            await invoke('open_wallet', { name: payload.name, password: payload.pwd });
            return { success: true, ...(result as any) };
          }
          case 'open':
            await invoke('open_wallet', { name: payload.name, password: payload.pwd });
            return { success: true };
          case 'close':
            await invoke('close_wallet');
            return { success: true };
          case 'mnemonic': {
            const seed = await invoke('get_mnemonic');
            return { success: true, seed };
          }
          default:
            return { success: false, error: `Unknown action: ${action}` };
        }
      } catch (e: any) {
        return { success: false, error: e.toString() };
      }
    },

    // ── Uplink Status ──
    // In Tauri, there's no separate engine process — the wallet connects directly.
    // Always return ONLINE so the unlock flow proceeds.
    getUplinkStatus: async () => ({
      status: 'ONLINE',
      isStagenet: false,
      error: '',
    }),
    retryEngine: () => Promise.resolve(),

    // ── Event Listeners ──
    onEngineStatus: (callback: any) => {
      let unlisten: UnlistenFn | null = null;
      listen('engine-status', (event) => callback(event.payload)).then(fn => unlisten = fn);
      return () => { unlisten?.(); };
    },
    onCoreLog: (callback: any) => {
      let unlisten: UnlistenFn | null = null;
      listen('core-log', (event) => callback(event.payload)).then(fn => unlisten = fn);
      return () => { unlisten?.(); };
    },
    onTorStatus: (callback: any) => {
      // Piggybacked on core-log with source="TOR_STATUS": "status|percent|message".
      let unlisten: UnlistenFn | null = null;
      listen('core-log', (event) => {
        const p = event.payload as any;
        if (p.source === 'TOR_STATUS') {
          const [status, percent, message] = (p.message as string).split('|');
          callback({ status, percent: parseInt(percent) || 0, message: message || '' });
        }
      }).then(fn => unlisten = fn);
      return () => { unlisten?.(); };
    },
    onWalletEvent: (callback: any) => {
      // Workaround: Tauri v2 custom events don't reach JS from background tokio tasks.
      // Sync data is piggybacked on core-log with source="SYNC_DATA".
      let unlisten: UnlistenFn | null = null;
      listen('core-log', (event) => {
        const p = event.payload as any;
        if (p.source === 'SYNC_DATA') {
          // Parse: "STATUS|height|daemonHeight|percent|nodeLabel"
          const parts = (p.message as string).split('|');
          if (parts.length >= 5) {
            callback({
              type: 'SYNC_UPDATE',
              payload: {
                height: parseInt(parts[1]),
                daemonHeight: parseInt(parts[2]),
                nodeLabel: parts[4],
              }
            });
          }
        }
        if (p.source === 'BALANCE_DATA') {
          // Parse: "total|unlocked" (atomic piconero)
          const parts = (p.message as string).split('|');
          if (parts.length >= 2) {
            callback({
              type: 'BALANCE_CHANGED',
              payload: {
                balance: parseInt(parts[0]),
                unlocked: parseInt(parts[1]),
              }
            });
          }
        }
      }).then(fn => unlisten = fn);

      return () => { unlisten?.(); };
    },
    onVaultShutdown: (callback: any) => {
      let unlisten: UnlistenFn | null = null;
      listen('vault-shutdown', (event) => { callback(event.payload); unlisten?.(); }).then(fn => unlisten = fn);
      return () => { unlisten?.(); };
    },
    onDeepLink: (callback: (url: string) => void) => {
      let unlisten: UnlistenFn | null = null;
      listen('deep-link', (event) => callback(event.payload as string)).then(fn => unlisten = fn);
      return () => { unlisten?.(); };
    },

    // ── Proxy RPC → Tauri commands ──
    // The frontend's RpcClient.call(method, params) goes through here.
    // We map each RPC method to the corresponding Tauri command with correct arg names.
    proxyRequest: async (payload: { method: string; params: any }) => {
      const p = payload.params || {};
      try {
        let result: any;
        switch (payload.method) {
          case 'get_accounts': {
            const accs: any[] = await invoke('get_accounts') as any[];
            result = {
              subaddress_accounts: accs.map((a: any) => ({
                account_index: a.index,
                label: a.label,
                balance: a.balance,
                unlocked_balance: a.unlockedBalance || a.unlocked_balance || '0',
                base_address: a.baseAddress || a.base_address || '',
              }))
            };
            break;
          }
          case 'get_balance':
          case 'getbalance': {
            const bal: any = await invoke('get_balance', { accountIndex: p.account_index || 0 });
            // Populate per_subaddress from get_subaddresses (atomic piconero strings)
            // so the Addresses tab shows real per-subaddress balances — walletService
            // .getSubaddresses reads them from here. Was hardcoded [] → every row "--".
            const subsForBal: any[] = await invoke('get_subaddresses', { accountIndex: p.account_index || 0 }) as any[];
            result = {
              total_balance: bal.total,
              unlocked_balance: bal.unlocked,
              per_subaddress: subsForBal.map((s: any) => ({
                address_index: s.index,
                balance: Number(s.balance) || 0,
                unlocked_balance: Number(s.unlockedBalance ?? s.unlocked_balance) || 0,
              })),
            };
            break;
          }
          case 'get_height':
            result = { height: await invoke('get_height') };
            break;
          case 'get_address': {
            const subs: any[] = await invoke('get_subaddresses', { accountIndex: p.account_index || 0 }) as any[];
            result = {
              address: subs[0]?.address || '',
              addresses: subs.map((s: any) => ({
                address_index: s.index,
                address: s.address,
                label: s.label,
                used: s.isUsed || s.is_used || false,
              }))
            };
            break;
          }
          case 'create_address':
            const addr = await invoke('create_subaddress', { label: p.label || 'Payment', accountIndex: p.account_index });
            result = { address: addr };
            break;
          case 'label_address':
            await invoke('set_subaddress_label', { index: p.index?.minor || 0, label: p.label || '', accountIndex: p.account_index || 0 });
            result = {};
            break;
          case 'transfer': {
            // wallet-rpc 'transfer' is one-call: prepare THEN relay. prepare_transfer
            // only builds the unsigned tx (fee + metadata) and does NOT broadcast —
            // so we chain relay_transfer and return the real broadcast tx hash.
            // (Previously this only prepared, so tx_hash was undefined → EMPTY_TX_HASH
            // and funds never moved.)
            const prep: any = await invoke('prepare_transfer', {
              destinations: (p.destinations || []).map((d: any) => ({ address: d.address || d.destination, amount: String(d.amount) })),
              accountIndex: p.account_index || 0,
              priority: p.priority,
            });
            const txid = await invoke('relay_transfer', { txMetadata: prep.txMetadata });
            result = { tx_hash: txid, fee: prep.fee, amount: prep.amount };
            break;
          }
          case 'relay_tx':
            result = { tx_hash: await invoke('relay_transfer', { txMetadata: p.hex }) };
            break;
          case 'get_transfers':
            // Rust returns the { in, out, pending } RPC shape directly.
            result = await invoke('get_transactions', { accountIndex: p.account_index || 0 });
            break;
          case 'incoming_transfers':
            // Rust returns the { transfers: [...] } RPC shape directly.
            result = await invoke('get_outputs', { accountIndex: p.account_index || 0 });
            break;
          case 'get_tx_key':
            result = { tx_key: await invoke('get_tx_key', { txid: p.txid }) };
            break;
          case 'get_tx_proof':
            result = { signature: await invoke('get_tx_proof', { txid: p.txid, address: p.address, message: p.message }) };
            break;
          case 'check_tx_key':
            result = await invoke('check_tx_key', { txid: p.txid, txKey: p.tx_key, address: p.address });
            break;
          case 'check_tx_proof':
            result = await invoke('check_tx_proof', { txid: p.txid, address: p.address, message: p.message, signature: p.signature });
            break;
          case 'get_fee_estimate':
            // Return a stub — the real fee comes during prepare_transfer
            result = { fees: [20000, 80000, 320000, 4000000], quantization_mask: 10000, status: 'OK' };
            break;
          case 'refresh':
            await invoke('refresh');
            result = { blocks_fetched: 0 };
            break;
          case 'store':
            result = {};
            break;
          case 'create_account':
            result = await invoke('create_account', { label: p.label || 'Account' });
            break;
          case 'label_account':
            await invoke('rename_account', { accountIndex: p.account_index, newLabel: p.label });
            result = {};
            break;
          case 'rescan_blockchain':
            await invoke('rescan', { height: p.height || 0 });
            result = {};
            break;
          case 'sweep_all': {
            // Returns ALL batch hashes — a >24-output sweep broadcasts multiple txs.
            const sweepHashes = await invoke('sweep_all', {
              address: p.address,
              accountIndex: p.account_index || 0,
              priority: p.priority || 0,
              // Forward the subaddress filter so "vanish subaddress" sweeps only that
              // subaddress's outputs, not the whole wallet. null => sweep everything.
              subaddrIndices: p.subaddr_indices || null,
            }) as string[];
            result = { tx_hash_list: sweepHashes, tx_hash: sweepHashes[0] };
            break;
          }
          case 'sweep_single': {
            const singleHashes = await invoke('sweep_single', {
              address: p.address,
              keyImage: p.key_image,
              priority: p.priority || 0,
            }) as string[];
            result = { tx_hash_list: singleHashes, tx_hash: singleHashes[0] };
            break;
          }
          default:
            return { success: false, error: `Unmapped RPC method: ${payload.method}` };
        }
        return { success: true, result };
      } catch (e: any) {
        return { success: false, error: e.toString() };
      }
    },

    // ── No-ops (Tauri has no RPC mutex) ──
    pauseWatcher: () => Promise.resolve(),
    resumeWatcher: () => Promise.resolve(),

    // ── App Info ──
    getAppInfo: () =>
      invoke('get_app_info').catch(() => ({
        version: '2.0.0',
        appDataPath: '',
        walletsPath: '',
        platform: navigator.platform.includes('Mac') ? 'darwin' : navigator.platform.includes('Win') ? 'win32' : 'linux',
        isPackaged: false,
      })),
    openPath: (path: string) =>
      invoke('reveal_path', { path })
        .then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    openExternal: (url: string, _options?: any) => {
      // Use Tauri shell plugin for proper external URL opening
      import('@tauri-apps/plugin-shell').then(({ open }) => open(url)).catch(() => window.open(url, '_blank'));
      return Promise.resolve({ success: true });
    },
    checkForUpdates: (include_prereleases: boolean) =>
      invoke('check_for_updates', { includePrereleases: include_prereleases })
        .catch((e: any) => ({ success: false, error: String(e) })),
    selectBackgroundImage: () =>
      invoke('select_background_image')
        .then((data: any) => ({ success: !!data, data: data || undefined }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    saveGhostTrade: (txHash: string, tradeId: string) =>
      invoke('save_ghost_trade', { txHash, tradeId })
        .then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    getGhostTrades: () =>
      invoke('get_ghost_trades')
        .then((trades: any) => ({ success: true, trades: trades || {} }))
        .catch(() => ({ success: false, trades: {} })),

    // ── XMR402 payment receipts (KV) ──
    saveXmr402Payment: (nonce: string, txid: string, proof: string, amount: string, returnUrl?: string) =>
      invoke('save_xmr402_payment', { nonce, txid, proof, amount, returnUrl })
        .then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    getXmr402Payment: (nonce: string) =>
      invoke('get_xmr402_payment', { nonce })
        .then((payment: any) => (payment ? { success: true, payment } : { success: false }))
        .catch((e: any) => ({ success: false, error: String(e) })),
    getAllXmr402Payments: () =>
      invoke('get_all_xmr402_payments')
        .then((payments: any) => ({ success: true, payments: payments || {} }))
        .catch(() => ({ success: false, payments: {} })),
    updateAgentConfig: (_config: any) => Promise.resolve(),
    onAgentActivity: (_callback: any) => () => {},
    onAgentPay402: (_callback: any) => () => {},
    onXmr402Challenge: (_callback: any) => () => {},
    authorizeXmr402: (_id: string, _password: string | null) => Promise.resolve({ success: false }),
    clearCache: () => Promise.resolve(),

    // Force the scanner to re-race the node pool (manual "re-select node").
    reselectNode: () => invoke('reselect_node'),

    // ── Send (legacy IPC) ──
    sendXmr: async (address: string, amountAtomic: string, accountIndex?: number) => {
      try {
        // prepare_transfer only builds the unsigned tx (fee + metadata); it
        // does NOT broadcast. Chain relay_transfer to actually send, matching
        // wallet-rpc's one-call 'transfer' semantics the renderer expects.
        // Returns the real broadcast tx hash (was previously returning the
        // PreparedTx object as txid and never relaying — funds never moved).
        const prepared: any = await invoke('prepare_transfer', {
          destinations: [{ address, amount: amountAtomic }],
          accountIndex: accountIndex || 0,
        });
        const txid = await invoke('relay_transfer', { txMetadata: prepared.txMetadata });
        return { success: true, txid };
      } catch (e: any) {
        return { success: false, error: e.toString() };
      }
    },
    getTxProof: async (txHash: string, address: string, message: string) => {
      try {
        const signature = await invoke('get_tx_proof', { txid: txHash, address, message });
        return { success: true, signature };
      } catch (e: any) {
        return { success: false, error: e.toString() };
      }
    },

    // Verify a vault password without unlocking/restarting the scanner.
    verifyPassword: (identityId: string, password: string) =>
      invoke('verify_password', { identityId, password }).catch(() => false) as Promise<boolean>,

    // ── Vigil (limit-order) persistence + price history ──
    vigilSaveStrikeKey: (identityId: string, blob: any) =>
      invoke('vigil_save_strike_key', { identityId, blob }).then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: e.toString() })),
    vigilGetStrikeKey: (identityId: string) =>
      invoke('vigil_get_strike_key', { identityId }).catch(() => null),
    vigilDeleteStrikeKey: (identityId: string) =>
      invoke('vigil_delete_strike_key', { identityId }).then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: e.toString() })),
    vigilArchiveStrikeKey: (identityId: string) =>
      invoke('vigil_archive_strike_key', { identityId }).then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: e.toString() })),
    vigilSaveSession: (identityId: string, session: any) =>
      invoke('vigil_save_session', { identityId, session }).then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: e.toString() })),
    vigilGetSession: (identityId: string) =>
      invoke('vigil_get_session', { identityId }).catch(() => null),
    vigilClearSession: (identityId: string) =>
      invoke('vigil_clear_session', { identityId }).then(() => ({ success: true }))
        .catch((e: any) => ({ success: false, error: e.toString() })),
    fetchPriceHistory: (pair: string) =>
      invoke('fetch_price_history', { pair }).catch((e: any) => ({ success: false, error: e.toString() })),

    confirmShutdown: () => {},
  };
}

export function installTauriBridge() {
  if (isTauri) {
    (window as any).api = createTauriApi();
    console.log('[TauriBridge] Installed — all window.api calls routed to Tauri invoke()');

    // Debug: listen for ALL events to verify they arrive
    listen('sync-update', (e) => {
      console.log('[TauriBridge:DEBUG] sync-update RAW:', e.payload);
    });
    listen('balance-changed', (e) => {
      console.log('[TauriBridge:DEBUG] balance-changed RAW:', e.payload);
    });
    listen('core-log', (e) => {
      console.log('[TauriBridge:DEBUG] core-log RAW:', (e.payload as any)?.message?.substring(0, 50));
    });
  }
}
