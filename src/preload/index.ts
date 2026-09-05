import { contextBridge, ipcRenderer } from 'electron'

const api = {
  getConfig: () => ipcRenderer.invoke('get-config'),
  saveConfigAndReload: (config: any) => ipcRenderer.invoke('save-config-and-reload', config),
  saveConfigOnly: (config: any) => ipcRenderer.invoke('save-config-only', config),

  getIdentities: () => ipcRenderer.invoke('get-identities'),
  saveIdentities: (ids: any) => ipcRenderer.invoke('save-identities', ids),
  getActiveIdentity: () => ipcRenderer.invoke('get-active-identity'),
  setActiveIdentity: (id: string) => ipcRenderer.invoke('set-active-identity', id),
  renameIdentity: (id: string, name: string) => ipcRenderer.invoke('rename-identity', { id, name }),
  deleteIdentityFiles: (id: string) => ipcRenderer.invoke('delete-identity-files', id),

  walletAction: (action: string, payload?: any) => ipcRenderer.invoke('wallet-action', action, payload),
  getUplinkStatus: () => ipcRenderer.invoke('get-uplink-status'),
  retryEngine: () => ipcRenderer.invoke('retry-engine'),

  // Event Listeners (returning a cleanup function to remove the listener)
  onEngineStatus: (callback: any) => {
    const handler = (_: any, data: any) => callback(data);
    ipcRenderer.on('engine-status', handler);
    return () => ipcRenderer.removeListener('engine-status', handler);
  },
  onCoreLog: (callback: any) => {
    const handler = (_: any, data: any) => callback(data);
    ipcRenderer.on('core-log', handler);
    return () => ipcRenderer.removeListener('core-log', handler);
  },
  onWalletEvent: (callback: any) => {
    const handler = (_: any, data: any) => callback(data);
    ipcRenderer.on('wallet-event', handler);
    return () => ipcRenderer.removeListener('wallet-event', handler);
  },
  onVaultShutdown: (callback: any) => {
    ipcRenderer.once('vault-shutdown', callback); // Notice 'once' instead of 'on'
    return () => { };
  },
  onDeepLink: (callback: (url: string) => void) => {
    const handler = (_: any, url: string) => callback(url);
    ipcRenderer.on('deep-link', handler);
    return () => ipcRenderer.removeListener('deep-link', handler);
  },
  proxyRequest: (payload: any) => ipcRenderer.invoke('proxy-request', payload),

  getAppInfo: () => ipcRenderer.invoke('get-app-info'),
  openPath: (targetPath: string) => ipcRenderer.invoke('open-path', targetPath),
  openExternal: (url: string, options?: { width?: number; height?: number }) => ipcRenderer.invoke('open-external', url, options),
  checkForUpdates: (include_prereleases: boolean) => ipcRenderer.invoke('check-for-updates', include_prereleases),
  selectBackgroundImage: () => ipcRenderer.invoke('select-background-image'),
  saveGhostTrade: (txHash: string, tradeId: string) => ipcRenderer.invoke('save-ghost-trade', txHash, tradeId),
  getGhostTrades: () => ipcRenderer.invoke('get-ghost-trades'),

  // XMR402 Payment Cache
  saveXmr402Payment: (nonce: string, txid: string, proof: string, amount: string, returnUrl?: string) =>
    ipcRenderer.invoke('save-xmr402-payment', nonce, txid, proof, amount, returnUrl),
  getXmr402Payment: (nonce: string) => ipcRenderer.invoke('get-xmr402-payment', nonce),
  getAllXmr402Payments: () => ipcRenderer.invoke('get-all-xmr402-payments'),

  updateAgentConfig: (config: any) => ipcRenderer.invoke('update-agent-config', config),

  onAgentActivity: (callback: (activity: any) => void) => {
    const handler = (_: any, data: any) => callback(data);
    ipcRenderer.on('agent-activity', handler);
    return () => ipcRenderer.removeListener('agent-activity', handler);
  },

  onAgentPay402: (callback: (data: any) => void) => {
    const handler = (_: any, data: any) => callback(data);
    ipcRenderer.on('agent-pay-402', handler);
    return () => ipcRenderer.removeListener('agent-pay-402', handler);
  },

  onXmr402Challenge: (callback: (url: string) => void) => {
    const handler = (_: any, url: string) => callback(url);
    ipcRenderer.on('xmr402-challenge', handler);
    return () => ipcRenderer.removeListener('xmr402-challenge', handler);
  },

  authorizeXmr402: (id: string, password: string | null) => ipcRenderer.invoke('authorize-xmr402', { id, password }),
  clearCache: () => ipcRenderer.invoke('clear-cache'),

  sendXmr: (address: string, amountAtomic: string, accountIndex?: number) => ipcRenderer.invoke('send-xmr', address, amountAtomic, accountIndex),
  getTxProof: (txHash: string, address: string, message: string) => ipcRenderer.invoke('get-tx-proof', txHash, address, message),

  confirmShutdown: () => ipcRenderer.send('confirm-shutdown')
}

// RipleyOS platform bridge — the small, STABLE contract ROS's platform/native.ts
// consumes (window.__rosNative). Kept separate from `api` so ROS stays decoupled
// from the wallet's internal IPC surface. Only `fetch` is wired in Phase 3a;
// native KV, monero RPC and browser webviews follow.
const rosNative = {
  runtime: 'electron' as const,
  fetch: (req: { url: string; method?: string; headers?: Record<string, string>; body?: string }) =>
    ipcRenderer.invoke('ros:native-fetch', req),
  caps: { tor: true, monero: true, browser: true },
  // Network control surface — ROS's Privacy + Settings read/set routing + Tor status.
  getConfig: async () => {
    const c: any = await ipcRenderer.invoke('get-config')
    return { routingMode: c?.routingMode, proxyAddress: c?.systemProxyAddress, network: c?.network }
  },
  setConfig: async (patch: { routingMode?: string; proxyAddress?: string; network?: string }) => {
    const c: any = (await ipcRenderer.invoke('get-config')) || {}
    if (patch.routingMode !== undefined) c.routingMode = patch.routingMode
    if (patch.proxyAddress !== undefined) c.systemProxyAddress = patch.proxyAddress
    if (patch.network !== undefined) c.network = patch.network
    // reload the uplink so the routing change (Tor/clearnet) takes effect now.
    await ipcRenderer.invoke('save-config-and-reload', c)
  },
  torStatus: async () => {
    const s: any = await ipcRenderer.invoke('get-uplink-status')
    return { status: String(s?.status || 'unknown').toLowerCase() }
  },
  // Stream the shell's core-log (Tor bootstrap, engine, daemon RPC) into ROS's console.
  onLog: (cb: (e: { source?: string; level?: string; message?: string }) => void) => {
    const h = (_: any, data: any) => cb(data)
    ipcRenderer.on('core-log', h)
    return () => ipcRenderer.removeListener('core-log', h)
  },
  // OS default browser (Telegram t.me, etc.) — not the in-app ROS browser.
  openExternal: (url: string) =>
    ipcRenderer.invoke('open-external', url).then(() => undefined),
}

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('api', api)
    contextBridge.exposeInMainWorld('__rosNative', rosNative)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.api = api
  // @ts-ignore (define in dts)
  window.__rosNative = rosNative
}