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
  fetchPriceHistory: (pair: string) => ipcRenderer.invoke('fetch-price-history', pair),

  // Vigil strike-wallet persistence (encrypted blobs + session snapshots)
  vigilSaveStrikeKey: (identityId: string, blob: any) => ipcRenderer.invoke('vigil-save-strike-key', identityId, blob),
  vigilGetStrikeKey: (identityId: string) => ipcRenderer.invoke('vigil-get-strike-key', identityId),
  vigilDeleteStrikeKey: (identityId: string) => ipcRenderer.invoke('vigil-delete-strike-key', identityId),
  vigilArchiveStrikeKey: (identityId: string) => ipcRenderer.invoke('vigil-archive-strike-key', identityId),
  vigilSaveSession: (identityId: string, session: any) => ipcRenderer.invoke('vigil-save-session', identityId, session),
  vigilGetSession: (identityId: string) => ipcRenderer.invoke('vigil-get-session', identityId),
  vigilClearSession: (identityId: string) => ipcRenderer.invoke('vigil-clear-session', identityId),

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

if (process.contextIsolated) {
  try {
    contextBridge.exposeInMainWorld('api', api)
  } catch (error) {
    console.error(error)
  }
} else {
  // @ts-ignore (define in dts)
  window.api = api
}