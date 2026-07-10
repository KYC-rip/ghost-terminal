// Define standard types that match your main process models
export interface AppConfig {
  routingMode: 'tor' | 'clearnet' | 'custom';
  useSystemProxy: boolean;
  systemProxyAddress: string;
  network: 'mainnet' | 'stagenet' | 'testnet';
  customNodeAddress: string;
  show_scanlines?: boolean;
  auto_lock_minutes?: number;
  skin_background?: string;
  skin_opacity?: number;
  skin_style?: 'cover' | 'contain' | 'tile' | 'top-left';
  shortcuts?: {
    [action: string]: string;
  };
  hide_zero_balances?: boolean;
  include_prereleases?: boolean;
  agent_config?: {
    enabled: boolean;
    apiKey: string;
    dailyLimit: string;
    totalLimit: string;
    selectedWalletId: string;
    selectedAccountIndex: number;
    accumulatedDailySpend: string;
    lastResetTimestamp: number;
    port: number;
  };
}

export interface EngineStatus {
  status: 'DISCONNECTED' | 'CONNECTING' | 'ONLINE' | 'ERROR' | 'SYNCING';
  node: string;
  nodeLabel: string;
  useTor: boolean;
  error?: string;
  isStagenet: boolean;
  /** '' | 'STAGENET' | 'FCMP++ STRESSNET' — drives the header chip */
  networkLabel?: string;
}

export interface VaultIdentity {
  id: string;
  name: string;
  created: number;
}

export interface WalletActionResponse {
  success: boolean;
  seed?: string;
  address?: string;
  error?: string;
  isSoft?: boolean;
  snapshot?: {
    balance: number;
    height: number;
  };
}

export interface IApi {
  // --- Config & Settings ---
  getConfig: () => Promise<AppConfig>;
  saveConfigAndReload: (config: AppConfig) => Promise<{ success: boolean; error?: string }>;
  saveConfigOnly: (config: AppConfig) => Promise<{ success: boolean; error?: string }>;

  // --- Identity & Vault Management ---
  getIdentities: () => Promise<VaultIdentity[]>;
  saveIdentities: (identities: VaultIdentity[]) => Promise<boolean>;
  getActiveIdentity: () => Promise<string>;
  setActiveIdentity: (id: string) => Promise<boolean>;
  renameIdentity: (id: string, name: string) => Promise<boolean>;
  deleteIdentityFiles: (id: string) => Promise<{ success: boolean; error?: string }>;

  // --- Core Wallet Operations (Delegated to RPC) ---
  walletAction: (action: 'create' | 'open' | 'close' | 'hard-close' | 'label_account' | 'mnemonic', payload?: { name?: string; pwd?: string, seed?: string, height?: number, language?: string, account_index?: number, label?: string }) => Promise<WalletActionResponse>;

  // --- Engine Telemetry ---
  getUplinkStatus: () => Promise<EngineStatus>;
  retryEngine: () => Promise<void>;

  // --- Event Listeners (Main -> Renderer) ---
  onEngineStatus: (callback: (status: EngineStatus) => void) => () => void;
  onCoreLog: (callback: (log: { source: string; level: 'info' | 'error'; message: string }) => void) => () => void;
  onWalletEvent: (callback: (event: { type: 'SYNC_UPDATE' | 'BALANCE_CHANGED'; payload: any }) => void) => () => void;
  onVaultShutdown: (callback: () => void) => () => void;
  onDeepLink: (callback: (url: string) => void) => () => void;

  // --- Shutdown Acknowledgment ---
  confirmShutdown: () => void;

  // --- Proxy RPC ---
  proxyRequest: (payload: { method: string; params: any }) => Promise<{ success: boolean; result?: any; error?: string }>;

  // --- App Info & Updates ---
  getAppInfo: () => Promise<{ version: string; appDataPath: string; walletsPath: string; platform: NodeJS.Platform; isPackaged: boolean; capabilities?: { stressnet: boolean } }>;
  openPath: (targetPath: string) => Promise<{ success: boolean; error?: string }>;
  openExternal: (url: string) => Promise<{ success: boolean; error?: string }>;
  checkForUpdates: (include_prereleases: boolean) => Promise<{ success: boolean; hasUpdate?: boolean; latestVersion?: string; releaseUrl?: string; body?: string; publishedAt?: string; error?: string }>;
  selectBackgroundImage: () => Promise<{ success: boolean; data?: string; error?: string }>;
  saveGhostTrade: (txHash: string, tradeId: string) => Promise<{ success: boolean; error?: string }>;
  getGhostTrades: () => Promise<{ success: boolean; trades: any[]; error?: string }>;

  // XMR402 Payment Cache
  saveXmr402Payment: (nonce: string, txid: string, proof: string, amount: string, returnUrl?: string) => Promise<{ success: boolean; error?: string }>;
  getXmr402Payment: (nonce: string) => Promise<{ success: boolean; payment?: any; error?: string }>;
  getAllXmr402Payments: () => Promise<{ success: boolean; payments?: Record<string, any>; error?: string }>;

  updateAgentConfig: (config: any) => Promise<{ success: boolean; error?: string }>;
  onAgentActivity: (callback: (activity: any) => void) => () => void;
  onAgentPay402: (callback: (data: any) => void) => () => void;
  onXmr402Challenge: (callback: (url: string) => void) => () => void;
  authorizeXmr402: (id: string, password: string | null) => Promise<{ success: boolean; error?: string }>;
  clearCache: () => Promise<{ success: boolean; error?: string }>;
  sendXmr: (address: string, amountAtomic: string, accountIndex?: number) => Promise<{ success: boolean; txid?: string; error?: string }>;
  getTxProof: (txHash: string, address: string, message: string) => Promise<{ success: boolean; signature?: string; error?: string }>;
}

declare global {
  interface Window {
    api: IApi;
  }
}