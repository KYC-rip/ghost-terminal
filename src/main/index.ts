// src/main/index.ts
import { app, BrowserWindow, ipcMain, net, session } from 'electron';
import { join } from 'path';
import { optimizer, electronApp } from '@electron-toolkit/utils';
import { DaemonManager } from './DaemonManager';
import { NodeManager } from './NodeManager';
import { WalletManager } from './WalletManager';
import { SyncWatcher } from './SyncWatcher';
import { AppConfig } from './types';
import { registerIdentityHandlers } from './handlers/IdentityHandler';
import { getNetworkLabel, getWalletDirName, parseCapabilities } from './networkPaths';
import { AgentGateway } from './AgentGateway';

if (process.defaultApp) {
  if (process.argv.length >= 2) {
    app.setAsDefaultProtocolClient('monero', process.execPath, [join(__dirname, '..', '..')]);
    app.setAsDefaultProtocolClient('ripley', process.execPath, [join(__dirname, '..', '..')]);
    app.setAsDefaultProtocolClient('ghost', process.execPath, [join(__dirname, '..', '..')]);
    app.setAsDefaultProtocolClient('xmr402', process.execPath, [join(__dirname, '..', '..')]);
  }
} else {
  app.setAsDefaultProtocolClient('monero');
  app.setAsDefaultProtocolClient('ripley');
  app.setAsDefaultProtocolClient('ghost');
  app.setAsDefaultProtocolClient('xmr402');
}

// macOS specific: handle URL when app is already running or launched via URL
app.on('open-url', (event, url) => {
  event.preventDefault();
  handleDeepLink(url);
});

const Store = require('electron-store').default;
const store = new Store({
  clearInvalidConfig: true,
  defaults: {
    routingMode: 'clearnet',
    useSystemProxy: true,
    systemProxyAddress: '', // Only fallback for explicit manual UI overrides
    network: 'mainnet',
    customNodeAddress: '',
    show_scanlines: true,
    auto_lock_minutes: 10,
    shortcuts: {
      'LOCK': 'Mod+L',
      'SEND': 'Mod+S',
      'RECEIVE': 'Mod+R',
      'CHURN': 'Mod+Alt+C',
      'SPLIT': 'Mod+Alt+S',
      'SYNC': 'Mod+U',
      'SETTINGS': 'Mod+,',
      'TERMINAL': 'Mod+Shift+T'
    },
    hide_zero_balances: false,
    include_prereleases: false,
    agent_config: {
      enabled: false,
      apiKey: 'RG-' + Math.random().toString(36).substring(2, 15).toUpperCase(),
      dailyLimit: '0.1',
      totalLimit: '1.0',
      port: 38084,
      selectedWalletId: '',
      selectedAccountIndex: 0,
      accumulatedDailySpend: '0',
      lastResetTimestamp: Date.now()
    }
  } as AppConfig
});

let mainWindow: BrowserWindow;
let daemonEngine: DaemonManager;
let nodeManager: NodeManager;
let watcher: SyncWatcher;
let agentGateway: AgentGateway;

// 🔗 Deep Link Buffer (to catch links that arrive before window is ready)
let pendingDeepLink: string | null = null;

function handleDeepLink(url: string) {
  console.log(`[Main] Incoming Deep Link: ${url}`);
  
  if (url.startsWith('xmr402:')) {
    console.log(`[Main] 🛡️ XMR402 Challenge detected. Triggering Tactical Prompt...`);
    if (mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('xmr402-challenge', url);
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
      return;
    }
  }

  if (mainWindow && !mainWindow.isDestroyed()) {
    console.log(`[Main] Sending deep-link to renderer...`);
    mainWindow.webContents.send('deep-link', url);
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  } else {
    console.log(`[Main] Window not ready, buffering deep link.`);
    pendingDeepLink = url;
  }
}

// 🛡️ Single Instance Lock
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
} else {
  app.on('second-instance', (_event, commandLine) => {
    // Someone tried to run a second instance, we should focus our window.
    if (mainWindow) {
      if (mainWindow.isMinimized()) mainWindow.restore();
      mainWindow.focus();
    }
    // Protocol handler for Windows/Linux
    const url = commandLine.pop();
    if (url && (url.startsWith('monero:') || url.startsWith('ghost:') || url.startsWith('ripley:') || url.startsWith('xmr402:'))) {
      handleDeepLink(url);
    }
  });
}

// 🟢 Global State Tracker (For UI polling)
const isStagenet = store.get("network") === 'stagenet';
let currentEngineState = { status: 'DISCONNECTED', node: '', nodeLabel: '', useTor: false, error: '', isStagenet, networkLabel: getNetworkLabel(store.get("network") || 'mainnet') };

function readBinCapabilities() {
  try {
    const binDir = app.isPackaged
      ? join(process.resourcesPath, 'bin')
      : join(__dirname, '../../resources/bin');
    const raw = require('fs').readFileSync(join(binDir, 'capabilities.json'), 'utf8');
    return parseCapabilities(raw);
  } catch {
    // Missing or unreadable manifest fails safe: stressnet hidden
    return parseCapabilities(null);
  }
}
let isSafeToExit = false;

function emitAppLog(source: string, level: 'info' | 'error', message: string) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('core-log', { source, level, message });
  }
}

app.whenReady().then(async () => {
  const fs = require('fs');
  // 🛡️ Data Migration: Handle rename from ghost-terminal to ripley-terminal
  const oldPath = join(app.getPath('appData'), 'ghost-terminal');
  const newPath = app.getPath('userData');
  if (fs.existsSync(oldPath) && !fs.existsSync(newPath)) {
    console.log(`[Main] Migrating data from ${oldPath} to ${newPath}`);
    try {
      fs.renameSync(oldPath, newPath);
    } catch (e) {
      console.error('[Main] Migration failed:', e);
    }
  }

  const skinPath = join(app.getPath('userData'), 'skin_bg.b64');
  const currentB64 = store.get('skin_background');
  if (currentB64) {
    try {
      fs.writeFileSync(skinPath, currentB64, 'utf8');
      store.delete('skin_background');
      console.log('[Config] Migrated skin_background out of config.json');
    } catch (e) { }
  }

  electronApp.setAppUserModelId('rip.kyc.ripley');

  session.defaultSession.setCertificateVerifyProc((_, callback) => {
    callback(0); // 0 stands for net::OK, direct unconditional release
  });

  mainWindow = new BrowserWindow({
    width: 1200, height: 768,
    minWidth: 1200, minHeight: 768,
    backgroundColor: '#050505',
    titleBarStyle: 'hiddenInset',
    show: false, // Hide until ready
    webPreferences: {
      preload: join(__dirname, '../preload/index.js'),
      sandbox: false
    }
  });

  mainWindow.on('ready-to-show', () => {
    mainWindow.show();
    if (pendingDeepLink) {
      setTimeout(() => {
        handleDeepLink(pendingDeepLink!);
        pendingDeepLink = null;
      }, 1000);
    }
  });

  // Protocol handler for macOS is now registered at the top level

  // 🛡️ Production Hardening: Disable Reload Shortcuts
  mainWindow.webContents.on('before-input-event', (event, input) => {
    if (app.isPackaged) {
      if ((input.control || input.meta) && input.key.toLowerCase() === 'r') {
        event.preventDefault();
      }
      if (input.key === 'F5') {
        event.preventDefault();
      }
    }
  });

  app.on('browser-window-created', (_, window) => optimizer.watchWindowShortcuts(window));

  // 🛡️ Graceful Shutdown Interceptor (Merged from old code)
  mainWindow.on('close', async (e) => {
    if (isSafeToExit) return;

    e.preventDefault();
    console.log('[Main] Shutdown sequence initiated. Saving wallet state...');

    // Instantly hide window so the app "feels" closed to the user while background saving completes
    mainWindow.hide();

    // Broadcast to UI to show a "Saving & Closing..." spinner (if they somehow unhide it)
    mainWindow.webContents.send('vault-shutdown');

    try {
      if (watcher) watcher.stop();

      // Give the Wallet RPC a maximum of 8 seconds to save its block state.
      // If it hangs longer than that, kill the engine anyway, so the app actually exits.
      await Promise.race([
        WalletManager.closeWallet(),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Wallet save timeout')), 8000))
      ]);

      if (daemonEngine) daemonEngine.killAll();
    } catch (err) {
      console.error('[Main] Error during shutdown:', err);
    } finally {
      isSafeToExit = true;
      app.quit();
    }
  });

  daemonEngine = new DaemonManager();
  nodeManager = new NodeManager();
  watcher = new SyncWatcher(mainWindow, emitAppLog);

  daemonEngine.setLogListener(emitAppLog);


  // 🔌 Register the Identity/Vault Handlers
  registerIdentityHandlers(store);

  // Agents never touch stressnet test wallets — gateway stays down there.
  if (store.get('network') !== 'stressnet') {
    agentGateway = new AgentGateway(mainWindow, store);
  } else {
    console.log('[AgentGateway] Disabled on stressnet.');
  }
  if (store.get('agent_config.enabled')) {
    agentGateway.start();
  }
  // ---------------------------------------------------------
  // 🔌 IPC Channels
  // ---------------------------------------------------------
  ipcMain.handle('get-uplink-status', () => currentEngineState);
  ipcMain.handle('retry-engine', () => reloadEngine(true));

  ipcMain.handle('get-config', () => {
    const config = { ...store.store } as any;
    const fs = require('fs');
    const skinPath = join(app.getPath('userData'), 'skin_bg.b64');
    if (fs.existsSync(skinPath)) {
      try { config.skin_background = fs.readFileSync(skinPath, 'utf8'); } catch (e) { }
    }
    return config;
  });

  ipcMain.handle('save-config-and-reload', async (_, newConfig: AppConfig) => {
    const configToSave = { ...newConfig } as any;
    if ('skin_background' in configToSave) {
      const fs = require('fs');
      const skinPath = join(app.getPath('userData'), 'skin_bg.b64');
      if (configToSave.skin_background) {
        fs.writeFileSync(skinPath, configToSave.skin_background, 'utf8');
      } else if (fs.existsSync(skinPath)) {
        fs.unlinkSync(skinPath);
      }
      delete configToSave.skin_background;
    }
    store.set(configToSave);
    try {
      await reloadEngine();
      return { success: true };
    } catch (err: any) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle('save-config-only', (_, newConfig: AppConfig) => {
    const configToSave = { ...newConfig } as any;
    if ('skin_background' in configToSave) {
      const fs = require('fs');
      const skinPath = join(app.getPath('userData'), 'skin_bg.b64');
      if (configToSave.skin_background) {
        fs.writeFileSync(skinPath, configToSave.skin_background, 'utf8');
      } else if (fs.existsSync(skinPath)) {
        fs.unlinkSync(skinPath);
      }
      delete configToSave.skin_background;
    }
    store.set(configToSave);
    console.log('[Config] Logical settings updated (Scanlines/LockTime).');
    return { success: true };
  });

  ipcMain.handle('clear-cache', async () => {
    const fs = require('fs');
    const path = require('path');
    const userData = app.getPath('userData');

    try {
      // 1. Clear Nodes Cache
      const nodesPath = path.join(userData, 'latest_nodes.json');
      if (fs.existsSync(nodesPath)) fs.unlinkSync(nodesPath);

      // 2. Clear Tor Data
      const torDataPath = path.join(userData, 'tor_data');
      if (fs.existsSync(torDataPath)) {
        fs.rmSync(torDataPath, { recursive: true, force: true });
      }

      console.log('[Main] Tactical Cache Purge Complete.');
      return { success: true };
    } catch (e: any) {
      console.error('[Main] Cache purge failed:', e);
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('get-app-info', async () => {
    return {
      version: app.getVersion(),
      appDataPath: app.getPath('appData'),
      walletsPath: join(app.getPath('userData'), getWalletDirName(store.get('network') || 'mainnet')),
      platform: process.platform,
      isPackaged: app.isPackaged,
      capabilities: readBinCapabilities()
    };
  });

  ipcMain.handle('open-path', async (_, targetPath: string) => {
    // shell.openPath returns a string error message if it fails, or empty string if it succeeds
    const error = await require('electron').shell.openPath(targetPath);
    return { success: !error, error };
  });

  ipcMain.handle('open-external', async (_, url: string, options?: { width?: number; height?: number }) => {
    try {
      if (options?.width && options?.height) {
        const { BrowserWindow } = require('electron');
        const win = new BrowserWindow({
          width: options.width,
          height: options.height,
          autoHideMenuBar: true,
          backgroundColor: '#050505',
          webPreferences: {
            nodeIntegration: false,
            contextIsolation: true
          }
        });
        win.loadURL(url);
        return { success: true };
      }
      await require('electron').shell.openExternal(url);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('save-ghost-trade', async (_, txHash: string, tradeId: string) => {
    try {
      const trades = store.get('ghost_trades', {}) as Record<string, { tradeId: string, timestamp: number }>;

      // Cleanup old trades (> 7 days)
      const now = Date.now();
      const expiry = 7 * 24 * 60 * 60 * 1000;
      const cleanTrades = Object.fromEntries(
        Object.entries(trades).filter(([_, data]) => now - data.timestamp < expiry)
      );

      cleanTrades[txHash] = { tradeId, timestamp: now };
      store.set('ghost_trades', cleanTrades);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('get-ghost-trades', async () => {
    try {
      const trades = store.get('ghost_trades', {}) as Record<string, { tradeId: string, timestamp: number }>;
      const now = Date.now();
      const expiry = 7 * 24 * 60 * 60 * 1000;

      // Filter expired ones on read just in case
      const activeTrades = Object.fromEntries(
        Object.entries(trades).filter(([_, data]) => now - data.timestamp < expiry)
      );

      return { success: true, trades: activeTrades };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('save-xmr402-payment', async (_, nonce: string, txid: string, proof: string, amount: string, returnUrl?: string) => {
    try {
      const extStore = new Store(); // Use a fresh instance to ensure safe write
      const payments = extStore.get('xmr402_payments', {}) as Record<string, any>;
      // We key by txid so the ledger can easily look it up later, but we also embed the nonce.
      payments[txid] = {
        nonce,
        amount,
        proof,
        returnUrl,
        timestamp: Date.now()
      };
      extStore.set('xmr402_payments', payments);
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('get-xmr402-payment', async (_, nonce: string) => {
    try {
      const extStore = new Store();
      const payments = extStore.get('xmr402_payments', {}) as Record<string, any>;
      // Find the payment object that has this nonce
      const payment = Object.values(payments).find(p => p.nonce === nonce);
      // We'll return the txid as well, so find the key
      const txid = Object.keys(payments).find(key => payments[key].nonce === nonce);

      if (payment && txid) {
        return { success: true, payment: { txid, ...payment } };
      }
      return { success: false, error: 'Payment not found' };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('get-all-xmr402-payments', async () => {
    try {
      const extStore = new Store();
      const payments = extStore.get('xmr402_payments', {}) as Record<string, any>;
      return { success: true, payments };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('update-agent-config', async (_, newAgentConfig: any) => {
    try {
      store.set('agent_config', newAgentConfig);
      if (newAgentConfig.enabled) {
        agentGateway.start();
      } else {
        agentGateway.stop();
      }
      return { success: true };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('send-xmr', async (_, address: string, amountAtomic: string, accountIndex: number = 0) => {
    try {
      const txHash = await WalletManager.transfer(address, amountAtomic, accountIndex);
      return { success: true, txid: txHash };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('get-tx-proof', async (_, txHash: string, address: string, message: string) => {
    try {
      const signature = await WalletManager.getTxProof(txHash, address, message);
      return { success: true, signature };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('authorize-xmr402', async (_, { id, password }) => {
    AgentGateway.resolveAuth(id, password);
    return { success: true };
  });

  ipcMain.handle('select-background-image', async () => {
    const { dialog } = require('electron');
    const fs = require('fs');

    const result = await dialog.showOpenDialog(mainWindow, {
      title: 'Select Background Skin',
      filters: [{ name: 'Images', extensions: ['jpg', 'png', 'gif', 'webp', 'jpeg'] }],
      properties: ['openFile']
    });

    if (result.canceled || result.filePaths.length === 0) {
      return { success: false, error: 'Cancelled' };
    }

    const filePath = result.filePaths[0];
    try {
      const stats = fs.statSync(filePath);
      if (stats.size > 5 * 1024 * 1024) {
        return { success: false, error: 'Image exceeds 5MB size limit.' };
      }
      const fileData = fs.readFileSync(filePath);
      const ext = filePath.split('.').pop()?.toLowerCase();
      const mimeType = ext === 'jpg' ? 'jpeg' : ext;
      const base64Str = `data:image/${mimeType};base64,` + fileData.toString('base64');
      return { success: true, data: base64Str };
    } catch (e: any) {
      return { success: false, error: e.message };
    }
  });

  ipcMain.handle('check-for-updates', async (_, include_prereleases: boolean) => {
    try {
      const config = { ...store.store } as AppConfig;
      config.include_prereleases = !!include_prereleases;
      store.set(config);

      let release: any;
      if (include_prereleases) {
        const response = await net.fetch('https://api.github.com/repos/KYC-rip/ripley-terminal/releases');
        if (response.status === 404) return { success: true, hasUpdate: false, latestVersion: '---', error: 'No releases found' };
        if (!response.ok) throw new Error(`GitHub API error: ${response.status}`);
        const releases = await response.json() as any[];
        release = releases[0];
      } else {
        const response = await net.fetch('https://api.github.com/repos/KYC-rip/ripley-terminal/releases/latest');
        if (response.status === 404) return { success: true, hasUpdate: false, latestVersion: '---', error: 'No releases found' };
        if (!response.ok) throw new Error(`GitHub API error: ${response.status}`);
        release = await response.json() as any;
      }

      if (!release) return { success: true, hasUpdate: false, latestVersion: '---', error: 'No releases found' };

      const latestVersion = release.tag_name.replace(/^v/, '');
      const currentVersion = app.getVersion();

      // Proper semver-aware comparison
      const isNewer = (latest: string, current: string): boolean => {
        const lp = latest.split('.').map((v) => parseInt(v, 10) || 0);
        const cp = current.split('.').map((v) => parseInt(v, 10) || 0);
        for (let i = 0; i < Math.max(lp.length, cp.length); i++) {
          if ((lp[i] || 0) > (cp[i] || 0)) return true;
          if ((lp[i] || 0) < (cp[i] || 0)) return false;
        }
        return false;
      };

      const hasUpdate = isNewer(latestVersion, currentVersion);

      return {
        success: true,
        hasUpdate,
        latestVersion,
        releaseUrl: release.html_url,
        body: release.body,
        publishedAt: release.published_at
      };
    } catch (error: any) {
      console.error('Update check failed:', error);
      return { success: false, error: error.message };
    }
  });

  ipcMain.handle('proxy-request', async (_, payload: { method: string; params: any }) => {
    try {
      const isDaemonMethod = ['get_fee_estimate', 'get_info', 'get_last_block_header'].includes(payload.method);
      let targetUrl = 'http://127.0.0.1:18082/json_rpc';

      if (isDaemonMethod && NodeManager.activeNodeStr) {
        const address = NodeManager.activeNodeStr;
        const protocol = address.includes('://') ? '' : 'http://';
        targetUrl = `${protocol}${address}/json_rpc`;
      }

      const response = await net.fetch(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: '0',
          method: payload.method,
          params: payload.params
        })
      });

      const data = await response.json();

      if (data.error) {
        return { success: false, error: data.error.message };
      }

      return { success: true, result: data.result };
    } catch (error: any) {
      return { success: false, error: error.message };
    }
  });

  let currentOpenWallet: { id: string, pwd: string } | null = null;

  ipcMain.handle('wallet-action', async (_, action: string, payload: any) => {
    try {
      if ((action === 'create' || action === 'open') && !payload?.name) {
        throw new Error("Missing wallet filename");
      }

      switch (action) {
        case 'create':
          if (payload.seed) {
            await WalletManager.restoreWallet(
              payload.name,
              payload.pwd,
              payload.seed,
              payload.height || 0,
              payload.language || 'English'
            );
            currentOpenWallet = { id: payload.name, pwd: payload.pwd };
            watcher.start();
            return { success: true };
          } else {
            await WalletManager.createWallet(payload.name, payload.pwd);
            const seed = await WalletManager.getMnemonic();
            currentOpenWallet = { id: payload.name, pwd: payload.pwd };
            watcher.start();
            return { success: true, seed, address: '' };
          }
        case 'open':
          // 🛡️ SOFT UNLOCK: If wallet is already open and password matches, just return success
          if (currentOpenWallet && currentOpenWallet.id === payload.name) {
            if (currentOpenWallet.pwd === payload.pwd) {
              console.log(`[Main] Soft unlock triggered for: ${payload.name}`);
              return { success: true, isSoft: true, snapshot: watcher.getSnapshot() };
            } else {
              throw new Error("Invalid password for active session.");
            }
          }

          await WalletManager.openWallet(payload.name, payload.pwd);
          currentOpenWallet = { id: payload.name, pwd: payload.pwd };
          watcher.start();
          return { success: true };

        case 'close':
          // 🛡️ SOFT LOCK: We stop pushing events but keep the RPC alive for background sync
          console.log(`[Main] Soft lock engaged for: ${currentOpenWallet?.id}`);
          // Note: We DON'T call watcher.stop() anymore to allow continuous scan
          return { success: true };

        case 'hard-close':
        // Genuine termination (e.g. for identity switch or purge)
          watcher.stop();
          await WalletManager.closeWallet();
          currentOpenWallet = null;
          return { success: true };

        case 'mnemonic':
          const seed = await WalletManager.getMnemonic();
          return { success: true, seed };
        default:
          return { success: false, error: 'Unknown action' };
      }
    } catch (error: any) {
      console.error('[Main] Wallet action error:', error);
      return { success: false, error: error.message };
    }
  });

  if (app.isPackaged) {
    mainWindow.loadFile(join(__dirname, '../renderer/index.html'));
  } else {
    mainWindow.loadURL(process.env['ELECTRON_RENDERER_URL'] || 'http://localhost:5173');
  }


  // 🚀 Start the engine
  reloadEngine();
});

async function applyGlobalNetworkRouting(config: AppConfig, torSocksPort: number) {
  const useTor = config.routingMode === 'tor' ||
    (!!config.customNodeAddress && config.customNodeAddress.includes('.onion'));

  if (useTor) {
    const activeProxyUrl = `socks5://127.0.0.1:${torSocksPort}`;
    await session.defaultSession.setProxy({ proxyRules: activeProxyUrl, proxyBypassRules: '127.0.0.1, localhost' });
    console.log(`[Network] 🛡️ Traffic sealed. Route: ${activeProxyUrl}`);
  } else if (config.useSystemProxy) {
    // macOS bypasses custom ports (18089/18081) in 'system' mode natively. We must explicitly extract the proxy URL 
    // from a standard port and then forcefully apply it globally via proxyRules.
    await session.defaultSession.setProxy({ mode: 'system' });
    const resolvedProxy = await session.defaultSession.resolveProxy("https://check.torproject.org");

    if (resolvedProxy && resolvedProxy !== 'DIRECT') {
      const match = resolvedProxy.match(/(PROXY|SOCKS5|SOCKS|HTTP|HTTPS) ([\w.:]+)/i);
      if (match) {
        const type = match[1].toUpperCase();
        const hostInfo = match[2];
        let forceUrl = '';
        if (type.startsWith('SOCKS5')) forceUrl = `socks5://${hostInfo}`;
        else if (type.startsWith('SOCKS')) forceUrl = `socks://${hostInfo}`;
        else forceUrl = `http://${hostInfo}`; // Fallback to HTTP CONNECT

        await session.defaultSession.setProxy({ proxyRules: forceUrl, proxyBypassRules: '127.0.0.1, localhost' });
        console.log(`[Network] 📡 OS Proxy extracted & forced universally: ${forceUrl}`);
        return;
      }
    }
    // If no proxy found or DIRECT, fall back to direct
    await session.defaultSession.setProxy({ mode: 'direct' });
    console.log(`[Network] 📡 OS Proxy resolved to DIRECT (Clearnet)`);
  } else if (config.systemProxyAddress) {
    const activeProxyUrl = config.systemProxyAddress.includes('://')
      ? config.systemProxyAddress
      : `socks5://${config.systemProxyAddress}`;
    await session.defaultSession.setProxy({ proxyRules: activeProxyUrl, proxyBypassRules: '127.0.0.1, localhost' });
    console.log(`[Network] 🛡️ Traffic sealed. Route: ${activeProxyUrl}`);
  } else {
    await session.defaultSession.setProxy({ mode: 'direct' });
    console.log(`[Network] ⚠️ Traffic on Clearnet (Direct)`);
  }
}

let lastPhysicalConfig = {
  routingMode: '',
  network: '',
  customNodeAddress: ''
};
async function reloadEngine(forceRestart = false) {
  const config = store.store;

  // 🔍 1. Check if physical parameters have changed
  const physicalChanged =
    config.routingMode !== lastPhysicalConfig.routingMode ||
    config.network !== lastPhysicalConfig.network ||
    config.customNodeAddress !== lastPhysicalConfig.customNodeAddress;

  // 🛡️ If status is ONLINE, physical parameters haven't changed, and it's not a forced restart, skip reload.
  if (currentEngineState.status === 'ONLINE' && !physicalChanged && !forceRestart) {
    console.log('[Engine] Configuration updated, but physical uplink remains unchanged. Skipping reload.');
    return;
  }

  // 🚀 Only physical changes reach this point
  console.log('[Engine] Physical reconfiguration triggered...');

  currentEngineState.status = 'CONNECTING';
  mainWindow?.webContents.send('engine-status', currentEngineState);

  watcher.stop();
  daemonEngine.killAll();

  try {
    const useTor = config.routingMode === 'tor' ||
      (!!config.customNodeAddress && config.customNodeAddress.includes('.onion'));

    if (useTor) {
      let torFrontProxy: string | undefined = undefined;

      if (config.useSystemProxy) {
        // Temporarily put Chromium in system mode to resolve OS level proxies
        await session.defaultSession.setProxy({ mode: 'system' });
        const resolvedProxy = await session.defaultSession.resolveProxy("https://check.torproject.org");
        if (resolvedProxy && resolvedProxy !== 'DIRECT') {
          const match = resolvedProxy.match(/(PROXY|SOCKS5|SOCKS|HTTP|HTTPS) ([\w.:]+)/i);
          if (match) {
            torFrontProxy = match[1].toUpperCase().startsWith('SOCKS')
              ? `socks5://${match[2]}`
              : `http://${match[2]}`;
          }
        }
      } else if (config.systemProxyAddress) {
        torFrontProxy = config.systemProxyAddress.includes('://')
          ? config.systemProxyAddress
          : `socks5://${config.systemProxyAddress}`;
      }

      await daemonEngine.startTor(torFrontProxy);
    }

    await applyGlobalNetworkRouting(config, daemonEngine.torSocksPort);

    await nodeManager.fetchRemoteNodes();

    let targetNode = '';
    if (config.customNodeAddress) {
      targetNode = config.customNodeAddress;
      NodeManager.activeNodeStr = targetNode;
      // We must manually ping the custom node to fetch daemonHeight for UI progress syncing
      try {
        await nodeManager.pingNode(targetNode);
      } catch (e) {
        console.warn('[Engine] Custom node ping failed, sync progress percentages may be unavailable.');
      }
    } else {
      const winner = await nodeManager.findFastestNode(config.network, useTor ? 'tor' : 'clearnet');
      targetNode = winner.address;
      NodeManager.activeNodeStr = targetNode;
      NodeManager.activeNodeLabel = winner.label;
    }

    await daemonEngine.startMoneroRpc(targetNode, useTor, config.useSystemProxy, config.systemProxyAddress, config.network);

    // ✅ Update successful, syncing snapshot
    lastPhysicalConfig = {
      routingMode: config.routingMode,
      network: config.network,
      customNodeAddress: config.customNodeAddress
    };

    currentEngineState = { status: 'ONLINE', node: targetNode, nodeLabel: NodeManager.activeNodeLabel, useTor, error: '', isStagenet: config.network === 'stagenet', networkLabel: getNetworkLabel(config.network) };
    mainWindow?.webContents.send('engine-status', currentEngineState);

  } catch (error: any) {
    console.error('[Engine] Start failed:', error);
    currentEngineState = { status: 'ERROR', node: '', nodeLabel: '', useTor: false, error: error.message, isStagenet: config.network === 'stagenet', networkLabel: getNetworkLabel(config.network) };
    mainWindow?.webContents.send('engine-status', currentEngineState);
  }
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});