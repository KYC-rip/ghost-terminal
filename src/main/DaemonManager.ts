// src/main/DaemonManager.ts
import { spawn, ChildProcess } from 'child_process';
import fs from 'fs';
import path from 'path';
import { app } from 'electron';
import { getWalletDirName, getRpcFolderName, getNetworkFlag } from './networkPaths';

export class DaemonManager {
  private binPath: string;
  private torPath: string;
  private rpcPath: string;
  private walletDir: string;

  private torProcess: ChildProcess | null = null;
  private rpcProcess: ChildProcess | null = null;

  public readonly torSocksPort = 9052;
  public readonly rpcPort = 18082;

  private onLog?: (source: string, level: 'info' | 'error', message: string) => void;

  public setLogListener(listener: (source: string, level: 'info' | 'error', message: string) => void) {
    this.onLog = listener;
  }

  private emitLog(source: string, level: 'info' | 'error', message: string) {
    if (this.onLog) this.onLog(source, level, message);
  }

  constructor() {
    this.binPath = app.isPackaged
      ? path.join(process.resourcesPath, 'bin')
      : path.join(__dirname, '../../resources/bin');

    const ext = process.platform === 'win32' ? '.exe' : '';
    this.torPath = path.join(this.binPath, `tor-bundle/tor/tor${ext}`);
    this.rpcPath = path.join(this.binPath, `rpc-core/monero-wallet-rpc${ext}`);

    this.walletDir = path.join(app.getPath('userData'), 'wallets');
    if (!fs.existsSync(this.walletDir)) fs.mkdirSync(this.walletDir, { recursive: true });
  }

  /**
   * Resolve the wallet dir and rpc binary for the requested network.
   * Called at startMoneroRpc time (engine reloads fully on network change),
   * so there are no stale references. Throws when the stressnet binary is
   * not bundled for this platform (capability manifest also hides the
   * option in the UI; this is the backstop).
   */
  private applyNetworkPaths(network: string) {
    const ext = process.platform === 'win32' ? '.exe' : '';
    this.rpcPath = path.join(this.binPath, `${getRpcFolderName(network)}/monero-wallet-rpc${ext}`);
    this.walletDir = path.join(app.getPath('userData'), getWalletDirName(network));

    if (!fs.existsSync(this.rpcPath)) {
      if (network === 'stressnet') {
        throw new Error('Stressnet build unavailable on this platform (missing rpc-stressnet binary)');
      }
      throw new Error(`monero-wallet-rpc binary missing at ${this.rpcPath}`);
    }
    if (!fs.existsSync(this.walletDir)) fs.mkdirSync(this.walletDir, { recursive: true });
  }

  public async startTor(systemProxy?: string): Promise<void> {
    if (process.platform !== 'win32') {
      const { execSync } = require('child_process');
      try {
        execSync("lsof -ti:9053 | xargs kill -9 > /dev/null 2>&1");
        console.log('[TOR] Cleaned up zombie processes from previous sessions.');
      } catch (e) {
      }

      try {
        fs.chmodSync(this.torPath, 0o755);
        const lyrebirdPath = path.join(this.binPath, 'tor-bundle', 'pluggable_transports', 'lyrebird');
        if (fs.existsSync(lyrebirdPath)) fs.chmodSync(lyrebirdPath, 0o755);
      } catch (chmodErr) {
        console.warn('[TOR] Warning: Failed to grant execution permissions. EACCES might occur:', chmodErr);
      }
    }

    return new Promise((resolve, reject) => {
      if (this.torProcess) return resolve();

      console.log('[TOR] Igniting darknet engine...');
      const torArgs = [
        '--SocksPort', `${this.torSocksPort}`,
        '--ControlPort', '9053',
        '--CookieAuthentication', '1',
        '--DataDirectory', path.join(app.getPath('userData'), 'tor_data'),
        '--Log', 'notice stdout' // 📢 FORCE Tor to stream its inner thoughts to standard output
      ];

      if (systemProxy) {
        let proxyType = '--Socks5Proxy';
        let cleanProxy = systemProxy;

        if (systemProxy.startsWith('socks5://')) {
          cleanProxy = systemProxy.replace('socks5://', '');
        } else if (systemProxy.startsWith('http://')) {
          proxyType = '--HTTPSProxy';
          cleanProxy = systemProxy.replace('http://', '');
        } else if (systemProxy.startsWith('https://')) {
          proxyType = '--HTTPSProxy';
          cleanProxy = systemProxy.replace('https://', '');
        }

        console.log(`[TOR] Mounting system proxy: ${proxyType} ${cleanProxy}`);
        torArgs.push(proxyType, cleanProxy);
      }

      const env = Object.assign({}, process.env);
      if (process.platform === 'darwin') {
        env.DYLD_LIBRARY_PATH = path.dirname(this.torPath);
        env.DYLD_FALLBACK_LIBRARY_PATH = path.dirname(this.torPath);
      }

      this.torProcess = spawn(this.torPath, torArgs, {
        env,
        stdio: 'pipe'
      });

      this.torProcess.stdout?.on('data', (data: Buffer) => {
        const rawLogs = data.toString().split('\n'); // 🛡️ Split into single lines
        rawLogs.forEach(line => {
          const log = line.trim();
          if (!log) return;
          this.emitLog('TOR', 'info', log);
        });
        console.log(`[TOR-CORE] ${rawLogs.join('\n')}`);

        if (rawLogs.some(line => line.includes('Bootstrapped 100%'))) {
          console.log('[TOR] Tunnel established successfully. (100%)');
          resolve();
        }
      });

      this.torProcess.stderr?.on('data', (data: Buffer) => {
        const errLog = data.toString().trim();
        if (errLog) {
          console.error(`[TOR-ERR] ${errLog}`);
          this.emitLog('TOR', 'error', errLog);
        }
      });

      // 🛑 FIXED: Now catches Signal terminations (code === null)
      this.torProcess.on('close', (code, signal) => {
        if (code !== 0) {
          const exitReason = code !== null ? `Code: ${code}` : `Signal: ${signal}`;
          const msg = `Process exited unexpectedly (${exitReason}).`;
          console.error(`[TOR-FATAL] ${msg}`);
          this.emitLog('TOR', 'error', msg);
          this.torProcess = null;
          reject(new Error(msg));
        }
      });

      this.torProcess.on('error', (err) => {
        console.error(`[TOR-ERROR] ${err.message}`);
        this.emitLog('TOR', 'error', err.message);
        reject(err);
      });
    });
  }

  public async startMoneroRpc(
    targetNode: string,
    useTor: boolean,
    useSystemProxy: boolean,
    systemProxyAddress: string,
    network: string
  ): Promise<void> {
    this.applyNetworkPaths(network);

    if (process.platform !== 'win32') {
      try {
        fs.chmodSync(this.rpcPath, 0o755);
      } catch (chmodErr) {
        console.warn('[RPC] Warning: Failed to grant execution permissions:', chmodErr);
      }
    }

    return new Promise((resolve, reject) => {
      if (this.rpcProcess) return resolve();

      console.log(`[RPC] Mounting stealth core. Target: ${targetNode} | Tor: ${useTor}`);
      const rpcArgs = [
        '--wallet-dir', this.walletDir,
        '--rpc-bind-port', `${this.rpcPort}`,
        '--disable-rpc-login',
        '--daemon-address', targetNode,
        '--max-concurrency', '4',
        '--no-initial-sync'
      ];

      const networkFlag = getNetworkFlag(network);
      if (networkFlag) rpcArgs.push(networkFlag);

      const env = Object.assign({}, process.env);
      if (useTor) {
        const proxyAddr = `127.0.0.1:${this.torSocksPort}`;
        rpcArgs.push('--proxy', proxyAddr);
        rpcArgs.push('--daemon-ssl-allow-any-cert');
        console.log(`[RPC] Applying Tor Proxy for Remote Node: ${proxyAddr} -> ${targetNode}`);
      } else if (useSystemProxy) {
        // Because dual-protocol proxies (e.g. Clash Mix port 1082) fail with monero's native SOCKS4a --proxy argument,
        // we inject standard proxy environment variables instead so curl/epee can route via HTTP Connect.
        env.HTTP_PROXY = systemProxyAddress;
        env.HTTPS_PROXY = systemProxyAddress;
        env.ALL_PROXY = systemProxyAddress;
        rpcArgs.push('--daemon-ssl-allow-any-cert');
        console.log(`[RPC] Applying Custom HTTP/SOCKS Proxy (EnvVar): ${systemProxyAddress} -> ${targetNode}`);
      } else {
        console.log(`[RPC] Direct Clearnet Connection -> ${targetNode}`);
      }

      this.rpcProcess = spawn(this.rpcPath, rpcArgs, {
        env,
        stdio: 'pipe'
      });

      this.rpcProcess.stdout?.on('data', (data: Buffer) => {
        const log = data.toString().trim();
        if (!log) return;

        console.log(`[RPC-CORE] ${log}`);
        this.emitLog('RPC', 'info', log);

        if (/Starting wallet RPC server/i.test(log) || /Binding on 127.0.0.1/i.test(log)) {
          console.log('[RPC] Daemon confirmed ready.');
          resolve();
        }
      });

      this.rpcProcess.stderr?.on('data', (data: Buffer) => {
        const errLog = data.toString().trim();
        if (errLog) {
          console.error(`[RPC-ERR] ${errLog}`);
          this.emitLog('RPC', 'error', errLog);
        }
      });

      this.rpcProcess.on('close', (code) => {
        if (code !== 0 && code !== null) {
          const msg = `RPC Process exited unexpectedly (Code: ${code}).`;
          console.error(`[RPC-FATAL] ${msg}`);
          this.emitLog('RPC', 'error', msg);
          this.rpcProcess = null;
          reject(new Error(msg));
        }
      });

      this.rpcProcess.on('error', (err) => {
        console.error(`[RPC-ERROR] ${err.message}`);
        this.emitLog('RPC', 'error', err.message);
        reject(err);
      });
    });
  }

  public killAll(): void {
    console.log('[DaemonManager] Executing physical disconnect and memory wipe...');
    if (this.rpcProcess) {
      this.rpcProcess.kill();
      this.rpcProcess = null;
    }
    if (this.torProcess) {
      this.torProcess.kill();
      this.torProcess = null;
    }
  }
}