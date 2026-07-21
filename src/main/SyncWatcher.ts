import { BrowserWindow } from 'electron';
import { WalletManager } from './WalletManager';
import { NodeManager } from './NodeManager';
import { WalletEventPayload } from './types';

export class SyncWatcher {
  private mainWindow: BrowserWindow;
  private intervalId: NodeJS.Timeout | null = null;
  private lastKnownBalance: number = -1;
  private lastKnownHeight: number = -1;
  private lastStoreTime: number = 0;
  private onLog?: (source: string, level: 'info' | 'error', message: string) => void;
  private loopCounter: number = 0;

  // Daemon height cache — no need to hit the remote node every 2s
  private cachedDaemonHeight: number = 0;
  private lastDaemonHeightFetch: number = 0;
  private static readonly DAEMON_HEIGHT_TTL = 60_000; // 60 seconds

  // Padded sync state
  private isSyncing: boolean = false;
  private syncAborted: boolean = false;

  // Throttle SYNC_UPDATE events to avoid IPC flood
  private lastSyncEventTime: number = 0;
  private static readonly SYNC_EVENT_THROTTLE = 1_000; // 1 second

  constructor(mainWindow: BrowserWindow, onLog?: (source: string, level: 'info' | 'error', message: string) => void) {
    this.mainWindow = mainWindow;
    this.onLog = onLog;
  }

  public start(): void {
    if (this.intervalId) return;
    this.syncAborted = false;
    this.emitLog('Watcher', 'info', '👁️ Pulse monitoring started...');
    this.lastStoreTime = Date.now();
    this.loopCounter = 0;
    // Kick off padded sync immediately, then start the polling loop
    this.startPaddedSync();
    this.intervalId = setTimeout(() => this.runLoop(), 0);
  }

  private async runLoop(): Promise<void> {
    try {
      if (!this.intervalId) return;

      // While padded sync is active, it owns the RPC — skip heavy polling
      // to avoid contention on the single-threaded wallet-rpc
      if (this.isSyncing) return;

      // 1. Check wallet height + cached daemon height
      await this.checkSyncStatus();

      // 2. Periodic tasks
      this.loopCounter++;

      // Check balance every 3 cycles (~6s) or first time
      if (this.loopCounter % 3 === 0 || this.lastKnownBalance === -1) {
        await this.checkBalance();
      }

      await this.periodicStore();
    } catch (e) {
      /* Loop resilience */
    } finally {
      if (this.intervalId !== null) {
        this.intervalId = setTimeout(() => this.runLoop(), 2000);
      }
    }
  }

  public getSnapshot() {
    return {
      balance: this.lastKnownBalance,
      height: this.lastKnownHeight,
    };
  }

  public stop(): void {
    this.syncAborted = true;
    if (this.intervalId) {
      clearTimeout(this.intervalId);
    }
    this.intervalId = null;
    this.lastKnownBalance = -1;
    this.lastKnownHeight = -1;
    this.isSyncing = false;
    this.emitLog('Watcher', 'info', '💤 Pulse monitoring suspended.');
  }

  private pushEvent(payload: WalletEventPayload) {
    if (!this.mainWindow.isDestroyed()) {
      this.mainWindow.webContents.send('wallet-event', payload);
    }
  }

  private async periodicStore(): Promise<void> {
    try {
      if (Date.now() - this.lastStoreTime > 60000) {
        await (WalletManager as any).callRpc('store', {});
        this.lastStoreTime = Date.now();
        this.emitLog('Watcher', 'info', '💾 Auto-saving wallet sync progress');
      }
    } catch (e) { console.warn('[SyncWatcher] Periodic store failed:', e); }
  }

  private emitLog(source: string, level: 'info' | 'error', message: string) {
    console.log(`[${source}] ${message}`);
    if (this.onLog) this.onLog(source, level, message);
  }

  // ─── Daemon Height with TTL Cache ───
  private async getDaemonHeight(): Promise<number> {
    const now = Date.now();
    if (now - this.lastDaemonHeightFetch < SyncWatcher.DAEMON_HEIGHT_TTL && this.cachedDaemonHeight > 0) {
      return this.cachedDaemonHeight;
    }
    try {
      const h = await NodeManager.fetchDaemonHeight();
      if (h > 0) {
        this.cachedDaemonHeight = h;
        this.lastDaemonHeightFetch = now;
      }
      return this.cachedDaemonHeight;
    } catch (e) {
      console.warn('[SyncWatcher] Daemon height fetch failed:', e);
      return this.cachedDaemonHeight;
    }
  }

  // ─── Padded (Chunked) Sync ───
  // Calls `refresh` in batches so the RPC actively scans blocks
  // instead of relying on its slow passive background refresh.
  private async startPaddedSync(): Promise<void> {
    if (this.isSyncing) return;
    this.isSyncing = true;

    this.emitLog('Sync', 'info', '🚀 Starting padded sync...');

    try {
      // Get initial wallet height
      const initialHeight = await (WalletManager as any).callRpc('get_height');
      let currentHeight = initialHeight.height || 0;

      // Fetch daemon height (fresh, ignore cache for initial sync)
      this.lastDaemonHeightFetch = 0;
      let targetHeight = await this.getDaemonHeight();

      if (targetHeight <= 0) {
        this.emitLog('Sync', 'info', '⏳ Daemon height unknown, falling back to passive sync');
        this.isSyncing = false;
        return;
      }

      const gap = targetHeight - currentHeight;
      if (gap <= 10) {
        this.emitLog('Sync', 'info', '✅ Wallet already synced');
        this.isSyncing = false;
        return;
      }

      this.emitLog('Sync', 'info', `📦 ${gap} blocks behind (${currentHeight} → ${targetHeight}), chunking refresh...`);

      // Chunk loop — call refresh repeatedly until caught up
      let chunkCounter = 0;
      while (!this.syncAborted) {
        try {
          // refresh returns { blocks_fetched, received_money }
          // It processes a batch of blocks and returns — not blocking forever
          const result = await (WalletManager as any).callRpc('refresh', {
            start_height: currentHeight
          });

          const fetched = result.blocks_fetched || 0;

          if (fetched === 0) {
            // Caught up or stalled — recheck daemon height with a real get_height
            this.lastDaemonHeightFetch = 0; // Force refresh
            const [freshTarget, heightNow] = await Promise.all([
              this.getDaemonHeight(),
              (WalletManager as any).callRpc('get_height')
            ]);
            currentHeight = heightNow.height || currentHeight;

            if (freshTarget - currentHeight <= 10) {
              this.emitLog('Sync', 'info', `✅ Padded sync complete at block ${currentHeight}`);
              break;
            }
            await new Promise(r => setTimeout(r, 500));
            continue;
          }

          // Use blocks_fetched to estimate height — avoids an extra get_height RPC per chunk.
          // Periodically verify with actual get_height to prevent drift.
          currentHeight += fetched;
          chunkCounter++;

          // Verify actual height every 20 chunks to correct any drift
          if (chunkCounter % 20 === 0) {
            const heightCheck = await (WalletManager as any).callRpc('get_height');
            currentHeight = heightCheck.height || currentHeight;
          }

          // Push progress to UI (throttled to avoid IPC flood)
          this.lastKnownHeight = currentHeight;
          const now = Date.now();
          if (now - this.lastSyncEventTime >= SyncWatcher.SYNC_EVENT_THROTTLE) {
            this.lastSyncEventTime = now;
            this.pushEvent({
              type: 'SYNC_UPDATE',
              payload: { height: currentHeight, daemonHeight: targetHeight }
            });
          }

          // Refresh daemon height every 30 chunks (non-blocking, fire-and-forget style)
          if (chunkCounter % 30 === 0) {
            this.getDaemonHeight().then(h => {
              if (h > targetHeight) targetHeight = h;
            }).catch(() => {});
          }
        } catch (e: any) {
          // refresh can timeout on slow nodes — just retry
          this.emitLog('Sync', 'error', `⚠️ Refresh chunk failed: ${e.message}, retrying...`);
          await new Promise(r => setTimeout(r, 2000));
        }
      }

      // Final sync update + balance check after sync completes
      if (!this.syncAborted) {
        // Emit final SYNC_UPDATE (bypass throttle)
        this.pushEvent({
          type: 'SYNC_UPDATE',
          payload: { height: currentHeight, daemonHeight: targetHeight }
        });
        await this.checkBalance();
        // Save progress immediately
        await (WalletManager as any).callRpc('store', {}).catch(() => {});
        this.lastStoreTime = Date.now();
      }
    } catch (e: any) {
      this.emitLog('Sync', 'error', `❌ Padded sync error: ${e.message}`);
    } finally {
      this.isSyncing = false;
    }
  }

  private async checkSyncStatus(): Promise<void> {
    try {
      // Use cached daemon height (refreshed every 30s)
      const daemonHeight = await this.getDaemonHeight();

      const result = await (WalletManager as any).callRpc('get_height');
      const isFirstRun = this.lastKnownHeight === -1;

      if (result.height !== this.lastKnownHeight || isFirstRun) {
        this.lastKnownHeight = result.height;
        this.emitLog('Watcher', 'info', `🔄 Block height update: ${result.height} / Daemon: ${daemonHeight}`);
        this.pushEvent({
          type: 'SYNC_UPDATE', payload: {
            height: result.height,
            daemonHeight: daemonHeight
          }
        });
      }
    } catch (e) { console.warn('[SyncWatcher] Sync status check failed:', e); }
  }

  private async checkBalance(): Promise<void> {
    try {
      const result = await (WalletManager as any).callRpc('get_balance');
      if (result.balance !== this.lastKnownBalance) {
        this.emitLog('Watcher', 'info', `💰 Balance change detected: ${result.balance}`);
        this.pushEvent({ type: 'BALANCE_CHANGED', payload: { balance: result.balance, unlocked: result.unlocked_balance } });
      }
      this.lastKnownBalance = result.balance;
    } catch (e) { console.warn('[SyncWatcher] Balance check failed:', e); }
  }
}
