// src/main/IdentityManager.ts
import { app, ipcMain } from 'electron';
import fs from 'fs/promises'; // 🚀 Force async API to prevent UI stutter
import { existsSync } from 'fs';
import path from 'path';
import { WalletManager } from '../WalletManager';
import { getWalletDirName } from '../networkPaths';

export function registerIdentityHandlers(store: any) {
  // Resolved per call: identities are network-scoped (stressnet wallets live
  // in their own dir) and the network can change at runtime via engine reload.
  const walletDir = () => path.join(app.getPath('userData'), getWalletDirName(store.get('network') || 'mainnet'));

  // 🔍 Fetch list: Force reconciliation between physical disk and Store database
  ipcMain.handle('get-identities', async () => {
    try {
      if (!existsSync(walletDir())) {
        await fs.mkdir(walletDir(), { recursive: true });
      }

      // 1. Read the absolute truth: physical vault files on disk
      const files = await fs.readdir(walletDir());
      const keyFiles = files.filter(f => f.endsWith('.keys'));

      console.log(`${keyFiles.length} key files found in ${walletDir()}`)

      // 2. Read auxiliary attributes: alias records in the Store
      const storedIds: any[] = store.get('identities') || [];

      // 3. Execute Reconciliation
      const validIdentities = await Promise.all(keyFiles.map(async (fileName) => {
        const id = fileName.replace('.keys', '');
        const existingMeta = storedIds.find((i: any) => i.id === id);

        if (existingMeta) {
          // If on disk and in Store, preserve user-defined name
          return existingMeta;
        } else {
          // 👻 "Ghost Wallet" detected: physical file present but no record in Store
          const stats = await fs.stat(path.join(walletDir(), fileName));
          return {
            id: id,
            name: id, // Default to filename as display name
            created: stats.birthtimeMs
          };
        }
      }));

      // 4. Cleanup dead links: if record exists in Store but file is deleted, remove it
      store.set('identities', validIdentities);

      // 5. Graceful degradation: avoid fabricating 'primary' dummy data in backend
      // If no files, return empty array and let React front-end render "Welcome" UI
      return validIdentities;

    } catch (error) {
      console.error('[IdentityManager] Failed to scan vault:', error);
      return [];
    }
  });

  // 📝 Maintain pure CRUD for other methods and remove redundant defensive code
  ipcMain.handle('get-active-identity', () => {
    return store.get('active_identity_id') || null;
  });

  ipcMain.handle('set-active-identity', (_, id) => {
    if (id) store.set('active_identity_id', id);
    else store.delete('active_identity_id');
    return true;
  });

  ipcMain.handle('save-identities', (_, ids) => {
    store.set('identities', ids);
    return true;
  });

  ipcMain.handle('rename-identity', (_, { id, name }) => {
    const ids = store.get('identities') || [];
    const updated = ids.map((i: any) => i.id === id ? { ...i, name } : i);
    store.set('identities', updated);
    return true;
  });

  // 🔥 Physical vault destruction — deletes .keys and companion files from disk
  ipcMain.handle('delete-identity-files', async (_, id: string) => {
    try {
      // Always attempt to hard-close the wallet via RPC first — the wallet-rpc process
      // holds a file lock on .keys files, preventing deletion
      await WalletManager.closeWallet().catch(() => { });

      const keysFile = path.join(walletDir(), `${id}.keys`);
      const cacheFile = path.join(walletDir(), id); // wallet cache file (no extension)

      if (existsSync(keysFile)) await fs.unlink(keysFile);
      if (existsSync(cacheFile)) await fs.unlink(cacheFile);

      // Also clean up from Store
      const ids = (store.get('identities') || []).filter((i: any) => i.id !== id);
      store.set('identities', ids);

      // If this was the active identity, clear it
      if (store.get('active_identity_id') === id) {
        store.delete('active_identity_id');
      }

      console.log(`[IdentityHandler] 🔥 Identity "${id}" physically destroyed.`);
      return { success: true };
    } catch (error: any) {
      console.error(`[IdentityHandler] Failed to delete identity "${id}":`, error);
      return { success: false, error: error.message };
    }
  });
}