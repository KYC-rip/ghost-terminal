//! Background sync pool for the optional "Sync all wallets" feature. Holds a
//! view-pair-only background scanner per non-active wallet so switching to any
//! of them is instant (its cache is kept warm). No spend keys, no mnemonics —
//! view-only. App-managed state, separate from WalletState, so it survives
//! lock/unlock. See project_multiwallet_background_sync.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tauri::AppHandle;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use monero_wallet::ViewPair;

use super::scanner;

struct Entry {
    cancel: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

pub struct SyncPool {
    /// Currently-running background scanners, keyed by identity id.
    entries: Mutex<HashMap<String, Entry>>,
    /// View pairs discovered (via password-reuse on unlock) this session, so a
    /// wallet can be re-pooled after it stops being active without re-decrypting.
    known: Mutex<HashMap<String, ViewPair>>,
    /// Set while the ACTIVE wallet is doing a heavy catch-up (large block gap /
    /// rescan). Background pool scanners back off while this is true, so they don't
    /// compete with the active wallet for the node + CPU.
    active_busy: Arc<AtomicBool>,
}

impl SyncPool {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            known: Mutex::new(HashMap::new()),
            active_busy: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Signal whether the active wallet is mid heavy catch-up (pool backs off).
    pub fn set_active_busy(&self, busy: bool) {
        self.active_busy.store(busy, Ordering::SeqCst);
    }

    /// Whether background pool scanners should back off right now.
    pub fn is_active_busy(&self) -> bool {
        self.active_busy.load(Ordering::SeqCst)
    }

    /// Start background sync for a wallet (idempotent — no-op if already running).
    /// `from_height` is a floor; the loop resumes from the wallet's cache if it's
    /// further along. Also records the view pair for later re-pooling.
    pub async fn start(&self, app: &AppHandle, id: String, view_pair: ViewPair, from_height: u64) {
        self.known.lock().await.insert(id.clone(), view_pair.clone());

        let mut entries = self.entries.lock().await;
        if entries.contains_key(&id) {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let handle = {
            let app = app.clone();
            let id = id.clone();
            let cancel = cancel.clone();
            tokio::spawn(async move {
                scanner::run_pool_scan(app, id, view_pair, from_height, cancel).await;
            })
        };
        entries.insert(id, Entry { cancel, handle });
    }

    /// Stop one wallet's background sync (e.g. it just became the active wallet).
    pub async fn stop(&self, id: &str) {
        if let Some(e) = self.entries.lock().await.remove(id) {
            e.cancel.store(true, Ordering::SeqCst);
            e.handle.abort();
        }
    }

    /// Stop everything (e.g. the "Sync all wallets" setting was turned off).
    pub async fn stop_all(&self) {
        let mut entries = self.entries.lock().await;
        for (_, e) in entries.drain() {
            e.cancel.store(true, Ordering::SeqCst);
            e.handle.abort();
        }
    }

    /// (Re)start every known wallet except `active`. Lets a previously-active
    /// wallet rejoin the pool after a switch, using its remembered view pair.
    pub async fn resume_all_except(&self, app: &AppHandle, active: &str) {
        let known: Vec<(String, ViewPair)> = self
            .known
            .lock()
            .await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        for (id, vp) in known {
            if id != active {
                self.start(app, id, vp, 0).await;
            }
        }
    }
}
