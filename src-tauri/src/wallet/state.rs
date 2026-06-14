use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::RwLock;
use tauri::AppHandle;
use tauri::Manager;

use zeroize::Zeroizing;

use monero_wallet::{ViewPair, Scanner, WalletOutput};
use monero_oxide::ed25519::{Scalar, Point};
use monero_address::{Network, MoneroAddress};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;

use super::keys;
use super::storage::{self, WalletFileData, AccountLabel};
use super::types::*;

/// A scanned output we own, tagged with the block height it was received at
/// (monero-wallet's WalletOutput doesn't carry block height).
#[derive(Clone)]
pub struct OwnedOutput {
    pub output: WalletOutput,
    pub height: u64,
}

/// Stable per-output identifier: "hextxid:index_in_transaction". Unique because
/// (txid, output index) is unique on-chain. Used for spent/frozen sets and as
/// the synthetic key image surfaced to the UI (a real key image needs output
/// private-key derivation, which monero-oxide doesn't expose).
pub fn output_id(o: &WalletOutput) -> String {
    format!("{}:{}", hex::encode(o.transaction()), o.index_in_transaction())
}

/// Stable key linking a prepared tx to its relay step. The tx metadata bytes are
/// identical at prepare (serialized) and relay (passed back), so their keccak256
/// is a reliable join key for the staged spend.
pub fn tx_meta_key(meta: &[u8]) -> String {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(meta);
    k.finalize(&mut out);
    hex::encode(out)
}

/// Core wallet state — holds keys, scanned outputs, accounts, sync progress.
pub struct WalletState {
    app: AppHandle,
    inner: Arc<RwLock<WalletInner>>,
    /// Incremented each time a new scanner is started. Old scanners check this
    /// and stop if it doesn't match their generation.
    pub scanner_generation: AtomicU64,
    /// When true (an EJECT vigil is armed), a UI lock retains the Monero spend
    /// key so the order can dispatch unattended. Mirrors the renderer's
    /// vigilHotWallet flag via the set_vigil_hot command. Default false: lock
    /// zeroes the spend key as usual.
    pub vigil_hot: AtomicBool,
}

struct WalletInner {
    is_locked: bool,
    active_identity: Option<String>,
    password: Option<String>,
    accounts: Vec<MoneroAccount>,
    sync_status: SyncStatus,
    network: Network,

    // Cryptographic material (cleared on lock)
    spend_key: Option<Zeroizing<Scalar>>,
    view_key: Option<Zeroizing<Scalar>>,
    view_pair: Option<ViewPair>,
    mnemonic: Option<Zeroizing<String>>,
    scanner: Option<Scanner>,

    // Subaddress tracking
    next_subaddress_index: u32, // next unused subaddress index for account 0
    subaddress_labels: Vec<(u32, String)>, // (index, label)

    // Tracked state from scanning
    scanned_outputs: Vec<OwnedOutput>,
    /// Output ids spent by a broadcast tx (excluded from balance/coin-control/
    /// input-selection until a rescan reconfirms). Fixes the balance over-count
    /// where spent outputs lingered in scanned_outputs.
    spent: HashSet<String>,
    /// Frozen output ids (coin control), persisted.
    frozen: HashSet<String>,
    /// Broadcast transactions, for outgoing history.
    sent: Vec<storage::SentTx>,
    /// Spend staged at prepare time (spent ids + partial sent-log entry), keyed
    /// by a hash of the tx metadata; committed only after the broadcast succeeds.
    pending_spends: HashMap<String, (Vec<String>, storage::SentTx)>,
    scan_height: u64,

    // Active daemon URL (set by scanner after connecting)
    daemon_url: Option<String>,

    // Data dir for wallet files
    data_dir: PathBuf,
}

impl WalletState {
    pub fn new(app: AppHandle) -> Self {
        let data_dir = app.path().app_data_dir()
            .unwrap_or_else(|_| PathBuf::from("."));

        Self {
            app,
            scanner_generation: AtomicU64::new(0),
            vigil_hot: AtomicBool::new(false),
            inner: Arc::new(RwLock::new(WalletInner {
                is_locked: true,
                active_identity: None,
                password: None,
                accounts: vec![],
                sync_status: SyncStatus {
                    status: "OFFLINE".to_string(),
                    height: 0,
                    daemon_height: 0,
                    sync_percent: 0.0, node_label: String::new(), node_url: String::new(),
                },
                network: Network::Mainnet,
                spend_key: None,
                view_key: None,
                view_pair: None,
                mnemonic: None,
                scanner: None,
                next_subaddress_index: 1,
                subaddress_labels: vec![],
                scanned_outputs: vec![],
                spent: HashSet::new(),
                frozen: HashSet::new(),
                sent: vec![],
                pending_spends: HashMap::new(),
                scan_height: 0,
                daemon_url: None,
                data_dir,
            })),
        }
    }

    pub async fn is_locked(&self) -> bool {
        self.inner.read().await.is_locked
    }

    /// Verify a vault password WITHOUT unlocking or touching the scanner —
    /// just attempt to decrypt the wallet file. Used by the vigil strike-wallet
    /// password gate so it doesn't restart the running sync (open_wallet would).
    pub async fn verify_password(&self, identity_id: &str, password: &str) -> Result<(), String> {
        let data_dir = self.inner.read().await.data_dir.clone();
        storage::load_wallet(&data_dir, identity_id, password).map(|_| ())
    }

    /// Create a new wallet from scratch or restore from mnemonic.
    pub async fn create_wallet(
        &self,
        identity_id: &str,
        password: &str,
        seed_phrase: Option<&str>,
        restore_height: Option<u64>,
    ) -> Result<String, String> {
        let (mnemonic, spend_key, view_key) = if let Some(seed) = seed_phrase {
            // Restore from existing mnemonic
            let (sk, vk) = keys::keys_from_mnemonic(seed)?;
            (seed.to_string(), sk, vk)
        } else {
            // Generate new wallet
            keys::generate_mnemonic()
        };

        // Save encrypted wallet file
        let inner = self.inner.read().await;
        let entropy_hex = hex::encode(<[u8; 32]>::from(*spend_key));
        let wallet_data = WalletFileData {
            seed_entropy: entropy_hex,
            // For new wallets, use u64::MAX as sentinel — scanner auto-adjusts to daemon tip.
            // For restores, use provided height (or 0 for full scan).
            scan_height: restore_height.unwrap_or(if seed_phrase.is_some() { 0 } else { u64::MAX }),
            accounts: vec![AccountLabel { index: 0, label: "Primary".into() }],
            subaddress_labels: vec![],
        };
        storage::save_wallet(&inner.data_dir, identity_id, &wallet_data, password)?;
        drop(inner);

        log::info!("Wallet created for identity: {}", identity_id);
        Ok(mnemonic)
    }

    /// Open an existing wallet with password.
    pub async fn unlock(&self, identity_id: &str, password: &str) -> Result<(), String> {
        let mut inner = self.inner.write().await;

        // Load and decrypt wallet file
        let wallet_data = storage::load_wallet(&inner.data_dir, identity_id, password)?;

        // Derive keys from stored entropy
        let entropy_bytes: [u8; 32] = hex::decode(&wallet_data.seed_entropy)
            .map_err(|e| format!("Invalid seed entropy: {}", e))?
            .try_into()
            .map_err(|_| "Seed entropy must be 32 bytes".to_string())?;

        let (spend_key, view_key) = keys::keys_from_entropy(&entropy_bytes)?;

        // Derive public spend key: G * spend_key
        let dalek_scalar: curve25519_dalek::Scalar = (*spend_key).into();
        let spend_point = Point::from(&dalek_scalar * ED25519_BASEPOINT_POINT);

        // Create ViewPair and Scanner
        let view_pair = ViewPair::new(spend_point, view_key.clone())
            .map_err(|e| format!("Failed to create ViewPair: {:?}", e))?;
        let mut scanner = Scanner::new(view_pair.clone());

        // Derive primary address for display
        let network = inner.network;
        let primary_address = view_pair.legacy_address(network);

        // Register existing subaddresses with the scanner so it can detect them
        let num_subaddresses = wallet_data.subaddress_labels.len().max(20) as u32;
        for i in 1..=num_subaddresses {
            if let Some(idx) = monero_address::SubaddressIndex::new(0, i) {
                scanner.register_subaddress(idx);
            }
        }

        // Set up accounts from saved labels
        let addr_str = primary_address.to_string();
        log::info!("Primary address derived: {}", addr_str);

        let accounts: Vec<MoneroAccount> = wallet_data.accounts.iter().map(|a| {
            MoneroAccount {
                index: a.index,
                label: a.label.clone(),
                balance: "0".to_string(),
                unlocked_balance: "0".to_string(),
                base_address: if a.index == 0 {
                    addr_str.clone()
                } else {
                    String::new()
                },
            }
        }).collect();

        // Restore subaddress labels
        let subaddress_labels: Vec<(u32, String)> = wallet_data.subaddress_labels.iter()
            .map(|s| (s.index, s.label.clone()))
            .collect();

        inner.spend_key = Some(spend_key);
        inner.view_key = Some(view_key);
        inner.view_pair = Some(view_pair);
        inner.scanner = Some(scanner);
        inner.is_locked = false;
        inner.active_identity = Some(identity_id.to_string());
        inner.password = Some(password.to_string());
        inner.scan_height = wallet_data.scan_height;
        inner.accounts = accounts;
        inner.next_subaddress_index = (num_subaddresses + 1).max(1);
        inner.subaddress_labels = subaddress_labels;
        inner.sync_status.status = "SYNCING".to_string();

        // Start from a clean slate: a soft lock leaves scanned_outputs
        // resident for background sync, so clear before reloading the cache —
        // otherwise re-unlock (or an identity switch) would append on top and
        // double-count the balance.
        inner.scanned_outputs.clear();
        inner.spent.clear();
        inner.frozen.clear();
        inner.sent.clear();
        inner.pending_spends.clear();

        // Load cached outputs (avoids full rescan on relaunch)
        let cache = storage::load_output_cache(&inner.data_dir, identity_id);
        if !cache.outputs.is_empty() {
            log::info!("Loaded {} cached outputs from disk", cache.outputs.len());
            // Restore WalletOutputs (+ their block height) from serialized cache
            for cached in &cache.outputs {
                if let Ok(output) = monero_wallet::WalletOutput::read(&mut cached.data.as_slice()) {
                    inner.scanned_outputs.push(OwnedOutput { output, height: cached.height });
                }
            }
            // Use cached scan height if it's ahead of what's in the wallet file
            if cache.scan_height > inner.scan_height {
                inner.scan_height = cache.scan_height;
            }
        }
        inner.spent = cache.spent.into_iter().collect();
        inner.frozen = cache.frozen.into_iter().collect();
        inner.sent = cache.sent;

        log::info!("Wallet unlocked for identity: {} (resume from height {}, {} subaddresses, {} cached outputs)",
            identity_id, inner.scan_height, num_subaddresses, inner.scanned_outputs.len());
        Ok(())
    }

    /// Get mnemonic seed (for backup).
    pub async fn get_mnemonic(&self) -> Result<String, String> {
        let inner = self.inner.read().await;
        let spend_key = inner.spend_key.as_ref()
            .ok_or("Wallet is locked")?;

        // Convert spend key back to mnemonic via entropy
        let entropy: [u8; 32] = <[u8; 32]>::from(**spend_key);
        let seed = monero_seed::Seed::from_entropy(
            monero_seed::Language::English,
            Zeroizing::new(entropy),
        ).ok_or("Failed to convert key to mnemonic")?;

        Ok((*seed.to_string()).clone())
    }

    /// True if `identity_id` is the wallet currently resident in this state
    /// (whether unlocked or soft-locked).
    pub async fn is_active_identity(&self, identity_id: &str) -> bool {
        self.inner.read().await.active_identity.as_deref() == Some(identity_id)
    }

    /// True if a scanner is resident — i.e. the background scan loop is alive
    /// (soft-lock keeps it). Used to detect "same wallet, still syncing".
    pub async fn has_scanner(&self) -> bool {
        self.inner.read().await.scanner.is_some()
    }

    /// Light re-unlock for an already-resident, soft-locked wallet: restore only
    /// the spend key (and password) the soft-lock zeroed, WITHOUT clearing
    /// scanned outputs or touching the scan height. Lets the running background
    /// scan keep its progress instead of being reset by a full unlock. Verifies
    /// the password via decrypt and fails on mismatch.
    pub async fn restore_spend_key(&self, identity_id: &str, password: &str) -> Result<(), String> {
        let data_dir = self.inner.read().await.data_dir.clone();
        let wallet_data = storage::load_wallet(&data_dir, identity_id, password)?;
        let entropy: [u8; 32] = hex::decode(&wallet_data.seed_entropy)
            .map_err(|e| format!("Invalid seed entropy: {}", e))?
            .try_into()
            .map_err(|_| "Seed entropy must be 32 bytes".to_string())?;
        let (spend_key, _view_key) = keys::keys_from_entropy(&entropy)?;
        let mut inner = self.inner.write().await;
        inner.spend_key = Some(spend_key);
        inner.is_locked = false;
        inner.password = Some(password.to_string());
        Ok(())
    }

    pub async fn lock(&self) {
        // Save output cache before taking exclusive lock
        self.save_output_cache().await;

        let mut inner = self.inner.write().await;

        // Save scan progress before locking
        if let (Some(identity_id), Some(password)) = (&inner.active_identity, &inner.password) {
            if let Some(spend_key) = &inner.spend_key {
                let entropy_hex = hex::encode(<[u8; 32]>::from(**spend_key));
                let wallet_data = WalletFileData {
                    seed_entropy: entropy_hex,
                    scan_height: inner.scan_height,
                    accounts: inner.accounts.iter().map(|a| AccountLabel {
                        index: a.index,
                        label: a.label.clone(),
                    }).collect(),
                    subaddress_labels: inner.subaddress_labels.iter().map(|(idx, label)| {
                        storage::SubaddressLabel { account: 0, index: *idx, label: label.clone() }
                    }).collect(),
                };
                let _ = storage::save_wallet(&inner.data_dir, identity_id, &wallet_data, password);
            }
        }

        // Soft lock: zero ONLY the spend-capable secrets. Keep the view key,
        // scanner, and scanned outputs alive so the background sync keeps
        // progressing while the UI is locked — otherwise a long restore dies
        // on the auto-lock timer and can never finish unattended. Syncing only
        // needs the view key; spending requires re-unlock (which restores the
        // spend key). View-only data (balance/address) stays resident — the
        // same lock-survival tradeoff used on the desktop build.
        inner.is_locked = true;
        // Retain the spend key ONLY while an EJECT vigil is armed (set via
        // set_vigil_hot), so the order can dispatch unattended behind the lock.
        // mnemonic + password are always zeroed regardless.
        if !self.vigil_hot.load(Ordering::SeqCst) {
            inner.spend_key = None;
        }
        inner.mnemonic = None;
        inner.password = None;
        log::info!("Wallet soft-locked — spend key zeroed; view-only background sync continues");
    }

    pub async fn get_accounts(&self) -> Vec<MoneroAccount> {
        self.inner.read().await.accounts.clone()
    }

    pub async fn get_sync_status(&self) -> SyncStatus {
        self.inner.read().await.sync_status.clone()
    }

    pub async fn update_sync_status(&self, height: u64, daemon_height: u64) {
        let mut inner = self.inner.write().await;
        inner.scan_height = height;
        inner.sync_status.height = height;
        inner.sync_status.daemon_height = daemon_height;
        if daemon_height > 0 {
            inner.sync_status.sync_percent = (height as f64 / daemon_height as f64) * 100.0;
            inner.sync_status.status = if daemon_height.saturating_sub(height) <= 5 {
                "SYNCED".to_string()
            } else {
                "SYNCING".to_string()
            };
        }
    }

    pub async fn get_scanner(&self) -> Option<Scanner> {
        self.inner.read().await.scanner.clone()
    }

    pub async fn get_scan_height(&self) -> u64 {
        self.inner.read().await.scan_height
    }

    /// Append scanned outputs, but only if `generation` is still the active
    /// scanner. Checking under the write lock makes the add atomic with
    /// rescan's reset: if a newer scanner (e.g. a rescan that just cleared
    /// scanned_outputs) has taken over, a stale scanner's outputs are dropped
    /// rather than re-appended on top of the fresh state (which would
    /// double-count the balance).
    pub async fn add_outputs(&self, outputs: Vec<WalletOutput>, height: u64, generation: u64) {
        let mut inner = self.inner.write().await;
        if self.scanner_generation.load(Ordering::SeqCst) != generation {
            return;
        }
        inner
            .scanned_outputs
            .extend(outputs.into_iter().map(|output| OwnedOutput { output, height }));
    }

    pub async fn get_spend_key(&self) -> Option<Zeroizing<Scalar>> {
        self.inner.read().await.spend_key.clone()
    }

    pub async fn get_view_pair(&self) -> Option<ViewPair> {
        self.inner.read().await.view_pair.clone()
    }

    pub async fn set_daemon_url(&self, url: &str) {
        self.inner.write().await.daemon_url = Some(url.to_string());
    }

    pub async fn get_daemon_url(&self) -> Option<String> {
        self.inner.read().await.daemon_url.clone()
    }

    /// Outputs available to spend: unspent and not frozen. (Locked-by-timelock
    /// outputs are left in; tx construction will reject any that aren't mature.)
    pub async fn get_spendable_outputs(&self) -> Vec<WalletOutput> {
        let inner = self.inner.read().await;
        inner
            .scanned_outputs
            .iter()
            .filter(|o| {
                let id = output_id(&o.output);
                !inner.spent.contains(&id) && !inner.frozen.contains(&id)
            })
            .map(|o| o.output.clone())
            .collect()
    }

    /// All owned outputs with their height and spent/frozen flags — for the
    /// coin-control list and for reconstructing incoming history.
    pub async fn list_owned(&self) -> Vec<(OwnedOutput, bool, bool)> {
        let inner = self.inner.read().await;
        inner
            .scanned_outputs
            .iter()
            .map(|o| {
                let id = output_id(&o.output);
                (o.clone(), inner.spent.contains(&id), inner.frozen.contains(&id))
            })
            .collect()
    }

    /// Broadcast-transaction log, for outgoing history.
    pub async fn get_sent(&self) -> Vec<storage::SentTx> {
        self.inner.read().await.sent.clone()
    }

    /// The stored tx secret key (hex) for a broadcast tx, if we have it.
    pub async fn get_tx_key(&self, txid: &str) -> Option<String> {
        self.inner
            .read()
            .await
            .sent
            .iter()
            .find(|s| s.tx_hash == txid && !s.tx_key.is_empty())
            .map(|s| s.tx_key.clone())
    }

    /// Daemon tip height (best-known), for confirmations / unlock checks.
    pub async fn tip_height(&self) -> u64 {
        self.inner.read().await.sync_status.daemon_height
    }

    /// Stage the spend a prepared tx will perform, keyed by a hash of its tx
    /// metadata. `sent` carries amount/fee/destinations; tx_hash/height/timestamp
    /// are filled at commit. Applied to the spent set only once broadcast succeeds.
    pub async fn stage_pending_spend(&self, meta_key: String, ids: Vec<String>, sent: storage::SentTx) {
        self.inner.write().await.pending_spends.insert(meta_key, (ids, sent));
    }

    /// Commit a staged spend after a successful broadcast: mark its inputs spent,
    /// finalize the sent-log entry (tx_hash/height/timestamp), and persist. If no
    /// staged spend is found (e.g. app restarted mid-flow), a rescan reconciles.
    pub async fn commit_spend(&self, meta_key: &str, tx_hash: String, height: u64, timestamp: u64) {
        {
            let mut inner = self.inner.write().await;
            if let Some((ids, mut sent)) = inner.pending_spends.remove(meta_key) {
                for id in ids {
                    inner.spent.insert(id);
                }
                sent.tx_hash = tx_hash;
                sent.height = height;
                sent.timestamp = timestamp;
                inner.sent.push(sent);
            }
        }
        self.save_output_cache().await;
    }

    /// Mark a set of output ids spent directly (used by sweep_all, which knows
    /// its inputs up-front). Records the sent entry and persists.
    pub async fn mark_spent(&self, ids: Vec<String>, sent: storage::SentTx) {
        {
            let mut inner = self.inner.write().await;
            for id in ids {
                inner.spent.insert(id);
            }
            inner.sent.push(sent);
        }
        self.save_output_cache().await;
    }

    pub async fn get_network(&self) -> Network {
        self.inner.read().await.network
    }

    pub async fn data_dir(&self) -> PathBuf {
        self.inner.read().await.data_dir.clone()
    }

    /// (active_identity, password) if a wallet is currently unlocked — lets
    /// settings changes reconcile the background sync pool without re-prompting.
    pub async fn active_session(&self) -> Option<(String, String)> {
        let inner = self.inner.read().await;
        match (&inner.active_identity, &inner.password) {
            (Some(id), Some(pw)) => Some((id.clone(), pw.clone())),
            _ => None,
        }
    }

    /// Derive the VIEW pair for another identity by decrypting its vault with
    /// `password` (view-only — no spend key retained). Used to start background
    /// sync of other wallets. Fails on wrong password.
    pub async fn derive_view_pair_for(
        &self,
        identity_id: &str,
        password: &str,
    ) -> Result<ViewPair, String> {
        let data_dir = self.inner.read().await.data_dir.clone();
        let wallet_data = storage::load_wallet(&data_dir, identity_id, password)?;
        let entropy: [u8; 32] = hex::decode(&wallet_data.seed_entropy)
            .map_err(|e| format!("Invalid seed entropy: {}", e))?
            .try_into()
            .map_err(|_| "Seed entropy must be 32 bytes".to_string())?;
        let (spend_key, view_key) = keys::keys_from_entropy(&entropy)?;
        let dalek_scalar: curve25519_dalek::Scalar = (*spend_key).into();
        let spend_point = Point::from(&dalek_scalar * ED25519_BASEPOINT_POINT);
        ViewPair::new(spend_point, view_key).map_err(|e| format!("Failed to create ViewPair: {:?}", e))
    }

    /// Increment scanner generation — any running scanner with an older generation will stop.
    pub fn next_scanner_generation(&self) -> u64 {
        self.scanner_generation.fetch_add(1, Ordering::SeqCst) + 1
    }

    pub fn current_scanner_generation(&self) -> u64 {
        self.scanner_generation.load(Ordering::SeqCst)
    }

    /// Reset scan progress for a rescan.
    pub async fn reset_scan(&self, from_height: u64) {
        let mut inner = self.inner.write().await;
        inner.scan_height = from_height;
        inner.scanned_outputs.clear();
        // Spent/pending are rebuilt by the rescan; frozen + sent are user/history
        // state and survive. This also clears any stale spent over-count.
        inner.spent.clear();
        inner.pending_spends.clear();
        inner.sync_status.status = "SYNCING".to_string();
        inner.sync_status.height = from_height;
        inner.sync_status.sync_percent = 0.0;
    }

    /// Derive the primary (legacy) address.
    pub async fn get_primary_address(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.view_pair.as_ref().map(|vp| vp.legacy_address(inner.network).to_string())
    }

    /// Create a new subaddress and register it with the scanner.
    pub async fn create_subaddress(&self, label: &str) -> Result<SubaddressInfo, String> {
        let mut inner = self.inner.write().await;

        let view_pair = inner.view_pair.as_ref().ok_or("Wallet is locked")?;
        let idx = inner.next_subaddress_index;

        let sub_idx = monero_address::SubaddressIndex::new(0, idx)
            .ok_or("Invalid subaddress index")?;

        // Derive the subaddress
        let address = view_pair.subaddress(inner.network, sub_idx);

        // Register with scanner so future scans detect outputs to this subaddress
        if let Some(scanner) = inner.scanner.as_mut() {
            scanner.register_subaddress(sub_idx);
        }

        inner.subaddress_labels.push((idx, label.to_string()));
        inner.next_subaddress_index = idx + 1;

        Ok(SubaddressInfo {
            index: idx,
            address: address.to_string(),
            label: label.to_string(),
            balance: "0".to_string(),
            unlocked_balance: "0".to_string(),
            is_used: false,
        })
    }

    /// Get all subaddresses (primary + derived).
    pub async fn get_subaddresses(&self) -> Vec<SubaddressInfo> {
        let inner = self.inner.read().await;
        let view_pair = match inner.view_pair.as_ref() {
            Some(vp) => vp,
            None => return vec![],
        };

        let mut result = vec![];

        // Index 0 = primary address
        result.push(SubaddressInfo {
            index: 0,
            address: view_pair.legacy_address(inner.network).to_string(),
            label: "Primary".to_string(),
            balance: "0".to_string(),
            unlocked_balance: "0".to_string(),
            is_used: true,
        });

        // Derived subaddresses
        for i in 1..inner.next_subaddress_index {
            if let Some(sub_idx) = monero_address::SubaddressIndex::new(0, i) {
                let address = view_pair.subaddress(inner.network, sub_idx);
                let label = inner.subaddress_labels.iter()
                    .find(|(idx, _)| *idx == i)
                    .map(|(_, l)| l.clone())
                    .unwrap_or_else(|| format!("Subaddress #{}", i));

                result.push(SubaddressInfo {
                    index: i,
                    address: address.to_string(),
                    label,
                    balance: "0".to_string(),
                    unlocked_balance: "0".to_string(),
                    is_used: false,
                });
            }
        }

        result
    }

    /// Set a label for a subaddress.
    /// Persist scanned outputs to disk cache.
    pub async fn save_output_cache(&self) {
        let inner = self.inner.read().await;
        if let Some(identity_id) = &inner.active_identity {
            let cached_outputs: Vec<storage::CachedOutput> = inner.scanned_outputs.iter().map(|o| {
                storage::CachedOutput {
                    data: o.output.serialize(),
                    amount: o.output.commitment().amount,
                    tx_hash: hex::encode(o.output.transaction()),
                    tx_index: o.output.index_in_transaction(),
                    subaddress: o.output.subaddress().map(|s| s.address()),
                    height: o.height,
                }
            }).collect();

            let cache = storage::OutputCache {
                scan_height: inner.scan_height,
                outputs: cached_outputs,
                spent: inner.spent.iter().cloned().collect(),
                frozen: inner.frozen.iter().cloned().collect(),
                sent: inner.sent.clone(),
            };

            if let Err(e) = storage::save_output_cache(&inner.data_dir, identity_id, &cache) {
                log::warn!("Failed to save output cache: {}", e);
            } else {
                log::info!("Output cache saved: {} outputs at height {}", cache.outputs.len(), cache.scan_height);
            }
        }
    }

    pub async fn set_subaddress_label(&self, index: u32, label: &str) {
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.subaddress_labels.iter_mut().find(|(idx, _)| *idx == index) {
            entry.1 = label.to_string();
        } else {
            inner.subaddress_labels.push((index, label.to_string()));
        }
    }

    /// Compute total balance from scanned outputs (in atomic units / piconero).
    pub async fn compute_balance(&self) -> u64 {
        let inner = self.inner.read().await;
        inner.scanned_outputs.iter()
            .filter(|o| !inner.spent.contains(&output_id(&o.output)))
            .map(|o| o.output.commitment().amount)
            .sum()
    }

    /// (total, unlocked) atomic balances over unspent outputs. `total` excludes
    /// spent; `unlocked` additionally excludes frozen and immature outputs (the
    /// standard 10-block lock plus any explicit timelock). `tip` is the current
    /// chain height. Amounts are atomic piconero.
    pub async fn balances(&self, tip: u64) -> (u64, u64) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let inner = self.inner.read().await;
        let mut total = 0u64;
        let mut unlocked = 0u64;
        for o in &inner.scanned_outputs {
            let id = output_id(&o.output);
            if inner.spent.contains(&id) {
                continue;
            }
            let amt = o.output.commitment().amount;
            total = total.saturating_add(amt);
            if inner.frozen.contains(&id) {
                continue;
            }
            let mature = tip >= o.height.saturating_add(10);
            let timelock_ok = match o.output.additional_timelock() {
                monero_oxide::transaction::Timelock::None => true,
                monero_oxide::transaction::Timelock::Block(b) => (tip as usize) >= b,
                monero_oxide::transaction::Timelock::Time(t) => now >= t,
            };
            if mature && timelock_ok {
                unlocked = unlocked.saturating_add(amt);
            }
        }
        (total, unlocked)
    }

    /// Format piconero to XMR string.
    pub fn format_xmr(atomic: u64) -> String {
        let whole = atomic / 1_000_000_000_000;
        let frac = atomic % 1_000_000_000_000;
        format!("{}.{:012}", whole, frac)
            .trim_end_matches('0')
            .trim_end_matches('.')
            .to_string()
    }

    /// Get the number of scanned outputs.
    pub async fn output_count(&self) -> usize {
        self.inner.read().await.scanned_outputs.len()
    }
}
