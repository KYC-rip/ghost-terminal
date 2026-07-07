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
    /// Real block header timestamp (Unix seconds); 0 if unknown (pre-timestamp cache).
    pub timestamp: u64,
}

/// Stable per-output identifier: "hextxid:index_in_transaction". Unique because
/// (txid, output index) is unique on-chain. Used for spent/frozen sets and as
/// the synthetic key image surfaced to the UI (a real key image needs output
/// private-key derivation, which monero-oxide doesn't expose).
pub fn output_id(o: &WalletOutput) -> String {
    format!("{}:{}", hex::encode(o.transaction()), o.index_in_transaction())
}

/// Max length (chars) for an account / subaddress label — bounds wallet-file bloat.
const MAX_LABEL_CHARS: usize = 64;

/// Persist the current in-memory accounts + subaddress labels to the encrypted wallet
/// file, preserving seed / scan_height. Returns Err on failure so callers of IRREVERSIBLE
/// create operations can roll back their in-memory mutation rather than let disk fall out
/// of sync (a desync would leave funds sent to a not-yet-persisted subaddress undetected
/// after restart). Load → update → save so unrelated fields stay untouched.
fn persist_meta(inner: &WalletInner) -> Result<(), String> {
    let (id, pw) = match (inner.active_identity.clone(), inner.password.clone()) {
        (Some(id), Some(pw)) => (id, pw),
        _ => return Err("wallet is locked (no retained password)".to_string()),
    };
    let mut wd = storage::load_wallet(&inner.data_dir, &id, &pw)
        .map_err(|e| format!("load wallet: {}", e))?;
    wd.accounts = inner
        .accounts
        .iter()
        .map(|a| storage::AccountLabel { index: a.index, label: a.label.clone() })
        .collect();
    wd.subaddress_labels = inner
        .subaddress_labels
        .iter()
        .map(|(a, i, l)| storage::SubaddressLabel { account: *a, index: *i, label: l.clone() })
        .collect();
    storage::save_wallet(&inner.data_dir, &id, &wd, &pw).map_err(|e| format!("save wallet: {}", e))
}

/// Every address this wallet controls, as strings: the legacy main address plus every
/// registered subaddress across ALL accounts (minor 0 for account>0 is that account's
/// base address). Used to recognize sends/sweeps that return funds to ourselves. Empty
/// while locked (no view pair).
fn own_address_strings(inner: &WalletInner) -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    if let Some(vp) = inner.view_pair.as_ref() {
        let net = inner.network;
        set.insert(vp.legacy_address(net).to_string());
        for (&account, &next) in &inner.subaddress_next {
            // Account 0's minor 0 IS the legacy address (added above); account>0's minor
            // 0 is its base subaddress, so start there.
            let start = if account == 0 { 1 } else { 0 };
            for i in start..next {
                if let Some(idx) = monero_address::SubaddressIndex::new(account, i) {
                    set.insert(vp.subaddress(net, idx).to_string());
                }
            }
        }
    }
    set
}

/// Compute the key image (linking tag) for an owned output:
///   KI = (spend_key + key_offset) · Hp(P)
/// where P is the output's one-time public key and Hp is Monero's key-image
/// generator. Mirrors monero-wallet's own signing derivation. Requires the
/// private spend key, so it's only computable for an unlocked (active) wallet —
/// view-only/background wallets can't detect spends. Returns the compressed
/// 32-byte key image. A wrong result simply never matches a chain input (the
/// output stays counted), so this can't hide spendable funds.
pub fn output_key_image(spend_key: &Scalar, o: &WalletOutput) -> [u8; 32] {
    let spend_dalek: curve25519_dalek::Scalar = (*spend_key).into();
    let offset_dalek: curve25519_dalek::Scalar = o.key_offset().into();
    let input_key = spend_dalek + offset_dalek;
    let hp: curve25519_dalek::EdwardsPoint =
        Point::biased_hash(o.key().compress().to_bytes()).into();
    Point::from(input_key * hp).compress().to_bytes()
}

/// Sanity check for spend-key correctness: returns true iff (spend_key + key_offset)·G
/// equals the output's one-time public key. If this is false, the private spend key
/// (or its conversion) is wrong, so the computed key image can't match the chain.
pub fn output_key_image_sane(spend_key: &Scalar, o: &WalletOutput) -> bool {
    let spend_dalek: curve25519_dalek::Scalar = (*spend_key).into();
    let offset_dalek: curve25519_dalek::Scalar = o.key_offset().into();
    let x = spend_dalek + offset_dalek;
    let xg = Point::from(&x * ED25519_BASEPOINT_POINT);
    xg.compress().to_bytes() == o.key().compress().to_bytes()
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
    // Next unused subaddress MINOR index per account (major account index → next minor).
    // Minor 0 is the account's base address; created subaddresses start at 1. Account 0
    // always present. Replaces the old single account-0 counter.
    subaddress_next: std::collections::HashMap<u32, u32>,
    subaddress_labels: Vec<(u32, u32, String)>, // (account, index, label)

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
    /// Optimistic change credit per outgoing txid (atomic). After a send, the
    /// change returns to us but isn't scanned until the tx is mined, so we credit
    /// it here (counted in the TOTAL, as locked) until the real output is scanned —
    /// at which point add_outputs prunes the entry. In-memory only (not persisted).
    pending_change: HashMap<String, u64>,
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
                subaddress_next: std::collections::HashMap::from([(0u32, 1u32)]),
                subaddress_labels: vec![],
                scanned_outputs: vec![],
                spent: HashSet::new(),
                frozen: HashSet::new(),
                sent: vec![],
                pending_spends: HashMap::new(),
                pending_change: HashMap::new(),
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

        let addr_str = primary_address.to_string();
        log::info!("Primary address derived: {}", addr_str);

        // Per-account next-minor counters, seeded from persisted accounts + labels.
        // Every account starts at minor 1 (minor 0 is the base address); persisted
        // subaddress labels raise the counter for their account.
        let mut subaddress_next: std::collections::HashMap<u32, u32> =
            std::collections::HashMap::from([(0u32, 1u32)]);
        for a in &wallet_data.accounts {
            subaddress_next.entry(a.index).or_insert(1);
        }
        for s in &wallet_data.subaddress_labels {
            let e = subaddress_next.entry(s.account).or_insert(1);
            if s.index + 1 > *e {
                *e = s.index + 1;
            }
        }

        // Register subaddresses for EVERY account so funds to any of them are detected.
        // Account 0's base is the legacy main address (auto-scanned); account>0's base is
        // subaddress (N,0), which MUST be registered explicitly. Cover persisted indices
        // plus a lookahead window per account so freshly-created (receive / churn /
        // splinter / vanish) subaddresses — and funds already sent to them — are scanned
        // even before their label is persisted.
        const SUBADDRESS_LOOKAHEAD: u32 = 50;
        for (&account, &next) in &subaddress_next {
            let cover = next.saturating_sub(1).max(SUBADDRESS_LOOKAHEAD);
            let start = if account == 0 { 1 } else { 0 };
            for i in start..=cover {
                if let Some(idx) = monero_address::SubaddressIndex::new(account, i) {
                    scanner.register_subaddress(idx);
                }
            }
        }

        // Set up accounts from saved labels; account 0 = legacy main address, account>0
        // base = subaddress (N,0). Guarantee account 0 is always present.
        let mut accounts: Vec<MoneroAccount> = wallet_data.accounts.iter().map(|a| {
            let base_address = if a.index == 0 {
                addr_str.clone()
            } else {
                monero_address::SubaddressIndex::new(a.index, 0)
                    .map(|idx| view_pair.subaddress(network, idx).to_string())
                    .unwrap_or_default()
            };
            MoneroAccount {
                index: a.index,
                label: a.label.clone(),
                balance: "0".to_string(),
                unlocked_balance: "0".to_string(),
                base_address,
            }
        }).collect();
        if !accounts.iter().any(|a| a.index == 0) {
            accounts.insert(0, MoneroAccount {
                index: 0,
                label: "Primary".to_string(),
                balance: "0".to_string(),
                unlocked_balance: "0".to_string(),
                base_address: addr_str.clone(),
            });
        }

        // Restore subaddress labels as (account, index, label).
        let subaddress_labels: Vec<(u32, u32, String)> = wallet_data.subaddress_labels.iter()
            .map(|s| (s.account, s.index, s.label.clone()))
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
        inner.subaddress_next = subaddress_next;
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
        inner.pending_change.clear();

        // Load cached outputs (avoids full rescan on relaunch)
        let cache = storage::load_output_cache(&inner.data_dir, identity_id);
        if !cache.outputs.is_empty() {
            log::info!("Loaded {} cached outputs from disk", cache.outputs.len());
            // Restore WalletOutputs (+ their block height) from serialized cache
            for cached in &cache.outputs {
                if let Ok(output) = monero_wallet::WalletOutput::read(&mut cached.data.as_slice()) {
                    inner.scanned_outputs.push(OwnedOutput { output, height: cached.height, timestamp: cached.timestamp });
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

        log::info!("Wallet unlocked for identity: {} (resume from height {}, {} accounts, {} cached outputs)",
            identity_id, inner.scan_height, inner.accounts.len(), inner.scanned_outputs.len());
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
                    subaddress_labels: inner.subaddress_labels.iter().map(|(account, idx, label)| {
                        storage::SubaddressLabel { account: *account, index: *idx, label: label.clone() }
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
    pub async fn add_outputs(&self, outputs: Vec<WalletOutput>, height: u64, timestamp: u64, generation: u64) {
        let mut inner = self.inner.write().await;
        if self.scanner_generation.load(Ordering::SeqCst) != generation {
            return;
        }
        // Dedupe by output id (txid:index). Re-scanning a block (e.g. a re-race or a
        // restart overlapping the same range) would otherwise add the same output
        // twice and inflate the balance. output_id is unique per real output.
        let mut existing: HashSet<String> =
            inner.scanned_outputs.iter().map(|o| output_id(&o.output)).collect();
        for output in outputs {
            let id = output_id(&output);
            if existing.insert(id) {
                // The real change output just arrived — drop its optimistic credit
                // so the balance isn't double-counted (now counted via this output).
                inner.pending_change.remove(&hex::encode(output.transaction()));
                inner.scanned_outputs.push(OwnedOutput { output, height, timestamp });
            }
        }
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
    /// Outputs that can be used as transaction inputs RIGHT NOW: unspent, unfrozen,
    /// AND unlocked (past the 10-block coinbase/standard lock + any explicit
    /// timelock). `tip` is the current chain height. Excluding immature outputs is
    /// essential — spending one (e.g. freshly-returned change) yields a tx the
    /// daemon rejects.
    pub async fn get_spendable_outputs(&self, tip: u64) -> Vec<WalletOutput> {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let inner = self.inner.read().await;
        inner
            .scanned_outputs
            .iter()
            .filter(|o| {
                let id = output_id(&o.output);
                if inner.spent.contains(&id) || inner.frozen.contains(&id) {
                    return false;
                }
                let mature = tip >= o.height.saturating_add(10);
                let timelock_ok = match o.output.additional_timelock() {
                    monero_oxide::transaction::Timelock::None => true,
                    monero_oxide::transaction::Timelock::Block(b) => (tip as usize) >= b,
                    monero_oxide::transaction::Timelock::Time(t) => now >= t,
                };
                mature && timelock_ok
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

    /// Drop a staged spend WITHOUT committing — e.g. the user cancelled at the native
    /// confirmation. Its inputs (never broadcast) return to the spendable balance
    /// immediately instead of reading as spent until the next lock/rescan.
    pub async fn discard_pending_spend(&self, meta_key: &str) {
        self.inner.write().await.pending_spends.remove(meta_key);
    }

    /// Commit a staged spend after a successful broadcast: mark its inputs spent,
    /// finalize the sent-log entry (tx_hash/height/timestamp), and persist. If no
    /// staged spend is found (e.g. app restarted mid-flow), a rescan reconciles.
    pub async fn commit_spend(&self, meta_key: &str, tx_hash: String, height: u64, timestamp: u64) {
        {
            let mut inner = self.inner.write().await;
            if let Some((ids, mut sent)) = inner.pending_spends.remove(meta_key) {
                // Derive the change = (sum of spent inputs) − sent − fee, BEFORE
                // marking the inputs spent (they're still resident). Credit it
                // optimistically as locked balance so the total doesn't visibly dip
                // by the full input until the change output is mined + scanned.
                let id_set: HashSet<String> = ids.iter().cloned().collect();
                let spent_sum: u64 = inner
                    .scanned_outputs
                    .iter()
                    .filter(|o| id_set.contains(&output_id(&o.output)))
                    .map(|o| o.output.commitment().amount)
                    .sum();
                // Guard against the (rare) race where the change output is already
                // scanned — don't double-credit; add_outputs would have pruned it.
                let already_scanned = inner
                    .scanned_outputs
                    .iter()
                    .any(|o| hex::encode(o.output.transaction()) == tx_hash);
                let change = spent_sum.saturating_sub(sent.amount).saturating_sub(sent.fee);

                // Destinations that are OUR OWN addresses (splinter shatters the
                // balance into fragments on our own subaddresses; also a send-to-self)
                // return to us too — credit them optimistically, not just the change,
                // so the balance doesn't read ~0 between broadcast and the next scan.
                let own = own_address_strings(&inner);
                let self_dest_total: u64 = sent
                    .destinations
                    .iter()
                    .filter(|(addr, _)| own.contains(addr))
                    .map(|(_, amt)| *amt)
                    .sum();
                let credit = change.saturating_add(self_dest_total);

                for id in ids {
                    inner.spent.insert(id);
                }
                if credit > 0 && !already_scanned {
                    inner.pending_change.insert(tx_hash.clone(), credit);
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
    /// its inputs up-front). Records the sent entry and persists. When `credit_self`
    /// (the sweep destination is one of OUR OWN addresses — churn / vanish), the swept
    /// `amount` is credited optimistically as locked balance, keyed by tx_hash and
    /// pruned in add_outputs once the real output is scanned. Without this a churn
    /// drops the balance to ~0 between broadcast and the next scan — which reads as
    /// "funds lost" to the user even though they're in-flight to their own address.
    pub async fn mark_spent(&self, ids: Vec<String>, sent: storage::SentTx, credit_self: bool) {
        {
            let mut inner = self.inner.write().await;
            for id in ids {
                inner.spent.insert(id);
            }
            if credit_self && sent.amount > 0 {
                // Guard the (rare) race where the swept output is already scanned —
                // don't double-credit; add_outputs would have pruned it.
                let already_scanned = inner
                    .scanned_outputs
                    .iter()
                    .any(|o| hex::encode(o.output.transaction()) == sent.tx_hash);
                if !already_scanned {
                    inner.pending_change.insert(sent.tx_hash.clone(), sent.amount);
                }
            }
            inner.sent.push(sent);
        }
        self.save_output_cache().await;
    }

    /// Whether `addr` is one of THIS wallet's addresses (primary or any derived
    /// subaddress of any account) — i.e. a sweep to it returns the funds to us, so the
    /// swept amount should be credited optimistically rather than shown as gone.
    pub async fn is_own_address(&self, addr: &MoneroAddress) -> bool {
        let inner = self.inner.read().await;
        own_address_strings(&inner).contains(&addr.to_string())
    }

    /// Detect spent outputs by matching their key images against a set of input
    /// key images observed on-chain (collected from scanned blocks' transaction
    /// inputs). Marks any owned output whose key image appears as spent. Requires
    /// the private spend key; a view-only wallet returns 0 (can't compute key
    /// images, so can't detect spends). Returns the number newly marked spent.
    pub async fn mark_spent_by_inputs(&self, input_key_images: &HashSet<[u8; 32]>) -> usize {
        if input_key_images.is_empty() {
            return 0;
        }
        let mut inner = self.inner.write().await;
        let Some(spend_key) = inner.spend_key.clone() else {
            return 0;
        };
        let mut newly_spent = Vec::new();
        for o in &inner.scanned_outputs {
            let id = output_id(&o.output);
            if inner.spent.contains(&id) {
                continue;
            }
            if input_key_images.contains(&output_key_image(&spend_key, &o.output)) {
                newly_spent.push(id);
            }
        }
        let count = newly_spent.len();
        for id in newly_spent {
            inner.spent.insert(id);
        }
        count
    }

    /// Whether spend detection is possible (the private spend key is loaded).
    /// View-only / locked wallets return false.
    pub async fn can_detect_spends(&self) -> bool {
        self.inner.read().await.spend_key.is_some()
    }

    /// Detect spends from a batch and record them as outgoing ledger entries.
    /// `ki_to_tx` maps each on-chain input key image to (spending txid, height).
    /// For every owned output whose key image appears, the output is marked spent
    /// and — grouped by spending tx — an outgoing `SentTx` is recorded so the ledger
    /// shows withdrawals (incl. those made in other wallets). The recorded amount is
    /// net of change received in the same tx. Dedupes against existing sent entries
    /// (e.g. our own broadcasts). Returns the number of outputs newly marked spent.
    pub async fn detect_and_record_spends(
        &self,
        ki_to_tx: &HashMap<[u8; 32], ([u8; 32], u64)>,
        tip: u64,
    ) -> usize {
        if ki_to_tx.is_empty() {
            return 0;
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let mut inner = self.inner.write().await;
        let Some(sk) = inner.spend_key.clone() else {
            return 0;
        };

        // Group spent owned outputs by their spending tx: txid -> (gross, ids, height).
        // NOTE: we do NOT skip outputs already in `spent`. The tip reconcile
        // (is_key_image_spent) marks inputs spent as soon as a tx hits the mempool —
        // before its block is scanned — but it can't record an outgoing ledger entry
        // (it only learns spent/unspent, not the txid). So a spend made in ANOTHER
        // client would drop the balance but never show as DISPATCHED. Recording here
        // regardless (deduped by txid via `existing`) closes that gap.
        let mut by_tx: HashMap<[u8; 32], (u64, Vec<String>, u64)> = HashMap::new();
        for o in &inner.scanned_outputs {
            let id = output_id(&o.output);
            if let Some((txid, height)) = ki_to_tx.get(&output_key_image(&sk, &o.output)) {
                let e = by_tx.entry(*txid).or_insert((0, Vec::new(), *height));
                e.0 = e.0.saturating_add(o.output.commitment().amount);
                e.1.push(id);
            }
        }
        if by_tx.is_empty() {
            return 0;
        }

        // Sum of our outputs received in each tx (change), to net the sent amount.
        let mut received_by_tx: HashMap<String, u64> = HashMap::new();
        for o in &inner.scanned_outputs {
            let txh = hex::encode(o.output.transaction());
            *received_by_tx.entry(txh).or_insert(0) += o.output.commitment().amount;
        }

        let existing: HashSet<String> = inner.sent.iter().map(|s| s.tx_hash.clone()).collect();
        let mut to_mark: Vec<String> = Vec::new();
        let mut to_record: Vec<storage::SentTx> = Vec::new();
        for (txid, (gross, ids, height)) in by_tx {
            let txid_hex = hex::encode(txid);
            let change = received_by_tx.get(&txid_hex).copied().unwrap_or(0);
            let net = gross.saturating_sub(change);
            let timestamp = now.saturating_sub(tip.saturating_sub(height).saturating_mul(120));
            to_mark.extend(ids);
            if !existing.contains(&txid_hex) {
                to_record.push(storage::SentTx {
                    tx_hash: txid_hex,
                    amount: net,
                    fee: 0,
                    destinations: Vec::new(),
                    height,
                    timestamp,
                    tx_key: String::new(),
                });
            }
        }

        let mut newly = 0;
        for id in to_mark {
            if inner.spent.insert(id) {
                newly += 1;
            }
        }
        let recorded = to_record.len();
        for s in to_record {
            inner.sent.push(s);
        }
        // Report nonzero when we recorded a new outgoing entry even if nothing was
        // newly-marked-spent (the reconcile-pre-marked case) — so the scanner still
        // emits the balance + persists the sent log.
        newly.max(recorded)
    }

    /// (output_id, key_image_hex) for every currently-unspent owned output.
    /// Empty if there's no spend key (view-only). Used to ask the daemon which
    /// outputs are spent via `is_key_image_spent`.
    pub async fn unspent_key_images(&self) -> Vec<(String, String)> {
        let inner = self.inner.read().await;
        let Some(sk) = inner.spend_key.as_ref() else {
            return Vec::new();
        };
        inner
            .scanned_outputs
            .iter()
            .filter(|o| !inner.spent.contains(&output_id(&o.output)))
            .map(|o| (output_id(&o.output), hex::encode(output_key_image(sk, &o.output))))
            .collect()
    }

    /// Mark the given output ids spent (from daemon reconciliation). Returns how
    /// many were newly inserted.
    pub async fn mark_ids_spent(&self, ids: &[String]) -> usize {
        let mut inner = self.inner.write().await;
        let mut n = 0;
        for id in ids {
            if inner.spent.insert(id.clone()) {
                n += 1;
            }
        }
        n
    }

    /// Diagnostic: for the first owned output, report whether the spend key derives
    /// the output key (x·G == P) plus a sample key image. Returns None if there's no
    /// spend key or no owned outputs yet.
    pub async fn first_output_kidiag(&self) -> Option<String> {
        let inner = self.inner.read().await;
        let spend_key = inner.spend_key.as_ref()?;
        let o = inner.scanned_outputs.first()?;
        let ki = output_key_image(spend_key, &o.output);
        let sane = output_key_image_sane(spend_key, &o.output);
        Some(format!(
            "owned={} sanity(xG==P)={} sample_ki={} sample_P={}",
            inner.scanned_outputs.len(),
            sane,
            hex::encode(ki),
            hex::encode(o.output.key().compress().to_bytes()),
        ))
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
        inner.pending_change.clear();
        inner.sync_status.status = "SYNCING".to_string();
        inner.sync_status.height = from_height;
        inner.sync_status.sync_percent = 0.0;
    }

    /// Derive the primary (legacy) address.
    pub async fn get_primary_address(&self) -> Option<String> {
        let inner = self.inner.read().await;
        inner.view_pair.as_ref().map(|vp| vp.legacy_address(inner.network).to_string())
    }

    /// Create a new subaddress under `account_index` and register it with the scanner.
    /// Persists so it survives relaunch (else funds sent to it would be untracked).
    pub async fn create_subaddress(&self, account_index: u32, label: &str) -> Result<SubaddressInfo, String> {
        if label.chars().count() > MAX_LABEL_CHARS {
            return Err("Label too long".to_string());
        }
        let mut inner = self.inner.write().await;
        let net = inner.network;

        let view_pair = inner.view_pair.as_ref().ok_or("Wallet is locked")?;
        let idx = *inner.subaddress_next.get(&account_index).unwrap_or(&1);

        let sub_idx = monero_address::SubaddressIndex::new(account_index, idx)
            .ok_or("Invalid subaddress index")?;
        let address = view_pair.subaddress(net, sub_idx);

        // Persist FIRST (with the new label staged), and only register with the scanner
        // once disk agrees — otherwise a persist failure would leave in-memory ahead of
        // disk and, after restart, funds to this subaddress could go undetected.
        inner.subaddress_labels.push((account_index, idx, label.to_string()));
        inner.subaddress_next.insert(account_index, idx + 1);
        if let Err(e) = persist_meta(&inner) {
            inner.subaddress_labels.pop();
            inner.subaddress_next.insert(account_index, idx);
            return Err(format!("Could not save subaddress: {}", e));
        }
        if let Some(scanner) = inner.scanner.as_mut() {
            scanner.register_subaddress(sub_idx);
        }

        Ok(SubaddressInfo {
            index: idx,
            address: address.to_string(),
            label: label.to_string(),
            balance: "0".to_string(),
            unlocked_balance: "0".to_string(),
            is_used: false,
        })
    }

    /// Create a new account (next major index) and register its base subaddress (N,0)
    /// with the scanner so funds to it are detected. Persists. Returns the new account.
    pub async fn create_account(&self, label: &str) -> Result<MoneroAccount, String> {
        if label.chars().count() > MAX_LABEL_CHARS {
            return Err("Label too long".to_string());
        }
        let mut inner = self.inner.write().await;
        let net = inner.network;

        let view_pair = inner.view_pair.as_ref().ok_or("Wallet is locked")?;
        // Accounts are append-only in Monero; the next index is one past the highest.
        // .max(1) so we can never collide with the always-present account 0.
        let new_index = inner
            .accounts
            .iter()
            .map(|a| a.index)
            .max()
            .map(|m| m + 1)
            .unwrap_or(1)
            .max(1);
        let base_idx = monero_address::SubaddressIndex::new(new_index, 0)
            .ok_or("Invalid account index")?;
        let base_address = view_pair.subaddress(net, base_idx).to_string();

        let account = MoneroAccount {
            index: new_index,
            label: label.to_string(),
            balance: "0".to_string(),
            unlocked_balance: "0".to_string(),
            base_address,
        };
        // Persist FIRST; only register the account's base subaddress with the scanner once
        // disk agrees (else a persist failure could hide funds sent to it after restart).
        inner.accounts.push(account.clone());
        inner.subaddress_next.entry(new_index).or_insert(1);
        if let Err(e) = persist_meta(&inner) {
            inner.accounts.pop();
            inner.subaddress_next.remove(&new_index);
            return Err(format!("Could not save account: {}", e));
        }
        if let Some(scanner) = inner.scanner.as_mut() {
            scanner.register_subaddress(base_idx);
        }
        Ok(account)
    }

    /// Rename an existing account and persist (rolling back the rename if persist fails).
    pub async fn rename_account(&self, index: u32, label: &str) -> Result<(), String> {
        if label.chars().count() > MAX_LABEL_CHARS {
            return Err("Label too long".to_string());
        }
        let mut inner = self.inner.write().await;
        let pos = inner
            .accounts
            .iter()
            .position(|a| a.index == index)
            .ok_or("Account not found")?;
        let previous = inner.accounts[pos].label.clone();
        inner.accounts[pos].label = label.to_string();
        if let Err(e) = persist_meta(&inner) {
            inner.accounts[pos].label = previous;
            return Err(format!("Could not save account: {}", e));
        }
        Ok(())
    }

    /// Get all subaddresses of `account_index` (base address at minor 0 + derived),
    /// each with its unspent balance so the Addresses tab shows where funds live.
    pub async fn get_subaddresses(&self, account_index: u32, tip: u64) -> Vec<SubaddressInfo> {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let inner = self.inner.read().await;
        let view_pair = match inner.view_pair.as_ref() {
            Some(vp) => vp,
            None => return vec![],
        };
        let net = inner.network;

        // Sum unspent outputs per minor index WITHIN this account. Mirrors balances() for
        // the unlocked figure (skip frozen, require the 10-block lock + any timelock).
        // Outputs with no subaddress attribute to account 0 / minor 0.
        let mut totals: std::collections::HashMap<u32, (u64, u64)> = std::collections::HashMap::new();
        for o in &inner.scanned_outputs {
            let id = output_id(&o.output);
            if inner.spent.contains(&id) {
                continue;
            }
            let (acct, minor) = match o.output.subaddress() {
                Some(s) => (s.account() as u32, s.address() as u32),
                None => (0, 0),
            };
            if acct != account_index {
                continue;
            }
            let amt = o.output.commitment().amount;
            let entry = totals.entry(minor).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(amt);
            let mature = tip >= o.height.saturating_add(10);
            let timelock_ok = match o.output.additional_timelock() {
                monero_oxide::transaction::Timelock::None => true,
                monero_oxide::transaction::Timelock::Block(b) => (tip as usize) >= b,
                monero_oxide::transaction::Timelock::Time(t) => now >= t,
            };
            if !inner.frozen.contains(&id) && mature && timelock_ok {
                entry.1 = entry.1.saturating_add(amt);
            }
        }

        let mut result = vec![];

        // Minor 0 = the account's base address (legacy main for account 0; subaddress
        // (N,0) otherwise).
        let base_address = if account_index == 0 {
            view_pair.legacy_address(net).to_string()
        } else {
            match monero_address::SubaddressIndex::new(account_index, 0) {
                Some(idx) => view_pair.subaddress(net, idx).to_string(),
                None => return result,
            }
        };
        let (b0, u0) = totals.get(&0u32).copied().unwrap_or((0, 0));
        result.push(SubaddressInfo {
            index: 0,
            address: base_address,
            label: if account_index == 0 { "Primary".to_string() } else { "Base".to_string() },
            balance: b0.to_string(),
            unlocked_balance: u0.to_string(),
            is_used: true,
        });

        // Derived subaddresses of this account.
        let next = *inner.subaddress_next.get(&account_index).unwrap_or(&1);
        for i in 1..next {
            if let Some(sub_idx) = monero_address::SubaddressIndex::new(account_index, i) {
                let address = view_pair.subaddress(net, sub_idx);
                let label = inner.subaddress_labels.iter()
                    .find(|(a, idx, _)| *a == account_index && *idx == i)
                    .map(|(_, _, l)| l.clone())
                    .unwrap_or_else(|| format!("Subaddress #{}", i));

                let (b, u) = totals.get(&i).copied().unwrap_or((0, 0));
                result.push(SubaddressInfo {
                    index: i,
                    address: address.to_string(),
                    label,
                    balance: b.to_string(),
                    unlocked_balance: u.to_string(),
                    is_used: b > 0,
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
                    timestamp: o.timestamp,
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

    pub async fn set_subaddress_label(&self, account: u32, index: u32, label: &str) {
        let mut inner = self.inner.write().await;
        if let Some(entry) = inner.subaddress_labels.iter_mut().find(|(a, idx, _)| *a == account && *idx == index) {
            entry.2 = label.to_string();
        } else {
            inner.subaddress_labels.push((account, index, label.to_string()));
        }
        // A label is cosmetic and re-editable, so best-effort persistence is fine here
        // (unlike the irreversible create_* ops, which roll back on persist failure).
        if let Err(e) = persist_meta(&inner) {
            log::warn!("Failed to persist subaddress label: {}", e);
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
        // Add optimistically-credited change (from sends whose change output isn't
        // scanned yet). It's locked, so it counts toward TOTAL but not unlocked.
        let pending: u64 = inner.pending_change.values().sum();
        (total.saturating_add(pending), unlocked)
    }

    /// (total, unlocked) atomic balances for a SINGLE account — same rules as `balances`,
    /// restricted to outputs whose subaddress major index is `account_index` (outputs
    /// with no subaddress attribute to account 0). Optimistic pending change is credited
    /// to account 0, where sends / churn / splinter operate. The sum over all accounts
    /// equals the wallet-wide `balances`, so no funds are lost or double-counted.
    pub async fn balances_for_account(&self, account_index: u32, tip: u64) -> (u64, u64) {
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let inner = self.inner.read().await;
        let mut total = 0u64;
        let mut unlocked = 0u64;
        for o in &inner.scanned_outputs {
            let acct = o.output.subaddress().map(|s| s.account() as u32).unwrap_or(0);
            if acct != account_index {
                continue;
            }
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
        if account_index == 0 {
            let pending: u64 = inner.pending_change.values().sum();
            total = total.saturating_add(pending);
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
