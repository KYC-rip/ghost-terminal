//! Encrypted wallet file storage.
//!
//! Wallet files are encrypted with ChaCha20-Poly1305 using a key derived
//! from the user's password via Argon2id.
//!
//! Format: { salt: [u8;16], nonce: [u8;12], ciphertext: Vec<u8> }
//! Plaintext is JSON: { seed_entropy: hex, scan_height: u64, accounts: [...], ... }

use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

/// Plaintext wallet data that gets encrypted.
#[derive(Serialize, Deserialize)]
pub struct WalletFileData {
    /// Hex-encoded 32-byte seed entropy (the secret)
    pub seed_entropy: String,
    /// Last scanned blockchain height (for fast resume)
    pub scan_height: u64,
    /// Account labels
    pub accounts: Vec<AccountLabel>,
    /// Subaddress labels
    pub subaddress_labels: Vec<SubaddressLabel>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AccountLabel {
    pub index: u32,
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SubaddressLabel {
    pub account: u32,
    pub index: u32,
    pub label: String,
}

/// Derive an encryption key from password using Argon2id.
fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .expect("Argon2 should not fail with valid parameters");
    key
}

/// Encrypt wallet data with a password.
pub fn encrypt_wallet(data: &WalletFileData, password: &str) -> Vec<u8> {
    let plaintext = serde_json::to_vec(data).expect("WalletFileData should serialize");

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .expect("encryption should not fail");

    // Output: salt || nonce || ciphertext
    let mut output = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// Decrypt wallet data with a password.
pub fn decrypt_wallet(encrypted: &[u8], password: &str) -> Result<WalletFileData, String> {
    if encrypted.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err("Wallet file too short".into());
    }

    let salt: [u8; SALT_LEN] = encrypted[..SALT_LEN].try_into().unwrap();
    let nonce_bytes: [u8; NONCE_LEN] = encrypted[SALT_LEN..SALT_LEN + NONCE_LEN]
        .try_into()
        .unwrap();
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Invalid password or corrupted wallet file".to_string())?;

    serde_json::from_slice(&plaintext).map_err(|e| format!("Wallet data corrupted: {}", e))
}

/// Charset guard for a renderer-supplied identity id that becomes a filesystem
/// path component (`wallets/{id}.vault` / `.cache`). A hostile renderer could
/// otherwise pass `../…` (or an absolute path) to read, delete, or probe files
/// OUTSIDE the wallets dir. Mirrors the VigilHandler id charset: non-empty,
/// <= 64 chars, `[A-Za-z0-9_-]` only — which by construction contains no `/`,
/// `\`, or `.`, so no traversal is expressible. This is the single choke point
/// every `.vault`/`.cache` path flows through; `delete_identity` validates
/// separately because it builds its paths inline.
pub fn valid_identity_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Get the wallet file path for an identity. Rejects ids that aren't a safe path
/// component (see `valid_identity_id`) so a hostile id can't escape the wallets dir.
pub fn wallet_path(data_dir: &Path, identity_id: &str) -> Result<PathBuf, String> {
    if !valid_identity_id(identity_id) {
        return Err("Invalid identity id".into());
    }
    Ok(data_dir
        .join("wallets")
        .join(format!("{}.vault", identity_id)))
}

/// Save encrypted wallet to disk.
pub fn save_wallet(
    data_dir: &Path,
    identity_id: &str,
    data: &WalletFileData,
    password: &str,
) -> Result<(), String> {
    let path = wallet_path(data_dir, identity_id)?;
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create wallet dir: {}", e))?;

    let encrypted = encrypt_wallet(data, password);
    // Write to a temp file then atomically rename over the target. A plain write
    // could be interrupted (crash / power loss) mid-flush and leave a truncated,
    // undecryptable vault — destroying the seed. This matters most for a password
    // CHANGE, whose re-encryption is the only write that overwrites an existing
    // vault under a different key; rename is atomic on the same filesystem, so the
    // old vault survives intact until the new one is fully written.
    let tmp = path.with_extension("vault.tmp");
    std::fs::write(&tmp, &encrypted).map_err(|e| format!("Failed to write wallet file: {}", e))?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        // Don't leave the half-written temp behind if the commit rename fails.
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to commit wallet file: {}", e));
    }

    log::info!("Wallet saved: {}", path.display());
    Ok(())
}

/// Load and decrypt wallet from disk.
pub fn load_wallet(
    data_dir: &Path,
    identity_id: &str,
    password: &str,
) -> Result<WalletFileData, String> {
    let path = wallet_path(data_dir, identity_id)?;
    let encrypted =
        std::fs::read(&path).map_err(|e| format!("Failed to read wallet file: {}", e))?;

    decrypt_wallet(&encrypted, password)
}

/// Check if a wallet file exists for an identity.
pub fn wallet_exists(data_dir: &Path, identity_id: &str) -> bool {
    wallet_path(data_dir, identity_id)
        .map(|p| p.exists())
        .unwrap_or(false)
}

// ── Output Cache (separate from encrypted wallet) ──
// Outputs are serialized versions of WalletOutput. They don't contain
// the seed, so they're encrypted with a key derived from the view key
// (which is already in memory when unlocked). This avoids re-encrypting
// the master seed on every scan batch.

/// Serialized output for persistence.
#[derive(Serialize, Deserialize, Clone)]
pub struct CachedOutput {
    /// Serialized WalletOutput bytes (monero-wallet's own format)
    pub data: Vec<u8>,
    /// Amount in atomic units (for quick balance computation without deserializing)
    pub amount: u64,
    /// Transaction hash
    pub tx_hash: String,
    /// Output index in transaction
    pub tx_index: u64,
    /// Subaddress index (None = primary)
    pub subaddress: Option<u32>,
    /// Block height the output was received at. Defaults to 0 for v1 caches
    /// written before height tracking — affects only display/confirmations.
    #[serde(default)]
    pub height: u64,
    /// The real block header timestamp (Unix seconds) of the block this output was
    /// mined in. Defaults to 0 for caches written before timestamp tracking; the ledger
    /// falls back to a height estimate in that case. Stable regardless of sync progress.
    #[serde(default)]
    pub timestamp: u64,
}

/// A transaction we broadcast (for "out"/"pending" history — received "in"
/// history is reconstructed from owned outputs).
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SentTx {
    pub tx_hash: String,
    pub amount: u64,
    pub fee: u64,
    pub destinations: Vec<(String, u64)>,
    pub height: u64,
    pub timestamp: u64,
    /// Transaction secret key (hex) for proof-of-payment export (get_tx_key).
    /// Only the main key — correct for single standard-address sends + sweeps.
    #[serde(default)]
    pub tx_key: String,
    /// Source account (major index) this send was spent from. Lets the ledger show
    /// outgoing txs under the right account. Defaults to 0 for pre-existing records
    /// and chain-reconciled sends where the source account can't be recovered.
    #[serde(default)]
    pub account: u32,
}

#[derive(Serialize, Deserialize, Default)]
pub struct OutputCache {
    pub scan_height: u64,
    pub outputs: Vec<CachedOutput>,
    /// Spent output ids ("hextxid:index_in_transaction"). Excluded from balance,
    /// coin control, and input selection until a rescan reconfirms.
    #[serde(default)]
    pub spent: Vec<String>,
    /// Frozen output ids (coin control). Persisted across sessions.
    #[serde(default)]
    pub frozen: Vec<String>,
    /// Broadcast transactions, for outgoing history.
    #[serde(default)]
    pub sent: Vec<SentTx>,
}

fn output_cache_path(data_dir: &Path, identity_id: &str) -> Result<PathBuf, String> {
    if !valid_identity_id(identity_id) {
        return Err("Invalid identity id".into());
    }
    Ok(data_dir
        .join("wallets")
        .join(format!("{}.cache", identity_id)))
}

// ── Device-key sealed container (watch tier) ────────────────────────────────
// Format: b"RIPC1" magic + 12B nonce + ChaCha20-Poly1305 ciphertext. The key is
// a high-entropy HKDF subkey of the keychain device key (see wallet::device_key),
// so no password KDF is involved — this protects data at rest from disk readers,
// not from someone who controls the unlocked OS session.

const SEAL_MAGIC: &[u8; 5] = b"RIPC1";

fn seal(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(&nonce.into(), plaintext)
        .expect("ChaCha20Poly1305 encrypt");
    let mut out = Vec::with_capacity(SEAL_MAGIC.len() + NONCE_LEN + ct.len());
    out.extend_from_slice(SEAL_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open_sealed(key: &[u8; KEY_LEN], data: &[u8]) -> Option<Vec<u8>> {
    let body = data.strip_prefix(SEAL_MAGIC.as_slice())?;
    if body.len() < NONCE_LEN {
        return None;
    }
    let (nonce, ct) = body.split_at(NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher.decrypt(nonce.into(), ct).ok()
}

fn is_sealed(data: &[u8]) -> bool {
    data.starts_with(SEAL_MAGIC)
}

/// Atomic temp-then-rename write, so an interrupted write can't leave a
/// truncated file (which loaders would discard, forcing a full rescan).
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create dir: {}", e))?;
    // APPEND .tmp (don't replace the extension): "<id>.cache" and "<id>.watch"
    // must not collide on the same "<id>.tmp" when written concurrently.
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(".tmp");
    let tmp = path.with_file_name(tmp_name);
    std::fs::write(&tmp, data).map_err(|e| format!("Failed to write: {}", e))?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to commit: {}", e));
    }
    Ok(())
}

/// Save output cache to disk — sealed with the device cache key when available.
/// Without a device key (keychain unavailable) this degrades to the legacy
/// plaintext write: no worse than the historical behavior, and the cache holds
/// no key material (it IS full financial history though — hence the seal).
pub fn save_output_cache(
    data_dir: &Path,
    identity_id: &str,
    cache: &OutputCache,
) -> Result<(), String> {
    let path = output_cache_path(data_dir, identity_id)?;
    let data =
        serde_json::to_vec(cache).map_err(|e| format!("Failed to serialize cache: {}", e))?;
    let body = match super::device_key::cache_key() {
        Some(k) => seal(&k, &data),
        None => data,
    };
    atomic_write(&path, &body)
}

/// Load output cache from disk. Handles both formats: sealed (magic-sniffed,
/// decrypt failure → empty cache → rescan; never a crash) and legacy plaintext
/// JSON — which is transparently re-saved sealed when a device key is available
/// (atomic + idempotent: once sealed, the magic sniff skips this path forever).
pub fn load_output_cache(data_dir: &Path, identity_id: &str) -> OutputCache {
    let Ok(path) = output_cache_path(data_dir, identity_id) else {
        return OutputCache::default();
    };
    let Ok(data) = std::fs::read(&path) else {
        return OutputCache::default();
    };
    if is_sealed(&data) {
        let Some(k) = super::device_key::cache_key() else {
            log::warn!("output cache for {identity_id} is sealed but the device key is unavailable — starting empty (rescan)");
            return OutputCache::default();
        };
        return open_sealed(&k, &data)
            .and_then(|pt| serde_json::from_slice(&pt).ok())
            .unwrap_or_else(|| {
                log::warn!("output cache for {identity_id} failed to unseal (device key changed?) — starting empty (rescan)");
                OutputCache::default()
            });
    }
    // Legacy plaintext cache: parse, then migrate to sealed on a best-effort
    // basis (only after a successful parse — never rewrite garbage).
    let cache: OutputCache = match serde_json::from_slice(&data) {
        Ok(c) => c,
        Err(_) => return OutputCache::default(),
    };
    if super::device_key::cache_key().is_some() {
        if save_output_cache(data_dir, identity_id, &cache).is_ok() {
            log::info!("output cache for {identity_id} migrated to sealed format");
        }
    }
    cache
}

// ── Watch store: persisted view pairs for boot-time view-only sync ──────────
// wallets/<id>.watch = sealed JSON { v, spend_pub (hex, compressed point),
// view_sec (hex, scalar), created_at }. EXACTLY those fields — the spend
// SECRET and mnemonic never leave the password-encrypted vault (tier model).
// Encrypt-or-don't-write: with no device key these functions refuse — a
// plaintext view key on disk would be a catastrophic regression.

#[derive(Serialize, Deserialize)]
struct WatchFile {
    v: u32,
    spend_pub: String,
    view_sec: String,
    created_at: u64,
}

fn watch_path(data_dir: &Path, identity_id: &str) -> Result<PathBuf, String> {
    if !valid_identity_id(identity_id) {
        return Err("Invalid identity id".into());
    }
    Ok(data_dir
        .join("wallets")
        .join(format!("{}.watch", identity_id)))
}

/// Persist an identity's view pair (watch tier). Refuses without a device key.
pub fn save_watch(
    data_dir: &Path,
    identity_id: &str,
    spend_pub: &[u8; 32],
    view_sec: &Zeroizing<[u8; 32]>,
) -> Result<(), String> {
    let Some(k) = super::device_key::watch_key() else {
        return Err("device key unavailable — refusing to persist a view key unencrypted".into());
    };
    save_watch_with_key(&k, data_dir, identity_id, spend_pub, view_sec)
}

fn save_watch_with_key(
    k: &[u8; KEY_LEN],
    data_dir: &Path,
    identity_id: &str,
    spend_pub: &[u8; 32],
    view_sec: &Zeroizing<[u8; 32]>,
) -> Result<(), String> {
    let path = watch_path(data_dir, identity_id)?;
    // Zeroizing: the serialized payload embeds the view secret (hex) — wipe the
    // heap copy once the sealed bytes are written.
    let payload = Zeroizing::new(
        serde_json::to_vec(&WatchFile {
            v: 1,
            spend_pub: hex::encode(spend_pub),
            view_sec: hex::encode(&view_sec[..]),
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        })
        .map_err(|e| format!("Failed to serialize watch file: {}", e))?,
    );
    atomic_write(&path, &seal(k, &payload))
}

/// Load an identity's persisted view pair. None on any failure (no file, no
/// device key, unseal failure, malformed payload) — callers just skip boot sync.
pub fn load_watch(data_dir: &Path, identity_id: &str) -> Option<monero_wallet::ViewPair> {
    let k = super::device_key::watch_key()?;
    load_watch_with_key(&k, data_dir, identity_id)
}

fn load_watch_with_key(
    k: &[u8; KEY_LEN],
    data_dir: &Path,
    identity_id: &str,
) -> Option<monero_wallet::ViewPair> {
    let path = watch_path(data_dir, identity_id).ok()?;
    let data = std::fs::read(&path).ok()?;
    let pt = Zeroizing::new(open_sealed(k, &data)?);
    let wf: WatchFile = serde_json::from_slice(&pt).ok()?;
    if wf.v != 1 {
        return None;
    }
    let spend_bytes: [u8; 32] = hex::decode(&wf.spend_pub).ok()?.try_into().ok()?;
    let view_bytes: [u8; 32] = hex::decode(&wf.view_sec).ok()?.try_into().ok()?;
    let spend = monero_oxide::ed25519::CompressedPoint::read(&mut &spend_bytes[..])
        .ok()?
        .decompress()?;
    let view_scalar = Option::<curve25519_dalek::Scalar>::from(
        curve25519_dalek::Scalar::from_canonical_bytes(view_bytes),
    )?;
    let view = Zeroizing::new(monero_oxide::ed25519::Scalar::from(view_scalar));
    monero_wallet::ViewPair::new(spend, view).ok()
}

/// Remove an identity's watch file (identity deletion / watch-sync toggle-off).
/// Idempotent — missing file is fine.
pub fn delete_watch(data_dir: &Path, identity_id: &str) {
    if let Ok(path) = watch_path(data_dir, identity_id) {
        let _ = std::fs::remove_file(&path);
    }
}

/// Identity ids that have a persisted watch file (boot-sync candidates).
pub fn list_watch_ids(data_dir: &Path) -> Vec<String> {
    let dir = data_dir.join("wallets");
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return vec![];
    };
    entries
        .filter_map(|e| {
            let name = e.ok()?.file_name().into_string().ok()?;
            let id = name.strip_suffix(".watch")?;
            valid_identity_id(id).then(|| id.to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = WalletFileData {
            seed_entropy: "deadbeef".repeat(4),
            scan_height: 3245000,
            accounts: vec![AccountLabel {
                index: 0,
                label: "Main".into(),
            }],
            subaddress_labels: vec![],
        };

        let encrypted = encrypt_wallet(&data, "test_password");
        let decrypted = decrypt_wallet(&encrypted, "test_password").unwrap();

        assert_eq!(data.seed_entropy, decrypted.seed_entropy);
        assert_eq!(data.scan_height, decrypted.scan_height);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = WalletFileData {
            seed_entropy: "deadbeef".repeat(4),
            scan_height: 0,
            accounts: vec![],
            subaddress_labels: vec![],
        };

        let encrypted = encrypt_wallet(&data, "correct_password");
        let result = decrypt_wallet(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn valid_identity_id_accepts_expected_charset() {
        assert!(valid_identity_id("vault_1720000000000_abc"));
        assert!(valid_identity_id("A-Z_0-9"));
        assert!(valid_identity_id(&"x".repeat(64)));
    }

    #[test]
    fn valid_identity_id_rejects_traversal_and_bad_charset() {
        assert!(!valid_identity_id(""));
        assert!(!valid_identity_id("../secret"));
        assert!(!valid_identity_id("a/b"));
        assert!(!valid_identity_id("a\\b"));
        assert!(!valid_identity_id("has.dot"));
        assert!(!valid_identity_id("/etc/passwd"));
        assert!(!valid_identity_id(&"x".repeat(65)));
    }

    #[test]
    fn wallet_path_rejects_traversal() {
        let dir = Path::new("/tmp/ripley-data");
        assert!(wallet_path(dir, "../../etc/passwd").is_err());
        assert!(output_cache_path(dir, "..").is_err());
        // A well-formed id stays inside the wallets dir.
        let p = wallet_path(dir, "vault_abc").unwrap();
        assert!(p.starts_with(dir.join("wallets")));
    }

    // ── Watch-tier seal/open + watch store invariants ────────────────────────

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("ripley-watch-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn seal_open_roundtrip_and_wrong_key() {
        let k = [7u8; KEY_LEN];
        let sealed = seal(&k, b"watch tier payload");
        assert!(is_sealed(&sealed));
        assert_eq!(
            open_sealed(&k, &sealed).as_deref(),
            Some(&b"watch tier payload"[..])
        );
        // Wrong key → authenticated decrypt refuses (None), never garbage.
        let wrong = [8u8; KEY_LEN];
        assert!(open_sealed(&wrong, &sealed).is_none());
        // Truncated/tampered → None.
        assert!(open_sealed(&k, &sealed[..SEAL_MAGIC.len() + 4]).is_none());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_sealed(&k, &tampered).is_none());
    }

    #[test]
    fn seal_uses_a_fresh_nonce_per_write() {
        let k = [7u8; KEY_LEN];
        // Same key + same plaintext must never produce the same bytes (random
        // nonce per call — the AEAD contract this format relies on).
        assert_ne!(seal(&k, b"same"), seal(&k, b"same"));
    }

    #[test]
    fn legacy_json_is_not_mistaken_for_sealed() {
        assert!(!is_sealed(b"{\"scan_height\":1}"));
        assert!(!is_sealed(b""));
    }

    #[test]
    fn legacy_cache_loads_and_decrypt_failure_degrades_to_default() {
        let dir = tmpdir("cache");
        // Legacy plaintext cache parses (device key absent in tests → no re-seal).
        let legacy = serde_json::to_vec(&OutputCache {
            scan_height: 42,
            ..Default::default()
        })
        .unwrap();
        std::fs::create_dir_all(dir.join("wallets")).unwrap();
        std::fs::write(dir.join("wallets/vault_t.cache"), &legacy).unwrap();
        assert_eq!(load_output_cache(&dir, "vault_t").scan_height, 42);
        // A sealed cache without the key to open it → empty cache (rescan), no panic.
        let k = [9u8; KEY_LEN];
        std::fs::write(dir.join("wallets/vault_t.cache"), seal(&k, &legacy)).unwrap();
        assert_eq!(load_output_cache(&dir, "vault_t").scan_height, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_store_refuses_without_device_key_and_roundtrips_with_one() {
        let dir = tmpdir("watch");
        // Real Monero keypair shape: view scalar + spend public point (from G).
        let view_sec = Zeroizing::new([3u8; 32]);
        let spend_pub = monero_oxide::ed25519::CompressedPoint::G.to_bytes();
        // Public API without an initialized device key (test process) → REFUSES.
        assert!(save_watch(&dir, "vault_t", &spend_pub, &view_sec).is_err());
        assert!(load_watch(&dir, "vault_t").is_none());
        // Explicit-key internals: seal → load reconstructs the same ViewPair.
        let k = [5u8; KEY_LEN];
        save_watch_with_key(&k, &dir, "vault_t", &spend_pub, &view_sec).unwrap();
        let vp = load_watch_with_key(&k, &dir, "vault_t").expect("watch roundtrip");
        assert_eq!(vp.spend().compress().to_bytes(), spend_pub);
        // Wrong key → None (no partial parse of secret material).
        assert!(load_watch_with_key(&[6u8; KEY_LEN], &dir, "vault_t").is_none());
        // The file on disk is sealed — the view secret never plaintext.
        let raw = std::fs::read(dir.join("wallets/vault_t.watch")).unwrap();
        assert!(is_sealed(&raw));
        assert!(!raw
            .windows(3)
            .any(|w| w == hex::encode([3u8; 32]).as_bytes()[..3].to_vec()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn watch_paths_and_listing_reject_hostile_ids() {
        let dir = tmpdir("watchlist");
        assert!(watch_path(&dir, "../../etc/cron.d/evil").is_err());
        std::fs::create_dir_all(dir.join("wallets")).unwrap();
        std::fs::write(dir.join("wallets/vault_ok.watch"), b"x").unwrap();
        std::fs::write(dir.join("wallets/has.dot.watch"), b"x").unwrap();
        let ids = list_watch_ids(&dir);
        assert_eq!(ids, vec!["vault_ok".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
