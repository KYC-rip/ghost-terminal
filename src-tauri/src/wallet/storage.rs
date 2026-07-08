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

    let ciphertext = cipher.encrypt(nonce, plaintext.as_slice())
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
    let nonce_bytes: [u8; NONCE_LEN] = encrypted[SALT_LEN..SALT_LEN + NONCE_LEN].try_into().unwrap();
    let ciphertext = &encrypted[SALT_LEN + NONCE_LEN..];

    let key = derive_key(password, &salt);
    let cipher = ChaCha20Poly1305::new(key.as_ref().into());
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| "Invalid password or corrupted wallet file".to_string())?;

    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("Wallet data corrupted: {}", e))
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
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Get the wallet file path for an identity. Rejects ids that aren't a safe path
/// component (see `valid_identity_id`) so a hostile id can't escape the wallets dir.
pub fn wallet_path(data_dir: &Path, identity_id: &str) -> Result<PathBuf, String> {
    if !valid_identity_id(identity_id) {
        return Err("Invalid identity id".into());
    }
    Ok(data_dir.join("wallets").join(format!("{}.vault", identity_id)))
}

/// Save encrypted wallet to disk.
pub fn save_wallet(data_dir: &Path, identity_id: &str, data: &WalletFileData, password: &str) -> Result<(), String> {
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
    std::fs::write(&tmp, &encrypted)
        .map_err(|e| format!("Failed to write wallet file: {}", e))?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        // Don't leave the half-written temp behind if the commit rename fails.
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to commit wallet file: {}", e));
    }

    log::info!("Wallet saved: {}", path.display());
    Ok(())
}

/// Load and decrypt wallet from disk.
pub fn load_wallet(data_dir: &Path, identity_id: &str, password: &str) -> Result<WalletFileData, String> {
    let path = wallet_path(data_dir, identity_id)?;
    let encrypted = std::fs::read(&path)
        .map_err(|e| format!("Failed to read wallet file: {}", e))?;

    decrypt_wallet(&encrypted, password)
}

/// Check if a wallet file exists for an identity.
pub fn wallet_exists(data_dir: &Path, identity_id: &str) -> bool {
    wallet_path(data_dir, identity_id).map(|p| p.exists()).unwrap_or(false)
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
    Ok(data_dir.join("wallets").join(format!("{}.cache", identity_id)))
}

/// Save output cache to disk (plaintext — outputs don't contain secret keys).
/// The output data is already committed on-chain, so no privacy loss from caching.
pub fn save_output_cache(data_dir: &Path, identity_id: &str, cache: &OutputCache) -> Result<(), String> {
    let path = output_cache_path(data_dir, identity_id)?;
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create cache dir: {}", e))?;
    let data = serde_json::to_vec(cache)
        .map_err(|e| format!("Failed to serialize cache: {}", e))?;
    // Temp-then-rename so an interrupted write can't leave a truncated cache (which
    // load_output_cache would discard, forcing a full rescan). Not secret data, but
    // the same atomicity keeps restarts cheap.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &data)
        .map_err(|e| format!("Failed to write cache: {}", e))?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("Failed to commit cache: {}", e));
    }
    Ok(())
}

/// Load output cache from disk.
pub fn load_output_cache(data_dir: &Path, identity_id: &str) -> OutputCache {
    let Ok(path) = output_cache_path(data_dir, identity_id) else {
        return OutputCache::default();
    };
    match std::fs::read(&path) {
        Ok(data) => serde_json::from_slice(&data).unwrap_or_default(),
        Err(_) => OutputCache::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = WalletFileData {
            seed_entropy: "deadbeef".repeat(4),
            scan_height: 3245000,
            accounts: vec![AccountLabel { index: 0, label: "Main".into() }],
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
}
