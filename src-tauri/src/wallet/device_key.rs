//! Device-bound keys for the "watch tier": the encrypted output cache and the
//! persisted view pairs (boot-time view-only sync). Tier model:
//!
//!   watch tier  — output cache + view key   → gated by THESE keys
//!   spend tier  — spend key + mnemonic      → gated by the user's password, always
//!
//! TWO device keys, deliberately different backends:
//!
//! * CACHE key — random 32 bytes in a 0600 file next to the app data. Chosen so
//!   that sealing the cache NEVER triggers an OS keychain prompt (macOS shows a
//!   scary ACL password dialog, and unsigned/dev builds re-prompt every rebuild —
//!   users who never opted into anything must never see that). A key file beside
//!   the data defeats grep/backup-tool exposure, not a full-disk attacker — still
//!   strictly better than the historical plaintext cache, at zero UX cost.
//!
//! * WATCH key — the OS keychain (macOS Keychain / Windows Credential Manager /
//!   Linux secret-service), loaded LAZILY: only when the user enables sync-at-
//!   launch (the prompt then has obvious context) or at boot after they already
//!   consented. The view key deserves the stronger backend: keychain material is
//!   only released to this app in an unlocked session, so a cold-seized disk
//!   doesn't yield it. Denied/unavailable → the watch store REFUSES to write
//!   (encrypt-or-don't-write, never plaintext) and enabling fails with a clear
//!   error instead of silently degrading.
//!
//! Subkeys are HKDF-SHA256-derived with distinct info strings, so no AEAD context
//! ever reuses a raw root key.

#[cfg(not(debug_assertions))]
use std::path::Path;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

#[cfg(not(debug_assertions))]
const KEYRING_SERVICE: &str = "ripley-terminal";
#[cfg(not(debug_assertions))]
const KEYRING_ENTRY: &str = "watch-key-v1";
const CACHE_KEY_FILE: &str = "device.key";
#[cfg(not(debug_assertions))]
const WATCH_KEY_SLOT_FILE: &str = "watch-key.slot";
#[cfg(not(debug_assertions))]
const MAX_WATCH_KEY_SLOT: u32 = 64;

/// File-backed root for the cache key. Loaded once at boot; None only if the
/// filesystem refuses us (then the cache degrades to legacy plaintext).
static FILE_KEY: OnceLock<Option<Zeroizing<[u8; 32]>>> = OnceLock::new();

/// Keychain-backed root for the watch key. Lazily populated by
/// `ensure_watch_key` (user-action or consented-boot); a failed/denied attempt
/// stays None and advances to a fresh keychain slot for the next retry, so a
/// one-off Deny does not permanently strand the feature.
static WATCH_ROOT: Mutex<Option<Zeroizing<[u8; 32]>>> = Mutex::new(None);

/// Load (or create on first run) the FILE key. No prompts, no keychain — safe to
/// call unconditionally at startup. Idempotent.
pub fn init_file_key(app: &AppHandle) {
    if FILE_KEY.get().is_some() {
        return;
    }
    let path = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(CACHE_KEY_FILE);
    let _ = FILE_KEY.set(load_or_create_file_key(&path));
}

fn load_or_create_file_key(path: &std::path::Path) -> Option<Zeroizing<[u8; 32]>> {
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            return Some(k);
        }
        log::warn!(
            "cache device key file has unexpected length {}; regenerating",
            bytes.len()
        );
    }
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, &k[..]) {
        log::warn!("cache device key write failed ({e}); cache stays plaintext");
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    log::info!("cache device key created");
    Some(k)
}

/// Load (or create) the keychain WATCH root. Call ONLY on a consent-backed path
/// (Enable click, or boot when watchSync is already on) — this is what can show
/// the OS keychain prompt. Blocking keyring work runs in spawn_blocking (it
/// panics inside tokio on Linux otherwise). Returns whether the key is ready.
pub async fn ensure_watch_key(app: &AppHandle) -> bool {
    if WATCH_ROOT.lock().map(|g| g.is_some()).unwrap_or(false) {
        return true;
    }

    // An ad-hoc macOS debug executable gets a new code-directory hash after
    // every Rust rebuild. Keychain ACLs therefore treat every hot-reloaded
    // binary as a new app and prompt again even after "Always Allow". Debug
    // builds use the stable 0600 device key with a distinct HKDF context; signed
    // production builds keep the stronger OS-keychain path below.
    #[cfg(debug_assertions)]
    {
        init_file_key(app);
        let Some(root) = FILE_KEY.get().and_then(|value| value.as_ref()) else {
            return false;
        };
        let mut copy = Zeroizing::new([0_u8; 32]);
        copy.copy_from_slice(&root[..]);
        if let Ok(mut guard) = WATCH_ROOT.lock() {
            *guard = Some(copy);
            log::info!("[watch-sync] debug build using file-backed watch root");
            return true;
        }
        return false;
    }

    #[cfg(not(debug_assertions))]
    {
        let slot_path = app
            .path()
            .app_data_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(WATCH_KEY_SLOT_FILE);
        log::info!(
            "[watch-sync] ensure_watch_key using slot file {}",
            slot_path.display()
        );
        let loaded = tokio::task::spawn_blocking(move || load_or_create_keychain_key(&slot_path))
            .await
            .unwrap_or(None);
        match loaded {
            Some(k) => {
                if let Ok(mut g) = WATCH_ROOT.lock() {
                    *g = Some(k);
                }
                true
            }
            None => false,
        }
    }
}

#[cfg(not(debug_assertions))]
fn load_or_create_keychain_key(slot_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let slot = read_watch_key_slot(slot_path);
    let entry_name = watch_key_entry_name(slot);
    log::info!("[watch-sync] loading keychain entry {entry_name} (slot {slot})");
    match load_or_create_keychain_key_for(&entry_name) {
        Some(k) => {
            log::info!("[watch-sync] keychain entry {entry_name} loaded");
            Some(k)
        }
        None => {
            // If the OS remembered a denied ACL for this keychain item, retrying the
            // exact same item can fail without a new prompt. Advance the slot so the
            // next explicit enable attempt uses a fresh keychain item and can ask
            // again. We do not immediately try the next slot here: one click should
            // produce at most one native keychain prompt.
            let next = slot.saturating_add(1).min(MAX_WATCH_KEY_SLOT);
            if next != slot {
                write_watch_key_slot(slot_path, next);
                log::info!("watch key: advanced retry slot to {next}");
            }
            None
        }
    }
}

#[cfg(not(debug_assertions))]
fn load_or_create_keychain_key_for(entry_name: &str) -> Option<Zeroizing<[u8; 32]>> {
    let entry = match keyring::Entry::new(KEYRING_SERVICE, entry_name) {
        Ok(e) => e,
        Err(e) => {
            log::warn!("[watch-sync] keychain entry {entry_name} unavailable ({e})");
            return None;
        }
    };
    match entry.get_secret() {
        Ok(bytes) if bytes.len() == 32 => {
            log::info!("[watch-sync] keychain read ok for {entry_name}");
            let mut k = Zeroizing::new([0u8; 32]);
            k.copy_from_slice(&bytes);
            Some(k)
        }
        Ok(bytes) => {
            // Wrong-sized secret = corrupt/foreign entry. Don't overwrite it (it may
            // belong to something else); treat the keychain as unavailable.
            log::warn!(
                "[watch-sync] keychain entry {entry_name} has unexpected length {}",
                bytes.len()
            );
            None
        }
        Err(keyring::Error::NoEntry) => {
            log::info!("[watch-sync] keychain entry {entry_name} missing; creating");
            let mut k = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *k);
            match entry.set_secret(&*k) {
                Ok(()) => {
                    log::info!("[watch-sync] created new keychain entry {entry_name}");
                    Some(k)
                }
                Err(e) => {
                    // Could not PERSIST the key → nothing encrypted with it would
                    // survive a restart. Refuse rather than strand data.
                    log::warn!("[watch-sync] keychain write failed for {entry_name}: {e:?}");
                    None
                }
            }
        }
        Err(e) => {
            // NoStorageAccess / PlatformFailure / user denied the ACL prompt.
            log::warn!("[watch-sync] keychain read failed for {entry_name}: {e:?}");
            None
        }
    }
}

#[cfg(not(debug_assertions))]
fn watch_key_entry_name(slot: u32) -> String {
    if slot == 0 {
        KEYRING_ENTRY.to_string()
    } else {
        format!("{KEYRING_ENTRY}-retry-{slot}")
    }
}

#[cfg(not(debug_assertions))]
fn read_watch_key_slot(path: &Path) -> u32 {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .map(|slot| slot.min(MAX_WATCH_KEY_SLOT))
        .unwrap_or(0)
}

#[cfg(not(debug_assertions))]
fn write_watch_key_slot(path: &Path, slot: u32) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(path, slot.to_string()) {
        log::warn!(
            "[watch-sync] failed to write retry slot {} ({e})",
            path.display()
        );
    } else {
        log::info!("[watch-sync] wrote retry slot {slot} to {}", path.display());
    }
}

/// HKDF-SHA256 subkey with a domain-separating info string.
fn subkey(root: &[u8; 32], info: &[u8]) -> Option<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(None, &root[..]);
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(info, &mut *out).ok()?;
    Some(out)
}

/// Key for the encrypted output cache (file-key root — never prompts).
/// None → cache stays plaintext (legacy).
pub fn cache_key() -> Option<Zeroizing<[u8; 32]>> {
    let root = FILE_KEY.get()?.as_ref()?;
    subkey(root, b"ripley/cache-v1")
}

/// Key for the persisted view pairs (keychain root — consent-gated, lazy).
/// None → watch store refuses to write and boot sync is skipped.
pub fn watch_key() -> Option<Zeroizing<[u8; 32]>> {
    let g = WATCH_ROOT.lock().ok()?;
    let root = g.as_ref()?;
    subkey(root, b"ripley/watch-v1")
}
