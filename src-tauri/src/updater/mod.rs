//! Signed over-the-air updates for the RipleyOS UI bundle.
//!
//! - [`ota`]: the trust core — manifest structs, the pinned Ed25519 key, and the pure
//!   verification pipeline (signature → rollback → freshness → backend-compat → size →
//!   content-hash) plus `.tar.zst` in-memory extraction. All decision logic is pure and
//!   unit-tested; see `docs/ota-signed-updates.md`.
//! - [`protocol`]: the `ros://` in-memory content handler.
//!
//! This module owns the launch-time glue: pick the bundle to load (verified cache, else
//! the bundled fallback), re-verify it, and hand the caller a ready [`protocol::RosBundle`].

pub mod ota;
pub mod protocol;

use std::path::PathBuf;
use tauri::{AppHandle, Manager};

/// The fallback ROS bundle, embedded in the signed binary at build time (so it is always
/// present and covered by the native build provenance — the root of trust). At load its
/// bytes are re-checked against [`ota::FALLBACK_SHA256`].
const FALLBACK_ARCHIVE: &[u8] = include_bytes!("../../resources/ros-fallback.tar.zst");

/// `app_data_dir()/ota` — where verified update archives + `state.json` live.
fn ota_dir(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("ota")
}

/// Read the active-bundle pointer, if any.
fn read_state(app: &AppHandle) -> Option<ota::State> {
    let raw = std::fs::read(ota_dir(app).join("state.json")).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Resolve-at-launch + re-verify (runbook §5.2–5.3). Returns a ready in-memory bundle:
///
/// 1. If `state.json` names a cached archive, read it and re-hash against
///    `state.sha256` — this closes the TOCTOU/tamper window between the download-time
///    check and now. On any mismatch or read error, fall through to the fallback.
/// 2. Otherwise (or on cache failure) use the binary-embedded fallback, re-checked
///    against the pinned [`ota::FALLBACK_SHA256`].
///
/// A `None` return means even the fallback failed its own integrity check — the binary
/// itself is compromised; the caller should refuse to load ROS (fail closed).
pub fn load_bundle_at_launch(app: &AppHandle) -> Option<protocol::RosBundle> {
    if let Some(state) = read_state(app) {
        let path = ota_dir(app).join(format!("ros-{}.tar.zst", state.version));
        match std::fs::read(&path) {
            Ok(bytes) if ota::verify_archive_hash(&bytes, &state.sha256) => {
                match protocol::RosBundle::from_archive(&bytes) {
                    Ok(b) => {
                        log::info!("[ota] loaded verified cache bundle v{}", state.version);
                        return Some(b);
                    }
                    Err(e) => log::warn!(
                        "[ota] cache archive v{} unreadable ({e}) — using fallback",
                        state.version
                    ),
                }
            }
            Ok(_) => log::warn!("[ota] cache archive hash mismatch — using fallback"),
            Err(e) => log::warn!("[ota] cache archive missing ({e}) — using fallback"),
        }
        // The cached archive named by state.json is gone/corrupt: drop the stale pointer
        // so status + the rollback gate reflect the fallback and the updater re-fetches
        // that version instead of treating it as already-installed.
        let _ = std::fs::remove_file(ota_dir(app).join("state.json"));
    }

    // Bundled fallback (first run, offline, or a bad cache).
    if !ota::verify_archive_hash(FALLBACK_ARCHIVE, ota::FALLBACK_SHA256) {
        log::error!("[ota] bundled fallback failed its pinned hash — refusing to load ROS");
        return None;
    }
    match protocol::RosBundle::from_archive(FALLBACK_ARCHIVE) {
        Ok(b) => {
            log::info!("[ota] loaded bundled fallback ({} files)", b.len());
            Some(b)
        }
        Err(e) => {
            log::error!("[ota] bundled fallback is corrupt ({e}) — refusing to load ROS");
            None
        }
    }
}

/// The currently active bundle version for status reporting: the cached state version,
/// else `"fallback"`.
pub fn active_version(app: &AppHandle) -> String {
    read_state(app)
        .map(|s| s.version)
        .unwrap_or_else(|| "fallback".to_string())
}

/// Current version for the rollback gate, RECONCILED with reality: the cached state
/// version only if its archive is present AND still hashes to `state.sha256`; otherwise
/// `"0.0.0"`. Without this, a stale `state.json` (archive lost/corrupt → launch fell back
/// to the bundled fallback) would make the updater treat that same signed version as
/// "up to date" and never re-download it — stranding the user on the fallback until a
/// higher version ships. Pure (no side effects); the stale pointer is cleared at launch
/// by `load_bundle_at_launch`.
fn current_semver(app: &AppHandle) -> String {
    if let Some(state) = read_state(app) {
        let path = ota_dir(app).join(format!("ros-{}.tar.zst", state.version));
        if let Ok(bytes) = std::fs::read(&path) {
            if ota::verify_archive_hash(&bytes, &state.sha256) {
                return state.version;
            }
        }
    }
    "0.0.0".to_string()
}

/// The manifest URL to check. Pinned to `ota::OTA_MANIFEST_URL` in release; a DEV-ONLY
/// `OTA_MANIFEST_URL` env var overrides it in debug builds (local test servers), ignored
/// + warned in release — same posture as the ROS_URL dev-gate (a shipped wallet must
/// never fetch updates from an attacker-chosen origin; the pinned signature key limits
/// blast radius anyway, but we don't even try a foreign host).
fn manifest_url() -> String {
    #[cfg(debug_assertions)]
    if let Ok(u) = std::env::var("OTA_MANIFEST_URL") {
        let u = u.trim();
        if !u.is_empty() {
            log::warn!("[ota] using dev OTA_MANIFEST_URL override: {u}");
            return u.to_string();
        }
    }
    #[cfg(not(debug_assertions))]
    if let Ok(u) = std::env::var("OTA_MANIFEST_URL") {
        if !u.trim().is_empty() {
            println!("[ota/warn] OTA_MANIFEST_URL ignored in release build (dev-only override)");
        }
    }
    ota::OTA_MANIFEST_URL.to_string()
}

/// The archive URL to download, derived from the PINNED manifest URL's directory rather
/// than the server-controlled `manifest.url` field — so the download origin is pinned to
/// the same trusted host as the manifest, and a (signed) manifest can't redirect the
/// fetch to an arbitrary host. e.g. `…/ota/manifest.json` → `…/ota/ros-<version>.tar.zst`.
fn archive_url_for(manifest_url: &str, version: &str) -> String {
    let base = manifest_url
        .rsplit_once('/')
        .map(|(b, _)| b)
        .unwrap_or(manifest_url);
    format!("{base}/ros-{version}.tar.zst")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Result of an update check (serialized to the renderer).
#[derive(Debug, Clone, serde::Serialize)]
pub struct CheckResult {
    /// A newer bundle was verified + staged (applies next launch).
    pub updated: bool,
    /// Already on the newest signed bundle.
    pub up_to_date: bool,
    /// The staged version (when `updated`) or the current version (when `up_to_date`).
    pub version: Option<String>,
    /// Present on any failure; the current bundle is left untouched (fail-closed).
    pub error: Option<String>,
}

impl CheckResult {
    fn updated(v: String) -> Self {
        Self {
            updated: true,
            up_to_date: false,
            version: Some(v),
            error: None,
        }
    }
    fn up_to_date(v: String) -> Self {
        Self {
            updated: false,
            up_to_date: true,
            version: Some(v),
            error: None,
        }
    }
    fn err(e: String) -> Self {
        Self {
            updated: false,
            up_to_date: false,
            version: None,
            error: Some(e),
        }
    }
}

/// Fetch → verify → download → hash → atomically stage a newer signed bundle (runbook
/// §5.1). Applies on the NEXT launch. Every failure is fail-closed: the current cache /
/// state is left untouched. The server is never trusted — the signature is checked over
/// the raw manifest bytes before parsing, and the archive against the manifest hash.
pub async fn check_and_stage_update(app: &AppHandle) -> CheckResult {
    use crate::commands::system::proxied_get_bytes;
    use std::time::Duration;

    // 1. manifest + detached sig (routed; ros.rip → onion in Tor mode). Small, tight caps.
    let m_url = manifest_url();
    let manifest_raw =
        match proxied_get_bytes(app, &m_url, Duration::from_secs(30), Some(1 << 20)).await {
            Ok(b) => b,
            Err(e) => return CheckResult::err(format!("manifest fetch failed: {e}")),
        };
    let sig_url = format!("{m_url}.sig");
    let sig = match proxied_get_bytes(app, &sig_url, Duration::from_secs(30), Some(4096)).await {
        Ok(b) => b,
        Err(e) => return CheckResult::err(format!("signature fetch failed: {e}")),
    };

    // 2. Verify + gate (pure; pinned key + injected clock/current/backend).
    let current = current_semver(app);
    let manifest = match ota::evaluate_manifest(
        &ota::OTA_UPDATE_PUBKEY,
        &manifest_raw,
        &sig,
        now_unix(),
        &current,
        env!("CARGO_PKG_VERSION"),
    ) {
        Ok(m) => m,
        // "not newer" isn't an error — we're already current.
        Err(ota::OtaReject::Rollback { .. }) => return CheckResult::up_to_date(current),
        Err(e) => return CheckResult::err(e.to_string()),
    };

    // 3. Download the archive from the PINNED origin (derived from the manifest URL, not
    //    the manifest's own `url` field), bigger timeout + hard size cap; verify its hash.
    let archive_url = archive_url_for(&m_url, &manifest.version);
    let archive = match proxied_get_bytes(
        app,
        &archive_url,
        Duration::from_secs(120),
        Some(ota::OTA_MAX_BYTES),
    )
    .await
    {
        Ok(b) => b,
        Err(e) => return CheckResult::err(format!("archive download failed: {e}")),
    };
    if !ota::verify_archive_hash(&archive, &manifest.sha256) {
        return CheckResult::err("archive sha256 does not match the signed manifest".into());
    }

    // 4. Atomically stage; applies next launch.
    if let Err(e) =
        ota::stage_verified_archive(&ota_dir(app), &manifest.version, &manifest.sha256, &archive)
    {
        return CheckResult::err(format!("staging failed: {e}"));
    }
    log::info!(
        "[ota] staged verified bundle v{} (applies next launch)",
        manifest.version
    );
    CheckResult::updated(manifest.version)
}

/// Status for the Settings UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChannelStatus {
    /// The bundle that will load (cached version, or "fallback").
    pub active_version: String,
    /// Where ROS loads from: "beta" (app.ros.rip) or "ota" (ros://local).
    pub source: String,
}

/// Manual "check for updates now" (Settings). Verifies + stages a newer bundle; the
/// result reports updated / up-to-date / error without mutating the running UI.
#[tauri::command]
pub async fn check_ros_update(app: AppHandle) -> Result<CheckResult, String> {
    Ok(check_and_stage_update(&app).await)
}

/// Current OTA channel status for the Settings UI.
#[tauri::command]
pub async fn ros_channel_status(app: AppHandle) -> Result<ChannelStatus, String> {
    Ok(ChannelStatus {
        active_version: active_version(&app),
        source: crate::commands::config::read_ros_source(&app),
    })
}
