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
                    Err(e) => log::warn!("[ota] cache archive v{} unreadable ({e}) — using fallback", state.version),
                }
            }
            Ok(_) => log::warn!("[ota] cache archive hash mismatch — using fallback"),
            Err(e) => log::warn!("[ota] cache archive missing ({e}) — using fallback"),
        }
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
