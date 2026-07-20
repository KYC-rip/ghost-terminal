//! Native wallpaper file store (RipleyOS `platform.wallpaper` capability).
//!
//! The renderer keeps wallpaper BYTES in its own IndexedDB; this store is a rev-addressed on-disk
//! cache so the webview can STREAM the image via the asset protocol instead of holding a multi-MB
//! blob on the JS heap. Files live under `$APPDATA/wallpapers/<key>.<rev>.img`; the same key+rev
//! always names the same bytes (the renderer bumps rev whenever a new image is applied), so saving
//! a rev prunes every other rev of that key. Plaintext by design — it is the user's own wallpaper,
//! painted on screen; nothing secret rides in here.

use std::fs;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

/// Key → filesystem-safe stem. The renderer sends keys like `wallpaper:lumen`; anything outside
/// [A-Za-z0-9_-] becomes '_' so a hostile key can never traverse out of the wallpapers dir.
fn sanitize(key: &str) -> String {
    key.chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}

fn dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?
        .join("wallpapers");
    fs::create_dir_all(&d).map_err(|e| format!("mkdir: {e}"))?;
    Ok(d)
}

fn file_for(app: &AppHandle, key: &str, rev: u64) -> Result<PathBuf, String> {
    Ok(dir(app)?.join(format!("{}.{}.img", sanitize(key), rev)))
}

/// Remove every stored rev of `key` except `keep` (u64::MAX ⇒ remove all).
fn prune(app: &AppHandle, key: &str, keep: u64) -> Result<(), String> {
    let stem = sanitize(key);
    let keep_name = format!("{stem}.{keep}.img");
    for entry in fs::read_dir(dir(app)?).map_err(|e| e.to_string())?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(&format!("{stem}.")) && name.ends_with(".img") && name != keep_name {
            let _ = fs::remove_file(entry.path());
        }
    }
    Ok(())
}

/// Save raw image bytes for key@rev, pruning older revs. Body is the RAW request payload
/// (`invoke(cmd, bytes, { headers })` on the JS side) — never base64, never a JSON array.
#[tauri::command]
pub async fn wallpaper_save(app: AppHandle, request: tauri::ipc::Request<'_>) -> Result<String, String> {
    let headers = request.headers();
    let key = headers
        .get("x-wp-key")
        .and_then(|v| v.to_str().ok())
        .ok_or("missing x-wp-key header")?
        .to_string();
    let rev: u64 = headers
        .get("x-wp-rev")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .ok_or("missing/invalid x-wp-rev header")?;
    let tauri::ipc::InvokeBody::Raw(bytes) = request.body() else {
        return Err("raw body required".into());
    };
    if bytes.is_empty() {
        return Err("empty body".into());
    }
    // Defence-in-depth cap (only the Pro-gated Wallpaper app calls this today, but a capability
    // should bound its own inputs). Generous vs select_background_image's 5MB: the renderer has
    // already downscaled, so anything near this is hostile, not a photo.
    const MAX_WALLPAPER_BYTES: usize = 20 * 1024 * 1024;
    if bytes.len() > MAX_WALLPAPER_BYTES {
        return Err("image exceeds the 20 MB limit".into());
    }
    let path = file_for(&app, &key, rev)?;
    // Atomic write: a process kill mid-write must never leave a partial file that wallpaper_url
    // would later report as "exists" and the webview would paint as garbage.
    let tmp = path.with_extension("img.tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("write: {e}"))?;
    fs::rename(&tmp, &path).map_err(|e| format!("rename: {e}"))?;
    let _ = prune(&app, &key, rev);
    Ok(path.to_string_lossy().to_string())
}

/// Absolute path for key@rev if that exact rev exists on disk, else None (renderer then saves).
#[tauri::command]
pub async fn wallpaper_url(app: AppHandle, key: String, rev: u64) -> Result<Option<String>, String> {
    let path = file_for(&app, &key, rev)?;
    Ok(if path.is_file() { Some(path.to_string_lossy().to_string()) } else { None })
}

/// Delete every stored rev of `key`.
#[tauri::command]
pub async fn wallpaper_clear(app: AppHandle, key: String) -> Result<(), String> {
    prune(&app, &key, u64::MAX)
}
