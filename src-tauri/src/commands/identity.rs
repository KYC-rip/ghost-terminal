use crate::wallet::Identity;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

fn identities_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("identities.json")
}

fn active_identity_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("active_identity")
}

fn load_identities(app: &AppHandle) -> Vec<Identity> {
    let path = identities_path(app);
    match std::fs::read_to_string(&path) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_default(),
        Err(_) => vec![],
    }
}

fn save_identities_to_disk(app: &AppHandle, ids: &[Identity]) -> Result<(), String> {
    let path = identities_path(app);
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create dir: {}", e))?;
    let data = serde_json::to_string_pretty(ids).map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, data).map_err(|e| format!("Write error: {}", e))
}

#[tauri::command]
pub async fn get_identities(app: AppHandle) -> Result<Vec<Identity>, String> {
    Ok(load_identities(&app))
}

/// All identity ids on disk — used to discover other wallets for background sync.
pub(crate) fn identity_ids(app: &AppHandle) -> Vec<String> {
    load_identities(app).into_iter().map(|i| i.id).collect()
}

#[tauri::command]
pub async fn save_identities(app: AppHandle, ids: Vec<Identity>) -> Result<(), String> {
    save_identities_to_disk(&app, &ids)
}

/// A wallet from a previous (Electron) Ripley install, offered for seed-restore.
#[derive(serde::Serialize)]
pub struct LegacyWallet {
    id: String,
    name: String,
    /// Suggested restore height derived from the wallet's creation time (so the
    /// restore scan starts near creation, not from the RingCT fork).
    est_restore_height: u64,
}

/// Candidate old-Electron data dirs. Electron stored under `<userData>/ripley-terminal`;
/// Tauri uses `run.ripley.terminal` — a sibling on macOS/Windows, but a different base
/// on Linux (config vs data dir), so we check several.
fn legacy_dir_candidates(app: &AppHandle) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = Vec::new();
    if let Ok(add) = app.path().app_data_dir() {
        if let Some(parent) = add.parent() {
            v.push(parent.join("ripley-terminal"));
        }
    }
    if let Some(base) = directories::BaseDirs::new() {
        v.push(base.data_dir().join("ripley-terminal"));
        v.push(base.config_dir().join("ripley-terminal"));
    }
    let mut seen = std::collections::HashSet::new();
    v.into_iter()
        .filter(|p| seen.insert(p.clone()))
        .filter(|p| p.join("config.json").is_file() && p.join("wallets").is_dir())
        .collect()
}

/// Detect wallets from a previous (Electron) Ripley install that aren't imported
/// here yet, so the user can bring them over via seed-restore. Reads ONLY the
/// public identity names + creation times from the old config — never key material.
#[tauri::command]
pub async fn detect_legacy_wallets(
    app: AppHandle,
    state: tauri::State<'_, crate::wallet::WalletState>,
) -> Result<Vec<LegacyWallet>, String> {
    let already: std::collections::HashSet<String> = identity_ids(&app).into_iter().collect();
    let tip = state.tip_height().await;

    // Reference (height, time) for estimating a restore height from a wallet's
    // creation timestamp. Use the live tip when synced; otherwise a fixed anchor
    // (mainnet ~block 3.709M at 2026-07-03, unix 1_783_000_000 s) — legacy wallets
    // were all created before it, so the estimate stays safely in the past.
    // ~120s/block. An anchor that's too EARLY makes the estimate too HIGH, which
    // would miss funds — so this must track real mainnet.
    const ANCHOR_HEIGHT: u64 = 3_709_000;
    const ANCHOR_TS_MS: i64 = 1_783_000_000_000;
    const RINGCT_FORK: u64 = 1_220_516;
    let (ref_height, ref_ts_ms) = if tip > 0 {
        (tip, chrono::Utc::now().timestamp_millis())
    } else {
        (ANCHOR_HEIGHT, ANCHOR_TS_MS)
    };

    let est_height = |created_ms: i64| -> u64 {
        let ms_ago = (ref_ts_ms - created_ms).max(0);
        let blocks_ago = (ms_ago / 1000 / 120) as u64;
        // ~2-day safety margin so the scan starts safely before any first tx,
        // clamped to the RingCT fork (nothing scannable before it).
        ref_height
            .saturating_sub(blocks_ago)
            .saturating_sub(1440)
            .max(RINGCT_FORK)
    };

    let mut out = Vec::new();
    for dir in legacy_dir_candidates(&app) {
        let Ok(cfg) = std::fs::read_to_string(dir.join("config.json")) else {
            continue;
        };
        let Ok(json) = serde_json::from_str::<serde_json::Value>(&cfg) else {
            continue;
        };
        let Some(ids) = json.get("identities").and_then(|v| v.as_array()) else {
            continue;
        };
        for it in ids {
            let id = it
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            if id.is_empty() || already.contains(&id) {
                continue;
            }
            // Only offer wallets whose encrypted keys file is actually present.
            if !dir.join("wallets").join(format!("{id}.keys")).is_file() {
                continue;
            }
            let name = it
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("Wallet")
                .to_string();
            let created_ms = it.get("created").and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;
            out.push(LegacyWallet {
                id,
                name,
                est_restore_height: est_height(created_ms),
            });
        }
        if !out.is_empty() {
            break;
        }
    }
    Ok(out)
}

#[tauri::command]
pub async fn create_identity(app: AppHandle, name: String) -> Result<Identity, String> {
    let id = format!(
        "vault_{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis(),
        &name.chars().take(3).collect::<String>()
    );

    let identity = Identity {
        id,
        name,
        created: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    };

    let mut ids = load_identities(&app);
    ids.push(identity.clone());
    save_identities_to_disk(&app, &ids)?;

    // Set as active if first identity
    if ids.len() == 1 {
        std::fs::write(active_identity_path(&app), &identity.id).ok();
    }

    Ok(identity)
}

#[tauri::command]
pub async fn delete_identity(app: AppHandle, id: String) -> Result<(), String> {
    // Guard the renderer-supplied id before it becomes a filesystem path below:
    // without this a hostile `../…` id would remove files OUTSIDE the wallets dir.
    if !crate::wallet::storage::valid_identity_id(&id) {
        return Err("Invalid identity id".into());
    }

    let mut ids = load_identities(&app);

    // FUND SAFETY (irreversible destruction): deleting a vault erases its encrypted
    // key file — a wallet whose seed wasn't backed up is gone for good. Require an
    // OS-level confirmation the renderer JS cannot fake, so no ROS app can enumerate
    // get_identities and silently wipe every vault. Names the wallet being deleted.
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let body = match ids.iter().find(|i| i.id == id).map(|i| i.name.as_str()) {
            Some(name) => format!(
                "Permanently delete the wallet \"{name}\"?\n\nIts encrypted keys will be erased. \
                 If you have not backed up its seed phrase, any funds it holds will be LOST FOREVER."
            ),
            None => "Permanently delete this wallet? Its encrypted keys will be erased and any \
                     un-backed-up funds will be LOST FOREVER."
                .to_string(),
        };
        let ok = app
            .dialog()
            .message(body)
            .title("Delete wallet")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Delete".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !ok {
            return Err("Deletion cancelled".into());
        }
    }

    ids.retain(|i| i.id != id);
    save_identities_to_disk(&app, &ids)?;

    // Delete wallet files (vault + cache + persisted watch view-pair)
    let data_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    let wallet_file = data_dir.join("wallets").join(format!("{}.vault", id));
    let cache_file = data_dir.join("wallets").join(format!("{}.cache", id));
    std::fs::remove_file(wallet_file).ok();
    std::fs::remove_file(cache_file).ok();
    crate::wallet::storage::delete_watch(&data_dir, &id);

    log::info!("Identity deleted: {}", id);
    Ok(())
}

#[tauri::command]
pub async fn switch_identity(app: AppHandle, id: String) -> Result<(), String> {
    std::fs::write(active_identity_path(&app), &id)
        .map_err(|e| format!("Failed to set active identity: {}", e))
}

/// Return the persisted active identity id. Falls back to the first identity if
/// the file is absent or points at an identity that no longer exists (e.g. it
/// was purged). Without this, switching wallets never sticks across reload.
#[tauri::command]
pub async fn get_active_identity(app: AppHandle) -> Result<String, String> {
    let ids = load_identities(&app);
    let stored = std::fs::read_to_string(active_identity_path(&app)).ok();
    let stored = stored
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let active = stored
        .filter(|id| ids.iter().any(|i| &i.id == id))
        .or_else(|| ids.first().map(|i| i.id.clone()))
        .unwrap_or_default();
    Ok(active)
}

#[tauri::command]
pub async fn rename_identity(app: AppHandle, id: String, name: String) -> Result<(), String> {
    let mut ids = load_identities(&app);
    if let Some(identity) = ids.iter_mut().find(|i| i.id == id) {
        identity.name = name;
    } else {
        return Err("Identity not found".into());
    }
    save_identities_to_disk(&app, &ids)
}
