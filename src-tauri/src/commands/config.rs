use std::path::{Path, PathBuf};
use tauri::{AppHandle, Manager};

use crate::wallet::{BlockScanner, WalletState};

fn config_path(app: &AppHandle) -> PathBuf {
    app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from(".")).join("config.json")
}

/// Side file for the skin background data URL — kept out of config.json so the
/// (frequently-rewritten) config stays small even with a multi-MB image.
fn skin_bg_path(app: &AppHandle) -> PathBuf {
    app.path().app_data_dir().unwrap_or_else(|_| PathBuf::from(".")).join("skin_bg.b64")
}

#[tauri::command]
pub async fn get_config(app: AppHandle) -> Result<serde_json::Value, String> {
    let path = config_path(&app);
    let mut config = match std::fs::read_to_string(&path) {
        // Merge the stored config OVER the defaults so configs written before a
        // new key existed (e.g. `shortcuts`) get backfilled — otherwise the
        // Settings UI shows empty sections for keys the old file never had.
        Ok(data) => {
            let stored: serde_json::Value =
                serde_json::from_str(&data).map_err(|e| format!("Config parse error: {}", e))?;
            let mut merged = default_config();
            if let (Some(m), Some(s)) = (merged.as_object_mut(), stored.as_object()) {
                for (k, v) in s {
                    m.insert(k.clone(), v.clone());
                }
            }
            // A config saved before `shortcuts` existed may have persisted it as
            // an empty object — treat that as missing and restore the defaults so
            // the Settings keybinding rows aren't blank.
            let shortcuts_empty = merged
                .get("shortcuts")
                .and_then(|s| s.as_object())
                .map_or(true, |o| o.is_empty());
            if shortcuts_empty {
                if let Some(m) = merged.as_object_mut() {
                    m.insert("shortcuts".to_string(), default_config()["shortcuts"].clone());
                }
            }
            merged
        }
        // Keep these in sync with the renderer's SettingsView controls so it
        // never reads `undefined`.
        Err(_) => default_config(),
    };

    // Reattach the skin background from its side file (it's stored out of
    // config.json to keep that small). Falls back to whatever's already in the
    // config if there's no side file (e.g. a pre-offload config still embedding
    // it — that migrates to the side file on the next save).
    if let Ok(bg) = std::fs::read_to_string(skin_bg_path(&app)) {
        if !bg.is_empty() {
            if let Some(m) = config.as_object_mut() {
                m.insert("skin_background".to_string(), serde_json::json!(bg));
            }
        }
    }
    Ok(config)
}

/// Default config shape. Mirrors the controls SettingsView renders.
pub fn default_config() -> serde_json::Value {
    serde_json::json!({
        "routingMode": "clearnet",
        "useSystemProxy": true,
        "systemProxyAddress": "",
        "network": "mainnet",
        "customNodeAddress": "",
        "autoLockMinutes": 10,
        "show_scanlines": true,
        "hide_zero_balances": false,
        "include_prereleases": false,
        "sync_all_wallets": false,
        "fast_sync": false,
        "shortcuts": {
            "LOCK": "Mod+L",
            "SEND": "Mod+S",
            "RECEIVE": "Mod+R",
            "CHURN": "Mod+Alt+C",
            "SPLIT": "Mod+Alt+S",
            "SYNC": "Mod+U",
            "SETTINGS": "Mod+,",
            "TERMINAL": "Mod+Shift+T"
        }
    })
}

/// App metadata + on-disk storage locations for the Settings → Data Storage
/// panel (the renderer showed "Loading..." because the bridge returned empty
/// paths). appDataPath holds config/nodes/Tor state; walletsPath holds the
/// encrypted .vault files.
#[tauri::command]
pub async fn get_app_info(app: AppHandle) -> Result<serde_json::Value, String> {
    let app_data = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {}", e))?;
    let wallets = app_data.join("wallets");
    Ok(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "appDataPath": app_data.to_string_lossy(),
        "walletsPath": wallets.to_string_lossy(),
        "platform": std::env::consts::OS,
        "isPackaged": !cfg!(debug_assertions),
    }))
}

/// Launch-capable file extensions `reveal_path` refuses to hand the OS opener even
/// inside the app dirs: `open`/`xdg-open`/`explorer` would RUN these, not reveal them.
/// Covers direct executables/scripts plus indirect launchers — `.desktop` executes its
/// `Exec=` line under `xdg-open`, and `.lnk` follows a shortcut to an arbitrary target.
const REVEAL_BLOCKED_EXT: &[&str] = &[
    "app", "exe", "com", "cmd", "bat", "sh", "bash", "zsh", "command", "scpt",
    "applescript", "desktop", "lnk",
];

/// Confinement check for `reveal_path`, split out PURE (no filesystem / process I/O)
/// so it's unit-testable. `requested` and `allowed` are ALREADY canonicalized by the
/// caller, so `..`/symlinks are resolved before we get here. Allows the path iff it
/// sits inside an allowed base — `Path::starts_with` is component-wise, so `/data`
/// never matches a sibling like `/data-evil` — and carries no launch-capable extension.
fn reveal_guard(requested: &Path, allowed: &[PathBuf]) -> Result<(), String> {
    if !allowed.iter().any(|base| requested.starts_with(base)) {
        return Err("Refusing to reveal a path outside the app's data directories".into());
    }
    if let Some(ext) = requested.extension().and_then(|e| e.to_str()) {
        if REVEAL_BLOCKED_EXT.iter().any(|b| b.eq_ignore_ascii_case(ext)) {
            return Err("Refusing to open an executable path".into());
        }
    }
    Ok(())
}

/// Reveal a path in the OS file manager (Settings → Data Storage "Reveal").
///
/// The renderer supplies `path`, so treat it as hostile: `open <arg>` will happily
/// launch an arbitrary app bundle or a URL (which in Tor mode would deanonymize by
/// opening in the default browser). Only reveal locations UNDER the app's own
/// data/log dirs — the Settings panel only ever passes those. We canonicalize the
/// request (resolving `..`/symlinks and requiring it to exist, so a URL or a
/// non-file can't slip through) and confirm it sits inside an allowed base.
///
/// Callers pass DIRECTORIES (the data/log dirs): `open <dir>` opens the folder in the
/// file manager. Note `open <file>` would instead LAUNCH the file's default handler
/// (macOS reveal-in-Finder needs `open -R`); `reveal_guard` refuses launch-capable
/// files, but a benign handler-triggering file (e.g. `.html`/`.pdf`) inside app_data
/// would still open in the default app — acceptable since only validated writers ever
/// touch app_data today.
#[tauri::command]
pub async fn reveal_path(app: AppHandle, path: String) -> Result<(), String> {
    // Canonicalize each allowed base up front (resolves symlinks; on macOS also maps
    // /var → /private/var) so it compares against the equally-canonicalized request.
    let mut allowed: Vec<PathBuf> = Vec::new();
    for base in [app.path().app_data_dir(), app.path().app_log_dir()] {
        if let Ok(d) = base {
            if let Ok(c) = std::fs::canonicalize(&d) {
                allowed.push(c);
            }
        }
    }

    let requested = std::fs::canonicalize(&path).map_err(|_| "Path does not exist".to_string())?;
    reveal_guard(&requested, &allowed)?;

    #[cfg(target_os = "macos")]
    let program = "open";
    #[cfg(target_os = "windows")]
    let program = "explorer";
    #[cfg(all(unix, not(target_os = "macos")))]
    let program = "xdg-open";

    std::process::Command::new(program)
        .arg(&requested)
        .spawn()
        .map_err(|e| format!("Failed to open {}: {e}", requested.display()))?;
    Ok(())
}

#[tauri::command]
pub async fn save_config(app: AppHandle, mut config: serde_json::Value) -> Result<(), String> {
    let path = config_path(&app);
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create config dir: {}", e))?;

    // Offload a large skin background (a base64 data URL) to a side file so
    // config.json stays small — it's rewritten on every save, and embedding a
    // multi-MB image bloated it. get_config reattaches it on read.
    let skin_path = skin_bg_path(&app);
    if let Some(obj) = config.as_object_mut() {
        match obj.get("skin_background").and_then(|v| v.as_str()) {
            Some(bg) if !bg.is_empty() => {
                std::fs::write(&skin_path, bg)
                    .map_err(|e| format!("Failed to write skin background: {}", e))?;
                obj.insert("skin_background".to_string(), serde_json::json!(""));
            }
            // Explicitly cleared → remove the side file so it doesn't reappear.
            Some(_) => {
                let _ = std::fs::remove_file(&skin_path);
            }
            None => {}
        }
    }

    let data = serde_json::to_string_pretty(&config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;
    std::fs::write(&path, data)
        .map_err(|e| format!("Failed to write config: {}", e))?;
    Ok(())
}

/// Save config for UI-only preferences (scanlines, auto-lock, theme). Does NOT
/// touch the network uplink — use this when nothing about routing changed.
#[tauri::command]
pub async fn save_config_only(app: AppHandle, config: serde_json::Value) -> Result<(), String> {
    save_config(app, config).await
}

/// Save config AND apply network-affecting changes live. If a wallet is
/// unlocked, restart the block scanner so a new routingMode / proxy / node /
/// network takes effect without re-login. BlockScanner::start bumps the scanner
/// generation, so the running scanner is cleanly superseded after its current
/// batch and the new one re-races nodes (re-reading config + re-running Tor
/// bootstrap as needed). The scanner resumes from the current scan height, so
/// no progress is lost.
#[tauri::command]
pub async fn save_config_and_reload(app: AppHandle, config: serde_json::Value) -> Result<(), String> {
    save_config(app.clone(), config).await?;

    let state = app.state::<WalletState>();
    if !state.is_locked().await {
        let height = state.get_scan_height().await;
        crate::emit_log(
            &app,
            "Network",
            "info",
            "♻️ Routing changed — restarting uplink with the new configuration...",
        );
        BlockScanner::start(app.clone(), "", "", height).await?;
    }

    // Apply the "Sync all wallets" setting immediately: reconcile the background
    // pool with the (possibly just-changed) toggle.
    let pool = app.state::<crate::wallet::SyncPool>();
    match state.active_session().await {
        Some((id, pw)) => crate::commands::wallet::refresh_pool(&app, &state, &pool, &id, &pw).await,
        // Locked: can't start background sync without a password; if the toggle
        // is off, make sure nothing is left running.
        None => {
            if !crate::wallet::scanner::read_config_bool(&app, "sync_all_wallets") {
                pool.stop_all().await;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod reveal_guard_tests {
    use super::{reveal_guard, Path, PathBuf};

    // Two allowed bases, as reveal_path builds (already canonicalized in production).
    fn bases() -> Vec<PathBuf> {
        vec![PathBuf::from("/home/u/.app/data"), PathBuf::from("/home/u/.app/logs")]
    }

    #[test]
    fn accepts_a_dir_inside_an_allowed_base() {
        assert!(reveal_guard(Path::new("/home/u/.app/data/wallets"), &bases()).is_ok());
        assert!(reveal_guard(Path::new("/home/u/.app/logs"), &bases()).is_ok());
    }

    #[test]
    fn accepts_a_non_launchable_file_inside() {
        assert!(reveal_guard(Path::new("/home/u/.app/data/config.json"), &bases()).is_ok());
    }

    #[test]
    fn rejects_a_path_outside_every_base() {
        assert!(reveal_guard(Path::new("/etc/passwd"), &bases()).is_err());
        assert!(reveal_guard(Path::new("/home/u/.ssh/id_ed25519"), &bases()).is_err());
    }

    #[test]
    fn rejects_a_prefix_sibling_directory() {
        // Component-wise starts_with: "/home/u/.app/data-evil" must NOT match ".../data".
        assert!(reveal_guard(Path::new("/home/u/.app/data-evil/loot"), &bases()).is_err());
    }

    #[test]
    fn rejects_launch_capable_extensions_case_insensitively() {
        for name in ["payload.app", "run.sh", "x.EXE", "hook.desktop", "s.LNK", "a.scpt"] {
            let p = PathBuf::from("/home/u/.app/data").join(name);
            assert!(reveal_guard(&p, &bases()).is_err(), "{name} should be refused");
        }
    }
}
