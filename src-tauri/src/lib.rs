// Release-mode layout computation of the deeply-nested async commands (e.g.
// prepare_transfer's tx_deadline(async { match { …await? } }) watchdog) exceeds the
// default query depth of 128. Raise it so `cargo tauri build` (release) compiles —
// dev builds compute shallower layouts and didn't surface this.
#![recursion_limit = "512"]

mod commands;
mod wallet;
mod tor;

use tauri::{AppHandle, Emitter, Manager};

/// Emit a log event to the frontend console (same format as Electron's core-log).
pub fn emit_log(app: &AppHandle, source: &str, level: &str, message: &str) {
    // Mirror app-console logs to stdout so they're visible when running headless /
    // via the dev server (the emit below only reaches the frontend window). Skip
    // the high-frequency SYNC_DATA/TOR_STATUS machine channels to avoid spam.
    if source != "SYNC_DATA" && source != "TOR_STATUS" && source != "BALANCE_DATA" {
        println!("[{}/{}] {}", source, level, message);
    }
    let _ = app.emit("core-log", serde_json::json!({
        "source": source,
        "level": level,
        "message": message,
    }));
}

/// Push a balance update to the frontend (piconero). Piggybacked on core-log with
/// source "BALANCE_DATA" (same workaround as sync status), message "total|unlocked".
/// The renderer maps this to a BALANCE_CHANGED event.
pub fn emit_balance(app: &AppHandle, total: u64, unlocked: u64) {
    let _ = app.emit("core-log", serde_json::json!({
        "source": "BALANCE_DATA",
        "level": "info",
        "message": format!("{}|{}", total, unlocked),
    }));
}

/// Emit sync status through the core-log channel (workaround for custom events
/// not reaching JS listeners from background tokio tasks in Tauri v2).
pub fn emit_sync_status(app: &AppHandle, status: &str, height: u64, daemon_height: u64, percent: f64, node_label: &str, scan_start: u64) {
    // Fields: status|height|daemon_height|percent|node|scan_start. scan_start is the
    // height this sync began from (restore baseline) so the UI can show progress
    // RELATIVE to the restore range, not to the whole chain.
    let _ = app.emit("core-log", serde_json::json!({
        "source": "SYNC_DATA",
        "level": "info",
        "message": format!("{}|{}|{}|{:.1}|{}|{}", status, height, daemon_height, percent, node_label, scan_start),
    }));
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    // WebKitGTK's DMABUF/EGL renderer segfaults on the NVIDIA driver during
    // platform-display init (crash lands in libnvidia-egl-wayland), especially on
    // Wayland — a well-known WebKit/NVIDIA bug that takes down the whole app on
    // launch. Disable the DMABUF renderer so the webview uses a safe path. Set
    // before the webview is created (Builder::run below). Overridable: we only set
    // it when the user hasn't already, so power users can opt back in.
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
            std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
        }
    }

    // Install a process-wide rustls crypto provider (ring) BEFORE any TLS is
    // used. Adding tokio-rustls (for TLS-over-Tor) left rustls without an
    // unambiguous default provider, which made the clearnet transport
    // (simple-request) panic on every connection — surfacing as "all nodes
    // failed" even for nodes that are perfectly reachable.
    let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            // Initialize wallet state manager
            let wallet_state = wallet::WalletState::new(app.handle().clone());
            app.manage(wallet_state);

            // Initialize Tor client
            let tor_state = tor::TorState::new();
            app.manage(tor_state);

            // Background sync pool ("Sync all wallets")
            app.manage(wallet::SyncPool::new());

            // Bootstrap Tor at startup — but ONLY if the user's routing mode is Tor.
            // The wallet scanner connects Tor lazily on first use; a hosted RipleyOS
            // renderer never runs the scanner, so without this its native fetches
            // (window.__rosNative → ros_native_fetch) sit at "Tor not connected".
            // Respects the user's choice (clearnet/custom → we don't force Tor);
            // arti's bootstrap is idempotent, so it won't fight the lazy path.
            let tor_boot = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // Bootstrap Tor at startup regardless of routing mode: .onion domains
                // (first-party api.kyc.rip and explicit onions) route over Tor even in
                // clearnet mode, so the client must be ready. This makes Tor AVAILABLE,
                // not forced — general clearnet traffic still goes direct.
                let _ = crate::wallet::scanner::ensure_tor(&tor_boot).await;
            });

            log::info!("Ripley Terminal v2 initialized");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // Wallet lifecycle
            commands::wallet::create_wallet,
            commands::wallet::open_wallet,
            commands::wallet::close_wallet,
            commands::wallet::get_mnemonic,
            // Account operations
            commands::wallet::get_accounts,
            commands::wallet::create_account,
            commands::wallet::rename_account,
            commands::wallet::get_balance,
            commands::wallet::get_height,
            // Address operations
            commands::wallet::get_subaddresses,
            commands::wallet::create_subaddress,
            commands::wallet::set_subaddress_label,
            commands::wallet::estimate_fees,
            // Transaction operations
            commands::wallet::prepare_transfer,
            commands::wallet::relay_transfer,
            commands::wallet::sweep_all,
            commands::wallet::sweep_single,
            commands::wallet::reselect_node,
            commands::wallet::get_transactions,
            commands::wallet::get_outputs,
            // Proof operations
            commands::wallet::get_tx_key,
            commands::wallet::get_tx_proof,
            commands::wallet::check_tx_key,
            commands::wallet::check_tx_proof,
            // Sync
            commands::wallet::get_sync_status,
            commands::wallet::refresh,
            commands::wallet::set_vigil_hot,
            commands::wallet::verify_password,
            commands::wallet::rescan,
            // Config
            commands::config::get_config,
            commands::config::save_config,
            commands::config::save_config_only,
            commands::config::save_config_and_reload,
            commands::config::get_app_info,
            commands::config::reveal_path,
            // Client-side metadata stores + system
            commands::kvstore::save_ghost_trade,
            commands::kvstore::get_ghost_trades,
            commands::kvstore::save_xmr402_payment,
            commands::kvstore::get_xmr402_payment,
            commands::kvstore::get_all_xmr402_payments,
            commands::system::select_background_image,
            commands::system::check_for_updates,
            commands::system::proxied_get,
            commands::system::ros_native_fetch,
            commands::system::open_native_browser,
            commands::system::browser_embed_open,
            commands::system::browser_embed_bounds,
            commands::system::browser_embed_navigate,
            commands::system::browser_embed_visible,
            commands::system::browser_embed_close,
            // Identity
            commands::identity::get_identities,
            commands::identity::save_identities,
            commands::identity::detect_legacy_wallets,
            commands::identity::create_identity,
            commands::identity::delete_identity,
            commands::identity::switch_identity,
            commands::identity::get_active_identity,
            commands::identity::rename_identity,
            // Tor
            commands::tor::get_tor_status,
            commands::tor::tor_circuit,
            commands::tor::restart_tor,
            // Vigil (limit-order persistence)
            commands::vigil::vigil_save_strike_key,
            commands::vigil::vigil_get_strike_key,
            commands::vigil::vigil_delete_strike_key,
            commands::vigil::vigil_archive_strike_key,
            commands::vigil::vigil_save_session,
            commands::vigil::vigil_get_session,
            commands::vigil::vigil_clear_session,
            commands::vigil::fetch_price_history,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
