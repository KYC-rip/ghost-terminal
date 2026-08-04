// Release-mode layout computation of the deeply-nested async commands (e.g.
// prepare_transfer's tx_deadline(async { match { …await? } }) watchdog) exceeds the
// default query depth of 128. Raise it so `cargo tauri build` (release) compiles —
// dev builds compute shallower layouts and didn't surface this.
#![recursion_limit = "512"]

mod agent;
mod commands;
mod dns_filter;
mod tor;
mod updater;
#[cfg(target_os = "macos")]
pub mod vpn_macos;
mod wallet;

use tauri::{AppHandle, Emitter, Manager};

/// Where remote RipleyOS lives in the beta phase. Session B (signed-OTA) replaces
/// this with the verified local `ros://local/index.html` bundle — this constant is
/// the single line that changes.
const ROS_REMOTE_URL: &str = "https://app.ros.rip";

/// Dev-build default for `ui_mode=ros`: the local ripley-os dev server (vite,
/// pinned :5174 — the classic renderer's dev server is pinned :5173/devUrl).
/// `ROS_URL` still overrides both defaults.
const ROS_DEV_URL: &str = "http://localhost:5174";

/// Emit a log event to the frontend console (same format as Electron's core-log).
pub fn emit_log(app: &AppHandle, source: &str, level: &str, message: &str) {
    // Mirror app-console logs to stdout so they're visible when running headless /
    // via the dev server (the emit below only reaches the frontend window). Skip
    // the high-frequency SYNC_DATA/TOR_STATUS machine channels to avoid spam.
    if source != "SYNC_DATA" && source != "TOR_STATUS" && source != "BALANCE_DATA" {
        println!("[{}/{}] {}", source, level, message);
    }
    let _ = app.emit(
        "core-log",
        serde_json::json!({
            "source": source,
            "level": level,
            "message": message,
        }),
    );
}

/// Push a balance update to the frontend (piconero). Piggybacked on core-log with
/// source "BALANCE_DATA" (same workaround as sync status), message "total|unlocked".
/// The renderer maps this to a BALANCE_CHANGED event.
pub fn emit_balance(app: &AppHandle, total: u64, unlocked: u64) {
    let _ = app.emit(
        "core-log",
        serde_json::json!({
            "source": "BALANCE_DATA",
            "level": "info",
            "message": format!("{}|{}", total, unlocked),
        }),
    );
}

/// Emit sync status through the core-log channel (workaround for custom events
/// not reaching JS listeners from background tokio tasks in Tauri v2).
pub fn emit_sync_status(
    app: &AppHandle,
    status: &str,
    height: u64,
    daemon_height: u64,
    percent: f64,
    node_label: &str,
    scan_start: u64,
) {
    // Fields: status|height|daemon_height|percent|node|scan_start. scan_start is the
    // height this sync began from (restore baseline) so the UI can show progress
    // RELATIVE to the restore range, not to the whole chain.
    let _ = app.emit("core-log", serde_json::json!({
        "source": "SYNC_DATA",
        "level": "info",
        "message": format!("{}|{}|{}|{:.1}|{}|{}", status, height, daemon_height, percent, node_label, scan_start),
    }));
}

/// Work around WebKitGTK triggering NVIDIA's Wayland EGL path during startup.
///
/// `WEBKIT_DISABLE_DMABUF_RENDERER` alone is not enough on some current
/// NVIDIA/Wayland stacks: WebKitGTK still creates a Wayland EGL display and the
/// driver can segfault before Tauri gets a window on screen. If XWayland is
/// available, make GTK choose it before GTK/WebKit initialization. Leave every
/// explicit user choice intact, and keep native Wayland for non-NVIDIA systems.
#[cfg(target_os = "linux")]
fn configure_linux_webview_environment() {
    let wayland_session = std::env::var("XDG_SESSION_TYPE")
        .map(|session| session.eq_ignore_ascii_case("wayland"))
        .unwrap_or(false)
        || std::env::var_os("WAYLAND_DISPLAY").is_some();
    let nvidia_loaded = std::path::Path::new("/proc/driver/nvidia/version").exists()
        || std::path::Path::new("/sys/module/nvidia").exists();

    if !wayland_session || !nvidia_loaded {
        return;
    }

    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }

    // `DISPLAY` is provided by XWayland on normal KDE/GNOME Wayland sessions.
    // Do not force X11 without it: a Wayland-only environment should retain its
    // user-selected backend rather than fail with an opaque display error.
    let xwayland_available = std::env::var_os("DISPLAY")
        .map(|display| !display.is_empty())
        .unwrap_or(false);
    if std::env::var_os("GDK_BACKEND").is_none() && xwayland_available {
        std::env::set_var("GDK_BACKEND", "x11");
        eprintln!("[linux] NVIDIA + Wayland detected; using XWayland for WebKitGTK stability");
    } else if !xwayland_available {
        eprintln!("[linux] NVIDIA + Wayland detected but no XWayland display is available; keeping the configured GDK backend");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    configure_linux_webview_environment();

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
        .plugin(tauri_plugin_clipboard_manager::init())
        // The ros:// protocol: the sole content source for the OTA (ros_source=ota) ROS
        // window. Serves the in-memory, on-device-verified bundle managed as RosBundle.
        // We attach the app CSP to HTML responses ourselves so the untrusted bundle is
        // always sandboxed (script-src 'self', object-src 'none', …) regardless of whether
        // Tauri injects its config CSP into a manually-registered scheme.
        .register_uri_scheme_protocol("ros", |ctx, request| {
            let uri = request.uri().to_string();
            let resp = match ctx.app_handle().try_state::<updater::protocol::RosBundle>() {
                Some(bundle) => bundle.resolve(&uri),
                None => updater::protocol::RosResponse {
                    status: 503,
                    content_type: "text/plain",
                    body: b"ROS bundle not loaded".to_vec(),
                },
            };
            let mut builder = tauri::http::Response::builder()
                .status(resp.status)
                .header(tauri::http::header::CONTENT_TYPE, resp.content_type);
            if resp.content_type == "text/html" {
                builder = builder
                    .header("Content-Security-Policy", updater::protocol::ROS_CSP);
            }
            builder
                .body(std::borrow::Cow::<'static, [u8]>::Owned(resp.body))
                .unwrap_or_else(|_| {
                    tauri::http::Response::new(std::borrow::Cow::Borrowed(&b""[..]))
                })
        })
        .setup(|app| {
            // OS-level deep links (ripley:// for "Sign in with Ripley", plus monero:/
            // xmr402: opened outside the app). The plugin captures the URI; we forward
            // each one to the frontend as a DEEP_LINK core-log line, which native.ts
            // routes to the right wallet flow (osHandleSiwr / osHandleXmr402 / send).
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let dl_app = app.handle().clone();
                app.deep_link().on_open_url(move |event| {
                    for url in event.urls() {
                        crate::emit_log(&dl_app, "DEEP_LINK", "info", url.as_str());
                    }
                });
                // Cold start: a URL that LAUNCHED the app is available via get_current()
                // (the on_open_url listener above only fires for links received while
                // running). Emit it on a delay — at setup() the webview isn't up yet, so
                // its DEEP_LINK listener would miss an immediate emit. A short wait lets
                // the frontend mount first (mirrors the Tor bootstrap spawn below).
                if let Ok(Some(urls)) = app.deep_link().get_current() {
                    let boot = app.handle().clone();
                    tauri::async_runtime::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                        for url in urls {
                            crate::emit_log(&boot, "DEEP_LINK", "info", url.as_str());
                        }
                    });
                }
            }

            // Initialize wallet state manager
            let wallet_state = wallet::WalletState::new(app.handle().clone());
            app.manage(wallet_state);

            // Initialize Tor client
            let tor_state = tor::TorState::new();
            app.manage(tor_state);

            // Background sync pool ("Sync all wallets")
            app.manage(wallet::SyncPool::new());

            // Agent gateway (loopback HTTP server for autonomous agents). Loaded from
            // config; auto-started only if the user previously enabled it. Spending is
            // gated by an armed transfer grant, so a cold/locked wallet is read-only.
            let agent_cfg = agent::gateway::load_config(&app.handle());
            let agent_enabled = agent_cfg.enabled;
            app.manage(agent::AgentGatewayState::new(agent_cfg));
            if agent_enabled {
                let h = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    let _ = agent::gateway::start(h).await;
                });
            }

            // Native Local AI owns one process-wide llama.cpp backend and keeps the
            // selected GGUF model resident between turns. The ROS capability exposes
            // only fixed model ids and lifecycle commands—never paths or executables.
            app.manage(commands::local_ai::NativeLocalAiState::new()?);

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

            // The main window is built HERE, not declared in tauri.conf.json, so its
            // URL follows the persisted `ui_mode`: "classic" → the bundled legacy
            // renderer (full `default` capability — local-context only), "ros" →
            // remote RipleyOS, which the URL-scoped `ros_remote` capability limits
            // to the wallet invoke surface (no fs/shell/dialog/core:default).
            // Built AFTER every manage() above so an early IPC call finds its state.
            let ui_mode = commands::config::read_ui_mode(app.handle());
            // Within ros mode, `ros_source` selects WHERE the UI comes from: "beta" =
            // remote app.ros.rip (fast iteration), "ota" = the on-device verified
            // ros://local bundle (the stable signed path). Default beta so a bad OTA
            // bundle can never strand the user.
            let ros_source = commands::config::read_ros_source(app.handle());
            // ROS_URL is a DEV-ONLY override. In release it is IGNORED (with a loud
            // warning if set): a shipped wallet must never be pointed at an
            // attacker-chosen origin via an env var — that origin would inherit the
            // ros_remote wallet-command surface. Release ROS mode is always the pinned
            // app.ros.rip (Session B: the local ros:// bundle).
            let ros_override = std::env::var("ROS_URL")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            #[cfg(not(debug_assertions))]
            let ros_override: Option<String> = {
                if let Some(u) = &ros_override {
                    println!("[UI/warn] ROS_URL={u} ignored in release build (dev-only override)");
                }
                None
            };
            let classic_url = || tauri::WebviewUrl::App("index.html".into());
            // The OTA (ros://) window uses a DISTINCT label so the broad local `default`
            // capability (windows:["main"]) cannot reach it — a ros:// page is local
            // context, so a shared "main" label would leak fs/shell to the untrusted
            // bundle (verified empirically). Only the actually-loaded ros:// window is
            // "ros"; any fallback to the classic renderer stays "main" (it needs default).
            let mut window_label: &str = "main";
            let window_url = if ui_mode == "ros" && ros_source == "ota" {
                // Stable path: serve the on-device VERIFIED bundle over ros://. The bundle
                // is loaded + re-verified here (cache, else the pinned bundled fallback)
                // and managed so the ros:// protocol handler can serve it. A None return
                // means even the fallback failed its pinned hash (binary integrity gone) —
                // fail closed to classic rather than load anything unverified.
                match updater::load_bundle_at_launch(app.handle()) {
                    Some(bundle) => {
                        app.manage(bundle);
                        match "ros://local/index.html".parse::<tauri::Url>() {
                            Ok(u) => {
                                window_label = "ros";
                                tauri::WebviewUrl::CustomProtocol(u)
                            }
                            Err(e) => {
                                println!("[ota/error] bad ros:// url ({e}) — booting classic");
                                classic_url()
                            }
                        }
                    }
                    None => {
                        println!("[ota] no loadable ROS bundle — booting classic");
                        classic_url()
                    }
                }
            } else if ui_mode == "ros" {
                // Beta path: remote app.ros.rip in production; dev builds default to the
                // local ripley-os dev server (:5174). ROS_URL overrides either.
                let default_ros =
                    if cfg!(debug_assertions) { ROS_DEV_URL } else { ROS_REMOTE_URL };
                let raw = ros_override.clone().unwrap_or_else(|| default_ros.to_string());
                match raw.parse::<tauri::Url>() {
                    Ok(u) => {
                        // Any non-production origin (the dev default, or a ROS_URL
                        // override) won't match the static ros_remote capability — so
                        // re-grant the SAME permission set for that origin at runtime
                        // (parse the shipped file and swap the URL, so the two surfaces
                        // can never drift).
                        if raw != ROS_REMOTE_URL {
                            println!("[UI/warn] loading RipleyOS from non-production origin {raw}");
                            let mut cap: serde_json::Value =
                                serde_json::from_str(include_str!("../capabilities/ros_remote.json"))
                                    .expect("ros_remote.json is valid JSON");
                            cap["identifier"] = serde_json::json!("ros-remote-override");
                            cap["remote"]["urls"] = serde_json::json!([raw]);
                            app.handle().add_capability(cap.to_string())?;
                        }
                        tauri::WebviewUrl::External(u)
                    }
                    Err(e) => {
                        // A broken URL must not brick the app — boot classic instead.
                        println!("[UI/error] invalid ROS url \"{raw}\" ({e}) — falling back to classic");
                        classic_url()
                    }
                }
            } else {
                classic_url()
            };
            tauri::WebviewWindowBuilder::new(app, window_label, window_url)
                .title("Ripley Terminal")
                .inner_size(1200.0, 800.0)
                .min_inner_size(900.0, 600.0)
                .build()?;

            // Watch tier boot: use persisted view keys to start a view-only scan
            // before a wallet is unlocked. This needs the watch key from the OS
            // keychain. On first use, explain that request in our own words before
            // macOS presents its generic Keychain password dialog.
            let watch_boot = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};

                // File-backed cache key: no prompts, safe unconditionally.
                wallet::device_key::init_file_key(&watch_boot);
                if !crate::wallet::scanner::read_config_bool(&watch_boot, "watchSync") {
                    return;
                }

                // Give the desktop shell time to become visible before placing any
                // permission UI in front of it. This is intentionally a short grace
                // period rather than a renderer readiness dependency: the boot sync
                // path must work for both the local and remote ROS UIs.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;

                if !crate::wallet::scanner::read_config_bool(&watch_boot, "watchSyncKeychainExplained") {
                    let continue_sync = watch_boot
                        .dialog()
                        .message(
                            "Watch Sync can update your balances and transaction history before you unlock a wallet.\n\nTo start it, Ripley Terminal needs access to its encrypted watch-only key in your macOS Keychain. It never reads your wallet password, recovery phrase, or spend key.\n\nmacOS may ask for your login Keychain password next.",
                        )
                        .title("Start Watch Sync")
                        .buttons(MessageDialogButtons::OkCancelCustom(
                            "Continue".into(),
                            "Not now".into(),
                        ))
                        .blocking_show();
                    if !continue_sync {
                        emit_log(
                            &watch_boot,
                            "Wallet",
                            "info",
                            "👁 Watch sync was skipped at startup — it will be offered again next launch.",
                        );
                        return;
                    }
                }

                if !wallet::device_key::ensure_watch_key(&watch_boot).await {
                    emit_log(&watch_boot, "Wallet", "warn",
                        "👁 Watch sync is enabled but the system keychain refused the key — skipping boot sync (re-enable in Settings ▸ Node to retry).");
                    return;
                }
                // Record the explanation only after Keychain access succeeded. If
                // macOS denies it, show the context again on the next launch.
                let _ = commands::config::set_config_bool(
                    &watch_boot,
                    "watchSyncKeychainExplained",
                    true,
                )
                .await;

                let data_dir = watch_boot
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."));
                let ids = wallet::storage::list_watch_ids(&data_dir);
                if !ids.is_empty() {
                    emit_log(&watch_boot, "Sync", "info", &format!(
                        "👁 Watch sync: starting view-only scan for {} wallet(s) before unlock…", ids.len()));
                    let pool = watch_boot.state::<wallet::SyncPool>();
                    for id in ids {
                        if let Some(vp) = wallet::storage::load_watch(&data_dir, &id) {
                            pool.start(&watch_boot, id, vp, 0).await;
                        }
                    }
                }
            });

            // Signed-OTA: only in ota mode, check the update channel in the background and
            // STAGE any newer verified bundle for the NEXT launch (never hot-swap — decision
            // #2). Best-effort + fail-closed; mirrors the Tor-boot spawn (short delay so the
            // window is up first, and Tor has a moment to bootstrap for the routed fetch).
            if ros_source == "ota" {
                let ota_boot = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(8)).await;
                    let r = updater::check_and_stage_update(&ota_boot).await;
                    if let Some(e) = &r.error {
                        emit_log(&ota_boot, "OTA", "warn", &format!("update check failed: {e}"));
                    } else if r.updated {
                        emit_log(&ota_boot, "OTA", "info",
                            &format!("staged RipleyOS v{} — applies next launch", r.version.unwrap_or_default()));
                    } else {
                        emit_log(&ota_boot, "OTA", "info", "RipleyOS is up to date");
                    }
                });
            }

            log::info!("Ripley Terminal v2 initialized (ui_mode={ui_mode})");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::system::clipboard_write_image,
            commands::system::capture_window_png,
            // Wallet lifecycle
            commands::wallet::create_wallet,
            commands::wallet::open_wallet,
            commands::wallet::close_wallet,
            commands::wallet::get_mnemonic,
            commands::wallet::sign_message,
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
            commands::wallet::sign_message,
            commands::wallet::check_tx_key,
            commands::wallet::check_tx_proof,
            // Sync
            commands::wallet::get_sync_status,
            commands::wallet::refresh,
            commands::wallet::set_vigil_hot,
            commands::wallet::verify_password,
            commands::wallet::change_wallet_password,
            commands::wallet::rescan,
            // Config
            commands::config::get_config,
            commands::config::save_config,
            commands::config::save_config_only,
            commands::config::watch_sync_set,
            commands::config::save_config_and_reload,
            commands::config::get_app_info,
            commands::config::reveal_path,
            commands::config::get_ui_mode,
            commands::config::set_ui_mode,
            updater::check_ros_update,
            updater::ros_channel_status,
            // Client-side metadata stores + system
            commands::kvstore::save_ghost_trade,
            commands::kvstore::get_ghost_trades,
            commands::kvstore::save_xmr402_payment,
            commands::kvstore::get_xmr402_payment,
            commands::kvstore::get_all_xmr402_payments,
            commands::system::select_background_image,
            commands::system::check_for_updates,
            commands::system::proxied_get,
            commands::system::agent_web_read,
            commands::system::resolve_openalias,
            commands::system::ros_native_fetch,
            commands::system::ros_native_fetch_bytes,
            commands::wallpaper::wallpaper_save,
            commands::wallpaper::wallpaper_url,
            commands::wallpaper::wallpaper_clear,
            commands::system::open_native_browser,
            commands::system::open_external_url,
            commands::system::browser_embed_open,
            commands::system::browser_embed_bounds,
            commands::system::browser_embed_navigate,
            commands::system::browser_embed_zoom,
            commands::system::browser_embed_visible,
            commands::system::browser_embed_close,
            commands::system::browser_embed_deliver_xmr402,
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
            // VPN (unprivileged client of the root-owned broker)
            commands::vpn::vpn_status,
            commands::vpn::vpn_probe_endpoints,
            commands::vpn::vpn_probe_exit_ip,
            commands::vpn::vpn_connect,
            commands::vpn::vpn_disconnect,
            commands::vpn::vpn_set_killswitch,
            commands::vpn::vpn_recover,
            commands::vpn::vpn_set_dns_filter,
            commands::vpn::vpn_cache_endpoints,
            commands::vpn::vpn_emergency_restore,
            commands::vpn::vpn_open_window,
            commands::vpn::vpn_set_locale,
            commands::vpn::vpn_profiles_load,
            commands::vpn::vpn_profiles_save,
            commands::vpn::vpn_profiles_clear,
            // Vigil (limit-order persistence)
            commands::vigil::vigil_save_strike_key,
            commands::vigil::vigil_get_strike_key,
            commands::vigil::vigil_delete_strike_key,
            commands::vigil::vigil_archive_strike_key,
            commands::vigil::vigil_save_session,
            commands::vigil::vigil_get_session,
            commands::vigil::vigil_clear_session,
            commands::vigil::fetch_price_history,
            // Transfer grants (EJECT autonomous sells)
            commands::transfer_grant::arm_transfer_grant,
            commands::transfer_grant::relay_transfer_grant,
            commands::transfer_grant::revoke_transfer_grant,
            commands::transfer_grant::revoke_all_transfer_grants,
            commands::transfer_grant::transfer_grant_status,
            commands::agent_gateway::agent_gateway_status,
            commands::agent_gateway::agent_gateway_set_config,
            commands::agent_gateway::agent_gateway_rotate_key,
            // Native Local AI (fixed, pinned GGUF registry)
            commands::local_ai::local_ai_status,
            commands::local_ai::local_ai_download,
            commands::local_ai::local_ai_load,
            commands::local_ai::local_ai_complete,
            commands::local_ai::local_ai_remove,
            commands::local_ai::local_ai_clear_all,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
