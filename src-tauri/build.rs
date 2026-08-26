/// Every command registered in `tauri::generate_handler!` (lib.rs). Declaring them
/// here generates `allow-<command>` / `deny-<command>` ACL permissions AND — the
/// actual point — flips Tauri's IPC authority into enforcing mode for app commands
/// (`has_app_acl_manifest` in tauri's webview/mod.rs): without an app manifest,
/// app commands are NOT ACL-checked at all, so any webview with the IPC injected
/// (including the `ros-embed` child webview showing arbitrary remote pages) could
/// invoke wallet commands. With it, a webview can only call what a capability
/// matching its window + URL context explicitly allows:
///   - capabilities/default.json    → the local classic renderer (everything)
///   - capabilities/ros_remote.json → remote RipleyOS (wallet surface only)
///   - anything else (ros-embed, ros-browser-* windows) → nothing.
const APP_COMMANDS: &[&str] = &[
    // Wallet lifecycle
    "create_wallet",
    "open_wallet",
    "close_wallet",
    "get_mnemonic",
    // Account operations
    "get_accounts",
    "create_account",
    "rename_account",
    "get_balance",
    "get_height",
    // Address operations
    "get_subaddresses",
    "create_subaddress",
    "set_subaddress_label",
    "estimate_fees",
    // Transaction operations
    "prepare_transfer",
    "relay_transfer",
    "sweep_all",
    "sweep_single",
    "reselect_node",
    "get_transactions",
    "get_outputs",
    // Proof operations
    "get_tx_key",
    "get_tx_proof",
    "sign_message",
    "check_tx_key",
    "check_tx_proof",
    // Sync
    "get_sync_status",
    "refresh",
    "set_vigil_hot",
    "verify_password",
    "change_wallet_password",
    "rescan",
    // Config
    "get_config",
    "save_config",
    "save_config_only",
    "save_config_and_reload",
    "watch_sync_set",
    "get_app_info",
    "reveal_path",
    "get_ui_mode",
    "set_ui_mode",
    // Signed-OTA update channel for the RipleyOS bundle
    "check_ros_update",
    "ros_channel_status",
    // Client-side metadata stores + system
    "save_ghost_trade",
    "get_ghost_trades",
    "save_xmr402_payment",
    "get_xmr402_payment",
    "get_all_xmr402_payments",
    "ros_kv_load",
    "ros_kv_set",
    "ros_kv_remove",
    "ros_kv_clear",
    "select_background_image",
    "check_for_updates",
    "proxied_get",
    "agent_web_read",
    // Window screenshot (RipleyOS ⌘-leader + I): snapshot the webview region, and put the PNG on
    // the clipboard — the webview itself has no image clipboard.
    "capture_window_png",
    "clipboard_write_image",
    "resolve_openalias",
    "ros_native_fetch",
    "open_native_browser",
    "open_external_url",
    "browser_embed_open",
    "browser_embed_bounds",
    "browser_embed_navigate",
    "browser_embed_zoom",
    "browser_embed_visible",
    "browser_embed_close",
    "browser_embed_deliver_xmr402",
    // Identity
    "get_identities",
    "save_identities",
    "detect_legacy_wallets",
    "create_identity",
    "delete_identity",
    "switch_identity",
    "get_active_identity",
    "rename_identity",
    // Tor
    "get_tor_status",
    "tor_circuit",
    "restart_tor",
    // VPN (unprivileged client of the root-owned broker)
    "vpn_status",
    "vpn_probe_endpoints",
    "vpn_probe_exit_ip",
    "vpn_connect",
    "vpn_disconnect",
    "vpn_set_killswitch",
    "vpn_recover",
    "vpn_set_dns_filter",
    "vpn_cache_endpoints",
    "vpn_emergency_restore",
    "vpn_open_window",
    "vpn_set_locale",
    "vpn_profiles_load",
    "vpn_profiles_save",
    "vpn_profiles_clear",
    // Vigil (limit-order persistence)
    "vigil_save_strike_key",
    "vigil_get_strike_key",
    "vigil_delete_strike_key",
    "vigil_archive_strike_key",
    "vigil_save_session",
    "vigil_get_session",
    "vigil_clear_session",
    "fetch_price_history",
    // Transfer grants (EJECT autonomous sells) + agent gateway
    "arm_transfer_grant",
    "relay_transfer_grant",
    "revoke_transfer_grant",
    "revoke_all_transfer_grants",
    "transfer_grant_status",
    "agent_gateway_status",
    "agent_gateway_set_config",
    "agent_gateway_rotate_key",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(APP_COMMANDS)),
    )
    .expect("failed to run tauri-build");
}
