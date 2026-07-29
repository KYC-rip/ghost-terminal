//! VPN Tauri commands — the UNPRIVILEGED client of the root-owned broker.
//!
//! These commands hold NO privilege themselves: they marshal a structured
//! request to `ripley-vpn-broker` over its peer-credential-checked Unix socket
//! and relay the reply. All parsing/validation and every kernel/network mutation
//! happen inside the broker (see ../../../broker). A renderer that reaches these
//! commands can still only ask the broker for a *structured* operation — never a
//! shell string, config path, or nft snippet.
//!
//! Capability split (keep in sync with capabilities/ros_local.json):
//!   - `vpn_status` + `vpn_open_window` — the ONLY VPN surface granted to the
//!     `ros` (OTA) renderer: read status, and ask the host to open its own VPN
//!     window. It gets NOTHING that mutates.
//!   - `vpn_connect` / `vpn_disconnect` / `vpn_set_killswitch` / `vpn_recover`
//!     are NOT granted to the renderer; they are invokable only from the native
//!     host window (the trusted, host-owned confirmation surface).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};

const SOCK: &str = "/run/ripley-vpn.sock";
const PROTOCOL: u32 = 1;
const IO_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_RESP: usize = 64 * 1024;

fn next_id() -> String {
    // Correlation only; the broker treats ids as opaque. Millis + a coarse
    // counter is plenty to line a reply up with its request in logs.
    format!("ros-{}", chrono::Utc::now().timestamp_millis())
}

/// One blocking round-trip to the broker: connect, send one JSON line, read one
/// JSON line. Returns the `status` object on success, or the broker's `reason`.
fn broker_call(request: Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(SOCK)
        .map_err(|e| format!("VPN broker unavailable ({e}). Is ripley-vpn-broker running?"))?;
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

    let env = json!({ "protocol": PROTOCOL, "id": next_id(), "request": request });
    let mut line = serde_json::to_string(&env).map_err(|e| e.to_string())?;
    line.push('\n');
    stream.write_all(line.as_bytes()).map_err(|e| e.to_string())?;

    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_RESP {
                    return Err("broker response too large".into());
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err(format!("broker read: {e}")),
        }
    }
    if buf.is_empty() {
        return Err("broker closed the connection without replying".into());
    }

    let resp: Value = serde_json::from_slice(&buf).map_err(|e| format!("bad broker reply: {e}"))?;
    match resp.get("result").and_then(|v| v.as_str()) {
        Some("ok") => Ok(resp.get("status").cloned().unwrap_or(Value::Null)),
        Some(_) => Err(resp
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("broker error")
            .to_string()),
        None => Err("malformed broker response".into()),
    }
}

/// Run the blocking broker round-trip off the async runtime's worker threads.
async fn call(request: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || broker_call(request))
        .await
        .map_err(|e| e.to_string())?
}

/// Read-only status. Safe to expose to the OTA renderer.
#[tauri::command]
pub async fn vpn_status() -> Result<Value, String> {
    call(json!({ "op": "status" })).await
}

/// Bring the tunnel up from raw `.conf` text. The broker parses+validates it
/// (parse-as-data) and seals the fail-closed egress block before any wg/route
/// change. Host-window only.
#[tauri::command]
pub async fn vpn_connect(config_text: String) -> Result<Value, String> {
    call(json!({ "op": "up", "config_text": config_text })).await
}

/// Tear down the tunnel. `restore = false` keeps the egress block (fail-closed);
/// `restore = true` re-opens clearnet (the broker gates this as a strong op).
/// Host-window only.
#[tauri::command]
pub async fn vpn_disconnect(restore: bool) -> Result<Value, String> {
    let op = if restore { "disconnect_and_restore_clearnet" } else { "disconnect_blocked" };
    call(json!({ "op": op })).await
}

/// Enable/disable the kill-switch. Host-window only. Disabling is a broker-side
/// strong op and is refused while a tunnel is up.
#[tauri::command]
pub async fn vpn_set_killswitch(on: bool) -> Result<Value, String> {
    let op = if on { "enable_kill_switch" } else { "disable_kill_switch" };
    call(json!({ "op": op })).await
}

/// Reconcile toward the fail-closed blocked state (clears stale rules WITHOUT
/// re-opening egress). Host-window only.
#[tauri::command]
pub async fn vpn_recover() -> Result<Value, String> {
    call(json!({ "op": "reconcile_blocked_state" })).await
}

/// Ask the host to surface its own VPN control window. The OTA renderer may call
/// this (it opens host UI, it does not mutate). We focus the native host window
/// and emit `vpn:open` so the host shell routes to its VPN panel — full control
/// lives in the host surface, never in the embedded renderer.
#[tauri::command]
pub async fn vpn_open_window(app: AppHandle) -> Result<(), String> {
    // The host surface is the "main" window in the classic shell and the "ros"
    // window in the OTA shell — focus whichever exists, then broadcast so the
    // shell routes to its VPN panel.
    for label in ["main", "ros"] {
        if let Some(win) = app.get_webview_window(label) {
            let _ = win.show();
            let _ = win.set_focus();
            break;
        }
    }
    app.emit("vpn:open", ()).map_err(|e| e.to_string())
}
