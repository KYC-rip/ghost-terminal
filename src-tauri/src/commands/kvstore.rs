//! Small JSON key-value stores for client-side metadata the renderer tracks:
//! ghost-trade tags (which txs were atomic swaps) and XMR402 payment receipts
//! (to dedupe deep-link replays). Plain JSON files in the app data dir — no
//! secrets, already-on-chain or public metadata only. Single-user desktop app,
//! so writes are last-writer-wins (no locking).

use serde_json::{json, Map, Value};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

const GHOST_TRADES_FILE: &str = "ghost_trades.json";
const XMR402_FILE: &str = "xmr402_payments.json";
const GHOST_TTL_SECS: u64 = 7 * 24 * 60 * 60; // prune ghost trades older than 7 days

fn store_path(app: &AppHandle, file: &str) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(file)
}

fn load_map(app: &AppHandle, file: &str) -> Map<String, Value> {
    let path = store_path(app, file);
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str::<Value>(&d).ok())
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

fn save_map(app: &AppHandle, file: &str, map: &Map<String, Value>) -> Result<(), String> {
    let path = store_path(app, file);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Failed to create dir: {}", e))?;
    }
    let data = serde_json::to_string_pretty(map).map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(&path, data).map_err(|e| format!("Write error: {}", e))
}

fn now_secs() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

// ── Ghost trades (atomic-swap tags), keyed by tx hash ──

#[tauri::command]
pub async fn save_ghost_trade(
    app: AppHandle,
    tx_hash: String,
    trade_id: String,
) -> Result<(), String> {
    let mut map = load_map(&app, GHOST_TRADES_FILE);
    map.insert(
        tx_hash,
        json!({ "tradeId": trade_id, "timestamp": now_secs() }),
    );
    save_map(&app, GHOST_TRADES_FILE, &map)
}

/// Returns the ghost-trade map, pruning entries older than 7 days. NOTE: prunes
/// on read (write-back); a failed write-back just leaves stale entries to be
/// pruned next time — harmless.
#[tauri::command]
pub async fn get_ghost_trades(app: AppHandle) -> Result<Value, String> {
    let mut map = load_map(&app, GHOST_TRADES_FILE);
    let cutoff = now_secs().saturating_sub(GHOST_TTL_SECS);
    let before = map.len();
    map.retain(|_, v| v.get("timestamp").and_then(|t| t.as_u64()).unwrap_or(0) >= cutoff);
    if map.len() != before {
        let _ = save_map(&app, GHOST_TRADES_FILE, &map);
    }
    Ok(Value::Object(map))
}

// ── XMR402 payment receipts, keyed by txid; looked up by nonce ──

#[tauri::command]
pub async fn save_xmr402_payment(
    app: AppHandle,
    nonce: String,
    txid: String,
    proof: String,
    amount: String,
    return_url: Option<String>,
) -> Result<(), String> {
    let mut map = load_map(&app, XMR402_FILE);
    map.insert(
        txid,
        json!({
            "nonce": nonce,
            "amount": amount,
            "proof": proof,
            "returnUrl": return_url,
            "timestamp": now_secs(),
        }),
    );
    save_map(&app, XMR402_FILE, &map)
}

/// Look up a stored payment by its nonce. Returns the receipt (with its txid
/// injected) or null if not found.
#[tauri::command]
pub async fn get_xmr402_payment(app: AppHandle, nonce: String) -> Result<Value, String> {
    let map = load_map(&app, XMR402_FILE);
    for (txid, entry) in &map {
        if entry.get("nonce").and_then(|n| n.as_str()) == Some(nonce.as_str()) {
            let mut found = entry.clone();
            if let Some(obj) = found.as_object_mut() {
                obj.insert("txid".to_string(), json!(txid));
            }
            return Ok(found);
        }
    }
    Ok(Value::Null)
}

#[tauri::command]
pub async fn get_all_xmr402_payments(app: AppHandle) -> Result<Value, String> {
    Ok(Value::Object(load_map(&app, XMR402_FILE)))
}
