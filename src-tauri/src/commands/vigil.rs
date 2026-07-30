//! Vigil (limit-order) persistence — the Tauri side of the Electron
//! VigilHandler. Stores the strike-wallet key as an OPAQUE encrypted blob
//! (AES-GCM ciphertext produced in the renderer; the backend never decrypts)
//! plus armed-session snapshots that carry NO key material. Retired keys are
//! archived, never deleted, so a mistaken rotation can never strand funds.
//!
//! Mirrors VigilHandler.ts validation: identity id charset, blob shape/size,
//! session version/mode/phase, and a defense-in-depth key-material scan.

use serde_json::{json, Value};
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

const MAX_SESSION_BYTES: usize = 16 * 1024;
const VIGIL_SESSION_VERSION: u64 = 1;

fn vigil_path(app: &AppHandle) -> PathBuf {
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("vigil.json")
}

fn load(app: &AppHandle) -> Value {
    match std::fs::read_to_string(vigil_path(app)) {
        Ok(data) => serde_json::from_str(&data).unwrap_or_else(|_| default_store()),
        Err(_) => default_store(),
    }
}

fn default_store() -> Value {
    json!({ "strike_keys": {}, "strike_keys_retired": {}, "sessions": {} })
}

fn persist(app: &AppHandle, store: &Value) -> Result<(), String> {
    let path = vigil_path(app);
    std::fs::create_dir_all(path.parent().unwrap())
        .map_err(|e| format!("Failed to create data dir: {}", e))?;
    std::fs::write(&path, serde_json::to_string_pretty(store).unwrap())
        .map_err(|e| format!("Failed to write vigil store: {}", e))
}

/// Single source of truth for the identity-id charset, shared with the wallet
/// storage path-builder so every id that reaches disk is validated identically.
fn valid_id(id: &str) -> bool {
    crate::wallet::storage::valid_identity_id(id)
}

fn is_b64(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// Strike-key blob shape: { v: 1, salt, iv, ct } (all base64).
fn valid_key_blob(blob: &Value) -> bool {
    blob.get("v").and_then(|v| v.as_u64()) == Some(1)
        && blob
            .get("salt")
            .and_then(|v| v.as_str())
            .map(|s| is_b64(s, 64))
            .unwrap_or(false)
        && blob
            .get("iv")
            .and_then(|v| v.as_str())
            .map(|s| is_b64(s, 64))
            .unwrap_or(false)
        && blob
            .get("ct")
            .and_then(|v| v.as_str())
            .map(|s| is_b64(s, 4096))
            .unwrap_or(false)
}

fn valid_session(session: &Value) -> Result<(), String> {
    if !session.is_object() {
        return Err("Session must be an object".into());
    }
    if session.get("version").and_then(|v| v.as_u64()) != Some(VIGIL_SESSION_VERSION) {
        return Err("Unsupported session version".into());
    }
    let mode = session.get("mode").and_then(|v| v.as_str()).unwrap_or("");
    if mode != "SNIPE" && mode != "EJECT" {
        return Err("Invalid mode".into());
    }
    let phase = session.get("phase").and_then(|v| v.as_str()).unwrap_or("");
    if !["ARMED", "EXECUTING", "POLLING"].contains(&phase) {
        return Err("Invalid phase".into());
    }
    let serialized = session.to_string();
    if serialized.len() > MAX_SESSION_BYTES {
        return Err("Session too large".into());
    }
    // Defense in depth: sessions must never carry key material
    let lower = serialized.to_lowercase();
    if lower.contains("privatekey") || lower.contains("mnemonic") || lower.contains("seed") {
        return Err("Session must not contain key material".into());
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── Strike key blobs (opaque ciphertext) ──

#[tauri::command]
pub async fn vigil_save_strike_key(
    app: AppHandle,
    identity_id: String,
    blob: Value,
) -> Result<(), String> {
    if !valid_id(&identity_id) {
        return Err("Invalid identity id".into());
    }
    if !valid_key_blob(&blob) {
        return Err("Invalid key blob".into());
    }
    let mut store = load(&app);
    store["strike_keys"][&identity_id] = blob;
    persist(&app, &store)
}

#[tauri::command]
pub async fn vigil_get_strike_key(app: AppHandle, identity_id: String) -> Result<Value, String> {
    if !valid_id(&identity_id) {
        return Ok(Value::Null);
    }
    Ok(load(&app)["strike_keys"]
        .get(&identity_id)
        .cloned()
        .unwrap_or(Value::Null))
}

#[tauri::command]
pub async fn vigil_delete_strike_key(app: AppHandle, identity_id: String) -> Result<(), String> {
    if !valid_id(&identity_id) {
        return Err("Invalid identity id".into());
    }
    let mut store = load(&app);
    if let Some(obj) = store["strike_keys"].as_object_mut() {
        obj.remove(&identity_id);
    }
    persist(&app, &store)
}

/// Move the current blob to a timestamped retired archive (never deleted) so
/// a mistaken rotation can never permanently strand funds.
#[tauri::command]
pub async fn vigil_archive_strike_key(app: AppHandle, identity_id: String) -> Result<(), String> {
    if !valid_id(&identity_id) {
        return Err("Invalid identity id".into());
    }
    let mut store = load(&app);
    if let Some(blob) = store["strike_keys"].get(&identity_id).cloned() {
        if !store["strike_keys_retired"]
            .get(&identity_id)
            .map(|v| v.is_array())
            .unwrap_or(false)
        {
            store["strike_keys_retired"][&identity_id] = json!([]);
        }
        let mut retired_blob = blob;
        if let Some(obj) = retired_blob.as_object_mut() {
            obj.insert("retiredAt".into(), json!(now_ms()));
        }
        store["strike_keys_retired"][&identity_id]
            .as_array_mut()
            .unwrap()
            .push(retired_blob);
        if let Some(obj) = store["strike_keys"].as_object_mut() {
            obj.remove(&identity_id);
        }
    }
    persist(&app, &store)
}

// ── Session snapshots (no key material) ──

#[tauri::command]
pub async fn vigil_save_session(
    app: AppHandle,
    identity_id: String,
    session: Value,
) -> Result<(), String> {
    if !valid_id(&identity_id) {
        return Err("Invalid identity id".into());
    }
    valid_session(&session)?;
    let mut store = load(&app);
    store["sessions"][&identity_id] = session;
    persist(&app, &store)
}

#[tauri::command]
pub async fn vigil_get_session(app: AppHandle, identity_id: String) -> Result<Value, String> {
    if !valid_id(&identity_id) {
        return Ok(Value::Null);
    }
    Ok(load(&app)["sessions"]
        .get(&identity_id)
        .cloned()
        .unwrap_or(Value::Null))
}

#[tauri::command]
pub async fn vigil_clear_session(app: AppHandle, identity_id: String) -> Result<(), String> {
    if !valid_id(&identity_id) {
        return Err("Invalid identity id".into());
    }
    let mut store = load(&app);
    if let Some(obj) = store["sessions"].as_object_mut() {
        obj.remove(&identity_id);
    }
    persist(&app, &store)
}

// ── Price history seed (Kraken OHLC) ──

fn valid_pair(pair: &str) -> bool {
    // e.g. "XMR/USD" — two 2-8 char alphanumeric legs
    match pair.split_once('/') {
        Some((a, b)) => {
            let ok = |s: &str| {
                (2..=8).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphanumeric())
            };
            ok(a) && ok(b)
        }
        None => false,
    }
}

/// Seed the vigil chart with 1-minute OHLC closes. Kraken's REST API blocks
/// browser CORS, so the renderer cannot fetch this directly — we do it here.
/// Returns { success, points: [{ time, value }] } | { success: false, error }.
/// NOTE: clearnet, matching the existing nodes.json fetch in scanner.rs;
/// Tor-routing the app's outbound HTTP is a separate follow-up. The renderer
/// degrades gracefully (live-tick accumulation) when this fails.
#[tauri::command]
pub async fn fetch_price_history(app: AppHandle, pair: String) -> Result<Value, String> {
    if !valid_pair(&pair) {
        return Ok(json!({ "success": false, "error": "Invalid pair" }));
    }
    let rest_pair = pair.replace('/', "");
    let url = format!(
        "https://api.kraken.com/0/public/OHLC?pair={}&interval=1",
        rest_pair
    );

    // In Tor mode, fetch over Tor (with TLS) so the price probe doesn't leak the
    // user IP. Both paths degrade gracefully — a failure just returns
    // { success:false } and the renderer falls back to live-tick accumulation.
    let routing = crate::wallet::scanner::read_routing_mode(&app);
    let raw: Vec<u8> = if routing == "tor" {
        match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => match crate::tor::tor_get(&tor, &url).await {
                Ok(bytes) => bytes,
                Err(e) => return Ok(json!({ "success": false, "error": format!("Tor: {}", e) })),
            },
            None => return Ok(json!({ "success": false, "error": "Tor not available" })),
        }
    } else if routing == "custom" {
        let proxy = crate::wallet::scanner::read_proxy_address(&app);
        if proxy.trim().is_empty() {
            return Ok(json!({ "success": false, "error": "No proxy address set" }));
        }
        match crate::tor::socks_get(&proxy, &url).await {
            Ok(bytes) => bytes,
            Err(e) => return Ok(json!({ "success": false, "error": format!("Proxy: {}", e) })),
        }
    } else {
        let resp = match reqwest::Client::new().get(&url).send().await {
            Ok(r) => r,
            Err(e) => return Ok(json!({ "success": false, "error": format!("{}", e) })),
        };
        match resp.bytes().await {
            Ok(b) => b.to_vec(),
            Err(e) => return Ok(json!({ "success": false, "error": format!("{}", e) })),
        }
    };
    let data: Value = match serde_json::from_slice(&raw) {
        Ok(v) => v,
        Err(e) => return Ok(json!({ "success": false, "error": format!("{}", e) })),
    };

    if let Some(errs) = data.get("error").and_then(|e| e.as_array()) {
        if !errs.is_empty() {
            let msg: Vec<String> = errs
                .iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect();
            return Ok(json!({ "success": false, "error": msg.join(", ") }));
        }
    }

    // result is an object keyed by the resolved pair name plus a "last" field
    let result = match data.get("result").and_then(|r| r.as_object()) {
        Some(r) => r,
        None => return Ok(json!({ "success": false, "error": "No OHLC data" })),
    };
    let candles = result
        .iter()
        .find(|(k, _)| k.as_str() != "last")
        .map(|(_, v)| v);
    let candles = match candles.and_then(|c| c.as_array()) {
        Some(c) => c,
        None => return Ok(json!({ "success": false, "error": "No OHLC data" })),
    };

    // Candle: [time, open, high, low, close, vwap, volume, count] — keep closes
    let points: Vec<Value> = candles
        .iter()
        .filter_map(|c| {
            let arr = c.as_array()?;
            let time = arr.first()?.as_u64()?;
            let close: f64 = arr.get(4)?.as_str()?.parse().ok()?;
            if time > 0 && close > 0.0 {
                Some(json!({ "time": time, "value": close }))
            } else {
                None
            }
        })
        .collect();

    Ok(json!({ "success": true, "points": points }))
}
