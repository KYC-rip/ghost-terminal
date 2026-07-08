//! The loopback HTTP server + its runtime state. See `mod.rs` for the security model.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Emitter, Manager};
use tokio::net::TcpListener;
use tokio::sync::{watch, Mutex};

use crate::wallet::WalletState;

/// Persisted gateway config (stored under `agent_config` in config.json). camelCase to
/// round-trip cleanly with the renderer's `platform.agent` bridge.
#[derive(Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    pub enabled: bool,
    pub port: u16,
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// The armed transfer grant the agent may spend within. `None` → read-only gateway.
    #[serde(rename = "boundGrantId")]
    pub bound_grant_id: Option<String>,
    /// Which account the gateway serves (balance / invoice subaddresses).
    #[serde(rename = "accountIndex")]
    pub account_index: u32,
}

impl AgentConfig {
    fn fresh() -> Self {
        Self {
            enabled: false,
            port: 38084,
            api_key: gen_key(),
            bound_grant_id: None,
            account_index: 0,
        }
    }
}

/// A fresh access key (`RG-<24 hex>`). Rotating severs any agent still holding the old one.
pub fn gen_key() -> String {
    let mut b = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut b);
    format!("RG-{}", hex::encode(b).to_uppercase())
}

struct Runtime {
    config: AgentConfig,
    running: bool,
    /// Set to `true` to signal the accept loop to stop; taken on stop.
    shutdown: Option<watch::Sender<bool>>,
}

/// Tauri-managed runtime state for the gateway.
pub struct AgentGatewayState {
    inner: Mutex<Runtime>,
}

impl AgentGatewayState {
    pub fn new(config: AgentConfig) -> Self {
        Self {
            inner: Mutex::new(Runtime {
                config,
                running: false,
                shutdown: None,
            }),
        }
    }

    pub async fn config(&self) -> AgentConfig {
        self.inner.lock().await.config.clone()
    }

    pub async fn is_running(&self) -> bool {
        self.inner.lock().await.running
    }

    pub async fn set_config(&self, cfg: AgentConfig) {
        self.inner.lock().await.config = cfg;
    }
}

/// Constant-time byte compare for the API key, so a same-host attacker can't time the
/// key out byte-by-byte. Length differing short-circuits (a length oracle is harmless here).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

static ACTIVITY_SEQ: AtomicU64 = AtomicU64::new(0);

/// Piconero → decimal XMR string (full 12-dp precision, no rounding).
fn format_atomic(a: u64) -> String {
    format!("{}.{:012}", a / 1_000_000_000_000, a % 1_000_000_000_000)
}

/// Push one line to the renderer's live activity feed (`platform.agent.onActivity`).
fn activity(app: &AppHandle, kind: &str, msg: &str, ok: bool) {
    let seq = ACTIVITY_SEQ.fetch_add(1, Ordering::Relaxed);
    let _ = app.emit(
        "agent-activity",
        json!({
            "id": format!("{}-{}", now_ms(), seq),
            "type": kind.to_uppercase(),
            "msg": msg,
            "status": if ok { "ok" } else { "fail" },
            "timestamp": now_ms(),
        }),
    );
}

/// Read config.json's `agent_config` at startup, or mint a fresh default (with a new key).
pub fn load_config(app: &AppHandle) -> AgentConfig {
    let path = app
        .path()
        .app_data_dir()
        .map(|d| d.join("config.json"))
        .ok();
    if let Some(path) = path {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(a) = v.get("agent_config") {
                    if let Ok(cfg) = serde_json::from_value::<AgentConfig>(a.clone()) {
                        return cfg;
                    }
                }
            }
        }
    }
    AgentConfig::fresh()
}

/// Persist `agent_config` into config.json, merging over whatever is already there.
pub fn persist_config(app: &AppHandle, cfg: &AgentConfig) -> Result<(), String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("no app data dir: {e}"))?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("mkdir: {e}"))?;
    let path = dir.join("config.json");
    let mut root: serde_json::Value = std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str(&d).ok())
        .unwrap_or_else(|| json!({}));
    if let Some(obj) = root.as_object_mut() {
        obj.insert(
            "agent_config".to_string(),
            serde_json::to_value(cfg).map_err(|e| e.to_string())?,
        );
    }
    let data = serde_json::to_string_pretty(&root).map_err(|e| e.to_string())?;
    // Atomic write (tmp + rename) so a crash mid-write can't corrupt config.json.
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("write: {e}"))?;
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("commit config: {e}"));
    }
    Ok(())
}

/// Start the loopback server if it isn't already running. Idempotent.
pub async fn start(app: AppHandle) -> Result<(), String> {
    let gw = app.state::<AgentGatewayState>();
    let (port, mut rx) = {
        let mut rt = gw.inner.lock().await;
        if rt.running {
            return Ok(());
        }
        let (tx, rx) = watch::channel(false);
        rt.shutdown = Some(tx);
        (rt.config.port, rx)
    };

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            let mut rt = gw.inner.lock().await;
            rt.shutdown = None;
            return Err(format!("Failed to bind 127.0.0.1:{port}: {e}"));
        }
    };
    gw.inner.lock().await.running = true;
    crate::emit_log(
        &app,
        "Agent",
        "info",
        &format!("🤖 Agent gateway listening on 127.0.0.1:{port}"),
    );

    let app2 = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            tokio::select! {
                res = rx.changed() => {
                    // Sender dropped (Err) or a stop was signalled (value true) → exit.
                    if res.is_err() || *rx.borrow() { break; }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok((stream, _)) => {
                            let io = TokioIo::new(stream);
                            let app3 = app2.clone();
                            tauri::async_runtime::spawn(async move {
                                let service = service_fn(move |req| handle(req, app3.clone()));
                                let _ = http1::Builder::new().serve_connection(io, service).await;
                            });
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let gw = app2.state::<AgentGatewayState>();
        let mut rt = gw.inner.lock().await;
        rt.running = false;
        rt.shutdown = None;
        crate::emit_log(&app2, "Agent", "info", "🤖 Agent gateway stopped");
    });
    Ok(())
}

/// Signal the running server to stop (non-blocking; the accept loop unwinds shortly after).
pub async fn stop(app: &AppHandle) {
    let gw = app.state::<AgentGatewayState>();
    let tx = { gw.inner.lock().await.shutdown.take() };
    if let Some(tx) = tx {
        let _ = tx.send(true);
    }
}

async fn handle(
    req: Request<Incoming>,
    app: AppHandle,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let gw = app.state::<AgentGatewayState>();
    let cfg = gw.config().await;

    // Auth: `Authorization: Bearer <key>` or `X-Agent-Key: <key>`.
    let provided = {
        let h = req.headers();
        h.get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.strip_prefix("Bearer ").unwrap_or(s).trim().to_string())
            .or_else(|| {
                h.get("x-agent-key")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.trim().to_string())
            })
    };
    let auth_ok = !cfg.api_key.is_empty()
        && provided
            .as_deref()
            .map(|p| ct_eq(p.as_bytes(), cfg.api_key.as_bytes()))
            .unwrap_or(false);

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    if !auth_ok {
        activity(&app, "auth", "Unauthorized request rejected", false);
        return Ok(json_resp(
            StatusCode::UNAUTHORIZED,
            json!({ "error": "Unauthorized" }),
        ));
    }

    match route(&app, &cfg, method, &path, req).await {
        Ok(resp) => Ok(resp),
        Err((code, msg)) => Ok(json_resp(code, json!({ "error": msg }))),
    }
}

async fn route(
    app: &AppHandle,
    cfg: &AgentConfig,
    method: Method,
    path: &str,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, (StatusCode, String)> {
    let state = app.state::<WalletState>();
    match (&method, path) {
        (&Method::GET, "/sync") => {
            let s = state.get_sync_status().await;
            activity(app, "sync", "Agent queried sync status", true);
            Ok(json_resp(
                StatusCode::OK,
                serde_json::to_value(s).unwrap_or_else(|_| json!({})),
            ))
        }
        (&Method::GET, "/balance") => {
            let tip = state.get_scan_height().await;
            let (total, unlocked) = state.balances_for_account(cfg.account_index, tip).await;
            activity(
                app,
                "balance",
                &format!("Agent queried balance (account #{})", cfg.account_index),
                true,
            );
            Ok(json_resp(
                StatusCode::OK,
                json!({
                    "account": cfg.account_index,
                    "balance": format_atomic(total),
                    "unlocked": format_atomic(unlocked),
                    "atomic": { "balance": total, "unlocked": unlocked }
                }),
            ))
        }
        (&Method::GET, "/network") => {
            let net = state.get_network().await;
            Ok(json_resp(
                StatusCode::OK,
                json!({ "network": format!("{:?}", net).to_lowercase() }),
            ))
        }
        (&Method::POST, "/subaddress") => {
            let body = read_json(req).await?;
            let label = body
                .get("label")
                .and_then(|v| v.as_str())
                .unwrap_or("AGENT_INVOICE")
                .to_string();
            let sub = state
                .create_subaddress(cfg.account_index, &label)
                .await
                .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
            activity(
                app,
                "subaddress",
                &format!("Agent created invoice subaddress '{label}'"),
                true,
            );
            Ok(json_resp(
                StatusCode::OK,
                json!({ "address": sub.address, "index": sub.index, "label": label }),
            ))
        }
        (&Method::POST, "/transfer") => {
            // Spending is ONLY ever within a user-armed grant. No grant bound → refuse.
            let grant_id = cfg.bound_grant_id.clone().ok_or((
                StatusCode::FORBIDDEN,
                "no armed grant bound — the gateway is read-only until you bind a spend grant"
                    .to_string(),
            ))?;
            let body = read_json(req).await?;
            let to = body
                .get("address")
                .and_then(|v| v.as_str())
                .ok_or((StatusCode::BAD_REQUEST, "missing 'address'".to_string()))?
                .to_string();
            let amount = body
                .get("amount")
                .and_then(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_f64().map(|f| format!("{f}")))
                })
                .ok_or((StatusCode::BAD_REQUEST, "missing 'amount'".to_string()))?;

            let to_short = to.chars().take(8).collect::<String>();
            match crate::commands::transfer_grant::relay_transfer_grant(
                app.clone(),
                app.state::<WalletState>(),
                grant_id,
                to.clone(),
                amount.clone(),
            )
            .await
            {
                Ok(txid) => {
                    let tx_short = txid.chars().take(8).collect::<String>();
                    activity(
                        app,
                        "transfer",
                        &format!("Agent paid {amount} XMR → {to_short}… (tx {tx_short}…)"),
                        true,
                    );
                    Ok(json_resp(
                        StatusCode::OK,
                        json!({ "status": "PAID", "txid": txid }),
                    ))
                }
                Err(e) => {
                    activity(app, "transfer", &format!("Transfer blocked: {e}"), false);
                    Err((StatusCode::BAD_REQUEST, e))
                }
            }
        }
        _ => Err((StatusCode::NOT_FOUND, "not found".to_string())),
    }
}

async fn read_json(req: Request<Incoming>) -> Result<serde_json::Value, (StatusCode, String)> {
    let bytes = req
        .into_body()
        .collect()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("body read error: {e}")))?
        .to_bytes();
    if bytes.is_empty() {
        return Ok(json!({}));
    }
    serde_json::from_slice(&bytes)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid JSON: {e}")))
}

fn json_resp(code: StatusCode, body: serde_json::Value) -> Response<Full<Bytes>> {
    let data = serde_json::to_vec(&body).unwrap_or_default();
    Response::builder()
        .status(code)
        .header("content-type", "application/json")
        .header("access-control-allow-origin", "*")
        .body(Full::new(Bytes::from(data)))
        .unwrap_or_else(|_| Response::new(Full::new(Bytes::from_static(b"{}"))))
}
