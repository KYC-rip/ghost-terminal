//! Tauri commands backing the renderer's `platform.agent` bridge: read status, patch
//! config (which reconciles the running server), and rotate the access key.

use serde_json::json;
use tauri::{AppHandle, Manager};

use crate::agent::{gateway, AgentGatewayState};
use crate::wallet::WalletState;

fn mask_key(k: &str) -> String {
    if k.len() <= 4 {
        return "RG-…".to_string();
    }
    format!("RG-…{}", &k[k.len() - 4..])
}

async fn status_json(app: &AppHandle) -> serde_json::Value {
    let gw = app.state::<AgentGatewayState>();
    let cfg = gw.config().await;
    let running = gw.is_running().await;
    let address = app.state::<WalletState>().get_primary_address().await;
    json!({
        "enabled": cfg.enabled,
        "running": running,
        "port": cfg.port,
        "apiKeyMasked": mask_key(&cfg.api_key),
        "boundGrantId": cfg.bound_grant_id,
        "accountIndex": cfg.account_index,
        "address": address,
    })
}

#[tauri::command]
pub async fn agent_gateway_status(app: AppHandle) -> Result<serde_json::Value, String> {
    Ok(status_json(&app).await)
}

/// Patch the gateway config, persist it, and reconcile the running server. `patch` is a
/// partial object — only the keys present are applied. Returns the fresh status.
#[tauri::command]
pub async fn agent_gateway_set_config(
    app: AppHandle,
    patch: serde_json::Value,
) -> Result<serde_json::Value, String> {
    let gw = app.state::<AgentGatewayState>();
    let mut cfg = gw.config().await;
    let old_port = cfg.port;

    if let Some(v) = patch.get("enabled").and_then(|v| v.as_bool()) {
        cfg.enabled = v;
    }
    if let Some(v) = patch.get("port").and_then(|v| v.as_u64()) {
        cfg.port = v as u16;
    }
    // boundGrantId is nullable: an explicit null clears it (back to read-only).
    if patch.get("boundGrantId").is_some() {
        cfg.bound_grant_id = patch
            .get("boundGrantId")
            .and_then(|v| if v.is_null() { None } else { v.as_str().map(String::from) });
    }
    if let Some(v) = patch.get("accountIndex").and_then(|v| v.as_u64()) {
        cfg.account_index = v as u32;
    }

    gw.set_config(cfg.clone()).await;
    gateway::persist_config(&app, &cfg)?;

    // Reconcile the listener. boundGrantId / accountIndex are read live per-request, so
    // only enable/port changes need to touch the server.
    let running = gw.is_running().await;
    let port_changed = old_port != cfg.port;
    if cfg.enabled && (!running || port_changed) {
        if running && port_changed {
            gateway::stop(&app).await;
            // Give the accept loop a beat to drop the old listener before re-binding.
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        }
        gateway::start(app.clone()).await?;
    } else if !cfg.enabled && running {
        gateway::stop(&app).await;
    }

    Ok(status_json(&app).await)
}

/// Mint a new access key (severs agents holding the old one). Returns the full key ONCE.
#[tauri::command]
pub async fn agent_gateway_rotate_key(app: AppHandle) -> Result<serde_json::Value, String> {
    let gw = app.state::<AgentGatewayState>();
    let mut cfg = gw.config().await;
    cfg.api_key = gateway::gen_key();
    gw.set_config(cfg.clone()).await;
    gateway::persist_config(&app, &cfg)?;
    Ok(json!({ "apiKey": cfg.api_key }))
}
