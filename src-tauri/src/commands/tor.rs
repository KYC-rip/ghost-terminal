use tauri::{AppHandle, State};
use crate::tor::TorState;

#[tauri::command]
pub async fn get_tor_status(state: State<'_, TorState>) -> Result<serde_json::Value, String> {
    let status = state.get_status().await;
    Ok(serde_json::to_value(status).map_err(|e| e.to_string())?)
}

/// Report the current Tor circuit's EXIT node (ip · country · city · org), fetched
/// over Tor. arti abstracts the guard/middle relays (privacy-by-design; its client
/// API doesn't expose a live stream's path), so the exit — what the internet sees —
/// is the meaningful, reliable datum for the circuit panel.
#[tauri::command]
pub async fn tor_circuit(state: State<'_, TorState>) -> Result<serde_json::Value, String> {
    let client = state.get_client().await.ok_or_else(|| "Tor not connected".to_string())?;
    let body = crate::tor::tor_get(&client, "https://ipinfo.io/json").await?;
    let info: serde_json::Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    Ok(serde_json::json!({
        "exit": {
            "ip": info.get("ip").and_then(|v| v.as_str()),
            "country": info.get("country").and_then(|v| v.as_str()),
            "city": info.get("city").and_then(|v| v.as_str()),
            "org": info.get("org").and_then(|v| v.as_str()),
        }
    }))
}

#[tauri::command]
pub async fn restart_tor(app: AppHandle, state: State<'_, TorState>) -> Result<String, String> {
    state.disconnect().await;
    state.connect(&app).await?;
    Ok("Tor connected".to_string())
}
