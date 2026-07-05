//! Miscellaneous app/system commands: pick a skin background image, and check
//! GitHub for app updates.

use std::time::Duration;
use tauri::{AppHandle, Manager};
use serde_json::{json, Value};

use base64::Engine;
use tauri_plugin_dialog::DialogExt;

const RELEASES_LATEST: &str = "https://api.github.com/repos/KYC-rip/ripley-terminal/releases/latest";
const RELEASES_LIST: &str = "https://api.github.com/repos/KYC-rip/ripley-terminal/releases";
const MAX_BACKGROUND_BYTES: usize = 5 * 1024 * 1024;

/// Open a native file picker and return the chosen image as a base64 data URL
/// (the renderer stores it in config.skin_background). Returns None if the user
/// cancels; errors if the file is unreadable or exceeds 5 MB.
#[tauri::command]
pub async fn select_background_image(app: AppHandle) -> Result<Option<String>, String> {
    let picked = app
        .dialog()
        .file()
        .add_filter("Images", &["jpg", "jpeg", "png", "gif", "webp"])
        .blocking_pick_file();

    let Some(file) = picked else {
        return Ok(None); // user cancelled
    };
    let path = file.into_path().map_err(|e| format!("Invalid path: {e}"))?;
    let bytes = std::fs::read(&path).map_err(|e| format!("Failed to read image: {e}"))?;
    if bytes.len() > MAX_BACKGROUND_BYTES {
        return Err("Image exceeds the 5 MB limit".into());
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("png")
        .to_lowercase();
    let mime = match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        _ => "image/png",
    };
    let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(Some(format!("data:{};base64,{}", mime, b64)))
}

/// Check GitHub for a newer release. Routes through the configured uplink (Tor /
/// custom proxy / clearnet). Always returns gracefully: any failure (including a
/// Tor exit node blocked by GitHub) yields { success: false } so the UI simply
/// shows no update banner.
#[tauri::command]
pub async fn check_for_updates(app: AppHandle, include_prereleases: bool) -> Result<Value, String> {
    let url = if include_prereleases { RELEASES_LIST } else { RELEASES_LATEST };

    let fetched: Result<Vec<u8>, String> = match crate::wallet::scanner::read_routing_mode(&app).as_str() {
        "tor" => match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => crate::tor::tor_get(&tor, url).await,
            None => Err("Tor not available".into()),
        },
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(&app);
            if proxy.trim().is_empty() {
                Err("No proxy address set".into())
            } else {
                crate::tor::socks_get(&proxy, url).await
            }
        }
        _ => {
            // Clearnet via reqwest. GitHub requires a User-Agent.
            async {
                let resp = reqwest::Client::new()
                    .get(url)
                    .header("User-Agent", concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")))
                    .timeout(Duration::from_secs(10))
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                resp.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string())
            }
            .await
        }
    };

    let bytes = match fetched {
        Ok(b) => b,
        Err(e) => return Ok(json!({ "success": false, "error": e })),
    };
    let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    // /releases returns an array (take the first); /releases/latest is an object.
    let release = if include_prereleases {
        parsed.as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null)
    } else {
        parsed
    };

    let tag = release.get("tag_name").and_then(|t| t.as_str()).unwrap_or("");
    if tag.is_empty() {
        return Ok(json!({ "success": false, "error": "No release found" }));
    }
    let latest = tag.trim_start_matches('v');
    let current = env!("CARGO_PKG_VERSION");

    Ok(json!({
        "success": true,
        "hasUpdate": version_gt(latest, current),
        "latestVersion": latest,
        "releaseUrl": release.get("html_url").and_then(|u| u.as_str()).unwrap_or(""),
        "body": release.get("body").and_then(|b| b.as_str()).unwrap_or(""),
        "publishedAt": release.get("published_at").and_then(|p| p.as_str()).unwrap_or(""),
    }))
}

/// The kyc.rip API .onion mirror. In Tor/custom mode, api.kyc.rip requests are
/// rewritten to this hidden service so no exit node is used and nothing leaks the
/// user's IP. The onion serves the same API under a `/api` prefix (clearnet
/// `https://api.kyc.rip/v1/x` → `http://<onion>/api/v1/x`).
const KYC_API_ONION: &str = "kycripxmrmlmkfaqf4hwchilhtrp36nu6vyjoh3e7rmsgmyylxfm25ad.onion";

/// Fetch a URL through the CONFIGURED uplink (Tor / SOCKS / clearnet), returning the
/// body as a string. The renderer routes its external API calls (stats/price,
/// address ban-check, market validate, xmr.bio, …) through this so none of them
/// leak the user's IP via a direct clearnet `fetch()` while Tor is enabled.
#[tauri::command]
pub async fn proxied_get(app: AppHandle, url: String) -> Result<String, String> {
    let mode = crate::wallet::scanner::read_routing_mode(&app);
    // Route kyc.rip through its onion when not on clearnet (no exit node, no IP leak).
    let target = if mode != "clearnet" {
        url.replace("https://api.kyc.rip", &format!("http://{KYC_API_ONION}/api"))
    } else {
        url.clone()
    };

    let bytes: Result<Vec<u8>, String> = match mode.as_str() {
        "tor" => match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => crate::tor::tor_get(&tor, &target).await,
            None => Err("Tor is enabled but not connected yet".into()),
        },
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(&app);
            if proxy.trim().is_empty() {
                Err("Custom routing selected but no proxy address is set".into())
            } else {
                crate::tor::socks_get(&proxy, &target).await
            }
        }
        _ => {
            async {
                let resp = reqwest::Client::new()
                    .get(&target)
                    .header("User-Agent", concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")))
                    .timeout(Duration::from_secs(15))
                    .send()
                    .await
                    .map_err(|e| e.to_string())?;
                resp.bytes().await.map(|b| b.to_vec()).map_err(|e| e.to_string())
            }
            .await
        }
    };

    String::from_utf8(bytes?).map_err(|e| format!("non-UTF-8 response: {e}"))
}

/// Compare two dotted versions numerically (ignoring any -prerelease/+build
/// suffix). Returns true if `a` is strictly newer than `b`.
fn version_gt(a: &str, b: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split(['-', '+'])
            .next()
            .unwrap_or("")
            .trim_start_matches('v')
            .split('.')
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (va, vb) = (parse(a), parse(b));
    for i in 0..va.len().max(vb.len()) {
        let x = va.get(i).copied().unwrap_or(0);
        let y = vb.get(i).copied().unwrap_or(0);
        if x != y {
            return x > y;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::version_gt;
    #[test]
    fn compares_versions() {
        assert!(version_gt("2.1.0", "2.0.0"));
        assert!(version_gt("2.0.1", "2.0.0"));
        assert!(version_gt("v2.0.0", "1.9.9"));
        assert!(!version_gt("2.0.0", "2.0.0"));
        assert!(!version_gt("2.0.0", "2.0.1"));
        assert!(version_gt("2.1.0-beta", "2.0.0"));
        assert!(!version_gt("2.0.0-beta", "2.0.0")); // prerelease suffix ignored
    }
}
