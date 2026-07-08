//! Miscellaneous app/system commands: pick a skin background image, and check
//! GitHub for app updates.

use std::time::Duration;
use tauri::{AppHandle, Manager};
use serde_json::{json, Value};

use base64::Engine;
use tauri_plugin_dialog::DialogExt;

use crate::wallet::WalletState;
use monero_address::MoneroAddress;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

/// Default DoH resolver for OpenAlias (RFC 8484 binary wire format). Mullvad —
/// privacy-focused, no-logging, DNSSEC-validating. MUST speak HTTP/1.1: our Tor
/// transport (`http_over_stream`) is hyper http1-only, and Quad9's DoH is
/// HTTP/2-only (returns 505 over HTTP/1.1) so it can't be used over Tor here.
/// Resolver-agnostic: any RFC 8484 HTTP/1.1-capable DoH endpoint works, so
/// promoting this to a user setting later is a one-line change.
const OPENALIAS_DOH_ENDPOINT: &str = "https://dns.mullvad.net/dns-query";

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

/// True if the URL's host is a `.onion` (case-INSENSITIVE — an uppercase `.ONION`
/// must not slip past). A `.onion` is only reachable over Tor, so every egress path
/// forces such a target through Tor regardless of the configured routing mode;
/// otherwise it would DNS-leak to the system resolver / connect direct in clearnet
/// mode. Matches on the parsed host so a `.onion` string in a path/query can't
/// false-trigger; falls back to a lowercase substring scan for scheme-less inputs.
fn is_onion(url: &str) -> bool {
    match tauri::Url::parse(url) {
        Ok(u) => u
            .host_str()
            .map(|h| h.to_ascii_lowercase().ends_with(".onion"))
            .unwrap_or(false),
        Err(_) => url.to_ascii_lowercase().contains(".onion"),
    }
}

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

    // A .onion is only reachable over Tor — force it through Tor regardless of the
    // configured mode, and REFUSE (never fall back to clearnet) if Tor isn't up, so
    // an onion target can never leak to the system resolver / a direct connection.
    let route = if is_onion(&target) { "tor" } else { mode.as_str() };
    let bytes: Result<Vec<u8>, String> = match route {
        "tor" => match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => crate::tor::tor_get(&tor, &target).await,
            None => Err("Tor is not connected yet (required for this request)".into()),
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

#[derive(serde::Deserialize)]
pub struct RosFetchReq {
    pub url: String,
    pub method: Option<String>,
    pub headers: Option<std::collections::HashMap<String, String>>,
    pub body: Option<String>,
}

/// General HTTP behind a hosted RipleyOS renderer (window.__rosNative.fetch).
/// Routes through the CONFIGURED uplink like `proxied_get`, but supports any method
/// + body so ROS's rosFetch() works (e.g. POST /v2/exchange/create) over Tor with
/// NO CORS. api.kyc.rip is rewritten to its .onion in Tor/custom mode (no exit
/// node, no IP leak). Returns { ok, status, body }; status is exact for clearnet/
/// custom (reqwest) and coarse for the Tor arti path (the transport treats non-2xx
/// as an error → surfaced as ok:false).
#[tauri::command]
pub async fn ros_native_fetch(app: AppHandle, req: RosFetchReq) -> Result<Value, String> {
    let mode = crate::wallet::scanner::read_routing_mode(&app);
    let method = req.method.as_deref().unwrap_or("GET").to_uppercase();
    let body = req.body.clone().unwrap_or_default().into_bytes();
    let has_body = !body.is_empty();
    let target = if mode != "clearnet" {
        req.url.replace("https://api.kyc.rip", &format!("http://{KYC_API_ONION}/api"))
    } else {
        req.url.clone()
    };

    // A .onion is only reachable over Tor — force it through Tor regardless of the
    // routing mode (so first-party api.kyc.rip → onion, and any explicit .onion, stay
    // on Tor even in clearnet mode; general clearnet traffic still goes direct).
    let route = if is_onion(&target) { "tor" } else { mode.as_str() };
    let outcome: Result<(u16, Vec<u8>), String> = match route {
        "tor" => match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => {
                if method == "GET" && !has_body {
                    crate::tor::tor_get(&tor, &target).await.map(|b| (200u16, b))
                } else {
                    let (https, host, port, path) = crate::tor::parse_url(&target)?;
                    if https {
                        // POST-over-Tor+TLS isn't in the arti transport yet; ROS's
                        // writes go to api.kyc.rip → onion (plain HTTP), so this only
                        // bites non-kyc.rip https POSTs.
                        Err(format!("{method} to https over Tor not supported yet: {host}"))
                    } else {
                        let m = hyper::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
                        crate::tor::tor_http(&tor, m, &host, port, &path, body, None).await.map(|b| (200u16, b))
                    }
                }
            }
            None => Err("Tor is enabled but not connected yet".into()),
        },
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(&app);
            if proxy.trim().is_empty() {
                Err("Custom routing selected but no proxy address is set".into())
            } else {
                // reqwest's `socks` feature routes any method through the SOCKS5 proxy.
                match reqwest::Proxy::all(&proxy) {
                    Ok(px) => ros_reqwest(reqwest::Client::builder().proxy(px), &method, &target, &req.headers, &body, has_body).await,
                    Err(e) => Err(e.to_string()),
                }
            }
        }
        _ => ros_reqwest(reqwest::Client::builder(), &method, &target, &req.headers, &body, has_body).await,
    };

    match outcome {
        Ok((status, bytes)) => Ok(json!({ "ok": status < 400, "status": status, "body": String::from_utf8_lossy(&bytes) })),
        Err(e) => Ok(json!({ "ok": false, "status": 502, "body": e })),
    }
}

/// Shared reqwest send (clearnet + custom-SOCKS): full method/headers/body → (status, body).
async fn ros_reqwest(
    builder: reqwest::ClientBuilder,
    method: &str,
    url: &str,
    headers: &Option<std::collections::HashMap<String, String>>,
    body: &[u8],
    has_body: bool,
) -> Result<(u16, Vec<u8>), String> {
    let client = builder.timeout(Duration::from_secs(30)).build().map_err(|e| e.to_string())?;
    let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
    let mut rb = client
        .request(m, url)
        .header("User-Agent", concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")));
    if let Some(hs) = headers {
        for (k, v) in hs {
            rb = rb.header(k, v);
        }
    }
    if has_body {
        rb = rb.body(body.to_vec());
    }
    let resp = rb.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let bytes = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
    Ok((status, bytes))
}

/// Open a real native browser window at `url`. The ROS Browser app uses this when
/// hosted so ANY site renders — no X-Frame-Options / iframe limits (an iframe can't
/// show google.com etc.).
///
/// Egress follows the user's routing `mode` (same switch as the rest of the shell):
/// "tor" → our loopback arti SOCKS proxy (Tor); "custom" → the user's proxy;
/// anything else → clearnet/direct. The user decides the mode — but we REFUSE to
/// open (rather than silently go direct) when Tor mode is selected yet Tor isn't
/// ready, or when the target is a .onion outside Tor mode (see resolve_browser_proxy).
///
/// The webview proxy is fixed at CREATE time (can't be changed later), so we close
/// any prior browser window and open a fresh one each time — that guarantees the
/// current routing mode is applied (a reused window would keep its old proxy).
static BROWSER_SEQ: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

#[tauri::command]
pub async fn open_native_browser(
    app: AppHandle,
    url: String,
    mode: Option<String>,
    proxy: Option<String>,
) -> Result<(), String> {
    let parsed: tauri::Url = url.parse().map_err(|e| format!("invalid url: {e}"))?;
    // Refuse (rather than open a direct/leaky window) when Tor isn't ready or the
    // target is an onion outside Tor mode — see resolve_browser_proxy.
    let proxy_url = resolve_browser_proxy(&parsed, &mode, &proxy)?;
    // Surface what routing the browser actually got — so "not using Tor" is diagnosable.
    let via = proxy_url.as_ref().map(|u| u.to_string()).unwrap_or_else(|| "direct".into());
    crate::emit_log(&app, "BROWSER", "info",
        &format!("open {} · mode={} · via {}", parsed.host_str().unwrap_or("?"), mode.as_deref().unwrap_or("?"), via));

    // Close any previous browser window so the fresh one takes the current proxy.
    for (label, win) in app.webview_windows() {
        if label.starts_with("ros-browser") { let _ = win.destroy(); }
    }
    let seq = BROWSER_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let label = format!("ros-browser-{seq}");
    let mut b = tauri::WebviewWindowBuilder::new(&app, label, tauri::WebviewUrl::External(parsed))
        .title("RipleyOS Browser")
        .inner_size(1100.0, 780.0);
    if let Some(pu) = proxy_url {
        b = b.proxy_url(pu);
    }
    b.build().map_err(|e| e.to_string())?;
    Ok(())
}

// ---- Embedded browser (child webview positioned over the ROS Browser frame) ----
// Unlike open_native_browser (a separate window), this is a child webview of the
// main window, positioned by the ROS Browser app over its content frame in logical
// px. Native child webviews always float above HTML, so the ROS side hides it when
// the Browser window isn't the topmost (covered / behind another window / minimized).
const EMBED_LABEL: &str = "ros-embed";

/// The routing mode the current embed webview was CREATED under. Its proxy is fixed
/// at creation, so if the user later switches routing (e.g. clearnet → Tor) the embed
/// keeps its original transport. We refuse to navigate a stale-mode embed rather than
/// leak (a clearnet-created embed would load over clearnet while the UI shows Tor).
/// Set on open, cleared on close. std Mutex is fine — never held across an await.
static EMBED_MODE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Resolve the webview proxy for the user's routing mode (shared by both browsers).
///
/// The webview's proxy is fixed at CREATE time and can't be changed afterwards, so a
/// wrong choice here is a silent leak for the window's whole lifetime. Two safety
/// rules the webview can't enforce itself — both return an actionable Err so the
/// caller surfaces the problem instead of opening a leaky window:
///   1. Tor mode but the SOCKS port is 0 (Tor still bootstrapping / just restarted)
///      → REFUSE. Building the webview with no proxy would load over CLEARNET while
///      the user believes they're on Tor (IP leak).
///   2. A `.onion` target with anything other than a live Tor proxy → REFUSE. An
///      onion can't resolve without Tor; a direct/custom webview would DNS-leak the
///      onion address instead of failing cleanly.
/// Ok(None) means an intentional direct clearnet connection.
fn resolve_browser_proxy(
    url: &tauri::Url,
    mode: &Option<String>,
    proxy: &Option<String>,
) -> Result<Option<tauri::Url>, String> {
    let onion = url
        .host_str()
        .map(|h| h.to_ascii_lowercase().ends_with(".onion"))
        .unwrap_or(false);
    match mode.as_deref() {
        Some("tor") => {
            let p = crate::tor::socks_port();
            if p == 0 {
                return Err("Tor is still connecting — try again in a moment.".into());
            }
            Ok(format!("socks5://127.0.0.1:{p}").parse().ok())
        }
        // Any non-Tor mode can't reach an onion — refuse rather than leak it.
        _ if onion => Err("This is a .onion address — switch routing to Tor to open it.".into()),
        Some("custom") => {
            // Fold CJK-IME fullwidth chars (`127.0.0.1：17890` → `127.0.0.1:17890`) — the
            // webview's proxy endpoint creation PANICS on a malformed host:port rather
            // than erroring, so validate host+port here and refuse cleanly if it's off.
            let raw = crate::wallet::scanner::fold_fullwidth(proxy.as_deref().unwrap_or("").trim());
            if raw.is_empty() {
                return Ok(None);
            }
            let with_scheme = if raw.contains("://") { raw.clone() } else { format!("socks5://{raw}") };
            let parsed: tauri::Url = with_scheme
                .parse()
                .map_err(|_| format!("Invalid proxy address \"{raw}\" — expected host:port."))?;
            if parsed.host_str().is_none() || parsed.port().is_none() {
                return Err(format!("Invalid proxy address \"{raw}\" — expected host:port (e.g. 127.0.0.1:9050)."));
            }
            Ok(Some(parsed))
        }
        _ => Ok(None),
    }
}

/// Pre-navigation gate for the case where we reuse an EXISTING webview (whose proxy
/// is already fixed) and only have the target URL + the current routing config —
/// mirrors `resolve_browser_proxy`'s rules so an embed can't be pointed at a leaky
/// target while Tor is down or at an onion outside Tor mode.
fn guard_browser_target(app: &AppHandle, url: &tauri::Url) -> Result<(), String> {
    let mode = crate::wallet::scanner::read_routing_mode(app);
    let tor_ready = crate::tor::socks_port() != 0;
    if mode == "tor" && !tor_ready {
        return Err("Tor is still connecting — try again in a moment.".into());
    }
    let onion = url
        .host_str()
        .map(|h| h.to_ascii_lowercase().ends_with(".onion"))
        .unwrap_or(false);
    if onion && !(mode == "tor" && tor_ready) {
        return Err("This is a .onion address — switch routing to Tor to open it.".into());
    }
    // The embed's proxy is frozen at creation. If routing changed since (e.g. the user
    // switched clearnet → Tor), navigating the stale-mode embed would use the OLD
    // transport — an IP leak. Refuse and make the caller reopen (which recreates the
    // webview under the current mode).
    if let Some(created) = EMBED_MODE.lock().ok().and_then(|g| g.clone()) {
        if created != mode {
            return Err("Routing mode changed since this page was opened — reopen the browser to apply it.".into());
        }
    }
    Ok(())
}

/// Parse "r,g,b" (from the ROS theme's computed bg) into a webview background color,
/// so the embed matches the theme instead of flashing white before the page paints.
fn parse_rgb(s: &str) -> Option<tauri::webview::Color> {
    let p: Vec<u8> = s.split(',').filter_map(|v| v.trim().parse().ok()).collect();
    if p.len() >= 3 { Some(tauri::webview::Color(p[0], p[1], p[2], 255)) } else { None }
}

/// Pin the embed's zoom to `z` (the OS text-scale factor from ROS; 1.0 = 100%).
/// macOS WKWebView has TWO zooms and tauri only exposes one: `pageZoom` (layout —
/// what set_zoom drives) and `magnification` (visual scale, NO reflow — content
/// draws bigger and clips at the right/bottom edge, exactly the "oversized page"
/// symptom). Child webviews have come up scaled on HiDPI, so go straight to the
/// WKWebView: read both, log anything off (evidence in the core log), then pin
/// magnification=1 and pageZoom=z.
#[cfg(target_os = "macos")]
fn embed_pin_zoom(app: &AppHandle, wv: &tauri::Webview, z: f64) {
    let app2 = app.clone();
    let _ = wv.with_webview(move |pw| {
        let view = unsafe { &*(pw.inner() as *const objc2_web_kit::WKWebView) };
        let (mag, pz) = unsafe { (view.magnification(), view.pageZoom()) };
        // Touch the view ONLY when a value is actually off-target: re-setting zoom on an
        // already-correct, live page is a needless repaint (and the blank-page suspect).
        if (mag - 1.0).abs() > 0.001 || (pz - z).abs() > 0.001 {
            crate::emit_log(&app2, "BROWSER", "info", &format!(
                "embed zoom pin: magnification {mag:.2}→1.00 · pageZoom {pz:.2}→{z:.2}"));
            unsafe {
                view.setMagnification(1.0);
                view.setPageZoom(z);
            }
        }
    });
}
#[cfg(not(target_os = "macos"))]
fn embed_pin_zoom(_app: &AppHandle, wv: &tauri::Webview, z: f64) {
    let _ = wv.set_zoom(z);
}

#[tauri::command]
pub async fn browser_embed_open(
    app: AppHandle,
    url: String,
    mode: Option<String>,
    proxy: Option<String>,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    bg: Option<String>,
    zoom: Option<f64>,
) -> Result<(), String> {
    let parsed: tauri::Url = url.parse().map_err(|e| format!("invalid url: {e}"))?;
    // Refuse (rather than embed a direct/leaky webview) when Tor isn't ready or the
    // target is an onion outside Tor mode — see resolve_browser_proxy.
    let proxy_url = resolve_browser_proxy(&parsed, &mode, &proxy)?;
    let via = proxy_url.as_ref().map(|u| u.to_string()).unwrap_or_else(|| "direct".into());
    crate::emit_log(&app, "BROWSER", "info",
        &format!("embed {} · mode={} · via {}", parsed.host_str().unwrap_or("?"), mode.as_deref().unwrap_or("?"), via));
    // The proxy is fixed at creation → recreate on open (mode may have changed).
    if let Some(wv) = app.get_webview(EMBED_LABEL) { let _ = wv.close(); }
    let win = app.get_window("main").ok_or_else(|| "no main window".to_string())?;
    // Diagnostic: compare the bounds ROS sends against the window's logical content
    // size, so a coverage gap (webview smaller than the frame) is measurable.
    if let (Ok(sz), Ok(sf)) = (win.inner_size(), win.scale_factor()) {
        let (lw, lh) = (sz.width as f64 / sf, sz.height as f64 / sf);
        crate::emit_log(&app, "BROWSER", "info", &format!(
            "embed recv x={:.0} y={:.0} w={:.0} h={:.0} | win {:.0}x{:.0} @{:.2}x | right-gap={:.0} bottom-gap={:.0}",
            x, y, w, h, lw, lh, sf, lw - (x + w), lh - (y + h)));
    }
    // Page-load progress → the ROS address-bar loading bar (via the core-log channel).
    let app_ev = app.clone();
    let app_nav = app.clone();
    // OS text-scale (os.css zooms .ros; this separate webview can't inherit it) — ROS
    // passes the matching factor, default 100%.
    let z = zoom.unwrap_or(1.0);
    let mut b = tauri::WebviewBuilder::new(EMBED_LABEL, tauri::WebviewUrl::External(parsed))
        // Suppress the webview's native right-click menu (Inspect / Reload / Back) on
        // every browsed page, matching the rest of the app. Runs in the page at
        // document-start on each navigation; capture-phase preventDefault wins even if
        // a page adds its own contextmenu handler.
        .initialization_script("document.addEventListener('contextmenu',function(e){e.preventDefault();},true);")
        .on_navigation(move |url| {
            // Wallet/payment URIs can't render as a web page — an in-page anchor like
            // <a href="monero:8B…?tx_amount=1.5"> would just dead-end in the webview.
            // Forward them to ROS (which routes monero: → the wallet Send flow) and
            // CANCEL the navigation so the webview stays on the current page.
            if matches!(url.scheme(), "monero" | "bitcoin" | "lightning" | "xmr402" | "ripley") {
                crate::emit_log(&app_nav, "BROWSER_URI", "info", url.as_str());
                return false;
            }
            true
        })
        .on_page_load(move |wv, payload| {
            let phase = match payload.event() {
                tauri::webview::PageLoadEvent::Started => "start",
                _ => "end",
            };
            // Re-pin zoom once the page has finished loading: values set at creation are
            // applied before the first navigation and can be reset when a page actually
            // loads. Only on "end" — touching zoom mid-load can blank the webview.
            if phase == "end" {
                embed_pin_zoom(&app_ev, &wv, z);
                // Dev-only probe: a tiny badge in the page corner with the CSS viewport +
                // devicePixelRatio, so a screenshot shows whether a scaling bug is layout
                // zoom (vw shrinks), magnification (vw normal but content clips), or bounds
                // (vw ≈ 2× the frame). Never ships in release builds.
                #[cfg(debug_assertions)]
                { let _ = wv.eval("(function(){try{var d=document.createElement('div');d.id='__ros_probe';d.style.cssText='position:fixed;left:4px;bottom:4px;z-index:2147483647;background:#000;color:#0f0;font:10px monospace;padding:2px 6px;opacity:.85;pointer-events:none';d.textContent='vw '+innerWidth+'x'+innerHeight+' dpr '+devicePixelRatio+(window.visualViewport?' vvscale '+visualViewport.scale:'');(document.body||document.documentElement).appendChild(d);}catch(e){}})();"); }
            }
            // "phase|url" — the url lets ROS sync its address bar to in-webview navigation.
            crate::emit_log(&app_ev, "BROWSER_LOAD", "info", &format!("{}|{}", phase, payload.url()));
        });
    if let Some(pu) = proxy_url { b = b.proxy_url(pu); }
    if let Some(c) = bg.as_deref().and_then(parse_rgb) { b = b.background_color(c); }
    let wv = win.add_child(b, tauri::LogicalPosition::new(x, y), tauri::LogicalSize::new(w, h))
        .map_err(|e| e.to_string())?;
    // Zoom is deliberately NOT applied here: poking pageZoom before the first
    // navigation commits can break WKWebView's first paint (blank page). The
    // on_page_load "end" hook pins it once the page is actually up.
    let _ = &wv;
    // Record the mode this embed was created under so a later navigate can refuse if
    // routing has since changed (its proxy is frozen at creation — see guard_browser_target).
    let created_mode = mode.clone().unwrap_or_else(|| crate::wallet::scanner::read_routing_mode(&app));
    if let Ok(mut g) = EMBED_MODE.lock() { *g = Some(created_mode); }
    Ok(())
}

#[tauri::command]
pub fn browser_embed_bounds(app: AppHandle, x: f64, y: f64, w: f64, h: f64) -> Result<(), String> {
    if let Some(wv) = app.get_webview(EMBED_LABEL) {
        wv.set_position(tauri::LogicalPosition::new(x, y)).map_err(|e| e.to_string())?;
        wv.set_size(tauri::LogicalSize::new(w, h)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[tauri::command]
pub fn browser_embed_navigate(app: AppHandle, url: String) -> Result<(), String> {
    let parsed: tauri::Url = url.parse().map_err(|e| format!("invalid url: {e}"))?;
    // The existing embed's proxy is fixed at creation; refuse to point it at a leaky
    // target (Tor down, or an onion outside Tor mode) rather than navigate + leak.
    guard_browser_target(&app, &parsed)?;
    match app.get_webview(EMBED_LABEL) {
        Some(wv) => {
            crate::emit_log(&app, "BROWSER", "info", &format!("embed navigate {}", parsed.host_str().unwrap_or("?")));
            // A navigation that only changes the QUERY of the current document (same
            // scheme+host+path) is treated as a no-op by WKWebView — so an xmr402 callback
            // like `.../?xmr402_txid=…&xmr402_proof=…` landing back on the challenge page
            // wouldn't reload, and the page's param-reading logic never re-runs. In that
            // case drive `location.replace` from inside the page (which always reloads on a
            // query change). Same webview → same fixed proxy, so no routing/leak change; the
            // target was already vetted by guard_browser_target above. URL is JSON-escaped
            // so it can't break out of the JS string literal.
            let same_doc_query_change = wv.url().ok().is_some_and(|cur| {
                cur.scheme() == parsed.scheme()
                    && cur.host_str() == parsed.host_str()
                    && cur.path() == parsed.path()
                    && cur.query() != parsed.query()
            });
            if same_doc_query_change {
                let js = format!(
                    "window.location.replace({})",
                    serde_json::to_string(parsed.as_str())
                        .unwrap_or_else(|_| "\"about:blank\"".to_string())
                );
                wv.eval(&js).map_err(|e| e.to_string())?;
            } else {
                wv.navigate(parsed).map_err(|e| e.to_string())?;
            }
        }
        None => crate::emit_log(&app, "BROWSER", "warn", "embed navigate: no ros-embed webview"),
    }
    Ok(())
}

#[tauri::command]
pub fn browser_embed_zoom(app: AppHandle, zoom: f64) -> Result<(), String> {
    // Live-track the OS text-scale on an already-open embed (no-op if none is open).
    if let Some(wv) = app.get_webview(EMBED_LABEL) { embed_pin_zoom(&app, &wv, zoom); }
    Ok(())
}

#[tauri::command]
pub fn browser_embed_visible(app: AppHandle, visible: bool) -> Result<(), String> {
    if let Some(wv) = app.get_webview(EMBED_LABEL) {
        if visible { wv.show().map_err(|e| e.to_string())?; }
        else { wv.hide().map_err(|e| e.to_string())?; }
    }
    Ok(())
}

#[tauri::command]
pub fn browser_embed_close(app: AppHandle) -> Result<(), String> {
    if let Some(wv) = app.get_webview(EMBED_LABEL) { let _ = wv.close(); }
    if let Ok(mut g) = EMBED_MODE.lock() { *g = None; }
    Ok(())
}

/// Hand an XMR402 payment proof back to the page currently loaded in the embed by
/// dispatching a `window` CustomEvent INSIDE the webview — WITHOUT navigating. The WS
/// relay channel depends on the merchant page keeping its live WebSocket open; the
/// URL-param callback (a navigation) would reload the page and destroy that socket, and
/// the reloaded page would then verify a WS-nonce proof against the HTTP endpoint's
/// different nonce and fail. Delivering in-page lets the page route the proof itself
/// (send PAYMENT_PROOF over the open socket, or re-fetch the HTTP resource). txid/proof
/// are JSON-encoded so they can't break out of the JS object literal.
#[tauri::command]
pub fn browser_embed_deliver_xmr402(app: AppHandle, txid: String, proof: String) -> Result<(), String> {
    match app.get_webview(EMBED_LABEL) {
        Some(wv) => {
            let detail = serde_json::json!({ "txid": txid, "proof": proof });
            let js = format!(
                "window.dispatchEvent(new CustomEvent('xmr402:proof', {{ detail: {} }}))",
                serde_json::to_string(&detail).map_err(|e| e.to_string())?
            );
            wv.eval(&js).map_err(|e| e.to_string())?;
            crate::emit_log(&app, "BROWSER", "info", "xmr402 proof delivered in-page to embed");
            Ok(())
        }
        None => Err("no embed webview".to_string()),
    }
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
    use super::{is_onion, version_gt};

    #[test]
    fn detects_onion_case_insensitively() {
        assert!(is_onion("http://abcdefghij.onion/api"));
        assert!(is_onion("http://ABCDEFGHIJ.ONION/api")); // uppercase must not slip past
        assert!(is_onion("https://Mixed.OnIoN"));
        assert!(!is_onion("https://api.kyc.rip/v1/stats"));
        // A .onion only in the path/query must NOT force Tor.
        assert!(!is_onion("https://example.com/?ref=foo.onion"));
    }

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

// ─────────────────────────────────────────────────────────────────────────────
// OpenAlias resolution (RFC 8484 binary DoH, DNSSEC-gated)
//
// Resolve a human-readable OpenAlias name (FQDN `donate.getmonero.org` or
// email-form `donate@getmonero.org`) to a crypto address via a DNS TXT
// `oa1:<ticker>` record. The lookup goes over the SAME Tor/SOCKS/clearnet routing
// as every other outbound request (no clearnet DNS leak in Tor mode), and we
// FAIL CLOSED unless the resolver reports DNSSEC-authenticated data (AD bit).
// For XMR the resolved address is re-validated natively before it's returned.
// ─────────────────────────────────────────────────────────────────────────────

#[derive(serde::Serialize)]
pub struct OpenAliasResult {
    pub address: String,
    #[serde(rename = "recipientName")]
    pub recipient_name: Option<String>,
    #[serde(rename = "txDescription")]
    pub tx_description: Option<String>,
    /// Always true — a result is only returned when the resolver's AD bit is set.
    pub dnssec: bool,
    pub ticker: String,
}

/// Normalize a user-entered OpenAlias name into a bare FQDN. Email-form
/// (`local@domain`) collapses to `local.domain`; lowercased; trailing dot
/// stripped. Rejects whitespace and non-FQDN inputs (a bare `@handle` has no
/// dot after normalization → rejected, which lets the caller fall back to the
/// xmr.bio `@handle` resolver).
fn normalize_openalias_name(name: &str) -> Result<String, String> {
    let mut s = name.trim().to_lowercase();
    if s.is_empty() {
        return Err("empty OpenAlias name".into());
    }
    if s.chars().any(|c| c.is_whitespace()) {
        return Err("OpenAlias name must not contain whitespace".into());
    }
    if s.matches('@').count() > 1 {
        return Err("invalid OpenAlias name".into());
    }
    if let Some(at) = s.find('@') {
        s.replace_range(at ..= at, ".");
    }
    let s = s.trim_end_matches('.').to_string();
    // Require ≥2 non-empty labels — rejects bare handles (`alice`, `@alice`) and
    // malformed names with empty labels (`foo..bar`, leading `.`), so a bare
    // `@handle` falls through to the xmr.bio resolver.
    let labels: Vec<&str> = s.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return Err("not a fully-qualified OpenAlias name (needs a domain)".into());
    }
    Ok(s)
}

/// True when `record` is an `oa1:<ticker>` record. The ticker is the first
/// whitespace-delimited token after the `oa1:` prefix, so `oa1:xmrig …` does NOT
/// match ticker `xmr`.
fn oa1_ticker_matches(record: &str, ticker: &str) -> bool {
    record
        .trim_start()
        .strip_prefix("oa1:")
        .and_then(|rest| rest.split_whitespace().next())
        .map(|tk| tk.eq_ignore_ascii_case(ticker))
        .unwrap_or(false)
}

/// Extract an OpenAlias `key=value;` field. Values may contain spaces
/// (e.g. recipient_name) and are terminated by `;`.
fn oa1_field(record: &str, key: &str) -> Option<String> {
    let rest = record.trim_start().strip_prefix("oa1:")?;
    // Skip the ticker token; fields begin at the first whitespace.
    let after_ticker = match rest.find(char::is_whitespace) {
        Some(i) => &rest[i ..],
        None => return None,
    };
    let needle = format!("{key}=");
    for seg in after_ticker.split(';') {
        let seg = seg.trim();
        if let Some(v) = seg.strip_prefix(&needle) {
            return Some(v.trim().to_string());
        }
    }
    None
}

/// Pick the single `oa1:<ticker>` record from the TXT set. Rejects when none
/// match, or when multiple records advertise DIFFERENT recipient_address values
/// (ambiguous → could silently misroute); identical duplicates are accepted.
fn select_oa1_record(txts: &[String], ticker: &str) -> Result<String, String> {
    let matches: Vec<&String> = txts.iter().filter(|t| oa1_ticker_matches(t, ticker)).collect();
    if matches.is_empty() {
        return Err(format!("no OpenAlias oa1:{ticker} record found"));
    }
    let first_addr = oa1_field(matches[0], "recipient_address");
    if matches.iter().any(|t| oa1_field(t, "recipient_address") != first_addr) {
        return Err("ambiguous OpenAlias: multiple records with different addresses".into());
    }
    Ok(matches[0].clone())
}

/// Parse a validated `oa1:<ticker>` record into (address, recipient_name?, tx_description?).
fn parse_oa1_record(record: &str) -> Result<(String, Option<String>, Option<String>), String> {
    let address = oa1_field(record, "recipient_address")
        .filter(|s| !s.is_empty())
        .ok_or("OpenAlias record missing recipient_address")?;
    let recipient_name = oa1_field(record, "recipient_name").filter(|s| !s.is_empty());
    let tx_description = oa1_field(record, "tx_description").filter(|s| !s.is_empty());
    Ok((address, recipient_name, tx_description))
}

/// Apply the fail-closed gate to a DoH response and select the oa1 record.
/// Split out from the network path so every rejection branch is unit-testable.
fn evaluate_response(noerror: bool, authentic: bool, truncated: bool, txts: &[String], ticker: &str) -> Result<String, String> {
    if truncated {
        // OpenAlias records fit well under 512 bytes; a TC=1 is anomalous. Reject
        // rather than silently retry over TCP/POST (deliberate v1 non-retry).
        return Err("DNS response was truncated (TC=1)".into());
    }
    if !noerror {
        return Err("DNS lookup failed (non-success response code)".into());
    }
    if !authentic {
        return Err("DNSSEC not validated (AD=0) — the domain's zone must be DNSSEC-signed to resolve securely".into());
    }
    select_oa1_record(txts, ticker)
}

/// Build the base64url-encoded (no padding) DNS query for `?dns=` DoH GET:
/// a single TXT question with the DNSSEC-OK bit set.
fn build_doh_query(fqdn: &str) -> Result<String, String> {
    let name = Name::from_ascii(fqdn).map_err(|e| format!("invalid DNS name: {e}"))?;
    let query = Query::query(name, RecordType::TXT);
    let mut msg = Message::new();
    msg.set_id(0)
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(query);
    let mut edns = Edns::new();
    edns.set_dnssec_ok(true);
    edns.set_max_payload(1232);
    msg.set_edns(edns);
    let wire = msg.to_bytes().map_err(|e| format!("DNS encode failed: {e}"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(wire))
}

/// Concatenate each answer's TXT char-strings into whole-record strings.
fn extract_txt_records(msg: &Message) -> Vec<String> {
    msg.answers()
        .iter()
        .filter_map(|rec| match rec.data() {
            Some(RData::TXT(txt)) => {
                let mut s = String::new();
                for chunk in txt.txt_data() {
                    s.push_str(&String::from_utf8_lossy(chunk));
                }
                Some(s)
            }
            _ => None,
        })
        .collect()
}

/// Resolve an OpenAlias name to a crypto address for `ticker`. Routed over the
/// configured transport; DNSSEC-gated; XMR addresses re-validated natively.
#[tauri::command]
pub async fn resolve_openalias(app: AppHandle, name: String, ticker: String) -> Result<OpenAliasResult, String> {
    let ticker = ticker.trim().to_lowercase();
    if ticker.is_empty() {
        return Err("ticker is required".into());
    }
    let fqdn = normalize_openalias_name(&name)?;
    let query = build_doh_query(&fqdn)?;
    let url = format!("{OPENALIAS_DOH_ENDPOINT}?dns={query}");
    let headers: &[(&str, &str)] = &[("Accept", "application/dns-message")];

    let mode = crate::wallet::scanner::read_routing_mode(&app);
    crate::emit_log(&app, "OPENALIAS", "process", &format!("resolving \"{fqdn}\" ({ticker}) via {mode} → {OPENALIAS_DOH_ENDPOINT}"));
    let bytes: Vec<u8> = match mode.as_str() {
        "tor" => match app.state::<crate::tor::TorState>().get_client().await {
            Some(tor) => crate::tor::tor_get_with_headers(&tor, &url, headers).await?,
            None => return Err("Tor is not connected yet (required for OpenAlias resolution)".into()),
        },
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(&app);
            if proxy.trim().is_empty() {
                return Err("Custom routing selected but no proxy address is set".into());
            }
            crate::tor::socks_get_with_headers(&proxy, &url, headers).await?
        }
        _ => {
            let resp = reqwest::Client::new()
                .get(&url)
                .header("Accept", "application/dns-message")
                .header("User-Agent", concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .send()
                .await
                .map_err(|e| e.to_string())?;
            resp.bytes().await.map_err(|e| e.to_string())?.to_vec()
        }
    };

    crate::emit_log(&app, "OPENALIAS", "info", &format!("DoH response: {} bytes", bytes.len()));
    let msg = Message::from_vec(&bytes).map_err(|e| format!("failed to parse DNS response ({} bytes — is the resolver HTTP/1.1-capable?): {e}", bytes.len()))?;
    let noerror = msg.response_code() == ResponseCode::NoError;
    let txts = extract_txt_records(&msg);
    crate::emit_log(&app, "OPENALIAS", "info", &format!("rcode={:?} AD={} TC={} txt_records={}", msg.response_code(), msg.authentic_data(), msg.truncated(), txts.len()));
    let record = evaluate_response(noerror, msg.authentic_data(), msg.truncated(), &txts, &ticker)?;
    let (address, recipient_name, tx_description) = parse_oa1_record(&record)?;

    // For Monero, re-validate the resolved address against the active network so a
    // poisoned/misformatted record can never reach prepare_transfer.
    if ticker == "xmr" {
        let network = app.state::<WalletState>().get_network().await;
        MoneroAddress::from_str(network, &address)
            .map_err(|e| format!("resolved XMR address failed validation: {e}"))?;
    }

    crate::emit_log(&app, "OPENALIAS", "success", &format!("{fqdn} → {address}"));
    Ok(OpenAliasResult { address, recipient_name, tx_description, dnssec: true, ticker })
}

#[cfg(test)]
mod openalias_tests {
    use super::*;

    #[test]
    fn normalize_email_form() {
        assert_eq!(normalize_openalias_name("Donate@GetMonero.org").unwrap(), "donate.getmonero.org");
    }
    #[test]
    fn normalize_strips_trailing_dot() {
        assert_eq!(normalize_openalias_name("donate.getmonero.org.").unwrap(), "donate.getmonero.org");
    }
    #[test]
    fn normalize_rejects_bare_handle() {
        assert!(normalize_openalias_name("alice").is_err());
        assert!(normalize_openalias_name("@alice").is_err());
    }
    #[test]
    fn normalize_rejects_whitespace() {
        assert!(normalize_openalias_name("foo bar.com").is_err());
    }

    #[test]
    fn parse_valid_xmr_record() {
        let rec = "oa1:xmr recipient_address=44AFFq5kSiGBoZ;recipient_name=Monero Donations;";
        let (addr, name, _) = parse_oa1_record(rec).unwrap();
        assert_eq!(addr, "44AFFq5kSiGBoZ");
        assert_eq!(name.as_deref(), Some("Monero Donations"));
    }
    #[test]
    fn parse_missing_address_errs() {
        assert!(parse_oa1_record("oa1:xmr recipient_name=Foo;").is_err());
    }
    #[test]
    fn select_wrong_ticker_errs() {
        let txts = vec!["oa1:btc recipient_address=bc1qxyz;".to_string()];
        assert!(select_oa1_record(&txts, "xmr").is_err());
    }
    #[test]
    fn select_ambiguous_errs() {
        let txts = vec![
            "oa1:xmr recipient_address=AAA;".to_string(),
            "oa1:xmr recipient_address=BBB;".to_string(),
        ];
        assert!(select_oa1_record(&txts, "xmr").is_err());
    }
    #[test]
    fn select_identical_dupes_ok() {
        let txts = vec![
            "oa1:xmr recipient_address=AAA;".to_string(),
            "oa1:xmr recipient_address=AAA;".to_string(),
        ];
        assert_eq!(select_oa1_record(&txts, "xmr").unwrap(), "oa1:xmr recipient_address=AAA;");
    }
    #[test]
    fn select_ignores_non_oa1_txt() {
        let txts = vec![
            "v=spf1 include:_spf.google.com ~all".to_string(),
            "oa1:xmr recipient_address=AAA;".to_string(),
        ];
        let rec = select_oa1_record(&txts, "xmr").unwrap();
        assert_eq!(oa1_field(&rec, "recipient_address").as_deref(), Some("AAA"));
    }
    #[test]
    fn oa1_prefix_not_confused_by_similar_ticker() {
        let txts = vec!["oa1:xmrig recipient_address=ZZZ;".to_string()];
        assert!(select_oa1_record(&txts, "xmr").is_err());
    }

    #[test]
    fn evaluate_rejects_ad_false() {
        let txts = vec!["oa1:xmr recipient_address=AAA;".to_string()];
        assert!(evaluate_response(true, false, false, &txts, "xmr").is_err());
    }
    #[test]
    fn evaluate_rejects_non_noerror() {
        let txts = vec!["oa1:xmr recipient_address=AAA;".to_string()];
        assert!(evaluate_response(false, true, false, &txts, "xmr").is_err());
    }
    #[test]
    fn evaluate_rejects_truncated() {
        let txts = vec!["oa1:xmr recipient_address=AAA;".to_string()];
        assert!(evaluate_response(true, true, true, &txts, "xmr").is_err());
    }
    #[test]
    fn evaluate_rejects_empty_answer() {
        assert!(evaluate_response(true, true, false, &[], "xmr").is_err());
    }
    #[test]
    fn evaluate_accepts_valid() {
        let txts = vec!["oa1:xmr recipient_address=AAA;recipient_name=Foo;".to_string()];
        assert_eq!(evaluate_response(true, true, false, &txts, "xmr").unwrap(), txts[0]);
    }
}
