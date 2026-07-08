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
        Some("custom") => Ok(proxy.clone().filter(|s| !s.is_empty()).and_then(|s| {
            if s.contains("://") { s } else { format!("socks5://{s}") }.parse().ok()
        })),
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
            if matches!(url.scheme(), "monero" | "bitcoin" | "lightning" | "xmr402") {
                crate::emit_log(&app_nav, "BROWSER_URI", "info", url.as_str());
                return false;
            }
            true
        })
        .on_page_load(move |_wv, payload| {
            let phase = match payload.event() {
                tauri::webview::PageLoadEvent::Started => "start",
                _ => "end",
            };
            // "phase|url" — the url lets ROS sync its address bar to in-webview navigation.
            crate::emit_log(&app_ev, "BROWSER_LOAD", "info", &format!("{}|{}", phase, payload.url()));
        });
    if let Some(pu) = proxy_url { b = b.proxy_url(pu); }
    if let Some(c) = bg.as_deref().and_then(parse_rgb) { b = b.background_color(c); }
    let wv = win.add_child(b, tauri::LogicalPosition::new(x, y), tauri::LogicalSize::new(w, h))
        .map_err(|e| e.to_string())?;
    // Child webviews can inherit a non-1.0 page zoom on macOS HiDPI → content renders
    // oversized. Pin to 100% (Retina backing is handled separately by the webview).
    let _ = wv.set_zoom(1.0);
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
