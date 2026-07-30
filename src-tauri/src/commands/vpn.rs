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
//!   - `vpn_connect` / `vpn_disconnect` / `vpn_set_killswitch` /
//!     `vpn_recover` / `vpn_emergency_restore`
//!     are NOT granted to the renderer; they are invokable only from the native
//!     host window (the trusted, host-owned confirmation surface).

#[cfg(target_os = "linux")]
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
use std::{
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tauri::{AppHandle, Manager};
use zeroize::Zeroizing;

#[cfg(target_os = "linux")]
const SOCK: &str = "/run/ripley-vpn.sock";
#[cfg(target_os = "linux")]
const PROTOCOL: u32 = 1;
#[cfg(target_os = "linux")]
const IO_TIMEOUT: Duration = Duration::from_secs(12);
#[cfg(target_os = "linux")]
const MAX_RESP: usize = 64 * 1024;
const PROFILE_STORE_FILE: &str = "vpn/profiles.v1";
const PROFILE_STORE_MAGIC: &[u8; 5] = b"RIPV1";
const PROFILE_NONCE_LEN: usize = 12;
const MAX_PROFILE_COUNT: usize = 128;
const MAX_PROFILE_TEXT: usize = 16 * 1024;
const MAX_PROFILE_STORE: usize = 3 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredVpnProfile {
    id: String,
    name: String,
    source_path: String,
    kind: String,
    config_text: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnProfileStore {
    v: u32,
    selected_profile_id: Option<String>,
    profiles: Vec<StoredVpnProfile>,
}

fn validate_profile_store(store: &VpnProfileStore) -> Result<(), String> {
    if store.v != 1 {
        return Err("unsupported VPN profile store version".into());
    }
    if store.profiles.len() > MAX_PROFILE_COUNT {
        return Err(format!(
            "VPN profile store exceeds {MAX_PROFILE_COUNT} profiles"
        ));
    }
    for profile in &store.profiles {
        if profile.id.is_empty()
            || profile.id.len() > 512
            || profile.name.is_empty()
            || profile.name.len() > 256
            || profile.source_path.is_empty()
            || profile.source_path.len() > 1024
            || profile.config_text.len() > MAX_PROFILE_TEXT
            || !matches!(profile.kind.as_str(), "wireguard" | "openvpn")
        {
            return Err("invalid VPN profile store entry".into());
        }
        if profile.config_text.contains('\0') {
            return Err("VPN profile contains binary data".into());
        }
    }
    if let Some(selected) = &store.selected_profile_id {
        if !store.profiles.iter().any(|profile| &profile.id == selected) {
            return Err("selected VPN profile is not present in the store".into());
        }
    }
    Ok(())
}

fn profile_store_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_data_dir()
        .map(|dir| dir.join(PROFILE_STORE_FILE))
        .map_err(|e| format!("resolve VPN profile store: {e}"))
}

fn seal_profile_store(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce = [0_u8; PROFILE_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| "encrypt VPN profile store".to_string())?;
    let mut body =
        Vec::with_capacity(PROFILE_STORE_MAGIC.len() + PROFILE_NONCE_LEN + ciphertext.len());
    body.extend_from_slice(PROFILE_STORE_MAGIC);
    body.extend_from_slice(&nonce);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

fn open_profile_store(key: &[u8; 32], body: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
    let encrypted = body
        .strip_prefix(PROFILE_STORE_MAGIC)
        .ok_or_else(|| "VPN profile store has an unknown format".to_string())?;
    if encrypted.len() < PROFILE_NONCE_LEN {
        return Err("VPN profile store is truncated".into());
    }
    let (nonce, ciphertext) = encrypted.split_at(PROFILE_NONCE_LEN);
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), ciphertext)
        .map(Zeroizing::new)
        .map_err(|_| "VPN profile store could not be decrypted".into())
}

fn atomic_private_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "VPN profile store has no parent directory".to_string())?;
    std::fs::create_dir_all(parent)
        .map_err(|e| format!("create VPN profile store directory: {e}"))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes).map_err(|e| format!("write VPN profile store: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("secure VPN profile store: {e}"))?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("commit VPN profile store: {e}"));
    }
    Ok(())
}

/// Fixed, cosmetic-only token contract accepted from ROS. The field names and
/// destination CSS variables are owned by this trusted host; ROS cannot provide
/// selectors, property names, scripts, URLs or arbitrary CSS.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnThemeTokens {
    base: String,
    panel: String,
    surface: String,
    text: String,
    dim: String,
    accent: String,
    border: String,
    success: String,
    warning: String,
    error: String,
    radius_sm: String,
    radius_md: String,
    radius_lg: String,
}

fn valid_computed_color(value: &str) -> bool {
    if value.is_empty() || value.len() > 64 || !value.is_ascii() {
        return false;
    }
    if let Some(hex) = value.strip_prefix('#') {
        return matches!(hex.len(), 3 | 4 | 6 | 8) && hex.bytes().all(|b| b.is_ascii_hexdigit());
    }
    let body = value
        .strip_prefix("rgb(")
        .or_else(|| value.strip_prefix("rgba("))
        .and_then(|v| v.strip_suffix(')'));
    body.is_some_and(|v| {
        !v.is_empty()
            && v.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b' ' | b',' | b'.' | b'%' | b'/'))
    })
}

fn valid_computed_radius(value: &str) -> bool {
    let Some(number) = value.strip_suffix("px") else {
        return false;
    };
    number
        .parse::<f32>()
        .is_ok_and(|n| n.is_finite() && (0.0..=48.0).contains(&n))
}

fn theme_script(theme: Option<&str>, tokens: Option<&VpnThemeTokens>, locale: Option<&str>) -> String {
    let mut vars = Map::new();
    if let Some(t) = tokens {
        let colors = [
            ("--bg-primary", &t.base),
            ("--bg-panel", &t.panel),
            ("--bg-surface", &t.surface),
            ("--text-primary", &t.text),
            ("--text-dim", &t.dim),
            ("--brand-color", &t.accent),
            ("--text-accent", &t.accent),
            ("--border-color", &t.border),
            ("--color-ghost", &t.accent),
            ("--success-color", &t.success),
            ("--warning-color", &t.warning),
            ("--error-color", &t.error),
        ];
        for (name, value) in colors {
            if valid_computed_color(value) {
                vars.insert(name.into(), Value::String(value.clone()));
            }
        }
        let radii = [
            ("--skin-radius-sm", &t.radius_sm),
            ("--skin-radius-md", &t.radius_md),
            ("--skin-radius-lg", &t.radius_lg),
            ("--skin-radius-xl", &t.radius_lg),
            ("--skin-radius-2xl", &t.radius_lg),
            ("--skin-radius-3xl", &t.radius_lg),
        ];
        for (name, value) in radii {
            if valid_computed_radius(value) {
                vars.insert(name.into(), Value::String(value.clone()));
            }
        }
    }
    let vars = serde_json::to_string(&vars).unwrap_or_else(|_| "{}".into());
    let theme =
        serde_json::to_string(theme.unwrap_or("system")).unwrap_or_else(|_| "\"system\"".into());
    let locale = serde_json::to_string(locale.unwrap_or("en")).unwrap_or_else(|_| "\"en\"".into());
    format!(
        r#"(()=>{{
const apply=()=>{{
  const requested={theme};
  const mode=requested==='system'
    ? (window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light')
    : requested;
  const root=document.documentElement;
  root.classList.remove('light','dark');
  root.classList.add(mode);
  const vars={vars};
  for(const [name,value] of Object.entries(vars)) root.style.setProperty(name,value);
  root.dataset.rosThemeBridge='1';
  window.__ripleyVpnLocale={locale};
  window.dispatchEvent(new CustomEvent('ripley-vpn-locale-changed',{{detail:{locale}}}));
}};
if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',apply,{{once:true}});
else apply();
}})()"#
    )
}

#[cfg(target_os = "linux")]
fn next_id() -> String {
    // Correlation only; the broker treats ids as opaque. Millis + a coarse
    // counter is plenty to line a reply up with its request in logs.
    format!("ros-{}", chrono::Utc::now().timestamp_millis())
}

/// One blocking round-trip to the broker: connect, send one JSON line, read one
/// JSON line. Returns the `status` object on success, or the broker's `reason`.
fn broker_call(request: Value) -> Result<Value, String> {
    #[cfg(target_os = "macos")]
    {
        if request.get("op").and_then(Value::as_str) == Some("status") {
            return Ok(crate::vpn_macos::status());
        }
        return crate::vpn_macos::privileged_call(request);
    }
    #[cfg(all(not(target_os = "linux"), not(target_os = "macos")))]
    {
        let _ = request;
        return Err("Host-wide VPN connection is currently supported on Linux and macOS.".into());
    }
    #[cfg(target_os = "linux")]
    {
        let mut stream = UnixStream::connect(SOCK)
            .map_err(|e| format!("VPN broker unavailable ({e}). Is ripley-vpn-broker running?"))?;
        stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
        stream.set_write_timeout(Some(IO_TIMEOUT)).ok();

        let env = json!({ "protocol": PROTOCOL, "id": next_id(), "request": request });
        let mut line = serde_json::to_string(&env).map_err(|e| e.to_string())?;
        line.push('\n');
        stream
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;

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

        let resp: Value =
            serde_json::from_slice(&buf).map_err(|e| format!("bad broker reply: {e}"))?;
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
}

/// Run the blocking broker round-trip off the async runtime's worker threads.
async fn call(request: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || broker_call(request))
        .await
        .map_err(|e| e.to_string())?
}

async fn logged_mutation(app: &AppHandle, label: &str, request: Value) -> Result<Value, String> {
    crate::emit_log(app, "VPN", "info", &format!("🔐 {label} requested"));
    match call(request).await {
        Ok(status) => {
            let phase = status
                .get("phase")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            crate::emit_log(app, "VPN", "success", &format!("✓ {label}: phase={phase}"));
            Ok(status)
        }
        Err(error) => {
            crate::emit_log(app, "VPN", "error", &format!("❌ {label}: {error}"));
            Err(error)
        }
    }
}

/// Read-only status. Safe to expose to the OTA renderer.
#[tauri::command]
pub async fn vpn_status() -> Result<Value, String> {
    call(json!({ "op": "status" })).await
}

fn probe_host(endpoint: &str) -> Result<String, String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() || endpoint.len() > 320 || endpoint.bytes().any(|b| b.is_ascii_control())
    {
        return Err("invalid VPN endpoint".into());
    }
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| "invalid IPv6 VPN endpoint".to_string())?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| "VPN endpoint has no port".to_string())?;
        (host, port)
    } else {
        endpoint
            .rsplit_once(':')
            .ok_or_else(|| "VPN endpoint has no port".to_string())?
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| "invalid VPN endpoint port".to_string())?;
    if port == 0 || host.is_empty() {
        return Err("invalid VPN endpoint".into());
    }
    if host.parse::<IpAddr>().is_err()
        && (host.len() > 253
            || host.starts_with('-')
            || host.ends_with('-')
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-')))
    {
        return Err("invalid VPN endpoint host".into());
    }
    Ok(host.to_string())
}

fn ping_millis(host: &str) -> Option<u64> {
    let started = Instant::now();
    #[cfg(target_os = "macos")]
    let mut command = Command::new("/sbin/ping");
    #[cfg(target_os = "macos")]
    command.args(["-n", "-c", "1", "-W", "1000", host]);
    #[cfg(target_os = "linux")]
    let mut command = Command::new("/usr/bin/ping");
    #[cfg(target_os = "linux")]
    command.args(["-n", "-c", "1", "-W", "1", host]);
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return None;
    let result = command.env_clear().output().ok()?;
    if !result.status.success() {
        return None;
    }
    let output = String::from_utf8_lossy(&result.stdout);
    output
        .split("time=")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .and_then(|value| value.parse::<f64>().ok())
        .map(|value| value.round().max(1.0) as u64)
        .or_else(|| Some(started.elapsed().as_millis().max(1).min(u64::MAX as u128) as u64))
}

/// Latency probe for the trusted native VPN picker. Inputs are reduced to validated
/// endpoint hosts before spawning `ping`; no renderer text is ever interpreted by a shell.
#[tauri::command]
pub async fn vpn_probe_endpoints(endpoints: Vec<String>) -> Result<Vec<Option<u64>>, String> {
    if endpoints.len() > MAX_PROFILE_COUNT {
        return Err(format!("speed test exceeds {MAX_PROFILE_COUNT} endpoints"));
    }
    let hosts = endpoints
        .iter()
        .map(|endpoint| probe_host(endpoint))
        .collect::<Result<Vec<_>, _>>()?;
    let probes = hosts
        .into_iter()
        .map(|host| tauri::async_runtime::spawn_blocking(move || ping_millis(&host)))
        .collect::<Vec<_>>();
    let mut results = Vec::with_capacity(probes.len());
    for probe in probes {
        results.push(
            probe
                .await
                .map_err(|e| format!("VPN speed probe failed: {e}"))?,
        );
    }
    Ok(results)
}

/// Bring the tunnel up from raw `.conf` text. The broker parses+validates it
/// (parse-as-data) and seals the fail-closed egress block before any wg/route
/// change. Host-window only.
#[tauri::command]
pub async fn vpn_connect(
    app: AppHandle,
    config_text: String,
    profile_name: Option<String>,
) -> Result<Value, String> {
    #[cfg(target_os = "macos")]
    let request = json!({
        "op": "up",
        "config_text": config_text,
        "profile_name": profile_name,
    });
    // The Linux broker predates display-only profile metadata and intentionally
    // receives only its strict protocol fields.
    #[cfg(not(target_os = "macos"))]
    let request = json!({ "op": "up", "config_text": config_text });
    logged_mutation(&app, "Connect", request).await
}

/// Tear down the tunnel. `restore = false` keeps the egress block (fail-closed);
/// `restore = true` re-opens clearnet (the broker gates this as a strong op).
/// Host-window only.
#[tauri::command]
pub async fn vpn_disconnect(app: AppHandle, restore: bool) -> Result<Value, String> {
    let op = if restore {
        "disconnect_and_restore_clearnet"
    } else {
        "disconnect_blocked"
    };
    logged_mutation(
        &app,
        if restore {
            "Disconnect + restore clearnet"
        } else {
            "Disconnect + stay blocked"
        },
        json!({ "op": op }),
    )
    .await
}

/// Enable/disable the kill-switch. Host-window only. Disabling is a broker-side
/// strong op and is refused while a tunnel is up.
#[tauri::command]
pub async fn vpn_set_killswitch(app: AppHandle, on: bool) -> Result<Value, String> {
    let op = if on {
        "enable_kill_switch"
    } else {
        "disable_kill_switch"
    };
    logged_mutation(
        &app,
        if on {
            "Enable kill-switch"
        } else {
            "Disable kill-switch"
        },
        json!({ "op": op }),
    )
    .await
}

/// Reconcile toward the fail-closed blocked state (clears stale rules WITHOUT
/// re-opening egress). Host-window only.
#[tauri::command]
pub async fn vpn_recover(app: AppHandle) -> Result<Value, String> {
    logged_mutation(
        &app,
        "Recover blocked state",
        json!({ "op": "reconcile_blocked_state" }),
    )
    .await
}

/// Break-glass recovery for a dirty blocked state. The broker still requires
/// interactive Polkit authorization and refuses to claim clearnet open unless
/// the host-wide nft block was actually removed. Host-window only.
#[tauri::command]
pub async fn vpn_emergency_restore(app: AppHandle) -> Result<Value, String> {
    logged_mutation(
        &app,
        "Emergency restore clearnet",
        json!({ "op": "emergency_restore_clearnet" }),
    )
    .await
}

/// Load an encrypted profile bundle. The existence check happens before the
/// keychain request, so a fresh install never prompts merely for opening VPN.
/// Host-window only: ROS has no permission for this command.
#[tauri::command]
pub async fn vpn_profiles_load(app: AppHandle) -> Result<Option<VpnProfileStore>, String> {
    let path = profile_store_path(&app)?;
    if !path.exists() {
        return Ok(None);
    }
    if !crate::wallet::device_key::ensure_watch_key(&app).await {
        return Err("Device key unavailable — stored VPN profiles remain locked.".into());
    }
    let key = crate::wallet::device_key::vpn_profiles_key()
        .ok_or_else(|| "Device key unavailable — stored VPN profiles remain locked.".to_string())?;
    let body = std::fs::read(&path).map_err(|e| format!("read VPN profile store: {e}"))?;
    if body.len() > MAX_PROFILE_STORE {
        return Err("VPN profile store exceeds the safety limit".into());
    }
    let plaintext = open_profile_store(&key, &body)?;
    let store: VpnProfileStore =
        serde_json::from_slice(&plaintext).map_err(|e| format!("parse VPN profile store: {e}"))?;
    validate_profile_store(&store)?;
    Ok(Some(store))
}

/// Encrypt and atomically persist imported profiles. There is intentionally no
/// plaintext fallback: these records can contain WireGuard private keys.
#[tauri::command]
pub async fn vpn_profiles_save(app: AppHandle, store: VpnProfileStore) -> Result<(), String> {
    validate_profile_store(&store)?;
    if !crate::wallet::device_key::ensure_watch_key(&app).await {
        return Err("Device key unavailable — refusing to persist VPN private keys.".into());
    }
    let key = crate::wallet::device_key::vpn_profiles_key().ok_or_else(|| {
        "Device key unavailable — refusing to persist VPN private keys.".to_string()
    })?;
    let plaintext = Zeroizing::new(
        serde_json::to_vec(&store).map_err(|e| format!("serialize VPN profile store: {e}"))?,
    );
    if plaintext.len() > MAX_PROFILE_STORE {
        return Err("VPN profile store exceeds the safety limit".into());
    }
    let sealed = seal_profile_store(&key, &plaintext)?;
    atomic_private_write(&profile_store_path(&app)?, &sealed)
}

/// Forget all persisted profiles. Removing an absent store is idempotent.
#[tauri::command]
pub async fn vpn_profiles_clear(app: AppHandle) -> Result<(), String> {
    let path = profile_store_path(&app)?;
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove VPN profile store: {e}")),
    }
}

/// Ask the host to surface a dedicated LOCAL VPN control window. The OTA
/// renderer may call this because opening trusted UI is not itself a mutation.
/// The window has its own narrow capability (`vpn-control.json`); it never loads
/// remote/OTA content and is the only surface, besides classic `main`, granted
/// the VPN mutation commands.
#[tauri::command]
pub async fn vpn_open_window(
    app: AppHandle,
    theme: Option<String>,
    tokens: Option<VpnThemeTokens>,
    reveal: Option<bool>,
    locale: Option<String>,
) -> Result<(), String> {
    // Appearance is the only renderer-provided data accepted here. Theme is
    // allow-listed; tokens are validated computed colors/radii and mapped onto
    // fixed local variables. Neither can reach the broker.
    let theme = match theme.as_deref() {
        Some("light") => Some("light"),
        Some("dark") => Some("dark"),
        Some("system") => Some("system"),
        _ => None,
    };
    let locale = locale
        .as_deref()
        .filter(|value| matches!(*value, "en" | "es" | "ru" | "zh" | "ja" | "fa"))
        .unwrap_or("en");
    let reveal = reveal.unwrap_or(true);
    let script = theme_script(theme, tokens.as_ref(), Some(locale));
    if let Some(win) = app.get_webview_window("vpn-control") {
        let _ = win.eval(script);
        if reveal {
            let _ = win.show();
            let _ = win.set_focus();
        }
        return Ok(());
    }
    // Theme synchronization must not pop open a privileged control window the
    // user never requested.
    if !reveal {
        return Ok(());
    }

    let query = match theme {
        Some(theme) => format!("index.html?vpn-control=1&theme={theme}&locale={locale}"),
        None => format!("index.html?vpn-control=1&locale={locale}"),
    };
    // In a ROS-mode dev session the app's default dev URL points at the ROS
    // renderer (:5174), which intentionally does not contain the trusted
    // classic VPN control surface. Keep production on the bundled App URL;
    // only debug builds use the classic renderer's fixed dev server (:5173).
    #[cfg(debug_assertions)]
    let url = std::env::var("VPN_CONTROL_DEV_URL")
        .ok()
        .filter(|value| value.starts_with("http://localhost:5173/"))
        .map(|base| format!("{base}{query}"))
        .and_then(|raw| raw.parse::<tauri::Url>().ok())
        .map(tauri::WebviewUrl::External)
        .unwrap_or_else(|| tauri::WebviewUrl::App(query.clone().into()));
    #[cfg(not(debug_assertions))]
    let url = tauri::WebviewUrl::App(query.into());
    tauri::WebviewWindowBuilder::new(&app, "vpn-control", url)
        .initialization_script(script)
        .title("Ripley VPN · host-wide controls")
        .inner_size(900.0, 760.0)
        .min_inner_size(420.0, 560.0)
        .build()
        .map_err(|e| format!("open VPN controls: {e}"))?;
    Ok(())
}

/// Update locale in an already-open VPN control window without revealing or focusing it.
#[tauri::command]
pub async fn vpn_set_locale(app: AppHandle, locale: String) -> Result<(), String> {
    if !matches!(locale.as_str(), "en" | "es" | "ru" | "zh" | "ja" | "fa") {
        return Err("unsupported VPN locale".into());
    }
    if let Some(win) = app.get_webview_window("vpn-control") {
        let js_locale = serde_json::to_string(&locale).map_err(|e| e.to_string())?;
        let script = format!(
            "window.__ripleyVpnLocale={js_locale};window.dispatchEvent(new CustomEvent('ripley-vpn-locale-changed',{{detail:{js_locale}}}));"
        );
        win.eval(&script).map_err(|e| format!("update VPN locale: {e}"))?;
    }
    Ok(())
}

#[cfg(test)]
mod capability_tests {
    use super::{
        open_profile_store, seal_profile_store, theme_script, valid_computed_color,
        valid_computed_radius, validate_profile_store, StoredVpnProfile, VpnProfileStore,
        VpnThemeTokens,
    };

    fn permissions(raw: &str) -> Vec<String> {
        serde_json::from_str::<serde_json::Value>(raw).unwrap()["permissions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect()
    }

    #[test]
    fn ros_capabilities_cannot_mutate_the_host_vpn() {
        let forbidden = [
            "allow-vpn-probe-endpoints",
            "allow-vpn-connect",
            "allow-vpn-disconnect",
            "allow-vpn-set-killswitch",
            "allow-vpn-recover",
            "allow-vpn-emergency-restore",
            "allow-vpn-profiles-load",
            "allow-vpn-profiles-save",
            "allow-vpn-profiles-clear",
        ];
        for raw in [
            include_str!("../../capabilities/ros_local.json"),
            include_str!("../../capabilities/ros_remote.json"),
        ] {
            let p = permissions(raw);
            assert!(p.contains(&"allow-vpn-status".to_string()));
            assert!(p.contains(&"allow-vpn-open-window".to_string()));
            for denied in forbidden {
                assert!(
                    !p.contains(&denied.to_string()),
                    "{denied} leaked into a ROS capability"
                );
            }
        }
    }

    #[test]
    fn dedicated_local_control_window_has_only_structured_vpn_commands() {
        let p = permissions(include_str!("../../capabilities/vpn_control.json"));
        assert!(p.iter().all(|v| v.starts_with("allow-vpn-")));
        assert!(p.contains(&"allow-vpn-probe-endpoints".to_string()));
        assert!(p.contains(&"allow-vpn-emergency-restore".to_string()));
        assert!(!p.contains(&"allow-vpn-open-window".to_string()));
    }

    #[test]
    fn native_theme_bridge_accepts_only_computed_colors_and_bounded_px_radii() {
        for good in [
            "#fff",
            "#ff66aa",
            "rgb(12, 34, 56)",
            "rgba(12, 34, 56, 0.5)",
        ] {
            assert!(valid_computed_color(good), "{good}");
        }
        for bad in [
            "",
            "red",
            "var(--accent)",
            "url(https://evil.test/a)",
            "rgb(1,2,3);background:url(x)",
            "color(display-p3 1 0 0)",
        ] {
            assert!(!valid_computed_color(bad), "{bad}");
        }
        assert!(valid_computed_radius("12px"));
        assert!(!valid_computed_radius("-1px"));
        assert!(!valid_computed_radius("49px"));
        assert!(!valid_computed_radius("1rem"));
    }

    #[test]
    fn native_theme_script_uses_fixed_property_names_and_json_escaped_values() {
        let t = VpnThemeTokens {
            base: "rgb(10, 11, 12)".into(),
            panel: "rgb(20, 21, 22)".into(),
            surface: "rgb(30, 31, 32)".into(),
            text: "rgb(240, 241, 242)".into(),
            dim: "rgb(160, 161, 162)".into(),
            accent: "rgb(255, 100, 160)".into(),
            border: "rgba(1, 2, 3, 0.2)".into(),
            success: "rgb(20, 180, 100)".into(),
            warning: "rgb(240, 170, 40)".into(),
            error: "rgb(240, 70, 70)".into(),
            radius_sm: "6px".into(),
            radius_md: "12px".into(),
            radius_lg: "18px".into(),
        };
        let script = theme_script(Some("light"), Some(&t), Some("en"));
        assert!(script.contains("\"--brand-color\":\"rgb(255, 100, 160)\""));
        assert!(script.contains("\"--skin-radius-md\":\"12px\""));
        assert!(!script.contains("url("));
    }

    fn profile_store() -> VpnProfileStore {
        VpnProfileStore {
            v: 1,
            selected_profile_id: Some("0:fi.conf".into()),
            profiles: vec![StoredVpnProfile {
                id: "0:fi.conf".into(),
                name: "xeovo-fi".into(),
                source_path: "fi.conf".into(),
                kind: "wireguard".into(),
                config_text: "[Interface]\nPrivateKey = secret\n[Peer]\nPublicKey = public".into(),
            }],
        }
    }

    #[test]
    fn vpn_profile_store_is_authenticated_and_does_not_expose_private_keys() {
        let store = profile_store();
        validate_profile_store(&store).unwrap();
        let plaintext = serde_json::to_vec(&store).unwrap();
        let key = [7_u8; 32];
        let sealed = seal_profile_store(&key, &plaintext).unwrap();
        assert!(!sealed
            .windows(b"PrivateKey".len())
            .any(|window| window == b"PrivateKey"));
        let opened = open_profile_store(&key, &sealed).unwrap();
        let decoded: VpnProfileStore = serde_json::from_slice(&opened).unwrap();
        assert_eq!(
            decoded.profiles[0].config_text,
            store.profiles[0].config_text
        );

        let mut tampered = sealed;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open_profile_store(&key, &tampered).is_err());
        assert!(open_profile_store(&[8_u8; 32], &tampered).is_err());
    }

    #[test]
    fn vpn_profile_store_rejects_unknown_kinds_and_dangling_selection() {
        let mut store = profile_store();
        store.profiles[0].kind = "script".into();
        assert!(validate_profile_store(&store).is_err());
        store = profile_store();
        store.selected_profile_id = Some("missing".into());
        assert!(validate_profile_store(&store).is_err());
    }
}
