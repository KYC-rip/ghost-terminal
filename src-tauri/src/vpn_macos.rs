//! macOS WireGuard backend.
//!
//! macOS cannot use the Linux netlink/nftables broker, and a first-party
//! Network Extension cannot run without an Apple Developer signing identity.
//! This backend is therefore an explicitly administrator-authorized, one-shot
//! helper. The helper is the same native executable, entered before Tauri
//! starts; it receives one structured request over a random Unix socket,
//! validates WireGuard text with the shared broker parser, performs only
//! fixed-argument operations, replies, and exits.
//!
//! Runtime tools are the upstream Homebrew `wireguard-tools` package
//! (`wireguard-go`, `wg`, and Darwin's `wg-quick`). No profile text or private
//! key is placed in argv. The root-only transient config is replaced with a
//! key-free stub immediately after bring-up.

use std::{
    ffi::CString,
    fs,
    io::{Read, Write},
    net::{IpAddr, ToSocketAddrs},
    os::{
        fd::AsRawFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use ripley_vpn_broker::{parse_wg_config, EndpointHost, Ipv6Policy, WgConfig};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

const MAX_FRAME: usize = 32 * 1024;
const HELPER_WAIT: Duration = Duration::from_secs(180);
const IO_TIMEOUT: Duration = Duration::from_secs(20);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const STATE_DIR: &str = "/var/run/ripley-vpn";
const PRIVATE_STATE: &str = "/var/run/ripley-vpn/mac-state.json";
const PUBLIC_STATUS: &str = "/var/run/ripley-vpn/status.json";
const CONFIG_FILE: &str = "/var/run/ripley-vpn/ripley0.conf";
const WG_NAME_FILE: &str = "/var/run/wireguard/ripley0.name";
const PF_ANCHOR: &str = "com.apple/ripley-vpn";

struct SecretText(Zeroizing<String>);

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Self(Zeroizing::new(String::deserialize(d)?)))
    }
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum HelperRequest {
    #[serde(rename = "up")]
    Up {
        config_text: SecretText,
        #[serde(default)]
        profile_name: Option<String>,
    },
    DisconnectBlocked,
    DisconnectAndRestoreClearnet,
    EnableKillSwitch,
    DisableKillSwitch,
    ReconcileBlockedState,
    EmergencyRestoreClearnet,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct MacState {
    phase: String,
    egress: String,
    killswitch_active: bool,
    interface: Option<String>,
    handshake_age_secs: Option<u64>,
    cleanup_required: bool,
    backend: String,
    #[serde(default)]
    profile_name: Option<String>,
    /// Unix epoch seconds when the tunnel last reached configured/connected.
    #[serde(default)]
    connected_at_unix: Option<u64>,
    /// Pinned peer `ip:port` while a tunnel is up (for live speed probes).
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pf_token: Option<String>,
}

fn now_unix() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

impl MacState {
    fn open() -> Self {
        Self {
            phase: "disconnected_open".into(),
            egress: "open".into(),
            killswitch_active: false,
            interface: None,
            handshake_age_secs: None,
            cleanup_required: false,
            backend: "wireguard-go · macOS".into(),
            profile_name: None,
            connected_at_unix: None,
            endpoint: None,
            pf_token: None,
        }
    }

    fn blocked(token: Option<String>) -> Self {
        Self {
            phase: "disconnected_blocked".into(),
            egress: "blocked".into(),
            killswitch_active: true,
            interface: None,
            handshake_age_secs: None,
            cleanup_required: false,
            backend: "wireguard-go · macOS".into(),
            profile_name: None,
            connected_at_unix: None,
            endpoint: None,
            pf_token: token,
        }
    }

    fn public_value(&self) -> Value {
        let uptime_secs = match (self.connected_at_unix, now_unix()) {
            (Some(since), Some(now)) if self.interface.is_some() => Some(now.saturating_sub(since)),
            _ => None,
        };
        json!({
            "phase": self.phase,
            "egress": self.egress,
            "killswitch_active": self.killswitch_active,
            "interface": self.interface,
            "handshake_age_secs": self.handshake_age_secs,
            "uptime_secs": uptime_secs,
            "connected_at_unix": self.connected_at_unix,
            "endpoint": self.endpoint,
            "received_bytes": Value::Null,
            "sent_bytes": Value::Null,
            "cleanup_required": self.cleanup_required,
            "backend": self.backend,
            "profile_name": self.profile_name,
        })
    }
}

fn format_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(v4) => format!("{v4}:{port}"),
        IpAddr::V6(v6) => format!("[{v6}]:{port}"),
    }
}

/// Profile labels originate in ZIP entry names and cross a root boundary.
/// They are display-only metadata: bound their length and reject control
/// characters before persisting them in the privileged status journal.
fn clean_profile_name(value: Option<String>) -> Option<String> {
    let value = value?.trim().to_string();
    if value.is_empty()
        || value.len() > 80
        || !value.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b' ' | b'.' | b'_' | b'-' | b'(' | b')')
        })
    {
        return None;
    }
    Some(value)
}

fn tool(name: &str) -> Result<PathBuf, String> {
    let candidates: &[&str] = match name {
        "bash" => &["/opt/homebrew/bin/bash", "/usr/local/bin/bash"],
        "wg-quick" => &["/opt/homebrew/bin/wg-quick", "/usr/local/bin/wg-quick"],
        "wireguard-go" => &[
            "/opt/homebrew/bin/wireguard-go",
            "/usr/local/bin/wireguard-go",
        ],
        "wg" => &["/opt/homebrew/bin/wg", "/usr/local/bin/wg"],
        _ => return Err("unsupported VPN tool".into()),
    };
    candidates
        .iter()
        .map(PathBuf::from)
        .find(|path| path.is_file())
        .ok_or_else(|| {
            "macOS WireGuard runtime missing. Install it with: brew install wireguard-tools"
                .to_string()
        })
}

fn wait_child(mut child: Child, label: &str) -> Result<std::process::Output, String> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                return child
                    .wait_with_output()
                    .map_err(|e| format!("{label}: {e}"))
            }
            Ok(None) if start.elapsed() < COMMAND_TIMEOUT => {
                thread::sleep(Duration::from_millis(40))
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{label} timed out"));
            }
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{label}: {e}"));
            }
        }
    }
}

fn run_capture(path: &Path, args: &[&str], input: Option<&[u8]>) -> Result<String, String> {
    let mut child = Command::new(path)
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("start {}: {e}", path.display()))?;
    if let Some(bytes) = input {
        child
            .stdin
            .take()
            .ok_or_else(|| "helper stdin unavailable".to_string())?
            .write_all(bytes)
            .map_err(|e| format!("write helper stdin: {e}"))?;
    }
    let output = wait_child(child, &path.display().to_string())?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!(
        "{} failed: {}",
        path.display(),
        stderr.trim().chars().take(600).collect::<String>()
    ))
}

fn run(path: &Path, args: &[&str]) -> Result<(), String> {
    run_capture(path, args, None).map(|_| ())
}

fn run_combined(path: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new(path)
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("start {}: {e}", path.display()))?;
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    if output.status.success() {
        Ok(combined)
    } else {
        Err(format!(
            "{} failed: {}",
            path.display(),
            combined.trim().chars().take(600).collect::<String>()
        ))
    }
}

fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode))
        .map_err(|e| format!("secure {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("commit {}: {e}", path.display()))
}

fn read_private_state() -> MacState {
    fs::read(PRIVATE_STATE)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_else(MacState::open)
}

fn write_state(state: &MacState) -> Result<(), String> {
    fs::create_dir_all(STATE_DIR).map_err(|e| format!("create VPN state directory: {e}"))?;
    // The unprivileged host reads PUBLIC_STATUS directly. The directory must
    // therefore be traversable, while the private journal (which contains the
    // PF capability token) remains protected by its own 0600 mode.
    fs::set_permissions(STATE_DIR, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("set VPN status directory permissions: {e}"))?;
    atomic_write(
        Path::new(PRIVATE_STATE),
        &serde_json::to_vec(state).map_err(|e| e.to_string())?,
        0o600,
    )?;
    atomic_write(
        Path::new(PUBLIC_STATUS),
        &serde_json::to_vec(&state.public_value()).map_err(|e| e.to_string())?,
        0o644,
    )
}

fn parse_doh_ipv4(body: &str) -> Option<IpAddr> {
    let value: Value = serde_json::from_str(body).ok()?;
    value.get("Answer")?.as_array()?.iter().find_map(|answer| {
        if answer.get("type").and_then(Value::as_u64) != Some(1) {
            return None;
        }
        let ip: IpAddr = answer.get("data")?.as_str()?.parse().ok()?;
        (!is_synthetic_tunnel_ip(ip)
            && !ip.is_unspecified()
            && !ip.is_multicast()
            && !ip.is_loopback())
        .then_some(ip)
    })
}

fn resolve_doh_ipv4(host: &str) -> Result<IpAddr, String> {
    // Pin the resolver IP in curl. Using a DoH hostname without --resolve
    // would ask the polluted system resolver how to reach the resolver that is
    // supposed to escape it. TLS still verifies the real resolver hostname.
    const RESOLVERS: [(&str, &str, &str); 2] = [
        ("cloudflare-dns.com", "1.1.1.1", "dns-query"),
        ("dns.google", "8.8.8.8", "resolve"),
    ];
    let mut errors = Vec::new();
    for (resolver, ip, path) in RESOLVERS {
        let pin = format!("{resolver}:443:{ip}");
        let url = format!("https://{resolver}/{path}?name={host}&type=A");
        match run_capture(
            Path::new("/usr/bin/curl"),
            &[
                "-fsS",
                "--max-time",
                "8",
                "--resolve",
                &pin,
                "-H",
                "accept: application/dns-json",
                &url,
            ],
            None,
        ) {
            Ok(output) => {
                if let Some(endpoint) = parse_doh_ipv4(&output) {
                    return Ok(endpoint);
                }
                errors.push(format!("{resolver}: no usable A record"));
            }
            Err(error) => errors.push(format!("{resolver}: {error}")),
        }
    }
    Err(format!(
        "resolve real WireGuard endpoint through pinned HTTPS DNS: {}",
        errors.join("; ")
    ))
}

fn endpoint_ip(cfg: &WgConfig) -> Result<IpAddr, String> {
    match cfg.endpoint().host() {
        EndpointHost::Ip(ip) => Ok(*ip),
        EndpointHost::Dns(host) => {
            let system = (host.as_str(), cfg.endpoint().port())
                .to_socket_addrs()
                .map_err(|e| format!("resolve WireGuard endpoint: {e}"))?
                .map(|addr| addr.ip())
                .next()
                .ok_or_else(|| "WireGuard endpoint resolved to no address".to_string())?;
            if is_synthetic_tunnel_ip(system) {
                resolve_doh_ipv4(host)
            } else {
                Ok(system)
            }
        }
    }
}

fn is_synthetic_tunnel_ip(ip: IpAddr) -> bool {
    match ip {
        // RFC 2544 benchmarking space is commonly used by transparent
        // proxy/TUN clients (Mihomo/Clash fake-ip mode). It is not a routable
        // WireGuard peer address.
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            octets[0] == 198 && matches!(octets[1], 18 | 19)
        }
        IpAddr::V6(_) => false,
    }
}

/// Resolve a DNS-named endpoint while the kill-switch is armed. The blackhole
/// drops clearnet DNS, so we temporarily swap the anchor to permit HTTPS ONLY
/// to the two pinned DoH resolvers, resolve, and immediately re-seal the
/// blackhole. The anchor is never empty and the PF reference held by the armed
/// kill-switch is never touched, so egress stays fail-closed throughout.
fn resolve_endpoint_while_blocked(
    host: &str,
    prev_endpoint: Option<(IpAddr, u16)>,
) -> Result<IpAddr, String> {
    load_pf(&pf_rules_doh_only(prev_endpoint))
        .map_err(|e| format!("open DoH-only window: {e}"))?;
    let resolved = resolve_doh_ipv4(host);
    // Re-seal BEFORE inspecting the result — a resolution failure must not
    // leave the DoH window open.
    load_pf(&pf_rules(None, None, None, None))
        .map_err(|e| format!("re-seal kill-switch after endpoint resolution: {e}"))?;
    resolved
}

/// Resolve the connect endpoint. When the kill-switch is already armed the
/// normal system resolver cannot be used (the block drops clearnet DNS), so a
/// DNS-named endpoint is resolved through a brief, tightly-scoped DoH window
/// instead. IP endpoints never need DNS and are returned directly.
fn resolve_connect_endpoint(
    cfg: &WgConfig,
    blocked: bool,
    prev_endpoint: Option<(IpAddr, u16)>,
) -> Result<IpAddr, String> {
    match cfg.endpoint().host() {
        EndpointHost::Ip(ip) => Ok(*ip),
        EndpointHost::Dns(host) if !blocked => endpoint_ip(cfg),
        EndpointHost::Dns(host) => {
            eprintln!("ripley-vpn: kill-switch armed — resolving endpoint via pinned DoH");
            resolve_endpoint_while_blocked(host, prev_endpoint)
        }
    }
}

fn parse_endpoint_label(label: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = if let Some(rest) = label.strip_prefix('[') {
        let (host, rest) = rest.split_once(']')?;
        (host, rest.strip_prefix(':')?)
    } else {
        label.rsplit_once(':')?
    };
    let ip: IpAddr = host.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    (!ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback()).then_some((ip, port))
}

fn route_field(target: &str, field: &str) -> Result<String, String> {
    let output = run_capture(Path::new("/sbin/route"), &["-n", "get", target], None)?;
    output
        .lines()
        .find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key.trim() == field).then(|| value.trim().to_string())
        })
        .filter(|value| {
            !value.is_empty()
                && value.bytes().all(|b| {
                    b.is_ascii_alphanumeric() || matches!(b, b'.' | b':' | b'_' | b'-' | b'%')
                })
        })
        .ok_or_else(|| format!("could not determine {field} for WireGuard endpoint"))
}

fn render_config(cfg: &WgConfig, endpoint: IpAddr) -> Zeroizing<String> {
    let mut text = Zeroizing::new(String::with_capacity(640));
    text.push_str("[Interface]\nPrivateKey = ");
    text.push_str(&Zeroizing::new(
        STANDARD.encode(cfg.private_key().as_bytes()),
    ));
    text.push_str("\nAddress = ");
    for (index, cidr) in cfg.address().iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(&format!("{}/{}", cidr.addr, cidr.prefix));
    }
    text.push_str("\nDNS = ");
    for (index, dns) in cfg.dns().iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(&dns.to_string());
    }
    if let Some(mtu) = cfg.mtu() {
        text.push_str(&format!("\nMTU = {mtu}"));
    }
    if let Some(port) = cfg.listen_port() {
        text.push_str(&format!("\nListenPort = {port}"));
    }
    text.push_str("\n\n[Peer]\nPublicKey = ");
    text.push_str(&STANDARD.encode(cfg.peer_public_key().bytes()));
    if let Some(psk) = cfg.preshared_key() {
        text.push_str("\nPresharedKey = ");
        text.push_str(&Zeroizing::new(STANDARD.encode(psk.as_bytes())));
    }
    text.push_str("\nAllowedIPs = 0.0.0.0/0");
    if matches!(cfg.ipv6(), Ipv6Policy::FullTunnel) {
        text.push_str(", ::/0");
    }
    text.push_str("\nEndpoint = ");
    match endpoint {
        IpAddr::V4(ip) => text.push_str(&format!("{ip}:{}", cfg.endpoint().port())),
        IpAddr::V6(ip) => text.push_str(&format!("[{ip}]:{}", cfg.endpoint().port())),
    }
    if let Some(keepalive) = cfg.persistent_keepalive() {
        text.push_str(&format!("\nPersistentKeepalive = {keepalive}"));
    }
    text.push('\n');
    text
}

fn pf_rules(
    physical: Option<&str>,
    endpoint: Option<IpAddr>,
    port: Option<u16>,
    tunnel: Option<&str>,
) -> String {
    let mut rules = String::from(
        "pass quick on lo0 all\n\
         pass out quick proto udp from any port 68 to any port 67 keep state\n\
         pass out quick inet6 proto ipv6-icmp all\n",
    );
    if let (Some(interface), Some(ip), Some(port)) = (physical, endpoint, port) {
        let family = if ip.is_ipv4() { "inet" } else { "inet6" };
        // WireGuard transport (UDP) plus ICMP to the same pinned peer so the
        // host speed-test can measure the live server (not only tunnel peers).
        rules.push_str(&format!(
            "pass out quick on {interface} {family} proto udp to {ip} port = {port} keep state\n"
        ));
        if ip.is_ipv4() {
            rules.push_str(&format!(
                "pass out quick on {interface} inet proto icmp to {ip} keep state\n"
            ));
        } else {
            rules.push_str(&format!(
                "pass out quick on {interface} inet6 proto ipv6-icmp to {ip} keep state\n"
            ));
        }
    }
    if let Some(interface) = tunnel {
        rules.push_str(&format!("pass out quick on {interface} all\n"));
    }
    rules.push_str("block drop out all\n");
    rules
}

/// A tight, connect-only ruleset used to resolve a DNS-named endpoint while the
/// kill-switch is armed. The blackhole drops clearnet DNS, so the ONLY clearnet
/// egress permitted here is HTTPS to the two hardcoded DoH resolvers the
/// resolver already pins (`resolve_doh_ipv4`). Everything else stays
/// fail-closed. The anchor is swapped in, the endpoint resolved, then the
/// blackhole is re-sealed — never left in this state.
///
/// `prev_endpoint` is the peer the armed kill-switch was pinning. A reconnect
/// while that tunnel is still up routes the DoH query INTO it; the re-encapsulated
/// WireGuard transport to the previous peer must escape, or the query dies inside
/// the still-live tunnel and both resolvers time out. It is the same peer the
/// kill-switch already permits, so no additional egress is opened.
fn pf_rules_doh_only(prev_endpoint: Option<(IpAddr, u16)>) -> String {
    let mut rules = String::from(
        "pass quick on lo0 all\n\
         pass out quick proto udp from any port 68 to any port 67 keep state\n\
         pass out quick inet6 proto ipv6-icmp all\n\
         pass out quick proto tcp to 1.1.1.1 port = 443 keep state\n\
         pass out quick proto tcp to 8.8.8.8 port = 443 keep state\n",
    );
    if let Some((ip, port)) = prev_endpoint {
        let family = if ip.is_ipv4() { "inet" } else { "inet6" };
        rules.push_str(&format!(
            "pass out quick {family} proto udp to {ip} port = {port} keep state\n"
        ));
    }
    rules.push_str("block drop out all\n");
    rules
}

/// DNS-filter rdr rules for the loopback filter (`dnsfilter::FILTER_ADDR`).
/// Redirects ALL outbound port-53 (UDP and TCP) to the on-device filter so
/// hardcoded-resolver bypasses still hit the blocklist. The filter runs in the
/// app process; this ruleset is installed by the helper when DNS filtering is
/// enabled and removed on disable.
fn pf_rules_dns_filter() -> String {
    "rdr pass proto udp from any to any port = 53 -> 127.0.0.1 port 5353\n\
     rdr pass proto tcp from any to any port = 53 -> 127.0.0.1 port 5353\n"
        .to_string()
}

fn enable_pf() -> Result<Option<String>, String> {
    // Darwin's pfctl writes its reference-count token to stderr on some OS
    // releases even when the command succeeds. Preserve both streams so we
    // can release exactly our own PF reference during restore.
    let output = run_combined(Path::new("/sbin/pfctl"), &["-E"])?;
    Ok(output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Token : ").map(str::to_string)))
}

fn load_pf(rules: &str) -> Result<(), String> {
    run_capture(
        Path::new("/sbin/pfctl"),
        &["-a", PF_ANCHOR, "-f", "-"],
        Some(rules.as_bytes()),
    )
    .map(|_| ())
}

fn clear_pf(token: Option<&str>) -> Result<(), String> {
    run(Path::new("/sbin/pfctl"), &["-a", PF_ANCHOR, "-F", "all"])?;
    if let Some(token) = token {
        // The anchor flush is the security-critical network restoration.
        // Releasing our PF reference is bookkeeping: a stale reference can
        // leave PF enabled, but with this anchor empty it cannot block traffic.
        let _ = run(Path::new("/sbin/pfctl"), &["-X", token]);
    }
    Ok(())
}

fn wg_quick(action: &str) -> Result<(), String> {
    let bash = tool("bash")?;
    let quick = tool("wg-quick")?;
    let go = tool("wireguard-go")?;
    let wg = tool("wg")?;
    let child = Command::new(&bash)
        .arg(&quick)
        .arg(action)
        .arg(CONFIG_FILE)
        .env_clear()
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .env("WG_QUICK_USERSPACE_IMPLEMENTATION", go)
        .env("WG_QUICK_WG", wg)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("start wg-quick: {e}"))?;
    let output = wait_child(child, "wg-quick")?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "wg-quick failed: {}",
            String::from_utf8_lossy(&output.stderr)
                .trim()
                .chars()
                .take(800)
                .collect::<String>()
        ))
    }
}

fn read_tunnel_name() -> Result<String, String> {
    fs::read_to_string(WG_NAME_FILE)
        .map_err(|e| format!("read WireGuard tunnel name: {e}"))
        .map(|name| name.trim().to_string())
        .and_then(|name| {
            if name.starts_with("utun")
                && name[4..].bytes().all(|byte| byte.is_ascii_digit())
                && name.len() <= 15
            {
                Ok(name)
            } else {
                Err("WireGuard returned an invalid tunnel name".into())
            }
        })
}

fn handshake_age(interface: &str) -> Option<u64> {
    let wg = tool("wg").ok()?;
    let output = run_capture(&wg, &["show", interface, "latest-handshakes"], None).ok()?;
    let latest = output
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1)?.parse::<u64>().ok())
        .max()
        .filter(|stamp| *stamp > 0)?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(latest))
}

fn transfer_counters(interface: &str) -> Option<(u64, u64)> {
    let wg = tool("wg").ok()?;
    let output = run_capture(&wg, &["show", interface, "transfer"], None).ok()?;
    let counters = output.lines().fold((0_u64, 0_u64), |totals, line| {
        let mut fields = line.split_whitespace();
        let _public_key = fields.next();
        let received = fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let sent = fields
            .next()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        (
            totals.0.saturating_add(received),
            totals.1.saturating_add(sent),
        )
    });
    Some(counters)
}

fn await_handshake(interface: &str) -> Option<u64> {
    let started = Instant::now();
    loop {
        if let Some(age) = handshake_age(interface) {
            return Some(age);
        }
        if started.elapsed() >= Duration::from_secs(15) {
            return None;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn handshake_diagnostics(interface: &str, endpoint: IpAddr, physical: &str) -> String {
    let transfer = tool("wg")
        .and_then(|wg| run_capture(&wg, &["show", interface, "transfer"], None))
        .ok()
        .and_then(|output| {
            let (received, sent) = output.lines().fold((0_u64, 0_u64), |totals, line| {
                let mut fields = line.split_whitespace();
                let _public_key = fields.next();
                let received = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                let sent = fields.next().and_then(|v| v.parse().ok()).unwrap_or(0);
                (
                    totals.0.saturating_add(received),
                    totals.1.saturating_add(sent),
                )
            });
            Some(format!("UDP counters sent={sent}B received={received}B"))
        })
        .unwrap_or_else(|| "UDP counters unavailable".into());
    let route_interface =
        route_field(&endpoint.to_string(), "interface").unwrap_or_else(|_| "unknown".into());
    let route_gateway =
        route_field(&endpoint.to_string(), "gateway").unwrap_or_else(|_| "unknown".into());
    format!(
        "{transfer}; endpoint route interface={route_interface}, gateway={route_gateway}, expected physical interface={physical}"
    )
}

fn remove_endpoint_route(endpoint: IpAddr) {
    let endpoint_text = endpoint.to_string();
    let family = if endpoint.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    };
    let _ = run(
        Path::new("/sbin/route"),
        &["-q", "-n", "delete", family, &endpoint_text],
    );
}

fn pin_endpoint_route(endpoint: IpAddr, gateway: &str, physical: &str) -> Result<(), String> {
    let endpoint_text = endpoint.to_string();
    let family = if endpoint.is_ipv4() {
        "-inet"
    } else {
        "-inet6"
    };
    run(
        Path::new("/sbin/route"),
        &[
            "-q",
            "-n",
            "add",
            family,
            &endpoint_text,
            "-gateway",
            gateway,
        ],
    )?;
    let observed = route_field(&endpoint_text, "interface")?;
    if observed != physical {
        remove_endpoint_route(endpoint);
        return Err(format!(
            "endpoint route verification selected {observed}, expected {physical}"
        ));
    }
    Ok(())
}

/// Authoritative tunnel teardown: destroy the utun interface. Returns Ok when
/// the interface is verifiably gone — either destroyed just now, or already
/// absent (e.g. a dropped connection that the kernel cleaned up). wg-quick
/// down alone is unreliable here (its stale-file heuristic can refuse), and a
/// dropped tunnel may leave nothing to destroy, so "already gone" must not be
/// treated as a teardown failure.
fn destroy_tunnel_interface(iface: &str) -> Result<(), String> {
    let _ = run(Path::new("/sbin/ifconfig"), &[iface, "destroy"]);
    // ifconfig <iface> exits non-zero when the interface does not exist.
    if run(Path::new("/sbin/ifconfig"), &[iface]).is_err() {
        Ok(())
    } else {
        Err(format!("WireGuard interface {iface} still present after destroy"))
    }
}

/// Destroy whichever utun owns the route to `ip`, if any. A tunnel left behind
/// by a failed/partial teardown keeps its split-default routes (`0/1`,
/// `128/1`), which capture the DoH resolver addresses even after the default
/// route has returned to the physical link — routing the DoH window into a
/// dead interface. Keyed on the live route, not stale state, so it catches
/// tunnels whose interface name state no longer records.
fn destroy_tunnel_owning(ip: &str) {
    let Some(iface) = route_field(ip, "interface").ok().filter(|i| i.starts_with("utun")) else {
        return;
    };
    let _ = destroy_tunnel_interface(&iface);
}

fn fail_connect(token: Option<String>, endpoint: Option<IpAddr>, reason: String) -> String {
    // wg-quick down can refuse ("'ripley0' is not a WireGuard interface") even
    // when the utun is up; destroying the interface is the authoritative
    // teardown, so attempt both.
    let had_interface = Path::new(WG_NAME_FILE).is_file();
    let down = if had_interface {
        let _ = wg_quick("down");
        read_tunnel_name()
            .ok()
            .map(|iface| destroy_tunnel_interface(&iface))
            .and_then(|result| result.err())
    } else {
        None
    };
    if let Some(endpoint) = endpoint {
        // wg-quick normally removes this direct route. This explicit,
        // idempotent cleanup also covers failures before it acquired the
        // interface.
        remove_endpoint_route(endpoint);
    }
    let _ = fs::remove_file(CONFIG_FILE);
    let restore = clear_pf(token.as_deref()).err();
    if down.is_none() && restore.is_none() {
        let _ = write_state(&MacState::open());
        return format!("{reason}. The attempted tunnel was removed and clearnet was restored.");
    }

    let dirty = MacState {
        phase: "error_blocked".into(),
        egress: "blocked".into(),
        killswitch_active: true,
        interface: read_tunnel_name().ok(),
        handshake_age_secs: None,
        cleanup_required: true,
        backend: "wireguard-go · macOS".into(),
        profile_name: None,
        connected_at_unix: None,
        endpoint: None,
        pf_token: token.clone(),
    };
    let _ = write_state(&dirty);
    format!(
        "{reason}. AUTOMATIC NETWORK RESTORATION FAILED (tunnel cleanup: {}; PF cleanup: {}). Use Emergency restore clearnet or restart macOS.",
        down.as_deref().unwrap_or("ok"),
        restore.as_deref().unwrap_or("ok"),
    )
}

fn connect(config_text: &str, profile_name: Option<String>) -> Result<MacState, String> {
    let profile_name = clean_profile_name(profile_name);
    // The shared parser canonicalizes wg-quick's optional Address masks to
    // /32 and /128 before any privileged network mutation.
    let cfg = parse_wg_config(config_text).map_err(|e| format!("invalid WireGuard config: {e}"))?;
    // Check every required runtime before sealing egress.
    for name in ["bash", "wg-quick", "wireguard-go", "wg"] {
        tool(name)?;
    }
    let previous = read_private_state();
    // A tunnel left behind by a failed/partial teardown owns split-default
    // routes that capture the DoH resolver addresses; the resolution would be
    // routed into it and die. Destroy whatever utun owns those routes — keyed
    // on the live route table, NOT stale state (a prior buggy teardown left
    // interface: None while the tunnel survived).
    destroy_tunnel_owning("1.1.1.1");
    destroy_tunnel_owning("8.8.8.8");
    // The kill-switch pins the previous peer. If the previous tunnel is still
    // up, the DoH query is routed into it and the encapsulated WireGuard
    // transport to that peer must be permitted inside the window.
    let prev_endpoint = previous
        .endpoint
        .as_deref()
        .and_then(parse_endpoint_label);
    let endpoint = resolve_connect_endpoint(&cfg, previous.killswitch_active, prev_endpoint)?;
    // Use the physical default link, not the current route to the peer. A
    // transparent proxy can own split-default routes through another utun;
    // wg-quick will add a host route for this real, DoH-resolved endpoint via
    // the physical gateway.
    let physical = route_field("default", "interface")?;
    let physical_gateway = route_field("default", "gateway")?;
    if physical.starts_with("utun") {
        return Err(format!(
            "the macOS default route is already owned by {physical}; no physical endpoint bypass can be proven, so Ripley refused before any network change"
        ));
    }
    // Reuse the PF reference held by an armed kill-switch instead of bumping
    // the refcount and orphaning the old token (that would leave PF enabled
    // after a later restore). Fall back to enabling PF only when there is no
    // held token (open state, or legacy state without one).
    let token = if previous.killswitch_active && previous.pf_token.is_some() {
        previous.pf_token
    } else {
        enable_pf()?
    };
    let initial_rules = pf_rules(
        Some(&physical),
        Some(endpoint),
        Some(cfg.endpoint().port()),
        None,
    );
    if let Err(error) = load_pf(&initial_rules) {
        let _ = clear_pf(token.as_deref());
        return Err(error);
    }
    let endpoint_label = format_endpoint(endpoint, cfg.endpoint().port());
    let connecting = MacState {
        phase: "connecting_blocked".into(),
        egress: "blocked".into(),
        killswitch_active: true,
        interface: None,
        handshake_age_secs: None,
        cleanup_required: false,
        backend: "wireguard-go · macOS".into(),
        profile_name: profile_name.clone(),
        connected_at_unix: None,
        endpoint: Some(endpoint_label.clone()),
        pf_token: token.clone(),
    };
    if let Err(error) = write_state(&connecting) {
        // Nothing beyond the PF anchor has changed yet. If we cannot publish
        // the blocked state, undo the anchor rather than invisibly stranding
        // the machine behind a kill-switch the UI cannot observe.
        let _ = clear_pf(token.as_deref());
        return Err(error);
    }
    // Install and prove the endpoint exception before wireguard-go opens its
    // UDP socket. Transparent proxy TUNs commonly install split-default
    // routes; waiting for wg-quick to add this exception after `wg setconf`
    // lets the first handshake bind to the wrong route.
    if let Err(error) = pin_endpoint_route(endpoint, &physical_gateway, &physical) {
        return Err(fail_connect(token, None, error));
    }

    let canonical = render_config(&cfg, endpoint);
    if let Err(error) = atomic_write(Path::new(CONFIG_FILE), canonical.as_bytes(), 0o600) {
        return Err(fail_connect(token, Some(endpoint), error));
    }
    if let Err(error) = wg_quick("up") {
        return Err(fail_connect(token, Some(endpoint), error));
    }
    // wg-quick only needs the filename and interface mapping for down. Remove
    // key material immediately; the live backend owns its zeroizing copy.
    let post_up = (|| {
        atomic_write(Path::new(CONFIG_FILE), b"[Interface]\n", 0o600)?;
        let tunnel = read_tunnel_name()?;
        load_pf(&pf_rules(
            Some(&physical),
            Some(endpoint),
            Some(cfg.endpoint().port()),
            Some(&tunnel),
        ))?;
        Ok::<String, String>(tunnel)
    })();
    let tunnel = match post_up {
        Ok(tunnel) => tunnel,
        Err(error) => {
            return Err(fail_connect(token, Some(endpoint), error));
        }
    };
    let observed_handshake = await_handshake(&tunnel);
    if observed_handshake.is_none() {
        let diagnostics = handshake_diagnostics(&tunnel, endpoint, &physical);
        return Err(fail_connect(
            token,
            Some(endpoint),
            format!(
                "WireGuard interface started but no handshake was observed within 15 seconds ({diagnostics})"
            ),
        ));
    }
    let connected = MacState {
        phase: "connected".into(),
        egress: "blocked".into(),
        killswitch_active: true,
        interface: Some(tunnel),
        handshake_age_secs: observed_handshake,
        cleanup_required: false,
        backend: "wireguard-go · macOS".into(),
        profile_name,
        connected_at_unix: now_unix(),
        endpoint: Some(endpoint_label),
        pf_token: token.clone(),
    };
    if let Err(error) = write_state(&connected) {
        return Err(fail_connect(token, Some(endpoint), error));
    }
    Ok(connected)
}

fn disconnect(restore: bool, emergency: bool) -> Result<MacState, String> {
    let previous = read_private_state();
    // wg-quick down is best-effort on macOS: cmd_down() refuses with "'ripley0'
    // is not a WireGuard interface" when its stale-file heuristic trips even
    // though the utun is up, and on success it only unlinks the UAPI socket and
    // name files. Destroying the interface is the authoritative teardown —
    // routes die with it — so a wg-quick refusal must not block it.
    let down = wg_quick("down");
    // Prefer the interface named in state; fall back to whichever utun owns
    // the resolver routes (a stale tunnel may survive with interface: None).
    let interface_gone = previous
        .interface
        .as_deref()
        .map(destroy_tunnel_interface)
        .map(|result| result.is_ok())
        .unwrap_or(false);
    if !interface_gone {
        destroy_tunnel_owning("1.1.1.1");
        destroy_tunnel_owning("8.8.8.8");
    }
    if down.is_err() && !interface_gone && !emergency && previous.interface.is_some() {
        let mut dirty = previous;
        dirty.phase = "error_blocked".into();
        dirty.cleanup_required = true;
        write_state(&dirty)?;
        return Err(down.unwrap_err());
    }
    let _ = fs::remove_file(CONFIG_FILE);
    if restore {
        clear_pf(previous.pf_token.as_deref())?;
        let open = MacState::open();
        write_state(&open)?;
        Ok(open)
    } else {
        let token = if previous.killswitch_active {
            previous.pf_token
        } else {
            enable_pf()?
        };
        load_pf(&pf_rules(None, None, None, None))?;
        let mut blocked = MacState::blocked(token);
        // Keep the last pinned peer so a reconnect's DoH window can re-allow
        // the encapsulated transport even if the interface teardown failed.
        blocked.endpoint = previous.endpoint.clone();
        write_state(&blocked)?;
        Ok(blocked)
    }
}

fn handle(request: HelperRequest) -> Result<MacState, String> {
    match request {
        HelperRequest::Up {
            config_text,
            profile_name,
        } => connect(config_text.0.as_str(), profile_name),
        HelperRequest::DisconnectBlocked => disconnect(false, false),
        HelperRequest::DisconnectAndRestoreClearnet => disconnect(true, false),
        HelperRequest::EnableKillSwitch | HelperRequest::ReconcileBlockedState => {
            let previous = read_private_state();
            if previous.interface.is_some() {
                return Ok(previous);
            }
            let token = if previous.killswitch_active {
                previous.pf_token
            } else {
                enable_pf()?
            };
            load_pf(&pf_rules(None, None, None, None))?;
            let blocked = MacState::blocked(token);
            write_state(&blocked)?;
            Ok(blocked)
        }
        HelperRequest::DisableKillSwitch => {
            let previous = read_private_state();
            if previous.interface.is_some() {
                return Err("disconnect the VPN before disabling the kill-switch".into());
            }
            clear_pf(previous.pf_token.as_deref())?;
            let open = MacState::open();
            write_state(&open)?;
            Ok(open)
        }
        HelperRequest::EmergencyRestoreClearnet => disconnect(true, true),
    }
}

fn peer_uid(stream: &std::os::unix::net::UnixStream) -> Result<u32, String> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if rc == 0 {
        Ok(uid)
    } else {
        Err(std::io::Error::last_os_error().to_string())
    }
}

fn helper(socket: &Path, expected_uid: u32) -> Result<(), String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("macOS VPN helper must run as root".into());
    }
    if expected_uid == 0 || socket.exists() {
        return Err("invalid macOS VPN helper socket".into());
    }
    let listener = UnixListener::bind(socket).map_err(|e| format!("bind helper socket: {e}"))?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("secure helper socket: {e}"))?;
    let path = CString::new(socket.as_os_str().as_encoded_bytes())
        .map_err(|_| "helper socket contains NUL".to_string())?;
    if unsafe { libc::chown(path.as_ptr(), expected_uid, u32::MAX) } != 0 {
        return Err(format!(
            "chown helper socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    let (mut stream, _) = listener
        .accept()
        .map_err(|e| format!("accept helper request: {e}"))?;
    if peer_uid(&stream)? != expected_uid {
        return Err("VPN helper rejected a different local user".into());
    }
    stream.set_read_timeout(Some(IO_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut frame = Zeroizing::new(Vec::with_capacity(2048));
    let mut byte = [0_u8; 1];
    while frame.len() <= MAX_FRAME {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) => frame.push(byte[0]),
            Err(error) => return Err(format!("read helper request: {error}")),
        }
    }
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err("invalid VPN helper request frame".into());
    }
    let request: HelperRequest =
        serde_json::from_slice(&frame).map_err(|_| "invalid VPN helper request".to_string())?;
    let response = match handle(request) {
        Ok(status) => json!({"result":"ok","status":status.public_value()}),
        Err(reason) => json!({"result":"error","reason":reason}),
    };
    let mut body = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    body.push(b'\n');
    stream
        .write_all(&body)
        .map_err(|e| format!("write helper response: {e}"))?;
    let _ = fs::remove_file(socket);
    Ok(())
}

/// Called before Tauri starts. Returns true when this process was the one-shot
/// privileged helper and should exit immediately.
pub fn run_helper_from_args() -> bool {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("--vpn-macos-helper") {
        return false;
    }
    let result = (|| {
        let socket = args
            .get(2)
            .map(PathBuf::from)
            .ok_or_else(|| "missing helper socket".to_string())?;
        let uid = args
            .get(3)
            .ok_or_else(|| "missing helper uid".to_string())?
            .parse::<u32>()
            .map_err(|_| "invalid helper uid".to_string())?;
        helper(&socket, uid)
    })();
    if let Err(error) = result {
        eprintln!("Ripley VPN helper: {error}");
        std::process::exit(1);
    }
    true
}

fn random_socket() -> PathBuf {
    let mut random = [0_u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut random);
    std::env::temp_dir().join(format!("ripley-vpn-{}.sock", hex::encode(random)))
}

fn spawn_authorized_helper(socket: &Path) -> Result<Child, String> {
    let executable = std::env::current_exe().map_err(|e| format!("locate VPN helper: {e}"))?;
    let uid = unsafe { libc::getuid() }.to_string();
    // Development binaries are unsigned on this machine. Packaged builds must
    // pass Apple's strict signature verification before the administrator
    // prompt launches their privileged entry point.
    #[cfg(debug_assertions)]
    let script = r#"on run argv
set helperPath to item 1 of argv
set socketPath to item 2 of argv
set userId to item 3 of argv
set commandText to quoted form of helperPath & " --vpn-macos-helper " & quoted form of socketPath & " " & quoted form of userId
do shell script commandText with administrator privileges
end run"#;
    #[cfg(not(debug_assertions))]
    let script = r#"on run argv
set helperPath to item 1 of argv
set socketPath to item 2 of argv
set userId to item 3 of argv
set verifyText to "/usr/bin/codesign --verify --strict " & quoted form of helperPath
set commandText to verifyText & " && exec " & quoted form of helperPath & " --vpn-macos-helper " & quoted form of socketPath & " " & quoted form of userId
do shell script commandText with administrator privileges
end run"#;
    Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(script)
        .arg(executable)
        .arg(socket)
        .arg(uid)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("open administrator authorization: {e}"))
}

fn connect_when_ready(
    socket: &Path,
    child: &mut Child,
) -> Result<std::os::unix::net::UnixStream, String> {
    let start = Instant::now();
    loop {
        match std::os::unix::net::UnixStream::connect(socket) {
            Ok(stream) => return Ok(stream),
            Err(_) if start.elapsed() < HELPER_WAIT => {
                if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
                    return Err(format!(
                        "VPN authorization was cancelled or failed ({status})"
                    ));
                }
                thread::sleep(Duration::from_millis(100));
            }
            Err(error) => {
                let _ = child.kill();
                return Err(format!("VPN authorization timed out: {error}"));
            }
        }
    }
}

pub fn privileged_call(request: Value) -> Result<Value, String> {
    let socket = random_socket();
    let mut child = spawn_authorized_helper(&socket)?;
    let mut stream = connect_when_ready(&socket, &mut child)?;
    stream.set_read_timeout(Some(COMMAND_TIMEOUT)).ok();
    stream.set_write_timeout(Some(IO_TIMEOUT)).ok();
    let mut body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    body.push(b'\n');
    stream
        .write_all(&body)
        .map_err(|e| format!("send VPN helper request: {e}"))?;
    let mut response = Vec::with_capacity(512);
    stream
        .take(MAX_FRAME as u64)
        .read_to_end(&mut response)
        .map_err(|e| format!("read VPN helper response: {e}"))?;
    let _ = child.wait();
    let _ = fs::remove_file(&socket);
    let value: Value =
        serde_json::from_slice(&response).map_err(|e| format!("bad VPN helper response: {e}"))?;
    match value.get("result").and_then(Value::as_str) {
        Some("ok") => Ok(value.get("status").cloned().unwrap_or(Value::Null)),
        Some(_) => Err(value
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("macOS VPN helper failed")
            .to_string()),
        None => Err("malformed macOS VPN helper response".into()),
    }
}

pub fn status() -> Value {
    let stored: Option<Value> = fs::read(PUBLIC_STATUS)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok());
    // Migration for tunnels created by the first macOS backend build: its
    // public file was 0644, but the containing root directory was mistakenly
    // 0700. A live wg-quick mapping plus exactly one userspace WireGuard
    // interface lets us recover the observable state without another admin
    // prompt. Future helper writes make the directory 0755 and use the normal
    // stored path above.
    let inferred = || -> Option<Value> {
        if !Path::new(WG_NAME_FILE).exists() {
            return None;
        }
        let wg = tool("wg").ok()?;
        let interfaces = run_capture(&wg, &["show", "interfaces"], None).ok()?;
        let mut names = interfaces.split_whitespace();
        let interface = names.next()?.to_string();
        if names.next().is_some() {
            return None;
        }
        // The legacy root-owned UAPI socket also prevents an unprivileged
        // handshake query. Prove that the sole userspace WireGuard interface
        // owns the full-tunnel route instead; the privileged connect path
        // already refused to publish success until it observed a handshake.
        if route_field("1.1.1.1", "interface").ok().as_deref() != Some(interface.as_str()) {
            return None;
        }
        Some(json!({
            "phase": "connected",
            "egress": "blocked",
            "killswitch_active": true,
            "interface": interface,
            "handshake_age_secs": null,
            "received_bytes": null,
            "sent_bytes": null,
            "cleanup_required": false,
            "backend": "wireguard-go · macOS",
            "profile_name": null,
        }))
    };
    let mut value = stored
        .or_else(inferred)
        .unwrap_or_else(|| MacState::open().public_value());
    if matches!(
        value.get("phase").and_then(Value::as_str),
        Some("connected" | "degraded_blocked")
    ) {
        if let Some(interface) = value
            .get("interface")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            let live = Command::new("/sbin/ifconfig")
                .arg(&interface)
                .env_clear()
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false);
            if !live {
                value["phase"] = Value::String("error_blocked".into());
                value["cleanup_required"] = Value::Bool(true);
            } else {
                if let Some(age) = handshake_age(&interface) {
                    value["phase"] = Value::String("connected".into());
                    value["handshake_age_secs"] = Value::Number(age.into());
                }
                if let Some((received, sent)) = transfer_counters(&interface) {
                    value["received_bytes"] = Value::Number(received.into());
                    value["sent_bytes"] = Value::Number(sent.into());
                }
                // Prefer the stamped connect time. Older status files (pre-field)
                // fall back to the public status file mtime (last written on
                // connect/state change) so uptime is not reinvented by the UI.
                let mut since = value.get("connected_at_unix").and_then(Value::as_u64);
                if since.is_none() {
                    if let Ok(meta) = std::fs::metadata(PUBLIC_STATUS) {
                        if let Ok(modified) = meta.modified() {
                            if let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) {
                                since = Some(d.as_secs());
                                value["connected_at_unix"] =
                                    Value::Number(d.as_secs().into());
                            }
                        }
                    }
                }
                if let (Some(since), Some(now)) = (since, now_unix()) {
                    value["uptime_secs"] =
                        Value::Number(now.saturating_sub(since).into());
                }
            }
        }
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_anchor_is_fail_closed_and_only_interpolates_typed_values() {
        let rules = pf_rules(
            Some("en0"),
            Some("203.0.113.5".parse().unwrap()),
            Some(51820),
            Some("utun9"),
        );
        assert!(rules.contains("pass out quick on en0 inet proto udp to 203.0.113.5 port = 51820"));
        assert!(rules.contains("pass out quick on en0 inet proto icmp to 203.0.113.5 keep state"));
        assert!(rules.contains("pass out quick on utun9 all"));
        assert!(rules.ends_with("block drop out all\n"));
        assert!(!rules.contains(';'));
    }

    #[test]
    fn canonical_render_cannot_preserve_wg_quick_hooks() {
        let key = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
        let raw = format!(
            "[Interface]\nPrivateKey = {key}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\
             [Peer]\nPublicKey = {key}\nEndpoint = 203.0.113.5:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        let cfg = parse_wg_config(&raw).unwrap();
        let rendered = render_config(&cfg, "203.0.113.5".parse().unwrap());
        for forbidden in [
            "PreUp",
            "PostUp",
            "PreDown",
            "PostDown",
            "SaveConfig",
            "Table",
        ] {
            assert!(!rendered.contains(forbidden));
        }
    }

    #[test]
    fn public_status_never_contains_pf_capability_token() {
        let mut state = MacState::blocked(Some("secret-token".into()));
        state.interface = Some("utun9".into());
        state.profile_name = Some("xeovo-al".into());
        let text = state.public_value().to_string();
        assert!(!text.contains("secret-token"));
        assert!(!text.contains("pf_token"));
        assert!(text.contains("xeovo-al"));
    }

    #[test]
    fn profile_names_are_bounded_and_control_free() {
        assert_eq!(
            clean_profile_name(Some("  xeovo-al  ".into())).as_deref(),
            Some("xeovo-al")
        );
        assert_eq!(clean_profile_name(Some("bad\nname".into())), None);
        assert_eq!(clean_profile_name(Some("bad\u{202e}name".into())), None);
        assert_eq!(clean_profile_name(Some("x".repeat(81))), None);
    }

    #[test]
    fn installed_pf_syntax_parses_without_loading_rules() {
        let rules = pf_rules(
            Some("en0"),
            Some("203.0.113.5".parse().unwrap()),
            Some(51820),
            Some("utun9"),
        );
        let parsed = run_capture(
            Path::new("/sbin/pfctl"),
            &["-nf", "-"],
            Some(rules.as_bytes()),
        );
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn doh_only_ruleset_permits_only_the_two_pinned_resolvers() {
        let rules = pf_rules_doh_only(None);
        assert!(rules.contains("pass out quick proto tcp to 1.1.1.1 port = 443 keep state"));
        assert!(rules.contains("pass out quick proto tcp to 8.8.8.8 port = 443 keep state"));
        assert_eq!(rules.matches("port = 443").count(), 2);
        assert!(rules.ends_with("block drop out all\n"));
        assert!(!rules.contains("pass out quick on en0"));
        assert!(!rules.contains("proto tcp to 1.1.1.1 port = 80"));
        assert!(!rules.contains("proto udp to 1.1.1.1 port = 53"));
    }

    #[test]
    fn doh_only_ruleset_also_permits_previous_peer_transport() {
        let rules = pf_rules_doh_only(Some(("167.88.161.83".parse().unwrap(), 51820)));
        assert!(rules.contains("pass out quick inet proto udp to 167.88.161.83 port = 51820 keep state"));
        assert!(rules.contains("pass out quick proto tcp to 1.1.1.1 port = 443 keep state"));
        assert!(rules.ends_with("block drop out all\n"));
    }

    #[test]
    fn endpoint_label_roundtrips_through_parser() {
        assert_eq!(
            parse_endpoint_label("167.88.161.83:51820"),
            Some(("167.88.161.83".parse().unwrap(), 51820))
        );
        assert_eq!(
            parse_endpoint_label("[2001:db8::1]:51820"),
            Some(("2001:db8::1".parse().unwrap(), 51820))
        );
        assert_eq!(parse_endpoint_label("not-an-endpoint"), None);
        assert_eq!(parse_endpoint_label("0.0.0.0:51820"), None);
        assert_eq!(parse_endpoint_label("1.1.1.1:notaport"), None);
    }

    #[test]
    fn doh_only_rules_parse() {
        let parsed = run_capture(
            Path::new("/sbin/pfctl"),
            &["-nf", "-"],
            Some(pf_rules_doh_only(None).as_bytes()),
        );
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn doh_only_rules_with_prev_peer_parse() {
        let parsed = run_capture(
            Path::new("/sbin/pfctl"),
            &["-nf", "-"],
            Some(
                pf_rules_doh_only(Some(("167.88.161.83".parse().unwrap(), 51820))).as_bytes(),
            ),
        );
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn dns_filter_rdr_rules_redirect_both_transports_to_loopback() {
        let rules = pf_rules_dns_filter();
        assert!(rules.contains("rdr pass proto udp from any to any port = 53 -> 127.0.0.1 port 5353"));
        assert!(rules.contains("rdr pass proto tcp from any to any port = 53 -> 127.0.0.1 port 5353"));
        assert!(!rules.contains("block"));
    }

    #[test]
    fn dns_filter_rdr_rules_parse() {
        let parsed = run_capture(
            Path::new("/sbin/pfctl"),
            &["-nf", "-"],
            Some(pf_rules_dns_filter().as_bytes()),
        );
        assert!(parsed.is_ok(), "{parsed:?}");
    }

    #[test]
    fn destroy_of_an_interface_that_never_existed_is_not_a_failure() {
        // A dropped tunnel leaves nothing to destroy; the helper must report the
        // interface as gone, not as a teardown failure (this is what made a
        // reconnect after a drop throw "'ripley0' is not a WireGuard interface").
        let probe = format!("ripley-dne-{}", std::process::id());
        assert_eq!(destroy_tunnel_interface(&probe), Ok(()));
        assert!(
            run(Path::new("/sbin/ifconfig"), &[probe.as_str()]).is_err(),
            "probe interface unexpectedly exists"
        );
    }

    #[test]
    fn fake_ip_dns_is_never_accepted_as_a_wireguard_peer() {
        assert!(is_synthetic_tunnel_ip("198.18.2.26".parse().unwrap()));
        assert!(is_synthetic_tunnel_ip("198.19.255.254".parse().unwrap()));
        assert!(!is_synthetic_tunnel_ip("185.148.1.88".parse().unwrap()));
    }

    #[test]
    fn doh_answer_selects_a_real_a_record_and_skips_fake_ip() {
        let body = r#"{
          "Status": 0,
          "Answer": [
            {"name":"fi.gw.xeovo.com","type":1,"TTL":60,"data":"198.18.2.26"},
            {"name":"fi.gw.xeovo.com","type":1,"TTL":60,"data":"185.148.1.88"}
          ]
        }"#;
        assert_eq!(parse_doh_ipv4(body), Some("185.148.1.88".parse().unwrap()));
    }
}
