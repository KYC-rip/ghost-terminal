//! Privileged network operations — executed as FIXED-ARGUMENT commands, never a
//! shell. Every argument is a typed value from a validated `WgConfig`; no caller
//! string is interpolated into a shell or into `wg-quick` (which runs hooks).
//!
//! Security posture:
//!  - The WireGuard key set goes to `wg setconf /dev/stdin` from a zeroizing
//!    buffer — no disk, no memfd/exec fd hazard.
//!  - Full-tunnel routing uses WireGuard's fwmark + policy routing (the wg-quick
//!    strategy): the suppress-main rule is evaluated FIRST (preserving specific
//!    main-table routes such as LAN), then the not-fwmark rule sends everything
//!    else into the tunnel table. Encrypted endpoint packets (fwmark-stamped)
//!    escape via the main table, so they never loop into their own tunnel.
//!  - Every command runs with a cleared environment + fixed PATH and a hard
//!    execution deadline (a hung child is killed and reaped, never left to wedge
//!    a worker). DNS resolution is done via a killable helper, not libc's
//!    unbounded getaddrinfo.
//!
//! Linux-only (v1). NOTE: full-tunnel here preserves specific LAN routes (wg-quick
//! semantics); it does NOT force LAN traffic through the VPN.
//!
//! Runtime dependencies (must be present in PATH, checked by the systemd unit /
//! packaging): `wg` (wireguard-tools), `ip` (iproute2), `nft` (nftables),
//! `resolvectl` (systemd-resolved), and `getent` (glibc NSS, for bounded DNS
//! resolution).

use std::fmt;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::thread::sleep;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::Zeroizing;

use crate::types::{Cidr, EndpointHost, Ipv6Policy, WgConfig};

pub const IFACE: &str = "ripley0";
pub const FWMARK: &str = "0xca6c";
const RT_TABLE: &str = "51820";
/// The suppress-main rule MUST be evaluated before the tunnel-catch rule (lower
/// pref = earlier), so specific main-table routes (LAN) survive.
const RT_PREF_SUPPRESS: &str = "51820";
const RT_PREF_MARK: &str = "51821";
const SAFE_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
const CMD_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
pub enum NetError {
    Spawn { cmd: String, err: String },
    NonZero { cmd: String, code: Option<i32>, stderr: String },
    Timeout { cmd: String },
    Resolve(String),
    NoEndpointIp,
    RouteParse,
}

impl fmt::Display for NetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetError::Spawn { cmd, err } => write!(f, "spawn {cmd}: {err}"),
            NetError::NonZero { cmd, code, stderr } => write!(f, "{cmd} exited {code:?}: {}", stderr.trim()),
            NetError::Timeout { cmd } => write!(f, "{cmd} timed out"),
            NetError::Resolve(e) => write!(f, "resolve endpoint: {e}"),
            NetError::NoEndpointIp => write!(f, "endpoint resolved to no usable address"),
            NetError::RouteParse => write!(f, "could not determine physical egress device"),
        }
    }
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Drain a child pipe on its own thread so neither stdout nor stderr can fill its
/// pipe buffer and block the child until our timeout fires (a false timeout).
fn spawn_drain<R: Read + Send + 'static>(pipe: Option<R>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = String::new();
        if let Some(mut p) = pipe {
            let _ = p.read_to_string(&mut buf);
        }
        buf
    })
}

/// Wait for a child within CMD_TIMEOUT, killing+reaping on timeout or error.
fn wait_bounded(cmd: &str, child: &mut Child) -> Result<std::process::ExitStatus, NetError> {
    let start = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if start.elapsed() > CMD_TIMEOUT {
                    reap(child);
                    return Err(NetError::Timeout { cmd: cmd.into() });
                }
                sleep(Duration::from_millis(40));
            }
            Err(e) => {
                reap(child);
                return Err(NetError::Spawn { cmd: cmd.into(), err: e.to_string() });
            }
        }
    }
}

/// Run a fixed-argument command (optionally feeding `input` to stdin) with a
/// cleared env + fixed PATH and a hard timeout. Ok only on exit status 0.
fn exec(cmd: &str, args: &[&str], input: Option<&[u8]>) -> Result<(), NetError> {
    let mut child = Command::new(cmd)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
        .spawn()
        .map_err(|e| NetError::Spawn { cmd: cmd.into(), err: e.to_string() })?;

    if let Some(bytes) = input {
        if let Some(mut sin) = child.stdin.take() {
            if let Err(e) = sin.write_all(bytes) {
                drop(sin);
                reap(&mut child);
                return Err(NetError::Spawn { cmd: cmd.into(), err: e.to_string() });
            }
        }
    }

    let stderr_h = spawn_drain(child.stderr.take());
    let status_res = wait_bounded(cmd, &mut child);
    let stderr = stderr_h.join().unwrap_or_default();
    let status = status_res?;
    if status.success() {
        return Ok(());
    }
    Err(NetError::NonZero { cmd: cmd.into(), code: status.code(), stderr })
}

fn run(cmd: &str, args: &[&str]) -> Result<(), NetError> {
    exec(cmd, args, None)
}

pub fn run_stdin(cmd: &str, args: &[&str], input: &[u8]) -> Result<(), NetError> {
    exec(cmd, args, Some(input))
}

/// Like `run`, but captures stdout — same cleared-env + hard-timeout guarantees,
/// so read-side probes (`ip route get`, `wg show`, DNS) can never wedge a worker.
fn exec_capture(cmd: &str, args: &[&str]) -> Result<String, NetError> {
    let mut child = Command::new(cmd)
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| NetError::Spawn { cmd: cmd.into(), err: e.to_string() })?;

    // Drain BOTH pipes concurrently so neither can block the child until timeout.
    let stdout_h = spawn_drain(child.stdout.take());
    let stderr_h = spawn_drain(child.stderr.take());
    let status_res = wait_bounded(cmd, &mut child);
    let out = stdout_h.join().unwrap_or_default(); // always join before propagating
    let stderr = stderr_h.join().unwrap_or_default();
    let status = status_res?;
    if status.success() {
        return Ok(out);
    }
    Err(NetError::NonZero { cmd: cmd.into(), code: status.code(), stderr })
}

/// Resolve the peer endpoint to a single pinned IP, BEFORE egress is sealed. DNS
/// names are resolved via `getent ahosts` (a KILLABLE helper bounded by our
/// timeout) rather than libc's unbounded getaddrinfo.
pub fn resolve_endpoint(cfg: &WgConfig) -> Result<IpAddr, NetError> {
    match cfg.endpoint().host() {
        EndpointHost::Ip(ip) => Ok(*ip),
        EndpointHost::Dns(name) => {
            let out = exec_capture("getent", &["ahosts", name])
                .map_err(|e| NetError::Resolve(e.to_string()))?;
            out.lines()
                .filter_map(|l| l.split_whitespace().next())
                .filter_map(|s| IpAddr::from_str(s).ok())
                .next()
                .ok_or(NetError::NoEndpointIp)
        }
    }
}

/// The physical interface that routes to the endpoint — captured BEFORE we seal
/// egress. Parses `ip route get <ip>`: "<ip> [via <gw>] dev <dev> ...".
pub fn physical_egress_dev(endpoint_ip: IpAddr) -> Result<String, NetError> {
    let text = exec_capture("ip", &["route", "get", &endpoint_ip.to_string()])?;
    let mut it = text.split_whitespace();
    while let Some(tok) = it.next() {
        if tok == "dev" {
            if let Some(dev) = it.next() {
                if dev.len() <= 15 && dev.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b'@') {
                    return Ok(dev.to_string());
                }
            }
        }
    }
    Err(NetError::RouteParse)
}

/// Render a MINIMAL wg config into a zeroizing buffer; every secret intermediate
/// (base64 of key/psk) is itself zeroizing.
fn render_wg_conf(cfg: &WgConfig, endpoint_ip: IpAddr) -> Zeroizing<String> {
    let mut t: Zeroizing<String> = Zeroizing::new(String::with_capacity(512));
    t.push_str("[Interface]\nPrivateKey = ");
    let pk = Zeroizing::new(STANDARD.encode(cfg.private_key().as_bytes()));
    t.push_str(&pk);
    t.push('\n');
    if let Some(port) = cfg.listen_port() {
        t.push_str("ListenPort = ");
        t.push_str(&port.to_string());
        t.push('\n');
    }
    t.push_str("\n[Peer]\nPublicKey = ");
    t.push_str(&STANDARD.encode(cfg.peer_public_key().bytes()));
    t.push('\n');
    if let Some(psk) = cfg.preshared_key() {
        let pk2 = Zeroizing::new(STANDARD.encode(psk.as_bytes()));
        t.push_str("PresharedKey = ");
        t.push_str(&pk2);
        t.push('\n');
    }
    let allowed = match cfg.ipv6() {
        Ipv6Policy::FullTunnel => "0.0.0.0/0, ::/0",
        Ipv6Policy::Block => "0.0.0.0/0",
    };
    t.push_str("AllowedIPs = ");
    t.push_str(allowed);
    t.push('\n');
    let port = cfg.endpoint().port();
    t.push_str("Endpoint = ");
    match endpoint_ip {
        IpAddr::V4(v4) => { t.push_str(&v4.to_string()); t.push(':'); }
        IpAddr::V6(v6) => { t.push('['); t.push_str(&v6.to_string()); t.push_str("]:"); }
    }
    t.push_str(&port.to_string());
    t.push('\n');
    if let Some(k) = cfg.persistent_keepalive() {
        t.push_str("PersistentKeepalive = ");
        t.push_str(&k.to_string());
        t.push('\n');
    }
    t
}

/// Create the wg interface, load keys via `wg setconf /dev/stdin`, stamp the
/// fwmark, add addresses, and install fwmark policy routing.
pub fn wg_up(cfg: &WgConfig, endpoint_ip: IpAddr) -> Result<(), NetError> {
    run("ip", &["link", "add", "dev", IFACE, "type", "wireguard"])?;
    let conf = render_wg_conf(cfg, endpoint_ip);
    run_stdin("wg", &["setconf", IFACE, "/dev/stdin"], conf.as_bytes())?;
    run("wg", &["set", IFACE, "fwmark", FWMARK])?;

    for c in cfg.address() {
        let family = if c.addr.is_ipv4() { "-4" } else { "-6" };
        run("ip", &[family, "address", "add", &fmt_cidr(c), "dev", IFACE])?;
    }
    if let Some(mtu) = cfg.mtu() {
        run("ip", &["link", "set", "mtu", &mtu.to_string(), "dev", IFACE])?;
    }
    run("ip", &["link", "set", IFACE, "up"])?;

    install_policy_routing("-4")?;
    if matches!(cfg.ipv6(), Ipv6Policy::FullTunnel) {
        install_policy_routing("-6")?;
    }
    Ok(())
}

fn install_policy_routing(family: &str) -> Result<(), NetError> {
    // Both rules BEFORE the tunnel default (wg-quick ordering): the table stays
    // ineffective until the suppress-main rule exists.
    run("ip", &[family, "rule", "add", "pref", RT_PREF_SUPPRESS, "table", "main", "suppress_prefixlength", "0"])?;
    run("ip", &[family, "rule", "add", "pref", RT_PREF_MARK, "not", "fwmark", FWMARK, "table", RT_TABLE])?;
    run("ip", &[family, "route", "add", "default", "dev", IFACE, "table", RT_TABLE])?;
    Ok(())
}

/// Per-link DNS via systemd-resolved with route-only `~.`.
pub fn dns_up(cfg: &WgConfig) -> Result<(), NetError> {
    if cfg.dns().is_empty() {
        return Ok(());
    }
    let mut args: Vec<String> = vec!["dns".into(), IFACE.into()];
    for ip in cfg.dns() {
        args.push(ip.to_string());
    }
    let argrefs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run("resolvectl", &argrefs)?;
    run("resolvectl", &["domain", IFACE, "~."])?;
    Ok(())
}

/// Best-effort teardown of DNS, policy routing and the interface. RETURNS the
/// list of failures so the caller can decide (a normal restore must NOT re-open
/// egress if teardown was incomplete). Rules are deleted by their FULL selector
/// (not pref alone) so we only ever remove our own.
pub fn wg_down() -> Vec<NetError> {
    let mut errs = Vec::new();
    for family in ["-4", "-6"] {
        collect(&mut errs, "ip", &[family, "rule", "del", "pref", RT_PREF_SUPPRESS, "table", "main", "suppress_prefixlength", "0"]);
        collect(&mut errs, "ip", &[family, "rule", "del", "pref", RT_PREF_MARK, "not", "fwmark", FWMARK, "table", RT_TABLE]);
        collect(&mut errs, "ip", &[family, "route", "flush", "table", RT_TABLE]);
    }
    collect(&mut errs, "resolvectl", &["revert", IFACE]);
    collect(&mut errs, "ip", &["link", "del", "dev", IFACE]);
    errs
}

/// A rule/route delete that fails because the object doesn't exist is EXPECTED on
/// a partial/never-up teardown — those are filtered out; only real failures are
/// surfaced. Everything is logged.
fn collect(errs: &mut Vec<NetError>, cmd: &str, args: &[&str]) {
    if let Err(e) = run(cmd, args) {
        let benign = matches!(&e, NetError::NonZero { stderr, .. }
            if stderr.contains("No such")
                || stderr.contains("does not exist")
                || stderr.contains("not found")
                || stderr.contains("Cannot find")
                || stderr.contains("cannot find"));
        eprintln!("ripley-vpn-broker: teardown {cmd} {}: {e}", args.join(" "));
        if !benign {
            errs.push(e);
        }
    }
}

fn fmt_cidr(c: &Cidr) -> String {
    format!("{}/{}", c.addr, c.prefix)
}

/// Age in seconds since the most recent handshake, or None. Bounded via
/// exec_capture so a hung `wg` can't stall a status probe.
pub fn handshake_age_secs() -> Option<u64> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let text = exec_capture("wg", &["show", IFACE, "latest-handshakes"]).ok()?;
    let newest = text
        .lines()
        .filter_map(|l| l.split_whitespace().last())
        .filter_map(|s| s.parse::<u64>().ok())
        .filter(|&t| t > 0)
        .max()?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(newest))
}
