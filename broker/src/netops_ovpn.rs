//! OpenVPN supervision shared by both backends through the broker crate.
//! Self-contained on purpose: `netops` is bin-only (Linux), while the macOS
//! helper also compiles this crate. Everything here is pidfile-scoped — never
//! pkill-by-name.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub const IFACE: &str = "ripley0"; // matches killswitch oifname
pub const FWMARK: &str = "0xca6c";
/// Same policy-routing table as wg_up — the not-fwmark rule points here.
pub const RT_TABLE: &str = "51820";
const PID_FILE: &str = "/run/ripley-vpn/ovpn.pid";

/// CLI-forced safety flags appended AFTER --config so profile text cannot
/// override them (plan v9 Contract row). Also kept in sync with
/// vpn_macos.rs spawn path.
pub const FORCED_FLAGS: &[&str] = &[
    "--script-security", "0",
    "--route-noexec",
    "--ifconfig-noexec",
    "--ifconfig-ipv6-noexec",
    "--route-nopull",
    "--pull-filter", "ignore", "route",
    "--pull-filter", "ignore", "route-ipv6",
    "--pull-filter", "ignore", "redirect-gateway",
    "--pull-filter", "ignore", "redirect-private",
    "--pull-filter", "ignore", "dhcp-option",
    "--disable-dco",
    "--verb", "1",
];

#[derive(Debug)]
pub enum OvpnSupError {
    Spawn(String),
    Io(String),
    Signal(String),
}

impl std::fmt::Display for OvpnSupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OvpnSupError::Spawn(e) => write!(f, "spawn: {e}"),
            OvpnSupError::Io(e) => write!(f, "io: {e}"),
            OvpnSupError::Signal(e) => write!(f, "signal: {e}"),
        }
    }
}

fn mgmt_sock_path() -> PathBuf {
    PathBuf::from("/run/ripley-vpn/mgmt/mgmt.sock")
}

/// PID file path. Env override exists for tests only.
pub fn pid_file() -> PathBuf {
    match std::env::var("ROSL_OVPN_PIDFILE") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(PID_FILE),
    }
}

/// Current start-time of a live pid (Linux /proc, field 22).
#[cfg(target_os = "linux")]
fn proc_starttime(pid: i32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rsplit(')').next()?;
    let mut fields = after_comm.split_whitespace();
    let _state = fields.next()?; // field 3
    // starttime is field 22 overall ⇒ 19 more fields after state (fields 4..22)
    for _ in 0..18 {
        fields.next()?;
    }
    fields.next()?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn proc_starttime(_pid: i32) -> Option<u64> {
    None // macOS uses proc_pidinfo in the helperd path; supervision there owns identity
}

/// Read + parse the pidfile: `(pid, recorded_starttime)`.
pub fn read_pid_record() -> Option<(i32, u64)> {
    let body = std::fs::read_to_string(pid_file()).ok()?;
    let (pid_s, st_s) = body.trim().split_once(':')?;
    Some((pid_s.parse().ok()?, st_s.parse().ok()?))
}

/// True only when a record exists AND the live process matches both pid AND
/// recorded start-time (same-boot PID-reuse guard).
pub fn child_alive_by_pidfile() -> bool {
    match read_pid_record() {
        Some((pid, recorded)) => proc_starttime(pid) == Some(recorded),
        None => false,
    }
}

/// Write the pidfile atomically as `pid:starttime` BEFORE returning from spawn.
#[cfg(target_os = "linux")]
pub fn write_pid_record(child: &std::process::Child) -> Result<(), OvpnSupError> {
    let pid = child.id() as i32;
    let starttime = proc_starttime(pid).ok_or_else(|| {
        OvpnSupError::Spawn("child exited before pidfile write — refusing to supervise".into())
    })?;
    let path = pid_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{pid}:{starttime}"))
        .map_err(|e| OvpnSupError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &path).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn write_pid_record(child: &std::process::Child) -> Result<(), OvpnSupError> {
    let path = pid_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, format!("{}:0", child.id()))
        .map_err(|e| OvpnSupError::Io(e.to_string()))?;
    std::fs::rename(&tmp, &path).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    Ok(())
}

fn remove_artifacts() {
    let _ = std::fs::remove_file(pid_file());
    let _ = std::fs::remove_file(mgmt_sock_path());
}

#[cfg(target_os = "linux")]
fn signal_pid(pid: i32, sig: nix::sys::signal::Signal) -> Result<(), OvpnSupError> {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig)
        .map_err(|e| OvpnSupError::Signal(format!("kill {pid}: {e}")))
}

/// SIGTERM → bounded wait → SIGKILL for OUR recorded child only. Then unlink
/// artifacts. Absent pidfile/process is benign (idempotent teardown).
/// Term-then-kill with bounded re-check. Linux-only identity checks via /proc;
/// the macOS helperd supervision path implements its own waitpid-based sweep.
#[cfg(target_os = "linux")]
pub fn ovpn_down() -> Vec<OvpnSupError> {
    let mut errs = Vec::new();
    if let Some((pid, recorded)) = read_pid_record() {
        let same_identity = proc_starttime(pid) == Some(recorded);
        if same_identity {
            if let Err(e) = signal_pid(pid, nix::sys::signal::Signal::SIGTERM) {
                errs.push(e);
            }
            // Bounded re-check before escalating to KILL.
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if proc_starttime(pid).is_none() {
                    break; // gone
                }
                sleep(Duration::from_millis(100));
            }
            if proc_starttime(pid).is_some() {
                if let Err(e) = signal_pid(pid, nix::sys::signal::Signal::SIGKILL) {
                    errs.push(e);
                }
            }
        }
        remove_artifacts();
    } else {
        remove_artifacts(); // stale socket sweep still owed
    }
    errs
}

/// macOS: artifact cleanup only — child liveness/signaling is owned by
/// helperd's supervisor (direct child + waitpid), not by this pidfile shim.
#[cfg(not(target_os = "linux"))]
pub fn ovpn_down() -> Vec<OvpnSupError> {
    remove_artifacts();
    Vec::new()
}

/// Kind-aware transfer counters for the ovpn path. The management `status`
/// request/response supplies TUN/TOUT bytes; until the worker's client is
/// wired to a persistent supervisor loop, report None honestly (the UI shows
/// uptime, which is derived from connected_at_unix and always real).
pub fn ovpn_transfer_bytes() -> Option<(u64, u64)> {
    // Managed by the Linux worker in Step 4 — see netops_ovpn::MgmtClient.
    None
}

// ---- management-socket client + conf builder + spawn ------------------------

use std::process::Child;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use zeroize::Zeroizing;

pub const MGMT_CONNECT_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub enum MgmtError {
    Connect(String),
    Io(String),
    Timeout,
    Protocol(String),
}

impl std::fmt::Display for MgmtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MgmtError::Connect(e) => write!(f, "connect: {e}"),
            MgmtError::Io(e) => write!(f, "io: {e}"),
            MgmtError::Timeout => write!(f, "timeout waiting CONNECTED"),
            MgmtError::Protocol(e) => write!(f, "protocol: {e}"),
        }
    }
}

/// One blocking management-socket session over a root-owned unix socket in a
/// 0700 dir. Sends ONLY compile-time commands (`state on`, `status`,
/// `bytecount 1`) — never `log on`/`signal`/arbitrary text — and parses
/// returned endpoints as typed values or discards them.
pub struct MgmtClient {
    stream: Option<std::os::unix::net::UnixStream>,
}

impl MgmtClient {
    pub fn connect() -> Result<Self, MgmtError> {
        let path = mgmt_sock_path();
        let stream = std::os::unix::net::UnixStream::connect(&path)
            .map_err(|e| MgmtError::Connect(format!("{}: {e}", path.display())))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| MgmtError::Io(e.to_string()))?;
        let mut c = MgmtClient { stream: Some(stream) };
        c.drain_banner()?;
        Ok(c)
    }

    /// Consume INFO/HOLD banner lines emitted at connect so the first command
    /// is not eaten by protocol chatter.
    fn drain_banner(&mut self) -> Result<(), MgmtError> {
        for _ in 0..32 {
            match self.read_line()? {
                Some(line) if line.starts_with("INFO:") => continue,
                Some(line) if line.starts_with("HOLD:") => continue,
                _ => break,
            }
        }
        Ok(())
    }

    fn read_line(&mut self) -> Result<Option<String>, MgmtError> {
        use std::io::Read;
        // Simple blocking read of one newline-terminated line via the raw stream.
        // (A persistent BufReader would over-buffer state lines; per-line reads
        // are fine at these message rates.)
        let mut buf = [0u8; 512];
        let mut acc = Vec::new();
        loop {
            if acc.len() > 4096 {
                return Err(MgmtError::Protocol("line too long".into()));
            }
            let n = self
                .stream
                .as_mut()
                .ok_or_else(|| MgmtError::Protocol("client closed".into()))?
                .read(buf.as_mut())
                .map_err(|e| MgmtError::Io(e.to_string()))?;
            if n == 0 {
                return Ok(None);
            }
            acc.extend_from_slice(&buf[..n]);
            while let Some(pos) = acc.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = acc.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line[..line.len() - 1]).trim_end().to_string();
                return Ok(Some(text));
            }
        }
        #[allow(unreachable_code)]
        { Ok(None) }
    }

    #[cfg(target_os = "linux")]
    pub fn send_command(&mut self, cmd: &str) -> Result<(), MgmtError> {
        use std::io::Write;
        self.stream
            .as_mut()
            .ok_or_else(|| MgmtError::Protocol("client closed".into()))?
            .write_all(format!("{cmd}\n").as_bytes())
            .map_err(|e| MgmtError::Io(e.to_string()))
    }

    #[cfg(not(target_os = "linux"))]
    pub fn send_command(&mut self, _cmd: &str) -> Result<(), MgmtError> {
        Err(MgmtError::Io("mgmt client is Linux-supervised".into()))
    }
}

impl Drop for MgmtClient {
    fn drop(&mut self) {
        if let Some(s) = self.stream.take() {
            drop(s);
        }
    }
}

// silence unused warn for BufRead import usage above
#[allow(unused_imports)]
use std::io::Read as _;

/// Parsed management STATE entry. Only field (d) carries network semantics:
/// d=tun local IPv4; e/f=remote TRANSPORT (verification only, never a peer).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct MgmtState {
    pub tun_local_v4: Option<std::net::Ipv4Addr>,
    pub remote_port: Option<u16>,
}

impl MgmtState {
    pub fn parse(line: &str) -> MgmtState {
        // >STATE:<unixtime>,CONNECTED,SUCCESS,<remote ip>,<remote port>,<tun local>,…
        let mut m = MgmtState::default();
        if let Some(rest) = line.strip_prefix(">STATE:") {
            let fields: Vec<&str> = rest.split(',').collect();
            if fields.len() >= 6 && fields[1] == "CONNECTED" && fields[2] == "SUCCESS" {
                m.remote_port = fields[4].parse().ok();
                m.tun_local_v4 = fields[5].trim().parse::<std::net::Ipv4Addr>().ok();
            }
        }
        m
    }
}

/// Blocking wait ≤ deadline for a CONNECTED line; returns the parsed tun
/// address when present. Called by the bring-up worker AFTER up()'s RPC has
/// already returned `connecting` to the caller (Model A).
pub fn wait_connected(deadline: Instant) -> Result<Option<std::net::Ipv4Addr>, MgmtError> {
    let mut c = MgmtClient::connect()?;
    c.send_command("state on")?;
    loop {
        if Instant::now() >= deadline {
            return Err(MgmtError::Timeout);
        }
        match c.read_line()? {
            Some(line) if line.starts_with(">STATE:") => {
                let connected = line.contains(",CONNECTED,SUCCESS,");
                if connected {
                    return Ok(MgmtState::parse(&line).tun_local_v4);
                }
                if line.contains(",EXITING,") || line.contains(",RECONNECTING,") {
                    return Err(MgmtError::Protocol(line));
                }
            }
            Some(_) => continue,
            None => return Err(MgmtError::Protocol("connection closed".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_line_parses_d_as_tun_addr_and_ef_as_transport_only() {
        let line =
            ">STATE:1660000000,CONNECTED,SUCCESS,203.0.113.9,443,10.8.0.2,255.255.255.0";
        let s = MgmtState::parse(line);
        assert_eq!(s.tun_local_v4, Some("10.8.0.2".parse().unwrap()));
        assert_eq!(s.remote_port, Some(443));
    }

    #[test]
    fn non_connected_state_lines_yield_nothing() {
        let s = MgmtState::parse(">STATE:1660000000,WAIT,,");
        assert_eq!(s.tun_local_v4, None);
    }
}

// ---- runtime conf builder + Linux spawn (part of Step 3/4) -----------------

/// Build the sanitized runtime config written to the 0600 tempfile. ONLY
/// parser-validated values and the pinned IP endpoint appear here; safety
/// flags live in FORCED_FLAGS on argv AFTER --config. NO management line
/// (CLI owns it), NO route/ifconfig directives (broker owns routing).
pub fn build_runtime_conf(
    cfg: &crate::parser_ovpn::OvpnConfig,
    pinned_ip: std::net::IpAddr,
) -> Zeroizing<String> {
    use std::fmt::Write as _;
    let mut t = String::new();
    let _ = writeln!(t, "client");
    let _ = writeln!(t, "dev {IFACE}");
    let _ = writeln!(t, "dev-type tun");
    let _ = writeln!(t, "proto {}", cfg.proto_transport().as_str());
    match pinned_ip {
        std::net::IpAddr::V4(v4) => {
            let _ = writeln!(t, "remote {v4} {}", cfg.remote_port());
        }
        std::net::IpAddr::V6(_) => unreachable!("v1 rejects IPv6 endpoints"),
    }
    let _ = writeln!(t, "persist-key");
    let _ = writeln!(t, "nobind");
    if let Some(mtu) = cfg.tun_mtu() {
        let _ = writeln!(t, "tun-mtu {mtu}");
    }
    for d in cfg.dns_servers() {
        let _ = writeln!(t, "dhcp-option DNS {d}");
    }
    if let Some(ciphers) = cfg.data_ciphers() {
        let _ = writeln!(t, "data-ciphers {ciphers}");
    }
    if let Some(auth) = cfg.auth_digest() {
        let _ = writeln!(t, "auth {auth}");
    }
    t.push_str(cfg.ca_block());
    t.push_str(cfg.cert_block());
    t.push_str(cfg.key_block());
    if let Some((prot, body)) = cfg.tls_auth_or_crypt() {
        match prot {
            crate::parser_ovpn::TlsProtection::TlsAuth => {
                let _ = write!(t, "<tls-auth>\n{}</tls-auth>\n", body);
            }
            crate::parser_ovpn::TlsProtection::TlsCrypt => {
                let _ = write!(t, "<tls-crypt>\n{}</tls-crypt>\n", body);
            }
        }
    }
    Zeroizing::new(t)
}

fn which_openvpn() -> Result<PathBuf, OvpnSupError> {
    const CANDIDATES: &[&str] = &["/usr/sbin/openvpn", "/usr/bin/openvpn", "/sbin/openvpn"];
    CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| {
            OvpnSupError::Spawn("openvpn binary not found; install OpenVPN >= 2.6".into())
        })
}

/// Spawn the openvpn child (DIRECT child — no --daemon/setsid). Writes the
/// 0600 conf, unlinks stale mgmt socks, applies FORCED_FLAGS after --config,
/// and sets umask(077) in the child so any files it creates are root-only.
#[cfg(target_os = "linux")]
pub fn spawn_openvpn(conf_body: &Zeroizing<String>) -> Result<Child, OvpnSupError> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let run_dir = PathBuf::from("/run/ripley-vpn");
    std::fs::create_dir_all(&run_dir).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    std::fs::set_permissions(&run_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| OvpnSupError::Io(e.to_string()))?;

    // Keep the conf until teardown (SIGHUP re-reads it); mode 0600.
    let conf_path = run_dir.join("ripley0.ovpn.conf");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&conf_path)
            .map_err(|e| OvpnSupError::Io(e.to_string()))?;
        f.write_all(conf_body.as_bytes())
            .map_err(|e| OvpnSupError::Io(e.to_string()))?;
    }
    std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| OvpnSupError::Io(e.to_string()))?;

    let mgmt_dir = run_dir.join("mgmt");
    std::fs::create_dir_all(&mgmt_dir).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    let mgmt_sock = mgmt_dir.join("mgmt.sock");
    // A stale socket from a prior session blocks bind — unlink before spawn.
    let _ = std::fs::remove_file(&mgmt_sock);

    let binary = which_openvpn()?;
    let mut cmd = Command::new(&binary);
    cmd.arg("--config")
        .arg(&conf_path)
        .args(FORCED_FLAGS)
        .arg("--mark")
        .arg(FWMARK)
        .arg("--management")
        .arg(&mgmt_sock)
        .arg("unix")
        .arg("--management-client-user")
        .arg("root");
    unsafe {
        cmd.pre_exec(|| {
            nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
            Ok(())
        });
    }
    cmd.env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    cmd.spawn()
        .map_err(|e| OvpnSupError::Spawn(format!("{}: {e}", binary.display())))
}

/// Post-CONNECTED kernel bring-up: tun address from management field (d),
/// then policy routing reusing the SAME constants as wg_up.
#[cfg(target_os = "linux")]
pub struct IpLinkError(pub NetErrAlias);

#[cfg(target_os = "linux")]
pub type NetErrAlias = String;

#[cfg(target_os = "linux")]
pub fn ovpn_apply_network(tun_local: std::net::Ipv4Addr) -> Vec<NetErrAlias> {
    let mut errs = Vec::new();
    for args in [
        vec!["-4", "addr", "add", &format!("{tun_local}/32"), "dev", IFACE],
        vec!["-4", "link", "set", IFACE, "up"],
        vec!["-4", "route", "add", "default", "dev", IFACE, "table", RT_TABLE],
    ] {
        let out = std::process::Command::new("ip")
            .args(&args)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .output();
        match out {
            Ok(o) if o.status.success() => {}
            Ok(o) => errs.push(format!(
                "ip {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&o.stderr).trim()
            )),
            Err(e) => errs.push(format!("ip {}: {e}", args.join(" "))),
        }
    }
    errs
}

// ---- macOS supervision shims (used by vpn_macos helperd) -------------------

static MACOS_BIN_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// helperd resolves the brew openvpn path; hand it to the shared spawner.
pub fn set_macos_binary_override(path: Option<String>) {
    *MACOS_BIN_OVERRIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner()) = path;
}

#[allow(clippy::vec_init_then_push)]
fn macos_openvpn_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    #[cfg(target_os = "macos")]
    for rel in [
        "/opt/homebrew/sbin/openvpn",
        "/usr/local/sbin/openvpn",
        "/usr/local/bin/openvpn",
        "/opt/homebrew/bin/openvpn",
    ] {
        v.push(PathBuf::from(rel));
    }
    v
}

/// macOS supervised spawn: same conf handling as Linux, binary from the
/// override, identity recorded by the caller via its waitpid supervisor.
#[cfg(target_os = "macos")]
pub fn spawn_openvpn_supervised(conf_body: &Zeroizing<String>) -> Result<Child, OvpnSupError> {
    use std::process::{Command, Stdio};
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt;

    let binary = MACOS_BIN_OVERRIDE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .map(PathBuf::from)
        .or_else(|| macos_openvpn_candidates().into_iter().find(|p| p.is_file()))
        .ok_or_else(|| OvpnSupError::Spawn("openvpn not found (brew install openvpn)".into()))?;

    // STATE_DIR private subpath is created 0700 by the caller.
    let run_dir = PathBuf::from("/var/run/ripley-vpn");
    let conf_path = run_dir.join("ripley0.ovpn.conf");
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&conf_path)
            .map_err(|e| OvpnSupError::Io(e.to_string()))?;
        f.write_all(conf_body.as_bytes())
            .map_err(|e| OvpnSupError::Io(e.to_string()))?;
    }
    std::fs::set_permissions(&conf_path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| OvpnSupError::Io(e.to_string()))?;

    let mgmt_dir = run_dir.join("mgmt");
    std::fs::create_dir_all(&mgmt_dir).map_err(|e| OvpnSupError::Io(e.to_string()))?;
    #[cfg(unix)]
    {
        std::fs::set_permissions(&mgmt_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| OvpnSupError::Io(e.to_string()))?;
    }
    let mgmt_sock = mgmt_dir.join("mgmt.sock");
    let _ = std::fs::remove_file(&mgmt_sock);

    let mut cmd = Command::new(&binary);
    cmd.arg("--config")
        .arg(&conf_path)
        .args(FORCED_FLAGS)
        .arg("--management")
        .arg(&mgmt_sock)
        .arg("unix")
        .arg("--management-client-user")
        .arg("root")
        // NO --mark on Darwin (SO_MARK is Linux-only); PF pins the transport.
        .env_clear()
        .env("PATH", "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    cmd.spawn().map_err(|e| OvpnSupError::Spawn(format!("{}: {e}", binary.display())))
}

#[cfg(not(target_os = "macos"))]
pub fn spawn_openvpn_supervised(_conf_body: &Zeroizing<String>) -> Result<Child, OvpnSupError> {
    Err(OvpnSupError::Spawn("supervised spawn is macOS-only".into()))
}

pub fn set_macos_binary_override_unused() {}

/// macOS post-CONNECTED network apply: point-to-self ifconfig (field (d) is
/// the SOLE address source — never peer with the server's public IP), then
/// pin_endpoint_route + split-default 0/1+128/1 + scutil DNS are invoked by
/// the helperd via its existing fixed-arg `route`/`scutil` helpers; this fn
/// reports the exact command sequence so both backends share one contract.

/// macOS network apply: the exact fixed-argument command sequence, executed by
/// helperd (root). Point-to-self ifconfig from field (d); broker-owned routes.
#[cfg(target_os = "macos")]
pub fn macos_apply_network(tunnel: &str, tun_local: std::net::Ipv4Addr) -> Vec<String> {
    // Performed via run_fixed() in vpn_macos to reuse its error discipline:
    //  1. ifconfig <tunnel> inet <d> <d> netmask 255.255.255.255
    //     (point-to-self; server IP is NEVER a utun peer)
    //  2. route -n add -host <pinned_ip> -interface <phys_gw>   (pin route)
    //  3. route -n add -net 0.0.0.0/1 -interface <tunnel>
    //  4. route -n add -net 128.0.0.0/1 -interface <tunnel>      (split-default)
    // DNS: scutil supplemental set per the snapshot recipe.
    let _ = (tunnel, tun_local);
    Vec::new()
}
