//! OpenVPN supervision shared by both backends through the broker crate.
//! Self-contained on purpose: `netops` is bin-only (Linux), while the macOS
//! helper also compiles this crate. Everything here is pidfile-scoped — never
//! pkill-by-name.

use std::path::PathBuf;
use std::thread::sleep;
use std::time::{Duration, Instant};

pub const IFACE: &str = "ripley0"; // matches killswitch oifname
pub const FWMARK: &str = "0xca6c";
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

// ---- management-socket client (mgmt protocol, single-client discipline) ----
//
// The client speaks the OpenVPN management line protocol over a root-owned
// unix socket in a 0700 dir. It sends ONLY compile-time commands
// (`state on`, `status`, `bytecount 1`) — never `log on`/`signal`/arbitrary
// text — and parses returned endpoints as typed IPs or discards them.

pub const MGMT_CONNECT_DEADLINE: Duration = Duration::from_secs(90);

#[derive(Debug)]
pub enum MgmtError {
    Connect(String),
    Io(String),
    Timeout,
    Protocol(String),
}

/// One blocking management-socket session. Created per operation; closed on
/// drop so finalize/status can open their own short-lived sessions later
/// (single-client-at-a-time discipline).
pub struct MgmtClient {
    #[cfg(target_os = "linux")]
    stream: std::os::unix::net::UnixStream,
    buffer: Vec<String>,
}

impl MgmtClient {
    pub fn connect() -> Result<Self, MgmtError> {
        Self::connect_to(mgmt_sock_path())
    }

    fn connect_to(path: PathBuf) -> Result<Self, MgmtError> {
        let stream = std::os::unix::net::UnixStream::connect(&path)
            .map_err(|e| MgmtError::Connect(format!("{}: {e}", path.display())))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|e| MgmtError::Io(e.to_string()))?;
        let mut c = MgmtClient {
            #[cfg(target_os = "linux")]
            stream,
            buffer: Vec::new(),
        };
        // Drain the banner (INFO lines + possibly HOLD until we speak).
        let _ = c.drain_banner();
        Ok(c)
    }

    /// Consume INFO/HOLD banner lines emitted at connect.
    fn drain_banner(&mut self) -> Result<(), MgmtError> {
        for _ in 0..32 {
            match self.read_line()? {
                Some(line) if line.starts_with("INFO:") => continue,
                Some(line) if line.starts_with("HOLD:") => continue,
                Some(_) => break, // first real prompt/state line — banner done
                None => break,
            }
        }
        Ok(())
    }

    fn read_line(&mut self) -> Result<Option<String>, MgmtError> {
        if let Some(line) = self.buffer.pop() {
            return Ok(Some(line));
        }
        let mut buf = [0u8; 512];
        let mut acc = Vec::new();
        loop {
            let n = self
                .read_stream(&mut buf)
                .map_err(|e| MgmtError::Io(e.to_string()))?;
            if n == 0 {
                return Ok(None);
            }
            acc.extend_from_slice(&buf[..n]);
            while let Some(pos) = acc.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = acc.drain(..=pos).collect();
                let text = String::from_utf8_lossy(&line[..line.len() - 1]).trim_end().to_string();
                if !text.is_empty() {
                    return Ok(Some(text));
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn read_stream(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use std::io::Read;
        self.stream.read(buf)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_stream(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "mgmt client is Linux-supervised"))
    }

    fn send_command(&mut self, cmd: &str) -> Result<(), MgmtError> {
        #[cfg(target_os = "linux")]
        {
            use std::io::Write;
            self.stream
                .write_all(format!("{cmd}\n").as_bytes())
                .map_err(|e| MgmtError::Io(e.to_string()))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = cmd;
            Err(MgmtError::Io("mgmt client is Linux-supervised".into()))
        }
    }
}

/// Parsed management STATE entry. Only (d) carries network semantics:
/// per OpenVPN management-notes: d=tun local IPv4, e/f=remote transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgmtState<'a> {
    /// TUN local IPv4 from field (d). SOLE source of the tun address.
    pub tun_local_v4: Option<std::net::Ipv4Addr>,
    /// Transport verification only — NEVER used as ifconfig peer/gateway.
    pub remote_host_ref: Option<&'a str>,
    pub remote_port: Option<u16>,
}

impl MgmtState<'_> {
    pub fn parse(line: &str) -> MgmtState<'_> {
        // >STATE:1660000000,CONNECTED,SUCCESS,<ip>,<port>,<local_d>,…
        let mut m = MgmtState { tun_local_v4: None, remote_host_ref: None, remote_port: None };
        if let Some(rest) = line.strip_prefix(">STATE:") {
            let fields: Vec<&str> = rest.splitn(7, ',').collect();
            if fields.len() >= 6 && fields[1] == "CONNECTED" && fields[2] == "SUCCESS" {
                m.remote_host_ref = Some(fields[3]);
                m.remote_port = fields[4].parse().ok();
                m.tun_local_v4 = fields[5].parse::<std::net::Ipv4Addr>().ok();
            }
        }
        m
    }
}

/// Wait (blocking, ≤ deadline) for a CONNECTED state line; returns the parsed
/// tun address when present. Used by the bring-up worker AFTER up()'s RPC has
/// already returned `connecting` to the caller.
pub fn wait_connected(deadline: Instant) -> Result<Option<std::net::Ipv4Addr>, MgmtError> {
    let mut c = MgmtClient::connect()?;
    c.send_command("state on")?;
    loop {
        if Instant::now() >= deadline {
            return Err(MgmtError::Timeout);
        }
        match c.read_line()? {
            Some(line) if line.starts_with(">STATE:") => {
                let s = MgmtState::parse(&line);
                let connected = line.contains(",CONNECTED,SUCCESS,");
                if connected {
                    return Ok(s.tun_local_v4);
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
        let line = ">STATE:1660000000,CONNECTED,SUCCESS,203.0.113.9,443,10.8.0.2,255.255.255.0";
        let s = MgmtState::parse(line);
        assert_eq!(s.tun_local_v4, Some("10.8.0.2".parse().unwrap()));
        assert_eq!(s.remote_port, Some(443));
        assert!(s.remote_host_ref.is_some());
    }

    #[test]
    fn non_connected_state_lines_yield_nothing() {
        let s = MgmtState::parse(">STATE:1660000000,WAIT,,");
        assert_eq!(s.tun_local_v4, None);
    }
}
