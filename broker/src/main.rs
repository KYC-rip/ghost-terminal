//! ripley-vpn-broker — the ONLY privileged component of the RipleyOS VPN panel.
//!
//! Runs as a minimal root service with CAP_NET_ADMIN. It listens on a
//! peer-credential-checked Unix socket and accepts **structured operations
//! only** (never caller-supplied shell strings, config paths, or nft snippets),
//! so a WebView/renderer compromise up in the unprivileged Tauri app cannot
//! become arbitrary root. See ../docs/vpn-panel.md for the full spec.
//!
//! This file is the skeleton hardened per Codex: fail-closed socket setup,
//! bounded framing with an ABSOLUTE deadline (slowloris-proof), an RAII-guarded
//! bounded worker pool, zeroized secret buffers, split kill-switch ops, and a
//! versioned request/response contract with stable error codes. The privileged
//! actions (WireGuard bring-up, nftables kill-switch, DNS) are still stubbed and
//! land in follow-up increments, each Codex-reviewed before commit.

// The contract (all phases/egress states, error codes) and the parsed WgConfig
// accessors are defined up-front but only partially exercised by this skeleton;
// bring-up increments consume the rest. Silence dead-code until then.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::stat::{fchmodat, lstat, umask, FchmodatFlags, Mode, SFlag};
use nix::unistd::{chown, Gid, Group, Pid, Uid};
use serde::{Deserialize, Deserializer, Serialize};
use zeroize::Zeroizing;

mod killswitch;
mod netops;
mod parser;
mod state;
mod types;

use types::Ipv6Policy;

/// A string field that is wrapped in `Zeroizing` at deserialization time, so it
/// is wiped on drop EVEN if the surrounding envelope is later rejected (bad
/// protocol / id) before we ever look at it. Carries private-key-bearing config.
struct SecretText(Zeroizing<String>);

impl SecretText {
    fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(SecretText(Zeroizing::new(String::deserialize(d)?)))
    }
}

/// Default socket path. Overridable via argv[1] for tests.
const DEFAULT_SOCK: &str = "/run/ripley-vpn.sock";
const BROKER_GROUP: &str = "ripley";
/// Wire protocol version. Bumped on any breaking contract change.
const PROTOCOL: u32 = 1;
/// Max bytes accepted for a single request frame (one JSON line).
const MAX_FRAME: usize = 32 * 1024;
/// Max length of a caller-supplied request id.
const MAX_ID: usize = 64;
/// Concurrent client cap — a bounded pool so a flood of slow/stalled clients
/// can neither exhaust threads nor serialize behind one another indefinitely.
const MAX_CLIENTS: usize = 8;
/// ABSOLUTE budget for reading one complete frame. Unlike SO_RCVTIMEO (which
/// resets every read), this caps total time so a byte-dribbling client cannot
/// hold a worker forever.
const FRAME_DEADLINE: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Kill-switch-aware connection phase. Every non-connected state that is still
/// fail-closed carries `_BLOCKED`: the egress block persists even when the
/// tunnel is down, so a crash/disconnect never silently leaks clearnet.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum VpnPhase {
    DisconnectedOpen,
    DisconnectedBlocked,
    ConnectingBlocked,
    Connected,
    DegradedBlocked,
    ErrorBlocked,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Egress {
    Open,
    Blocked,
}

/// Stable, machine-readable error codes. The renderer switches on these; the
/// human `reason` is for logs only.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ErrCode {
    BadProtocol,
    BadFrame,
    FrameTooLarge,
    BadRequest,
    NotAuthorized,
    Busy,
    InvalidConfig,
    NotImplemented,
    Internal,
}

/// A full status snapshot. Richer than a single enum so the UI can distinguish
/// "kill-switch desired but nft rules not actually installed" etc. Bring-up
/// increments populate the currently-stubbed fields from real state.
#[derive(Debug, Clone, Serialize)]
struct StatusSnapshot {
    protocol: u32,
    phase: VpnPhase,
    egress: Egress,
    /// Operator's desired kill-switch setting.
    killswitch_pref: bool,
    /// Whether the nftables block is actually installed right now.
    killswitch_active: bool,
    ipv6_policy: Option<Ipv6Policy>,
    interface: Option<String>,
    /// Display-only label of the active profile (never used for routing decisions).
    profile_name: Option<String>,
    /// Seconds since the last successful handshake (age), not a wall-clock stamp.
    handshake_age_secs: Option<u64>,
    /// Seconds the tunnel has been configured in this broker process.
    uptime_secs: Option<u64>,
    connected_at_unix: Option<u64>,
    received_bytes: Option<u64>,
    sent_bytes: Option<u64>,
    /// A prior teardown left possibly-stale state; a normal restore stays blocked
    /// until it verifies a clean teardown (emergency forces).
    cleanup_required: bool,
    error_code: Option<ErrCode>,
}

impl StatusSnapshot {
    /// Cold-start / stubbed snapshot until the state machine + journal land.
    fn stub() -> Self {
        StatusSnapshot {
            protocol: PROTOCOL,
            phase: VpnPhase::DisconnectedOpen,
            egress: Egress::Open,
            killswitch_pref: false,
            killswitch_active: false,
            ipv6_policy: None,
            interface: None,
            profile_name: None,
            handshake_age_secs: None,
            uptime_secs: None,
            connected_at_unix: None,
            received_bytes: None,
            sent_bytes: None,
            cleanup_required: false,
            error_code: None,
        }
    }
}

/// The versioned request envelope. `deny_unknown_fields` so a hostile/garbled
/// payload can't smuggle extra keys past the contract. No `Debug` derive — the
/// `Up` variant carries private-key-bearing config text that must never print.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    protocol: u32,
    /// Caller-supplied id, echoed back for correlation only (NOT yet idempotency
    /// — replay/dedup lands with the mutating bring-up increment).
    id: String,
    request: Request,
}

/// Structured operation — the ONLY thing the broker acts on. Kill-switch is
/// split into explicit enable/disable (never a bool the renderer can flip), and
/// disconnect distinguishes "stay blocked" from "restore clearnet" so dropping
/// the tunnel never implicitly re-opens egress. No `Debug` (see `Envelope`).
#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    /// Raw `.conf` text — the broker parses + validates it (parse-as-data at the
    /// trust boundary), so the unprivileged side never decides what's safe. Held
    /// as `SecretText` so it zeroizes even on a rejected envelope.
    /// Optional `profile_name` is display-only metadata echoed in status.
    Up {
        config_text: SecretText,
        #[serde(default)]
        profile_name: Option<String>,
    },
    /// Tear down the tunnel but KEEP the egress block (fail-closed).
    DisconnectBlocked,
    /// Tear down the tunnel AND restore clearnet — the only path that re-opens
    /// egress; requires the strongest (interactive) authorization.
    DisconnectAndRestoreClearnet,
    EnableKillSwitch,
    /// Disabling the kill-switch is a privileged de-escalation — strongest auth.
    DisableKillSwitch,
    /// Break-glass: drop everything and restore clearnet regardless of state.
    EmergencyRestoreClearnet,
    /// Reconcile toward the fail-closed blocked state after a crash (clears stale
    /// rules WITHOUT re-opening egress). Safe by construction, so not strong-auth.
    ReconcileBlockedState,
}

#[derive(Debug, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    Ok {
        id: String,
        status: StatusSnapshot,
    },
    /// Caller not permitted (peer-cred / future Polkit). Distinct from a bad config.
    Denied {
        id: String,
        code: ErrCode,
        reason: String,
    },
    /// The submitted config failed validation — NOT a permission problem.
    InvalidConfig {
        id: String,
        code: ErrCode,
        reason: String,
    },
    Error {
        id: String,
        code: ErrCode,
        reason: String,
    },
}

/// RAII guard for a worker-pool slot: decrements the in-flight counter on drop,
/// so a panicking (or never-spawned) handler can never permanently leak capacity.
struct SlotGuard(Arc<AtomicUsize>);
impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn main() {
    let sock_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_SOCK.to_string());

    // Refuse to run unprivileged — the whole point is to be the single root gate.
    if !Uid::effective().is_root() {
        eprintln!("ripley-vpn-broker: must run as root (CAP_NET_ADMIN); refusing");
        std::process::exit(2);
    }

    // Recover to a safe (fail-closed) state BEFORE we accept any request — the
    // journal replay must not race an incoming op.
    state::init();

    let listener = match bind_socket(&sock_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("ripley-vpn-broker: {e}");
            std::process::exit(1);
        }
    };

    eprintln!("ripley-vpn-broker: listening on {sock_path}");
    let inflight = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                eprintln!("ripley-vpn-broker: accept: {e}");
                continue;
            }
        };
        // Bounded pool: if we're already at capacity, reject fast rather than
        // spawn unbounded threads or block the accept loop.
        if inflight.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
            inflight.fetch_sub(1, Ordering::SeqCst);
            let _ = reply(
                &stream,
                Response::Error {
                    id: String::new(),
                    code: ErrCode::Busy,
                    reason: "broker busy".into(),
                },
            );
            continue;
        }
        let guard = SlotGuard(Arc::clone(&inflight));
        // On spawn failure the closure (and its guard) drops here, releasing the
        // slot; on success the guard lives until the handler returns or panics.
        if let Err(e) = thread::Builder::new().spawn(move || {
            let _slot = guard;
            handle(stream);
        }) {
            eprintln!("ripley-vpn-broker: spawn: {e}");
        }
    }
}

/// Fail-closed socket setup: never blindly delete an arbitrary path, apply a
/// restrictive umask so the bind mode can't be widened by a permissive process
/// umask, and abort on ANY permission-setting failure (do not just log).
fn bind_socket(sock_path: &str) -> Result<UnixListener, String> {
    let path = Path::new(sock_path);

    // Only remove a pre-existing path if it is a root-owned Unix socket. Refuse
    // to unlink a regular file, a symlink, or anything we don't own — that would
    // be an attacker planting bait for us to delete as root.
    match lstat(path) {
        Ok(st) => {
            let is_sock = SFlag::from_bits_truncate(st.st_mode) & SFlag::S_IFMT == SFlag::S_IFSOCK;
            if !is_sock {
                return Err(format!("refusing to remove non-socket at {sock_path}"));
            }
            if st.st_uid != 0 {
                return Err(format!(
                    "refusing to remove non-root-owned socket at {sock_path}"
                ));
            }
            std::fs::remove_file(path).map_err(|e| format!("unlink {sock_path}: {e}"))?;
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(e) => return Err(format!("lstat {sock_path}: {e}")),
    }

    // Restrictive umask BEFORE bind so the socket is created 0660 at most; then
    // tighten explicitly. Restore the prior umask afterwards.
    let prev = umask(Mode::from_bits_truncate(0o117));
    let listener = UnixListener::bind(path);
    umask(prev);
    let listener = listener.map_err(|e| format!("bind {sock_path}: {e}"))?;

    // Reachable only by root + the ripley group (0660). Set the group explicitly;
    // inheriting root's primary group would leave the desktop client locked out.
    let group = Group::from_name(BROKER_GROUP)
        .map_err(|e| format!("lookup group {BROKER_GROUP}: {e}"))?
        .ok_or_else(|| format!("required group {BROKER_GROUP} does not exist"))?;
    chown(path, None, Some(group.gid)).map_err(|e| format!("chgrp {sock_path}: {e}"))?;
    fchmodat(
        None,
        path,
        Mode::from_bits_truncate(0o660),
        FchmodatFlags::FollowSymlink,
    )
    .map_err(|e| format!("chmod {sock_path}: {e}"))?;

    Ok(listener)
}

fn handle(stream: UnixStream) {
    // If we can't bound writes, a stalled reader could block a worker — refuse
    // to serve rather than risk it (client sees EOF).
    if stream.set_write_timeout(Some(WRITE_TIMEOUT)).is_err() {
        return;
    }
    let deadline = Instant::now() + FRAME_DEADLINE;

    // Peer-credential gate: the socket mode is the coarse group gate, and this
    // second check makes the group requirement explicit. Strong mutations are
    // separately authorized by Polkit below.
    let peer = match getsockopt(&stream, PeerCredentials) {
        Ok(cred) => cred,
        Err(e) => {
            let _ = reply(
                &stream,
                Response::Denied {
                    id: String::new(),
                    code: ErrCode::NotAuthorized,
                    reason: format!("no peer creds: {e}"),
                },
            );
            return;
        }
    };
    let group = Group::from_name(BROKER_GROUP).ok().flatten().map(|g| g.gid);
    let peer_pid = Some(Pid::from_raw(peer.pid()));
    if !authorized_connect(
        Uid::from_raw(peer.uid()),
        Gid::from_raw(peer.gid()),
        peer_pid,
        group,
    ) {
        let _ = reply(
            &stream,
            Response::Denied {
                id: String::new(),
                code: ErrCode::NotAuthorized,
                reason: "peer not authorized".into(),
            },
        );
        return;
    }

    // Frame held in a zeroizing buffer — it carries private-key-bearing config
    // text and must be wiped, not left in freed heap.
    let frame = match read_frame(&stream, deadline) {
        Ok(f) => f,
        Err((code, reason)) => {
            let _ = reply(
                &stream,
                Response::Error {
                    id: String::new(),
                    code,
                    reason,
                },
            );
            return;
        }
    };

    let resp = match serde_json::from_slice::<Envelope>(frame.as_slice()) {
        Ok(env) if env.protocol != PROTOCOL => Response::Error {
            id: safe_id(&env.id),
            code: ErrCode::BadProtocol,
            reason: format!("unsupported protocol {}, expected {PROTOCOL}", env.protocol),
        },
        Ok(env) if env.id.len() > MAX_ID || !env.id.is_ascii() => Response::Error {
            id: String::new(),
            code: ErrCode::BadRequest,
            reason: "request id too long or non-ASCII".into(),
        },
        Ok(env) => dispatch(env, Uid::from_raw(peer.uid()), peer_pid),
        Err(e) => Response::Error {
            id: String::new(),
            code: ErrCode::BadRequest,
            reason: format!("bad request: {e}"),
        },
    };
    let _ = reply(&stream, resp);
}

/// Read exactly one newline-terminated frame, capped at MAX_FRAME, within one
/// ABSOLUTE deadline. Before each read the socket timeout is set to the time
/// remaining, so total read time is bounded regardless of how the bytes dribble.
fn read_frame(
    mut stream: &UnixStream,
    deadline: Instant,
) -> Result<Zeroizing<Vec<u8>>, (ErrCode, String)> {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(256));
    let mut byte = [0u8; 1];
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err((ErrCode::BadFrame, "frame deadline exceeded".into()));
        }
        // A zero Duration would mean "block forever" for SO_RCVTIMEO, so floor it.
        let remaining = (deadline - now).max(Duration::from_millis(1));
        // The absolute deadline depends on this succeeding — if it can't, refuse
        // rather than risk read() blocking forever.
        if let Err(e) = stream.set_read_timeout(Some(remaining)) {
            return Err((ErrCode::BadFrame, format!("set read timeout: {e}")));
        }
        match stream.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() {
                    return Err((ErrCode::BadFrame, "empty request".into()));
                }
                return Ok(buf); // EOF without newline — accept what we have
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    return Ok(buf);
                }
                if buf.len() >= MAX_FRAME {
                    return Err((ErrCode::FrameTooLarge, "request exceeds frame limit".into()));
                }
                buf.push(byte[0]);
            }
            Err(e) => return Err((ErrCode::BadFrame, format!("read: {e}"))),
        }
    }
}

/// Echo an id back only if it is short + ASCII; otherwise drop it (don't reflect
/// attacker-controlled bulk back into logs/responses).
fn safe_id(id: &str) -> String {
    if id.len() <= MAX_ID && id.is_ascii() {
        id.to_string()
    } else {
        String::new()
    }
}

/// The kernel already enforces the socket's root:ripley 0660 gate. This extra
/// check covers primary and supplementary group membership and avoids trusting
/// a non-group peer if the socket is misconfigured.
fn authorized_connect(uid: Uid, gid: Gid, pid: Option<Pid>, broker_gid: Option<Gid>) -> bool {
    if uid.is_root() {
        return true;
    }
    let Some(target) = broker_gid else {
        return false;
    };
    if gid == target {
        return true;
    }
    let Some(pid) = pid else {
        return false;
    };
    let Ok(status) = std::fs::read_to_string(format!("/proc/{}/status", pid.as_raw())) else {
        return false;
    };
    status
        .lines()
        .find(|line| line.starts_with("Groups:"))
        .map(|line| {
            line.split_whitespace()
                .skip(1)
                .any(|g| g.parse::<u32>().ok() == Some(target.as_raw()))
        })
        .unwrap_or(false)
}

/// Ask Polkit to authorize the exact peer process. Supplying the process start
/// time prevents a PID-reuse race between the socket connection and the prompt.
/// No shell is involved; the broker invokes pkcheck directly.
fn authorized_strong(uid: Uid, pid: Option<Pid>, action: &str) -> bool {
    if uid.is_root() {
        return true;
    }
    let Some(pid) = pid else {
        return false;
    };
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", pid.as_raw())) else {
        return false;
    };
    // After the closing ')' the first token is field 3; field 22 is token 19.
    let Some(start) = stat
        .rsplit_once(')')
        .and_then(|(_, suffix)| suffix.split_whitespace().nth(19))
    else {
        return false;
    };
    let process = format!("{},{}", pid.as_raw(), start);
    let checker = if Path::new("/usr/bin/pkcheck").exists() {
        "/usr/bin/pkcheck"
    } else {
        "pkcheck"
    };
    Command::new(checker)
        .args([
            "--action-id",
            action,
            "--process",
            &process,
            "--allow-user-interaction",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn dispatch(env: Envelope, uid: Uid, pid: Option<Pid>) -> Response {
    let id = env.id;
    let strong = |uid: Uid, id: &str, action: &str| -> Option<Response> {
        if authorized_strong(uid, pid, action) {
            None
        } else {
            Some(Response::Denied {
                id: id.to_string(),
                code: ErrCode::NotAuthorized,
                reason: "operation requires interactive authorization".into(),
            })
        }
    };

    match env.request {
        Request::Status => status_response(id),

        // Parse+validate first. A validation failure is InvalidConfig, NOT Denied
        // (permission) — the caller can distinguish "you may not" from "this
        // config is bad". `up()` seals the fail-closed nftables block BEFORE any
        // route/wg change and tears down partial state on any failure.
        Request::Up {
            config_text,
            profile_name,
        } => match parser::parse_wg_config(config_text.as_str()) {
            Ok(cfg) => match strong(uid, &id, "org.ripley.vpn.connect") {
                Some(deny) => deny,
                None => run_op(id, |m| m.up(&cfg, clean_profile_name(profile_name))),
            },
            Err(e) => Response::InvalidConfig {
                id,
                code: ErrCode::InvalidConfig,
                reason: format!("invalid config: {e}"),
            },
        },

        Request::DisconnectBlocked => run_op(id, |m| m.disconnect_blocked()),

        Request::DisconnectAndRestoreClearnet => match strong(uid, &id, "org.ripley.vpn.restore") {
            Some(deny) => deny,
            None => run_op(id, |m| m.disconnect_restore()),
        },
        Request::EnableKillSwitch => run_op(id, |m| m.enable_killswitch()),
        Request::DisableKillSwitch => match strong(uid, &id, "org.ripley.vpn.disable-killswitch") {
            Some(deny) => deny,
            None => run_op(id, |m| m.disable_killswitch()),
        },
        Request::EmergencyRestoreClearnet => match strong(uid, &id, "org.ripley.vpn.restore") {
            Some(deny) => deny,
            None => run_op(id, |m| m.emergency_restore()),
        },
        // Fail-closed by construction → no strong-auth gate.
        Request::ReconcileBlockedState => run_op(id, |m| m.reconcile_blocked()),
    }
}

/// Display-only profile label: bound length and reject control / non-ASCII so a
/// ZIP-derived name cannot smuggle log/UI injection across the root boundary.
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

/// Build a wire snapshot from the manager's view.
fn snapshot_from(view: state::View) -> StatusSnapshot {
    StatusSnapshot {
        protocol: PROTOCOL,
        phase: view.phase,
        egress: view.egress,
        killswitch_pref: view.ks_pref,
        killswitch_active: view.ks_active,
        ipv6_policy: view.ipv6,
        interface: view.iface,
        profile_name: view.profile_name,
        handshake_age_secs: view.handshake_age_secs,
        uptime_secs: view.uptime_secs,
        connected_at_unix: view.connected_at_unix,
        received_bytes: view.received_bytes,
        sent_bytes: view.sent_bytes,
        cleanup_required: view.cleanup_required,
        error_code: None,
    }
}

/// Lock the manager. A POISONED lock means a prior op panicked mid-mutation, so
/// our in-memory view of the kernel is untrustworthy. We do NOT continue with a
/// possibly-inconsistent state: we force the fail-closed blackhole block and exit
/// (systemd restarts us, and boot recovery re-reconciles from the durable
/// journal). Better to be offline-but-blocked than online-and-uncertain.
fn lock_manager() -> std::sync::MutexGuard<'static, state::Manager> {
    match state::manager().lock() {
        Ok(g) => g,
        Err(_) => {
            eprintln!("ripley-vpn-broker: state mutex poisoned — forcing fail-closed and exiting");
            let _ = killswitch::block_all();
            std::process::exit(1);
        }
    }
}

fn status_response(id: String) -> Response {
    // Capture state under the lock, release it, THEN probe the handshake.
    let base = lock_manager().base();
    Response::Ok {
        id,
        status: snapshot_from(state::finalize(base)),
    }
}

/// Run a state-mutating op under the single lock and reply with the resulting
/// snapshot, or a stable Internal error carrying the op's message. The lock is
/// released before the (IO-bearing) snapshot is finalized.
fn run_op(id: String, f: impl FnOnce(&mut state::Manager) -> Result<(), String>) -> Response {
    let base = {
        let mut mgr = lock_manager();
        match f(&mut mgr) {
            Ok(()) => mgr.base(),
            Err(reason) => {
                return Response::Error {
                    id,
                    code: ErrCode::Internal,
                    reason,
                }
            }
        }
    };
    Response::Ok {
        id,
        status: snapshot_from(state::finalize(base)),
    }
}

fn reply(mut stream: &UnixStream, resp: Response) -> std::io::Result<()> {
    let mut json = serde_json::to_string(&resp).unwrap_or_else(|_| {
        "{\"result\":\"error\",\"code\":\"internal\",\"reason\":\"serialize\"}".into()
    });
    json.push('\n');
    stream.write_all(json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn reads_exactly_one_frame() {
        let (mut a, b) = UnixStream::pair().unwrap();
        // Second frame after the newline must be ignored (first-frame-only).
        std::thread::spawn(move || {
            let _ = a.write_all(b"{\"protocol\":1}\n{\"second\":true}\n");
        });
        let frame = read_frame(&b, Instant::now() + Duration::from_secs(5)).unwrap();
        assert_eq!(frame.as_slice(), b"{\"protocol\":1}");
    }

    #[test]
    fn oversized_frame_rejected() {
        let (mut a, b) = UnixStream::pair().unwrap();
        std::thread::spawn(move || {
            let _ = a.write_all(&vec![b'x'; MAX_FRAME + 16]); // no newline
        });
        let r = read_frame(&b, Instant::now() + Duration::from_secs(5));
        assert!(matches!(r, Err((ErrCode::FrameTooLarge, _))));
    }

    #[test]
    fn deadline_exceeded_is_bad_frame() {
        let (_a, b) = UnixStream::pair().unwrap(); // keep peer open, send nothing
        let r = read_frame(&b, Instant::now()); // already elapsed
        assert!(matches!(r, Err((ErrCode::BadFrame, _))));
    }

    #[test]
    fn slot_guard_releases_on_drop() {
        let c = Arc::new(AtomicUsize::new(0));
        c.fetch_add(1, Ordering::SeqCst);
        {
            let _g = SlotGuard(Arc::clone(&c));
            assert_eq!(c.load(Ordering::SeqCst), 1);
        }
        assert_eq!(c.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn secret_text_deserializes_into_zeroizing() {
        let s: SecretText = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(s.as_str(), "hunter2");
    }
}
