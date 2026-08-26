//! The single source of truth for VPN state, serialized under one mutex, with a
//! DURABLE write-ahead journal so a crash/reboot never leaves egress silently
//! open.
//!
//! Fixes from Codex round-2:
//!  - `egress` / `ks_active` are AUTHORITATIVE fields driven ONLY by a verified
//!    kernel op (an nft/ip command that exited 0). We never *derive* "blocked"
//!    from an in-memory phase, and never report fail-closed without having
//!    actually installed the block.
//!  - The journal lives under `/var/lib` (survives reboot), is written
//!    atomically (tmp → fsync → rename → fsync dir), and a mutation that cannot
//!    persist its intent is REFUSED before it touches the network.
//!  - Recovery runs BEFORE the socket serves (see main.rs `init`).
//!  - "Connected" is only reported once a fresh handshake is observed.

use std::io::Write;
use std::sync::{Mutex, OnceLock};
use std::net::{IpAddr};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::types::{Ipv6Policy, WgConfig};
use crate::{dnsfilter, killswitch, netops, Egress, VpnPhase};

fn now_unix() -> Option<u64> {
    SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}


const JOURNAL_DIR: &str = "/var/lib/ripley-vpn";
const JOURNAL: &str = "/var/lib/ripley-vpn/state";

/// A read-only projection for the status snapshot.
pub struct View {
    pub phase: VpnPhase,
    pub egress: Egress,
    pub ks_pref: bool,
    pub ks_active: bool,
    pub ipv6: Option<Ipv6Policy>,
    pub iface: Option<String>,
    /// Which tunnel protocol this status describes. Additive field — the
    /// envelope `protocol` u32 (wire version) is untouched.
    pub tunnel_kind: Option<TunnelKind>,
    pub profile_name: Option<String>,
    pub handshake_age_secs: Option<u64>,
    pub uptime_secs: Option<u64>,
    /// Unix epoch when the tunnel became configured (for live UI clocks).
    pub connected_at_unix: Option<u64>,
    pub received_bytes: Option<u64>,
    pub sent_bytes: Option<u64>,
    /// A prior teardown left possibly-stale routes/DNS/iface — a normal restore
    /// will refuse to open until it verifies a clean teardown (emergency forces).
    pub cleanup_required: bool,
    /// The on-device DNS blocklist filter is active.
    pub dns_filter: bool,
}

/// The in-memory state captured UNDER the lock. Deliberately IO-free — the
/// handshake probe (which shells out to `wg`) is done afterwards in `finalize`,
/// OUTSIDE the mutex, so a hung `wg` can never freeze every broker operation.
pub struct Base {
    egress: Egress,
    ks_pref: bool,
    ks_active: bool,
    ipv6: Option<Ipv6Policy>,
    configured: bool,
    degraded: bool,
    errored: bool,
    dirty: bool,
    profile_name: Option<String>,
    /// Process-local epoch seconds when the tunnel last became configured.
    connected_since_unix: Option<u64>,
    dns_filter: bool,
    /// Which tunnel kind is (or was last) active. `None` = WG legacy state
    /// (pre-OpenVPN journals never carried a kind).
    tunnel_kind: Option<TunnelKind>,
    /// OpenVPN liveness proof — finalize requires it for Connected.
    ovpn_connected: bool,
}

/// Finalize a snapshot: probe the handshake (bounded, outside the lock) and
/// derive the display phase. `Connected` requires that a handshake has actually
/// happened at least once; we do NOT downgrade on age alone (an idle tunnel with
/// no keepalive legitimately has an old last-handshake), so age is surfaced in
/// `handshake_age_secs` for the UI to judge rather than triggering false alarms.
pub fn finalize(b: Base) -> View {
    // Kind-aware liveness: WireGuard proves Connected via `wg show` handshakes;
    // OpenVPN has no handshake analog — the bring-up worker journals
    // `connected ovpn` after mgmt CONNECTED + iface-up, and finalize treats the
    // configured flag plus that marker as proof (never `wg show` on ovpn kind).
    let is_ovpn = matches!(b.tunnel_kind, Some(TunnelKind::OpenVpn));
    let (hs, transfer) = if !b.configured {
        (None, None)
    } else if is_ovpn {
        (None, ripley_vpn_broker::netops_ovpn::ovpn_transfer_bytes())
    } else {
        (
            netops::handshake_age_secs(),
            netops::transfer_bytes(),
        )
    };
    let phase = if b.configured {
        if b.degraded {
            VpnPhase::DegradedBlocked
        } else if is_ovpn {
            // OVPN: Connected ONLY when the worker completed apply (mgmt
            // CONNECTED + addr/routes/DNS verified under the lock). configured-
            // at-spawn alone is ConnectingBlocked while TLS is in flight.
            if b.ovpn_connected {
                VpnPhase::Connected
            } else {
                VpnPhase::ConnectingBlocked
            }
        } else if hs.is_some() {
            VpnPhase::Connected // WG handshake observed
        } else {
            VpnPhase::ConnectingBlocked // configured, no handshake yet
        }
    } else if b.errored && b.egress == Egress::Blocked {
        VpnPhase::ErrorBlocked
    } else {
        match b.egress {
            Egress::Open => VpnPhase::DisconnectedOpen,
            Egress::Blocked => VpnPhase::DisconnectedBlocked,
        }
    };
    View {
        phase,
        egress: b.egress,
        ks_pref: b.ks_pref,
        ks_active: b.ks_active,
        ipv6: b.ipv6,
        iface: if b.configured {
            Some(netops::IFACE.to_string())
        } else {
            None
        },
        // Only surface a label while a tunnel is actually configured.
        profile_name: if b.configured { b.profile_name } else { None },
        handshake_age_secs: hs,
        uptime_secs: if b.configured {
            match (b.connected_since_unix, now_unix()) {
                (Some(since), Some(now)) => Some(now.saturating_sub(since)),
                _ => None,
            }
        } else {
            None
        },
        connected_at_unix: if b.configured { b.connected_since_unix } else { None },
        received_bytes: transfer.map(|value| value.0),
        sent_bytes: transfer.map(|value| value.1),
        cleanup_required: b.dirty,
        dns_filter: b.dns_filter,
        tunnel_kind: b.tunnel_kind,
    }
}

pub struct Manager {
    egress: Egress,  // authoritative — set only after a verified kernel op
    ks_pref: bool,   // operator's desired setting
    ks_active: bool, // our nft table is actually installed
    ipv6: Option<Ipv6Policy>,
    configured: bool, // wg interface is up
    degraded: bool,   // tunnel up but DNS failed
    errored: bool,    // last op left an error
    dirty: bool,      // a teardown left (possibly) stale routes/DNS/iface
    profile_name: Option<String>, // display-only; cleared when tunnel is down
    connected_since_unix: Option<u64>, // session start for uptime (process-local)
    dns_filter: bool, // loopback DNS blocklist filter is running
    /// Which tunnel kind is active. Kind-aware teardown/boot switch on this.
    tunnel_kind: Option<TunnelKind>,
    /// OpenVPN liveness proof: set ONLY by the worker after mgmt CONNECTED +
    /// network apply; cleared on any teardown. finalize() requires it for
    /// Connected — `configured` alone means ConnectingBlocked (TLS in flight).
    ovpn_connected: bool,
    /// Monotonic cancel counter (plan v9 `Connect generation` row). Every
    /// de-escalating mutator bumps it BEFORE tearing down; a bring-up worker
    /// captured the value at spawn and must find it unchanged before applying
    /// any network mutation or journaling `connected`.
    connect_gen: u64,
}

/// Canonical definition lives in the lib (shared with the macOS helper).
pub use ripley_vpn_broker::TunnelKind;

/// Atomic, durable journal write. tmp → fsync → rename → fsync(dir).
fn journal_persist(marker: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(JOURNAL_DIR)?;
    // Best-effort tighten of the dir (root-only).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(JOURNAL_DIR, std::fs::Permissions::from_mode(0o700));
    }
    let tmp = format!("{JOURNAL}.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(marker.as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, JOURNAL)?;
    // fsync the directory so the rename itself is durable — propagate failure.
    let dir = std::fs::File::open(JOURNAL_DIR)?;
    dir.sync_all()?;
    Ok(())
}

fn journal_best(marker: &str) {
    if let Err(e) = journal_persist(marker) {
        eprintln!("ripley-vpn-broker: journal '{marker}': {e}");
    }
}

/// The journal, distinguishing a genuine first run (NotFound) from an unreadable
/// journal (EIO / permissions / corruption). We must NEVER treat the latter as
/// "open" — an unknown state is recovered fail-closed.
enum Journal {
    FirstRun,
    Marker(String),
    Unreadable(String),
}

fn journal_read() -> Journal {
    match std::fs::read_to_string(JOURNAL) {
        Ok(s) => Journal::Marker(s.trim().to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Journal::FirstRun,
        Err(e) => Journal::Unreadable(e.to_string()),
    }
}

static MGR: OnceLock<Mutex<Manager>> = OnceLock::new();

/// Force initialization (and journal-replay recovery). Call BEFORE binding the
/// socket so we converge to a safe state before serving any request.
pub fn init() {
    let _ = manager();
}

pub fn manager() -> &'static Mutex<Manager> {
    MGR.get_or_init(|| Mutex::new(Manager::boot()))
}

impl Manager {
    fn fresh() -> Manager {
        Manager {
            egress: Egress::Open,
            ks_pref: false,
            ks_active: false,
            ipv6: None,
            configured: false,
            degraded: false,
            errored: false,
            dirty: false,
            profile_name: None,
            connected_since_unix: None,
            dns_filter: false,
            tunnel_kind: None,
            ovpn_connected: false,
            connect_gen: 0,
        }
    }

    /// Best-effort teardown that records whether it left stale state behind, so a
    /// later "open" op can refuse until a clean teardown is verified.
    fn teardown_marking_dirty(&mut self) {
        let errs = self.teardown_any();
        if !errs.is_empty() {
            self.dirty = true;
        }
        self.profile_name = None;
        self.connected_since_unix = None;
    }

    /// THE teardown: switches on the active tunnel kind and sweeps BOTH kinds'
    /// artifacts so a protocol switch can never leave cross-protocol leftovers.
    /// Every former direct `wg_down()` caller goes through here.
    fn teardown_any(&mut self) -> Vec<netops::NetError> {
        let mut errs = netops::wg_down(); // WG iface + policy routing + DNS revert (all benign-if-absent)
        // Clear the OVPN liveness flag HERE so every teardown path — not just
        // worker arms — cannot inherit a stale Connected proof.
        self.ovpn_connected = false;
        match self.tunnel_kind {
            Some(TunnelKind::OpenVpn) => {
                // OpenVPN userspace child: SIGTERM→SIGKILL ladder, then artifact
                // sweep. The pidfile lives in /run (same-boot scope by design).
                errs.extend(ripley_vpn_broker::netops_ovpn::ovpn_down().into_iter().map(|e| netops::NetError::NonZero { cmd: "openvpn teardown".into(), code: None, stderr: e.to_string() }));
            }
            Some(TunnelKind::WireGuard) | None => {}
        }
        self.tunnel_kind = None;
        errs
    }

    /// Monotonic cancel counter bump. Call BEFORE any teardown triggered by a
    /// de-escalating op, so an in-flight bring-up worker observes a mismatched
    /// generation and exits without touching the network or journal.
    fn bump_connect_gen(&mut self) {
        self.connect_gen = self.connect_gen.wrapping_add(1);
    }

    pub fn connect_gen(&self) -> u64 {
        self.connect_gen
    }

    /// The single guarded path to clearnet: verify a CLEAN teardown, then remove
    /// the block. Refuses (stays blocked) if anything is left dirty.
    fn guarded_open(&mut self) -> Result<(), String> {
        self.bump_connect_gen();
        let errs = self.teardown_any();
        if !errs.is_empty() {
            self.dirty = true;
            self.errored = true;
            return Err(format!(
                "teardown incomplete ({}); staying blocked — use emergency restore to force clearnet",
                errs.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; ")
            ));
        }
        self.open_after_verified_teardown()
    }

    /// Replay the journal and converge to a safe state before serving.
    fn boot() -> Manager {
        let mut m = Manager::fresh();
        // OpenVPN artifact sweep runs on EVERY boot (before the journal read):
        // a pidfile surviving our own clean-exit path would be unusual, but a
        // sweep is idempotent and covers any drift. /run scope => reboot-safe.
        if !ripley_vpn_broker::netops_ovpn::ovpn_down().is_empty() {
            m.dirty = true;
        }
        let recover = match journal_read() {
            Journal::FirstRun => false,                 // never ran — genuinely open
            Journal::Marker(m) if m == "open" => false, // clean shutdown
            Journal::Marker(_) => true,                 // may have touched the network
            Journal::Unreadable(e) => {
                eprintln!("ripley-vpn-broker: journal unreadable ({e}) — treating as unknown, recovering fail-closed");
                true
            }
        };
        if recover {
            if !netops::wg_down().is_empty() {
                m.dirty = true;
            }
            // OpenVPN journal recovery: sweep the pidfile-scoped child if any.
            // (PID-reuse safe: the /run pidfile only survives within one boot.)
            let ovpn_errs = ripley_vpn_broker::netops_ovpn::ovpn_down();
            if !ovpn_errs.is_empty() {
                m.dirty = true;
            }
            match killswitch::block_all() {
                Ok(()) => {
                    m.egress = Egress::Blocked;
                    m.ks_active = true;
                    m.ks_pref = true;
                    journal_best("blocked");
                }
                Err(e) => {
                    // A promised fail-closed service must NOT start serving if it
                    // could not secure egress on recovery. Exit (systemd restarts
                    // and retries); never continue open.
                    eprintln!("ripley-vpn-broker: EMERGENCY — recovery block failed, refusing to start OPEN: {e}");
                    std::process::exit(1);
                }
            }
        }
        m
    }

    /// Capture the IO-free state under the lock (handshake is probed later, in
    /// `finalize`, outside the mutex).
    pub fn base(&self) -> Base {
        Base {
            egress: self.egress,
            ks_pref: self.ks_pref,
            ks_active: self.ks_active,
            ipv6: self.ipv6,
            configured: self.configured,
            degraded: self.degraded,
            errored: self.errored,
            dirty: self.dirty,
            profile_name: self.profile_name.clone(),
            connected_since_unix: self.connected_since_unix,
            dns_filter: self.dns_filter,
            tunnel_kind: self.tunnel_kind,
            ovpn_connected: self.ovpn_connected,
        }
    }

    /// guard source state → resolve → capture phys dev → persist intent → seal
    /// block → wg → DNS. egress flips to Blocked ONLY after the nft install
    /// verifiably succeeds. Allowed only from a not-connected state.
    pub fn up(&mut self, cfg: &WgConfig, profile_name: Option<String>) -> Result<(), String> {
        // Reconnect semantics: refuse to bring up over a live tunnel (that would
        // risk tearing down a working link and leaving the box blocked). The
        // caller must disconnect first.
        if self.configured {
            return Err("already connected; disconnect first".into());
        }

        // Resolution needs clearnet DNS. If the kill-switch is already armed
        // (blackhole), a DNS-name endpoint cannot resolve through the normal
        // resolver — `resolve_endpoint_handling_blocked` retries through a
        // scoped DNS hole and re-seals, so a reconnect never forces the user
        // to disable the kill-switch first.
        let endpoint_ip =
            match netops::resolve_endpoint_handling_blocked(cfg, self.egress == Egress::Blocked) {
                Ok(ip) => ip,
                Err(e) if self.egress == Egress::Blocked => {
                    return Err(format!(
                        "cannot resolve endpoint while the kill-switch is armed ({e}); use an IP endpoint or disable the kill-switch first"
                    ));
                }
                Err(e) => return Err(e.to_string()),
            };
        let phys = netops::physical_egress_dev(endpoint_ip).map_err(|e| e.to_string())?;

        // The pre-attempt durable marker, so a CLEAN install failure restores the
        // real prior state instead of clobbering an existing block's journal.
        let prior = if self.egress == Egress::Blocked {
            "blocked"
        } else {
            "open"
        };

        // Persist intent BEFORE touching the network; refuse if we can't.
        journal_persist("connecting").map_err(|e| format!("cannot persist intent: {e}"))?;

        // Seal egress first (fail-closed). Only on success is egress Blocked.
        if let Err(e) = killswitch::install(
            endpoint_ip,
            cfg.endpoint().port(),
            cfg.ipv6(),
            &phys,
            killswitch::EndpointProto::Udp, // WireGuard transport is always UDP
        ) {
            self.errored = true;
            // nft -f is atomic: on failure any prior block is intact, so restore
            // the prior marker (never a blanket "open" that would drop protection
            // on reboot).
            journal_best(prior);
            return Err(format!("kill-switch install: {e}"));
        }
        self.egress = Egress::Blocked;
        self.ks_active = true;
        self.ks_pref = true;
        self.ipv6 = Some(cfg.ipv6());
        journal_best("blocked");

        // Clear any stale state from a prior failed teardown first, so a leftover
        // `ripley0` / routes can't fail this bring-up (bring-up recovers over a
        // dirty blocked state — the egress block installed above stays intact).
        // ALSO the up()-side gen capture point: this bump invalidates any worker
        // from an earlier connect attempt.
        self.bump_connect_gen();
        let captured_gen = self.connect_gen;
        let _ = self.teardown_any();

        // Bring up wg + routes; on failure tear down but KEEP the block.
        if let Err(e) = netops::wg_up(cfg, endpoint_ip) {
            self.teardown_marking_dirty();
            self.configured = false;
            self.errored = true;
            return Err(format!("wg up: {e}"));
        }
        self.configured = true;
        self.errored = false;
        self.dirty = false; // clean bring-up clears any prior dirty state
        self.profile_name = profile_name;
        self.connected_since_unix = now_unix();

        // DNS failure degrades (still blocked), it does not leak.
        self.degraded = if let Err(e) = netops::dns_up(cfg) {
            eprintln!("ripley-vpn-broker: dns up: {e}");
            true
        } else {
            false
        };
        journal_best("connected");
        Ok(())
    }

    pub fn disconnect_blocked(&mut self) -> Result<(), String> {
        // Cancel any in-flight bring-up worker FIRST: gen mismatch means the
        // worker must not install routes/DNS or journal 'connected' after us.
        self.bump_connect_gen();
        // Fail-closed intent is persisted BEFORE the mutation, so a crash can only
        // ever recover toward blocked.
        journal_persist("blocked").map_err(|e| format!("cannot persist intent: {e}"))?;
        self.teardown_marking_dirty();
        if self.egress != Egress::Blocked || !self.ks_active {
            self.seal().map_err(|e| {
                self.errored = true;
                format!("block: {e}")
            })?;
            self.egress = Egress::Blocked;
            self.ks_active = true;
            self.ks_pref = true;
        }
        self.configured = false;
        self.degraded = false;
        self.errored = false;
        self.profile_name = None;
        self.connected_since_unix = None;
        Ok(())
    }

    /// Tear down AND restore clearnet. A NORMAL restore refuses to re-open egress
    /// if teardown was incomplete (stale routes/DNS/iface could remain) — it stays
    /// blocked and tells the caller to force via emergency. On nft-removal failure
    /// we also stay blocked and report — never claim open falsely.
    pub fn disconnect_restore(&mut self) -> Result<(), String> {
        self.guarded_open()
    }

    fn open_after_verified_teardown(&mut self) -> Result<(), String> {
        killswitch::remove().map_err(|e| {
            self.errored = true;
            format!("kill-switch remove: {e}")
        })?;
        self.egress = Egress::Open;
        self.ks_active = false;
        self.ks_pref = false;
        self.configured = false;
        self.degraded = false;
        self.errored = false;
        self.dirty = false;
        self.ipv6 = None;
        self.profile_name = None;
        self.connected_since_unix = None;
        // If the DNS filter is active, restoring clearnet must ALSO reinstall
        // the open-egress redirect so ad-blocking keeps working (the block
        // removal above dropped the redirect chain along with the table).
        if self.dns_filter {
            killswitch::redirect_only().map_err(|e| {
                self.errored = true;
                format!("dns filter redirect: {e}")
            })?;
        }
        journal_best("open");
        Ok(())
    }

    pub fn enable_killswitch(&mut self) -> Result<(), String> {
        if self.configured {
            self.ks_pref = true; // already blocked while connected
            return Ok(());
        }
        journal_persist("blocked").map_err(|e| format!("cannot persist intent: {e}"))?;
        self.seal().map_err(|e| {
            self.errored = true;
            format!("block: {e}")
        })?;
        self.egress = Egress::Blocked;
        self.ks_active = true;
        self.ks_pref = true;
        Ok(())
    }

    /// Disable the kill-switch. Refused while connected. Goes through the SAME
    /// guarded teardown as restore: if any stale routes/DNS/iface remain, it stays
    /// blocked and refuses to open — only `emergency_restore` overrides that.
    pub fn disable_killswitch(&mut self) -> Result<(), String> {
        if self.configured {
            return Err("refusing to disable kill-switch while connected; disconnect first".into());
        }
        self.guarded_open()
    }

    /// Break-glass: FORCE teardown + clearnet regardless of teardown noise. Still
    /// requires the nft removal to succeed (else we cannot honestly open).
    pub fn emergency_restore(&mut self) -> Result<(), String> {
        self.bump_connect_gen();
        let _ = self.teardown_any(); // force — ignore teardown failures
        self.open_after_verified_teardown()
    }

    /// Reconcile toward the fail-closed blocked state (clears stale rules WITHOUT
    /// re-opening egress).
    pub fn reconcile_blocked(&mut self) -> Result<(), String> {
        self.bump_connect_gen();
        journal_persist("blocked").map_err(|e| format!("cannot persist intent: {e}"))?;
        self.teardown_marking_dirty();
        self.seal().map_err(|e| {
            self.errored = true;
            format!("block: {e}")
        })?;
        self.egress = Egress::Blocked;
        self.ks_active = true;
        self.ks_pref = true;
        self.configured = false;
        self.degraded = false;
        self.errored = false;
        self.profile_name = None;
        self.connected_since_unix = None;
        Ok(())
    }

    /// Install the fail-closed blackhole, choosing the DNS-filtering variant
    /// when the on-device filter is active so the port-53 redirect chain stays
    /// installed. This is the ONE place a block is sealed, so the filter flag
    /// and the armed kill-switch can never disagree about which ruleset is live.
    fn seal(&mut self) -> Result<(), String> {
        if self.dns_filter {
            let resolvers = netops::resolvconf_nameservers();
            killswitch::block_with_dns_filter(&resolvers).map_err(|e| e.to_string())
        } else {
            killswitch::block_all().map_err(|e| e.to_string())
        }
    }

    /// Toggle the on-device DNS blocklist. Enabling redirects ALL port-53
    /// traffic through the loopback filter (hardcoded-resolver bypasses
    /// included) and spawns the filter thread; disabling reverts to the plain
    /// block. The flag is process-local and defaults OFF after a restart.
    pub fn set_dns_filter(&mut self, enabled: bool) -> Result<(), String> {
        if enabled == self.dns_filter {
            return Ok(());
        }
        // The kill-switch's DNS hole must reach the system stub (loopback is
        // permitted by the blackhole); the filter's forward needs a REAL
        // resolver — the stub drops queries from the filter's loopback socket.
        let resolvers = netops::resolvconf_nameservers();
        let filter_upstreams = netops::upstream_nameservers();
        if enabled && filter_upstreams.is_empty() {
            return Err("no upstream resolvers found; DNS filter needs a resolver to forward to".into());
        }
        // Install the redirect that forces port-53 through the loopback filter.
        // When the kill-switch is armed the full DNS-filtering blackhole is
        // used (redirect + marked holes); when egress is open the redirect-only
        // ruleset applies so ad-blocking works without dropping any traffic.
        if self.egress == Egress::Blocked {
            if enabled {
                killswitch::block_with_dns_filter(&resolvers).map_err(|e| {
                    self.errored = true;
                    format!("dns filter block: {e}")
                })?;
            } else {
                killswitch::block_all().map_err(|e| {
                    self.errored = true;
                    format!("block: {e}")
                })?;
            }
        } else if enabled {
            killswitch::redirect_only().map_err(|e| {
                self.errored = true;
                format!("dns filter redirect: {e}")
            })?;
        } else {
            // Open egress + filter off: nothing to remove (the redirect table
            // lives in the same ripley_vpn table, removed by block_all/remove).
            let _ = killswitch::remove();
        }
        if enabled {
            let rules = dnsfilter::parse_blocklist(dnsfilter::DEFAULT_BLOCKLIST);
            let upstreams: Vec<_> = filter_upstreams
                .iter()
                .filter_map(|ip| dnsfilter::upstream_from(&format!("{ip}:53")))
                .collect();
            crate::dns_worker::start(upstreams, rules).map_err(|e| {
                self.errored = true;
                format!("start dns filter: {e}")
            })?;
        } else {
            crate::dns_worker::stop();
        }
        self.dns_filter = enabled;
        self.errored = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(egress: Egress) -> Base {
        Base {
            egress,
            ks_pref: false,
            ks_active: false,
            ipv6: None,
            configured: false,
            degraded: false,
            errored: false,
            dirty: false,
            profile_name: None,
            connected_since_unix: None,
            dns_filter: false,
            tunnel_kind: None,
            ovpn_connected: false,
        }
    }

    #[test]
    fn disconnected_open_maps() {
        let v = finalize(base(Egress::Open));
        assert_eq!(v.phase, VpnPhase::DisconnectedOpen);
        assert_eq!(v.egress, Egress::Open);
        assert!(v.iface.is_none());
        assert!(v.handshake_age_secs.is_none());
    }

    #[test]
    fn disconnected_blocked_maps() {
        let v = finalize(base(Egress::Blocked));
        assert_eq!(v.phase, VpnPhase::DisconnectedBlocked);
        assert_eq!(v.egress, Egress::Blocked);
    }

    #[test]
    fn errored_blocked_is_error_phase() {
        let mut b = base(Egress::Blocked);
        b.errored = true;
        assert_eq!(finalize(b).phase, VpnPhase::ErrorBlocked);
    }

    #[test]
    fn egress_is_authoritative_errored_open_is_not_error_blocked() {
        // An error while egress is genuinely OPEN must not masquerade as blocked.
        let mut b = base(Egress::Open);
        b.errored = true;
        let v = finalize(b);
        assert_eq!(v.phase, VpnPhase::DisconnectedOpen);
        assert_eq!(v.egress, Egress::Open);
    }
}

impl Manager {
    /// Content-based protocol sniff for the Up envelope (no filename exists
    /// there). Exact two-field rule: WG needs BOTH markers; OVPN needs a
    /// line-anchored client/remote token; anything else (both or neither) is
    /// ambiguous ⇒ invalid config.
    pub fn sniff_tunnel_kind(text: &str) -> Result<TunnelKind, String> {
        let lower = text.to_ascii_lowercase();
        let wg_present = lower.contains("[interface]") && lower.contains("[peer]");
        let ovpn_present = text
            .lines()
            .any(|l| {
                let t = l.trim_start();
                t.starts_with("client ") || t == "client" || t.starts_with("remote ")
                    || t.starts_with("--client") || t.starts_with("--remote")
            });
        match (wg_present, ovpn_present) {
            (true, false) => Ok(TunnelKind::WireGuard),
            (false, true) => Ok(TunnelKind::OpenVpn),
            (true, true) | (false, false) => {
                Err("unknown protocol: cannot determine tunnel kind".into())
            }
        }
    }
}

#[cfg(test)]
mod sniff_tests {
    use super::*;

    #[test]
    fn sniffs_wireguard_conf() {
        let wg = "[Interface]\nPrivateKey = x\n[Peer]\nPublicKey = y\n";
        assert!(matches!(Manager::sniff_tunnel_kind(wg), Ok(TunnelKind::WireGuard)));
    }

    #[test]
    fn sniffs_ovpn_by_client_or_remote_line() {
        let ovpn = "client\nremote vpn.example.net 443 tcp\n<ca>x</ca>\n";
        assert!(matches!(Manager::sniff_tunnel_kind(ovpn), Ok(TunnelKind::OpenVpn)));
        let remote_only = "  remote other.example.net 1194\n";
        assert!(matches!(Manager::sniff_tunnel_kind(remote_only), Ok(TunnelKind::OpenVpn)));
    }

    #[test]
    fn ambiguous_and_unknown_are_invalid() {
        let both = "[Interface]\n[Peer]\nclient\nremote a 443\n";
        assert!(Manager::sniff_tunnel_kind(both).is_err());
        let neither = "hello world\n";
        assert!(Manager::sniff_tunnel_kind(neither).is_err());
    }
}

impl Manager {
    /// OpenVPN bring-up — the numbered Model-A copy of `up()`:
    /// resolve-pin → phys dev → journal connecting → seal(proto) → stale
    /// sweep (gen bump + capture) → spawn → RPC returns `connecting` →
    /// worker: wait CONNECTED → link up → addr → policy routing → DNS →
    /// journal connected. Any failure ⇒ teardown_any + prior-token restore.
    pub fn up_openvpn(
        &mut self,
        cfg: &ripley_vpn_broker::parser_ovpn::OvpnConfig,
        profile_name: Option<String>,
    ) -> Result<(), String> {
        use ripley_vpn_broker::netops_ovpn;

        if self.configured {
            return Err("already connected; disconnect first".into());
        }

        // Resolve-pin BEFORE any seal (WG-order parity). Hostname remotes are
        // resolved on clearnet with the WG resolver (getent); ONLY when the
        // kill-switch is already armed do we refuse — that path needs the
        // scoped-DNS-hole retry, which lands with reconnect-under-blocked.
        let endpoint_host: IpAddr = match cfg.remote_host() {
            ripley_vpn_broker::types::EndpointHost::Ip(ip) => *ip,
            ripley_vpn_broker::types::EndpointHost::Dns(name) => {
                if self.egress == Egress::Blocked && self.ks_active {
                    return Err(
                        "cannot resolve hostname while the kill-switch is armed; restore clearnet once or use an IP remote"
                            .into(),
                    );
                }
                let out = std::process::Command::new("getent")
                    .args(["ahosts", name])
                    .env_clear()
                    .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
                    .output()
                    .map_err(|e| format!("resolve {name}: {e}"))?;
                let text = String::from_utf8_lossy(&out.stdout);
                let ip = text
                    .lines()
                    .filter_map(|l| l.split_whitespace().next())
                    .filter_map(|s| s.parse::<IpAddr>().ok())
                    .find(|ip| ip.is_ipv4() || ip.is_ipv4() == false && false)
                    .or_else(|| {
                        text.lines()
                            .filter_map(|l| l.split_whitespace().next())
                            .filter_map(|s| IpAddr::from_str(s).ok())
                            .next()
                    })
                    .ok_or_else(|| format!("remote '{name}' resolved to no usable address"))?;
                if ip.is_ipv6() {
                    return Err("IPv6 remotes are not supported in v1".into());
                }
                ip
            }
        };

        let phys = netops::physical_egress_dev(endpoint_host)
            .map_err(|e| e.to_string())?;

        let prior = if self.egress == Egress::Blocked { "blocked" } else { "open" };

        journal_persist("connecting ovpn").map_err(|e| format!("cannot persist intent: {e}"))?;

        // Seal egress FIRST (fail-closed). v1 OVPN always blocks IPv6.
        if let Err(e) = killswitch::install(
            endpoint_host,
            cfg.remote_port(),
            Ipv6Policy::Block,
            &phys,
            crate_killswitch_proto(cfg),
        ) {
            self.errored = true;
            journal_best(prior);
            return Err(format!("kill-switch install: {e}"));
        }
        self.egress = Egress::Blocked;
        self.ks_active = true;
        self.ks_pref = true;
        // NEVER journal "open" after a successful seal: crash recovery must
        // treat the box as blocked, not clean-open.
        journal_best("blocked");

        // Gen capture + bump BEFORE the stale sweep so a concurrent teardown
        // invalidates this worker.
        self.bump_connect_gen();
        let captured_gen = self.connect_gen;
        let _ = self.teardown_any();
        self.tunnel_kind = Some(TunnelKind::OpenVpn);

        // Spawn + pidfile + connecting reply. Post-seal failures stay BLOCKED.
        #[cfg(target_os = "linux")]
        let conf_body = netops_ovpn::build_runtime_conf(cfg, endpoint_host);
        #[cfg(target_os = "linux")]
        let mut child = match netops_ovpn::spawn_openvpn(&conf_body) {
            Ok(c) => c,
            Err(e) => {
                self.errored = true;
                self.tunnel_kind = None;
                journal_best("blocked");
                return Err(format!("openvpn spawn: {e}"));
            }
        };
        #[cfg(target_os = "linux")]
        if let Err(e) = netops_ovpn::write_pid_record(&child) {
            let _ = child.kill();
            let _ = netops_ovpn::ovpn_down();
            self.errored = true;
            self.tunnel_kind = None;
            journal_best("blocked");
            return Err(format!("pidfile write: {e}"));
        }
        self.configured = true; // ConnectingBlocked-under-KS until CONNECTED
        self.ovpn_connected = false;
        self.profile_name = profile_name.filter(|p| !p.is_empty());
        self.connected_since_unix = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        );

        // Model A worker: everything below runs after the RPC returned OK.
        // Gen-gated under the manager lock at BOTH apply and failure points.
        // Linux-only: on macOS helperd owns supervision via its own loop.
        let dns_servers: Vec<std::net::IpAddr> = cfg.dns_servers().to_vec();
        #[cfg(target_os = "linux")]
        std::thread::spawn(move || {
            use std::time::{Duration, Instant};

            // Reaper liveness: monitor the child for unexpected death.
            let deadline = Instant::now() + netops_ovpn::MGMT_CONNECT_DEADLINE;

            // wait_result: Ok(tun_local) | Err(reason)
            let wait_result: Result<std::net::Ipv4Addr, String> = loop {
                match child.try_wait() {
                    Ok(Some(status)) => {
                        break Err(format!("openvpn exited during TLS: status={status:?}"));
                    }
                    Ok(None) => {}
                    Err(e) => break Err(format!("waitpid probe: {e}")),
                }
                if Instant::now() >= deadline {
                    break Err("CONNECTED not observed within deadline".into());
                }
                match netops_ovpn::poll_connected_once() {
                    Ok(Some(addr)) => break Ok(addr),
                    Ok(None) => sleep_sleep(Duration::from_millis(250)),
                    Err(e) => break Err(e.to_string()),
                }
            };

            // Lock + gen gate + apply + journal — ALL under ONE lock hold.
            let mut mgr = match crate_state_lock() {
                Some(g) => g,
                None => return, // poisoned: another thread force-exits
            };
            if mgr.connect_gen != captured_gen {
                // A newer intent (disconnect/reconcile/restore) owns the child.
                // The cancel path already ran teardown_any under its own lock,
                // which SIGTERM/KILLed this child via pidfile identity. Sweep
                // once more idempotently in case we raced between its steps.
                let _ = netops_ovpn::ovpn_down();
                eprintln!("ripley-vpn-broker: openvpn worker gen mismatch — no mutation, exiting");
                drop(mgr);
                return;
            }

            match wait_result {
                Ok(tun_local) => {
                    let mut errs: Vec<String> =
                        netops_ovpn::ovpn_apply_network(tun_local, &dns_servers);
                    errs.extend(
                        netops_policy_routing_up()
                            .iter()
                            .map(|e| e.to_string()),
                    );
                    if !errs.is_empty() {
                        // Fail closed: tear down the half-open tunnel.
                        let _ = netops_ovpn::ovpn_down();
                        mgr.errored = true;
                        mgr.configured = false;
                        mgr.ovpn_connected = false;
                        mgr.tunnel_kind = None;
                        mgr.teardown_marking_dirty();
                        journal_best("errored ovpn");
                        eprintln!(
                            "ripley-vpn-broker: openvpn network apply failed — torn down: {}",
                            errs.join("; ")
                        );
                        drop(mgr);
                        return; // do NOT fall into the death watcher after teardown
                    }
                    mgr.ovpn_connected = true;
                    mgr.degraded = false;
                    mgr.dirty = false;
                    journal_best("connected ovpn");
                    eprintln!("ripley-vpn-broker: openvpn connected (worker)");
                }
                Err(e) => {
                    // Fail closed on TLS/wait: tear down, stay blocked. RETURN —
                    // never enter the child-death watcher from this path.
                    let _ = netops_ovpn::ovpn_down();
                    mgr.errored = true;
                    mgr.teardown_marking_dirty();
                    mgr.configured = false;
                    mgr.ovpn_connected = false;
                    mgr.tunnel_kind = None;
                    journal_best("blocked");
                    eprintln!("ripley-vpn-broker: openvpn connect failed fail-closed ({e})");
                    drop(mgr);
                    return;
                }
            }

            // Child-death watcher (post-apply only). ONE lock acquisition per
            // tick — no nested re-lock of a guard we still hold.
            let gen_at_watch = mgr.connect_gen;
            drop(mgr);
            loop {
                sleep_sleep(Duration::from_secs(1));
                let mut locked = match crate_state_lock() {
                    Some(g) => g,
                    None => return,
                };
                if locked.connect_gen != gen_at_watch {
                    drop(locked);
                    return; // superseded by disconnect/reconcile — they own cleanup
                }
                if !netops_ovpn::child_alive_by_pidfile() {
                    // Unexpected death of a live tunnel: converge to blocked.
                    let _ = netops_ovpn::ovpn_down();
                    netops::wg_down(); // sweep routes/DNS too (benign-if-absent)
                    locked.dirty = true;
                    locked.configured = false;
                    locked.ovpn_connected = false;
                    locked.tunnel_kind = None;
                    drop(locked); // release BEFORE journal write is fine (fs op)
                    journal_best("blocked");
                    eprintln!(
                        "ripley-vpn-broker: openvpn child died unexpectedly — reconciled to blocked"
                    );
                    return;
                }
                drop(locked);
            }
        });

        Ok(())
    }

    pub fn ovpn_connected(&self) -> bool {
        self.ovpn_connected
    }
}

fn crate_state_lock() -> Option<std::sync::MutexGuard<'static, Manager>> {
    manager().lock().ok()
}


/// Kill-switch transport for the parsed OVPN profile.
fn crate_killswitch_proto(
    cfg: &ripley_vpn_broker::parser_ovpn::OvpnConfig,
) -> killswitch::EndpointProto {
    match cfg.proto_transport() {
        ripley_vpn_broker::parser_ovpn::TransportProto::Udp => killswitch::EndpointProto::Udp,
        ripley_vpn_broker::parser_ovpn::TransportProto::Tcp => killswitch::EndpointProto::Tcp,
    }
}

fn sleep_sleep(d: Duration) {
    std::thread::sleep(d);
}

/// Policy-routing install for the ovpn tun — reuses the EXACT WG constants
/// (fwmark rule pair + table 51820) via netops' internal helper, exposed as
/// pub(crate).
fn netops_policy_routing_up() -> Vec<netops::NetError> {
    netops::ovpn_routes_up()
}

#[cfg(test)]
mod ovpn_phase_tests {
    use super::*;

    fn ovpn_base(connected: bool) -> Base {
        Base {
            egress: Egress::Blocked,
            ks_pref: true,
            ks_active: true,
            ipv6: Some(Ipv6Policy::Block),
            configured: true,
            degraded: false,
            errored: false,
            dirty: false,
            profile_name: Some("test".into()),
            connected_since_unix: None,
            dns_filter: false,
            tunnel_kind: Some(TunnelKind::OpenVpn),
            ovpn_connected: connected,
        }
    }

    #[test]
    fn ovpn_configured_without_worker_proof_is_connecting_blocked() {
        // TLS in flight: mgmt CONNECTED has not been journaled yet.
        let v = finalize(ovpn_base(false));
        assert_eq!(v.phase, VpnPhase::ConnectingBlocked);
    }

    #[test]
    fn ovpn_with_worker_applied_is_connected() {
        let v = finalize(ovpn_base(true));
        assert_eq!(v.phase, VpnPhase::Connected);
    }
}
