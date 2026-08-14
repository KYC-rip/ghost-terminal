//! The macOS DNS filter proxy (app process, persistent). Listens on the
//! loopback port the helper's PF rdr rules redirect port-53 to, answers
//! blocklisted names with NXDOMAIN, and forwards everything else to a real
//! resolver. The helper is one-shot (spawn → one request → exit), so the
//! long-lived proxy MUST live here, in the persistent app.
//!
//! Reuses the broker's pure `dnsfilter` logic (parse/blocklist/NXDOMAIN) via
//! the `ripley-vpn-broker` crate dependency — no duplicated DNS wire code.

use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ripley_vpn_broker::dnsfilter::{
    is_blocked, nxdomain_response, parse_blocklist, parse_query, DEFAULT_BLOCKLIST,
};

use crate::vpn_macos::{DNS_FILTER_ADDR, DNS_FILTER_FWD_PORT};

const FORWARD_TIMEOUT: Duration = Duration::from_secs(3);
/// Real resolvers to forward to when /etc/resolv.conf only lists a loopback
/// stub (systemd-resolved-style), which drops queries from foreign sockets.
const FALLBACK_UPSTREAMS: &[&str] = &["1.1.1.1:53", "8.8.8.8:53"];

static WORKER: Mutex<Option<Worker>> = Mutex::new(None);

struct Worker {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Start the filter proxy (no-op if already running). `blocklist` is
/// hosts-style text; `None` uses the built-in default. Upstreams are read
/// from the system resolver config.
pub fn start(blocklist: Option<&str>) -> Result<(), String> {
    let mut guard = WORKER.lock().map_err(|_| "dns filter lock poisoned".to_string())?;
    if guard.is_some() {
        return Ok(());
    }
    let rules = parse_blocklist(blocklist.unwrap_or(DEFAULT_BLOCKLIST));
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("ripley-dns-filter".into())
        .spawn(move || run_loop(rules, stop_clone))
        .map_err(|e| format!("spawn dns filter: {e}"))?;
    *guard = Some(Worker { stop, handle: Some(handle) });
    Ok(())
}

/// Stop the filter proxy and join its thread.
pub fn stop() {
    let mut guard = match WORKER.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(worker) = guard.take() {
        worker.stop.store(true, Ordering::SeqCst);
        if let Some(h) = worker.handle {
            let _ = h.join();
        }
    }
}

/// The filter loop: bind the loopback socket, answer blocklisted names with
/// NXDOMAIN, forward the rest to the first reachable upstream.
fn run_loop(rules: Vec<String>, stop: Arc<AtomicBool>) {
    let sock = match UdpSocket::bind(DNS_FILTER_ADDR) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ripley-vpn-broker: dns filter bind {DNS_FILTER_ADDR}: {e}");
            return;
        }
    };
    let rules = Arc::new(rules);
    let mut buf = [0_u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        let (n, peer) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) if stop.load(Ordering::SeqCst) => break,
            Err(_) => continue,
        };
        let pkt = buf[..n].to_vec();
        let sock = Arc::clone(&sock);
        let rules = Arc::clone(&rules);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let Some((id, qname, qlen)) = parse_query(&pkt) else {
                return;
            };
            if is_blocked(&rules, &qname) {
                let resp = nxdomain_response(id, &pkt[12..qlen]);
                let _ = sock.send_to(&resp, peer);
                return;
            }
            for upstream in upstreams() {
                if let Some(resp) = forward(&upstream, &pkt) {
                    let _ = sock.send_to(&resp, peer);
                    return;
                }
            }
            // No upstream answered: SERVFAIL-style NXDOMAIN so clients fail
            // fast instead of hanging on a timeout.
            let resp = nxdomain_response(id, &pkt[12..qlen]);
            let _ = sock.send_to(&resp, peer);
        });
    }
}

/// Real (non-loopback) upstream resolvers. The forward socket uses a fixed
/// source port (`DNS_FILTER_FWD_PORT`) so the PF `no rdr` rule exempts it —
/// otherwise the filter would redirect its own upstream queries back into
/// itself. It binds 0.0.0.0 (not loopback) so it can reach real resolvers.
fn forward(upstream: &SocketAddr, pkt: &[u8]) -> Option<Vec<u8>> {
    let sock = UdpSocket::bind(format!("0.0.0.0:{DNS_FILTER_FWD_PORT}")).ok()?;
    sock.set_read_timeout(Some(FORWARD_TIMEOUT)).ok()?;
    sock.send_to(pkt, upstream).ok()?;
    let mut buf = [0_u8; 4096];
    loop {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let resp = &buf[..n];
                if resp.len() >= 12 && resp[..2] == pkt[..2] {
                    return Some(resp.to_vec());
                }
            }
            Err(_) => return None,
        }
    }
}

fn upstreams() -> Vec<SocketAddr> {
    let from_resolv: Vec<SocketAddr> = std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let mut f = line.split_whitespace();
            if f.next() != Some("nameserver") {
                return None;
            }
            let ip: std::net::IpAddr = f.next()?.parse().ok()?;
            (!ip.is_loopback()).then(|| SocketAddr::new(ip, 53))
        })
        .collect();
    if from_resolv.is_empty() {
        FALLBACK_UPSTREAMS.iter().filter_map(|s| s.parse().ok()).collect()
    } else {
        from_resolv
    }
}
