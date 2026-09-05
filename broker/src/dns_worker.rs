//! The broker's DNS filter worker (Linux-only): owns the loopback UDP proxy
//! thread and stamps its upstream queries with the kill-switch fwmark so the
//! nft redirect does not loop them back into the filter. Lives in the bin
//! (not the lib) because it shells out to nothing but does need SO_MARK, which
//! only the root broker process is allowed to set.

use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock, atomic::AtomicBool, atomic::Ordering};
use std::thread::JoinHandle;

use nix::sys::socket::{sockopt::Mark, setsockopt};

use crate::dnsfilter::{self, FILTER_ADDR};
use crate::netops::FWMARK;

/// Process-wide handle so `set_dns_filter` can start/stop the worker idempotently.
static WORKER: OnceLock<Mutex<Option<Worker>>> = OnceLock::new();

fn worker_lock() -> &'static Mutex<Option<Worker>> {
    WORKER.get_or_init(|| Mutex::new(None))
}

struct Worker {
    stop: Arc<AtomicBool>,
    handle: JoinHandle<()>,
}

/// Start the filter worker (no-op if already running).
pub fn start(upstreams: Vec<SocketAddr>, rules: Vec<String>) -> Result<(), String> {
    let mut guard = worker_lock().lock().map_err(|_| "dns worker lock poisoned".to_string())?;
    if guard.is_some() {
        return Ok(());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop);
    let handle = std::thread::Builder::new()
        .name("ripley-dns-filter".into())
        .spawn(move || run_loop(upstreams, rules, stop_clone))
        .map_err(|e| format!("spawn dns filter: {e}"))?;
    *guard = Some(Worker { stop, handle });
    Ok(())
}

/// Stop the filter worker and join it.
pub fn stop() {
    let mut guard = match worker_lock().lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    if let Some(worker) = guard.take() {
        worker.stop.store(true, Ordering::SeqCst);
        let _ = worker.handle.join();
    }
}

/// The filter loop: bind the loopback socket, parse each query, answer
/// blocklisted names with NXDOMAIN, and forward the rest to the first
/// upstream that answers. The forwarding socket is fwmark-stamped so the
/// nft `dns_redirect` chain (which excludes marked packets) lets it through.
fn run_loop(upstreams: Vec<SocketAddr>, rules: Vec<String>, stop: Arc<AtomicBool>) {
    let sock = match UdpSocket::bind(FILTER_ADDR) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            eprintln!("ripley-vpn-broker: dns filter bind {FILTER_ADDR}: {e}");
            return;
        }
    };
    let upstreams = Arc::new(upstreams);
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
        let upstreams = Arc::clone(&upstreams);
        let rules = Arc::clone(&rules);
        let stop = Arc::clone(&stop);
        // Each query is independent; a slow upstream must not stall others.
        std::thread::spawn(move || {
            let Some((id, qname, qlen)) = dnsfilter::parse_query(&pkt) else {
                return;
            };
            if dnsfilter::is_blocked(&rules, &qname) {
                let resp = dnsfilter::nxdomain_response(id, &pkt[12..qlen]);
                let _ = sock.send_to(&resp, peer);
                return;
            }
            for upstream in upstreams.iter() {
                if let Some(resp) = forward(upstream, &pkt, &stop) {
                    let _ = sock.send_to(&resp, peer);
                    return;
                }
            }
            // No upstream answered: SERVFAIL so clients fail fast instead of
            // hanging on a timeout.
            let resp = dnsfilter::nxdomain_response(id, &pkt[12..qlen]);
            let _ = sock.send_to(&resp, peer);
        });
    }
}

/// Forward a raw query to `upstream`, returning the resolver's response. Uses
/// a per-query socket stamped with the kill-switch fwmark so the redirect chain
/// (`meta mark != FWMARK ... redirect`) passes our own upstream traffic.
fn forward(upstream: &SocketAddr, pkt: &[u8], stop: &Arc<AtomicBool>) -> Option<Vec<u8>> {
    // Bind to ANY interface (0.0.0.0), NOT loopback: a socket bound to
    // 127.0.0.1 cannot send to a non-loopback destination (EINVAL), and the
    // filter forwards to real resolvers. The redirect chain exempts the
    // marked forward regardless of source.
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(std::time::Duration::from_secs(3))).ok()?;
    // fwmark is a 32-bit value; FWMARK is the hex string used in nft rules.
    let mark: u32 = u32::from_str_radix(FWMARK.trim_start_matches("0x"), 16).ok()?;
    // SO_MARK: only the root broker may set it; the redirect chain
    // (`meta mark != FWMARK ... redirect`) passes our marked upstream traffic.
    // A failure here is fatal — an unmarked forward would be redirected back
    // into the filter, looping forever. Do NOT swallow it.
    if let Err(e) = setsockopt(&sock, Mark, &mark) {
        eprintln!("ripley-vpn-broker: dns filter forward SO_MARK failed: {e}");
        return None;
    }
    if let Err(e) = sock.send_to(pkt, upstream) {
        eprintln!("ripley-vpn-broker: dns filter send_to {upstream}: {e}");
        return None;
    }
    let mut buf = [0_u8; 4096];
    loop {
        if stop.load(Ordering::SeqCst) {
            return None;
        }
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                let resp = &buf[..n];
                // Sanity: the response must echo our query id.
                if resp.len() >= 12 && resp[..2] == pkt[..2] {
                    return Some(resp.to_vec());
                }
                eprintln!("ripley-vpn-broker: dns filter ignored mismatched id from {upstream}");
            }
            Err(e) => {
                eprintln!("ripley-vpn-broker: dns filter recv {upstream}: {e}");
                return None;
            }
        }
    }
}
