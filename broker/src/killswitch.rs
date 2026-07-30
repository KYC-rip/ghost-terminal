//! The kill-switch: a dedicated, idempotent nftables table applied as a single
//! atomic transaction via `nft -f -`. Installed BEFORE any route/wg change
//! (fail-closed).
//!
//! Fixes from Codex round-2:
//!  - NO blanket `ct state established,related accept` — that let PRE-EXISTING
//!    clearnet flows keep egressing the physical link. Return traffic for our
//!    permitted flows arrives on the INPUT hook, which this OUTPUT chain doesn't
//!    police, so dropping the blanket rule closes the leak with no downside.
//!  - Endpoint / DHCP / NDP exceptions are scoped to the CAPTURED physical
//!    egress device, not "any interface".
//!  - Explicit `add table` / `delete table` / redefine idiom (add-table is a
//!    no-op if present, so the delete can't EEXIST-abort) for a dependable
//!    atomic replace across reconnect / recovery / removal.
//!
//! We only ever touch `inet ripley_vpn` — never the user's own tables.

use std::net::IpAddr;

use crate::netops::{run_stdin, NetError, FWMARK, IFACE};
use crate::types::Ipv6Policy;

pub const TABLE: &str = "ripley_vpn";

fn header() -> String {
    // add-then-delete makes the following (re)definition an atomic replace that
    // never fails on a pre-existing OR absent table.
    format!("add table inet {TABLE}\ndelete table inet {TABLE}\n")
}

/// Build the active ruleset that pins exactly the endpoint via the physical dev.
fn ruleset(endpoint_ip: IpAddr, port: u16, ipv6: Ipv6Policy, phys: &str) -> String {
    // `meta mark {FWMARK}` ensures ONLY WireGuard's own marked transport packets
    // can use the endpoint hole — not another process racing during bring-up.
    // WireGuard transport is fwmark-stamped. Plain ICMP to the same peer is
    // also allowed so the host speed-test can measure the live server while
    // connected (without opening a general clearnet hole).
    let ep = match endpoint_ip {
        IpAddr::V4(v4) => format!(
            "        oifname \"{phys}\" meta mark {FWMARK} ip daddr {v4} udp dport {port} accept\n\
             oifname \"{phys}\" ip daddr {v4} icmp type echo-request accept\n"
        ),
        IpAddr::V6(v6) => format!(
            "        oifname \"{phys}\" meta mark {FWMARK} ip6 daddr {v6} udp dport {port} accept\n\
             oifname \"{phys}\" ip6 daddr {v6} icmpv6 type echo-request accept\n"
        ),
    };
    let mut s = header();
    s.push_str(&format!("table inet {TABLE} {{\n"));
    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority -100; policy drop;\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str(&format!("        oifname \"{IFACE}\" accept\n")); // tunnel traffic
    s.push_str(&ep); // the exact pinned endpoint, via the physical link only
                     // DHCPv4 + NDP, scoped to the physical link so the tunnel path stays clean.
    s.push_str(&format!(
        "        oifname \"{phys}\" udp dport 67 udp sport 68 accept\n"
    ));
    s.push_str(&format!("        oifname \"{phys}\" icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept\n"));
    if matches!(ipv6, Ipv6Policy::Block) {
        s.push_str("        meta nfproto ipv6 drop\n");
    }
    s.push_str("    }\n}\n");
    s
}

/// Install (or atomically replace) the kill-switch pinning `endpoint_ip:port`
/// out `phys`.
pub fn install(
    endpoint_ip: IpAddr,
    port: u16,
    ipv6: Ipv6Policy,
    phys: &str,
) -> Result<(), NetError> {
    run_stdin(
        "nft",
        &["-f", "-"],
        ruleset(endpoint_ip, port, ipv6, phys).as_bytes(),
    )
}

/// Maximally fail-closed block with NO endpoint hole — used for crash recovery
/// when we don't know (or no longer trust) which endpoint/dev was pinned.
/// Permits only loopback and the minimum DHCP/NDP link housekeeping.
pub fn block_all() -> Result<(), NetError> {
    let mut s = header();
    s.push_str(&format!("table inet {TABLE} {{\n"));
    s.push_str("    chain output {\n");
    s.push_str("        type filter hook output priority -100; policy drop;\n");
    s.push_str("        oifname \"lo\" accept\n");
    s.push_str("        udp dport 67 udp sport 68 accept\n");
    s.push_str("        icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept\n");
    s.push_str("    }\n}\n");
    run_stdin("nft", &["-f", "-"], s.as_bytes())
}

/// Remove the kill-switch, re-opening clearnet. Idempotent (add-then-delete).
pub fn remove() -> Result<(), NetError> {
    run_stdin("nft", &["-f", "-"], header().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn ruleset_pins_endpoint_and_has_no_established_hole() {
        let rs = ruleset(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
            51820,
            Ipv6Policy::Block,
            "eth0",
        );
        assert!(rs.contains("policy drop;"));
        assert!(rs.contains(
            "oifname \"eth0\" meta mark 0xca6c ip daddr 203.0.113.7 udp dport 51820 accept"
        ));
        assert!(rs.contains(
            "oifname \"eth0\" ip daddr 203.0.113.7 icmp type echo-request accept"
        ));
        assert!(rs.contains(&format!("oifname \"{IFACE}\" accept")));
        assert!(rs.contains("meta nfproto ipv6 drop"));
        // The pre-existing-flow leak must be gone.
        assert!(!rs.contains("ct state established"));
    }

    #[test]
    fn full_tunnel_v6_has_no_extra_ipv6_drop() {
        let rs = ruleset(
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            1,
            Ipv6Policy::FullTunnel,
            "wlan0",
        );
        assert!(!rs.contains("meta nfproto ipv6 drop"));
    }

    #[test]
    fn atomic_replace_header_is_add_then_delete() {
        assert!(header().starts_with(&format!(
            "add table inet {TABLE}\ndelete table inet {TABLE}"
        )));
    }
}
