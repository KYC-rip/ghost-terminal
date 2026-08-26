//! Shared, non-privileged parts of the VPN broker.
//!
//! The macOS on-demand helper and the Linux service use the exact same
//! parse-as-data boundary. Keeping the parser here prevents a platform port
//! from quietly accepting hooks or partial-tunnel configurations that Linux
//! rejects.

pub mod dnsfilter;
pub mod parser;
pub mod types;

pub use dnsfilter::{
    is_blocked, nxdomain_response, parse_blocklist, parse_query, DEFAULT_BLOCKLIST,
};
pub use parser::{parse_wg_config, ParseError};
pub use parser_ovpn::{parse_ovpn_config, OvpnParseError, OvpnConfig, TransportProto};
pub use types::{Cidr, Endpoint, EndpointHost, Ipv6Policy, WgConfig};
pub mod netops_ovpn;
pub mod parser_ovpn;


/// Free-function sniff re-exported for the Linux bin (state's method needs a
/// Manager instance there — this is the pure content rule).
pub fn state_sniff(text: &str) -> Result<TunnelKind, String> {
    // Delegate to state via its public API if exposed; else inline rule.
    let lower = text.to_ascii_lowercase();
    let wg_present = lower.contains("[interface]") && lower.contains("[peer]");
    let ovpn_present = text.lines().any(|l| {
        let t = l.trim_start();
        t.eq_ignore_ascii_case("client")
            || t.to_ascii_lowercase().starts_with("client ")
            || t.to_ascii_lowercase().starts_with("remote ")
    });
    match (wg_present, ovpn_present) {
        (true, false) => Ok(TunnelKind::WireGuard),
        (false, true) => Ok(TunnelKind::OpenVpn),
        _ => Err("unknown protocol: cannot determine tunnel kind".into()),
    }
}

/// Which tunnel protocol a state/journal entry describes. Canonical in the
/// lib so both the Linux bin and the macOS helper share one definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TunnelKind {
    WireGuard,
    OpenVpn,
}

impl TunnelKind {
    pub fn journal_token(self) -> &'static str {
        match self {
            TunnelKind::WireGuard => "wireguard",
            TunnelKind::OpenVpn => "ovpn",
        }
    }
}
