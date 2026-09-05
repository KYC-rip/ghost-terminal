//! WireGuard `.conf` parser — parse-as-DATA, in the broker (the trust boundary).
//!
//! Hard rules (docs/vpn-panel.md + Codex):
//!  - Reject executable hooks `PreUp/PostUp/PreDown/PostDown` + `SaveConfig`/`Table`.
//!  - Exactly one `[Interface]` + one `[Peer]`; reject unknown/duplicate keys+sections.
//!  - Keys base64-DECODED to 32 bytes, canonical, non-zero (see types.rs); secret
//!    temporaries held in zeroizing buffers and never echoed in error text.
//!  - Endpoint parsed to a typed host+port (types.rs), not arbitrary text.
//!  - Full-tunnel only: `AllowedIPs` must be exactly `0.0.0.0/0` (+ optional `::/0`);
//!    `::/0` sets `Ipv6Policy::FullTunnel`, else `Block`. No other AllowedIPs.
//!  - Addresses/DNS parsed to typed values, canonical-deduped, unusable classes
//!    rejected, and IPv6 family kept coherent with the IPv6 policy.
//!  - Require ≥1 DNS (a full-tunnel with no DNS + kill-switch = broken resolution).
//!  - Size- and cardinality-capped; reject duplicate values.

use std::net::IpAddr;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::types::{
    parse_endpoint, parse_interface_cidr, parse_public_key, parse_secret_key, validate_dns_ip,
    Cidr, Ipv6Policy, WgConfig,
};

const MAX_INPUT: usize = 16 * 1024;
const MAX_LIST: usize = 32;
const HOOK_KEYS: &[&str] = &[
    "preup",
    "postup",
    "predown",
    "postdown",
    "saveconfig",
    "table",
];

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    TooLarge,
    Empty,
    ForbiddenHook(String),
    BadSection(String),
    MissingSection(&'static str),
    DuplicateSection(&'static str),
    UnknownKey {
        section: &'static str,
        key: String,
    },
    DuplicateKey {
        section: &'static str,
        key: String,
    },
    DuplicateValue {
        key: &'static str,
        val: String,
    },
    TooManyValues(&'static str),
    Missing {
        section: &'static str,
        key: &'static str,
    },
    BadValue {
        key: &'static str,
        reason: String,
    },
    MalformedLine, // key=value shape violated — line NOT echoed (may hold a secret)
    NotFullTunnel, // AllowedIPs is not exactly 0.0.0.0/0 (+ optional ::/0)
    NoDns,
    Ipv6Incoherent(&'static str),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ParseError::*;
        match self {
            TooLarge => write!(f, "config exceeds size limit"),
            Empty => write!(f, "empty config"),
            ForbiddenHook(k) => write!(f, "forbidden executable hook: {k}"),
            BadSection(s) => write!(f, "unexpected section [{s}]"),
            MissingSection(s) => write!(f, "missing [{s}] section"),
            DuplicateSection(s) => write!(f, "duplicate [{s}] section"),
            UnknownKey { section, key } => write!(f, "unknown key '{key}' in [{section}]"),
            DuplicateKey { section, key } => write!(f, "duplicate key '{key}' in [{section}]"),
            DuplicateValue { key, val } => write!(f, "duplicate value '{val}' in {key}"),
            TooManyValues(k) => write!(f, "too many values in {k}"),
            Missing { section, key } => write!(f, "missing '{key}' in [{section}]"),
            BadValue { key, reason } => write!(f, "invalid {key}: {reason}"),
            MalformedLine => write!(f, "malformed line (not key=value)"),
            NotFullTunnel => write!(
                f,
                "only full-tunnel accepted (AllowedIPs must be 0.0.0.0/0 [+ ::/0])"
            ),
            NoDns => write!(f, "at least one DNS server is required"),
            Ipv6Incoherent(r) => write!(f, "IPv6 configuration incoherent: {r}"),
        }
    }
}

#[derive(PartialEq)]
enum Section {
    None,
    Interface,
    Peer,
}

pub fn parse_wg_config(input: &str) -> Result<WgConfig, ParseError> {
    if input.len() > MAX_INPUT {
        return Err(ParseError::TooLarge);
    }
    if input.trim().is_empty() {
        return Err(ParseError::Empty);
    }

    let mut section = Section::None;
    let (mut seen_iface, mut seen_peer) = (false, false);

    // Secret temporaries in zeroizing buffers.
    let mut private_key: Option<Zeroizing<String>> = None;
    let mut preshared_key: Option<Zeroizing<String>> = None;

    let mut address: Vec<String> = Vec::new();
    let mut dns: Vec<String> = Vec::new();
    let mut mtu: Option<u16> = None;
    let mut listen_port: Option<u16> = None;
    let mut peer_public_key: Option<String> = None;
    let mut endpoint: Option<String> = None;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut keepalive: Option<u16> = None;

    let mut iface_keys: Vec<String> = Vec::new();
    let mut peer_keys: Vec<String> = Vec::new();

    for raw in input.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            match name.trim().to_ascii_lowercase().as_str() {
                "interface" => {
                    if seen_iface {
                        return Err(ParseError::DuplicateSection("Interface"));
                    }
                    seen_iface = true;
                    section = Section::Interface;
                }
                "peer" => {
                    if seen_peer {
                        return Err(ParseError::DuplicateSection("Peer"));
                    }
                    seen_peer = true;
                    section = Section::Peer;
                }
                other => return Err(ParseError::BadSection(clip(other))),
            }
            continue;
        }

        let (key, val) = match line.split_once('=') {
            Some((k, v)) => (k.trim().to_string(), v.trim().to_string()),
            None => return Err(ParseError::MalformedLine),
        };
        let klc = key.to_ascii_lowercase();
        if HOOK_KEYS.contains(&klc.as_str()) {
            return Err(ParseError::ForbiddenHook(clip(&key)));
        }

        match section {
            Section::None => return Err(ParseError::MalformedLine),
            Section::Interface => {
                if iface_keys.contains(&klc) {
                    return Err(ParseError::DuplicateKey {
                        section: "Interface",
                        key: clip(&key),
                    });
                }
                iface_keys.push(klc.clone());
                match klc.as_str() {
                    "privatekey" => private_key = Some(Zeroizing::new(val)),
                    "address" => push_list("Address", &mut address, &val)?,
                    "dns" => push_list("DNS", &mut dns, &val)?,
                    "mtu" => mtu = Some(parse_bounded("MTU", &val, 1280, 1500)?),
                    "listenport" => {
                        listen_port = Some(parse_bounded("ListenPort", &val, 1, 65535)?)
                    }
                    _ => {
                        return Err(ParseError::UnknownKey {
                            section: "Interface",
                            key: clip(&key),
                        })
                    }
                }
            }
            Section::Peer => {
                if peer_keys.contains(&klc) {
                    return Err(ParseError::DuplicateKey {
                        section: "Peer",
                        key: clip(&key),
                    });
                }
                peer_keys.push(klc.clone());
                match klc.as_str() {
                    "publickey" => peer_public_key = Some(val),
                    "presharedkey" => preshared_key = Some(Zeroizing::new(val)),
                    "endpoint" => endpoint = Some(val),
                    "allowedips" => push_list("AllowedIPs", &mut allowed_ips, &val)?,
                    "persistentkeepalive" => {
                        keepalive = Some(parse_bounded("PersistentKeepalive", &val, 0, 65535)?)
                    }
                    _ => {
                        return Err(ParseError::UnknownKey {
                            section: "Peer",
                            key: clip(&key),
                        })
                    }
                }
            }
        }
    }

    if !seen_iface {
        return Err(ParseError::MissingSection("Interface"));
    }
    if !seen_peer {
        return Err(ParseError::MissingSection("Peer"));
    }

    // Interface: private key (secret in-out never logged).
    let private_key = {
        let raw = private_key.ok_or(ParseError::Missing {
            section: "Interface",
            key: "PrivateKey",
        })?;
        parse_secret_key(&raw).map_err(|e| ParseError::BadValue {
            key: "PrivateKey",
            reason: e.to_string(),
        })?
    };

    if address.is_empty() {
        return Err(ParseError::Missing {
            section: "Interface",
            key: "Address",
        });
    }
    let mut addr_typed: Vec<Cidr> = Vec::new();
    for a in &address {
        let c = parse_interface_cidr(a.trim()).map_err(|e| ParseError::BadValue {
            key: "Address",
            reason: e.to_string(),
        })?;
        if !addr_typed.contains(&c) {
            addr_typed.push(c); // canonical dedup (equivalent spellings collapse)
        }
    }

    if dns.is_empty() {
        return Err(ParseError::NoDns);
    }
    let mut dns_typed: Vec<IpAddr> = Vec::new();
    for d in &dns {
        let ip = IpAddr::from_str(d.trim()).map_err(|_| ParseError::BadValue {
            key: "DNS",
            reason: "bad IP".into(),
        })?;
        validate_dns_ip(ip).map_err(|e| ParseError::BadValue {
            key: "DNS",
            reason: e.to_string(),
        })?;
        if !dns_typed.contains(&ip) {
            dns_typed.push(ip);
        }
    }

    // Peer
    let peer_public_key = parse_public_key(&require("Peer", "PublicKey", peer_public_key)?)
        .map_err(|e| ParseError::BadValue {
            key: "PublicKey",
            reason: e.to_string(),
        })?;
    let preshared_key = match preshared_key {
        Some(p) => Some(parse_secret_key(&p).map_err(|e| ParseError::BadValue {
            key: "PresharedKey",
            reason: e.to_string(),
        })?),
        None => None,
    };
    let endpoint = parse_endpoint(&require("Peer", "Endpoint", endpoint)?).map_err(|e| {
        ParseError::BadValue {
            key: "Endpoint",
            reason: e.to_string(),
        }
    })?;

    if allowed_ips.is_empty() {
        return Err(ParseError::Missing {
            section: "Peer",
            key: "AllowedIPs",
        });
    }
    // Full-tunnel only: exactly 0.0.0.0/0 (+ optional ::/0). Anything else refused.
    let mut has_v4_default = false;
    let mut has_v6_default = false;
    for c in &allowed_ips {
        match c.trim() {
            "0.0.0.0/0" => has_v4_default = true,
            "::/0" => has_v6_default = true,
            _ => return Err(ParseError::NotFullTunnel),
        }
    }
    if !has_v4_default {
        return Err(ParseError::NotFullTunnel);
    }
    let ipv6 = if has_v6_default {
        Ipv6Policy::FullTunnel
    } else {
        Ipv6Policy::Block
    };

    // Family coherence: don't tunnel v6 with no v6 address, and don't leave a v6
    // interface/DNS reachable when v6 is meant to be blocked.
    let has_v6_addr = addr_typed.iter().any(|c| c.addr.is_ipv6());
    let has_v6_dns = dns_typed.iter().any(|ip| ip.is_ipv6());
    match ipv6 {
        Ipv6Policy::FullTunnel if !has_v6_addr => {
            return Err(ParseError::Ipv6Incoherent(
                "::/0 requires an IPv6 interface Address",
            ));
        }
        Ipv6Policy::Block if has_v6_addr => {
            return Err(ParseError::Ipv6Incoherent(
                "IPv6 Address present but ::/0 not in AllowedIPs",
            ));
        }
        Ipv6Policy::Block if has_v6_dns => {
            return Err(ParseError::Ipv6Incoherent(
                "IPv6 DNS unreachable when IPv6 is blocked",
            ));
        }
        _ => {}
    }

    Ok(WgConfig::assemble(
        private_key,
        addr_typed,
        dns_typed,
        peer_public_key,
        preshared_key,
        endpoint,
        ipv6,
        keepalive,
        mtu,
        listen_port,
    ))
}

fn strip_comment(s: &str) -> &str {
    s.split('#').next().unwrap_or("")
}

/// Clip an echoed user token so a pathological line (e.g. mangled key material
/// landing in a key position) can't reflect a full secret back into logs.
fn clip(s: &str) -> String {
    s.chars().take(24).collect()
}

fn push_list(key: &'static str, out: &mut Vec<String>, val: &str) -> Result<(), ParseError> {
    for item in val.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if out.iter().any(|e| e == item) {
            return Err(ParseError::DuplicateValue {
                key,
                val: clip(item),
            });
        }
        out.push(item.to_string());
        if out.len() > MAX_LIST {
            return Err(ParseError::TooManyValues(key));
        }
    }
    Ok(())
}

fn require(
    section: &'static str,
    key: &'static str,
    v: Option<String>,
) -> Result<String, ParseError> {
    v.filter(|s| !s.is_empty())
        .ok_or(ParseError::Missing { section, key })
}

fn parse_bounded(key: &'static str, v: &str, lo: u32, hi: u32) -> Result<u16, ParseError> {
    let n: u32 = v.parse().map_err(|_| ParseError::BadValue {
        key,
        reason: "not a number".into(),
    })?;
    if n < lo || n > hi {
        return Err(ParseError::BadValue {
            key,
            reason: format!("{n} out of range {lo}..={hi}"),
        });
    }
    Ok(n as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // canonical 32-byte

    fn good() -> String {
        format!("[Interface]\nPrivateKey = {KEY}\nAddress = 10.0.0.2/32\nDNS = 10.0.0.1\n\n[Peer]\nPublicKey = {KEY}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n")
    }

    #[test]
    fn accepts_valid_full_tunnel() {
        let c = parse_wg_config(&good()).expect("should parse");
        assert_eq!(c.ipv6(), Ipv6Policy::Block);
        assert_eq!(c.dns().len(), 1);
        assert_eq!(c.address().len(), 1);
    }
    #[test]
    fn v6_default_with_v6_addr_is_full_tunnel() {
        let cfg = good()
            .replace(
                "Address = 10.0.0.2/32",
                "Address = 10.0.0.2/32, fd00::2/128",
            )
            .replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
        assert_eq!(
            parse_wg_config(&cfg).unwrap().ipv6(),
            Ipv6Policy::FullTunnel
        );
    }
    #[test]
    fn accepts_wg_quick_dual_stack_addresses_without_explicit_masks() {
        let cfg = good()
            .replace(
                "Address = 10.0.0.2/32",
                "Address = 10.143.216.101,fd64:e20:68a3::f:d865",
            )
            .replace("DNS = 10.0.0.1", "DNS = 10.0.0.20,fd64:e20:68a2::20")
            .replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0,::/0");
        let parsed = parse_wg_config(&cfg).unwrap();
        assert_eq!(parsed.ipv6(), Ipv6Policy::FullTunnel);
        assert_eq!(parsed.address()[0].prefix, 32);
        assert_eq!(parsed.address()[1].prefix, 128);
    }
    #[test]
    fn v6_default_without_v6_addr_is_incoherent() {
        let cfg = good().replace("AllowedIPs = 0.0.0.0/0", "AllowedIPs = 0.0.0.0/0, ::/0");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::Ipv6Incoherent(_))
        ));
    }
    #[test]
    fn v6_addr_without_v6_default_is_incoherent() {
        let cfg = good().replace(
            "Address = 10.0.0.2/32",
            "Address = 10.0.0.2/32, fd00::2/128",
        );
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::Ipv6Incoherent(_))
        ));
    }
    #[test]
    fn rejects_all_six_hooks() {
        for hook in [
            "PreUp = x",
            "PostUp = /bin/evil",
            "PreDown = x",
            "PostDown = x",
            "SaveConfig = true",
            "Table = off",
        ] {
            let cfg = good().replace(
                "Address = 10.0.0.2/32",
                &format!("Address = 10.0.0.2/32\n{hook}"),
            );
            assert!(
                matches!(parse_wg_config(&cfg), Err(ParseError::ForbiddenHook(_))),
                "{hook}"
            );
        }
    }
    #[test]
    fn rejects_non_full_tunnel() {
        let cfg = good().replace("0.0.0.0/0", "10.0.0.0/24");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::NotFullTunnel)
        ));
    }
    #[test]
    fn rejects_extra_allowed_ip() {
        let cfg = good().replace(
            "AllowedIPs = 0.0.0.0/0",
            "AllowedIPs = 0.0.0.0/0, 8.8.8.8/32",
        );
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::NotFullTunnel)
        ));
    }
    #[test]
    fn requires_dns() {
        let cfg = good().replace("DNS = 10.0.0.1\n", "");
        assert!(matches!(parse_wg_config(&cfg), Err(ParseError::NoDns)));
    }
    #[test]
    fn rejects_unspecified_dns() {
        let cfg = good().replace("DNS = 10.0.0.1", "DNS = 0.0.0.0");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::BadValue { .. })
        ));
    }
    #[test]
    fn rejects_unknown_key() {
        let cfg = good().replace("DNS = 10.0.0.1", "Bogus = 1");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::UnknownKey { .. })
        ));
    }
    #[test]
    fn rejects_bad_key() {
        let cfg = good().replacen(KEY, "short", 1);
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::BadValue { .. })
        ));
    }
    #[test]
    fn malformed_line_does_not_echo() {
        // A private-key-looking line without '=' must not be echoed back.
        let cfg = good().replace(
            "Address = 10.0.0.2/32",
            "Address = 10.0.0.2/32\nbaretokenwithoutanyequalssign",
        );
        match parse_wg_config(&cfg) {
            Err(ParseError::MalformedLine) => {}
            other => panic!("expected MalformedLine, got {other:?}"),
        }
    }
    #[test]
    fn rejects_duplicate_key() {
        let cfg = good().replace("DNS = 10.0.0.1", "DNS = 10.0.0.1\nDNS = 10.0.0.2");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::DuplicateKey { .. })
        ));
    }
    #[test]
    fn rejects_bad_endpoint() {
        let cfg = good().replace("vpn.example.com:51820", "http://evil:51820");
        assert!(matches!(
            parse_wg_config(&cfg),
            Err(ParseError::BadValue { .. })
        ));
    }
}
