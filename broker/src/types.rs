//! Typed, security-hardened value types for the broker.
//!
//! Per Codex: keys are base64-DECODED to 32 bytes (not shape-checked); every
//! secret buffer is zeroized; secrets are non-Clone / non-Serde / redacted
//! Debug; endpoints and CIDRs are parsed to typed values, not kept as arbitrary
//! text. `WgConfig` is constructible only through `WgConfig::assemble` (called
//! by the parser) and exposes read-only accessors — no public fields.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD, Engine};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 32-byte WireGuard public key (non-secret, but identifying → redacted Debug).
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey([u8; 32]);

impl PublicKey {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey(<32 bytes>)")
    }
}

/// A 32-byte secret (private key or PSK). Zeroized on drop, no Clone, no Serde,
/// redacted Debug — it must never be logged, cloned, or serialized.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretKey(<redacted>)")
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    Base64,
    Len(usize),
    NonCanonical,
    AllZero,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::Base64 => write!(f, "not valid base64"),
            KeyError::Len(n) => write!(f, "decoded to {n} bytes, expected 32"),
            KeyError::NonCanonical => write!(f, "non-canonical base64 encoding"),
            KeyError::AllZero => write!(f, "all-zero key rejected"),
        }
    }
}

/// Decode a base64 32-byte key. The decoded bytes and the re-encoded canonical
/// check are held in zeroizing buffers so no plaintext copy outlives this fn.
fn decode_key32(s: &str) -> Result<[u8; 32], KeyError> {
    let s = s.trim();
    let bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(STANDARD.decode(s).map_err(|_| KeyError::Base64)?);
    if bytes.len() != 32 {
        return Err(KeyError::Len(bytes.len()));
    }
    // Reject non-canonical encodings so one key has exactly one representation.
    let reenc: Zeroizing<String> = Zeroizing::new(STANDARD.encode(bytes.as_slice()));
    if reenc.as_str() != s {
        return Err(KeyError::NonCanonical);
    }
    if bytes.iter().all(|&b| b == 0) {
        return Err(KeyError::AllZero);
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&bytes);
    Ok(a)
}

pub fn parse_public_key(s: &str) -> Result<PublicKey, KeyError> {
    decode_key32(s).map(PublicKey)
}

pub fn parse_secret_key(s: &str) -> Result<SecretKey, KeyError> {
    decode_key32(s).map(SecretKey)
}

/// A validated peer endpoint. Kept typed so no arbitrary text reaches later code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: EndpointHost,
    port: u16,
}

impl Endpoint {
    pub fn host(&self) -> &EndpointHost {
        &self.host
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointHost {
    Ip(IpAddr),
    Dns(String), // strict ASCII DNS name
}

#[derive(Debug, PartialEq, Eq)]
pub enum EndpointError {
    NoPort,
    BadPort,
    EmptyHost,
    BadHost,
    UnbracketedIpv6,
}

impl fmt::Display for EndpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EndpointError::NoPort => write!(f, "missing :port"),
            EndpointError::BadPort => write!(f, "invalid port (1..=65535)"),
            EndpointError::EmptyHost => write!(f, "empty host"),
            EndpointError::BadHost => write!(f, "invalid host"),
            EndpointError::UnbracketedIpv6 => {
                write!(f, "IPv6 endpoint must be bracketed [addr]:port")
            }
        }
    }
}

pub fn parse_endpoint(s: &str) -> Result<Endpoint, EndpointError> {
    let s = s.trim();
    // Bracketed IPv6 literal: [2001:db8::1]:51820
    if let Some(rest) = s.strip_prefix('[') {
        let (ip6, tail) = rest.split_once(']').ok_or(EndpointError::BadHost)?;
        let ip: IpAddr = ip6.parse().map_err(|_| EndpointError::BadHost)?;
        if !ip.is_ipv6() {
            return Err(EndpointError::BadHost);
        }
        let port = tail.strip_prefix(':').ok_or(EndpointError::NoPort)?;
        return Ok(Endpoint {
            host: EndpointHost::Ip(ip),
            port: parse_port(port)?,
        });
    }
    let (host, port) = s.rsplit_once(':').ok_or(EndpointError::NoPort)?;
    // An unbracketed colon in the host means someone passed a bare IPv6 literal;
    // rsplit_once would silently mangle it. Force the bracketed form.
    if host.contains(':') {
        return Err(EndpointError::UnbracketedIpv6);
    }
    let port = parse_port(port)?;
    if let Ok(ip) = IpAddr::from_str(host) {
        return Ok(Endpoint {
            host: EndpointHost::Ip(ip),
            port,
        });
    }
    validate_dns(host)?;
    Ok(Endpoint {
        host: EndpointHost::Dns(host.to_ascii_lowercase()),
        port,
    })
}

fn parse_port(p: &str) -> Result<u16, EndpointError> {
    let n: u32 = p.trim().parse().map_err(|_| EndpointError::BadPort)?;
    if n == 0 || n > 65535 {
        return Err(EndpointError::BadPort);
    }
    Ok(n as u16)
}

/// Strict ASCII DNS hostname: labels 1-63 chars of [a-z0-9-] not starting/ending
/// with '-', total ≤ 253, at least one label.
fn validate_dns(host: &str) -> Result<(), EndpointError> {
    if host.is_empty() {
        return Err(EndpointError::EmptyHost);
    }
    if host.len() > 253 {
        return Err(EndpointError::BadHost);
    }
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(EndpointError::BadHost);
        }
        let b = label.as_bytes();
        if b[0] == b'-' || b[label.len() - 1] == b'-' {
            return Err(EndpointError::BadHost);
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            return Err(EndpointError::BadHost);
        }
    }
    Ok(())
}

/// A validated CIDR (interface address / DNS reachability). AllowedIPs are handled
/// separately as the full-tunnel literals, so this rejects unusable classes
/// (unspecified/multicast) that make no sense as a host or resolver address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix: u8,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CidrError {
    Shape,
    BadIp,
    BadPrefix,
    Unusable,
}

impl fmt::Display for CidrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CidrError::Shape => write!(f, "not addr/prefix"),
            CidrError::BadIp => write!(f, "bad IP"),
            CidrError::BadPrefix => write!(f, "bad prefix"),
            CidrError::Unusable => write!(f, "unspecified/multicast address not allowed"),
        }
    }
}

/// Parse an interface address. wg-quick explicitly permits the CIDR mask to be
/// omitted; in that case it is a host address (/32 for IPv4, /128 for IPv6).
/// Rejects unspecified (0.0.0.0/::) and multicast — neither is valid here.
pub fn parse_interface_cidr(s: &str) -> Result<Cidr, CidrError> {
    let (ip, explicit_prefix) = match s.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (s, None),
    };
    let addr = IpAddr::from_str(ip.trim()).map_err(|_| CidrError::BadIp)?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let p: u16 = match explicit_prefix {
        Some(prefix) => prefix.trim().parse().map_err(|_| CidrError::BadPrefix)?,
        None => max,
    };
    // A /0 "interface address" is nonsensical and dangerous once it becomes a
    // route — reject it outright.
    if p == 0 || p > max {
        return Err(CidrError::BadPrefix);
    }
    if addr.is_unspecified() || addr.is_multicast() || addr.is_loopback() {
        return Err(CidrError::Unusable);
    }
    if let IpAddr::V4(v4) = addr {
        if v4.is_broadcast() {
            return Err(CidrError::Unusable);
        }
    }
    Ok(Cidr {
        addr,
        prefix: p as u8,
    })
}

/// Reject an IP that is unusable as a DNS resolver (unspecified/multicast).
pub fn validate_dns_ip(addr: IpAddr) -> Result<(), CidrError> {
    if addr.is_unspecified() || addr.is_multicast() {
        return Err(CidrError::Unusable);
    }
    Ok(())
}

/// v1 IPv6 policy: either the tunnel carries `::/0` (full) or IPv6 is blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Ipv6Policy {
    FullTunnel,
    Block,
}

/// A fully validated WireGuard config. Fields are private; construct only via
/// `assemble` (the parser) and read via accessors, so no other module can forge
/// one that skipped validation.
#[derive(Debug)]
pub struct WgConfig {
    private_key: SecretKey,
    address: Vec<Cidr>,
    dns: Vec<IpAddr>,
    peer_public_key: PublicKey,
    preshared_key: Option<SecretKey>,
    endpoint: Endpoint,
    ipv6: Ipv6Policy,
    persistent_keepalive: Option<u16>,
    mtu: Option<u16>,
    listen_port: Option<u16>,
}

impl WgConfig {
    /// The single construction path. `pub(crate)` so only the parser (same crate)
    /// can call it, and every argument is already a validated typed value.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assemble(
        private_key: SecretKey,
        address: Vec<Cidr>,
        dns: Vec<IpAddr>,
        peer_public_key: PublicKey,
        preshared_key: Option<SecretKey>,
        endpoint: Endpoint,
        ipv6: Ipv6Policy,
        persistent_keepalive: Option<u16>,
        mtu: Option<u16>,
        listen_port: Option<u16>,
    ) -> Self {
        WgConfig {
            private_key,
            address,
            dns,
            peer_public_key,
            preshared_key,
            endpoint,
            ipv6,
            persistent_keepalive,
            mtu,
            listen_port,
        }
    }

    pub fn private_key(&self) -> &SecretKey {
        &self.private_key
    }
    pub fn address(&self) -> &[Cidr] {
        &self.address
    }
    pub fn dns(&self) -> &[IpAddr] {
        &self.dns
    }
    pub fn peer_public_key(&self) -> &PublicKey {
        &self.peer_public_key
    }
    pub fn preshared_key(&self) -> Option<&SecretKey> {
        self.preshared_key.as_ref()
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }
    pub fn ipv6(&self) -> Ipv6Policy {
        self.ipv6
    }
    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.persistent_keepalive
    }
    pub fn mtu(&self) -> Option<u16> {
        self.mtu
    }
    pub fn listen_port(&self) -> Option<u16> {
        self.listen_port
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A canonical 32-byte base64 key (all 0x01 bytes).
    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[test]
    fn key_decode_ok() {
        assert!(parse_public_key(K1).is_ok());
        assert!(parse_secret_key(K1).is_ok());
    }
    #[test]
    fn key_rejects_all_zero() {
        let z = STANDARD.encode([0u8; 32]);
        assert_eq!(parse_public_key(&z), Err(KeyError::AllZero));
    }
    #[test]
    fn key_rejects_short() {
        let s = STANDARD.encode([1u8; 16]);
        assert!(matches!(parse_public_key(&s), Err(KeyError::Len(_))));
    }
    #[test]
    fn endpoint_ok_forms() {
        assert!(parse_endpoint("vpn.example.com:51820").is_ok());
        assert!(parse_endpoint("1.2.3.4:51820").is_ok());
        assert!(parse_endpoint("[2001:db8::1]:51820").is_ok());
    }
    #[test]
    fn endpoint_rejects_junk() {
        for bad in [
            "http://evil:51820",
            "bad host:123",
            "vpn.example:0",
            "vpn.example:99999",
            "noport",
        ] {
            assert!(parse_endpoint(bad).is_err(), "{bad} should be rejected");
        }
    }
    #[test]
    fn endpoint_rejects_unbracketed_ipv6() {
        assert_eq!(
            parse_endpoint("2001:db8::1:51820"),
            Err(EndpointError::UnbracketedIpv6)
        );
    }
    #[test]
    fn cidr_rejects_unusable() {
        assert_eq!(parse_interface_cidr("0.0.0.0/32"), Err(CidrError::Unusable));
        assert_eq!(
            parse_interface_cidr("224.0.0.1/32"),
            Err(CidrError::Unusable)
        );
        assert_eq!(
            parse_interface_cidr("127.0.0.1/32"),
            Err(CidrError::Unusable)
        );
        assert_eq!(
            parse_interface_cidr("255.255.255.255/32"),
            Err(CidrError::Unusable)
        );
        assert_eq!(
            parse_interface_cidr("10.0.0.0/0"),
            Err(CidrError::BadPrefix)
        );
        assert!(parse_interface_cidr("10.0.0.2/32").is_ok());
    }
    #[test]
    fn cidr_accepts_wg_quick_host_addresses_without_masks() {
        assert_eq!(
            parse_interface_cidr("10.143.216.101").unwrap(),
            Cidr {
                addr: "10.143.216.101".parse().unwrap(),
                prefix: 32,
            }
        );
        assert_eq!(
            parse_interface_cidr("fd64:e20:68a3::f:d865").unwrap(),
            Cidr {
                addr: "fd64:e20:68a3::f:d865".parse().unwrap(),
                prefix: 128,
            }
        );
    }
    #[test]
    fn secret_debug_redacted() {
        let k = parse_secret_key(K1).unwrap();
        assert_eq!(format!("{k:?}"), "SecretKey(<redacted>)");
    }
}
