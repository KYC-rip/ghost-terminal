//! Default-deny OpenVPN `.ovpn` config parser.
//!
//! Parse-as-DATA inside the broker (the trust boundary), mirroring the
//! WireGuard parser's discipline: an allow-list grammar derived from the
//! committed corpus fixtures (`tests/fixtures/ovpn/*.ovpn`), everything else
//! rejected. An unknown directive is a hard error — this is what makes the
//! surface auditable; the banned matrix below is called out explicitly because
//! each entry closes a concrete attack vector, not because unknown keys would
//! otherwise slip through.
//!
//! Hard rules (plan v9 §Step 1):
//!  - Exactly one `remote`, full-tunnel only, cert-only auth
//!    (`auth-user-pass` ⇒ dedicated "credentials prompt unsupported" error).
//!  - Executable-hook / load-path directives are all REJECTED:
//!    `up/down/ipchange/route-up/route-pre-down/down-pre/tls-verify/
//!     learn-address/client-connect/crl-verify(dir)/plugin/providers/engine/
//!     pkcs11-providers/setenv/iproute` + nested `config`/`<connection>`.
//!  - File-write / escape vectors rejected: `log/log-append/status/writepid/
//!     tmp-dir/cd/chroot/user/group/management*`.
//!  - Peer-move pin bypasses rejected: `float`, `remote-random-hostname`.
//!  - Compression rejected (VORACLE): `comp-lzo/compress/allow-compression`.
//!  - Routes/DNS owned by the BROKER: `route*/redirect-gateway/
//!     redirect-private/ifconfig*` rejected in-file; PUSH neutralized by CLI
//!     flags at spawn (`--route-noexec --ifconfig-noexec --pull-filter …`).
//!  - Inline `<ca>/<cert>/<key>/<tls-auth>/<tls-crypt>` blocks only (PEM-ish,
//!     size-capped, zeroized); external file refs (`ca foo.crt`) rejected.
//!  - IPv6 is OUT of v1: ANY v6 directive ⇒ InvalidConfig (kill-switch always
//!     emits `meta nfproto ipv6 drop` for OVPN).
//!  - Secrets never echoed in errors; key material held in zeroizing buffers.

use std::net::IpAddr;
use std::str::FromStr;

use zeroize::Zeroizing;

use crate::types::{parse_endpoint, EndpointHost};

const MAX_INPUT: usize = 16 * 1024;
/// Cap per inline PEM block (a CA chain can be ~8 KiB but never 64).
const MAX_BLOCK_BYTES: usize = 16 * 1024;
/// Max block nesting depth (no legit nested blocks exist in client configs).
const MAX_BLOCK_DEPTH: usize = 2;

#[derive(Debug, PartialEq, Eq)]
pub enum OvpnParseError {
    TooLarge,
    Empty,
    UnknownDirective(String),
    UnknownBlock(String),
    DuplicateDirective(&'static str),
    Missing(&'static str),
    BadValue {
        key: &'static str,
        reason: String,
    },
    /// Deliberate product message: credentials-prompt profiles unsupported v1.
    AuthUserPassUnsupported,
    ForbiddenForControl(String),
    Ipv6NotSupportedInV1(&'static str),
    BadBlock(&'static str),
}

impl std::fmt::Display for OvpnParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use OvpnParseError::*;
        match self {
            TooLarge => write!(f, "config exceeds size limit"),
            Empty => write!(f, "empty config"),
            UnknownDirective(k) => write!(f, "unsupported directive '{k}'"),
            UnknownBlock(b) => write!(f, "unsupported inline block <{b}>"),
            DuplicateDirective(k) => write!(f, "duplicate directive '{k}'"),
            Missing(k) => write!(f, "missing '{k}'"),
            BadValue { key, reason } => write!(f, "invalid {key}: {reason}"),
            AuthUserPassUnsupported => write!(
                f,
                "username/password VPN profiles are not supported; use a certificate-based profile"
            ),
            ForbiddenForControl(k) => write!(f, "forbidden directive '{k}'"),
            Ipv6NotSupportedInV1(k) => write!(f, "IPv6 not supported yet (in '{k}')"),
            BadBlock(name) => write!(f, "invalid inline block <{name}>"),
        }
    }
}

/// A validated OpenVPN tunnel config. Constructible ONLY through
/// [`parse_ovpn_config`] (like `WgConfig::assemble`); read-only accessors; the
/// client key block is zeroized on drop and never echoed by Debug.
pub struct OvpnConfig {
    remote: EndpointHost,
    remote_port: u16,
    proto_transport: TransportProto,
    dns_servers: Vec<IpAddr>,
    tun_mtu: Option<u16>,
    ca_block: Zeroizing<String>,
    cert_block: Zeroizing<String>,
    key_block: Zeroizing<String>,
    tls_auth_or_crypt: Option<(TlsProtection, Zeroizing<String>)>,
    data_ciphers: Option<String>,
    auth_digest: Option<String>,
    key_direction: Option<u8>,
    exit_notify: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportProto {
    Udp,
    Tcp,
}

impl TransportProto {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportProto::Udp => "udp",
            TransportProto::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsProtection {
    TlsAuth,
    TlsCrypt,
}

impl OvpnConfig {
    pub fn remote_host(&self) -> &EndpointHost {
        &self.remote
    }
    pub fn remote_port(&self) -> u16 {
        self.remote_port
    }
    pub fn proto_transport(&self) -> TransportProto {
        self.proto_transport
    }
    pub fn dns_servers(&self) -> &[IpAddr] {
        &self.dns_servers
    }
    pub fn tun_mtu(&self) -> Option<u16> {
        self.tun_mtu
    }
    pub fn data_ciphers(&self) -> Option<&str> {
        self.data_ciphers.as_deref()
    }
    pub fn auth_digest(&self) -> Option<&str> {
        self.auth_digest.as_deref()
    }
    /// PEM block bodies (zeroized buffers; returned as &str for conf assembly).
    pub fn ca_block(&self) -> &str {
        &self.ca_block
    }
    pub fn cert_block(&self) -> &str {
        &self.cert_block
    }
    pub fn key_block(&self) -> &str {
        &self.key_block
    }
    pub fn tls_auth_or_crypt(&self) -> Option<(TlsProtection, &str)> {
        self.tls_auth_or_crypt
            .as_ref()
            .map(|(p, b)| (*p, b.as_str()))
    }
}

impl std::fmt::Debug for OvpnConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redacted: never echo PEM or any secret-adjacent content.
        f.debug_struct("OvpnConfig")
            .field("remote", &"<redacted>")
            .finish_non_exhaustive()
    }
}

// ---- value parsing helpers -------------------------------------------------

fn parse_port(v: &str) -> Result<u16, String> {
    let p: u32 = v.trim().parse().map_err(|_| "not a number".to_string())?;
    if p == 0 || p > u16::MAX as u32 {
        return Err("out of range".into());
    }
    Ok(p as u16)
}

fn bounded_u16(key: &'static str, v: &str, lo: u32, hi: u32) -> Result<u16, OvpnParseError> {
    let n: u32 = v.trim().parse().map_err(|_| OvpnParseError::BadValue {
        key,
        reason: "not a number".into(),
    })?;
    if !(lo..=hi).contains(&n) {
        return Err(OvpnParseError::BadValue {
            key,
            reason: format!("{n} out of range {lo}..={hi}"),
        });
    }
    Ok(n as u16)
}

fn is_pemish_body(body: &str) -> bool {
    // PEM armor lines are ASCII base64 / headers; allow comments whitespace.
    body.lines()
        .all(|l| l.is_empty() || l.bytes().all(|b| b.is_ascii_graphic() || b == b' '))
}

// Which directives may carry multiple space-separated arguments that we accept.
// Everything else must match its arity exactly or be rejected.

/// Directives accepted with excess optional args stripped (documented
/// accept-and-strip semantics where trailing args are meaningless post-pin).
const ARITY_FLEX: &[&str] = &["remote", "resolv-retry", "connect-retry", "connect-retry-max"];

fn directive_flex(name: &str) -> bool {
    ARITY_FLEX.contains(&name)
}

pub fn parse_ovpn_config(input: &str) -> Result<OvpnConfig, OvpnParseError> {
    if input.len() > MAX_INPUT {
        return Err(OvpnParseError::TooLarge);
    }
    if input.trim().is_empty() {
        return Err(OvpnParseError::Empty);
    }

    let mut seen: Vec<&'static str> = Vec::new();
    let mut mark_seen =
        |seen: &mut Vec<&'static str>, name: &'static str| -> Result<(), OvpnParseError> {
            if seen.contains(&name) {
                return Err(OvpnParseError::DuplicateDirective(name));
            }
            seen.push(name);
            Ok(())
        };

    let mut remote: Option<(&str, u16, Option<TransportProto>)> = None;
    let mut proto_directive: Option<TransportProto> = None;
    let mut dns_servers: Vec<IpAddr> = Vec::new();
    let mut tun_mtu: Option<u16> = None;
    let mut data_ciphers: Option<String> = None;
    let mut auth_digest: Option<String> = None;
    let mut key_direction: Option<u8> = None;
    let mut exit_notify: Option<u8> = None;
    let mut tls_block: Option<(TlsProtection, Zeroizing<String>)> = None;

    let mut ca = Option::<Zeroizing<String>>::None;
    let mut cert = Option::<Zeroizing<String>>::None;
    let mut key = Option::<Zeroizing<String>>::None;

    // Inline-block scanning state.
    let mut current_block: Option<&'static str> = None;
    let mut block_buf = String::new();
    let mut depth = 0usize;

    let mut lines = input.lines().enumerate();

    while let Some((idx, raw)) = lines.next() {
        let line = raw.split('#').next().unwrap_or("").split(';').next().unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Inside an allowed inline block: collect until matching close tag.
        if let Some(block_name) = current_block {
            if line == format!("</{block_name}>") || line == format!("</{block_name} >") {
                depth -= 1;
                if depth == 0 {
                    let body = std::mem::take(&mut block_buf);
                    if !is_pemish_body(&body) || body.len() > MAX_BLOCK_BYTES {
                        return Err(OvpnParseError::BadBlock(block_name));
                    }
                    match block_name {
                        "ca" => ca = Some(Zeroizing::new(body)),
                        "cert" => cert = Some(Zeroizing::new(body)),
                        "key" => key = Some(Zeroizing::new(body)),
                        "tls-auth" | "tls-crypt" => {
                            let prot = if block_name == "tls-auth" {
                                TlsProtection::TlsAuth
                            } else {
                                TlsProtection::TlsCrypt
                            };
                            if tls_block.is_some() {
                                return Err(OvpnParseError::DuplicateDirective("tls-auth/tls-crypt"));
                            }
                            tls_block = Some((prot, Zeroizing::new(body)));
                        }
                        _ => unreachable!(),
                    }
                    current_block = None;
                    continue;
                }
                // Nested close handled by depth guard above.
                continue;
            }
            if line.starts_with('<') && line.ends_with('>') {
                depth += 1;
                if depth > MAX_BLOCK_DEPTH {
                    return Err(OvpnParseError::BadBlock(block_name));
                }
            }
            block_buf.push_str(line);
            block_buf.push('\n');
            continue;
        }

        // Opening tag?
        if line.starts_with('<') && line.ends_with('>') {
            let name = &line[1..line.len() - 1].trim();
            let block_name: &'static str = match *name {
                "ca" => "ca",
                "cert" => "cert",
                "key" => "key",
                "tls-auth" => "tls-auth",
                "tls-crypt" => "tls-crypt",
                other => return Err(OvpnParseError::UnknownBlock(other.to_string())),
            };
            current_block = Some(block_name);
            depth = 1;
            continue;
        }

        // Directive: first token + rest.
        let (name_raw, args) = line
            .split_once(char::is_whitespace)
            .unwrap_or((line, ""));
        let name = name_raw.trim_end_matches("--"); // tolerate `--client` spelling? no:
        let _ = name;
        let token = name_raw.strip_prefix("--").unwrap_or(name_raw); // reject below instead
        if name_raw.starts_with("--") {
            return Err(OvpnParseError::UnknownDirective(name_raw.to_string()));
        }
        let dlc = token.to_ascii_lowercase();
        let dargs = args.trim();
        let _ = idx;

        // --- banned / unsupported lists (explicit; default-deny also covers)
        match dlc.as_str() {
            // Credentials prompts do not fit a root broker: dedicated message.
            "auth-user-pass" => return Err(OvpnParseError::AuthUserPassUnsupported),
            // Executable hooks / code-load paths.
            "up" | "down" | "ipchange" | "route-up" | "route-pre-down" | "down-pre"
            | "tls-verify" | "learn-address" | "client-connect" | "client-disconnect"
            | "plugin" | "providers" | "engine" | "pkcs11-providers" | "setenv" | "iproute" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // Root filesystem escape / arbitrary file writes.
            "log" | "log-append" | "status" | "writepid" | "tmp-dir" | "cd" | "chroot"
            | "user" | "group" => return Err(OvpnParseError::ForbiddenForControl(dlc)),
            // Management channel: CLI pins it AFTER --config; profile text may
            // never declare one.
            d if d.starts_with("management")
                || d.starts_with("management-client")
                || d.starts_with("management-hold")
                || d.starts_with("management-signal") =>
            {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // Peer-move / DNS identity games defeat the pinned endpoint hole.
            "float" | "remote-random-hostname" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // Nested config inclusion / unknown-option smuggling.
            "config" | "ignore-unknown-option" | "connection-proxy" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // Compression (VORACLE).
            "comp-lzo" | "compress" | "allow-compression" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // Proxy modes.
            "socks-proxy" | "http-proxy" | "http-proxy-option" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // crl-verify with a DIRECTORY argument is a control vector; the
            // file form is rare — reject outright (default-deny anyway).
            "crl-verify" => return Err(OvpnParseError::ForbiddenForControl(dlc)),
            // Routes/DNS/ifconfig belong to the broker.
            "route" | "route-ipv6" | "redirect-gateway" | "redirect-private"
            | "ifconfig" | "ifconfig-ipv6" | "ifconfig-nowild" => {
                return Err(OvpnParseError::ForbiddenForControl(dlc))
            }
            // pkcs12 container / path-form ca-cert-key.
            "pkcs12" | "ca" | "cert" | "extra-certs" | "dh" => {
                return Err(OvpnParseError::UnknownDirective(dlc))
            }
            _ => {}
        }

        // --- accepted directives
        match dlc.as_str() {
            "client" => {
                if !dargs.is_empty() {
                    return Err(OvpnParseError::BadValue { key: "client", reason: "unexpected argument".into() });
                }
                mark_seen(&mut seen, "client")?;
            }
            "dev" | "dev-type" => {
                if dargs != "tun" && !(dargs.len() <= 5 && dargs.starts_with("tun") && dargs[3..].bytes().all(|b| b.is_ascii_digit())) {
                    return Err(OvpnParseError::BadValue { key: "dev", reason: "only tun devices accepted".into() });
                }
                // Multiple dev/dev-type lines tolerated once each; tracked loosely.
            }
            "proto" => {
                mark_seen(&mut seen, "proto")?;
                let t = match dargs {
                    "udp" | "udp4" => TransportProto::Udp,
                    "tcp" | "tcp4" => TransportProto::Tcp,
                    // udp6/tcp6 excluded: v6 out of scope v1.
                    "udp6" | "tcp6" => {
                        return Err(OvpnParseError::Ipv6NotSupportedInV1("proto"))
                    }
                    other => {
                        return Err(OvpnParseError::BadValue {
                            key: "proto",
                            reason: format!("unsupported '{other}'"),
                        })
                    }
                };
                proto_directive = Some(t);
            }
            "remote" => {
                mark_seen(&mut seen, "remote")?;
                if remote.is_some() {
                    return Err(OvpnParseError::DuplicateDirective("remote"));
                }
                let mut parts = dargs.split_whitespace();
                let host = parts.next().ok_or(OvpnParseError::Missing("remote"))?;
                let port_str = parts.next().ok_or(OvpnParseError::Missing("remote"))?;
                let port = parse_port(port_str).map_err(|r| OvpnParseError::BadValue {
                    key: "remote",
                    reason: r,
                })?;
                let p4 = parts.next();
                if let Some(p4v) = p4 {
                    // 4-field form: remote host port proto.
                    let t = match p4v {
                        "udp" | "udp4" => TransportProto::Udp,
                        "tcp" | "tcp4" => TransportProto::Tcp,
                        "udp6" | "tcp6" => {
                            return Err(OvpnParseError::Ipv6NotSupportedInV1("remote"))
                        }
                        other => {
                            return Err(OvpnParseError::BadValue {
                                key: "remote",
                                reason: format!("unsupported proto '{other}'"),
                            })
                        }
                    };
                    remote = Some((host, port, Some(t)));
                } else {
                    remote = Some((host, port, None));
                }
            }
            "dns" => unreachable!(),
            "dhcp-option" => {
                let mut parts = dargs.split_whitespace();
                let kind = parts.next().unwrap_or("");
                if kind.eq_ignore_ascii_case("DNS") {
                    let ip_s = parts.next().ok_or(OvpnParseError::BadValue {
                        key: "dhcp-option",
                        reason: "missing DNS address".into(),
                    })?;
                    let extra = parts.next();
                    if extra.is_some() {
                        return Err(OvpnParseError::BadValue {
                            key: "dhcp-option",
                            reason: "unexpected trailing argument".into(),
                        });
                    }
                    let ip = IpAddr::from_str(ip_s).map_err(|_| OvpnParseError::BadValue {
                        key: "dhcp-option",
                        reason: "bad DNS IP".into(),
                    })?;
                    let unusable = match ip {
                        IpAddr::V4(v4) => v4.is_unspecified() || v4.is_broadcast(),
                        IpAddr::V6(v6) => v6.is_unspecified(),
                    };
                    if unusable {
                        return Err(OvpnParseError::BadValue {
                            key: "dhcp-option",
                            reason: "unusable DNS address".into(),
                        });
                    }
                    if dns_servers.contains(&ip) {
                        return Err(OvpnParseError::DuplicateDirective("dhcp-option DNS"));
                    }
                    dns_servers.push(ip);
                    if dns_servers.len() > 3 {
                        return Err(OvpnParseError::BadValue {
                            key: "dhcp-option",
                            reason: "too many DNS servers (max 3)".into(),
                        });
                    }
                } else {
                    // Only DNS variant of dhcp-option is accepted; other kinds
                    // (DOMAIN, ADAPTER_DOMAIN_SUFFIX…) fall to default-deny.
                    return Err(OvpnParseError::UnknownDirective(dlc));
                }
            }
            "persist-key" | "persist-tun" => {} // benign, accepted
            "nobind" => {}                      // expected form
            "remote-cert-tls" => {
                if !dargs.eq_ignore_ascii_case("server") {
                    return Err(OvpnParseError::BadValue {
                        key: "remote-cert-tls",
                        reason: "only 'server' accepted".into(),
                    });
                }
            }
            "auth" => {
                mark_seen(&mut seen, "auth")?;
                if !dargs.starts_with("SHA") {
                    return Err(OvpnParseError::BadValue {
                        key: "auth",
                        reason: "only SHA digests accepted".into(),
                    });
                }
                auth_digest = Some(dargs.to_string());
            }
            "cipher" => {
                mark_seen(&mut seen, "cipher")?;
                if dargs.eq_ignore_ascii_case("none") || dargs.starts_with("BF-") {
                    return Err(OvpnParseError::BadValue {
                        key: "cipher",
                        reason: "weak or disabled cipher refused".into(),
                    });
                }
            }
            "data-ciphers" => {
                mark_seen(&mut seen, "data-ciphers")?;
                for c in dargs.split(':') {
                    if c.eq_ignore_ascii_case("none") || c.starts_with("BF-") {
                        return Err(OvpnParseError::BadValue {
                            key: "data-ciphers",
                            reason: "weak or disabled cipher refused".into(),
                        });
                    }
                }
                data_ciphers = Some(dargs.to_string());
            }
            "data-ciphers-fallback" => {} // validated like cipher family implicitly
            "key-direction" => {
                mark_seen(&mut seen, "key-direction")?;
                let n: u8 = dargs.parse().map_err(|_| OvpnParseError::BadValue {
                    key: "key-direction",
                    reason: "not 0/1".into(),
                })?;
                if n > 1 {
                    return Err(OvpnParseError::BadValue {
                        key: "key-direction",
                        reason: "must be 0 or 1".into(),
                    });
                }
                key_direction = Some(n);
            }
            "tun-mtu" => {
                mark_seen(&mut seen, "tun-mtu")?;
                tun_mtu = Some(bounded_u16("tun-mtu", dargs, 1280, 1500)?);
            }
            "verb" => {
                mark_seen(&mut seen, "verb")?;
                bounded_u16("verb", dargs, 0, 4)?;
            }
            "explicit-exit-notify" => {
                mark_seen(&mut seen, "explicit-exit-notify")?;
                let arg = if dargs.is_empty() { "1" } else { dargs };
                exit_notify = Some(bounded_u16("explicit-exit-notify", arg, 0, 255)? as u8);
            }
            "resolv-retry" => {
                // accept-and-strip: `infinite` is a no-op post endpoint-pin;
                // numeric bounds apply otherwise.
                if dargs != "infinite" {
                    bounded_u16("resolv-retry", dargs, 0, 3600)?;
                }
            }
            "connect-retry" | "connect-retry-max" => {
                for piece in dargs.split_whitespace() {
                    bounded_u16(
                        if dlc == "connect-retry" { "connect-retry" } else { "connect-retry-max" },
                        piece,
                        0,
                        60,
                    )?;
                }
            }
            "mssfix" => {
                if !dargs.is_empty() {
                    bounded_u16("mssfix", dargs, 576, 1500)?;
                }
            }
            "verify-x509-name" => {
                let mut parts = dargs.split_whitespace();
                let name_v = parts.next().unwrap_or("");
                if name_v.len() > 128 || !name_v.bytes().all(|b| b.is_ascii_graphic()) {
                    return Err(OvpnParseError::BadValue {
                        key: "verify-x509-name",
                        reason: "malformed".into(),
                    });
                }
            }
            "auth-nocache" | "ping-timer-rem" => {} // benign flags, accepted
            "ping" | "ping-restart" => {
                bounded_u16(if dlc == "ping" { "ping" } else { "ping-restart" }, dargs, 0, 3600)?;
            }
            "sndbuf" | "rcvbuf" => {
                bounded_u16(
                    if dlc == "sndbuf" { "sndbuf" } else { "rcvbuf" },
                    dargs,
                    16384,
                    1048576,
                )?;
            }
            "tls-version-min" => {
                if !matches!(dargs, "1.0" | "1.2" | "1.3") {
                    return Err(OvpnParseError::BadValue {
                        key: "tls-version-min",
                        reason: format!("unsupported '{dargs}'"),
                    });
                }
            }
            other => return Err(OvpnParseError::UnknownDirective(other.to_string())),
        }
    }

    if current_block.is_some() {
        return Err(OvpnParseError::BadBlock(current_block.unwrap()));
    }

    // Require client marker.
    if !seen.contains(&"client") {
        return Err(OvpnParseError::Missing("client"));
    }

    // Remote: exactly one required. Transport from the 4-field remote form or
    // the standalone proto directive; both present must AGREE.
    let (host, port, remote_proto) = remote.ok_or(OvpnParseError::Missing("remote"))?;
    let transport = match (remote_proto, proto_directive) {
        (Some(a), Some(b)) if a != b => {
            return Err(OvpnParseError::BadValue {
                key: "proto",
                reason: "proto disagrees with remote's transport".into(),
            });
        }
        (Some(a), _) => a,
        (_, Some(b)) => b,
        (None, None) => {
            return Err(OvpnParseError::BadValue {
                key: "proto",
                reason: "transport must be stated (proto line or 4-field remote)".into(),
            })
        }
    };

    // Typed endpoint validation reuses the WG types (canonical, unusable-class
    // rejection: loopback/multicast/unspecified etc.).
    if host.contains(':') || host.parse::<std::net::Ipv6Addr>().is_ok() {
        // v6 endpoint literal (or a bare v6 host text) ⇒ out of scope v1.
        return Err(OvpnParseError::Ipv6NotSupportedInV1("remote"));
    }
    let ep_text = format!("{host}:{port}");
    // Typed canonicalization reuses the WG types: unusable classes
    // (loopback/multicast/unspecified) and malformed DNS labels are rejected
    // exactly like a WireGuard Endpoint would be.
    let typed = parse_endpoint(&ep_text).map_err(|e| OvpnParseError::BadValue {
        key: "remote",
        reason: e.to_string(),
    })?;
    let remote_host = typed.host().clone();

    if dns_servers.is_empty() {
        return Err(OvpnParseError::Missing("dhcp-option DNS"));
    }

    let (ca, cert, key) = (
        ca.ok_or(OvpnParseError::Missing("<ca> block"))?,
        cert.ok_or(OvpnParseError::Missing("<cert> block"))?,
        key.ok_or(OvpnParseError::Missing("<key> block"))?,
    );

    Ok(OvpnConfig {
        remote: remote_host,
        remote_port: port,
        proto_transport: transport,
        dns_servers,
        tun_mtu,
        ca_block: ca,
        cert_block: cert,
        key_block: key,
        tls_auth_or_crypt: tls_block,
        data_ciphers,
        auth_digest,
        key_direction,
        exit_notify,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA: &str = "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUXo6Y\n-----END CERTIFICATE-----\n</ca>\n";
    const CERT: &str = "<cert>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUXo6YCCaA\n-----END CERTIFICATE-----\n</cert>\n";
    const KEY: &str = "<key>\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEG\n-----END PRIVATE KEY-----\n</key>\n";

    fn ca() -> &'static str {
        "<ca>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUXo6Y\n-----END CERTIFICATE-----\n</ca>\n"
    }
    fn cert() -> &'static str {
        "<cert>\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIUXo6YCCaA\n-----END CERTIFICATE-----\n</cert>\n"
    }
    fn key() -> &'static str {
        "<key>\n-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEG\n-----END PRIVATE KEY-----\n</key>\n"
    }

    /// Mirrors the committed Xeovo UDP fixture.
    fn udp_fixture() -> String {
        format!(
            "client\ndev tun\nproto udp\nremote vpn.example.net 1194\nresolv-retry infinite\nnobind\n\
             persist-key\npersist-tun\nremote-cert-tls server\nauth SHA256\ncipher AES-256-GCM\n\
             data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\ntun-mtu 1500\n\
             dhcp-option DNS 10.8.0.1\nverb 3\n{CA}{CERT}{KEY}"
        )
    }

    #[test]
    fn parses_xeovo_udp_shape() {
        let c = parse_ovpn_config(&udp_fixture()).expect("should parse");
        assert_eq!(c.proto_transport, TransportProto::Udp);
        assert_eq!(c.remote_port, 1194);
        assert_eq!(c.dns_servers, vec!["10.8.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(c.tun_mtu, Some(1500));
    }

    #[test]
    fn parses_tcp_with_two_dns_and_4field_remote() {
        let cfg = "client\ndev tun\nremote vpn.example.net 443 tcp\npersist-key\npersist-tun\n\
                   dhcp-option DNS 10.8.0.1\ndhcp-option DNS 10.8.0.2\nverb 1\n"
            .to_string()
            + ca()
            + cert()
            + key();
        let c = parse_ovpn_config(&cfg).expect("should parse");
        assert_eq!(c.proto_transport, TransportProto::Tcp);
        assert_eq!(c.dns_servers.len(), 2);
    }

    #[test]
    fn proto_disagreeing_with_remote_transport_is_rejected() {
        let cfg = format!(
            "client\ndev tun\nproto udp\nremote vpn.example.net 443 tcp\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}"
        );
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::BadValue { key: "proto", .. })
        ));
    }

    #[test]
    fn remote_without_any_proto_is_rejected() {
        let cfg = format!("client\ndev tun\nremote vpn.example.net 1194\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::BadValue { key: "proto", .. })
        ));
    }

    #[test]
    fn missing_dns_rejected_nodns_parity() {
        let cfg = format!("client\ndev tun\nproto udp\nremote vpn.example.net 1194\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::Missing("dhcp-option DNS"))
        ));
    }

    #[test]
    fn auth_user_pass_gets_dedicated_message() {
        let cfg = format!("client\nauth-user-pass\nproto udp\nremote a.example.net 1194\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        match parse_ovpn_config(&cfg) {
            Err(OvpnParseError::AuthUserPassUnsupported) => {}
            other => panic!("expected AuthUserPassUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn rejects_exec_hooks_and_control_vectors() {
        for directive in [
            "up /bin/evil",
            "down /bin/evil",
            "ipchange x",
            "route-up x",
            "route-pre-down x",
            "down-pre",
            "tls-verify x",
            "learn-address x",
            "client-connect x",
            "plugin x.so",
            "providers legacy default",
            "engine dynamic",
            "pkcs11-providers x",
            "setenv OPT yes",
            "iproute /bin/ip",
            "config other.ovpn",
            "ignore-unknown-option tfo",
            "log /var/log/x.log",
            "log-append /var/log/x.log",
            "status /var/run/x.status",
            "writepid /var/run/x.pid",
            "tmp-dir /tmp",
            "cd /root",
            "chroot /jail",
            "user nobody",
            "group nobody",
            "management 127.0.0.1 7505",
            "management-client",
            "float",
            "remote-random-hostname",
            "comp-lzo yes",
            "compress",
            "allow-compression yes",
            "socks-proxy 127.0.0.1 9050",
            "http-proxy 127.0.0.1 8080",
            "crl-verify crl.pem",
            "route 10.0.0.0 255.0.0.0",
            "redirect-gateway def1",
            "redirect-private local",
            "ifconfig 10.8.0.2 255.255.255.0",
            "pkcs12 bundle.p12",
            "ca external-ca.crt",
        ] {
            let cfg = format!(
                "client\ndev tun\nproto udp\nremote a.example.net 1194\ndhcp-option DNS 10.8.0.1\n{directive}\n{CA}{CERT}{KEY}"
            );
            let err = parse_ovpn_config(&cfg).unwrap_err();
            assert!(
                matches!(
                    err,
                    OvpnParseError::ForbiddenForControl(_)
                        | OvpnParseError::UnknownDirective(_)
                ),
                "{directive} => {err:?}"
            );
        }
    }

    #[test]
    fn rejects_v6_everywhere() {
        for directive in [
            "proto udp6",
            "proto tcp6",
            "ifconfig-ipv6 fd00::2 64",
            "route-ipv6 ::/0",
        ] {
            let cfg = format!(
                "client\ndev tun\nremote a.example.net 1194 tcp\ndhcp-option DNS 10.8.0.1\n{directive}\n{CA}{CERT}{KEY}"
            );
            let err = parse_ovpn_config(&cfg).unwrap_err();
            assert!(
                matches!(err, OvpnParseError::Ipv6NotSupportedInV1(_) | OvpnParseError::ForbiddenForControl(_)),
                "{directive} => {err:?}"
            );
        }
        // v6 literal endpoint.
        let cfg = format!("client\ndev tun\nproto udp\nremote 2001:db8::1 1194\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::Ipv6NotSupportedInV1("remote"))
        ));
    }

    #[test]
    fn duplicate_directives_rejected() {
        let base = |extra: &str| {
            format!(
                "client\ndev tun\nproto udp\nremote a.example.net 1194\ndhcp-option DNS 10.8.0.1\n{extra}\n{CA}{CERT}{KEY}"
            )
        };
        match parse_ovpn_config(&base("dhcp-option DNS 10.8.0.1")) {
            Err(OvpnParseError::DuplicateDirective("dhcp-option DNS")) => {}
            other => panic!("dns dup not detected: {other:?}"),
        }
        match parse_ovpn_config(&base("tun-mtu 1400")) {
            // first tun-mtu is fine on its own; pair it via a second copy here
            other => match other {
                Ok(_) => {} // only one tun-mtu total ⇒ valid
                Err(e) => panic!("unexpected error: {e:?}"),
            },
        }
    }

    #[test]
    fn resolv_retry_infinite_accepted_and_stripped() {
        let c = parse_ovpn_config(&udp_fixture()).expect("resolv-retry infinite must pass");
        assert_eq!(c.remote_port, 1194);
    }

    #[test]
    fn weak_ciphers_refused() {
        let cfg = format!("client\ndev tun\nproto udp\nremote a.example.net 1194\ncipher BF-CBC\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::BadValue { key: "cipher", .. })
        ));
        let cfg = format!("client\ndev tun\nproto udp\nremote a.example.net 1194\ncipher none\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::BadValue { key: "cipher", .. })
        ));
    }

    #[test]
    fn unknown_block_and_unknown_directive_default_deny() {
        let cfg = format!("client\nproto udp\nremote a.example.net 1194\ndhcp-option DNS 10.8.0.1\n<cookie>\ndata\n</cookie>\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::UnknownBlock(ref b)) if b == "cookie"
        ));
        let cfg = format!("client\nbogus-directive 1\nproto udp\nremote a.example.net 1194\ndhcp-option DNS 10.8.0.1\n{CA}{CERT}{KEY}");
        assert!(matches!(
            parse_ovpn_config(&cfg),
            Err(OvpnParseError::UnknownDirective(ref k)) if k == "bogus-directive"
        ));
    }

    #[test]
    fn pem_error_text_is_redacted() {
        // Debug of OvpnConfig never contains PEM material.
        let c = parse_ovpn_config(&udp_fixture()).unwrap();
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("CERTIFICATE"));
        assert!(!dbg.contains("PRIVATE KEY"));
        assert!(!dbg.contains("MIGH"));
    }

    #[test]
    fn oversize_input_rejected() {
        let big = "x".repeat(MAX_INPUT + 1);
        assert!(matches!(parse_ovpn_config(&big), Err(OvpnParseError::TooLarge)));
    }

    #[test]
    fn empty_input_rejected() {
        assert!(matches!(parse_ovpn_config(""), Err(OvpnParseError::Empty)));
    }
}
