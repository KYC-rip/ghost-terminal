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
