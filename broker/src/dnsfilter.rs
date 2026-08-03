//! On-device DNS filtering, shared by the broker's privileged filter and any
//! platform front-end that wants the same blocklist semantics.
//!
//! The broker runs a loopback UDP proxy (`run_loop` in the Linux binary) that
//! answers blocklisted names with NXDOMAIN and forwards everything else to the
//! real resolver. The kill-switch's nft redirect forces every port-53 packet
//! through that socket, so even an app hardcoding a resolver can't bypass the
//! blocklist.
//!
//! Blocklist format: hosts-style lines (`0.0.0.0 ads.example.com`), bare
//! domains (`ads.example.com`), or `#`/`;` comments. Matching is suffix-based:
//! a rule for `example.com` blocks `example.com` and any subdomain.

use std::net::SocketAddr;

/// Loopback address the filter binds. Must match the nft `redirect to`
/// target in `killswitch::blocked_ruleset_with_dns_filter`.
pub const FILTER_ADDR: &str = "127.0.0.1:5353";

/// DNS header is 12 bytes; qname labels are `<len><bytes>` terminated by a 0
/// length byte, followed by 4 bytes of QTYPE+QCLASS.
const HEADER_LEN: usize = 12;
const TRAILER_LEN: usize = 4;

/// Parse one blocklist line into a lowercased domain rule. Accepts hosts-style
/// (`0.0.0.0 domain`), bare domains, comments (`#`/`;`), and blank lines.
pub fn parse_rule(line: &str) -> Option<String> {
    let line = line.trim();
    let line = line.split(['#', ';']).next().unwrap_or("").trim();
    if line.is_empty() {
        return None;
    }
    // hosts-style: the FIRST token is the address, the domain is the SECOND.
    let tokens: Vec<&str> = line.split_whitespace().collect();
    let candidate = if tokens.len() >= 2 {
        tokens[1]
    } else {
        tokens[0]
    };
    let domain = candidate.trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 || domain.contains(['/', ' ']) {
        return None;
    }
    // Must look like a domain (at least one dot), not a bare IP or a hostname
    // fragment. This also rejects rules that would never match a query.
    let has_dot = domain.contains('.');
    let looks_like_ip = domain
        .split('.')
        .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()));
    (has_dot && !looks_like_ip).then_some(domain)
}

/// Is `qname` (lowercased, no trailing dot) covered by any rule? Suffix match:
/// `example.com` blocks itself and `sub.example.com`, but not `badexample.com`.
pub fn is_blocked(rules: &[String], qname: &str) -> bool {
    rules
        .iter()
        .any(|rule| qname == rule.as_str() || qname.ends_with(&format!(".{rule}")))
}

/// Parse a DNS query. Returns the query id, the lowercased qname (no trailing
/// dot), and the byte length of the question section (qname + QTYPE/QCLASS).
pub fn parse_query(pkt: &[u8]) -> Option<(u16, String, usize)> {
    if pkt.len() < HEADER_LEN {
        return None;
    }
    let id = u16::from_be_bytes([pkt[0], pkt[1]]);
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]);
    if qdcount != 1 {
        return None; // only handle the single-question case
    }
    // Walk the qname labels.
    let mut pos = HEADER_LEN;
    let mut name = String::new();
    loop {
        let len = *pkt.get(pos)? as usize;
        if len == 0 {
            break;
        }
        // Compression pointers (top two bits set) are legal in questions but
        // rare from real resolvers; reject rather than risk a bad parse.
        if len & 0xC0 != 0 {
            return None;
        }
        let label = pkt.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(&String::from_utf8_lossy(label).to_ascii_lowercase());
        pos += 1 + len;
    }
    // 4 bytes of QTYPE+QCLASS follow the terminating 0 label.
    let end = pos.checked_add(1 + TRAILER_LEN)?;
    if end > pkt.len() {
        return None;
    }
    Some((id, name, end))
}

/// Build an NXDOMAIN response echoing the query's id and question section.
/// Flags: QR=1, opcode copied, RCODE=3 (NXDOMAIN), recursion desired kept.
pub fn nxdomain_response(id: u16, question: &[u8]) -> Vec<u8> {
    let mut resp = Vec::with_capacity(HEADER_LEN + question.len());
    resp.extend_from_slice(&id.to_be_bytes());
    resp.extend_from_slice(&[0x81, 0x83]); // QR + RD + RCODE=3
    resp.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QD=1, AN=NS=AR=0
    resp.extend_from_slice(question);
    resp
}

/// Load a blocklist from its text representation (hosts-style or bare domains).
/// Returns the parsed rules, skipping comments/blank/invalid lines.
pub fn parse_blocklist(text: &str) -> Vec<String> {
    text.lines().filter_map(parse_rule).collect()
}

/// Convenience for callers that hold parsed `SocketAddr`s.
pub fn upstream_from(addr: &str) -> Option<SocketAddr> {
    addr.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str) -> Vec<u8> {
        let mut pkt = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        pkt
    }

    #[test]
    fn parses_hosts_and_bare_domain_rules() {
        let rules = parse_blocklist(
            "0.0.0.0 ads.example.com\n\
             tracker.net\n\
             # comment\n\
             ; another\n\
             \n\
             127.0.0.1 192.168.1.1\n\
             1.2.3.4\n\
             bad rule with spaces\n",
        );
        assert_eq!(rules, vec!["ads.example.com", "tracker.net"]);
    }

    #[test]
    fn suffix_matching_blocks_subdomains_but_not_similar() {
        let rules = vec!["example.com".to_string()];
        assert!(is_blocked(&rules, "example.com"));
        assert!(is_blocked(&rules, "sub.example.com"));
        assert!(is_blocked(&rules, "a.b.example.com"));
        assert!(!is_blocked(&rules, "badexample.com"));
        assert!(!is_blocked(&rules, "example.org"));
    }

    #[test]
    fn parses_single_question_query() {
        let pkt = query("www.Example.COM");
        let (id, qname, qlen) = parse_query(&pkt).unwrap();
        assert_eq!(id, 0x1234);
        assert_eq!(qname, "www.example.com");
        assert_eq!(qlen, pkt.len());
    }

    #[test]
    fn rejects_compressed_or_multi_question_queries() {
        let mut compressed = query("example.com");
        compressed[HEADER_LEN] = 0xC0; // compression pointer
        assert!(parse_query(&compressed).is_none());

        let mut multi = query("example.com");
        multi[5] = 2; // QDCOUNT = 2
        assert!(parse_query(&multi).is_none());
    }

    #[test]
    fn nxdomain_response_echoes_id_and_question() {
        let pkt = query("blocked.example.com");
        let (id, _, qlen) = parse_query(&pkt).unwrap();
        let resp = nxdomain_response(id, &pkt[HEADER_LEN..qlen]);
        assert_eq!(&resp[..2], &[0x12, 0x34]); // id echoed
        assert_eq!(resp[2], 0x81); // QR + RD
        assert_eq!(resp[3], 0x83); // RCODE = NXDOMAIN
        assert_eq!(&resp[4..6], &[0, 1]); // QDCOUNT = 1
        assert_eq!(&resp[6..12], &[0, 0, 0, 0, 0, 0]); // no answers
        assert_eq!(&resp[HEADER_LEN..], &pkt[HEADER_LEN..qlen]); // question echoed
    }

    #[test]
    fn random_resolver_ip_never_counts_as_a_domain_rule() {
        let rules = parse_blocklist("0.0.0.0 1.1.1.1\n1.1.1.1\n");
        assert!(rules.is_empty());
    }

    #[test]
    fn upstream_addr_parses() {
        assert!(upstream_from("1.1.1.1:53").is_some());
        assert!(upstream_from("not-an-addr").is_none());
    }
}
