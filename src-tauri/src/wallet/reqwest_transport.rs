//! A reqwest-backed `HttpTransport` for monero-oxide's `MoneroDaemon`.
//!
//! monero-oxide's bundled `simple-request` transport hangs while reading a large
//! streamed response body over its manually-driven, unpooled hyper connection.
//! Small responses complete fine, so it went unnoticed until (a) sends, which
//! fetch the full RingCT distribution (`get_output_distribution.bin`, ~20 MB),
//! and (b) sync catch-ups spanning many blocks (large `get_blocks.bin` batches)
//! — both stalled on EVERY node with "timeout reached: Elapsed". reqwest reads
//! the same bodies in a few seconds (verified against the nodes directly), so we
//! use it for the clearnet daemon transport. `MoneroDaemon` is generic over
//! `HttpTransport`, so this is a drop-in with no vendored patching.
//!
//! Distribution caching: monero-oxide's `OutputWithDecoys::new` re-fetches the
//! full distribution for EVERY input (decoys.rs — no cache), so an N-input
//! sweep/churn would pull ~20 MB × N. The distribution is identical for all
//! inputs of one tx (same block height), so we cache the `get_output_distribution.bin`
//! response per transport instance with single-flight: the first fetch populates
//! it, every other input reuses it. One tx == one daemon == one distribution fetch.
//!
//! Proxy compatibility: monerod answers every JSON-RPC-level error (parse error,
//! unknown method) with HTTP 200 and an error envelope, and monero-oxide relies
//! on that — `MoneroDaemon::new` probes batch support and expects `-32700` back
//! as a *body*. Method-allow-listing proxies (mnr.network's `/v1/<token>` relay)
//! carry the same envelope on a 400/403 instead, which used to surface here as
//! a transport error and fail the connect outright. A non-2xx whose body is a
//! JSON-RPC envelope is therefore handed back as the response. Error strings
//! never include the base URL's path: with such proxies the token lives there.

use std::sync::Arc;
use tokio::sync::Mutex;

use monero_daemon_rpc::prelude::*;

const OUTPUT_DISTRIBUTION_ROUTE: &str = "get_output_distribution.bin";

#[derive(Clone)]
pub struct ReqwestTransport {
    base: String,
    /// `scheme://host[:port]` — safe to put in errors/logs (no path, no token).
    base_display: String,
    client: reqwest::Client,
    // (request body, response) — keyed by body so a differing height misses.
    dist_cache: Arc<Mutex<Option<(Vec<u8>, Vec<u8>)>>>,
}

impl ReqwestTransport {
    /// Build a `MoneroDaemon` backed by reqwest for the given clearnet URL. The
    /// timeout bounds each request (connect + send + full body read).
    pub async fn connect(
        url: String,
        timeout: std::time::Duration,
    ) -> Result<MoneroDaemon<ReqwestTransport>, String> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|e| format!("reqwest client build failed: {e}"))?;
        let base = url.trim_end_matches('/').to_string();
        let base_display = redact_url(&base);
        MoneroDaemon::new(ReqwestTransport {
            base,
            base_display,
            client,
            dist_cache: Arc::new(Mutex::new(None)),
        })
        .await
        .map_err(|e| format!("daemon init failed: {e:?}"))
    }

    async fn do_post(
        client: &reqwest::Client,
        url: &str,
        shown: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> Result<Vec<u8>, InterfaceError> {
        let resp = client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("post {shown} failed: {e}")))?;
        let status = resp.status();
        if !status.is_success() {
            // A JSON-RPC error envelope on a 4xx is still an RPC answer (monerod
            // would have said the same thing with a 200) — let monero-oxide read it.
            // Never buffer more than ENVELOPE_MAX of an error body: a hostile node
            // must not get to fill memory with a "404 page".
            if let Some(bytes) = read_capped(resp, ENVELOPE_MAX).await {
                if is_json_rpc_envelope(&bytes) {
                    return Ok(bytes);
                }
            }
            return Err(InterfaceError::InterfaceError(format!(
                "{shown} returned HTTP {status}"
            )));
        }
        // Enforce monero-oxide's size limit up-front via Content-Length when present.
        if let (Some(limit), Some(cl)) = (response_size_limit, resp.content_length()) {
            if (cl as usize) > limit {
                return Err(InterfaceError::InterfaceError(format!(
                    "{shown} response {cl} exceeds limit {limit}"
                )));
            }
        }
        let bytes = resp.bytes().await.map_err(|e| {
            InterfaceError::InterfaceError(format!("read body {shown} failed: {e}"))
        })?;
        Ok(bytes.to_vec())
    }
}

/// Small bodies only: an envelope is a few hundred bytes; anything larger on a
/// non-2xx is an HTML error page or a proxy banner, not an RPC answer.
const ENVELOPE_MAX: usize = 64 * 1024;

/// Read up to `cap` bytes of a response body; `None` once the body proves
/// larger than that (or a read fails). Streams, so nothing beyond `cap` is held.
async fn read_capped(resp: reqwest::Response, cap: usize) -> Option<Vec<u8>> {
    use futures::StreamExt;
    let mut out = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.ok()?;
        if out.len() + chunk.len() > cap {
            return None;
        }
        out.extend_from_slice(&chunk);
    }
    Some(out)
}

fn is_json_rpc_envelope(body: &[u8]) -> bool {
    if body.len() > ENVELOPE_MAX {
        return false;
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(o)) => o.contains_key("jsonrpc") && o.contains_key("error"),
        _ => false,
    }
}

/// `scheme://host[:port]` of a daemon URL — the path is dropped because
/// authenticating proxies carry the token there. Scheme-less input (a bare
/// `host:port` from Settings) keeps its authority the same way.
pub fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (Some(s), r),
        None => (None, url),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo too (`user:pass@host`).
    let host = authority.rsplit('@').next().unwrap_or(authority);
    if host.is_empty() {
        return "<node>".to_string();
    }
    match scheme {
        Some(scheme) => format!("{scheme}://{host}"),
        None => host.to_string(),
    }
}

impl HttpTransport for ReqwestTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, InterfaceError>> + Send {
        let url = format!("{}/{}", self.base, route);
        let shown = format!("{}/{}", self.base_display, route);
        let client = self.client.clone();
        let is_distribution = route == OUTPUT_DISTRIBUTION_ROUTE;
        let cache = self.dist_cache.clone();
        async move {
            if is_distribution {
                // Hold the lock across the fetch → single-flight: concurrent decoy
                // fetches for the same tx share one download instead of N.
                let mut guard = cache.lock().await;
                if let Some((k, v)) = guard.as_ref() {
                    if *k == body {
                        return Ok(v.clone());
                    }
                }
                let bytes =
                    Self::do_post(&client, &url, &shown, body.clone(), response_size_limit).await?;
                *guard = Some((body, bytes.clone()));
                return Ok(bytes);
            }
            Self::do_post(&client, &url, &shown, body, response_size_limit).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_drops_path_userinfo_and_query() {
        assert_eq!(
            redact_url("https://rpc.mnr.network/v1/sub_secrettoken/json_rpc"),
            "https://rpc.mnr.network"
        );
        assert_eq!(
            redact_url("http://node.example:18081"),
            "http://node.example:18081"
        );
        assert_eq!(
            redact_url("http://node.example:18081/"),
            "http://node.example:18081"
        );
        assert_eq!(redact_url("https://u:p@host:443/x?t=1"), "https://host:443");
        assert_eq!(
            redact_url("node.example:18081/v1/tok"),
            "node.example:18081"
        );
        assert_eq!(
            redact_url("http://[::1]:18081/v1/tok"),
            "http://[::1]:18081"
        );
        assert_eq!(redact_url("http:///v1/tok"), "<node>");
        assert_eq!(redact_url(""), "<node>");
    }

    /// Every place that formats a node URL into a log/error string must go
    /// through `redact_url`: with a token-in-path proxy the raw URL IS the
    /// secret. Scans the non-test halves of the node-touching modules: each
    /// `format!`/`log::`/`println!` call is collected until its parentheses
    /// balance (rustfmt splits them over lines), then checked for a bare
    /// `url` / `daemon_url` / `node_url` argument. A hit means "wrap it in
    /// redact_url", not "loosen the test".
    #[test]
    fn node_urls_are_never_formatted_raw() {
        let sources = [
            ("wallet/scanner.rs", include_str!("scanner.rs")),
            ("commands/wallet.rs", include_str!("../commands/wallet.rs")),
            ("tor/transport.rs", include_str!("../tor/transport.rs")),
            (
                "wallet/reqwest_transport.rs",
                include_str!("reqwest_transport.rs"),
            ),
        ];
        let sinks = ["format!(", "log::", "println!(", "eprintln!("];
        let names = ["url", "daemon_url", "node_url"];
        let mut hits = Vec::new();
        for (name, src) in sources {
            let body = src.split("#[cfg(test)]").next().unwrap_or("");
            let lines: Vec<&str> = body.lines().collect();
            let mut i = 0;
            while i < lines.len() {
                let line = lines[i];
                // `let url = format!(..)` builds a URL; it is not a sink.
                let builds_url = line.contains("let url = format!(");
                if line.trim_start().starts_with("//")
                    || builds_url
                    || !sinks.iter().any(|s| line.contains(s))
                {
                    i += 1;
                    continue;
                }
                // Collect the call until its parentheses balance.
                let first = i;
                let mut depth: i32 = 0;
                let mut snippet = String::new();
                loop {
                    let l = lines[i];
                    snippet.push_str(l);
                    snippet.push('\n');
                    depth += l.matches('(').count() as i32 - l.matches(')').count() as i32;
                    i += 1;
                    if depth <= 0 || i >= lines.len() || i - first > 12 {
                        break;
                    }
                }
                if snippet.contains("redact_url") {
                    continue;
                }
                let raw = snippet
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|tok| names.contains(&tok));
                if raw {
                    hits.push(format!("{name}:{}: {}", first + 1, lines[first].trim()));
                }
            }
        }
        assert!(
            hits.is_empty(),
            "raw node URL reaches a log/error string:\n{}",
            hits.join("\n")
        );
    }

    #[test]
    fn envelope_detection() {
        assert!(is_json_rpc_envelope(
            br#"{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}"#
        ));
        assert!(!is_json_rpc_envelope(
            br#"{"jsonrpc":"2.0","id":0,"result":"ok"}"#
        ));
        assert!(!is_json_rpc_envelope(br#"{"status":"Failed"}"#));
        assert!(!is_json_rpc_envelope(b"<html>403 Forbidden</html>"));
        assert!(!is_json_rpc_envelope(b"error code: 1010\n"));
        let big = vec![b' '; ENVELOPE_MAX + 1];
        assert!(!is_json_rpc_envelope(&big));
    }
}
