//! HTTP-over-Tor transport for the Monero daemon RPC.
//!
//! monero-oxide talks to a daemon through the `HttpTransport` trait. The stock
//! `SimpleRequestTransport` opens clearnet TCP connections with no proxy hook,
//! so it leaks the user's IP to every node. `ArtiTransport` implements the same
//! trait but tunnels each request through an arti `DataStream` (pure-Rust Tor),
//! driving HTTP/1.1 with `hyper` over that stream.
//!
//! Why hyper rather than a hand-rolled parser: monero-oxide reads responses via
//! hyper today (through `simple-request`), so `monerod` is free to reply with
//! chunked transfer-encoding (notably the large `.bin` endpoints). hyper decodes
//! both Content-Length and chunked transparently, so reusing it here is correct
//! by construction. `http_body_util::Limited` enforces the response size limit
//! the trait passes in.
//!
//! Connections are NOT reused: we open a fresh stream per request and drop it
//! once the body is fully read. This sidesteps the trait's "read the full
//! response before reusing the connection" hazard entirely. arti manages circuit
//! reuse internally, so the per-request cost is a stream open, not a circuit build.

use std::future::Future;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_socks::tcp::Socks5Stream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

/// Hard ceiling on a single Tor request — circuits can be slow, but we must not
/// hang a background fetch forever. Applies to connect + TLS + HTTP round-trip.
/// 60s (not 30s) because decoy selection downloads the full ~20MB RingCT output
/// distribution, which over Tor's limited bandwidth can take well past 30s.
const TOR_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

use monero_daemon_rpc::prelude::InterfaceError;
use monero_daemon_rpc::{HttpTransport, MoneroDaemon};

/// An `HttpTransport` that tunnels every request through Tor via arti.
#[derive(Clone)]
pub struct ArtiTransport {
    /// Shared, Arc-backed Tor client. Cloning is cheap; all transports in the
    /// scanner's multi-node pool share one `TorClient` and arti reuses circuits.
    tor: TorClient<PreferredRuntime>,
    host: String,
    port: u16,
}

impl ArtiTransport {
    /// Build a daemon backed by Tor for the given node URL.
    ///
    /// `url` may be `http://host:port`, `host:port`, or a bare `host` (port
    /// defaults to 18081, monerod's standard RPC port). `.onion` hosts are
    /// dialed natively by arti — no exit node is used.
    pub async fn connect(
        tor: TorClient<PreferredRuntime>,
        url: String,
    ) -> Result<MoneroDaemon<ArtiTransport>, InterfaceError> {
        let (host, port) = parse_host_port(&url)?;
        let transport = ArtiTransport { tor, host, port };
        // MoneroDaemon::new validates the connection (calls get_info).
        MoneroDaemon::new(transport).await
    }
}

impl HttpTransport for ArtiTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
        let tor = self.tor.clone();
        let host = self.host.clone();
        let port = self.port;
        // monero-oxide passes the route without a leading slash (e.g. "json_rpc",
        // "get_info", "get_blocks.bin"); normalize to an origin-form request target.
        let path = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{route}")
        };
        async move {
            // Fresh-circuit retry. A large response (get_output_distribution.bin,
            // ~20MB) frequently drops mid-stream over a single Tor circuit
            // ("error reading a body from connection"). Each tor_http call opens a
            // NEW arti stream, so retrying gives the transfer another circuit — which
            // is what lets the currently-syncing node actually complete the download
            // instead of the failover abandoning it after one try.
            const TOR_POST_ATTEMPTS: u32 = 3;
            let mut last_err = String::new();
            for attempt in 1 ..= TOR_POST_ATTEMPTS {
                match tor_http(&tor, Method::POST, &host, port, &path, body.clone(), response_size_limit).await {
                    Ok(bytes) => return Ok(bytes),
                    Err(e) => {
                        last_err = e;
                        if attempt < TOR_POST_ATTEMPTS {
                            log::warn!("Tor POST {path} to {host}:{port} attempt {attempt}/{TOR_POST_ATTEMPTS} failed ({last_err}); retrying on a fresh circuit");
                            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                        }
                    }
                }
            }
            Err(InterfaceError::InterfaceError(format!("{last_err} (after {TOR_POST_ATTEMPTS} Tor attempts)")))
        }
    }
}

/// An `HttpTransport` that tunnels daemon RPC through an EXTERNAL SOCKS5 proxy
/// (custom/Whonix mode). Unlike `ArtiTransport`, Tor runs outside the app; we
/// just dial node host:port through the user's proxy. `.onion` targets are
/// resolved REMOTELY by the proxy (SOCKS5h), so no exit/local DNS is involved.
#[derive(Clone)]
pub struct SocksTransport {
    proxy: String,
    host: String,
    port: u16,
}

impl SocksTransport {
    /// Build a daemon backed by an external SOCKS5 proxy. `proxy` is "host:port"
    /// (e.g. Whonix's 10.152.152.10:9050 or a local 127.0.0.1:9050).
    pub async fn connect(
        proxy: String,
        url: String,
    ) -> Result<MoneroDaemon<SocksTransport>, InterfaceError> {
        if proxy.trim().is_empty() {
            return Err(InterfaceError::InterfaceError(
                "custom routing selected but no proxy address is set".to_owned(),
            ));
        }
        let (host, port) = parse_host_port(&url)?;
        MoneroDaemon::new(SocksTransport { proxy, host, port }).await
    }
}

impl HttpTransport for SocksTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u8>, InterfaceError>> {
        let proxy = self.proxy.clone();
        let host = self.host.clone();
        let port = self.port;
        let path = if route.starts_with('/') {
            route.to_string()
        } else {
            format!("/{route}")
        };
        async move {
            socks_http(&proxy, Method::POST, &host, port, &path, body, response_size_limit)
                .await
                .map_err(InterfaceError::InterfaceError)
        }
    }
}

/// Issue a single HTTP/1.1 request to host:port through a SOCKS5 proxy. Daemon
/// nodes in custom mode are `.onion` over plain HTTP (no TLS), mirroring
/// `tor_http`. Remote DNS (SOCKS5h) resolves the onion at the proxy's Tor.
async fn socks_http(
    proxy: &str,
    method: Method,
    host: &str,
    port: u16,
    path: &str,
    body: Vec<u8>,
    size_limit: Option<usize>,
) -> Result<Vec<u8>, String> {
    let content_length = body.len();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::CONTENT_LENGTH, content_length)
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("Failed to build request: {e}"))?;

    let exchange = async {
        let stream = Socks5Stream::connect(proxy, (host, port))
            .await
            .map_err(|e| format!("SOCKS connect to {host}:{port} via {proxy} failed: {e}"))?;
        http_over_stream(stream, request, size_limit).await
    };

    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("SOCKS request to {host}:{port} timed out"))?
}

/// Issue a single HTTP/1.1 request over a fresh Tor stream and return the body.
///
/// Used by both `ArtiTransport::post` (daemon RPC) and the reqwest-replacement
/// GETs (Phase 2). Opens `tor.connect((host, port))`, wraps the `DataStream` in
/// `hyper_util::TokioIo`, performs an HTTP/1.1 handshake, sends the request, and
/// collects the full body (respecting `size_limit` via `Limited`).
pub async fn tor_http(
    tor: &TorClient<PreferredRuntime>,
    method: Method,
    host: &str,
    port: u16,
    path: &str,
    body: Vec<u8>,
    size_limit: Option<usize>,
) -> Result<Vec<u8>, String> {
    let content_length = body.len();
    let request = Request::builder()
        .method(method)
        .uri(path)
        .header(hyper::header::HOST, host)
        .header(hyper::header::CONTENT_LENGTH, content_length)
        .body(Full::new(Bytes::from(body)))
        .map_err(|e| format!("Failed to build request: {e}"))?;

    let exchange = async {
        // Open a stream through Tor. arti dials .onion natively; for clearnet
        // hosts it exits through the Tor network (still no IP leak to the node).
        let stream = tor
            .connect((host, port))
            .await
            .map_err(|e| format!("Tor connect to {host}:{port} failed: {e}"))?;
        http_over_stream(stream, request, size_limit).await
    };

    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("Tor request to {host}:{port} timed out"))?
}

/// GET a URL over Tor, with TLS when the scheme is `https`. Returns the response
/// body. Used by Phase 2 to route the nodes.json and price-history fetches off
/// clearnet. Note: some CDNs/APIs block Tor exit nodes — callers MUST treat a
/// failure as "degrade gracefully" (cached nodes, live-tick chart), never fatal.
pub async fn tor_get(tor: &TorClient<PreferredRuntime>, url: &str) -> Result<Vec<u8>, String> {
    tor_get_with_headers(tor, url, &[]).await
}

/// `tor_get` with a hard response-size cap enforced DURING body collection (via
/// `http_body_util::Limited`), so an oversized/hostile response is aborted mid-stream
/// rather than fully buffered then rejected. Used by the OTA updater (manifest/archive).
pub async fn tor_get_capped(
    tor: &TorClient<PreferredRuntime>,
    url: &str,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let (https, host, port, path) = parse_url(url)?;
    let exchange = async {
        let stream = tor
            .connect((host.as_str(), port))
            .await
            .map_err(|e| format!("Tor connect to {host}:{port} failed: {e}"))?;
        http_get_over(stream, https, &host, &path, &[], Some(limit)).await
    };
    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("Tor GET to {host} timed out"))?
}

/// `socks_get` with the same during-collection size cap as `tor_get_capped`.
pub async fn socks_get_capped(proxy: &str, url: &str, limit: usize) -> Result<Vec<u8>, String> {
    let (https, host, port, path) = parse_url(url)?;
    let exchange = async {
        let stream = Socks5Stream::connect(proxy, (host.as_str(), port))
            .await
            .map_err(|e| format!("SOCKS connect to {host}:{port} via {proxy} failed: {e}"))?;
        http_get_over(stream, https, &host, &path, &[], Some(limit)).await
    };
    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("SOCKS GET to {host} timed out"))?
}

/// Like `tor_get` but attaches caller-supplied request headers (e.g. a DoH
/// `Accept: application/dns-message`). Same graceful-degradation contract.
pub async fn tor_get_with_headers(tor: &TorClient<PreferredRuntime>, url: &str, extra_headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let (https, host, port, path) = parse_url(url)?;
    let exchange = async {
        let stream = tor
            .connect((host.as_str(), port))
            .await
            .map_err(|e| format!("Tor connect to {host}:{port} failed: {e}"))?;
        http_get_over(stream, https, &host, &path, extra_headers, None).await
    };
    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("Tor GET to {host} timed out"))?
}

/// GET a URL through an external SOCKS5 proxy (custom/Whonix mode). `.onion`
/// targets are passed to the proxy for REMOTE resolution (SOCKS5h). Same
/// graceful-degradation contract as `tor_get`.
pub async fn socks_get(proxy: &str, url: &str) -> Result<Vec<u8>, String> {
    socks_get_with_headers(proxy, url, &[]).await
}

/// Like `socks_get` but attaches caller-supplied request headers (DoH `Accept`).
pub async fn socks_get_with_headers(proxy: &str, url: &str, extra_headers: &[(&str, &str)]) -> Result<Vec<u8>, String> {
    let (https, host, port, path) = parse_url(url)?;
    let exchange = async {
        let stream = Socks5Stream::connect(proxy, (host.as_str(), port))
            .await
            .map_err(|e| format!("SOCKS connect to {host}:{port} via {proxy} failed: {e}"))?;
        http_get_over(stream, https, &host, &path, extra_headers, None).await
    };
    tokio::time::timeout(TOR_REQUEST_TIMEOUT, exchange)
        .await
        .map_err(|_| format!("SOCKS GET to {host} timed out"))?
}

/// Issue a GET over an already-connected byte stream, wrapping in TLS first when
/// the scheme is https. Shared by `tor_get` (arti DataStream) and `socks_get`
/// (SOCKS5 stream) — only the stream source differs.
async fn http_get_over<S>(stream: S, https: bool, host: &str, path: &str, extra_headers: &[(&str, &str)], limit: Option<usize>) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(hyper::header::HOST, host)
        // GitHub's API 403s without a User-Agent; harmless for other GETs.
        .header(hyper::header::USER_AGENT, concat!("ripley-terminal/", env!("CARGO_PKG_VERSION")))
        // No connection reuse — ask the server to close after the response.
        .header(hyper::header::CONNECTION, "close");
    // Caller-supplied headers (e.g. `Accept: application/dns-message` for DoH).
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let request = builder
        .body(Full::new(Bytes::new()))
        .map_err(|e| format!("Failed to build request: {e}"))?;

    if https {
        // SNI / cert validation uses the URL host. Invalid names (IPs,
        // malformed) error out → the caller falls back gracefully.
        let server_name = ServerName::try_from(host.to_string())
            .map_err(|_| format!("invalid TLS server name: {host}"))?;
        let tls_stream = tls_connector()
            .connect(server_name, stream)
            .await
            .map_err(|e| format!("TLS handshake with {host} failed: {e}"))?;
        http_over_stream(tls_stream, request, limit).await
    } else {
        http_over_stream(stream, request, limit).await
    }
}

/// Drive a single HTTP/1.1 request over any byte stream (plain Tor `DataStream`
/// or a `TlsStream` over one) and return the collected body. The transport-layer
/// stream is the only thing that differs between http/https and clearnet/Tor, so
/// the hyper handshake + request + body collection live here once.
async fn http_over_stream<S>(
    stream: S,
    request: Request<Full<Bytes>>,
    size_limit: Option<usize>,
) -> Result<Vec<u8>, String>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| format!("HTTP handshake failed: {e}"))?;

    // The connection future must be driven concurrently while we await the
    // response. Spawn it; abort once the body is fully read.
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let response = sender
        .send_request(request)
        .await
        .map_err(|e| format!("Request failed: {e}"))?;

    // monerod returns 200 for RPC (errors ride in the body); for plain GETs a
    // non-2xx (e.g. a CDN 4xx/redirect) means the body is not what we asked for.
    let status = response.status();
    if !status.is_success() {
        conn_task.abort();
        return Err(format!("HTTP {status}"));
    }

    let incoming = response.into_body();
    let result = match size_limit {
        Some(limit) => Limited::new(incoming, limit)
            .collect()
            .await
            .map_err(|e| format!("Response body error (limit {limit}): {e}")),
        None => incoming
            .collect()
            .await
            .map_err(|e| format!("Response body error: {e}")),
    };

    // Always tear down the connection driver, including on the body-error path
    // (an early `?` would otherwise leak the spawned task until the stream dies).
    conn_task.abort();
    Ok(result?.to_bytes().to_vec())
}

/// Process-wide rustls connector, built once from the OS trust store. ring is the
/// crypto provider (enabled by tokio-rustls' default features); we pass it
/// explicitly rather than relying on a globally-installed default provider.
fn tls_connector() -> TlsConnector {
    static CONNECTOR: OnceLock<TlsConnector> = OnceLock::new();
    CONNECTOR
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = roots.add(cert);
            }
            if roots.is_empty() {
                log::warn!("rustls: no native root certificates loaded; HTTPS-over-Tor will fail");
            }
            let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
            let config = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .expect("rustls default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
            TlsConnector::from(Arc::new(config))
        })
        .clone()
}

/// Parse an http(s) URL into (is_https, host, port, path-with-query). Defaults
/// port to 443 (https) / 80 (http). Path defaults to "/".
pub fn parse_url(url: &str) -> Result<(bool, String, u16, String), String> {
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(format!("unsupported URL scheme: {url}"));
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        return Err(format!("invalid URL (no host): {url}"));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| format!("invalid port in URL: {url}"))?;
            (h.to_string(), port)
        }
        None => (authority.to_string(), if https { 443 } else { 80 }),
    };
    Ok((https, host, port, path.to_string()))
}

/// Parse a node URL into (host, port). Accepts `scheme://host:port`, `host:port`,
/// or bare `host`. Defaults to monerod's standard RPC port 18081.
fn parse_host_port(url: &str) -> Result<(String, u16), InterfaceError> {
    let without_scheme = url.split("://").last().unwrap_or(url);
    // Strip any trailing path.
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    if authority.is_empty() {
        return Err(InterfaceError::InterfaceError(format!("invalid node URL: {url}")));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port: u16 = port
                .parse()
                .map_err(|_| InterfaceError::InterfaceError(format!("invalid port in URL: {url}")))?;
            Ok((host.to_string(), port))
        }
        None => Ok((authority.to_string(), 18081)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_port() {
        assert_eq!(parse_host_port("http://node.example:18089").unwrap(), ("node.example".into(), 18089));
        assert_eq!(parse_host_port("node.example:18081").unwrap(), ("node.example".into(), 18081));
        assert_eq!(parse_host_port("xmrtoaddr.onion").unwrap(), ("xmrtoaddr.onion".into(), 18081));
        assert_eq!(parse_host_port("https://abc.onion:443/foo").unwrap(), ("abc.onion".into(), 443));
        assert!(parse_host_port("http://").is_err());
    }

    #[test]
    fn parses_urls() {
        assert_eq!(
            parse_url("https://raw.githubusercontent.com/a/b/nodes.json").unwrap(),
            (true, "raw.githubusercontent.com".into(), 443, "/a/b/nodes.json".into())
        );
        assert_eq!(
            parse_url("https://api.kraken.com/0/public/OHLC?pair=XMRUSD&interval=1").unwrap(),
            (true, "api.kraken.com".into(), 443, "/0/public/OHLC?pair=XMRUSD&interval=1".into())
        );
        assert_eq!(
            parse_url("http://example.com").unwrap(),
            (false, "example.com".into(), 80, "/".into())
        );
        assert_eq!(
            parse_url("https://host.tld:8443/x").unwrap(),
            (true, "host.tld".into(), 8443, "/x".into())
        );
        assert!(parse_url("ftp://x").is_err());
        assert!(parse_url("https://").is_err());
    }

    /// Live smoke test against a known monero .onion node. Ignored by default
    /// (needs network + a bootstrapped Tor); run explicitly:
    ///   cargo test -p ripley-terminal arti_onion_get_info -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn arti_onion_get_info() {
        use arti_client::{TorClient, TorClientConfig};
        use monero_daemon_rpc::prelude::ProvidesBlockchainMeta;
        let tor = TorClient::create_bootstrapped(TorClientConfig::default())
            .await
            .expect("tor bootstrap");
        // Real mainnet.tor nodes from resources/nodes.json. Individual hidden
        // services go up and down, so try several and pass if ANY one answers —
        // this validates the full stack (onion dial → HTTP → parse), not a
        // specific node's uptime.
        let nodes = [
            "cakexmrl7bonq7ovjka5kuwuyd3f7qnkz6z6s6dmsy3uckwra7bvggyd.onion:18081",
            "sfprpc2fws6ltnq4hyr7lvpul3nank5layd7q7tyc5h4gy4h77gtabad.onion:18089",
            "plowsof3t5hogddwabaeiyrno25efmzfxyro2vligremt7sxpsclfaid.onion:18089",
            "xqnnz2xmlmtpy2p4cm4cphg2elkwu5oob7b7so5v4wwgt44p6vbx5ryd.onion:18089",
            "zu3oyzi45x3ul24sncs4245nlpz76jzizm36tvrkfvq2r33azzjv5syd.onion:18089",
        ];
        let mut last_err = String::new();
        for url in nodes {
            match ArtiTransport::connect(tor.clone(), url.to_string()).await {
                Ok(daemon) => match daemon.latest_block_number().await {
                    Ok(height) => {
                        println!("✅ {url} height = {height}");
                        assert!(height > 3_000_000);
                        return;
                    }
                    Err(e) => last_err = format!("{url}: height err {e:?}"),
                },
                Err(e) => last_err = format!("{url}: connect err {e:?}"),
            }
            println!("…{url} unreachable, trying next");
        }
        panic!("no onion node reachable; last error: {last_err}");
    }
}
