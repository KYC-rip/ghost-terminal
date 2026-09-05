//! Background blockchain scanner.
//!
//! Connects to a Monero daemon, fetches blocks in batches, and scans each block
//! for outputs belonging to the wallet's ViewPair using monero-wallet's Scanner.

use std::collections::HashMap;
use std::future::Future;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::time::sleep;

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use monero_address::SubaddressIndex;
use monero_daemon_rpc::prelude::*;
use monero_daemon_rpc::{HttpTransport, MoneroDaemon};
use monero_simple_request_rpc::SimpleRequestTransport;
use monero_wallet::{Scanner, ViewPair};

use super::state::WalletState;
use super::{storage, types::SyncStatus};
use crate::emit_log;
use crate::tor::{ArtiTransport, SocksTransport, TorState};

const GITHUB_NODES_URL: &str =
    "https://raw.githubusercontent.com/KYC-rip/ripley-terminal/main/resources/nodes.json";

/// Read the configured routing mode ("tor" | "clearnet") from config.json.
/// Defaults to "clearnet" when the file is absent or unparseable.
pub(crate) fn read_routing_mode(app: &AppHandle) -> String {
    read_config_str(app, "routingMode").unwrap_or_else(|| "clearnet".to_string())
}

pub(crate) fn known_routing_mode(mode: &str) -> bool {
    matches!(mode, "tor" | "clearnet" | "custom")
}

/// Read the external SOCKS proxy address (custom routing mode) from config.json,
/// Fold fullwidth ASCII variants (U+FF01..U+FF5E, e.g. `：` `．` fullwidth digits)
/// and the ideographic space back to their ASCII equivalents. A CJK IME commonly
/// emits a fullwidth colon `：` for `host：port`, which every downstream parser
/// (tokio-socks, reqwest, the webview proxy) rejects — and the webview one PANICS.
/// Normalizing at the single read point makes the whole app tolerate the typo.
pub(crate) fn fold_fullwidth(s: &str) -> String {
    s.chars()
        .map(|c| {
            let u = c as u32;
            if (0xFF01..=0xFF5E).contains(&u) {
                char::from_u32(u - 0xFEE0).unwrap_or(c)
            } else if u == 0x3000 {
                ' '
            } else {
                c
            }
        })
        .collect()
}

/// normalized to a bare `host:port` (tokio-socks wants no scheme prefix).
pub(crate) fn read_proxy_address(app: &AppHandle) -> String {
    let raw = read_config_str(app, "systemProxyAddress").unwrap_or_default();
    let folded = fold_fullwidth(&raw);
    let trimmed = folded.trim();
    for prefix in ["socks5h://", "socks5://", "socks://", "http://"] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return rest.trim_end_matches('/').to_string();
        }
    }
    trimmed.to_string()
}

/// Read a boolean field from config.json (default false).
pub(crate) fn read_config_bool(app: &AppHandle, key: &str) -> bool {
    let path = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("config.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok())
        .and_then(|v| v.get(key).and_then(|m| m.as_bool()))
        .unwrap_or(false)
}

/// Read a string field from config.json, if present.
fn read_config_str(app: &AppHandle, key: &str) -> Option<String> {
    let path = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("config.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|d| serde_json::from_str::<serde_json::Value>(&d).ok())
        .and_then(|v| v.get(key).and_then(|m| m.as_str()).map(String::from))
}

/// Parse nodes for a given network + section ("clearnet" | "tor") from nodes.json.
///
/// Clearnet addresses keep their scheme (bare `host:port` defaults to `http://`);
/// https nodes race alongside http ones — reqwest handles TLS. Tor `.onion`
/// addresses are stored verbatim as `host:port` — `ArtiTransport` parses them
/// and arti dials them natively (no exit node).
fn parse_nodes(parsed: &serde_json::Value, network: &str, section: &str) -> Vec<(String, String)> {
    let mut nodes = vec![];
    if let Some(sec) = parsed
        .get(network)
        .and_then(|m| m.get(section))
        .and_then(|c| c.as_object())
    {
        for (label, addresses) in sec {
            if let Some(addrs) = addresses.as_array() {
                for addr in addrs {
                    if let Some(addr_str) = addr.as_str() {
                        if section == "clearnet" {
                            // https nodes are kept: the clearnet transport is reqwest
                            // (native TLS) — the old "skip HTTPS" rule was for the
                            // retired simple-request transport and it silently dropped
                            // the only nodes that survive DPI-filtered networks (plain
                            // HTTP on 18081/18089 gets reset; TLS on 443 passes).
                            let url = if addr_str.starts_with("http://")
                                || addr_str.starts_with("https://")
                            {
                                addr_str.to_string()
                            } else {
                                format!("http://{}", addr_str)
                            };
                            nodes.push((label.clone(), url));
                        } else {
                            // Tor / .onion: verbatim host:port (ArtiTransport parses it)
                            nodes.push((label.clone(), addr_str.to_string()));
                        }
                    }
                }
            }
        }
    }
    nodes
}

/// A pluggable way to build a `MoneroDaemon` for a node URL. The clearnet variant
/// uses `SimpleRequestTransport`; the Tor variant uses `ArtiTransport` over arti.
/// This keeps the scan logic generic over one concrete transport per run, while
/// leaving the clearnet path (and its battle-tested behavior) entirely unchanged.
pub trait DaemonConnector: Clone + Send + Sync + 'static {
    type Transport: HttpTransport + Clone + Send + Sync + 'static;

    /// nodes.json section this connector reads ("clearnet" | "tor").
    fn section(&self) -> &'static str;

    fn connect(
        &self,
        url: String,
    ) -> impl Future<Output = Option<MoneroDaemon<Self::Transport>>> + Send;
}

#[derive(Clone)]
struct ClearnetConnector;

impl DaemonConnector for ClearnetConnector {
    // reqwest, not simple-request: the latter hangs reading large response bodies
    // (multi-block get_blocks.bin catch-ups, and get_output_distribution.bin during
    // sends). See wallet::reqwest_transport. 60s bounds even a large bulk batch.
    type Transport = crate::wallet::reqwest_transport::ReqwestTransport;
    fn section(&self) -> &'static str {
        "clearnet"
    }
    async fn connect(&self, url: String) -> Option<MoneroDaemon<Self::Transport>> {
        crate::wallet::reqwest_transport::ReqwestTransport::connect(
            url,
            std::time::Duration::from_secs(60),
        )
        .await
        .ok()
    }
}

#[derive(Clone)]
struct TorConnector {
    tor: TorClient<PreferredRuntime>,
}

impl DaemonConnector for TorConnector {
    type Transport = ArtiTransport;
    fn section(&self) -> &'static str {
        "tor"
    }
    async fn connect(&self, url: String) -> Option<MoneroDaemon<ArtiTransport>> {
        match ArtiTransport::connect(self.tor.clone(), url.clone()).await {
            Ok(daemon) => Some(daemon),
            Err(e) => {
                log::warn!(
                    "Tor connect to {} failed: {e:?}",
                    crate::wallet::reqwest_transport::redact_url(&url)
                );
                None
            }
        }
    }
}

/// Custom/Whonix mode: dial nodes through an EXTERNAL SOCKS5 proxy. Uses the
/// same .onion node section — the proxy's Tor resolves them remotely (SOCKS5h).
#[derive(Clone)]
struct CustomProxyConnector {
    proxy: String,
}

impl DaemonConnector for CustomProxyConnector {
    type Transport = SocksTransport;
    fn section(&self) -> &'static str {
        "tor"
    }
    async fn connect(&self, url: String) -> Option<MoneroDaemon<SocksTransport>> {
        match SocksTransport::connect(self.proxy.clone(), url.clone()).await {
            Ok(daemon) => Some(daemon),
            Err(e) => {
                log::warn!(
                    "SOCKS connect to {} via {} failed: {e:?}",
                    crate::wallet::reqwest_transport::redact_url(&url),
                    self.proxy
                );
                None
            }
        }
    }
}

// Force a specific node for testing (set to None for normal racing)
// Set to Some(("label", "url")) to force a specific node for testing
const FORCE_NODE: Option<(&str, &str)> = None;

/// Load nodes for the given section ("clearnet" | "tor"): try fresh GitHub fetch
/// → cached disk copy → bundled fallback.
pub(crate) async fn load_nodes(app: &AppHandle, section: &str) -> Vec<(String, String)> {
    if let Some((label, url)) = FORCE_NODE {
        return vec![(label.to_string(), url.to_string())];
    }
    // Manual override: if the user set a custom node address in Settings, use
    // ONLY that node (no racing). Works in any routing mode — the active
    // connector (clearnet/Tor/SOCKS) dials it. Clearnet needs an http:// scheme;
    // Tor/SOCKS connectors parse host:port and ignore the scheme.
    let custom = read_config_str(app, "customNodeAddress").unwrap_or_default();
    let custom = custom.trim();
    if !custom.is_empty() {
        let url = if custom.starts_with("http://") || custom.starts_with("https://") {
            custom.to_string()
        } else {
            format!("http://{}", custom)
        };
        // Path redacted: authenticating proxies (mnr.network) carry the token there.
        log::info!(
            "Using manual node override: {}",
            crate::wallet::reqwest_transport::redact_url(&url)
        );
        return vec![("custom".to_string(), url)];
    }
    load_pool_nodes(app, section).await
}

/// Load the public node pool (GitHub → cached → bundled), IGNORING any custom-node
/// override. Used by the connect-time fallback path: when a pinned node is
/// unreachable AND the user enabled `nodeFallback`, we race this pool instead.
pub(crate) async fn load_pool_nodes(app: &AppHandle, section: &str) -> Vec<(String, String)> {
    let cache_path = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join("latest_nodes.json");

    // 1. Try fetching fresh nodes from GitHub. In Tor mode this goes over Tor
    //    (tor_get); on any failure (e.g. exit-node blocked by GitHub) we fall
    //    through to the cached/bundled copy — never a hard failure.
    let mode = read_routing_mode(app);
    let fetched: Option<String> = if mode == "tor" {
        match app.state::<TorState>().get_client().await {
            Some(tor) => match crate::tor::tor_get(&tor, GITHUB_NODES_URL).await {
                Ok(bytes) => String::from_utf8(bytes).ok(),
                Err(e) => {
                    log::warn!("Tor nodes.json fetch failed ({e}); using cache/bundled");
                    None
                }
            },
            None => None,
        }
    } else if mode == "custom" {
        let proxy = read_proxy_address(app);
        if proxy.trim().is_empty() {
            None
        } else {
            match crate::tor::socks_get(&proxy, GITHUB_NODES_URL).await {
                Ok(bytes) => String::from_utf8(bytes).ok(),
                Err(e) => {
                    log::warn!("SOCKS nodes.json fetch failed ({e}); using cache/bundled");
                    None
                }
            }
        }
    } else {
        match reqwest::Client::new()
            .get(GITHUB_NODES_URL)
            .timeout(Duration::from_secs(8))
            .send()
            .await
        {
            Ok(response) => response.text().await.ok(),
            Err(_) => None,
        }
    };
    if let Some(text) = fetched {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
            let nodes = parse_nodes(&parsed, "mainnet", section);
            if !nodes.is_empty() {
                // Cache to disk
                let _ = std::fs::write(&cache_path, &text);
                log::info!("Fetched {} {} nodes, cached locally", nodes.len(), section);
                return nodes;
            }
        }
    }

    // 2. Try cached nodes from disk
    if let Ok(text) = std::fs::read_to_string(&cache_path) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&text) {
            let nodes = parse_nodes(&parsed, "mainnet", section);
            if !nodes.is_empty() {
                log::info!("Using {} cached {} nodes from disk", nodes.len(), section);
                return nodes;
            }
        }
    }

    // 3. Fall back to bundled nodes.json
    let bundled = include_str!("../../../resources/nodes.json");
    let parsed: serde_json::Value = serde_json::from_str(bundled).unwrap_or_default();
    let nodes = parse_nodes(&parsed, "mainnet", section);
    log::info!("Using {} bundled fallback {} nodes", nodes.len(), section);
    nodes
}

/// Race ALL nodes — first to connect wins. Generic over the connector so the
/// same racing logic serves both clearnet (SimpleRequestTransport) and Tor
/// (ArtiTransport).
async fn race_nodes<C: DaemonConnector>(
    app: &AppHandle,
    connector: &C,
) -> Option<(String, String, MoneroDaemon<C::Transport>)> {
    let nodes = load_nodes(app, connector.section()).await;
    // "Racing 1 nodes" reads oddly — a single node means a pinned custom node.
    if nodes.len() == 1 {
        emit_log(app, "Network", "info", "🔗 Connecting to pinned node…");
    } else {
        emit_log(
            app,
            "Network",
            "info",
            &format!("🏁 Racing {} nodes...", nodes.len()),
        );
    }
    race_list(connector, nodes).await
}

/// Race an explicit node list — first to connect wins (15s cap). Split out so the
/// custom-node fallback path can race the public pool without the custom override.
async fn race_list<C: DaemonConnector>(
    connector: &C,
    nodes: Vec<(String, String)>,
) -> Option<(String, String, MoneroDaemon<C::Transport>)> {
    use tokio::sync::mpsc;
    let (tx, mut rx) = mpsc::channel(1);

    for (label, url) in nodes {
        let tx = tx.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Some(daemon) = connector.connect(url.clone()).await {
                let _ = tx.send((label, url, daemon)).await;
            }
        });
    }
    drop(tx);

    tokio::select! {
        result = rx.recv() => result,
        _ = sleep(Duration::from_secs(15)) => None,
    }
}

/// Background blockchain scanner.
pub struct BlockScanner;

impl BlockScanner {
    /// Race all nodes for fastest connection, then start scanning.
    /// On scan failure, re-race and retry.
    pub async fn start(
        app: AppHandle,
        _daemon_url: &str,
        _node_label: &str,
        from_height: u64,
    ) -> Result<(), String> {
        // Bump generation — any previous scanner will see the mismatch and stop
        let wallet_state = app.state::<WalletState>();
        let generation = wallet_state.next_scanner_generation();

        let app_clone = app.clone();
        tokio::spawn(async move {
            // Routing mode decides the transport. In Tor mode we bootstrap arti
            // FIRST (so the very first node race already goes over Tor — no
            // clearnet leak), then drive the same scan logic with ArtiTransport.
            let mode = read_routing_mode(&app_clone);
            match mode.as_str() {
                "tor" => {
                    emit_log(&app_clone, "Network", "info", "🧅 Routing mode: Tor (arti, pure Rust)");
                    // Never fall back to clearnet (would leak the IP the user asked us
                    // to hide). ensure_tor now bounds + retries each bootstrap; if it
                    // still fails, wait and retry the WHOLE thing so a transient network
                    // issue self-recovers instead of sync sitting dead forever. Abort if
                    // a newer scan supersedes us (re-select / relock / relaunch).
                    let ws = app_clone.state::<WalletState>();
                    loop {
                        if ws.current_scanner_generation() != generation {
                            break;
                        }
                        match ensure_tor(&app_clone).await {
                            Some(tor) => {
                                run_outer(app_clone.clone(), generation, TorConnector { tor }).await;
                                break;
                            }
                            None => {
                                emit_log(&app_clone, "Network", "warn", "🧅 Tor unavailable — retrying bootstrap in 15s (check your network if this persists)…");
                                sleep(Duration::from_secs(15)).await;
                            }
                        }
                    }
                }
                "custom" => {
                    let proxy = read_proxy_address(&app_clone);
                    if proxy.trim().is_empty() {
                        // Refuse — starting clearnet would leak the IP. Surface
                        // the misconfiguration instead of silently downgrading.
                        emit_log(
                            &app_clone,
                            "Network",
                            "error",
                            "❌ Custom routing selected but no proxy address is set. Sync paused — set a SOCKS proxy in Settings.",
                        );
                    } else {
                        emit_log(&app_clone, "Network", "info", &format!("🧦 Routing mode: custom SOCKS proxy ({proxy})"));
                        run_outer(app_clone, generation, CustomProxyConnector { proxy }).await;
                    }
                }
                "clearnet" => {
                    run_outer(app_clone, generation, ClearnetConnector).await;
                }
                other => emit_log(
                    &app_clone,
                    "Network",
                    "error",
                    &format!("❌ Unknown routing mode {other:?}. Sync paused rather than falling back to clearnet."),
                ),
            }
        });

        Ok(())
    }
}

/// Ensure arti is bootstrapped and return the shared `TorClient`. Emits UI log
/// events so the first-run consensus download (~30-120s) is visible.
pub(crate) async fn ensure_tor(app: &AppHandle) -> Option<TorClient<PreferredRuntime>> {
    let tor_state = app.state::<TorState>();
    if let Some(client) = tor_state.get_client().await {
        return Some(client);
    }
    emit_log(
        app,
        "Tor",
        "info",
        "🧅 Bootstrapping Tor (downloading consensus — up to ~30-120s on first run)...",
    );
    match tor_state.connect(app).await {
        Ok(()) => {
            emit_log(
                app,
                "Tor",
                "success",
                "🧅 Tor connected — daemon RPC routes through Tor",
            );
            tor_state.get_client().await
        }
        Err(e) => {
            emit_log(
                app,
                "Tor",
                "error",
                &format!("❌ Tor bootstrap failed: {}. Sync paused — check your connection or switch to clearnet.", e),
            );
            None
        }
    }
}

/// The race → scan → re-race loop, generic over the transport connector.
async fn run_outer<C: DaemonConnector>(app_clone: AppHandle, generation: u64, connector: C) {
    loop {
        // Check if we've been superseded by a newer scanner
        let ws = app_clone.state::<WalletState>();
        if ws.current_scanner_generation() != generation {
            emit_log(
                &app_clone,
                "Sync",
                "info",
                "🛑 Scanner stopped (superseded by newer scan)",
            );
            return;
        }

        // Race all nodes
        let (label, url, daemon) = match race_nodes(&app_clone, &connector).await {
            Some(result) => result,
            None => {
                // A pinned custom node just failed to connect. If the user opted into
                // fallback, race the PUBLIC POOL (bypassing the pin) so a dead node
                // doesn't brick sync. Otherwise keep the pin (privacy: never silently
                // talk to a node the user didn't choose) and surface a clear reason.
                let custom = read_config_str(&app_clone, "customNodeAddress").unwrap_or_default();
                let custom = custom.trim().to_string();
                if !custom.is_empty() && read_config_bool(&app_clone, "nodeFallback") {
                    emit_log(
                        &app_clone,
                        "Network",
                        "warn",
                        "🔌 Pinned node unreachable — falling back to the public pool…",
                    );
                    let pool = load_pool_nodes(&app_clone, connector.section()).await;
                    match race_list(&connector, pool).await {
                        Some(result) => result,
                        None => {
                            emit_log(&app_clone, "Network", "error", "❌ Pinned node and public pool both unreachable. Retrying in 10s...");
                            sleep(Duration::from_secs(10)).await;
                            continue;
                        }
                    }
                } else if !custom.is_empty() {
                    emit_log(&app_clone, "Network", "error", &format!("❌ Pinned node {} unreachable — check the address or clear the pin in Settings ▸ Node. Retrying in 10s...", crate::wallet::reqwest_transport::redact_url(&custom)));
                    sleep(Duration::from_secs(10)).await;
                    continue;
                } else {
                    emit_log(
                        &app_clone,
                        "Network",
                        "error",
                        "❌ All nodes failed. Retrying in 10s...",
                    );
                    sleep(Duration::from_secs(10)).await;
                    continue;
                }
            }
        };

        emit_log(
            &app_clone,
            "Network",
            "success",
            &format!(
                "✅ Fastest node: {} ({})",
                label,
                crate::wallet::reqwest_transport::redact_url(&url)
            ),
        );

        // Store daemon URL so tx commands can connect
        let wallet_state = app_clone.state::<WalletState>();
        wallet_state.set_daemon_url(&url).await;

        // Read current scan height from state (may have been updated by rescan)
        let current_height = {
            let ws = app_clone.state::<WalletState>();
            ws.get_scan_height().await
        };

        // Run scan loop — if it fails, re-race
        match scan_loop(
            app_clone.clone(),
            daemon,
            current_height,
            url.clone(),
            label.clone(),
            generation,
            &connector,
        )
        .await
        {
            Ok(()) => break,
            Err(e) => {
                emit_log(
                    &app_clone,
                    "Sync",
                    "error",
                    &format!("⚠️ {} disconnected: {}. Re-racing...", label, e),
                );
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

// RingCT fork height — blocks before this have no RingCT outputs.
// monero-wallet only scans RingCT outputs, so scanning earlier blocks is pointless.
const RINGCT_FORK_HEIGHT: u64 = 1_220_516;

/// Validated per-block fetch of a contiguous range, pipelined round-robin across
/// the connection pool (buffered = pool size). This is the trustless default path
/// and the fast-sync fallback.
async fn parallel_per_block<T>(
    pool: &[MoneroDaemon<T>],
    range: RangeInclusive<usize>,
) -> Result<Vec<ScannableBlock>, InterfaceError>
where
    T: HttpTransport + Clone + Send + Sync + 'static,
{
    use futures::stream::StreamExt;
    let pool_n = pool.len().max(1);
    futures::stream::iter(range.enumerate())
        .map(|(i, n)| {
            let d = &pool[i % pool_n];
            async move { ProvidesScannableBlocks::scannable_block_by_number(d, n).await }
        })
        .buffered(pool_n)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect()
}

/// Fast-sync bulk fetch, parallelized. Splits `range` into consecutive sub-ranges
/// of up to `sub_size` blocks and fetches them CONCURRENTLY (`streams` in flight)
/// against the SAME trusted node, reassembled in order. Over Tor the bottleneck is
/// circuit latency, not bandwidth, so overlapping fetches multiplies throughput
/// while the scanner stays idle far less. `buffered` yields results in input
/// (height) order, so the concatenated stream is contiguous from `range.start()` —
/// the downstream scan loop (`block_height = scan_height + i`) is unchanged.
///
/// One trusted node × K circuits (rather than K different nodes): in fast-sync we
/// already trust this node, so a single node keeps the trust model identical and
/// avoids any cross-node tip/reorg mismatch in the reassembled stream. arti reuses
/// circuits internally, so concurrent calls on clones spread across Tor streams.
/// If ANY sub-range fails, the whole call errors → the caller's existing
/// shrink-and-retry / per-block fallback handles it.
async fn bulk_parallel<T>(
    daemon: &MoneroDaemon<T>,
    range: RangeInclusive<usize>,
    sub_size: usize,
    streams: usize,
) -> Result<Vec<ScannableBlock>, InterfaceError>
where
    T: HttpTransport + Clone + Send + Sync + 'static,
{
    use futures::stream::StreamExt;
    let (start, end) = (*range.start(), *range.end());
    let sub_size = sub_size.max(1);
    let mut subs: Vec<RangeInclusive<usize>> = Vec::new();
    let mut s = start;
    while s <= end {
        let e = (s + sub_size - 1).min(end);
        subs.push(s..=e);
        s = e + 1;
    }
    let chunks: Vec<Vec<ScannableBlock>> = futures::stream::iter(subs)
        .map(|sub| {
            let d = daemon.clone();
            async move { d.bulk_scannable_blocks_trusting_node(sub).await }
        })
        .buffered(streams.max(1))
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    Ok(chunks.into_iter().flatten().collect())
}

/// How long any single block-fetch attempt may run before the watchdog aborts it.
/// Healthy bulk/per-block batches finish in ~10–50s even over Tor; this only trips
/// on a genuinely stalled node/circuit.
const FETCH_DEADLINE: Duration = Duration::from_secs(75);

/// Watchdog wrapper: bound a fetch by FETCH_DEADLINE. Over Tor a dead circuit can
/// make a request hang with NO transport-level timeout — `buffered()` then waits on
/// the stuck future forever, the scan loop never returns, and the outer re-race
/// never fires (a true deadlock, not a slow sync). Converting the hang into an Err
/// lets the existing retry/shrink/re-race recover, so the app self-heals across
/// flaky networks instead of freezing. Returns `String` errors so the caller's
/// recovery is identical whether the cause was an RPC error or a stall.
async fn with_deadline<F>(fut: F) -> Result<Vec<ScannableBlock>, String>
where
    F: Future<Output = Result<Vec<ScannableBlock>, InterfaceError>>,
{
    match tokio::time::timeout(FETCH_DEADLINE, fut).await {
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => Err(format!("{:?}", e)),
        Err(_) => Err(format!(
            "watchdog: fetch exceeded {}s — node/circuit stalled, recovering",
            FETCH_DEADLINE.as_secs()
        )),
    }
}

/// Ask the daemon which key images are spent via the `is_key_image_spent` RPC.
/// Returns the spent_status array (0 = unspent, 1 = spent on-chain, 2 = spent in
/// pool), aligned with `kis_hex`. None on RPC/parse error. This is the
/// authoritative way to detect spends — it consults the daemon's global key-image
/// set, independent of which blocks we've scanned.
async fn query_spent_status<T>(daemon: &MoneroDaemon<T>, kis_hex: &[String]) -> Option<Vec<u64>>
where
    T: HttpTransport + Clone + Send + Sync + 'static,
{
    let body = serde_json::json!({ "key_images": kis_hex }).to_string();
    let resp = daemon
        .rpc_call("is_key_image_spent", Some(body), 4 * 1024 * 1024)
        .await
        .ok()?;
    let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
    let arr = v.get("spent_status")?.as_array()?;
    Some(arr.iter().map(|x| x.as_u64().unwrap_or(0)).collect())
}

/// Build the multi-node fallback pool: spread ONE connection across many distinct
/// nodes (each sees a single connection → no per-IP throttling). The primary daemon
/// is always first. Historical blocks are identical across nodes and every per-block
/// fetch is validated, so multi-node fetch is safe. In Tor mode all entries share
/// one TorClient (arti reuses circuits internally).
async fn build_fallback_pool<C: DaemonConnector>(
    app: &AppHandle,
    connector: &C,
    primary: &MoneroDaemon<C::Transport>,
    primary_url: &str,
    cap: usize,
) -> Vec<MoneroDaemon<C::Transport>> {
    use futures::stream::StreamExt;
    let mut pool = vec![primary.clone()];
    let others: Vec<(String, String)> = load_nodes(app, connector.section())
        .await
        .into_iter()
        .filter(|(_, u)| u != primary_url)
        .collect();
    let connected: Vec<Option<_>> = futures::stream::iter(others)
        .map(|(_, url)| {
            let connector = connector.clone();
            async move { connector.connect(url).await }
        })
        .buffer_unordered(cap)
        .collect()
        .await;
    for d in connected.into_iter().flatten() {
        pool.push(d);
        if pool.len() >= cap {
            break;
        }
    }
    pool
}

async fn scan_loop<C: DaemonConnector>(
    app: AppHandle,
    daemon: MoneroDaemon<C::Transport>,
    mut scan_height: u64,
    node_url: String,
    node_label: String,
    generation: u64,
    connector: &C,
) -> Result<(), String> {
    // Dynamic batch size based on gap — bigger gap = bigger batches for speed.
    // Monero daemon limits response to ~100MB, so we cap at 1000 blocks.
    let base_batch: u64 = 50;
    // Concurrent block fetches per batch (pipelined RPC round-trips). Tor
    // circuits add latency and arti builds them lazily, so fewer parallel
    // streams perform better over Tor; clearnet keeps wide parallelism.
    let fetch_concurrency: usize = if connector.section() == "tor" { 4 } else { 12 };

    // Opt-in "Fast sync" (Settings, default OFF): bulk-fetch each batch via
    // get_blocks.bin, trusting the node for tx content. Skips the prunable_hash
    // gate (monero #10120) that otherwise forces a slow per-block JSON fallback.
    // Output ownership is still proven cryptographically; the residual trust is
    // that the node doesn't hide/alter txs (recoverable by rescanning). On any
    // bulk error we fall back to the validated multi-node per-block path below.
    let fast_sync = read_config_bool(&app, "fast_sync");

    // One-time marker so it's obvious from the log whether THIS build includes
    // key-image spend detection (and whether it can run). If you don't see this
    // line, the running binary predates the feature — restart `tauri dev` so the
    // Rust side rebuilds (frontend HMR alone does NOT rebuild Rust).
    if app.state::<WalletState>().can_detect_spends().await {
        emit_log(&app, "Sync", "info", "🔑 Key-image spend detection: ON");
    } else {
        emit_log(
            &app,
            "Sync",
            "info",
            "🔑 Key-image spend detection: OFF (no spend key)",
        );
    }

    if scan_height == u64::MAX {
        emit_log(
            &app,
            "Sync",
            "info",
            "🔍 New wallet — will sync from daemon tip",
        );
    } else {
        emit_log(
            &app,
            "Sync",
            "info",
            &format!("🔍 Scan loop started from height {}", scan_height),
        );
    }
    // Restore baseline — the height this session's scan begins from (captured once,
    // after the sentinel/RingCT clamps below). Lets the UI show restore-range progress.
    // (Named restore_base, not scan_start, to avoid colliding with the per-batch timer.)
    let mut restore_base: Option<u64> = None;

    // The multi-node fallback pool. In NORMAL mode it's the primary fetch path, so
    // build it upfront (one connection spread across many nodes for parallelism).
    // In FAST mode a single node carries the whole sync via get_blocks.bin, so we
    // skip the upfront connections entirely and only build the pool lazily if a
    // bulk batch ever fails (see the fallback branch below).
    let mut pool = vec![daemon.clone()];
    if !fast_sync {
        pool = build_fallback_pool(&app, connector, &daemon, &node_url, fetch_concurrency).await;
    }
    let pool_n = pool.len();
    if fast_sync {
        emit_log(&app, "Sync", "info", &format!("⚡ Fast sync ON — bulk get_blocks.bin, trusting {} (fallback nodes spun up only if a batch fails)", node_label));
    } else {
        emit_log(
            &app,
            "Sync",
            "info",
            &format!("🔗 Fetching across {} nodes in parallel", pool_n),
        );
    }

    // Rolling measured throughput (blocks/sec), seeded then EMA-smoothed from real
    // batch timings so the ETA reflects actual speed. Fast sync is seeded high
    // (bulk path) so the first ETA isn't wildly pessimistic; both self-correct.
    let mut measured_bps: f64 = if fast_sync {
        80.0
    } else {
        (pool_n as f64) * 1.5
    };

    // Public nodes routinely drop the keep-alive connection after a big
    // get_blocks.bin response, so the next request fails with ConnectionReset.
    // That's almost always cured by an immediate reconnect — NOT a reason to
    // sleep 5s or abandon the node. We retry quickly a few times; only if the
    // node stays unresponsive do we return Err so run_outer re-races to a fresh
    // node (instead of looping forever on a dead one).
    const MAX_NODE_FAILURES: u32 = 3;
    let mut consecutive_failures = 0u32;

    // Adaptive bulk batch (fast sync). A bulk get_blocks.bin response for a dense
    // near-tip range can be too big to transfer within the request timeout, so on a
    // bulk failure we HALVE the batch and retry bulk (staying on the fast path) down
    // to a floor. Only if even a floor-sized bulk fails do we serve one validated
    // per-block batch and then re-race — never grinding the slow path forever on a
    // node that can't bulk. Successful batches grow it back toward the max.
    const MAX_BULK_BATCH: u64 = 1000;
    const MIN_BULK_BATCH: u64 = 100;
    let mut bulk_batch: u64 = MAX_BULK_BATCH;

    // Bulk fetches in flight per batch (fast sync). Over Tor the bottleneck is
    // circuit latency, not bandwidth, so we fetch BULK_STREAMS sub-ranges of
    // `bulk_batch` blocks concurrently against the trusted node and reassemble in
    // order — overlapping the round-trips the sequential path wasted. 4 matches the
    // Tor `fetch_concurrency` (wider hurts over Tor per arti's lazy circuit build).
    const BULK_STREAMS: usize = 4;

    // AIMD sizing to stop the batch from oscillating. A bulk timeout means K
    // concurrent responses of this size overwhelmed the circuit, so we remember the
    // largest size that WORKS (`bulk_ceiling`) and refuse to grow straight back into
    // the size that just failed — otherwise every success doubles into the failing
    // size, wasting ~half the fetches on doomed timeouts. We only probe ABOVE the
    // ceiling after a streak of clean fetches (region got sparser / circuit improved),
    // so the steady state settles at the sustainable size instead of bouncing.
    let mut bulk_ceiling: u64 = MAX_BULK_BATCH;
    let mut bulk_streak: u32 = 0;
    const GROW_PROBE_STREAK: u32 = 6;

    // One-shot spend-detection diagnostics (filter the console for "KIDIAG"):
    // `diag_inputs` fires on the first batch (confirms input key images are being
    // collected at all); `diag_sanity` fires once we have an owned output (checks
    // x·G == P, i.e. the spend key is correct).
    let mut diag_inputs_logged = false;
    let mut diag_sanity_logged = false;

    // Reconcile spends with the daemon once we reach the tip. The per-block
    // scan-based detection can miss spends; this asks the daemon directly (via
    // is_key_image_spent) which of our outputs are spent — authoritative, and it
    // works on an already-synced wallet without rescanning.
    let mut spend_reconciled = false;

    loop {
        // Check if superseded
        let ws = app.state::<WalletState>();
        if ws.current_scanner_generation() != generation {
            emit_log(&app, "Sync", "info", "🛑 Scan loop stopped (superseded)");
            return Ok(());
        }

        // Get daemon height
        let daemon_height = match daemon.latest_block_number().await {
            Ok(h) => h as u64,
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_NODE_FAILURES {
                    return Err(format!(
                        "{} unresponsive ({} consecutive failures): {:?}",
                        node_label, consecutive_failures, e
                    ));
                }
                emit_log(
                    &app,
                    "Sync",
                    "warn",
                    &format!(
                        "⚠️ Height check failed ({}/{}) — reconnecting…",
                        consecutive_failures, MAX_NODE_FAILURES
                    ),
                );
                sleep(Duration::from_millis(400)).await;
                continue;
            }
        };

        if scan_height == u64::MAX {
            // New wallet sentinel — start near the tip.
            emit_log(
                &app,
                "Sync",
                "info",
                &format!(
                    "📦 New wallet: starting near daemon tip ({})",
                    daemon_height
                ),
            );
            scan_height = daemon_height.saturating_sub(10);
        }
        // NOTE: being slightly AHEAD of the daemon (scan_height == daemon_height + 1,
        // the normal fully-synced state) must NOT reset to near-tip — that caused an
        // infinite re-scan loop of the last ~10 blocks. The SYNCED check below handles
        // scan_height >= daemon_height by idling.

        // Skip pre-RingCT blocks — monero-wallet can only scan RingCT outputs
        if scan_height < RINGCT_FORK_HEIGHT {
            emit_log(&app, "Sync", "info", &format!("⏩ Skipping to RingCT fork (block {}), pre-RingCT blocks have no scannable outputs", RINGCT_FORK_HEIGHT));
            scan_height = RINGCT_FORK_HEIGHT;
        }
        // Lock in the restore baseline on the first iteration (after the clamps).
        if restore_base.is_none() {
            restore_base = Some(scan_height);
        }
        let restore_base = restore_base.unwrap_or(scan_height);

        if scan_height >= daemon_height {
            // Active wallet caught up — let the background pool run again.
            app.state::<crate::wallet::SyncPool>()
                .set_active_busy(false);
            // Persist the tip here too. update_sync_status is otherwise only called in
            // the batch-scan path below, which runs solely when there are NEW blocks to
            // scan. A wallet that resumes already at/near the tip goes straight to this
            // branch every iteration and never sets sync_status.daemon_height — leaving
            // tip_height() at 0, so balances()/get_spendable_outputs() treat EVERY output
            // as immature: unlocked balance reads 0, no spendable inputs, sends fail.
            ws.update_sync_status(scan_height, daemon_height).await;
            // Reconcile spends with the daemon once we're at the tip (authoritative,
            // catches spends made in any wallet — including before this feature).
            if !spend_reconciled {
                spend_reconciled = true;
                let unspent = ws.unspent_key_images().await;
                if !unspent.is_empty() {
                    emit_log(
                        &app,
                        "Scan",
                        "info",
                        &format!(
                            "🔁 Reconciling spend status of {} outputs with the daemon…",
                            unspent.len()
                        ),
                    );
                    let kis: Vec<String> = unspent.iter().map(|(_, k)| k.clone()).collect();
                    match query_spent_status(&daemon, &kis).await {
                        Some(status) => {
                            let spent_ids: Vec<String> = unspent
                                .iter()
                                .zip(status.iter())
                                .filter(|(_, s)| **s != 0)
                                .map(|((id, _), _)| id.clone())
                                .collect();
                            let n = ws.mark_ids_spent(&spent_ids).await;
                            if n > 0 {
                                ws.save_output_cache().await;
                                let bal = WalletState::format_xmr(ws.compute_balance().await);
                                emit_log(&app, "Scan", "success", &format!("📤 Reconciled spends: {} output(s) marked spent. Balance: {} XMR", n, bal));
                            } else {
                                emit_log(&app, "Scan", "info", "✓ No spent outputs found — balance already accurate");
                            }
                        }
                        None => emit_log(&app, "Scan", "warn", "⚠️ Spend reconciliation RPC failed (is_key_image_spent) — balance may over-count"),
                    }
                }
                // Push the (now reconciled) balance to the UI — frontend polling
                // stops once synced, so without this the displayed balance stays at
                // the pre-reconcile over-count.
                let (total, unlocked) = ws.balances(daemon_height).await;
                crate::emit_balance(&app, total, unlocked);
            }
            crate::emit_sync_status(
                &app,
                "SYNCED",
                scan_height,
                daemon_height,
                100.0,
                &node_label,
                restore_base,
            );
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        // We have new blocks to scan — re-arm the daemon reconcile so it runs again
        // when we next catch up (to detect spends made since the last reconcile).
        spend_reconciled = false;

        // In fast-sync the whole batch comes back in ONE get_blocks.bin call, so
        // use a large batch. The validated per-block fallback gains nothing from
        // big batches, so keep those modest for smooth progress reporting.
        let gap = daemon_height - scan_height;

        // Pause the background "Sync all wallets" pool during a heavy catch-up so
        // it doesn't compete with the active wallet for the node + CPU. Resumes
        // automatically once the gap is small (and in the SYNCED branch above).
        app.state::<crate::wallet::SyncPool>()
            .set_active_busy(gap > 2_000);
        let batch_size: u64 = if fast_sync {
            // K sub-ranges of `bulk_batch`, fetched concurrently (see bulk_parallel).
            (bulk_batch * BULK_STREAMS as u64).min(gap)
        } else if gap > 1_000 {
            100
        } else {
            base_batch
        };

        // Show ETA for large syncs, based on MEASURED throughput (updated
        // after each batch) rather than a hardcoded guess.
        if gap > 10_000 {
            let eta_secs = (gap as f64 / measured_bps.max(0.1)) as u64;
            let eta_mins = eta_secs / 60;
            let eta_hours = eta_mins / 60;
            if eta_hours > 0 {
                emit_log(
                    &app,
                    "Sync",
                    "info",
                    &format!(
                        "⏱️ ETA: ~{}h {}m ({} blocks remaining at {:.1} blk/s)",
                        eta_hours,
                        eta_mins % 60,
                        gap,
                        measured_bps
                    ),
                );
            } else {
                emit_log(
                    &app,
                    "Sync",
                    "info",
                    &format!(
                        "⏱️ ETA: ~{}m ({} blocks remaining at {:.1} blk/s)",
                        eta_mins, gap, measured_bps
                    ),
                );
            }
        }

        let batch_end = (scan_height + batch_size).min(daemon_height);
        let range = (scan_height as usize)..=(batch_end as usize);

        emit_log(
            &app,
            "Sync",
            "info",
            &format!(
                "📥 Fetching blocks {}-{} / {}",
                scan_height, batch_end, daemon_height
            ),
        );

        let fetch_start = std::time::Instant::now();
        // When set, this batch was served by the slow per-block fallback because the
        // node couldn't bulk even at the minimum size — re-race afterward to find a
        // bulk-capable node instead of staying slow.
        let mut reraise_for_bulk = false;
        // Fast sync: one bulk get_blocks.bin call for the whole batch (trusting the
        // node). Normal mode uses the validated per-block path across the pool.
        let parallel_result = if fast_sync {
            match with_deadline(bulk_parallel(
                &daemon,
                range.clone(),
                bulk_batch as usize,
                BULK_STREAMS,
            ))
            .await
            {
                Ok(blocks) => {
                    // Grow the sub-range size after a clean fetch, but never straight
                    // back into a size that just timed out (see bulk_ceiling). Stay
                    // at/under the known-good ceiling; only probe above it after a
                    // streak of clean fetches earns it (then a timeout knocks it back).
                    bulk_streak = bulk_streak.saturating_add(1);
                    let want = (bulk_batch * 2).min(MAX_BULK_BATCH);
                    if want <= bulk_ceiling {
                        bulk_batch = want;
                    } else if bulk_streak >= GROW_PROBE_STREAK {
                        bulk_batch = want;
                        bulk_ceiling = want;
                        bulk_streak = 0;
                    }
                    Ok(blocks)
                }
                Err(e) if bulk_batch > MIN_BULK_BATCH => {
                    // K concurrent responses of this size overwhelmed the circuit/timeout.
                    // HALVE and retry bulk (stay on the fast path), and remember the
                    // halved size as the ceiling so we don't immediately grow back into
                    // the size that just failed.
                    bulk_batch = (bulk_batch / 2).max(MIN_BULK_BATCH);
                    bulk_ceiling = bulk_batch;
                    bulk_streak = 0;
                    emit_log(&app, "Sync", "warn", &format!("⚡ Bulk fetch failed ({:?}) — shrinking to {}-block batches and retrying bulk", e, bulk_batch));
                    continue;
                }
                Err(e) => {
                    // Even a floor-sized bulk failed: this node can't serve bulk. Serve
                    // THIS batch via the validated per-block path so we still progress,
                    // then re-race to hunt for a node that CAN bulk (resetting the batch
                    // size) — never grinding the slow path forever.
                    emit_log(&app, "Sync", "warn", &format!("⚡ Bulk unavailable on {} even at {} blocks ({:?}) — one validated per-block batch, then re-racing", node_label, MIN_BULK_BATCH, e));
                    if pool.len() == 1 {
                        pool = build_fallback_pool(
                            &app,
                            connector,
                            &daemon,
                            &node_url,
                            fetch_concurrency,
                        )
                        .await;
                        emit_log(
                            &app,
                            "Sync",
                            "info",
                            &format!("🔗 Fallback pool ready: {} nodes", pool.len()),
                        );
                    }
                    reraise_for_bulk = true;
                    bulk_batch = MAX_BULK_BATCH;
                    bulk_ceiling = MAX_BULK_BATCH;
                    bulk_streak = 0;
                    with_deadline(parallel_per_block(&pool, range.clone())).await
                }
            }
        } else {
            with_deadline(parallel_per_block(&pool, range.clone())).await
        };
        match parallel_result {
            Ok(blocks) => {
                let fetch_ms = fetch_start.elapsed().as_millis();
                // Update rolling throughput (EMA) from this batch's real timing
                if fetch_ms > 0 && !blocks.is_empty() {
                    let batch_bps = blocks.len() as f64 / (fetch_ms as f64 / 1000.0);
                    measured_bps = measured_bps * 0.6 + batch_bps * 0.4;
                }
                let blk_s = if fetch_ms > 0 {
                    blocks.len() as f64 / (fetch_ms as f64 / 1000.0)
                } else {
                    0.0
                };
                emit_log(
                    &app,
                    "Sync",
                    "info",
                    &format!(
                        "✅ Got {} blocks in {}ms ({:.0} blk/s)",
                        blocks.len(),
                        fetch_ms,
                        blk_s
                    ),
                );
                // A successful fetch means the node is healthy — reset the failure counter.
                consecutive_failures = 0;
                // Scan each block with the wallet's Scanner. This is CPU-bound and,
                // for recent (dense) blocks, can dominate wall-clock — far exceeding
                // the fetch time — so we time it separately to make the cost visible.
                let scan_start = std::time::Instant::now();
                let wallet_state = app.state::<WalletState>();
                if let Some(mut scanner) = wallet_state.get_scanner().await {
                    let mut new_output_count = 0u64;
                    let mut new_amount = 0u64;
                    // Map each spent input key image in this batch to (spending txid,
                    // height) — used to detect which owned outputs were spent (incl.
                    // spends made in other wallets) AND to record the outgoing tx.
                    // block.transactions[k] is the hash of the k-th parsed tx, which we
                    // use as the txid (we can't recompute pruned-tx hashes ourselves).
                    let mut ki_to_tx: HashMap<[u8; 32], ([u8; 32], u64)> = HashMap::new();

                    for (i, block) in blocks.iter().enumerate() {
                        // Blocks are fetched in range order starting at scan_height,
                        // so the i-th block is at height scan_height + i.
                        let block_height = scan_height + i as u64;
                        match scanner.scan(block.clone()) {
                            Ok(timelocked) => {
                                let outputs = timelocked.ignore_additional_timelock();
                                if !outputs.is_empty() {
                                    for output in &outputs {
                                        new_amount += output.commitment().amount;
                                    }
                                    new_output_count += outputs.len() as u64;
                                    // Real block header time (Unix s) — stable, unlike the
                                    // now−(tip−height)·120 estimate that drifts during sync.
                                    let block_ts = block.block.header.timestamp;
                                    wallet_state
                                        .add_outputs(outputs, block_height, block_ts, generation)
                                        .await;
                                }
                            }
                            Err(e) => {
                                emit_log(
                                    &app,
                                    "Scan",
                                    "error",
                                    &format!("⚠️ Scan error at ~{}: {:?}", scan_height, e),
                                );
                            }
                        }
                        // Collect key image -> spending tx for this block's (non-miner) txs.
                        for (tx_idx, tx) in block.transactions.iter().enumerate() {
                            let txid = block
                                .block
                                .transactions
                                .get(tx_idx)
                                .copied()
                                .unwrap_or([0u8; 32]);
                            for input in &tx.prefix().inputs {
                                if let monero_oxide::transaction::Input::ToKey {
                                    key_image, ..
                                } = input
                                {
                                    ki_to_tx.insert(key_image.to_bytes(), (txid, block_height));
                                }
                            }
                        }
                    }

                    let scan_ms = scan_start.elapsed().as_millis();
                    let scan_bps = if scan_ms > 0 {
                        blocks.len() as f64 / (scan_ms as f64 / 1000.0)
                    } else {
                        0.0
                    };
                    emit_log(
                        &app,
                        "Scan",
                        "info",
                        &format!(
                            "🔬 Scanned {} blocks in {}ms ({:.0} blk/s)",
                            blocks.len(),
                            scan_ms,
                            scan_bps
                        ),
                    );

                    // Diagnostics (filter console for KIDIAG).
                    if !diag_inputs_logged {
                        emit_log(&app, "Scan", "warn", &format!("🔧 KIDIAG-inputs first batch [{}-{}]: collected {} input key images, txs={}", scan_height, batch_end, ki_to_tx.len(), blocks.iter().map(|b| b.transactions.len()).sum::<usize>()));
                        diag_inputs_logged = true;
                    }
                    if !diag_sanity_logged {
                        if let Some(diag) = wallet_state.first_output_kidiag().await {
                            emit_log(&app, "Scan", "warn", &format!("🔧 KIDIAG-sanity {}", diag));
                            diag_sanity_logged = true;
                        }
                    }

                    // Detect spends + record outgoing ledger entries for the spending
                    // txs. Requires the spend key (active wallet only).
                    let newly_spent = wallet_state
                        .detect_and_record_spends(&ki_to_tx, daemon_height)
                        .await;
                    if newly_spent > 0 {
                        emit_log(
                            &app,
                            "Scan",
                            "info",
                            &format!(
                                "📤 Detected {} spent output(s) in blocks {}-{}",
                                newly_spent, scan_height, batch_end
                            ),
                        );
                        let (total, unlocked) = wallet_state.balances(daemon_height).await;
                        crate::emit_balance(&app, total, unlocked);
                    }

                    if new_output_count > 0 {
                        emit_log(
                            &app,
                            "Scan",
                            "success",
                            &format!(
                                "💰 Found {} outputs ({} piconero) in blocks {}-{}",
                                new_output_count, new_amount, scan_height, batch_end
                            ),
                        );
                        let total = wallet_state.compute_balance().await;
                        crate::emit_sync_status(
                            &app,
                            "SYNCING",
                            scan_height,
                            daemon_height,
                            (scan_height as f64 / daemon_height as f64) * 100.0,
                            &node_label,
                            restore_base,
                        );
                    }
                }

                scan_height = batch_end + 1;

                // Check generation BEFORE updating state — don't overwrite a rescan's reset
                let ws = app.state::<WalletState>();
                if ws.current_scanner_generation() != generation {
                    emit_log(
                        &app,
                        "Sync",
                        "info",
                        "🛑 Scan loop stopped (superseded after batch)",
                    );
                    return Ok(());
                }

                // Update scan height in state
                ws.update_sync_status(scan_height, daemon_height).await;

                // Persist progress after EVERY batch. The old `scan_height % 500`
                // heuristic drifted with the batch step and rarely fired, so the
                // cache froze tens of thousands of blocks behind the live scan —
                // and since unlock/restart resumes from the persisted height, all
                // that progress was lost on every relaunch. The cache is small
                // (serialized owned outputs only), so saving each batch is cheap.
                ws.save_output_cache().await;
            }
            Err(e) => {
                consecutive_failures += 1;
                if consecutive_failures >= MAX_NODE_FAILURES {
                    return Err(format!(
                        "{} block fetch failing ({} consecutive): {:?}",
                        node_label, consecutive_failures, e
                    ));
                }
                emit_log(
                    &app,
                    "Sync",
                    "warn",
                    &format!(
                        "⚠️ Block fetch failed {}-{} ({}/{}) — reconnecting…",
                        scan_height, batch_end, consecutive_failures, MAX_NODE_FAILURES
                    ),
                );
                sleep(Duration::from_millis(400)).await;
                continue;
            }
        }

        // This batch was served by per-block because the node couldn't bulk. We've
        // persisted its progress above; now re-race for a bulk-capable node so fast
        // sync resumes rather than crawling the slow path on a bulk-hostile node.
        if reraise_for_bulk {
            return Err(format!(
                "{} can't serve bulk — re-racing for a faster node",
                node_label
            ));
        }

        // Emit sync progress
        let percent = if daemon_height > 0 {
            (scan_height as f64 / daemon_height as f64) * 100.0
        } else {
            0.0
        };
        crate::emit_sync_status(
            &app,
            "SYNCING",
            scan_height,
            daemon_height,
            percent,
            &node_label,
            restore_base,
        );
    }
}

// ── Background multi-wallet sync ("Sync all wallets") ──
//
// Scans a NON-active wallet from `view_pair` alone (no spend key), keeping its
// <id>.cache warm so switching to it is instant. Independent of WalletState; it
// owns its own scanner + cache and never touches the active wallet's state.

/// Dispatch the background scan for one pooled wallet over the configured route.
pub(crate) async fn run_pool_scan(
    app: AppHandle,
    identity_id: String,
    view_pair: ViewPair,
    from_height: u64,
    cancel: Arc<AtomicBool>,
) {
    match read_routing_mode(&app).as_str() {
        "tor" => {
            if let Some(tor) = ensure_tor(&app).await {
                pool_loop(app, identity_id, view_pair, from_height, cancel, TorConnector { tor }).await;
            }
        }
        "custom" => {
            let proxy = read_proxy_address(&app);
            if !proxy.trim().is_empty() {
                pool_loop(app, identity_id, view_pair, from_height, cancel, CustomProxyConnector { proxy }).await;
            }
        }
        "clearnet" => pool_loop(app, identity_id, view_pair, from_height, cancel, ClearnetConnector).await,
        other => emit_log(
            &app,
            "Network",
            "error",
            &format!("❌ Unknown routing mode {other:?}. Background sync paused rather than falling back to clearnet."),
        ),
    }
}

async fn pool_loop<C: DaemonConnector>(
    app: AppHandle,
    identity_id: String,
    view_pair: ViewPair,
    mut scan_height: u64,
    cancel: Arc<AtomicBool>,
    connector: C,
) {
    use futures::stream::StreamExt;

    let data_dir = app.state::<WalletState>().data_dir().await;

    // Build a view-only scanner and register subaddresses (account 0). Generous
    // fixed count so outputs to any reasonable subaddress are detected.
    let mut scanner = Scanner::new(view_pair.clone());
    for i in 1..=100u32 {
        if let Some(idx) = SubaddressIndex::new(0, i) {
            scanner.register_subaddress(idx);
        }
    }

    // Resume from (and accumulate into) the wallet's own cache.
    let mut cache = storage::load_output_cache(&data_dir, &identity_id);
    if cache.scan_height > scan_height {
        scan_height = cache.scan_height;
    }
    if scan_height < RINGCT_FORK_HEIGHT {
        scan_height = RINGCT_FORK_HEIGHT;
    }

    let short = identity_id
        .chars()
        .rev()
        .take(7)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();

    // Opt-in fast sync (same trade-off as the active scanner; see scan_loop).
    let fast_sync = read_config_bool(&app, "fast_sync");

    'outer: loop {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        // The active wallet scans itself via WalletState — never double-scan it.
        if app
            .state::<WalletState>()
            .is_active_identity(&identity_id)
            .await
        {
            return;
        }

        let (_, _, daemon) = match race_nodes(&app, &connector).await {
            Some(r) => r,
            None => {
                sleep(Duration::from_secs(15)).await;
                continue;
            }
        };

        loop {
            if cancel.load(Ordering::SeqCst)
                || app
                    .state::<WalletState>()
                    .is_active_identity(&identity_id)
                    .await
            {
                return;
            }
            // Back off while the active wallet is doing a heavy catch-up, so we
            // don't compete for the node + CPU (resumes when it's caught up).
            if app.state::<crate::wallet::SyncPool>().is_active_busy() {
                sleep(Duration::from_secs(5)).await;
                continue;
            }
            let daemon_height = match daemon.latest_block_number().await {
                Ok(h) => h as u64,
                Err(_) => continue 'outer, // re-race
            };
            if scan_height >= daemon_height {
                cache.scan_height = scan_height;
                let _ = storage::save_output_cache(&data_dir, &identity_id, &cache);
                log::info!("[bg {short}] synced to {scan_height}");
                sleep(Duration::from_secs(30)).await;
                continue;
            }

            let batch_step: u64 = if fast_sync { 1000 } else { 100 };
            let batch_end = (scan_height + batch_step).min(daemon_height);
            let range = (scan_height as usize)..=(batch_end as usize);
            let per_block = || async {
                let r: Result<Vec<_>, _> = futures::stream::iter(range.clone())
                    .map(|n| ProvidesScannableBlocks::scannable_block_by_number(&daemon, n))
                    .buffered(4)
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .collect();
                r
            };
            // Fast sync: one bulk get_blocks.bin call (trusting node); fall back to
            // the validated per-block path on any error.
            let fetched = if fast_sync {
                match daemon
                    .bulk_scannable_blocks_trusting_node(range.clone())
                    .await
                {
                    Ok(b) => Ok(b),
                    Err(_) => per_block().await,
                }
            } else {
                per_block().await
            };
            let blocks = match fetched {
                Ok(b) => b,
                Err(_) => continue 'outer, // re-race
            };

            for (i, block) in blocks.iter().enumerate() {
                let h = scan_height + i as u64;
                if let Ok(timelocked) = scanner.scan(block.clone()) {
                    for o in timelocked.ignore_additional_timelock() {
                        cache.outputs.push(storage::CachedOutput {
                            data: o.serialize(),
                            amount: o.commitment().amount,
                            tx_hash: hex::encode(o.transaction()),
                            tx_index: o.index_in_transaction(),
                            subaddress: o.subaddress().map(|s| s.address()),
                            height: h,
                            timestamp: block.block.header.timestamp,
                        });
                    }
                }
            }
            scan_height = batch_end + 1;
            cache.scan_height = scan_height;
            let _ = storage::save_output_cache(&data_dir, &identity_id, &cache);
            log::info!(
                "[bg {short}] {scan_height} / {daemon_height} ({} outputs)",
                cache.outputs.len()
            );
        }
    }
}

#[cfg(test)]
mod fold_tests {
    use super::{fold_fullwidth, known_routing_mode};

    #[test]
    fn folds_fullwidth_colon_and_digits() {
        // CJK-IME fullwidth colon + fullwidth digits → ASCII host:port.
        assert_eq!(fold_fullwidth("127.0.0.1：17890"), "127.0.0.1:17890");
        assert_eq!(
            fold_fullwidth("１２７．０．０．１：９０５０"),
            "127.0.0.1:9050"
        );
    }
    #[test]
    fn leaves_ascii_untouched() {
        assert_eq!(fold_fullwidth("127.0.0.1:9050"), "127.0.0.1:9050");
        assert_eq!(
            fold_fullwidth("socks5://localhost:1080"),
            "socks5://localhost:1080"
        );
    }
    #[test]
    fn folds_ideographic_space() {
        assert_eq!(fold_fullwidth("a\u{3000}b"), "a b");
    }
    #[test]
    fn only_legacy_routing_values_are_network_capable() {
        for mode in ["tor", "clearnet", "custom"] {
            assert!(known_routing_mode(mode));
        }
        for mode in ["torOverVpn", "vpn", "", "TOR"] {
            assert!(!known_routing_mode(mode));
        }
    }
}

#[cfg(test)]
mod connect_smoke {
    use monero_daemon_rpc::prelude::*;
    use monero_simple_request_rpc::SimpleRequestTransport;

    // Reproduce the app's exact clearnet connect path against a known-reachable
    // node. Run: cargo test -p ripley-terminal clearnet_connect -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn clearnet_connect() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let url = "http://xmr-node.cakewallet.com:18081".to_string();
        match SimpleRequestTransport::new(url.clone()).await {
            Ok(daemon) => {
                let h = daemon.latest_block_number().await;
                println!("✅ connected {url} -> height {h:?}");
                assert!(h.is_ok());
            }
            Err(e) => panic!("❌ SimpleRequestTransport::new({url}) failed: {e:?}"),
        }
    }

    // Probe which nodes serve get_blocks.bin (bulk). 30-block contiguous fetch:
    // fast (<2s) ⇒ bulk path; slow (>8s) ⇒ per-block JSON fallback.
    // Run: cargo test -p ripley-terminal bulk_probe -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn bulk_probe() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let nodes = [
            "http://xmr-node.cakewallet.com:18081",
            "http://node3-us.monero.love:18081",
            "http://node2-eu.monero.love:18089",
            "http://node.monerodevs.org:18089",
            "http://nodes.hashvault.pro:18081",
        ];
        let start = 3_400_000usize;
        for url in nodes {
            let daemon = match SimpleRequestTransport::new(url.to_string()).await {
                Ok(d) => d,
                Err(e) => {
                    println!("⚠️  {url}: connect failed {e:?}");
                    continue;
                }
            };
            let t = std::time::Instant::now();
            let r =
                ProvidesScannableBlocks::contiguous_scannable_blocks(&daemon, start..=(start + 29))
                    .await;
            let ms = t.elapsed().as_millis();
            match r {
                Ok(b) => println!(
                    "{} {url}: {} blocks in {}ms ({:.0} blk/s)",
                    if ms < 2500 {
                        "🚀 BULK"
                    } else {
                        "🐌 FALLBACK"
                    },
                    b.len(),
                    ms,
                    b.len() as f64 / (ms.max(1) as f64 / 1000.0)
                ),
                Err(e) => println!("❌ {url}: {e:?}"),
            }
        }
    }

    // Exercise the app's real clearnet transport (ReqwestTransport, the same path
    // the custom-node setting takes) against an arbitrary daemon URL — every
    // route a sync + spend needs, in the order the scanner uses them. Meant for
    // proxies that allow-list methods (e.g. mnr.network's /v1/<token> URLs).
    // Run: RIPLEY_PROBE_NODE=https://host/base cargo test -p ripley-terminal node_probe -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn node_probe() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let url = std::env::var("RIPLEY_PROBE_NODE").expect("set RIPLEY_PROBE_NODE=<daemon url>");
        // Never echo the URL: a proxy token may live in its path.
        let daemon = crate::wallet::reqwest_transport::ReqwestTransport::connect(
            url,
            std::time::Duration::from_secs(60),
        )
        .await
        .expect("connect (get_height)");
        let tip = daemon
            .latest_block_number()
            .await
            .expect("latest_block_number");
        println!("✅ /get_height -> {tip}");

        let fee = daemon
            .fee_rate(FeePriority::Normal, 500_000)
            .await
            .expect("get_fee_estimate");
        println!("✅ get_fee_estimate -> {fee:?}");

        let start = tip.saturating_sub(120);
        let t = std::time::Instant::now();
        let blocks = daemon
            .bulk_scannable_blocks_trusting_node(start..=(start + 99))
            .await
            .expect("get_blocks.bin (trusting bulk)");
        println!(
            "✅ /get_blocks.bin -> {} blocks in {}ms",
            blocks.len(),
            t.elapsed().as_millis()
        );
        assert_eq!(blocks.len(), 100);

        let dist = daemon
            .ringct_output_distribution(start..=(start + 99))
            .await
            .expect("get_output_distribution.bin");
        println!("✅ /get_output_distribution.bin -> {} entries", dist.len());
        let last = *dist.last().expect("distribution non-empty");
        assert!(last > 0);

        let idx = [
            last.saturating_sub(3),
            last.saturating_sub(2),
            last.saturating_sub(1),
        ];
        let outs = daemon.ringct_outputs(&idx).await.expect("get_outs.bin");
        println!("✅ /get_outs.bin -> {} outputs", outs.len());
        assert_eq!(outs.len(), idx.len());

        let tx_hash = blocks
            .iter()
            .flat_map(|b| b.block.transactions.iter().copied())
            .next()
            .expect("a non-miner tx in the window");
        let txs = daemon
            .transactions(&[tx_hash])
            .await
            .expect("/get_transactions");
        println!("✅ /get_transactions -> {} tx", txs.len());
        let oi = daemon
            .output_indexes(tx_hash)
            .await
            .expect("get_o_indexes.bin");
        println!("✅ /get_o_indexes.bin -> {} indexes", oi.len());

        let body = serde_json::json!({ "key_images": [format!("{:064x}", 1u8)] }).to_string();
        let res = daemon
            .rpc_call("is_key_image_spent", Some(body), 1024 * 1024)
            .await
            .expect("/is_key_image_spent");
        println!("✅ /is_key_image_spent -> {} bytes", res.len());
        println!("🎉 every sync/spend route answered (send_raw_transaction not exercised)");
    }

    // Measures the FORK's trusting bulk path (get_blocks.bin without prunable_hash).
    // Run: cargo test -p ripley-terminal fast_bulk_speed -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn fast_bulk_speed() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let daemon =
            SimpleRequestTransport::new("http://xmr-node.cakewallet.com:18081".to_string())
                .await
                .expect("connect");
        let start = 3_400_000usize;
        let t = std::time::Instant::now();
        let blocks = daemon
            .bulk_scannable_blocks_trusting_node(start..=(start + 999))
            .await
            .expect("bulk trusting fetch");
        let ms = t.elapsed().as_millis().max(1);
        println!(
            "⚡ fast bulk: {} blocks in {}ms ({:.0} blk/s)",
            blocks.len(),
            ms,
            blocks.len() as f64 / (ms as f64 / 1000.0)
        );
        assert_eq!(blocks.len(), 1000);
        let with_idx = blocks
            .iter()
            .filter(|b| b.output_index_for_first_ringct_output.is_some())
            .count();
        println!("   {with_idx}/1000 blocks carry a first-ringct output index");
        assert!(
            with_idx > 0,
            "no output indices populated — spending would break"
        );
    }
}
