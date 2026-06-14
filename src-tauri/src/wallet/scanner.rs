//! Background blockchain scanner.
//!
//! Connects to a Monero daemon, fetches blocks in batches, and scans each block
//! for outputs belonging to the wallet's ViewPair using monero-wallet's Scanner.

use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Emitter, Manager};
use tokio::time::sleep;

use arti_client::TorClient;
use tor_rtcompat::PreferredRuntime;

use monero_daemon_rpc::prelude::*;
use monero_daemon_rpc::{HttpTransport, MoneroDaemon};
use monero_simple_request_rpc::SimpleRequestTransport;
use monero_wallet::{Scanner, ViewPair};
use monero_address::SubaddressIndex;

use crate::emit_log;
use crate::tor::{ArtiTransport, SocksTransport, TorState};
use super::state::WalletState;
use super::{storage, types::SyncStatus};

const GITHUB_NODES_URL: &str = "https://raw.githubusercontent.com/KYC-rip/ripley-terminal/main/resources/nodes.json";

/// Read the configured routing mode ("tor" | "clearnet") from config.json.
/// Defaults to "clearnet" when the file is absent or unparseable.
pub(crate) fn read_routing_mode(app: &AppHandle) -> String {
    read_config_str(app, "routingMode").unwrap_or_else(|| "clearnet".to_string())
}

/// Read the external SOCKS proxy address (custom routing mode) from config.json,
/// normalized to a bare `host:port` (tokio-socks wants no scheme prefix).
pub(crate) fn read_proxy_address(app: &AppHandle) -> String {
    let raw = read_config_str(app, "systemProxyAddress").unwrap_or_default();
    let trimmed = raw.trim();
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
/// Clearnet addresses are normalized to an `http://` URL and HTTPS is skipped
/// (simple-request has TLS cert issues). Tor `.onion` addresses are stored
/// verbatim as `host:port` — `ArtiTransport` parses them and arti dials them
/// natively (no exit node).
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
                            // Skip HTTPS nodes — simple-request has TLS cert issues
                            if addr_str.starts_with("https://") {
                                continue;
                            }
                            let url = if addr_str.starts_with("http://") {
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
    type Transport = SimpleRequestTransport;
    fn section(&self) -> &'static str {
        "clearnet"
    }
    async fn connect(&self, url: String) -> Option<MoneroDaemon<SimpleRequestTransport>> {
        SimpleRequestTransport::new(url).await.ok()
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
                log::warn!("Tor connect to {url} failed: {e:?}");
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
                log::warn!("SOCKS connect to {url} via {} failed: {e:?}", self.proxy);
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
async fn load_nodes(app: &AppHandle, section: &str) -> Vec<(String, String)> {
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
        log::info!("Using manual node override: {url}");
        return vec![("custom".to_string(), url)];
    }
    let cache_path = app.path().app_data_dir()
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
    use tokio::sync::mpsc;

    let nodes = load_nodes(app, connector.section()).await;
    emit_log(app, "Network", "info", &format!("🏁 Racing {} nodes...", nodes.len()));

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
                    match ensure_tor(&app_clone).await {
                        Some(tor) => run_outer(app_clone, generation, TorConnector { tor }).await,
                        // ensure_tor already logged the failure; do not start a
                        // clearnet fallback — that would leak the IP the user
                        // asked us to hide.
                        None => {}
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
                _ => {
                    run_outer(app_clone, generation, ClearnetConnector).await;
                }
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
            emit_log(app, "Tor", "success", "🧅 Tor connected — daemon RPC routes through Tor");
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
            emit_log(&app_clone, "Sync", "info", "🛑 Scanner stopped (superseded by newer scan)");
            return;
        }

        // Race all nodes
        let (label, url, daemon) = match race_nodes(&app_clone, &connector).await {
            Some(result) => result,
            None => {
                emit_log(&app_clone, "Network", "error", "❌ All nodes failed. Retrying in 10s...");
                sleep(Duration::from_secs(10)).await;
                continue;
            }
        };

        emit_log(&app_clone, "Network", "success", &format!("✅ Fastest node: {} ({})", label, url));

        // Store daemon URL so tx commands can connect
        let wallet_state = app_clone.state::<WalletState>();
        wallet_state.set_daemon_url(&url).await;

        // Read current scan height from state (may have been updated by rescan)
        let current_height = {
            let ws = app_clone.state::<WalletState>();
            ws.get_scan_height().await
        };

        // Run scan loop — if it fails, re-race
        match scan_loop(app_clone.clone(), daemon, current_height, url.clone(), label.clone(), generation, &connector).await {
            Ok(()) => break,
            Err(e) => {
                emit_log(&app_clone, "Sync", "error", &format!("⚠️ {} disconnected: {}. Re-racing...", label, e));
                sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

// RingCT fork height — blocks before this have no RingCT outputs.
// monero-wallet only scans RingCT outputs, so scanning earlier blocks is pointless.
const RINGCT_FORK_HEIGHT: u64 = 1_220_516;

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

    if scan_height == u64::MAX {
        emit_log(&app, "Sync", "info", "🔍 New wallet — will sync from daemon tip");
    } else {
        emit_log(&app, "Sync", "info", &format!("🔍 Scan loop started from height {}", scan_height));
    }

    // Each transport serializes its own requests (SimpleRequestTransport via a
    // mutex; ArtiTransport opens one stream per request), and public nodes cap
    // connections per IP. So build the pool by spreading ONE connection across
    // MANY distinct nodes — each node sees a single connection (no throttling)
    // and we still get wide parallelism. Historical blocks are identical across
    // nodes and every fetch is validated, so multi-node fetch is safe. In Tor
    // mode all entries share one TorClient (arti reuses circuits internally).
    let mut pool = vec![daemon.clone()];
    {
        use futures::stream::StreamExt;
        let others: Vec<(String, String)> = load_nodes(&app, connector.section())
            .await
            .into_iter()
            .filter(|(_, u)| u != &node_url)
            .collect();
        let connected: Vec<Option<_>> = futures::stream::iter(others)
            .map(|(_, url)| {
                let connector = connector.clone();
                async move { connector.connect(url).await }
            })
            .buffer_unordered(fetch_concurrency)
            .collect()
            .await;
        for d in connected.into_iter().flatten() {
            pool.push(d);
            if pool.len() >= fetch_concurrency {
                break;
            }
        }
    }
    let pool_n = pool.len();
    if fast_sync {
        emit_log(&app, "Sync", "info", &format!("⚡ Fast sync ON — bulk get_blocks.bin, trusting {} (fallback: {} nodes)", node_label, pool_n));
    } else {
        emit_log(&app, "Sync", "info", &format!("🔗 Fetching across {} nodes in parallel", pool_n));
    }

    // Rolling measured throughput (blocks/sec), seeded then EMA-smoothed from
    // real batch timings so the ETA reflects actual speed, not a guess.
    let mut measured_bps: f64 = (pool_n as f64) * 1.5;

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
                emit_log(&app, "Sync", "error", &format!("⚠️ Failed to get daemon height: {:?}", e));
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        };

        if scan_height == u64::MAX || scan_height > daemon_height {
            // New wallet sentinel (u64::MAX) or somehow ahead — start near tip
            emit_log(&app, "Sync", "info", &format!("📦 New wallet: starting near daemon tip ({})", daemon_height));
            scan_height = daemon_height.saturating_sub(10);
        }

        // Skip pre-RingCT blocks — monero-wallet can only scan RingCT outputs
        if scan_height < RINGCT_FORK_HEIGHT {
            emit_log(&app, "Sync", "info", &format!("⏩ Skipping to RingCT fork (block {}), pre-RingCT blocks have no scannable outputs", RINGCT_FORK_HEIGHT));
            scan_height = RINGCT_FORK_HEIGHT;
        }

        if scan_height >= daemon_height {
            crate::emit_sync_status(&app, "SYNCED", scan_height, daemon_height, 100.0, &node_label);
            sleep(Duration::from_secs(10)).await;
            continue;
        }

        // In fast-sync the whole batch comes back in ONE get_blocks.bin call, so
        // use a large batch. The validated per-block fallback gains nothing from
        // big batches, so keep those modest for smooth progress reporting.
        let gap = daemon_height - scan_height;
        let batch_size: u64 = if fast_sync {
            1_000.min(gap)
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
                emit_log(&app, "Sync", "info", &format!("⏱️ ETA: ~{}h {}m ({} blocks remaining at {:.1} blk/s)", eta_hours, eta_mins % 60, gap, measured_bps));
            } else {
                emit_log(&app, "Sync", "info", &format!("⏱️ ETA: ~{}m ({} blocks remaining at {:.1} blk/s)", eta_mins, gap, measured_bps));
            }
        }

        let batch_end = (scan_height + batch_size).min(daemon_height);
        let range = (scan_height as usize)..=(batch_end as usize);

        emit_log(&app, "Sync", "info", &format!("📥 Fetching blocks {}-{} / {}", scan_height, batch_end, daemon_height));

        let fetch_start = std::time::Instant::now();
        // The validated per-block path: contiguous_scannable_blocks is a serial
        // per-block loop (~0.8s/block over clearnet → multi-hour syncs). buffered(N)
        // pipelines N block fetches across the node pool, preserving height order
        // and cutting wall-clock by ~Nx. This is the trustless default AND the
        // fallback when a fast-sync bulk fetch fails.
        let parallel_fetch = || async {
            use futures::stream::StreamExt;
            futures::stream::iter(range.clone().enumerate())
                .map(|(i, n)| {
                    let d = &pool[i % pool_n];
                    async move { ProvidesScannableBlocks::scannable_block_by_number(d, n).await }
                })
                .buffered(pool_n)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>()
        };
        // Fast sync: one bulk get_blocks.bin call for the whole batch (trusting the
        // node). On ANY error, fall back to the validated per-block path so we never
        // do worse than the default.
        let parallel_result = if fast_sync {
            match daemon.bulk_scannable_blocks_trusting_node(range.clone()).await {
                Ok(blocks) => Ok(blocks),
                Err(e) => {
                    emit_log(&app, "Sync", "warn", &format!("⚡ Fast-sync bulk fetch failed ({:?}) — falling back to validated per-block for this batch", e));
                    parallel_fetch().await
                }
            }
        } else {
            parallel_fetch().await
        };
        match parallel_result {
            Ok(blocks) => {
                let fetch_ms = fetch_start.elapsed().as_millis();
                // Update rolling throughput (EMA) from this batch's real timing
                if fetch_ms > 0 && !blocks.is_empty() {
                    let batch_bps = blocks.len() as f64 / (fetch_ms as f64 / 1000.0);
                    measured_bps = measured_bps * 0.6 + batch_bps * 0.4;
                }
                let blk_s = if fetch_ms > 0 { blocks.len() as f64 / (fetch_ms as f64 / 1000.0) } else { 0.0 };
                emit_log(&app, "Sync", "info", &format!("✅ Got {} blocks in {}ms ({:.0} blk/s)", blocks.len(), fetch_ms, blk_s));
                // Scan each block with the wallet's Scanner
                let wallet_state = app.state::<WalletState>();
                if let Some(mut scanner) = wallet_state.get_scanner().await {
                    let mut new_output_count = 0u64;
                    let mut new_amount = 0u64;

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
                                    wallet_state.add_outputs(outputs, block_height, generation).await;
                                }
                            }
                            Err(e) => {
                                emit_log(&app, "Scan", "error", &format!("⚠️ Scan error at ~{}: {:?}", scan_height, e));
                            }
                        }
                    }

                    if new_output_count > 0 {
                        emit_log(&app, "Scan", "success", &format!(
                            "💰 Found {} outputs ({} piconero) in blocks {}-{}",
                            new_output_count, new_amount, scan_height, batch_end
                        ));
                        let total = wallet_state.compute_balance().await;
                        crate::emit_sync_status(&app, "SYNCING", scan_height, daemon_height,
                            (scan_height as f64 / daemon_height as f64) * 100.0, &node_label);
                    }
                }

                scan_height = batch_end + 1;

                // Check generation BEFORE updating state — don't overwrite a rescan's reset
                let ws = app.state::<WalletState>();
                if ws.current_scanner_generation() != generation {
                    emit_log(&app, "Sync", "info", "🛑 Scan loop stopped (superseded after batch)");
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
                emit_log(&app, "Sync", "error", &format!("⚠️ Block fetch failed ({}-{}): {:?}", scan_height, batch_end, e));
                sleep(Duration::from_secs(5)).await;
                continue;
            }
        }

        // Emit sync progress
        let percent = if daemon_height > 0 {
            (scan_height as f64 / daemon_height as f64) * 100.0
        } else {
            0.0
        };
        crate::emit_sync_status(&app, "SYNCING", scan_height, daemon_height, percent, &node_label);
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
        _ => pool_loop(app, identity_id, view_pair, from_height, cancel, ClearnetConnector).await,
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

    let short = identity_id.chars().rev().take(7).collect::<String>().chars().rev().collect::<String>();

    // Opt-in fast sync (same trade-off as the active scanner; see scan_loop).
    let fast_sync = read_config_bool(&app, "fast_sync");

    'outer: loop {
        if cancel.load(Ordering::SeqCst) {
            return;
        }
        // The active wallet scans itself via WalletState — never double-scan it.
        if app.state::<WalletState>().is_active_identity(&identity_id).await {
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
                || app.state::<WalletState>().is_active_identity(&identity_id).await
            {
                return;
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
                match daemon.bulk_scannable_blocks_trusting_node(range.clone()).await {
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
                        });
                    }
                }
            }
            scan_height = batch_end + 1;
            cache.scan_height = scan_height;
            let _ = storage::save_output_cache(&data_dir, &identity_id, &cache);
            log::info!("[bg {short}] {scan_height} / {daemon_height} ({} outputs)", cache.outputs.len());
        }
    }
}

#[cfg(test)]
mod connect_smoke {
    use monero_simple_request_rpc::SimpleRequestTransport;
    use monero_daemon_rpc::prelude::*;

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
                Err(e) => { println!("⚠️  {url}: connect failed {e:?}"); continue; }
            };
            let t = std::time::Instant::now();
            let r = ProvidesScannableBlocks::contiguous_scannable_blocks(&daemon, start..=(start + 29)).await;
            let ms = t.elapsed().as_millis();
            match r {
                Ok(b) => println!("{} {url}: {} blocks in {}ms ({:.0} blk/s)",
                    if ms < 2500 { "🚀 BULK" } else { "🐌 FALLBACK" }, b.len(), ms,
                    b.len() as f64 / (ms.max(1) as f64 / 1000.0)),
                Err(e) => println!("❌ {url}: {e:?}"),
            }
        }
    }

    // Measures the FORK's trusting bulk path (get_blocks.bin without prunable_hash).
    // Run: cargo test -p ripley-terminal fast_bulk_speed -- --ignored --nocapture
    #[tokio::test]
    #[ignore]
    async fn fast_bulk_speed() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let daemon = SimpleRequestTransport::new("http://xmr-node.cakewallet.com:18081".to_string())
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
        let with_idx =
            blocks.iter().filter(|b| b.output_index_for_first_ringct_output.is_some()).count();
        println!("   {with_idx}/1000 blocks carry a first-ringct output index");
        assert!(with_idx > 0, "no output indices populated — spending would break");
    }
}
