//! Disk-cached, chunked, RESUMABLE RingCT output-distribution provider.
//!
//! Decoy selection (`OutputWithDecoys::new`) fetches the FULL RingCT output
//! distribution for every input via `ringct_output_distribution(..= tip)` — a
//! ~20 MB response. Over Tor that single large transfer reliably drops mid-stream
//! (circuits die before 20 MB completes), so Tor sends fail on every node.
//!
//! The distribution is cumulative and only GROWS (one entry per block), so once
//! built it never needs a full re-fetch. `CachingDecoys` wraps a daemon and:
//!   * serves `ringct_output_distribution` from an on-disk cache;
//!   * after the first build, fetches only the NEW blocks' slice (a few KB);
//!   * builds that first cache in ~100k-block chunks (~800 KB each) — small
//!     enough to complete over a single Tor circuit — walking DOWNWARD from the
//!     tip until a short response reveals the RingCT start height;
//!   * **persists after every chunk**, so a timeout / node failover keeps the
//!     partial progress and the next attempt RESUMES downward instead of
//!     restarting. This is what makes the first build survive Tor's flaky pool.
//! Every other daemon operation delegates to the inner daemon unchanged.

use core::ops::{Bound, RangeBounds};
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use tokio::sync::Mutex;

use monero_daemon_rpc::prelude::*;
use monero_oxide::ed25519::Point;
use monero_oxide::transaction::Transaction;

/// Blocks per chunk while building. 100k * 8 bytes ≈ 800 KB per fetch — reliably
/// completes over a single Tor circuit (unlike the ~20 MB full pull).
const BUILD_CHUNK_BLOCKS: usize = 100_000;

#[derive(Clone)]
struct CacheState {
    /// `true` once the downward build reached the RingCT start block, i.e. `dist`
    /// is the complete `distribution[start ..= tip]` and safe to serve.
    complete: bool,
    /// Highest block number `dist` covers.
    tip: usize,
    /// `distribution[bottom ..= tip]`, where `bottom = tip + 1 - dist.len()`.
    /// When `complete`, `bottom == start` (the RingCT activation block).
    dist: Vec<u64>,
}

impl CacheState {
    fn bottom(&self) -> usize {
        self.tip + 1 - self.dist.len()
    }
}

/// App-global, per-cache-file distribution store (keyed by path). Shared across
/// every wrapper instance so failover attempts and successive sends reuse it.
fn global() -> &'static Arc<Mutex<HashMap<PathBuf, CacheState>>> {
    static G: OnceLock<Arc<Mutex<HashMap<PathBuf, CacheState>>>> = OnceLock::new();
    G.get_or_init(|| Arc::new(Mutex::new(HashMap::new())))
}

fn load_from_disk(path: &PathBuf) -> Option<CacheState> {
    let bytes = std::fs::read(path).ok()?;
    // [complete: u8][tip: u64 LE][dist: u64 LE ...]
    if bytes.len() < 9 || ((bytes.len() - 9) % 8 != 0) {
        return None;
    }
    let complete = bytes[0] != 0;
    let tip = u64::from_le_bytes(bytes[1..9].try_into().ok()?) as usize;
    let dist: Vec<u64> = bytes[9..]
        .chunks_exact(8)
        .map(|c| u64::from_le_bytes(c.try_into().unwrap()))
        .collect();
    if dist.is_empty() {
        return None;
    }
    Some(CacheState {
        complete,
        tip,
        dist,
    })
}

fn persist_to_disk(path: &PathBuf, state: &CacheState) {
    let mut buf = Vec::with_capacity(9 + state.dist.len() * 8);
    buf.push(u8::from(state.complete));
    buf.extend_from_slice(&(state.tip as u64).to_le_bytes());
    for v in &state.dist {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(path, &buf);
}

/// Wraps a daemon, serving `ringct_output_distribution` from a persisted,
/// incrementally-built, resumable cache. All other ops delegate to `inner`.
pub struct CachingDecoys<D> {
    inner: D,
    path: PathBuf,
}

impl<D> CachingDecoys<D> {
    pub fn new(inner: D, cache_path: PathBuf) -> Self {
        Self {
            inner,
            path: cache_path,
        }
    }
}

fn range_end<R: RangeBounds<usize>>(range: &R) -> Option<usize> {
    match range.end_bound() {
        Bound::Included(n) => Some(*n),
        Bound::Excluded(n) => Some(n.saturating_sub(1)),
        Bound::Unbounded => None,
    }
}

impl<D> ProvidesBlockchainMeta for CachingDecoys<D>
where
    D: ProvidesBlockchainMeta + Sync,
{
    fn latest_block_number(&self) -> impl Send + Future<Output = Result<usize, InterfaceError>> {
        self.inner.latest_block_number()
    }
}

impl<D> ProvidesFeeRates for CachingDecoys<D>
where
    D: ProvidesFeeRates + Sync,
{
    fn fee_rate(
        &self,
        priority: FeePriority,
        max_per_weight: u64,
    ) -> impl Send + Future<Output = Result<FeeRate, FeeError>> {
        self.inner.fee_rate(priority, max_per_weight)
    }
}

impl<D> PublishTransaction for CachingDecoys<D>
where
    D: PublishTransaction + Sync,
{
    fn publish_transaction(
        &self,
        transaction: &Transaction,
    ) -> impl Send + Future<Output = Result<(), PublishTransactionError>> {
        self.inner.publish_transaction(transaction)
    }
}

impl<D> ProvidesDecoys for CachingDecoys<D>
where
    D: ProvidesDecoys + Sync,
{
    fn unlocked_ringct_outputs(
        &self,
        indexes: &[u64],
        evaluate_unlocked: EvaluateUnlocked,
    ) -> impl Send + Future<Output = Result<Vec<Option<[Point; 2]>>, TransactionsError>> {
        self.inner
            .unlocked_ringct_outputs(indexes, evaluate_unlocked)
    }

    fn ringct_output_distribution(
        &self,
        range: impl Send + RangeBounds<usize>,
    ) -> impl Send + Future<Output = Result<Vec<u64>, InterfaceError>> {
        async move {
            // Decoy selection always requests `..= tip`; resolve the tip block N.
            let n = match range_end(&range) {
                Some(n) => n,
                None => self.inner.latest_block_number().await?,
            };

            let g = global();

            // Fast path: a COMPLETE cache already covers N.
            {
                let mut map = g.lock().await;
                if !map.contains_key(&self.path) {
                    if let Some(state) = load_from_disk(&self.path) {
                        log::info!(
                            "[dist-cache] loaded {} entries (tip {}, complete={}) from disk",
                            state.dist.len(),
                            state.tip,
                            state.complete
                        );
                        map.insert(self.path.clone(), state);
                    }
                }
                if let Some(state) = map.get(&self.path) {
                    if state.complete && n <= state.tip {
                        let start = state.bottom();
                        return Ok(if n < start {
                            Vec::new()
                        } else {
                            state.dist[..=(n - start)].to_vec()
                        });
                    }
                }
            }

            // Slow path: build/resume/extend WITHOUT holding the global lock
            // (this is the long, chunked, Tor-safe part). Failover is sequential,
            // so no two builds race for the same cache.
            let state = self.build_resume_extend(n).await?;

            // Publish the finished state to the in-memory map.
            {
                let mut map = g.lock().await;
                map.insert(self.path.clone(), state.clone());
            }
            let start = state.bottom();
            Ok(if n < start {
                Vec::new()
            } else {
                state.dist[..=(n - start).min(state.dist.len() - 1)].to_vec()
            })
        }
    }
}

impl<D> CachingDecoys<D>
where
    D: ProvidesDecoys + Sync,
{
    /// Ensure a COMPLETE cache covering `n` exists on disk, building downward in
    /// Tor-sized chunks (persisting each) then extending forward to `n`.
    async fn build_resume_extend(&self, n: usize) -> Result<CacheState, InterfaceError> {
        // Start from whatever's on disk (a partial build to resume), else fresh.
        let mut state = load_from_disk(&self.path).unwrap_or(CacheState {
            complete: false,
            tip: n,
            dist: Vec::new(),
        });

        // Downward build: keep prepending chunks until we reach the RingCT start.
        if !state.complete {
            log::info!(
                "[dist-cache] building/resuming distribution in {}-block chunks (one-time)",
                BUILD_CHUNK_BLOCKS
            );
            while !state.complete {
                let bottom = if state.dist.is_empty() {
                    state.tip + 1
                } else {
                    state.bottom()
                };
                let to = bottom - 1;
                let from = to.saturating_sub(BUILD_CHUNK_BLOCKS - 1);
                let requested = to - from + 1;
                let piece = self.inner.ringct_output_distribution(from..=to).await?;
                let got = piece.len();
                // Prepend this lower slice.
                let mut merged = piece;
                merged.extend_from_slice(&state.dist);
                state.dist = merged;
                // A short response (or reaching block 0) means we hit the start.
                if got < requested || from == 0 {
                    state.complete = true;
                }
                persist_to_disk(&self.path, &state); // resumable checkpoint
            }
            log::info!(
                "[dist-cache] build complete: {} entries, start {}",
                state.dist.len(),
                state.bottom()
            );
        }

        // Extend forward to the requested tip (tiny delta on every later send).
        if n > state.tip {
            let delta = self
                .inner
                .ringct_output_distribution((state.tip + 1)..=n)
                .await?;
            let added = delta.len();
            state.dist.extend_from_slice(&delta);
            state.tip = n;
            persist_to_disk(&self.path, &state);
            log::info!("[dist-cache] extended by {} blocks -> tip {}", added, n);
        }

        Ok(state)
    }
}
