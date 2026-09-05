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

use std::sync::Arc;
use tokio::sync::Mutex;

use monero_daemon_rpc::prelude::*;

const OUTPUT_DISTRIBUTION_ROUTE: &str = "get_output_distribution.bin";

#[derive(Clone)]
pub struct ReqwestTransport {
    base: String,
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
        MoneroDaemon::new(ReqwestTransport {
            base,
            client,
            dist_cache: Arc::new(Mutex::new(None)),
        })
        .await
        .map_err(|e| format!("daemon init failed: {e:?}"))
    }

    async fn do_post(
        client: &reqwest::Client,
        url: &str,
        body: Vec<u8>,
        response_size_limit: Option<usize>,
    ) -> Result<Vec<u8>, InterfaceError> {
        let resp = client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("post {url} failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(InterfaceError::InterfaceError(format!(
                "{url} returned HTTP {}",
                resp.status()
            )));
        }
        // Enforce monero-oxide's size limit up-front via Content-Length when present.
        if let (Some(limit), Some(cl)) = (response_size_limit, resp.content_length()) {
            if (cl as usize) > limit {
                return Err(InterfaceError::InterfaceError(format!(
                    "{url} response {cl} exceeds limit {limit}"
                )));
            }
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| InterfaceError::InterfaceError(format!("read body {url} failed: {e}")))?;
        Ok(bytes.to_vec())
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
                let bytes = Self::do_post(&client, &url, body.clone(), response_size_limit).await?;
                *guard = Some((body, bytes.clone()));
                return Ok(bytes);
            }
            Self::do_post(&client, &url, body, response_size_limit).await
        }
    }
}
