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

use monero_daemon_rpc::prelude::*;

#[derive(Clone)]
pub struct ReqwestTransport {
    base: String,
    client: reqwest::Client,
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
        MoneroDaemon::new(ReqwestTransport { base, client })
            .await
            .map_err(|e| format!("daemon init failed: {e:?}"))
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
        async move {
            let resp = client
                .post(&url)
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
}
