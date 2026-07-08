//! The `ros://` custom protocol: the sole content source for the RipleyOS window.
//!
//! A verified bundle is decompressed once into an in-memory `path -> bytes` map (nothing
//! is extracted to disk — see [`super::ota::extract_tar_zst`]); this handler serves
//! `ros://local/<path>` straight from that map. Because the map is the only source, a
//! path the map doesn't contain simply 404s — there is no filesystem to traverse into.
//!
//! The resolution logic ([`RosBundle::resolve`]) is pure and unit-tested; `lib.rs` wraps
//! it in `register_uri_scheme_protocol` and turns [`RosResponse`] into an HTTP response.

use std::collections::HashMap;

/// An in-memory, verified ROS UI bundle. Built once at launch, then read-only.
pub struct RosBundle {
    files: HashMap<String, Vec<u8>>,
}

/// A resolved response: HTTP status, MIME type, and the body bytes to serve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosResponse {
    pub status: u16,
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

impl RosBundle {
    /// Decompress + verify-shape a `.tar.zst` archive into memory. Fails if the archive
    /// is malformed, contains an unsafe path, or lacks `index.html` at its root (the SPA
    /// entry point the handler falls back to).
    pub fn from_archive(archive: &[u8]) -> Result<Self, String> {
        let files = super::ota::extract_tar_zst(archive)?;
        if !files.contains_key("index.html") {
            return Err("archive has no index.html at root".into());
        }
        Ok(Self { files })
    }

    #[cfg(test)]
    pub fn from_map(files: HashMap<String, Vec<u8>>) -> Self {
        Self { files }
    }

    pub fn len(&self) -> usize {
        self.files.len()
    }

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Resolve a `ros://local/<path>` request against the in-memory map.
    ///
    /// - `/` or empty → `index.html`.
    /// - an exact file hit → that file, typed by extension.
    /// - a miss with NO file extension → `index.html` (SPA client-side routing).
    /// - a miss WITH an extension (e.g. a real missing asset) → 404 (never index.html,
    ///   so a stray `<script src>` to a bad path fails loudly instead of executing HTML).
    pub fn resolve(&self, uri: &str) -> RosResponse {
        let path = path_from_uri(uri);
        let key = if path.is_empty() { "index.html" } else { &path };

        if let Some(body) = self.files.get(key) {
            return RosResponse {
                status: 200,
                content_type: mime_for(key),
                body: body.clone(),
            };
        }

        // SPA fallback only for extensionless routes ("/wallet/receive").
        if !has_extension(key) {
            if let Some(body) = self.files.get("index.html") {
                return RosResponse {
                    status: 200,
                    content_type: "text/html",
                    body: body.clone(),
                };
            }
        }

        RosResponse {
            status: 404,
            content_type: "text/plain",
            body: b"not found".to_vec(),
        }
    }
}

/// Extract the relative asset path from a `ros://local/...` URI: drop the scheme+host,
/// strip a query/fragment and a leading slash. Returns "" for the bare origin. Uses the
/// same normalization as the archive keys so a `..` or absolute path can never match.
fn path_from_uri(uri: &str) -> String {
    // After the scheme, skip the authority (host) up to the first '/'.
    let after_scheme = uri.splitn(2, "://").nth(1).unwrap_or(uri);
    let path_and_rest = match after_scheme.find('/') {
        Some(i) => &after_scheme[i + 1..],
        None => "", // "ros://local" with no path
    };
    // Drop query/fragment.
    let path = path_and_rest
        .split(['?', '#'])
        .next()
        .unwrap_or("");
    // Percent-decode is not needed for our own build's ASCII asset names; normalize the
    // same way archive keys were normalized (rejects traversal → empty ⇒ index fallback).
    super::ota::normalize_entry_path(path).unwrap_or_default()
}

fn has_extension(path: &str) -> bool {
    match path.rsplit('/').next() {
        Some(last) => last.contains('.'),
        None => false,
    }
}

/// MIME type by file extension — the set a Vite `dist/` actually emits, plus fonts/wasm.
fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "html" | "htm" => "text/html",
        "js" | "mjs" => "text/javascript",
        "css" => "text/css",
        "json" | "map" => "application/json",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "avif" => "image/avif",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        "wasm" => "application/wasm",
        "txt" => "text/plain",
        "webmanifest" => "application/manifest+json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle() -> RosBundle {
        let mut m = HashMap::new();
        m.insert("index.html".into(), b"<!doctype html><h1>ros</h1>".to_vec());
        m.insert("assets/app-abc.js".into(), b"console.log(1)".to_vec());
        m.insert("assets/app-abc.css".into(), b"body{}".to_vec());
        m.insert("logo.svg".into(), b"<svg/>".to_vec());
        RosBundle::from_map(m)
    }

    #[test]
    fn serves_index_for_root() {
        let b = bundle();
        for uri in ["ros://local/", "ros://local", "ros://local/index.html"] {
            let r = b.resolve(uri);
            assert_eq!(r.status, 200, "{uri}");
            assert_eq!(r.content_type, "text/html", "{uri}");
            assert!(r.body.starts_with(b"<!doctype"), "{uri}");
        }
    }

    #[test]
    fn serves_assets_with_correct_mime() {
        let b = bundle();
        let js = b.resolve("ros://local/assets/app-abc.js");
        assert_eq!((js.status, js.content_type), (200, "text/javascript"));
        let css = b.resolve("ros://local/assets/app-abc.css");
        assert_eq!((css.status, css.content_type), (200, "text/css"));
        let svg = b.resolve("ros://local/logo.svg");
        assert_eq!((svg.status, svg.content_type), (200, "image/svg+xml"));
    }

    #[test]
    fn spa_fallback_for_extensionless_route() {
        let b = bundle();
        let r = b.resolve("ros://local/wallet/receive");
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/html");
        assert!(r.body.starts_with(b"<!doctype"));
    }

    #[test]
    fn missing_asset_with_extension_is_404_not_index() {
        let b = bundle();
        let r = b.resolve("ros://local/assets/missing-xyz.js");
        assert_eq!(r.status, 404);
        // Crucially NOT the HTML index — a bad script src must fail, not run markup.
        assert_ne!(r.content_type, "text/html");
    }

    #[test]
    fn query_and_fragment_are_ignored() {
        let b = bundle();
        let r = b.resolve("ros://local/assets/app-abc.js?v=2#x");
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/javascript");
    }

    #[test]
    fn traversal_attempt_cannot_escape() {
        let b = bundle();
        // normalize_entry_path collapses "../" to a reject → empty path → index fallback,
        // never a file outside the map.
        let r = b.resolve("ros://local/../../etc/passwd");
        assert_eq!(r.content_type, "text/html"); // fell back to index, served nothing outside
        assert_eq!(r.status, 200);
    }

    #[test]
    fn from_archive_requires_index_html() {
        // A tar.zst with no index.html is refused.
        let mut tar_buf = Vec::new();
        {
            let mut bld = tar::Builder::new(&mut tar_buf);
            let body = &b"x"[..];
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_cksum();
            bld.append_data(&mut h, "assets/only.js", body).unwrap();
            bld.finish().unwrap();
        }
        let zst = zstd::stream::encode_all(&tar_buf[..], 3).unwrap();
        assert!(RosBundle::from_archive(&zst).is_err());
    }
}
