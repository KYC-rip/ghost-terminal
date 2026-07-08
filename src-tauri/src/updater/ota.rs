//! Signed-OTA verification core for the RipleyOS UI bundle.
//!
//! Design + threat model: `kyc-rip/docs/ota-signed-updates.md`. The renderer (ROS) is
//! untrusted and drives sensitive wallet commands, so **arbitrary remote JS must never
//! run**: an update is only accepted if it is signed by the pinned Ed25519 key AND
//! passes rollback / freshness / backend-compat / size / content-hash gates. The server
//! and CDN are never trusted.
//!
//! Everything in this file that makes a trust decision is a **pure function** (no I/O,
//! no clock, no network) so it is exhaustively unit-testable; the clock and the pinned
//! key are injected. The I/O orchestration (fetch, download, persist, load) lives in the
//! sibling modules and calls into here.

use serde::{Deserialize, Serialize};

/// Ed25519 verifying key, pinned in the signed binary — the OTA trust anchor.
/// DEV key (2026-07-09); rotated to a production key via a signed native release
/// before stable (decision #5 in the runbook: rotation-via-release only, never in-band).
pub const OTA_UPDATE_PUBKEY: [u8; 32] =
    hex_literal::hex!("499e307aa4fd84e47a2e3dffbf030eeedd95cee566a67c87ad66afd814cf8907");

/// Clearnet manifest URL + its byte-identical `.onion` mirror (Tor-routed in native).
pub const OTA_MANIFEST_URL: &str = "https://ros.rip/ota/manifest.json";
pub const OTA_MANIFEST_ONION: &str =
    "http://rosriprqvi346zjxaxdxfhntf7l2gdba45ou2skk24waewizo3fttdqd.onion/ota/manifest.json";

/// Hard size cap on the archive — rejected before download (anti-DoS).
pub const OTA_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Freshness window — a manifest older than this is rejected (anti-freeze: a hostile
/// server can't pin you forever on a stale-but-validly-signed version).
pub const OTA_MAX_AGE_SECS: i64 = 30 * 24 * 3600;

/// SHA-256 of the bundled fallback archive (`resources/ros-fallback.tar.zst`), shipped
/// inside the signed binary and covered by the native build provenance. Re-checked at
/// load: if the on-disk resource doesn't match, the binary's integrity is compromised.
/// Regenerated together with the resource by `ripley-os/scripts/build-ota.mjs`.
pub const FALLBACK_SHA256: &str =
    "580b172eaa66d2977dbd35842efb785614013cbb864828c4a13def31ca4eadea";

/// The signed manifest served at `OTA_MANIFEST_URL`. Its detached `.sig` is Ed25519
/// over the RAW bytes of this document exactly as served — so we verify the bytes
/// BEFORE JSON-parsing (no canonicalization ambiguity).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Manifest {
    pub schema: u32,
    pub version: String,
    #[serde(rename = "minBackend")]
    pub min_backend: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub released: String,
}

/// The on-disk `state.json`: which verified bundle is active.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct State {
    pub version: String,
    pub sha256: String,
}

/// Why a candidate manifest was refused. Every arm is a fail-closed outcome — the
/// caller leaves the current bundle untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OtaReject {
    BadSignature,
    BadJson(String),
    UnsupportedSchema(u32),
    BadSemver(String),
    Rollback { candidate: String, current: String },
    Stale { age_secs: i64 },
    BackendTooOld { min: String, backend: String },
    TooLarge { size: u64 },
}

impl std::fmt::Display for OtaReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OtaReject::BadSignature => write!(f, "manifest signature verification failed"),
            OtaReject::BadJson(e) => write!(f, "manifest JSON parse error: {e}"),
            OtaReject::UnsupportedSchema(s) => write!(f, "unsupported manifest schema {s}"),
            OtaReject::BadSemver(v) => write!(f, "unparseable version \"{v}\""),
            OtaReject::Rollback { candidate, current } => {
                write!(f, "rollback refused: candidate {candidate} <= current {current}")
            }
            OtaReject::Stale { age_secs } => write!(f, "manifest too old ({age_secs}s)"),
            OtaReject::BackendTooOld { min, backend } => {
                write!(f, "backend {backend} < required minBackend {min}")
            }
            OtaReject::TooLarge { size } => write!(f, "archive too large ({size} bytes)"),
        }
    }
}

/// Schema versions this binary understands. A newer schema → refuse (fail-closed)
/// rather than misinterpret fields.
const SUPPORTED_SCHEMA: u32 = 1;

/// Verify an Ed25519 detached signature (`sig`, 64 raw bytes) over `raw` with the given
/// 32-byte verifying key. Pure. Any malformed input → false (never panics). Uses
/// `verify_strict` to reject the known malleability / weak-key edge cases.
pub fn verify_sig(vk_bytes: &[u8; 32], raw: &[u8], sig: &[u8]) -> bool {
    use ed25519_dalek::{Signature, VerifyingKey};
    let vk = match VerifyingKey::from_bytes(vk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match Signature::from_slice(sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    vk.verify_strict(raw, &sig).is_ok()
}

/// Parse a `major.minor.patch` core, ignoring any `-prerelease`/`+build` suffix. Returns
/// None if the three numeric components aren't present. Enough for our own version line
/// (we control the manifest); not a full SemVer implementation.
pub fn parse_semver(s: &str) -> Option<(u64, u64, u64)> {
    let core = s.trim().split(['-', '+']).next().unwrap_or("");
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    if it.next().is_some() {
        return None; // 1.2.3.4 is not a valid core
    }
    Some((a, b, c))
}

/// Parse an RFC 3339 timestamp (e.g. `2026-07-09T00:00:00Z`) to unix seconds.
fn released_unix(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s.trim())
        .ok()
        .map(|dt| dt.timestamp())
}

/// The whole trust decision, pure. Order matters: signature FIRST (over raw bytes,
/// before any parse), then structural + policy gates. `now_unix` and the pinned key are
/// injected so this is deterministic and unit-testable.
///
/// - `raw` / `sig`: the manifest bytes exactly as served and its detached signature.
/// - `current_version`: the active bundle's version (`"0.0.0"` if none yet).
/// - `backend_version`: this binary's version (`CARGO_PKG_VERSION`).
#[allow(clippy::result_large_err)]
pub fn evaluate_manifest(
    vk_bytes: &[u8; 32],
    raw: &[u8],
    sig: &[u8],
    now_unix: i64,
    current_version: &str,
    backend_version: &str,
) -> Result<Manifest, OtaReject> {
    // 1. Signature over the RAW bytes — before JSON parsing.
    if !verify_sig(vk_bytes, raw, sig) {
        return Err(OtaReject::BadSignature);
    }
    // 2. Parse.
    let m: Manifest =
        serde_json::from_slice(raw).map_err(|e| OtaReject::BadJson(e.to_string()))?;
    // 3. Schema.
    if m.schema != SUPPORTED_SCHEMA {
        return Err(OtaReject::UnsupportedSchema(m.schema));
    }
    // 4. Rollback: candidate must be strictly newer than the active version.
    let cand = parse_semver(&m.version).ok_or_else(|| OtaReject::BadSemver(m.version.clone()))?;
    let cur = parse_semver(current_version)
        .ok_or_else(|| OtaReject::BadSemver(current_version.to_string()))?;
    if cand <= cur {
        return Err(OtaReject::Rollback {
            candidate: m.version.clone(),
            current: current_version.to_string(),
        });
    }
    // 5. Freshness (anti-freeze). A missing/garbage `released` is treated as infinitely
    //    old → rejected.
    let rel = released_unix(&m.released).unwrap_or(i64::MIN);
    let age = now_unix.saturating_sub(rel);
    if age > OTA_MAX_AGE_SECS {
        return Err(OtaReject::Stale { age_secs: age });
    }
    // 6. Backend compat.
    let min = parse_semver(&m.min_backend)
        .ok_or_else(|| OtaReject::BadSemver(m.min_backend.clone()))?;
    let backend =
        parse_semver(backend_version).ok_or_else(|| OtaReject::BadSemver(backend_version.to_string()))?;
    if min > backend {
        return Err(OtaReject::BackendTooOld {
            min: m.min_backend.clone(),
            backend: backend_version.to_string(),
        });
    }
    // 7. Size cap (before any download).
    if m.size > OTA_MAX_BYTES {
        return Err(OtaReject::TooLarge { size: m.size });
    }
    Ok(m)
}

/// Constant-time-ish check that `bytes` hash to the expected lowercase-hex SHA-256.
/// (The hash is integrity, not a secret; a plain compare is fine, but we lowercase the
/// expected string so `AB…` == `ab…`.)
pub fn verify_archive_hash(bytes: &[u8], expected_hex: &str) -> bool {
    use sha2::{Digest, Sha256};
    let got = Sha256::digest(bytes);
    hex::encode(got).eq_ignore_ascii_case(expected_hex.trim())
}

/// Decompress a `.tar.zst` archive fully into memory: `path -> bytes`. Nothing touches
/// disk. Rejects path traversal (absolute paths, `..`, drive/UNC-ish) so a hostile
/// archive can't reference outside the virtual root. `index.html` is expected at the
/// archive root (the build tars the `dist/` CONTENTS, not the `dist/` dir).
pub fn extract_tar_zst(bytes: &[u8]) -> Result<std::collections::HashMap<String, Vec<u8>>, String> {
    use std::io::Read;
    let decoder = zstd::stream::read::Decoder::new(bytes).map_err(|e| format!("zstd: {e}"))?;
    let mut archive = tar::Archive::new(decoder);
    let mut out = std::collections::HashMap::new();
    let entries = archive.entries().map_err(|e| format!("tar entries: {e}"))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| format!("tar entry: {e}"))?;
        let path = entry.path().map_err(|e| format!("tar path: {e}"))?;
        let rel = normalize_entry_path(&path.to_string_lossy())
            .ok_or_else(|| format!("unsafe archive path: {}", path.to_string_lossy()))?;
        // Directories (empty rel) and non-file entries carry no bytes we serve.
        if rel.is_empty() {
            continue;
        }
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).map_err(|e| format!("tar read: {e}"))?;
        out.insert(rel, buf);
    }
    if out.is_empty() {
        return Err("archive contained no files".into());
    }
    Ok(out)
}

/// Reduce a tar entry path to a safe forward-slash relative key, or None if it escapes
/// the root. Rejects absolute paths and any `..` component; strips a leading `./`.
pub fn normalize_entry_path(raw: &str) -> Option<String> {
    let raw = raw.replace('\\', "/");
    // Absolute (`/x`), UNC (`//host`), or anything with a `:` (Windows drive `C:`, or a
    // scheme) — none of which a legitimate relative web-asset path ever has.
    if raw.starts_with('/') || raw.starts_with("//") || raw.contains(':') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in raw.split('/') {
        match seg {
            "" | "." => continue,
            ".." => return None, // refuse traversal outright (don't try to resolve)
            s => parts.push(s),
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    // Deterministic test keypair (fixed seed — no rng, reproducible). Distinct from the
    // pinned production key; evaluate_manifest takes the vk as a param exactly so tests
    // can use their own key.
    fn test_keys() -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let vk = sk.verifying_key().to_bytes();
        (sk, vk)
    }

    fn manifest_json(version: &str, min_backend: &str, released: &str, size: u64) -> Vec<u8> {
        format!(
            r#"{{"schema":1,"version":"{version}","minBackend":"{min_backend}","url":"https://ros.rip/ota/ros-{version}.tar.zst","sha256":"{}","size":{size},"released":"{released}"}}"#,
            "0".repeat(64)
        )
        .into_bytes()
    }

    // A fixed "now": 2026-07-09T12:00:00Z.
    const NOW: i64 = 1_783_598_400;
    const FRESH: &str = "2026-07-09T00:00:00Z";

    #[test]
    fn accepts_a_well_formed_signed_manifest() {
        let (sk, vk) = test_keys();
        let raw = manifest_json("2.4.0", "2.0.0", FRESH, 8_000_000);
        let sig = sk.sign(&raw).to_bytes();
        let m = evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0").unwrap();
        assert_eq!(m.version, "2.4.0");
    }

    #[test]
    fn rejects_a_bad_signature_before_parsing() {
        let (sk, vk) = test_keys();
        let raw = manifest_json("2.4.0", "2.0.0", FRESH, 8_000_000);
        let mut sig = sk.sign(&raw).to_bytes();
        sig[0] ^= 0xff; // flip a byte
        assert_eq!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::BadSignature)
        );
    }

    #[test]
    fn rejects_wrong_key() {
        let (sk, _vk) = test_keys();
        let other_vk = SigningKey::from_bytes(&[9u8; 32]).verifying_key().to_bytes();
        let raw = manifest_json("2.4.0", "2.0.0", FRESH, 8_000_000);
        let sig = sk.sign(&raw).to_bytes();
        assert_eq!(
            evaluate_manifest(&other_vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::BadSignature)
        );
    }

    #[test]
    fn rejects_valid_json_with_bad_sig_before_trusting_fields() {
        // Even perfectly-formed JSON is refused if the sig is wrong — the fields are
        // never trusted.
        let (_sk, vk) = test_keys();
        let raw = manifest_json("9.9.9", "0.0.0", FRESH, 1);
        let sig = [0u8; 64];
        assert_eq!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::BadSignature)
        );
    }

    #[test]
    fn rejects_rollback_and_equal_version() {
        let (sk, vk) = test_keys();
        for v in ["2.3.0", "2.2.9", "1.0.0"] {
            let raw = manifest_json(v, "2.0.0", FRESH, 10);
            let sig = sk.sign(&raw).to_bytes();
            let r = evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0");
            assert!(matches!(r, Err(OtaReject::Rollback { .. })), "{v} must be refused");
        }
    }

    #[test]
    fn rejects_stale_manifest() {
        let (sk, vk) = test_keys();
        // released 40 days before NOW → older than the 30-day window.
        let raw = manifest_json("2.4.0", "2.0.0", "2026-05-30T12:00:00Z", 10);
        let sig = sk.sign(&raw).to_bytes();
        assert!(matches!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::Stale { .. })
        ));
    }

    #[test]
    fn rejects_backend_too_old() {
        let (sk, vk) = test_keys();
        let raw = manifest_json("2.4.0", "2.1.0", FRESH, 10);
        let sig = sk.sign(&raw).to_bytes();
        assert!(matches!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::BackendTooOld { .. })
        ));
        // equal minBackend == backend is fine.
        let raw = manifest_json("2.4.0", "2.0.0", FRESH, 10);
        let sig = sk.sign(&raw).to_bytes();
        assert!(evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0").is_ok());
    }

    #[test]
    fn rejects_oversize() {
        let (sk, vk) = test_keys();
        let raw = manifest_json("2.4.0", "2.0.0", FRESH, OTA_MAX_BYTES + 1);
        let sig = sk.sign(&raw).to_bytes();
        assert!(matches!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::TooLarge { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_schema() {
        let (sk, vk) = test_keys();
        let raw = br#"{"schema":2,"version":"2.4.0","minBackend":"2.0.0","url":"x","sha256":"00","size":1,"released":"2026-07-09T00:00:00Z"}"#.to_vec();
        let sig = sk.sign(&raw).to_bytes();
        assert!(matches!(
            evaluate_manifest(&vk, &raw, &sig, NOW, "2.3.0", "2.0.0"),
            Err(OtaReject::UnsupportedSchema(2))
        ));
    }

    #[test]
    fn semver_parsing() {
        assert_eq!(parse_semver("2.4.0"), Some((2, 4, 0)));
        assert_eq!(parse_semver(" 2.4.0-beta.1 "), Some((2, 4, 0)));
        assert_eq!(parse_semver("2.4.0+build5"), Some((2, 4, 0)));
        assert_eq!(parse_semver("2.4"), None);
        assert_eq!(parse_semver("2.4.0.1"), None);
        assert_eq!(parse_semver("x.y.z"), None);
        assert!((1, 0, 0) > (0, 9, 9));
    }

    #[test]
    fn archive_hash_check() {
        use sha2::{Digest, Sha256};
        let bytes = b"hello ripley";
        let good = hex::encode(Sha256::digest(bytes));
        assert!(verify_archive_hash(bytes, &good));
        assert!(verify_archive_hash(bytes, &good.to_uppercase()));
        assert!(!verify_archive_hash(bytes, &"0".repeat(64)));
    }

    #[test]
    fn path_normalization_rejects_traversal() {
        assert_eq!(normalize_entry_path("index.html").as_deref(), Some("index.html"));
        assert_eq!(normalize_entry_path("./assets/app.js").as_deref(), Some("assets/app.js"));
        assert_eq!(normalize_entry_path("a//b/./c").as_deref(), Some("a/b/c"));
        assert_eq!(normalize_entry_path("../etc/passwd"), None);
        assert_eq!(normalize_entry_path("assets/../../x"), None);
        assert_eq!(normalize_entry_path("/abs/path"), None);
        assert_eq!(normalize_entry_path("C:\\win"), None);
    }

    // ---- Golden fixture: a real bundle signed by the DEV key (which is the pinned
    // OTA_UPDATE_PUBKEY), produced by ripley-os/scripts/build-ota.mjs. Exercises the whole
    // chain against real bytes: verify (with the PINNED key) -> hash -> in-memory extract
    // -> the index.html the ros:// handler will serve. Fixtures committed under
    // src-tauri/tests/fixtures/ota/. -------------------------------------------------------
    const FIX_MANIFEST: &[u8] = include_bytes!("../../tests/fixtures/ota/manifest.json");
    const FIX_SIG: &[u8] = include_bytes!("../../tests/fixtures/ota/manifest.json.sig");
    const FIX_ARCHIVE: &[u8] = include_bytes!("../../tests/fixtures/ota/ros-2.0.0.tar.zst");

    #[test]
    fn golden_fixture_verifies_end_to_end_with_the_pinned_key() {
        // "now" = the manifest's own released time + 1h, so the freshness gate passes
        // regardless of the wall clock when the suite runs.
        let m_preview: Manifest = serde_json::from_slice(FIX_MANIFEST).unwrap();
        let now = released_unix(&m_preview.released).unwrap() + 3600;

        // Verify with the PINNED production key (not a test key) — proves the dev key that
        // signed the fixture matches OTA_UPDATE_PUBKEY.
        let m = evaluate_manifest(&OTA_UPDATE_PUBKEY, FIX_MANIFEST, FIX_SIG, now, "1.0.0", "2.0.0")
            .expect("golden fixture must verify against the pinned key");
        assert_eq!(m.version, "2.0.0");

        // Archive bytes hash to the manifest's sha256.
        assert!(verify_archive_hash(FIX_ARCHIVE, &m.sha256));

        // Decompresses in memory and contains the SPA entry point.
        let map = extract_tar_zst(FIX_ARCHIVE).unwrap();
        assert!(map.contains_key("index.html"));
        assert!(String::from_utf8_lossy(&map["index.html"]).contains("RipleyOS"));
    }

    #[test]
    fn golden_fixture_tamper_is_rejected() {
        let mut bad = FIX_MANIFEST.to_vec();
        // flip a byte in the middle of the manifest → signature no longer matches.
        let mid = bad.len() / 2;
        bad[mid] ^= 0x01;
        let now = released_unix(&serde_json::from_slice::<Manifest>(FIX_MANIFEST).unwrap().released)
            .unwrap()
            + 3600;
        assert_eq!(
            evaluate_manifest(&OTA_UPDATE_PUBKEY, &bad, FIX_SIG, now, "1.0.0", "2.0.0"),
            Err(OtaReject::BadSignature)
        );
    }

    #[test]
    fn bundled_fallback_matches_pinned_hash() {
        // The archive we ship as resources/ros-fallback.tar.zst (== the fixture archive)
        // must match the pinned FALLBACK_SHA256 the loader re-checks at runtime.
        assert!(verify_archive_hash(FIX_ARCHIVE, FALLBACK_SHA256));
    }

    #[test]
    fn tar_zst_roundtrip_in_memory() {
        // Build a tiny .tar.zst in memory, then extract it.
        let mut tar_buf = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_buf);
            for (name, body) in [("index.html", &b"<h1>ros</h1>"[..]), ("assets/x.js", b"1")] {
                let mut h = tar::Header::new_gnu();
                h.set_size(body.len() as u64);
                h.set_cksum();
                b.append_data(&mut h, name, body).unwrap();
            }
            b.finish().unwrap();
        }
        let zst = zstd::stream::encode_all(&tar_buf[..], 3).unwrap();
        let map = extract_tar_zst(&zst).unwrap();
        assert_eq!(map.get("index.html").map(|v| v.as_slice()), Some(&b"<h1>ros</h1>"[..]));
        assert_eq!(map.get("assets/x.js").map(|v| v.as_slice()), Some(&b"1"[..]));
    }
}
