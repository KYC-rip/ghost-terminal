//! Signed over-the-air updates for the RipleyOS UI bundle.
//!
//! - [`ota`]: the trust core — manifest structs, the pinned Ed25519 key, and the pure
//!   verification pipeline (signature → rollback → freshness → backend-compat → size →
//!   content-hash) plus `.tar.zst` in-memory extraction. All decision logic is pure and
//!   unit-tested; see `docs/ota-signed-updates.md`.
//!
//! The I/O orchestration (fetch over Tor/onion, download, atomic cache, load) and the
//! `ros://` protocol handler are wired in follow-up steps and call into `ota`.

pub mod ota;
