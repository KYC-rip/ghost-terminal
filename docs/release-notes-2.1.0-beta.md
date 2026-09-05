# Ripley Terminal 2.1.0-beta.1

Beta build. Unsigned by design (anti-dox) — verify authenticity via the attached
`SHA256SUMS` and the keyless build-provenance attestation (Sigstore) on this release,
not code-signing. Re-download to update; there is no native self-updater.

## RipleyOS in the native wallet (new)

- **RipleyOS ships inside Ripley Terminal.** Toggle `ui_mode=ros` to launch the full
  RipleyOS desktop in place of the classic wallet renderer; `ui_mode=classic` (default)
  is unchanged. Exit back to classic from inside ROS.
- **Two ROS sources, behind a flag** (`ros_source`, default `beta`):
  - `beta` → loads `app.ros.rip` (always-current, network-served).
  - `ota` → loads a **signed, on-device bundle** over the `ros://` custom protocol under
    a strict CSP, fully offline-capable.
- **Signed OTA updater.** Ed25519 signature verified over the raw manifest bytes
  *before* parsing, then rollback / freshness / backend-compat / size gates, then a
  sha256 check of the archive — fail-closed to a pinned, provenance-covered bundled
  fallback at every step. Updates apply on next launch (never hot-swapped). The
  renderer stays untrusted; a stolen key is bounded by the narrow command surface.
- **Capability isolation.** The `ros://` window runs under its own capability set
  (`ros_local`) with a narrow wallet surface and **no fs / shell / dialog** access —
  distinct from the classic `main` window.

## ROS Wallet app — settings parity

- Ported **Fast sync** and **Sync all wallets** into the ROS Wallet app's settings,
  matching the classic wallet (maps to the native `fast_sync` / `sync_all_wallets`
  keys; both trigger a scanner reload).

## Privacy / hardening

- **Bundled DM Sans** (self-hosted, `font-src 'self'`) — removes the Google Fonts
  request that leaked to the system-font fallback under CSP. No third-party font hosts.
- OTA size caps enforced *during* collection over Tor/SOCKS/clearnet (not just
  post-read); archive origin pinned to the manifest directory, not the manifest body.

## Notes

- Builds: universal macOS `.dmg`, Linux AppImage + `.deb`, Windows NSIS + `.msi`.
- The bundled ROS fallback in this build is RipleyOS **2.1.1**
  (`sha256 0ce529a1…`, built 2026-08-27 from `ripley-os` main), including
  native KV persistence. `minBackend` 2.1.0.
