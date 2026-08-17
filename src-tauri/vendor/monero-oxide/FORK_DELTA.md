# FORK_DELTA — ripley-terminal vendored monero-oxide

This directory is a vendored copy of the monero-oxide fork at
`github.com/KYC-rip/monero-oxide`, rev `31136bc913ebd8cc96b1e9048ce98c5c7c54de5e`
(the same rev pinned in `src-tauri/Cargo.toml`), with one **additive** delta.

Why vendored: the offline-signing flow needs to verify a signed transaction
against the prepared (unsigned) one, and to classify change ownership on the
cold signer. `monero-wallet`'s `SignableTransaction` fields are private and its
`InternalPayment` / `ChangeEnum` types are crate-private, so the shell cannot
reach them through the public API. Vendoring lets the shell build against the
fork + a small additive patch without waiting on an upstream release.

How the wiring works: `src-tauri/Cargo.toml` still declares the monero crates as
git deps at the pinned rev, and a `[patch."https://github.com/KYC-rip/monero-oxide"]`
section redirects those sources to `vendor/monero-oxide/...` (path deps). Path
deps inside the vendored workspace (`monero-oxide = { path = ".." }`, etc.)
resolve locally, so the whole workspace must be vendored — do not prune member
crates.

## Delta vs upstream rev 31136bc

Single file changed: `monero-oxide/wallet/src/send/mod.rs`

1. `enum ChangeEnum` → `pub enum ChangeEnum`
2. `enum InternalPayment` → `pub enum InternalPayment`
3. Added to `impl SignableTransaction`:
   - `pub fn real_inputs(&self) -> &[OutputWithDecoys]` — exposes the real inputs
     with their decoy rings, so a verifier can compare the multiset of ring
     key offsets (`real_inputs()[i].decoys().offsets()`) of a signed transaction
     against the prepared transaction. Signing re-sorts inputs by key image
     (`with_key_images`), not by ring offset, so a *multiset* comparison is
     the correct bijection check. (Named `real_inputs` — `tx.rs` already has a
     `SignableTransaction::inputs()` that builds protocol `Input`s.)
   - `pub fn payments(&self) -> &[InternalPayment]` — exposes destinations
     (address, amount) and the change spec, so a cold signer can classify every
     output and verify the change output returns to its own wallet (same spend
     public key / subaddress).

No behavior changes; purely additive API surface. `cargo fmt`/`clippy` clean.

## Rebasing onto a newer fork rev

1. Re-vendor the new rev into this directory (rsync, excluding `.git`/`target`).
2. Re-apply the three edits above.
3. Bump the `rev` in `src-tauri/Cargo.toml` git deps to match.

The `[patch]` section keeps working unchanged as long as the member crate paths
are unchanged.
