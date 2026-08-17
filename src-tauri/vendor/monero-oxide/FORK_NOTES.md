# Ripley Terminal fork of monero-oxide

Base: upstream `a941dfff1a5333b6349d9a1ee5de49c158b0e3d2`.

## Delta (single additive commit, branch `fast-sync-trusting`)
Adds an **opt-in fast bulk sync** path that upstream cannot offer because of
Monero issue #10120 (public nodes omit per-tx `prunable_hash` from
`get_blocks.bin`, forcing monero-oxide's validated path to fall back to slow
per-block JSON).

Two additive items, NO change to any existing validated path:

1. `interface/daemon/src/bin_rpc/epee.rs`
   `extract_scannable_blocks_trusting_node()` — a copy of
   `extract_blocks_from_blocks_bin` that ignores `prunable_hash` and builds
   `ScannableBlock`s directly (public fields), using the daemon-supplied global
   `output_indices`. Skips the per-tx prunable-hash binding / `verify_as_possible`.

2. `interface/daemon/src/bin_rpc/blocks_bin.rs`
   `MoneroDaemon::bulk_scannable_blocks_trusting_node()` — public method that
   issues the same `get_blocks.bin` request loop and returns `Vec<ScannableBlock>`,
   erroring (so callers fall back) if the node doesn't serve the binary endpoint.

## Security model
Output ownership is still proven cryptographically (ECDH between wallet view key
and each tx public key), so a node CANNOT fabricate spendable funds. The residual
trust is that the node does not omit/alter transactions — a malicious node could
only hide incoming funds (recoverable by rescanning a trusted node), not steal.
Callers MUST gate this behind explicit user opt-in (Ripley: Settings "Fast sync",
default OFF).

## Rebasing
The change is isolated to two files and is purely additive, so rebasing onto a
newer upstream is a clean cherry-pick of the `fast-sync-trusting` commit.

## TODO (maintenance)
Promote this local clone to a real `KYC-rip/monero-oxide` fork on GitHub and
update the `git = "file://..."` deps in `ripley-terminal/src-tauri/Cargo.toml`
to the GitHub URL + rev so other machines / CI can build.
