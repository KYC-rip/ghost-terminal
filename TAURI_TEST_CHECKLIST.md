# Ripley Terminal — Tauri Test Checklist

Branch: `feat/tauri-migration` · Run with `npm run tauri dev` (or your launch command).

> Tip: open the integrated **console** (terminal icon / shortcut) to watch logs as you test.
> Use the new **Copy** button to grab logs for any failure.
> _(In `tauri dev` the console shows each line twice — that's a dev-only React StrictMode artifact, gone in a packaged build.)_

How to use: tick each box as you go. For anything that fails, note it under **Result** and paste the relevant console log.

---

## 🔴 Critical — Fast Sync correctness (NEW — has a trust tradeoff)

- [ ] Enable **Settings → Fast_Sync ⚡** → Save. Console shows `⚡ Fast sync ON` and **~100+ blk/s** with 1000-block batches.
- [ ] Confirm only **one** connection is used (no `Fetching across N nodes` upfront; a fallback pool line appears *only if* a batch fails).
- [ ] Let an old wallet restore fully — should take **~20 min**, not hours.
- [ ] **Balance + transaction history match** the same seed restored in Electron / `monero-wallet-cli`.
  _(Proves no incoming transactions were missed by the trusting bulk path.)_
- [ ] **Send a small amount and confirm it relays.**
  _(Proves the daemon-supplied output indices are spendable — this validates the whole fork. If a send ever fails to build, rescan that range with Fast Sync OFF and report it.)_

**Result:**

---

## 🟠 Sync — routing & lifecycle

- [ ] **Clearnet** sync works (no "all nodes failed").
- [ ] **Tor** sync works — bootstrap % shows, status chip updates.
- [ ] **Custom SOCKS proxy** (Whonix) mode connects.
- [ ] Changing **routing mode** in Settings applies **live** (scanner restarts, no re-login).
- [ ] **Lock mid-sync → sync keeps running**; progress does NOT reset to a lower height.
- [ ] **Unlock after sync** → resumes from current height (no progress loss).
- [ ] **Sync all wallets** toggle: unlock one wallet → others sync in background. Off by default.
- [ ] Set a **restore height** and confirm sync starts there (not from the RingCT fork).

**Result:**

---

## 🟡 Wallet core

- [ ] Create a fresh wallet (onboarding → password → default name).
- [ ] Restore from seed.
- [ ] Open / unlock with password; **wrong password rejected**.
- [ ] **Switch wallets from the lock/login screen.**
- [ ] Balance correct (no double-count); spent outputs excluded.
- [ ] Transaction history renders with correct amounts **+ fiat values**.
- [ ] Outputs / coin-control list correct.

**Result:**

---

## 🟡 Send / Receive

- [ ] Prepare transfer (fee probe) → relay → confirm txid.
- [ ] **Sweep all** works.
- [ ] Receive address + subaddress generation.

**Result:**

---

## 🟢 Settings & security

- [ ] **Shortcuts** mapping shows and works.
- [ ] **Skin / background image** loads; `config.json` stays small (image offloaded to `skin_bg.b64`).
- [ ] **Data Storage** panel shows real paths; **Reveal** opens the folder.
- [ ] **Seed reveal requires confirmation** — seed does NOT appear before you confirm the dialog.

**Result:**

---

## 🟢 Console (NEW this round)

- [ ] **Maximize / restore** button resizes the console panel.
- [ ] **Copy** button copies the log to clipboard (✓ Copied feedback).

**Result:**

---

## 🔵 Proofs & misc

- [ ] **get_tx_key** returns a key for a sent tx.
- [ ] OutProofV2 (`get_tx_proof`) is still **gated** — un-gate only after running the live `check_tx_proof` validation.
- [ ] Ghost-trade / xmr402 KV persistence (if used).
- [ ] Update checker runs without error.

**Result:**

---

## Notes / bugs found

-
