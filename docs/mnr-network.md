# Connecting ripley-terminal / RipleyOS to mnr.network

> Copy for mnr.network's "Connect wallets" page (Ripley section) + the facts behind it.
> Verified 2026-09-05 against `rpc.mnr.network` with a free token: every route the wallet
> uses for sync and spend answered through the app's real clearnet transport
> (`cargo test -p ripley-terminal node_probe -- --ignored --nocapture` with
> `RIPLEY_PROBE_NODE=https://rpc.mnr.network/v1/<token>`).

## Page copy (proposed)

### Ripley Terminal (RipleyOS)

Ripley Terminal is a Monero wallet + private OS shell. It scans the chain itself (a light
wallet with its own view key), so it only needs a daemon RPC endpoint — your mnr token URL
works as that endpoint.

1. Get a token above (free tier is enough: a wallet sync is a few hundred requests).
2. In Ripley open **Settings** and scroll to **Uplink_Protocols**.
3. Under **Uplink_Routing** pick **Clearnet**.
4. In **Manual_Uplink_Address** paste your endpoint:

   ```
   https://rpc.mnr.network/v1/<token>
   ```

   Keep the `https://` and the `/v1/<token>` path, no trailing `/json_rpc`.
5. Save. The log should show `🔗 Connecting to pinned node…` followed by
   `✅ Fastest node: custom (https://rpc.mnr.network)`, then `⚡ Fast sync ON — bulk
   get_blocks.bin, trusting custom`.

That's it — sync, decoy selection and broadcasting all go through mnr from then on.

**Tor / I2P:** not yet. Ripley's Tor and custom-SOCKS routing modes dial `host:port` only and
drop the URL path, so the token can't travel in the URL there and Ripley has no daemon-login
field. Until Ripley gains daemon-login (Basic auth) support, use Clearnet mode with mnr; the
connection is still TLS to `rpc.mnr.network`, and Ripley's own Tor mode is the alternative if
you'd rather not pin a node at all.

**Privacy notes.** Ripley never sends your view key or address to the node — it downloads
blocks in bulk and scans locally. What mnr sees is what any node sees: your IP (unless you
front it with a VPN), which blocks you fetch, the output indices you ask for while building
a transaction, and the signed transaction you broadcast. Ripley redacts the token from its
own logs (it logs `https://rpc.mnr.network`, never the path).

**Requirements.** A Ripley Terminal build newer than 2.1.0 (2.1.0 and earlier fail to
connect to mnr — see below).

## Facts for whoever maintains the page

- Config key: `customNodeAddress` in Ripley's `config.json` (the Settings field writes it).
  A bare `host:port` is prefixed with `http://`; a full `https://…/v1/<token>` is used as-is
  and every route is posted as `<base>/<route>` (`json_rpc`, `get_blocks.bin`, …).
- Routes Ripley uses, all on mnr's allow-list: `/get_height`, `json_rpc: get_info`,
  `get_fee_estimate`, `get_block`, `on_get_block_hash` (monero-oxide's batch probe),
  `/get_blocks.bin` (bulk sync, trusting), `/get_output_distribution.bin`,
  `/get_outs.bin`, `/get_o_indexes.bin`, `/get_transactions`, `/is_key_image_spent`,
  `/send_raw_transaction`. Nothing from the deny list (`get_transaction_pool`, `relay_tx`,
  `sync_info`, …).
- Cloudflare in front of `rpc.mnr.network` returns `403 error code: 1010` for some
  User-Agents (Python-urllib is blocked). Ripley's transport sends no User-Agent, which
  passes; curl passes.
- **Compatibility bug mnr may want to fix (affects every monero-oxide-based client, not
  only Ripley):** monero-oxide's `MoneroDaemon::new` probes JSON-RPC batch support by
  POSTing a JSON *array* to `/json_rpc` and expects monerod's answer — HTTP **200** with
  `{"error":{"code":-32700,"message":"Parse error"}}`. mnr returns the same envelope with
  HTTP **400** (`crates/relay/src/ingress.rs`, the `json_rpc_error(StatusCode::BAD_REQUEST,
  …PARSE_ERROR…)` arm). Clients that treat non-2xx as a transport failure then fail to
  connect at all. Ripley builds after 2.1.0 work around it (a 4xx whose body is a JSON-RPC error
  envelope is handed to the RPC layer); returning 200 there, as monerod does, would make
  older Ripley builds and other oxide wallets work unchanged.
