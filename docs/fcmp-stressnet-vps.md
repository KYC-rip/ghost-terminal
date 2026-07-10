# FCMP++ Stressnet VPS Setup

Runbook for the dedicated VPS that serves the FCMP++ stressnet: a
`seraphis-migration/monero` stressnet daemon (public restricted RPC) plus a
faucet `monero-wallet-rpc` exposed only through a Cloudflare Access tunnel,
consumed by the `kyc-rip-api` Worker route `POST /v1/faucet/stressnet/claim`.

> **SECURITY — risk acceptance**
> This VPS and the faucet wallet are **testnet-only**. They must **never**
> hold, receive, or touch mainnet funds, mainnet wallet files, or mainnet
> seeds. The wallet RPC runs with `--disable-rpc-login` and the box is
> treated as disposable: assume full compromise is survivable because the
> only thing at stake is worthless tXMR. Do not reuse this host, its SSH
> keys, or its Cloudflare tunnel for anything that handles real value.

## 1. Sizing

| Resource | Requirement |
|----------|-------------|
| Disk     | < 10 GB (stressnet chain is small; budget headroom for resyncs) |
| RAM      | 2 GB |
| CPU      | 1–2 vCPU is plenty |
| OS       | Debian 12 / Ubuntu 24.04 LTS (systemd assumed below) |

## 2. Download the pinned stressnet release

Binaries come from the Seraphis migration fork, **not** upstream monero.
Browse <https://github.com/seraphis-migration/monero/releases> and pin the
**latest beta tag** (do not track "latest" blindly — record the exact tag
here once chosen, and only move it deliberately).

```bash
# Example — replace <TAG> with the pinned beta tag from the releases page.
STRESSNET_TAG="<TAG>"
cd /tmp
curl -LO "https://github.com/seraphis-migration/monero/releases/download/${STRESSNET_TAG}/monero-linux-x64-${STRESSNET_TAG}.tar.bz2"
# Verify the checksum/signature published on the release page before unpacking.
tar xjf "monero-linux-x64-${STRESSNET_TAG}.tar.bz2"
sudo install -m 0755 monero-*/monerod monero-*/monero-wallet-rpc monero-*/monero-wallet-cli /usr/local/bin/
```

Create the runtime directories:

```bash
sudo useradd --system --home /var/lib/monero-stressnet --shell /usr/sbin/nologin monero-stressnet
sudo mkdir -p /var/lib/monero-stressnet /etc/monero-stressnet
sudo chown monero-stressnet:monero-stressnet /var/lib/monero-stressnet
```

## 3. systemd: `monerod-stressnet.service`

`/etc/systemd/system/monerod-stressnet.service`:

```ini
[Unit]
Description=FCMP++ stressnet daemon (seraphis-migration/monero)
After=network-online.target
Wants=network-online.target

[Service]
User=monero-stressnet
Group=monero-stressnet
Type=simple
ExecStart=/usr/local/bin/monerod \
    --testnet \
    --non-interactive \
    --data-dir /var/lib/monero-stressnet \
    --rpc-restricted-bind-ip 0.0.0.0 \
    --rpc-restricted-bind-port 28089 \
    --confirm-external-bind
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

> **IMPORTANT:** the pinned release's README typically mandates extra flags
> for the stressnet — seed nodes (`--add-exclusive-node` / `--seed-node`),
> a custom network ID, or hard-fork height overrides. Copy those flags
> verbatim from the pinned tag's README into `ExecStart` above. The
> stressnet will not sync without them.

The unrestricted RPC defaults to `127.0.0.1:28081` under `--testnet`; the
faucet wallet uses that loopback port.

## 4. systemd: `faucet-wallet-rpc.service`

Create the faucet wallet once (testnet):

```bash
sudo -u monero-stressnet /usr/local/bin/monero-wallet-cli --testnet \
    --generate-new-wallet /var/lib/monero-stressnet/faucet \
    --daemon-address 127.0.0.1:28081
```

Store the wallet password in a root-only file:

```bash
sudo install -m 0600 -o root -g root /dev/null /etc/monero-stressnet/faucet.pass
# then write the password into it (single line, no trailing newline needed)
sudo nano /etc/monero-stressnet/faucet.pass
```

`/etc/systemd/system/faucet-wallet-rpc.service`:

```ini
[Unit]
Description=FCMP++ stressnet faucet wallet RPC
After=monerod-stressnet.service
Requires=monerod-stressnet.service

[Service]
# Runs as root so it can read the 0600 root:root password file; the
# wallet only ever holds tXMR (see risk acceptance at the top).
User=root
Type=simple
ExecStart=/usr/local/bin/monero-wallet-rpc \
    --testnet \
    --rpc-bind-ip 127.0.0.1 \
    --rpc-bind-port 28088 \
    --wallet-file /var/lib/monero-stressnet/faucet \
    --password-file /etc/monero-stressnet/faucet.pass \
    --daemon-address 127.0.0.1:28081 \
    --disable-rpc-login
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

> **Why `--disable-rpc-login` is safe here:** the wallet RPC binds to
> loopback only and is reachable from outside exclusively through the
> cloudflared tunnel, which enforces a Cloudflare Access **service token**
> in front of it (section 5). Auth happens at the Access layer; adding RPC
> digest auth on top would just mean a second credential to rotate inside
> the Workers env for no extra boundary. Nothing on the public interface
> can reach port 28088 (section 7).

Enable both units:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now monerod-stressnet faucet-wallet-rpc
```

## 5. cloudflared tunnel (faucet RPC only)

Install `cloudflared`, authenticate, and create a tunnel that exposes
**only** the wallet RPC on loopback — the stressnet daemon RPC (28089) is
served directly, not through the tunnel.

```bash
cloudflared tunnel login
cloudflared tunnel create stressnet-faucet
```

`/etc/cloudflared/config.yml`:

```yaml
tunnel: stressnet-faucet
credentials-file: /root/.cloudflared/<TUNNEL_UUID>.json

ingress:
  - hostname: stressnet-faucet.kyc.rip
    service: http://127.0.0.1:28088
  - service: http_status:404
```

```bash
cloudflared tunnel route dns stressnet-faucet stressnet-faucet.kyc.rip
sudo cloudflared service install
sudo systemctl enable --now cloudflared
```

In the Cloudflare Zero Trust dashboard:

1. Create a **service token** (Access → Service Auth → Service Tokens),
   e.g. `stressnet-faucet-worker`.
2. Create an **Access application** for `stressnet-faucet.kyc.rip` with a
   policy of action **Service Auth** that allows only that service token.

Record the token into the Workers env (names match the faucet route in
`api/src/routes/faucet.ts` — the same pair already used for the mainnet
wallet proxy):

```bash
cd kyc-rip/api
npx wrangler secret put CF_ACCESS_CLIENT_ID      # token Client ID
npx wrangler secret put CF_ACCESS_CLIENT_SECRET  # token Client Secret
npx wrangler secret put FAUCET_RPC_URL           # https://stressnet-faucet.kyc.rip/json_rpc
npx wrangler secret put FAUCET_ENABLED           # 'true' to open the faucet
npx wrangler secret put FAUCET_EPOCH             # '1' initially; bump on chain wipes
```

> If the mainnet wallet proxy and the faucet end up behind **different**
> Access applications, allow the same service token in both apps so one
> credential pair serves both upstreams.

## 6. Recovery after a stressnet chain reset

Stressnets get wiped. When the pinned release announces a reset (or the
chain forks unrecoverably):

```bash
# 1. Stop services
sudo systemctl stop faucet-wallet-rpc monerod-stressnet

# 2. Wipe the chain data (keep the wallet files!)
sudo rm -rf /var/lib/monero-stressnet/testnet
#    NOTE: do NOT delete /var/lib/monero-stressnet/faucet* (wallet + keys).
#    If the reset ships new binaries, reinstall per section 2 first.

# 3. Resync
sudo systemctl start monerod-stressnet
#    wait until synced: monerod --testnet status

# 4. Rescan the wallet against the fresh chain
sudo systemctl start faucet-wallet-rpc
curl -s http://127.0.0.1:28088/json_rpc -d \
  '{"jsonrpc":"2.0","id":"0","method":"rescan_blockchain"}' \
  -H 'Content-Type: application/json'
```

Then **bump `FAUCET_EPOCH`** in the Workers env (e.g. `1` → `2`). The
faucet keys all per-address/per-IP/daily counters under
`faucet:${FAUCET_EPOCH}:…`, so bumping the epoch resets "one claim per
address ever" — necessary because every address's claim is meaningless on
the new chain.

```bash
cd kyc-rip/api && npx wrangler secret put FAUCET_EPOCH   # new value, e.g. '2'
```

## 7. Firewall

```bash
# Public stressnet RPC for wallet clients
sudo ufw allow 28089/tcp comment 'stressnet restricted RPC'
# Wallet RPC must never be reachable directly — loopback + tunnel only
sudo ufw deny 28088/tcp comment 'faucet wallet RPC (cloudflared only)'
# P2P (testnet default 28080) — allow so the daemon can peer
sudo ufw allow 28080/tcp comment 'stressnet p2p'
sudo ufw enable
```

Alternatively, serve the restricted RPC as a **Tor hidden service** instead
of (or in addition to) clearnet 28089 — point the HS at
`127.0.0.1:28089` in `torrc` and skip the public allow rule.

## 8. Sanity checks

```bash
# Daemon synced?
curl -s http://127.0.0.1:28081/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_info"}' -H 'Content-Type: application/json' | head -c 400

# Wallet reachable + funded? (unlocked_balance in piconero)
curl -s http://127.0.0.1:28088/json_rpc -d '{"jsonrpc":"2.0","id":"0","method":"get_balance","params":{"account_index":0}}' -H 'Content-Type: application/json'

# End-to-end via the Worker
curl -s https://api.kyc.rip/v1/faucet/stressnet/health
```

Fund the faucet wallet with mined/donated tXMR; the Worker refuses to
dispense below 1.5 tXMR unlocked (`EXHAUSTED`) and pays out 0.5 tXMR per
claim, capped at 5 tXMR per UTC day globally.
