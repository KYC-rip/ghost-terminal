# RipleyOS VPN / network-privacy panel — implementation spec

Status: **implemented through native auth/control and the additive ROS transport-policy increment;
Linux packaging/integration tests and packaged macOS signing remain release work.**
Branch: `feat/ros-integration`. Host: Tauri v2 (Rust, `src-tauri/`). Renderer: RipleyOS (Vite/React PWA) served into the webview.

## Non-negotiables (from the two Codex reviews)

1. **Tauri IPC is the trust boundary** — `#[tauri::command]` + capabilities replace any localhost helper. Each new command must be added to all three enforcement points: `build.rs` `APP_COMMANDS`, `tauri::generate_handler!` in `lib.rs`, and a capability grant.
2. **Bump Tauri 2.10.3 → 2.11.1** (remote-origin custom-command ACL fix) before shipping. Requires `cargo update -p tauri --precise 2.11.1` on a machine with the Rust toolchain.
3. **Never run the Tauri/WebView process as root.** The app stays unprivileged. On Linux,
   kernel/network mutations go to a separate root-owned broker with peer-credential/Polkit checks
   and only `CAP_NET_ADMIN`. On macOS, where no Apple signing identity is available for a
   NetworkExtension during development, each mutation launches a one-shot, administrator-authorized
   native helper. Both accept structured operations only; imported profile text is parsed into a
   canonical configuration and is never executed as shell.
4. **Remote renderer is untrusted.** `ros_remote` (including the localhost dev override) and `ros_local` may read status and *open* a host-owned VPN window, but neither receives mutation commands. The repo's threat model treats even the OTA bundle as untrusted (see the capability files — no fs/shell). Therefore **all VPN mutations (import, connect, disable-kill-switch) require a native, host-owned confirmation window** (mirror the existing wallet-op confirm pattern), not renderer trust.
5. **Host support:** Linux uses the persistent broker. macOS uses upstream Homebrew
   `wireguard-tools` plus a per-action authorization prompt and a dedicated PF anchor. A signed
   NetworkExtension remains the preferred packaged macOS architecture once Apple entitlements are
   available. Windows (WFP) is later.
6. **VPN-over-Tor is OUT of v1.** Plain WireGuard and the supplied OpenVPN profiles use UDP; Tor carries TCP streams only. VPN-over-Tor needs a UDP-over-TCP/obfuscation transport = separate project. **Tor-over-VPN** (ROS's Arti traffic inside an established host VPN) is the supported variant.

## Components

### `broker` (new root-owned crate) — the only privileged code
- Runs as a minimal systemd service with `CAP_NET_ADMIN` (+ `CAP_NET_RAW` if needed), no shell.
- Unix socket `/run/ripley-vpn.sock`, root:`ripley` group perms; verify peer creds (SO_PEERCRED).
  Strong operations invoke Polkit with the connecting uid/pid/start-time, so PID reuse cannot
  transfer an interactive authorization to another process. Install `polkit/org.ripley.vpn.policy`
  and ensure the desktop user is in the `ripley` group.
- Structured request enum: `Up{iface_cfg}`, `Down`, `Status`, `KillSwitchOn/Off`, `Recover`.
- Owns: wg interface (via `wireguard` netlink or `wg`/`ip` with fixed args), the dedicated nftables table, per-link DNS, IPv6 policy, crash-recovery journal.

### `src-tauri/src/commands/vpn.rs` (unprivileged) — talks to broker
- Commands: `vpn_connect`, `vpn_disconnect`, `vpn_status`, `vpn_set_killswitch`, `vpn_recover`, `vpn_emergency_restore`, `vpn_open_window`.
- Register in `commands/mod.rs` (`pub mod vpn;`), `lib.rs` `generate_handler!`, `build.rs` `APP_COMMANDS`.
- `vpn_open_window` creates/focuses a dedicated local `vpn-control` webview. That window has its
  own narrow capability and never loads ROS/remote content. Mutations require confirmation there;
  the ROS renderer can only request that this host surface be shown.

### macOS one-shot backend
- Requires `brew install wireguard-tools`; resolves only fixed Homebrew tool paths.
- The same signed native executable enters `--vpn-macos-helper` before Tauri starts, after an
  administrator prompt. It accepts one request on a random mode-0600 Unix socket, verifies the
  connecting uid with `getpeereid`, replies, and exits.
- The shared strict WireGuard parser renders a canonical root-only config. No profile/private key
  appears in argv; the transient file is replaced with a key-free stub immediately after bring-up.
- PF anchor `com.apple/ripley-vpn` is enabled and loaded before `wg-quick up`, allowing only
  loopback, DHCP/NDP, and the pinned endpoint. The live `utun` is allowed only after it is observed.
  A first-connect failure (including no handshake within 15 seconds) automatically tears down the
  attempted interface and flushes the anchor back to clearnet. Only a failed cleanup is retained as
  `ERROR_BLOCKED`/cleanup-required, with an Emergency restore path.
- Public status is readable without prompting. Connect, disconnect, kill-switch, and recovery
  mutations require a fresh macOS administrator authorization. Every mutation start, terminal
  phase, and exact error/restoration result is emitted through `core-log` into RipleyOS's integrated
  system console as well as stdout.

### Capabilities
- `ros_remote.json`: read status + open the host window only; no mutation perms.
- `ros_local.json`: `allow-vpn-status` + `allow-vpn-open-window` only (read + open host UI). Mutations are host-driven, not granted to the renderer.
- New permissions declared in `build.rs` manifest, kept in sync with `native.ts`.
- `vpn_control.json`: local `vpn-control` window only; structured VPN commands and no wallet,
  filesystem, shell, keychain, or generic network permissions.

### RipleyOS renderer
- A VPN app under `src/os/apps/Vpn/` + a status chip; drives via the `platform.network` seam in `src/os/platform/`. Full control only in the host-owned window; the embedded ROS view shows status + an "Open VPN" button.

## Additive transport policy (requested vs observed)

`routingMode` remains exactly `tor | clearnet | custom`. It is the legacy app-level transport
contract and MUST NOT be widened: older scanner/browser readers historically treated unknown
strings as clearnet. Those readers now refuse unknown values.

The independent VPN expectation is persisted additively:

```json
{
  "routingMode": "tor",
  "transportPolicy": { "v": 2, "vpn": "require" }
}
```

Supported combinations are clearnet, Tor, custom SOCKS5, VPN (`clearnet + require`), and
Tor-over-VPN (`tor + require`). An older shell ignores `transportPolicy` and safely retains the
app leg. The ROS Settings status card is computed from requested policy plus live Tor and broker
observations; it never calls a requested path “verified” merely because a button was pressed.
Requiring VPN in ROS is an assertion, not a kill-switch: only the broker can enforce host egress.

VPN-over-Tor is deliberately not representable. The UI names the UDP/Tor limitation rather than
silently delivering the opposite chain.

## Config parser (Rust, in broker) — parse as DATA
- Size cap; exactly one `[Interface]` + one `[Peer]`; reject duplicate/unknown fields.
- **Reject `PreUp/PostUp/PreDown/PostDown` and `SaveConfig`** (wg-quick executes these → RCE). Never run `wg-quick` on imported content.
- Validate base64 key lengths (priv/pub/PSK), CIDRs, endpoint host:port, MTU/keepalive bounds.
- Accept only full-tunnel (`AllowedIPs` incl. `0.0.0.0/0`); if no `::/0`, block IPv6 entirely.
- Redact + zeroize private/PSK material; store root-only.

## Kill-switch (proactive, atomic)
- Install blocking nft rules **before** creating routes / starting wg (fail-closed).
- Dedicated idempotent nftables table; do not replace user rules.
- Permit only: loopback, required DHCP/NDP, the **exact** WireGuard endpoint (resolved+pinned, not its whole IP range), and tunnel traffic.
- Serialize state under one lock; persist a crash-recovery journal.
- On connect failure: tear down partial tunnel/DNS, **keep the block**.
- Disconnect with kill-switch on = stays offline; restoring clearnet needs the host-owned confirm.
- `vpn_recover` clears stale rules (also an uninstall step).

## DNS / IPv6 (Linux)
- Target `systemd-resolved` per-link DNS with route-only `~.`; do **not** overwrite `/etc/resolv.conf`.
- Allow configured DNS only through the tunnel; block phys-iface DNS on TCP/UDP 53 + 853.
- Resolve the endpoint before sealing egress, then pin the resolved address.
- IPv6: fully configure it or fully block it — never IPv4-VPN + ambient IPv6.
- Exit-IP check runs through normal OS routing, **not** the Arti/Tor transport.

## Status state machine
`DISCONNECTED_OPEN · DISCONNECTED_BLOCKED · CONNECTING_BLOCKED · CONNECTED · DEGRADED_BLOCKED · ERROR_BLOCKED`

## Linux release blockers
Trusted local renderer only · unprivileged Tauri + minimal broker · Tauri 2.11.1 · defined resolver/distro matrix · crash/reboot/uninstall recovery · integration tests: forced interface-drop, endpoint-change, DNS, IPv6, suspend/resume, concurrent-command.

## Build note
The macOS backend compiles and its canonicalization/PF syntax tests run against the host `pfctl`.
An end-to-end connect still needs an operator-approved live profile test, and a packaged release
needs an Apple signing identity. The Linux broker is checked against its Linux target; live
nftables/WireGuard/Polkit integration still requires a disposable Linux VM and remains a release
gate. Unit checks alone do not prove kernel-route behaviour on either platform.
