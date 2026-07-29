# RipleyOS VPN / network-privacy panel — implementation spec

Status: **implemented through the native auth/control increment; Linux packaging and live broker
integration tests remain release work.**
Branch: `feat/ros-integration`. Host: Tauri v2 (Rust, `src-tauri/`). Renderer: RipleyOS (Vite/React PWA) served into the webview.

## Non-negotiables (from the two Codex reviews)

1. **Tauri IPC is the trust boundary** — `#[tauri::command]` + capabilities replace any localhost helper. Each new command must be added to all three enforcement points: `build.rs` `APP_COMMANDS`, `tauri::generate_handler!` in `lib.rs`, and a capability grant.
2. **Bump Tauri 2.10.3 → 2.11.1** (remote-origin custom-command ACL fix) before shipping. Requires `cargo update -p tauri --precise 2.11.1` on a machine with the Rust toolchain.
3. **Never run the Tauri/WebView process as root.** The app + `VpnManager` stay unprivileged. Kernel/network mutations go to a **separate root-owned broker** (own binary/crate) over a Unix socket / D-Bus, with peer-credential/Polkit checks and only `CAP_NET_ADMIN`. The broker accepts **structured operations only** — never shell strings, config paths, or nft snippets. A WebView exploit must not become arbitrary root.
4. **Remote renderer is untrusted.** `ros_remote` (Cloudflare `app.ros.rip`) gets **zero** VPN permissions — not even status. `ros_local` (the signed `ros://` OTA window) may read status and *open* a host-owned VPN window, but this repo's own threat model treats even the OTA bundle as untrusted (see `capabilities/ros_local.json` — no fs/shell). Therefore **all VPN mutations (import, connect, disable-kill-switch) require a native, host-owned confirmation window** (mirror the existing wallet-op confirm pattern), not renderer trust.
5. **v1 = Linux only.** macOS (NetworkExtension) and Windows (WFP) are later.
6. **Over-Tor is OUT of v1.** Plain WireGuard is UDP; Tor carries TCP streams only. Tor→VPN needs a UDP-over-TCP/obfuscation transport = separate project. VPN→Tor (ROS's Arti traffic inside an established VPN) is the doable variant, documented separately.

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
- Commands: `vpn_import_config`, `vpn_connect`, `vpn_disconnect`, `vpn_status`, `vpn_set_killswitch`, `vpn_recover`.
- Register in `commands/mod.rs` (`pub mod vpn;`), `lib.rs` `generate_handler!`, `build.rs` `APP_COMMANDS`.
- Mutations open a host-owned native confirmation modal before forwarding to the broker; the ROS
  renderer can only request that the host surface be shown via `vpn:open`.

### Capabilities
- `ros_remote.json`: **no** vpn perms.
- `ros_local.json`: `allow-vpn-status` + `allow-vpn-open-window` only (read + open host UI). Mutations are host-driven, not granted to the renderer.
- New permissions declared in `build.rs` manifest, kept in sync with `native.ts`.

### RipleyOS renderer
- A VPN app under `src/os/apps/Vpn/` + a status chip; drives via the `platform.network` seam in `src/os/platform/`. Full control only in the host-owned window; the embedded ROS view shows status + an "Open VPN" button.

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

## DNS / IPv6 (Linux v1)
- Target `systemd-resolved` per-link DNS with route-only `~.`; do **not** overwrite `/etc/resolv.conf`.
- Allow configured DNS only through the tunnel; block phys-iface DNS on TCP/UDP 53 + 853.
- Resolve the endpoint before sealing egress, then pin the resolved address.
- IPv6: fully configure it or fully block it — never IPv4-VPN + ambient IPv6.
- Exit-IP check runs through normal OS routing, **not** the Arti/Tor transport.

## Status state machine
`DISCONNECTED_OPEN · DISCONNECTED_BLOCKED · CONNECTING_BLOCKED · CONNECTED · DEGRADED_BLOCKED · ERROR_BLOCKED`

## Linux-v1 release blockers
Trusted local renderer only · unprivileged Tauri + minimal broker · Tauri 2.11.1 · defined resolver/distro matrix · crash/reboot/uninstall recovery · integration tests: forced interface-drop, endpoint-change, DNS, IPv6, suspend/resume, concurrent-command.

## Build note
No Rust toolchain is present on the current build box (`cargo`/`rustc` absent), so the privileged Rust cannot be compiled/verified here. Build the broker + `vpn.rs` on a machine with `rustup`, or install it here first. This is security-critical privileged code — do not merge unverified.
