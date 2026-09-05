# 📟 RIPLEY_TERMINAL :: FEATURE_LOG

This file tracks the tactical capabilities of the Ripley Terminal.

## 🛡️ Security & Privacy (Core)
- [x] **Mandatory Tor Routing**: All outgoing traffic is forced through SOCKS5 Tor tunnels. No Clearnet fallback allowed.
- [x] **Vault Lock**: Master Password encryption for local identity files. No keys are stored in plain text.
- [x] **Unlock Resilience**: Automatic retry mechanism (5 attempts) to handle RPC connection race conditions during fast unlocks.
- [x] **Auto-Lock Timeout**: Securely close and lock the identity after a period of inactivity (default 10 min).
- [x] **Persistent Storage**: Physical `.keys` file management with auto-save checkpoints during sync.
- [x] **Hardware Isolation**: Local environment execution with zero reliance on centralized database servers.
- [x] **Production Hardening**: Mandatory safety locks on reload shortcuts (`Cmd+R`, `F5`) in packaged builds to prevent UI state loss.

## 🌪️ On-Chain Privacy (Tactical)
- [x] **One-Click Churn**: Sweep entire unlocked balance back to self via fresh subaddresses to break deterministic links.
- [x] **Tactical Splinter**: Shatter large UTXOs into multiple smaller fragments across new stealth addresses to prevent "toxic change" and net-worth leakage.
- [x] **Individual Coin Vanishing**: Selectively sweep individual UTXOs (Deterministic Outputs) back to the primary address using `sweep_single` to isolate trailing transactions.
- [x] **Subaddress Vanishing**: Sweep all outputs from a specific subaddress to a freshly generated one using `sweep_all` with `subaddr_indices`, breaking on-chain linkability at the subaddress level.
- [x] **Native Sweep All**: Extinguish entire account balances with optimized RPC calls and real-time fee estimation for maximum efficiency.
- [x] **Coin Control (UTXO)**: Detailed list of every deterministic output (unspent) with unlock status and Key Image tracking.
- [x] **Forced Subaddressing**: Mandatory new subaddress generation for every receive request to prevent metadata leakage via address reuse.
- [x] **Identity Labeling**: Attach purpose-driven labels to subaddresses for precise ledger management.
- [x] **Dust Filtering**: Reactive "DUST_FILTERED" toggle in the Address List header to hide zero-balance subaddresses and maintain focus.
- [x] **Per-Subaddress Balances**: Real-time balance display per subaddress via `getbalance` RPC with `per_subaddress` data.
- [x] **Custom Fee Settings**: Full priority control (Unimportant, Normal, Elevated, Priority) for optimal on-chain extraction speed.

## 🆔 Identity Management
- [x] **Multi-Identity Support**: Create and manage multiple isolated cryptographic vaults with distinct passwords and files.
- [x] **Account Indexing**: Create and switch between multiple deterministic accounts within the same cryptographic identity.
- [x] **Identity Switcher**: Secure hot-swapping between identities via the tactical authorization screen.
- [x] **Identity Ledger**: High-density transaction history with flow analysis, block heights, network fees, and destination decoding.
- [x] **Expandable Histories**: Deep dive into individual transactions to view exact confirmations, recipient address splits, payment IDs, and robust privacy-protected fallbacks.
- [x] **Subaddress Recognition**: Transaction ledger automatically maps incoming and outgoing transactions to known subaddresses, replacing raw hashes with friendly labels.

## 📊 Tactical Interface
- [x] **Sidebar Navigation**: Professional layout for rapid access to Vault, Swap, and Intelligence tools.
- [x] **Global Theme Support**: Semantic Dark (Tactical), Light (Financial), and System modes with optimized contrast rendering.
- [x] **Custom Background Skins**: Upload custom local images (JPG/PNG/GIF) with opacity and position controls to personalize the terminal interface.
- [x] **Local Intel Feed**: Real-time XMR market data and network pulse (Hashrate, Fees, Mempool).
- [x] **Local Chart Rendering**: Integrated `lightweight-charts` engine for theme-aware, interactive market analysis.
- [x] **Address Detail Modal**: Click any subaddress row to open a full-featured modal showing QR code, address, and payment link.
- [x] **Protocol Console**: Toggleable system log viewer via `Cmd+Shift+T` with copiable diagnostic output for troubleshooting the uplink.
- [x] **Global Keybindings**: Remappable tactical shortcuts (LOCK, SEND, SYNC, etc.) for high-speed terminal operations.
- [x] **Protocol Deep Link Handling**: Native support for `monero:` and `ghost:` URIs—clicking a payment link on kyc.rip or any tactical portal instantly populates the Dispatch modal.
- [x] **Intelligent Network Selection**: Daemon-level persistence for Mainnet and Stagenet with automatic node discovery per network environment.
- [x] **Tactical Action Modals**: Dedicated interface overlays for executing sensitive on-chain actions like UTXO Churns and Splinters without cluttering the main UI.

## 💸 Asset Bridging
- [x] **Ghost_Swap Integration**: Quote and execute non-custodial asset swaps directly into your private vault via kyc.rip routing.
- [x] **Cross-Chain Payment Links**: Generate shareable `kyc.rip/swap?source=pay` links that let external payers choose any asset — funds settle automatically into your XMR subaddress.
- [x] **Ghost Send (Reverse/Fixed)**: Refactored delivery logic to support fixed-output swaps—input the exact amount you want the receiver to get, and the terminal calculates the XMR payload.
- [x] **Ghost Persistence (Ledger)**: On-chain trades are recorded locally and mapped to TX hashes in the ledger; includes a **Ghost** badge and direct status tracker link with a 7-day TTL.
- [x] **Sized Status Windows**: External status trackers launch in a calibrated 940x820 viewport for optimal visualization of trade progress.
- [x] **Address Book**: Securely archive external Monero addresses with alias support for rapid dispatching.
- [x] **Send From Subaddress**: Dispatch XMR or execute Ghost Sends scoped to a specific subaddress for granular coin control.
- [x] **xmr.bio Resolver**: Send funds instantly to Twitter handles—automatically fetching Monero addresses from `api.xmr.bio` and displaying beautiful profile cards inline.
- [x] **Dynamic Send Controls**: Real-time unlocked balance display, "Sweep All" integration, and percentage-based quick-select (25%, 50%, 75%, 100%) for high-speed dispatching.

## 📦 Deployment & Execution
- [x] **Automated Packaging**: Cross-platform Tauri 2 build system (macOS `.dmg`/`.app`, Windows `.msi`/`.exe`, Linux `.deb`/`.AppImage`).
- [x] **Secure Subtree CI/CD**: Custom deployment scripts that scrub the Git history for anonymity and push to a clean, public-facing repository natively.
- [x] **Update Intelligence**: Automated update discovery with support for optional pre-release builds and graceful error handling.

## 🤖 AI Agent Gateway (Beta)
- [x] **Secure RPC Uplink**: Local HTTP gateway (port 38084) allowing AI agents to interact with Monero wallets via a secure API key.
- [x] **Account Isolation**: Granularly select which specific Monero account the AI agent can access, preventing unauthorized vault-wide exposure.
- [x] **Spend Limits**: Daily and session-based XMR limits to prevent agent runaway or overspending.
- [x] **Real-time Activity Feed**: High-density logs showing every agent RPC call, balance query, and blocked attempt directly in the UI.
- [x] **Multi-Platform Uplink**: Pre-configured installation commands for Gemini, OpenClaw, and Claude Desktop.
- [x] **Network Discovery**: Automatic network detection (Mainnet/Stagenet) for AI agents to prevent cross-network friction.
- [x] **Animated Mascot**: Dynamic "Ripley" cyber-cat with scanning animations and theme-aware glowing effects.
- [x] **Collapsible Knowledge Base**: Streamlined UI that hides setup instructions once configured to maximize activity visibility.

---
*Last Updated: 2026-03-01 (v1.0.31)*
