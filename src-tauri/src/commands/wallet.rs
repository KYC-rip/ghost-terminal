use crate::emit_log;
use crate::wallet::transact;
use crate::wallet::{
    BlockScanner, MoneroAccount, PreparedTx, SubaddressInfo, SyncStatus, Transaction,
    TxDestination, WalletOutput, WalletState,
};
use monero_address::MoneroAddress;
use monero_daemon_rpc::prelude::*;
use monero_daemon_rpc::{HttpTransport, MoneroDaemon};
use monero_oxide::transaction::Timelock;
use tauri::{AppHandle, Manager, State};

// ── Wallet Lifecycle ──

#[tauri::command]
pub async fn create_wallet(
    state: State<'_, WalletState>,
    name: String,
    password: String,
    seed: Option<String>,
    restore_height: Option<u64>,
) -> Result<serde_json::Value, String> {
    let mnemonic = state
        .create_wallet(&name, &password, seed.as_deref(), restore_height)
        .await?;
    Ok(serde_json::json!({ "success": true, "seed": mnemonic }))
}

#[tauri::command]
pub async fn open_wallet(
    app: AppHandle,
    state: State<'_, WalletState>,
    pool: State<'_, crate::wallet::SyncPool>,
    name: String,
    password: String,
) -> Result<serde_json::Value, String> {
    emit_log(
        &app,
        "Wallet",
        "info",
        &format!("🔓 Unlocking vault: {}...", name),
    );

    // Light re-unlock: if this same wallet is already resident with a live
    // background scanner (soft-locked), just restore the spend key and keep the
    // running scan + its in-memory progress — don't clear outputs or restart
    // (which would reset the scan and lose progress).
    if state.is_active_identity(&name).await && state.has_scanner().await {
        state.restore_spend_key(&name, &password).await?;
        refresh_pool(&app, &state, &pool, &name, &password).await;
        emit_log(
            &app,
            "Wallet",
            "success",
            "✅ Vault re-unlocked — background sync continued.",
        );
        return Ok(serde_json::json!({ "success": true }));
    }

    state.unlock(&name, &password).await?;
    emit_log(
        &app,
        "Wallet",
        "success",
        "✅ Vault unlocked. Deriving keys...",
    );

    // Spend-detection sanity: log whether the spend key derives the (already cached)
    // outputs' keys. Fires immediately on unlock — no rescan needed. Filter "KIDIAG".
    if let Some(diag) = state.first_output_kidiag().await {
        emit_log(
            &app,
            "Wallet",
            "warn",
            &format!("🔧 KIDIAG-sanity (on unlock) {}", diag),
        );
    }

    let scan_height = state.get_scan_height().await;
    if scan_height == u64::MAX {
        emit_log(
            &app,
            "Sync",
            "info",
            "📦 New wallet — starting scanner near daemon tip...",
        );
    } else {
        emit_log(
            &app,
            "Sync",
            "info",
            &format!("📦 Resuming scan from height {}...", scan_height),
        );
    }

    let app_clone = app.clone();
    BlockScanner::start(app_clone, "", "", scan_height).await?;

    // Watch tier: persist this identity's VIEW pair (never spend material) so
    // the next launch can start watch-only sync before any unlock. Consent-gated
    // (watchSync) and encrypt-or-don't-write (save_watch refuses without the
    // device key). Best-effort — a keychain hiccup must not fail the unlock.
    if crate::wallet::scanner::read_config_bool(&app, "watchSync") {
        match state.derive_view_pair_and_parts_for(&name, &password).await {
            Ok((_vp, spend_pub, view_sec)) => {
                let data_dir = app
                    .path()
                    .app_data_dir()
                    .unwrap_or_else(|_| std::path::PathBuf::from("."));
                if let Err(e) =
                    crate::wallet::storage::save_watch(&data_dir, &name, &spend_pub, &view_sec)
                {
                    log::warn!("watch store write for {name} failed: {e}");
                }
            }
            Err(e) => log::warn!("watch parts derivation for {name} failed: {e}"),
        }
    }

    refresh_pool(&app, &state, &pool, &name, &password).await;

    Ok(serde_json::json!({ "success": true }))
}

/// Reconcile the background sync pool with the "Sync all wallets" setting. When
/// ON: stop the active wallet (WalletState scans it), then try the unlock
/// password against every OTHER vault (in memory only — never stored) and start
/// background sync for each that decrypts; also resume any wallet discovered
/// earlier this session. When OFF: stop the whole pool.
pub(crate) async fn refresh_pool(
    app: &AppHandle,
    state: &WalletState,
    pool: &crate::wallet::SyncPool,
    active_id: &str,
    password: &str,
) {
    if !crate::wallet::scanner::read_config_bool(app, "sync_all_wallets") {
        pool.stop_all().await;
        return;
    }
    // The active wallet is scanned by WalletState — never double-scan it.
    pool.stop(active_id).await;

    let watch_on = crate::wallet::scanner::read_config_bool(app, "watchSync");
    let data_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    for id in crate::commands::identity::identity_ids(app) {
        if id == active_id {
            continue;
        }
        // Same-password wallets decrypt; others are skipped (start when opened).
        if let Ok((view_pair, spend_pub, view_sec)) =
            state.derive_view_pair_and_parts_for(&id, password).await
        {
            // Watch tier: pooled identities persist their view pair too, so the
            // next launch boot-syncs them all (encrypt-or-don't-write inside).
            if watch_on {
                if let Err(e) =
                    crate::wallet::storage::save_watch(&data_dir, &id, &spend_pub, &view_sec)
                {
                    log::warn!("watch store write for {id} failed: {e}");
                }
            }
            pool.start(app, id, view_pair, 0).await;
        }
    }
    // Re-pool wallets discovered earlier this session (e.g. the previously-active one).
    pool.resume_all_except(app, active_id).await;
}

#[tauri::command]
pub async fn close_wallet(state: State<'_, WalletState>) -> Result<(), String> {
    state.lock().await;
    Ok(())
}

#[tauri::command]
pub async fn get_mnemonic(app: AppHandle, state: State<'_, WalletState>) -> Result<String, String> {
    // FUND SAFETY: the seed phrase is the whole wallet. Revealing it requires an
    // OS-level confirmation the renderer JS can't fake — so no app can exfiltrate the
    // recovery phrase silently, even via a direct invoke. (Tauri injects app + state.)
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let ok = app
            .dialog()
            .message("Reveal your secret recovery phrase?\n\nAnyone who sees it can steal ALL funds. Only continue if you personally requested this.")
            .title("Reveal seed phrase")
            .buttons(MessageDialogButtons::OkCancelCustom("Reveal".into(), "Cancel".into()))
            .blocking_show();
        if !ok {
            return Err("Seed reveal cancelled".into());
        }
    }
    state.get_mnemonic().await
}

// ── Account Operations ──

#[tauri::command]
pub async fn get_accounts(state: State<'_, WalletState>) -> Result<Vec<MoneroAccount>, String> {
    let mut accounts = state.get_accounts().await;
    // Inject each account's live balance as ATOMIC piconero strings (the renderer
    // formats them). Per-account now that multi-account is real; the sum matches the
    // wallet-wide total.
    let tip = state.tip_height().await;
    for account in accounts.iter_mut() {
        let (total, unlocked) = state.balances_for_account(account.index, tip).await;
        account.balance = total.to_string();
        account.unlocked_balance = unlocked.to_string();
    }
    Ok(accounts)
}

#[tauri::command]
pub async fn create_account(
    state: State<'_, WalletState>,
    label: String,
) -> Result<serde_json::Value, String> {
    let account = state.create_account(&label).await?;
    Ok(serde_json::json!({ "index": account.index, "address": account.base_address }))
}

#[tauri::command]
pub async fn rename_account(
    state: State<'_, WalletState>,
    account_index: u32,
    new_label: String,
) -> Result<(), String> {
    state.rename_account(account_index, &new_label).await
}

#[tauri::command]
pub async fn get_balance(
    state: State<'_, WalletState>,
    account_index: u32,
) -> Result<serde_json::Value, String> {
    // Return ATOMIC piconero — the renderer (tauriBridge → walletService.formatXmr)
    // divides by 1e12 itself. Returning pre-formatted XMR here caused a double
    // conversion that displayed every balance as ~0. Per-account balance; the sum over
    // all accounts equals the wallet-wide total.
    let tip = state.tip_height().await;
    let (total, unlocked) = state.balances_for_account(account_index, tip).await;
    Ok(serde_json::json!({
        "total": total,
        "unlocked": unlocked
    }))
}

#[tauri::command]
pub async fn get_height(state: State<'_, WalletState>) -> Result<u64, String> {
    let status = state.get_sync_status().await;
    Ok(status.height)
}

/// Re-race the node pool and reconnect the scanner, without touching routing/config.
/// For when the current node is slow/unresponsive: bumps the scanner generation (the
/// old scan loop sees the mismatch and stops) and starts a fresh node race from the
/// current height — same mechanism as the automatic re-race on scan failure.
#[tauri::command]
pub async fn reselect_node(app: AppHandle, state: State<'_, WalletState>) -> Result<(), String> {
    let height = state.get_sync_status().await.height;
    emit_log(
        &app,
        "Network",
        "info",
        "🔄 Re-selecting node — racing for a fresh connection…",
    );
    crate::wallet::scanner::BlockScanner::start(app.clone(), "", "", height).await
}

// ── Address Operations ──

#[tauri::command]
pub async fn get_subaddresses(
    state: State<'_, WalletState>,
    account_index: u32,
) -> Result<Vec<SubaddressInfo>, String> {
    let tip = state.tip_height().await;
    Ok(state.get_subaddresses(account_index, tip).await)
}

#[tauri::command]
pub async fn create_subaddress(
    state: State<'_, WalletState>,
    label: Option<String>,
    account_index: Option<u32>,
) -> Result<String, String> {
    let info = state
        .create_subaddress(
            account_index.unwrap_or(0),
            label.as_deref().unwrap_or("Payment"),
        )
        .await?;
    Ok(info.address)
}

#[tauri::command]
pub async fn set_subaddress_label(
    state: State<'_, WalletState>,
    index: u32,
    label: String,
    account_index: u32,
) -> Result<(), String> {
    state
        .set_subaddress_label(account_index, index, &label)
        .await;
    Ok(())
}

// ── Transaction Operations ──

use crate::wallet::reqwest_transport::ReqwestTransport;

/// On-disk path for the RingCT output-distribution cache, per active network.
/// See wallet::decoy_cache — this cache is what makes Tor sends viable (fetch the
/// ~20MB distribution once in chunks, then only the new-block delta).
async fn dist_cache_path(app: &AppHandle) -> std::path::PathBuf {
    let network = app.state::<WalletState>().get_network().await;
    app.path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .join(format!("ringct_dist_{:?}.cache", network))
}

/// Prepare a transaction with NODE FAILOVER for decoy selection.
///
/// Decoy selection calls `get_output_distribution.bin` (the full RingCT output
/// distribution). Many public nodes serve `get_blocks.bin` (sync) fine but
/// stall/refuse that heavy binary RPC, so which node the scanner happened to
/// race onto determined whether a send worked — flaky by luck. We try the
/// currently-connected node first, then rotate through the pool, giving each a
/// short budget so a stalling node is abandoned quickly. The first node that
/// serves it wins AND becomes the persisted daemon (bias future ops toward a
/// proven-good node). We do NOT probe the distribution during the sync race —
/// that would download ~30MB per node and cripple sync.
async fn prepare_with_failover(
    app: &AppHandle,
    view_pair: &monero_wallet::ViewPair,
    outputs: &[monero_wallet::WalletOutput],
    payments: &[(MoneroAddress, u64)],
    fee_priority: FeePriority,
    primary_url: String,
) -> Result<transact::PreparedTransaction, String> {
    let mode = crate::wallet::scanner::read_routing_mode(app);
    // ClearnetConnector reads the "clearnet" node section; Tor and custom-proxy
    // both dial the .onion ("tor") section.
    let section = if mode == "clearnet" {
        "clearnet"
    } else {
        "tor"
    };

    // Candidate URLs: the connected node first, then the rest of the pool.
    let mut candidates: Vec<String> = vec![primary_url.clone()];
    for (_label, url) in crate::wallet::scanner::load_nodes(app, section).await {
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    }

    // A warm/willing node serves the distribution + get_outs in a few seconds; a
    // stalling node never responds. 25s cleanly abandons stallers while allowing
    // a node that must compute a cold distribution a fair chance.
    // Tor/custom bandwidth makes the ~20MB distribution + circuit build far slower
    // than clearnet, so give them a much larger per-node budget; clearnet stays tight
    // so a dead node is abandoned fast.
    let per_node_secs: u64 = if mode == "clearnet" { 25 } else { 180 };
    // Tor's .onion pool has many dead hidden services to skip, so try more nodes
    // to reach a healthy one; clearnet nodes are mostly up, so 4 is plenty.
    let max_nodes: usize = if mode == "clearnet" { 4 } else { 10 };

    let cache_path = dist_cache_path(app).await;

    let total = candidates.len().min(max_nodes);
    let mut last_err = String::from("no candidate nodes available");
    for (i, url) in candidates.into_iter().take(max_nodes).enumerate() {
        emit_log(
            app,
            "Tx",
            "info",
            &format!("🔗 Decoy selection — node {}/{}: {}", i + 1, total, url),
        );
        let outs = outputs.to_vec();
        let pays = payments.to_vec();
        let build_url = url.clone();
        let cache_path = cache_path.clone();
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(per_node_secs), async {
            // Wrap every transport in the distribution cache: decoy selection fetches
            // the ~20MB RingCT distribution once (chunked, Tor-safe) and only the
            // new-block delta thereafter — the difference between Tor sends working
            // and dying on the 20MB pull.
            use crate::wallet::decoy_cache::CachingDecoys;
            match mode.as_str() {
                "tor" => {
                    let tor = crate::wallet::scanner::ensure_tor(app).await.ok_or(
                        "Tor is not available — cannot select decoys without leaking your IP",
                    )?;
                    let daemon = crate::tor::ArtiTransport::connect(tor, build_url)
                        .await
                        .map_err(|e| format!("connect over Tor failed: {:?}", e))?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    transact::prepare_transaction(&daemon, view_pair, outs, pays, fee_priority)
                        .await
                }
                "custom" => {
                    let proxy = crate::wallet::scanner::read_proxy_address(app);
                    if proxy.trim().is_empty() {
                        return Err(
                            "Custom routing selected but no proxy address is set".to_string()
                        );
                    }
                    let daemon = crate::tor::SocksTransport::connect(proxy, build_url)
                        .await
                        .map_err(|e| format!("connect via proxy failed: {:?}", e))?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    transact::prepare_transaction(&daemon, view_pair, outs, pays, fee_priority)
                        .await
                }
                _ => {
                    // Clearnet: reqwest transport (reads the large distribution body
                    // reliably, unlike simple-request). Timeout bounds the whole call.
                    let daemon = ReqwestTransport::connect(
                        build_url,
                        std::time::Duration::from_secs(per_node_secs),
                    )
                    .await?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    transact::prepare_transaction(&daemon, view_pair, outs, pays, fee_priority)
                        .await
                }
            }
        })
        .await;

        match attempt {
            Ok(Ok(prepared)) => {
                emit_log(
                    app,
                    "Tx",
                    "success",
                    &format!("✅ Decoys selected via {}", url),
                );
                // Bias future sends/sync toward this proven-good node.
                app.state::<WalletState>().set_daemon_url(&url).await;
                return Ok(prepared);
            }
            Ok(Err(e)) => {
                last_err = e;
                emit_log(
                    app,
                    "Tx",
                    "warn",
                    &format!(
                        "⚠️ {} couldn't serve decoy selection ({}). Trying next node…",
                        url, last_err
                    ),
                );
            }
            Err(_) => {
                last_err = format!(
                    "{} stalled >{}s on get_output_distribution.bin",
                    url, per_node_secs
                );
                emit_log(
                    app,
                    "Tx",
                    "warn",
                    &format!("⚠️ {} — failing over to next node…", last_err),
                );
            }
        }
    }
    Err(format!(
        "Decoy selection failed on every node tried ({} attempted). Last error: {}",
        total, last_err
    ))
}

/// Step 1: Prepare transaction — select inputs, fetch decoys, compute fee.
/// Returns a PreparedTx with fee details for user review. No signing yet.
#[tauri::command]
pub async fn prepare_transfer(
    app: AppHandle,
    state: State<'_, WalletState>,
    destinations: Vec<TxDestination>,
    _account_index: u32,
    priority: Option<u8>,
    selected_output_ids: Option<Vec<String>>,
) -> Result<PreparedTx, String> {
    emit_log(&app, "Tx", "info", "🔧 Preparing transaction...");

    let (tx_metadata, _meta_key, prepared) =
        prepare_and_stage(&app, &state, destinations.clone(), priority, selected_output_ids)
            .await?;

    Ok(PreparedTx {
        fee: WalletState::format_xmr(prepared.fee),
        amount: WalletState::format_xmr(prepared.amount),
        tx_hash: String::new(), // Hash not known until signed
        tx_metadata,
        destinations: prepared
            .destinations
            .iter()
            .map(|(addr, amt)| TxDestination {
                address: addr.clone(),
                amount: amt.to_string(),
            })
            .collect(),
    })
}

/// Shared body of `prepare_transfer` and `export_unsigned_transfer`: connect to
/// the daemon, select coins (honoring coin control), prepare the transaction via
/// node failover, and stage the spend. Returns (serialized signable metadata,
/// its meta key, the full prepared record).
async fn prepare_and_stage(
    app: &AppHandle,
    state: &WalletState,
    destinations: Vec<TxDestination>,
    priority: Option<u8>,
    selected_output_ids: Option<Vec<String>>,
) -> Result<(Vec<u8>, String, transact::PreparedTransaction), String> {
    // Get daemon connection
    let daemon_url = state
        .get_daemon_url()
        .await
        .ok_or("No daemon connected. Wait for sync to complete.")?;

    let view_pair = state.get_view_pair().await.ok_or("Wallet is locked")?;

    let tip = state.tip_height().await;
    let mut outputs = state.get_spendable_outputs(tip).await;
    if outputs.is_empty() {
        return Err(
            "No spendable (unlocked) outputs yet — recent change may still be maturing.".into(),
        );
    }

    // Coin control: if the caller pinned specific outputs, restrict the input set to
    // exactly those (matched by the synthetic output_id the UI exposes for coins).
    let coin_control = selected_output_ids
        .as_ref()
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    if coin_control {
        let want: std::collections::HashSet<&str> = selected_output_ids
            .as_ref()
            .unwrap()
            .iter()
            .map(|s| s.as_str())
            .collect();
        outputs.retain(|o| want.contains(crate::wallet::state::output_id(o).as_str()));
        if outputs.is_empty() {
            return Err("None of the selected coins are spendable.".into());
        }
        // Surface any pinned coins that silently dropped out (spent/frozen/immature since
        // the UI listed them) so the user isn't left guessing why the input set shrank.
        let matched: std::collections::HashSet<String> = outputs
            .iter()
            .map(crate::wallet::state::output_id)
            .collect();
        let dropped = want.iter().filter(|id| !matched.contains(**id)).count();
        if dropped > 0 {
            emit_log(
                app,
                "Tx",
                "warn",
                &format!(
                    "⚠ Coin control: {} pinned coin(s) no longer spendable — using {} input(s)",
                    dropped,
                    outputs.len()
                ),
            );
        } else {
            emit_log(
                app,
                "Tx",
                "info",
                &format!("🎯 Coin control: {} pinned input(s)", outputs.len()),
            );
        }
    }

    // Parse destination addresses
    let network = state.get_network().await;
    let payments: Vec<(MoneroAddress, u64)> = destinations
        .iter()
        .map(|d| {
            let addr = MoneroAddress::from_str(network, &d.address)
                .map_err(|e| format!("Invalid address {}: {:?}", d.address, e))?;
            let amount: u64 = d
                .amount
                .parse()
                .map_err(|_| format!("Invalid amount: {}", d.amount))?;
            Ok((addr, amount))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let total_amount: u64 = payments.iter().map(|(_, a)| a).sum();
    emit_log(
        app,
        "Tx",
        "info",
        &format!(
            "💰 Sending {} piconero to {} destination(s)",
            total_amount,
            payments.len()
        ),
    );

    // Coin selection: spend a MINIMAL set of outputs (largest-first) covering the
    // amount + a fee headroom. Previously ALL spendable outputs were passed as
    // inputs, producing a huge many-input transaction with an absurd fee (~0.005
    // XMR for a 0.01 send). Largest-first keeps the input count — and thus the
    // fee — small. (Leaves smaller outputs unspent; churn/sweep to consolidate.)
    // With coin control the user pinned the exact inputs — use ALL of them; otherwise
    // auto-select a minimal largest-first set covering the amount + a fee headroom.
    let (selected, selected_sum) = if coin_control {
        let sum = outputs
            .iter()
            .map(|o| o.commitment().amount)
            .fold(0u64, u64::saturating_add);
        (outputs, sum)
    } else {
        outputs.sort_by(|a, b| b.commitment().amount.cmp(&a.commitment().amount));
        const FEE_HEADROOM: u64 = 2_000_000_000; // 0.002 XMR — generous fee buffer
        let target = total_amount.saturating_add(FEE_HEADROOM);
        let mut selected = Vec::new();
        let mut selected_sum = 0u64;
        for o in outputs.drain(..) {
            selected_sum = selected_sum.saturating_add(o.commitment().amount);
            selected.push(o);
            if selected_sum >= target {
                break;
            }
        }
        (selected, selected_sum)
    };
    if selected_sum < total_amount {
        return Err(format!(
            "Insufficient balance: selected {} piconero, need {} + fee",
            selected_sum, total_amount
        ));
    }
    let outputs = selected;
    emit_log(
        app,
        "Tx",
        "info",
        &format!(
            "🪙 Selected {} input(s) totaling {} piconero",
            outputs.len(),
            selected_sum
        ),
    );

    let fee_priority = match priority.unwrap_or(0) {
        0 => FeePriority::Normal,
        1 => FeePriority::Unimportant,
        2 => FeePriority::Normal,
        3 => FeePriority::Elevated,
        4 => FeePriority::Priority,
        p => FeePriority::Custom { priority: p as u32 },
    };

    // Prepare the transaction (decoy selection + fee computation) with NODE
    // FAILOVER. Decoy selection needs get_output_distribution.bin; many public
    // nodes serve get_blocks.bin (sync) fine but stall/refuse the heavy
    // distribution RPC, so a send that landed on such a node used to hang for
    // 30s then fail ("timeout reached: Elapsed"). We now try the connected node,
    // then rotate through the pool, abandoning any node that stalls, until one
    // actually serves it. prepare_transaction is generic over the transport.
    emit_log(
        app,
        "Tx",
        "info",
        "🎲 Selecting decoys and computing fee...",
    );
    let prepared = prepare_with_failover(
        app,
        &view_pair,
        &outputs,
        &payments,
        fee_priority,
        daemon_url,
    )
    .await?;

    let fee_formatted = WalletState::format_xmr(prepared.fee);
    let amount_formatted = WalletState::format_xmr(prepared.amount);
    emit_log(
        app,
        "Tx",
        "success",
        &format!(
            "✅ Transaction prepared: {} XMR + {} XMR fee",
            amount_formatted, fee_formatted
        ),
    );

    // Serialize the SignableTransaction for the relay step
    let tx_metadata = prepared.signable.serialize();

    // Stage the spend keyed by the tx metadata; relay commits it on a successful
    // broadcast so spent inputs leave the balance/coin-control immediately.
    let meta_key = crate::wallet::state::tx_meta_key(&tx_metadata);
    let staged_sent = crate::wallet::storage::SentTx {
        tx_hash: String::new(),
        amount: prepared.amount,
        fee: prepared.fee,
        destinations: prepared.destinations.clone(),
        height: 0,
        timestamp: 0,
        tx_key: prepared.tx_key_hex.clone(),
        // Input selection isn't account-scoped yet (see _account_index above), so a send
        // spends from the pooled/primary balance — record it under account 0.
        account: 0,
    };
    state
        .stage_pending_spend(meta_key.clone(), prepared.spent_ids.clone(), staged_sent)
        .await;

    Ok((tx_metadata, meta_key, prepared))
}

/// Build the spend-confirmation dialog body from the BACKEND-authoritative staged record
/// (destinations + fee in atomic units), or a fail-closed generic warning when no staged
/// record exists. Kept pure + separate from `relay_transfer` so both branches are unit-
/// testable and can NEVER be fed renderer-supplied text — the whole point of the guard.
fn format_spend_confirm(staged: Option<(&[(String, u64)], u64)>) -> String {
    match staged {
        Some((dests, fee_atomic)) => {
            let lines: Vec<String> = dests
                .iter()
                .map(|(addr, amt)| {
                    format!("Send {} XMR\nto {}", WalletState::format_xmr(*amt), addr)
                })
                .collect();
            format!(
                "{}\n\nNetwork fee {} XMR",
                lines.join("\n\n"),
                WalletState::format_xmr(fee_atomic)
            )
        }
        // No staged record (e.g. the wallet locked/restarted between prepare and relay — in
        // which case signing fails downstream anyway). NEVER fall back to renderer text.
        None => "Authorize this Monero transaction broadcast?\n\n(Destination could not be \
                 re-verified from the prepared transaction — only continue if you just \
                 created this send.)"
            .to_string(),
    }
}

/// Step 2: Sign and broadcast — called after user confirms + enters password.
#[tauri::command]
pub async fn relay_transfer(
    app: AppHandle,
    state: State<'_, WalletState>,
    tx_metadata: Vec<u8>,
    to: Option<String>,
    amount: Option<String>,
    fee: Option<String>,
) -> Result<String, String> {
    // FUND SAFETY (per-spend authorization): every broadcast requires an OS-level
    // confirmation the renderer JS cannot fake — so no ROS app (or compromised page)
    // can spend silently, even though it could reach this command via invoke.
    //
    // The confirm text is built from the BACKEND's staged record (destinations/amount/fee
    // recorded by prepare_transfer, keyed by the tx-metadata hash) — NEVER from the
    // renderer-supplied `to`/`amount`/`fee`. Otherwise a hostile renderer could prepare a
    // tx paying B while passing `to="A"` here, so the dialog would show A while the signed
    // tx_metadata (the source of truth for the broadcast) pays B. We show what is actually
    // being paid.
    let meta_key = crate::wallet::state::tx_meta_key(&tx_metadata);
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let _ = (&amount, &fee); // renderer-supplied; intentionally NOT trusted for the dialog.
        let staged = state.peek_pending_spend(&meta_key).await;
        // Tamper telemetry: if the renderer's display `to` isn't among the prepared
        // destinations, it tried to mislead the user. The dialog shows the authoritative
        // destination regardless; just record that it diverged.
        if let (Some(t), Some((dests, _, _))) = (&to, &staged) {
            if !dests.iter().any(|(addr, _)| addr == t) {
                emit_log(&app, "Tx", "warn",
                    "Spend-confirm destination mismatch: renderer display differs from the prepared transaction");
            }
        }
        let body = format_spend_confirm(staged.as_ref().map(|(d, _a, f)| (d.as_slice(), *f)));
        let ok = app
            .dialog()
            .message(body)
            .title("Confirm transaction")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Send".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !ok {
            // Un-stage the spend prepare() staged so the (never-broadcast) inputs
            // return to the spendable balance immediately.
            state.discard_pending_spend(&meta_key).await;
            emit_log(&app, "Tx", "warn", "Transaction cancelled at confirmation");
            return Err("Transaction cancelled".into());
        }
    }

    sign_and_broadcast(&app, &state, tx_metadata).await
}

/// Sign + broadcast a prepared transaction's metadata over the configured routing
/// mode, then commit the staged spend. This is the body of `relay_transfer` AFTER
/// its OS confirmation dialog — extracted so the autonomous transfer-grant relay
/// (pre-authorized once at arm time, per the EJECT design) can reuse the EXACT same
/// signing/broadcast/commit path WITHOUT a per-tx dialog. Pure extraction: behavior,
/// logs, the IP-hiding routing, and the commit are unchanged from the original.
pub(crate) async fn sign_and_broadcast(
    app: &AppHandle,
    state: &WalletState,
    tx_metadata: Vec<u8>,
) -> Result<String, String> {
    emit_log(app, "Tx", "info", "🔐 Signing transaction...");

    let spend_key = state.get_spend_key().await.ok_or("Wallet is locked")?;

    // Deserialize the prepared transaction
    let signable = monero_wallet::send::SignableTransaction::read(&mut tx_metadata.as_slice())
        .map_err(|e| format!("Invalid transaction data: {:?}", e))?;

    // Sign it
    let prepared = transact::PreparedTransaction {
        signable,
        fee: 0,
        amount: 0,
        destinations: vec![],
        spent_ids: vec![],
        tx_key_hex: String::new(),
    };
    let signed_tx = transact::sign_transaction(prepared, &spend_key)?;

    let meta_key = crate::wallet::state::tx_meta_key(&tx_metadata);
    broadcast_and_commit(app, state, signed_tx, meta_key).await
}

/// Broadcast an already-signed transaction over the configured routing mode and
/// commit its staged spend. Shared by `relay_transfer` (signs locally) and
/// `import_signed_transfer` (broadcasts an externally-signed envelope) so both
/// take the identical IP-hiding relay + commit path.
async fn broadcast_and_commit(
    app: &AppHandle,
    state: &WalletState,
    signed_tx: monero_oxide::transaction::Transaction,
    meta_key: String,
) -> Result<String, String> {
    emit_log(app, "Tx", "info", "📡 Broadcasting to network...");

    let daemon_url = state.get_daemon_url().await.ok_or("No daemon connected")?;

    // Broadcast over the configured routing mode so the originating IP for the
    // transaction is never exposed. broadcast_transaction is generic.
    tx_deadline(app, "Broadcast", async {
        match crate::wallet::scanner::read_routing_mode(app).as_str() {
            "tor" => {
                let tor = crate::wallet::scanner::ensure_tor(app)
                    .await
                    .ok_or("Tor is not available — refusing to broadcast over clearnet")?;
                let daemon = crate::tor::ArtiTransport::connect(tor, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon over Tor: {:?}", e))?;
                transact::broadcast_transaction(&daemon, &signed_tx).await?;
            }
            "custom" => {
                let proxy = crate::wallet::scanner::read_proxy_address(app);
                if proxy.trim().is_empty() {
                    return Err("Custom routing selected but no proxy address is set".to_string());
                }
                let daemon = crate::tor::SocksTransport::connect(proxy, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon via proxy: {:?}", e))?;
                transact::broadcast_transaction(&daemon, &signed_tx).await?;
            }
            _ => {
                let daemon =
                    ReqwestTransport::connect(daemon_url, std::time::Duration::from_secs(60))
                        .await?;
                transact::broadcast_transaction(&daemon, &signed_tx).await?;
            }
        }
        Ok::<(), String>(())
    })
    .await?;

    let tx_hash = hex::encode(signed_tx.hash());

    // Broadcast succeeded — commit the staged spend so the consumed outputs
    // leave the balance / coin-control immediately (a rescan reconciles later).
    let tip = state.tip_height().await;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    state
        .commit_spend(&meta_key, tx_hash.clone(), tip, now)
        .await;

    emit_log(
        app,
        "Tx",
        "success",
        &format!("✅ Transaction broadcast! Hash: {}", tx_hash),
    );

    Ok(tx_hash)
}

/// Prepare → sign → broadcast a sweep over one concrete daemon transport.
/// Returns (tx_hash, fee, amount, spent_output_ids, destinations) on success.
/// Bound a tx build/broadcast network op (decoy fetch + relay over the configured
/// route) so a stalled Tor circuit can't hang the sweep/transfer commands forever —
/// the scan-loop watchdog doesn't cover this path. Decoy selection + broadcast take
/// longer than a single block fetch, so the deadline is generous; on timeout the
/// caller surfaces a retryable error instead of deadlocking.
const TX_DEADLINE_SECS: u64 = 90;

async fn tx_deadline<T, F>(app: &AppHandle, label: &str, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    let r = match tokio::time::timeout(std::time::Duration::from_secs(TX_DEADLINE_SECS), fut).await
    {
        Ok(r) => r,
        Err(_) => Err(format!(
            "{} timed out after {}s — node/Tor circuit stalled, please try again",
            label, TX_DEADLINE_SECS
        )),
    };
    // Surface failures to the console — a command's Err otherwise returns silently to
    // the UI (swallowed to the browser console) and reads as "nothing happened".
    if let Err(e) = &r {
        emit_log(app, "Tx", "error", &format!("❌ {} failed: {}", label, e));
    }
    r
}

async fn sweep_via_daemon<D>(
    daemon: &D,
    view_pair: &monero_wallet::ViewPair,
    inputs: Vec<monero_wallet::WalletOutput>,
    dest: MoneroAddress,
    fee_priority: FeePriority,
    spend_key: &zeroize::Zeroizing<monero_oxide::ed25519::Scalar>,
) -> Result<(String, u64, u64, Vec<String>, Vec<(String, u64)>, String), String>
where
    D: ProvidesDecoys + ProvidesBlockchainMeta + ProvidesFeeRates + PublishTransaction + Sync,
{
    let prepared = transact::prepare_sweep(daemon, view_pair, inputs, dest, fee_priority).await?;
    let fee = prepared.fee;
    let amount = prepared.amount;
    let spent_ids = prepared.spent_ids.clone();
    let destinations = prepared.destinations.clone();
    let tx_key = prepared.tx_key_hex.clone();
    let signed = transact::sign_transaction(prepared, spend_key)?;
    transact::broadcast_transaction(daemon, &signed).await?;
    Ok((
        hex::encode(signed.hash()),
        fee,
        amount,
        spent_ids,
        destinations,
        tx_key,
    ))
}

/// Sweep one batch with NODE FAILOVER — the sweep analogue of `prepare_with_failover`.
/// Sweep decoy selection fetches the same ~20 MB distribution as a send, and a
/// transient node error (502, stalled distribution) shouldn't kill a churn/sweep:
/// try the connected node, then rotate the pool, persisting the first that works.
#[allow(clippy::too_many_arguments)]
async fn sweep_with_failover(
    app: &AppHandle,
    view_pair: &monero_wallet::ViewPair,
    batch: Vec<monero_wallet::WalletOutput>,
    dest: MoneroAddress,
    fee_priority: FeePriority,
    spend_key: &zeroize::Zeroizing<monero_oxide::ed25519::Scalar>,
    primary_url: String,
) -> Result<(String, u64, u64, Vec<String>, Vec<(String, u64)>, String), String> {
    let mode = crate::wallet::scanner::read_routing_mode(app);
    let section = if mode == "clearnet" {
        "clearnet"
    } else {
        "tor"
    };
    let mut candidates: Vec<String> = vec![primary_url.clone()];
    for (_label, url) in crate::wallet::scanner::load_nodes(app, section).await {
        if !candidates.contains(&url) {
            candidates.push(url);
        }
    }

    // Tor/custom bandwidth makes the ~20MB distribution + circuit build far slower
    // than clearnet, so give them a much larger per-node budget; clearnet stays tight
    // so a dead node is abandoned fast.
    let per_node_secs: u64 = if mode == "clearnet" { 25 } else { 180 };
    // Tor's .onion pool has many dead hidden services to skip, so try more nodes
    // to reach a healthy one; clearnet nodes are mostly up, so 4 is plenty.
    let max_nodes: usize = if mode == "clearnet" { 4 } else { 10 };
    let cache_path = dist_cache_path(app).await;
    let total = candidates.len().min(max_nodes);
    let mut last_err = String::from("no candidate nodes available");
    for (i, url) in candidates.into_iter().take(max_nodes).enumerate() {
        emit_log(
            app,
            "Tx",
            "info",
            &format!("🔗 Sweep — node {}/{}: {}", i + 1, total, url),
        );
        let batch_c = batch.clone();
        let dest_c = dest.clone();
        let build_url = url.clone();
        let cache_path = cache_path.clone();
        let attempt = tokio::time::timeout(std::time::Duration::from_secs(per_node_secs), async {
            use crate::wallet::decoy_cache::CachingDecoys;
            match mode.as_str() {
                "tor" => {
                    let tor = crate::wallet::scanner::ensure_tor(app)
                        .await
                        .ok_or("Tor is not available — refusing to sweep over clearnet")?;
                    let daemon = crate::tor::ArtiTransport::connect(tor, build_url)
                        .await
                        .map_err(|e| format!("connect over Tor failed: {:?}", e))?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    sweep_via_daemon(&daemon, view_pair, batch_c, dest_c, fee_priority, spend_key)
                        .await
                }
                "custom" => {
                    let proxy = crate::wallet::scanner::read_proxy_address(app);
                    if proxy.trim().is_empty() {
                        return Err(
                            "Custom routing selected but no proxy address is set".to_string()
                        );
                    }
                    let daemon = crate::tor::SocksTransport::connect(proxy, build_url)
                        .await
                        .map_err(|e| format!("connect via proxy failed: {:?}", e))?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    sweep_via_daemon(&daemon, view_pair, batch_c, dest_c, fee_priority, spend_key)
                        .await
                }
                _ => {
                    let daemon = ReqwestTransport::connect(
                        build_url,
                        std::time::Duration::from_secs(per_node_secs),
                    )
                    .await?;
                    let daemon = CachingDecoys::new(daemon, cache_path);
                    sweep_via_daemon(&daemon, view_pair, batch_c, dest_c, fee_priority, spend_key)
                        .await
                }
            }
        })
        .await;

        match attempt {
            Ok(Ok(res)) => {
                app.state::<WalletState>().set_daemon_url(&url).await;
                return Ok(res);
            }
            Ok(Err(e)) => {
                last_err = e;
                emit_log(
                    app,
                    "Tx",
                    "warn",
                    &format!(
                        "⚠️ {} couldn't sweep ({}). Trying next node…",
                        url, last_err
                    ),
                );
            }
            Err(_) => {
                last_err = format!("{} stalled >{}s", url, per_node_secs);
                emit_log(
                    app,
                    "Tx",
                    "warn",
                    &format!("⚠️ {} — failing over to next node…", last_err),
                );
            }
        }
    }
    Err(format!(
        "Sweep failed on every node tried ({} attempted). Last error: {}",
        total, last_err
    ))
}

/// Sweep ALL spendable outputs to a single address (no change). One command:
/// builds, signs, and broadcasts over the configured routing mode.
#[tauri::command]
pub async fn sweep_all(
    app: AppHandle,
    state: State<'_, WalletState>,
    address: String,
    account_index: u32,
    priority: Option<u8>,
    // When Some, sweep only outputs belonging to these subaddress (minor) indices of
    // `account_index` ("vanish subaddress"). When None, sweep the whole wallet.
    subaddr_indices: Option<Vec<u32>>,
) -> Result<Vec<String>, String> {
    // FUND SAFETY: a sweep moves funds — require an OS-level confirmation the renderer
    // JS can't fake (used by churn / vanish-subaddress too).
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let scope = match &subaddr_indices {
            Some(idxs) => format!("subaddress(es) {:?}", idxs),
            None => "ALL funds".to_string(),
        };
        let ok = app
            .dialog()
            .message(format!("Sweep {scope}\nto {address}?"))
            .title("Confirm sweep")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Sweep".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !ok {
            return Err("Sweep cancelled".into());
        }
    }
    let view_pair = state.get_view_pair().await.ok_or("Wallet is locked")?;
    let spend_key = state.get_spend_key().await.ok_or("Wallet is locked")?;
    let network = state.get_network().await;
    let daemon_url = state.get_daemon_url().await.ok_or("No daemon connected")?;

    let dest = MoneroAddress::from_str(network, &address)
        .map_err(|e| format!("Invalid address {}: {:?}", address, e))?;

    let sweep_tip = state.tip_height().await;
    let mut inputs = state.get_spendable_outputs(sweep_tip).await;
    if let Some(idxs) = &subaddr_indices {
        inputs.retain(|o| {
            o.subaddress()
                .map(|s| {
                    s.account() as u32 == account_index && idxs.contains(&(s.address() as u32))
                })
                .unwrap_or(false)
        });
    }
    if inputs.is_empty() {
        return Err("No spendable outputs to sweep".into());
    }

    run_sweep(
        &app, &*state, view_pair, spend_key, daemon_url, dest, inputs, priority,
    )
    .await
}

/// Sweep exactly ONE spendable output to `address` ("vanish coin"). The output is
/// identified by the synthetic output_id that `get_outputs` exposes to the UI as
/// `key_image` (we can't derive real key images for arbitrary outputs client-side).
#[tauri::command]
pub async fn sweep_single(
    app: AppHandle,
    state: State<'_, WalletState>,
    address: String,
    key_image: String,
    priority: Option<u8>,
) -> Result<Vec<String>, String> {
    // FUND SAFETY: sweeping a single output moves funds — native confirmation (vanish coin).
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let ok = app
            .dialog()
            .message(format!("Sweep this single output\nto {address}?"))
            .title("Confirm sweep")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Sweep".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !ok {
            return Err("Sweep cancelled".into());
        }
    }
    let view_pair = state.get_view_pair().await.ok_or("Wallet is locked")?;
    let spend_key = state.get_spend_key().await.ok_or("Wallet is locked")?;
    let network = state.get_network().await;
    let daemon_url = state.get_daemon_url().await.ok_or("No daemon connected")?;

    let dest = MoneroAddress::from_str(network, &address)
        .map_err(|e| format!("Invalid address {}: {:?}", address, e))?;

    let sweep_tip = state.tip_height().await;
    let mut inputs = state.get_spendable_outputs(sweep_tip).await;
    inputs.retain(|o| crate::wallet::state::output_id(o) == key_image);
    if inputs.is_empty() {
        return Err(
            "Output not found among spendable outputs (already spent or still immature)".into(),
        );
    }

    run_sweep(
        &app, &*state, view_pair, spend_key, daemon_url, dest, inputs, priority,
    )
    .await
}

/// Shared sweep core for `sweep_all` / `sweep_single`: pick fee priority, build +
/// sign + broadcast `inputs` to `dest` over the configured route, mark the swept
/// outputs spent, record the ledger entry, and log. `inputs` is already the exact
/// set to sweep (the callers do the selection/filtering).
async fn run_sweep(
    app: &AppHandle,
    state: &WalletState,
    view_pair: monero_wallet::ViewPair,
    spend_key: zeroize::Zeroizing<monero_oxide::ed25519::Scalar>,
    daemon_url: String,
    dest: MoneroAddress,
    inputs: Vec<monero_wallet::WalletOutput>,
    priority: Option<u8>,
) -> Result<Vec<String>, String> {
    // Large input sets can't fit one tx — the node throttles the concurrent decoy
    // fetches and a many-input tx is heavy to build/sign, blowing the tx watchdog.
    // So sweep in BATCHES: multiple txs to the same destination (like
    // monero-wallet-rpc sweep_all). Each batch is an independent sweep of a disjoint
    // subset of inputs; the destination receives everything minus one fee per batch.
    // Batches run sequentially; a mid-way failure leaves earlier batches broadcast
    // (funds already at the destination) and the rest unswept — safe to re-run.
    const MAX_SWEEP_INPUTS: usize = 24;
    let batches: Vec<Vec<monero_wallet::WalletOutput>> = inputs
        .chunks(MAX_SWEEP_INPUTS)
        .map(|c| c.to_vec())
        .collect();
    let total_batches = batches.len();
    // A sweep to our OWN address (churn / vanish) returns the funds to us, so credit
    // the swept amount optimistically — otherwise the balance reads ~0 between
    // broadcast and the next scan, which looks like lost funds to the user.
    let dest_is_self = state.is_own_address(&dest).await;

    let mut hashes: Vec<String> = Vec::with_capacity(total_batches);
    for (bi, batch) in batches.into_iter().enumerate() {
        let fee_priority = match priority.unwrap_or(0) {
            1 => FeePriority::Unimportant,
            3 => FeePriority::Elevated,
            4 => FeePriority::Priority,
            p if p > 4 => FeePriority::Custom { priority: p as u32 },
            _ => FeePriority::Normal,
        };

        if total_batches > 1 {
            emit_log(
                app,
                "Tx",
                "info",
                &format!(
                    "🧹 Sweep batch {}/{} ({} output(s))…",
                    bi + 1,
                    total_batches,
                    batch.len()
                ),
            );
        } else {
            emit_log(
                app,
                "Tx",
                "info",
                &format!("🧹 Sweeping {} output(s)...", batch.len()),
            );
        }

        let daemon_url = daemon_url.clone();
        let dest = dest.clone();

        // Node failover, same as the send path: a sweep decoy fetch that stalls or
        // hits a transient node error (e.g. 502) rotates to the next node instead of
        // failing the whole sweep/churn.
        let (tx_hash, fee, amount, spent_ids, destinations, tx_key) = sweep_with_failover(
            app,
            &view_pair,
            batch,
            dest,
            fee_priority,
            &spend_key,
            daemon_url,
        )
        .await?;

        // Mark this batch's outputs spent + log the broadcast.
        let tip = state.tip_height().await;
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        state
            .mark_spent(
                spent_ids,
                crate::wallet::storage::SentTx {
                    tx_hash: tx_hash.clone(),
                    amount,
                    fee,
                    destinations,
                    height: tip,
                    timestamp: now,
                    tx_key,
                    account: 0, // sweeps/churn aren't account-scoped either — record under account 0
                },
                dest_is_self,
            )
            .await;

        emit_log(
            app,
            "Tx",
            "success",
            &format!("✅ Sweep broadcast! Hash: {}", tx_hash),
        );
        hashes.push(tx_hash);
    }

    Ok(hashes)
}

/// Tip-independent estimate of a block's wall-clock time from a fixed (height, time)
/// anchor and Monero's ~120s target block time. Fallback ONLY when the real block
/// header timestamp is unavailable (block_ts==0, e.g. an output not yet timestamp-
/// populated mid-restore); a rescan replaces it with the exact value. Unlike the old
/// now−(tip−height) form it never collapses to "now" when the sync tip lags the output.
/// Anchor: mainnet block 3,709,104 ≈ 2026-07-02 (observed from real ledger data).
pub(crate) fn estimate_block_time(height: u64) -> u64 {
    const ANCHOR_HEIGHT: u64 = 3_709_104;
    const ANCHOR_TS: u64 = 1_782_950_400;
    const BLOCK_SECS: u64 = 120;
    if height >= ANCHOR_HEIGHT {
        ANCHOR_TS + (height - ANCHOR_HEIGHT) * BLOCK_SECS
    } else {
        ANCHOR_TS.saturating_sub((ANCHOR_HEIGHT - height) * BLOCK_SECS)
    }
}

/// Returns transaction history in the Monero-RPC `get_transfers` shape the
/// renderer's walletService expects: `{ in, out, pending }`, amounts ATOMIC,
/// timestamps in SECONDS. Incoming txs are reconstructed from owned outputs
/// (grouped by txid); outgoing from the broadcast log.
#[tauri::command]
pub async fn get_transactions(
    state: State<'_, WalletState>,
    account_index: u32,
) -> Result<serde_json::Value, String> {
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    let tip = state.tip_height().await;
    let now = chrono::Utc::now().timestamp().max(0) as u64;

    // Txids of our own outgoing transactions. An owned output created by one of
    // these is CHANGE returning to us — not an incoming payment — so it must be
    // excluded from the incoming list (otherwise a send shows twice: once as
    // DISPATCHED, once as a bogus RECEIVED for the change).
    let sent_txids: HashSet<String> = state
        .get_sent()
        .await
        .iter()
        .map(|s| s.tx_hash.clone())
        .collect();

    // Incoming: group owned outputs (incl. spent) by txid, skipping our own
    // change outputs.
    let mut incoming: HashMap<String, (u64, u64, u32, u64)> = HashMap::new(); // txid -> (amount, min_height, account, block_ts)
    for (owned, _spent, _frozen) in state.list_owned().await {
        let txid = hex::encode(owned.output.transaction());
        if sent_txids.contains(&txid) {
            continue; // change from our own send, not an incoming payment
        }
        let amt = owned.output.commitment().amount;
        let acct = owned.output.subaddress().map(|s| s.account()).unwrap_or(0);
        if acct != account_index {
            continue; // only this account's incoming outputs belong in its ledger
        }
        let entry = incoming
            .entry(txid)
            .or_insert((0, owned.height, acct, owned.timestamp));
        entry.0 += amt;
        if owned.height < entry.1 {
            entry.1 = owned.height;
            entry.3 = owned.timestamp; // keep the timestamp aligned to the earliest output
        }
    }
    let in_txs: Vec<serde_json::Value> = incoming
        .into_iter()
        .map(|(txid, (amount, height, account, block_ts))| {
            let confirmations = if tip >= height { tip - height + 1 } else { 0 };
            // Prefer the real block header timestamp (stable, exact). Fall back to a
            // tip-INDEPENDENT anchor estimate when it's missing (block_ts==0, e.g. an
            // output not yet timestamp-populated during a restore). The old
            // now−(tip−height)·120 form collapsed to "now" whenever the sync tip lagged
            // the output height — dumping every such tx under "TODAY / 6s".
            let timestamp = if block_ts > 0 {
                block_ts
            } else {
                estimate_block_time(height).min(now)
            };
            json!({
                "txid": txid,
                "amount": amount,
                "timestamp": timestamp,
                "height": height,
                "confirmations": confirmations,
                "subaddr_index": { "major": account, "minor": 0 },
                "payment_id": "0000000000000000",
            })
        })
        .collect();

    // Outgoing: from the broadcast log.
    let mut out_txs = Vec::new();
    let mut pending_txs = Vec::new();
    for sent in state.get_sent().await {
        if sent.account != account_index {
            continue; // sends are recorded under account 0 (input selection isn't account-scoped)
        }
        let pending = sent.height == 0 || tip < sent.height;
        let confirmations = if sent.height > 0 && tip >= sent.height {
            tip - sent.height
        } else {
            0
        };
        let entry = json!({
            "txid": sent.tx_hash,
            "amount": sent.amount,
            "timestamp": sent.timestamp,
            "height": sent.height,
            "confirmations": confirmations,
            "fee": sent.fee,
            "address": sent.destinations.first().map(|(a, _)| a.clone()).unwrap_or_default(),
            "subaddr_index": { "major": 0, "minor": 0 },
            "destinations": sent.destinations.iter().map(|(a, amt)| json!({ "address": a, "amount": amt })).collect::<Vec<_>>(),
        });
        if pending {
            pending_txs.push(entry);
        } else {
            out_txs.push(entry);
        }
    }

    Ok(json!({ "in": in_txs, "out": out_txs, "pending": pending_txs }))
}

/// Returns unspent outputs in the Monero-RPC `incoming_transfers` shape:
/// `{ transfers: [...] }`, amounts ATOMIC. `key_image` is a stable synthetic id
/// (a real key image needs unavailable output private-key derivation).
#[tauri::command]
pub async fn get_outputs(
    state: State<'_, WalletState>,
    _account_index: u32,
) -> Result<serde_json::Value, String> {
    use serde_json::json;
    let tip = state.tip_height().await;
    let now = chrono::Utc::now().timestamp().max(0) as u64;

    let mut transfers = Vec::new();
    for (owned, spent, frozen) in state.list_owned().await {
        if spent {
            continue; // coin control lists unspent outputs only
        }
        let o = &owned.output;
        // Mature after the standard 10-block lock, and any explicit timelock met.
        let mature = tip >= owned.height.saturating_add(10);
        let timelock_ok = match o.additional_timelock() {
            Timelock::None => true,
            Timelock::Block(b) => (tip as usize) >= b,
            Timelock::Time(t) => now >= t,
        };
        // Real block time when known; height estimate only for pre-timestamp caches.
        let timestamp = if owned.timestamp > 0 {
            owned.timestamp
        } else {
            now.saturating_sub(tip.saturating_sub(owned.height).saturating_mul(120))
        };
        transfers.push(json!({
            "amount": o.commitment().amount,
            "key_image": crate::wallet::state::output_id(o),
            "unlocked": mature && timelock_ok,
            "frozen": frozen,
            "subaddr_index": { "major": o.subaddress().map(|s| s.account()).unwrap_or(0), "minor": o.subaddress().map(|s| s.address()).unwrap_or(0) },
            "timestamp": timestamp,
            "txid": hex::encode(o.transaction()),
        }));
    }
    Ok(json!({ "transfers": transfers }))
}

// ── Proof Operations ──

/// Return the transaction secret key (hex) for a tx this wallet broadcast, for
/// proof-of-payment. Only available for txs sent since this feature shipped
/// (the key is captured at send time). Note: this is the MAIN tx key — correct
/// for single standard-address sends and sweeps; see the deferred get_tx_proof
/// for full recipient-bound OutProofV2 signatures.
#[tauri::command]
pub async fn get_tx_key(state: State<'_, WalletState>, txid: String) -> Result<String, String> {
    state
        .get_tx_key(&txid)
        .await
        .ok_or_else(|| "No tx key on record — only available for transactions sent after this feature was enabled".to_string())
}

#[tauri::command]
/// Generate an OutProofV2 proof-of-payment for a tx we sent. UNVALIDATED crypto
/// — must pass `monero-wallet-cli check_tx_proof` against official Monero before
/// being relied on (see wallet/tx_proof.rs). Standard (non-subaddress) recipient
/// only; uses the tx secret key captured at send time.
pub async fn get_tx_proof(
    state: State<'_, WalletState>,
    txid: String,
    address: String,
    message: Option<String>,
) -> Result<String, String> {
    let r_hex = state
        .get_tx_key(&txid)
        .await
        .ok_or("No tx key on record — proofs are only available for transactions sent after this feature was enabled")?;
    let r_bytes: [u8; 32] = hex::decode(&r_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("Stored tx key is malformed")?;
    let r = Option::from(curve25519_dalek::Scalar::from_canonical_bytes(r_bytes))
        .ok_or("Stored tx key is not a canonical scalar")?;

    let txid_bytes: [u8; 32] = hex::decode(&txid)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("Invalid txid")?;

    let network = state.get_network().await;
    let addr = MoneroAddress::from_str(network, &address)
        .map_err(|e| format!("Invalid address: {:?}", e))?;

    crate::wallet::tx_proof::generate_out_proof_v2(
        txid_bytes,
        message.as_deref().unwrap_or(""),
        r,
        &addr,
    )
}

/// Result of signing an arbitrary message with a wallet address.
#[derive(serde::Serialize)]
pub struct SignedMessage {
    pub signature: String,
    #[serde(rename = "signerAddress")]
    pub signer_address: String,
}

/// Sign an arbitrary UTF-8 message with the key for the exact wallet address in
/// `address` (primary or registered subaddress; integrated addresses are rejected).
/// This is the signing primitive behind "Sign in with Ripley" — it proves control
/// of `address` without moving funds. Requires the wallet unlocked (spend key
/// resident). UNAUDITED crypto (see wallet/msg_sign.rs).
#[tauri::command]
pub async fn sign_message(
    state: State<'_, WalletState>,
    address: String,
    message: String,
) -> Result<SignedMessage, String> {
    let network = state.get_network().await;
    let target = MoneroAddress::from_str(network, &address)
        .map_err(|e| format!("Invalid address: {:?}", e))?;

    let (spend_sec, spend_pub) = state.message_signing_key_for_address(&target).await?;
    let signature = crate::wallet::msg_sign::sign_message_v1(&message, &spend_sec, &spend_pub);
    Ok(SignedMessage {
        signature,
        signer_address: target.to_string(),
    })
}

/// Verify a transaction SECRET key against the on-chain transaction and report the
/// atomic amount it paid `address`, plus confirmations. `good` is true iff the key is
/// genuinely this tx's key (r·G == on-chain R). Runs over the configured routing mode.
/// UNAUDITED crypto (see wallet/tx_proof.rs).
#[tauri::command]
pub async fn check_tx_key(
    app: AppHandle,
    state: State<'_, WalletState>,
    txid: String,
    tx_key: String,
    address: String,
) -> Result<serde_json::Value, String> {
    let txid_hex = txid.trim().to_lowercase();
    let txid_bytes: [u8; 32] = hex::decode(&txid_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("Invalid txid")?;

    let network = state.get_network().await;
    let addr = MoneroAddress::from_str(network, address.trim())
        .map_err(|e| format!("Invalid address: {:?}", e))?;

    let daemon_url = state
        .get_daemon_url()
        .await
        .ok_or("No daemon connected — open a wallet first")?;

    tx_deadline(&app, "Verify key", async {
        match crate::wallet::scanner::read_routing_mode(&app).as_str() {
            "tor" => {
                let tor = crate::wallet::scanner::ensure_tor(&app)
                    .await
                    .ok_or("Tor is not available — refusing to query over clearnet")?;
                let daemon = crate::tor::ArtiTransport::connect(tor, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon over Tor: {:?}", e))?;
                check_key_on_daemon(&daemon, txid_bytes, &txid_hex, &tx_key, &addr).await
            }
            "custom" => {
                let proxy = crate::wallet::scanner::read_proxy_address(&app);
                if proxy.trim().is_empty() {
                    return Err("Custom routing selected but no proxy address is set".to_string());
                }
                let daemon = crate::tor::SocksTransport::connect(proxy, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon via proxy: {:?}", e))?;
                check_key_on_daemon(&daemon, txid_bytes, &txid_hex, &tx_key, &addr).await
            }
            _ => {
                let daemon =
                    ReqwestTransport::connect(daemon_url, std::time::Duration::from_secs(60))
                        .await?;
                check_key_on_daemon(&daemon, txid_bytes, &txid_hex, &tx_key, &addr).await
            }
        }
    })
    .await
}

/// Report a tx's confirmation count and mempool status. Uses the raw `/get_transactions`
/// route (which carries `block_height` / `in_pool`, unlike the typed `transactions()`
/// helper) and the chain tip. On any lookup failure returns `(0, false)` — the proof
/// verdict stands on its own; confirmations are advisory metadata.
async fn tx_confirmations<T: HttpTransport + Sync>(
    daemon: &MoneroDaemon<T>,
    txid_hex: &str,
) -> (u64, bool) {
    let params = format!(
        r#"{{"txs_hashes":["{}"],"decode_as_json":false}}"#,
        txid_hex
    );
    let raw = match daemon
        .rpc_call("get_transactions", Some(params), 1024 * 1024)
        .await
    {
        Ok(r) => r,
        Err(_) => return (0, false),
    };
    let v: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return (0, false),
    };
    let tx0 = v.get("txs").and_then(|t| t.get(0));
    if tx0
        .and_then(|t| t.get("in_pool"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false)
    {
        return (0, true);
    }
    let Some(block_height) = tx0
        .and_then(|t| t.get("block_height"))
        .and_then(|h| h.as_u64())
    else {
        return (0, false);
    };
    let tip = match daemon.latest_block_number().await {
        Ok(t) => t as u64,
        Err(_) => return (0, false),
    };
    // blockchain_height = tip + 1; confirmations = blockchain_height − block_height.
    (tip.saturating_sub(block_height).saturating_add(1), false)
}

/// Nominal weight of a typical 2-in/2-out RingCT tx. Used to turn the daemon's
/// per-weight fee rate into an at-a-glance fee for the send UI — the EXACT fee is
/// always computed from the real tx at prepare time; this is only an estimate.
const NOMINAL_TX_WEIGHT: usize = 1500;

/// Per-priority ballpark fees (atomic piconero) for a nominal tx, indexed to the UI's
/// priority levels: [0 auto, 1 slow, 2 normal, 3 fast, 4 fastest].
async fn fees_on_daemon<T: HttpTransport + Sync>(
    daemon: &MoneroDaemon<T>,
) -> Result<Vec<u64>, String> {
    // Generous per-weight cap: this is a DISPLAY estimate, so let even the fastest
    // priority through (its per-weight rate is well above the 500k cap used when
    // actually building a tx). Still bounded far below any overflow in fee×weight.
    const MAX_PER_WEIGHT: u64 = 1_000_000_000;
    let priorities = [
        FeePriority::Normal,      // 0 auto
        FeePriority::Unimportant, // 1 slow
        FeePriority::Normal,      // 2 normal
        FeePriority::Elevated,    // 3 fast
        FeePriority::Priority,    // 4 fastest
    ];
    let mut out = Vec::with_capacity(priorities.len());
    let mut any_ok = false;
    // Resilient: a single priority the node won't quote shouldn't null the whole row.
    for p in priorities {
        match daemon.fee_rate(p, MAX_PER_WEIGHT).await {
            Ok(rate) => {
                out.push(rate.calculate_fee_from_weight(NOMINAL_TX_WEIGHT));
                any_ok = true;
            }
            Err(_) => out.push(0),
        }
    }
    if any_ok {
        Ok(out)
    } else {
        Err("daemon returned no usable fee rates".into())
    }
}

/// Per-priority fee estimate for the send UI (atomic piconero, indexed 0..=4). Routed
/// through the configured uplink like every other daemon call.
#[tauri::command]
pub async fn estimate_fees(
    app: AppHandle,
    state: State<'_, WalletState>,
) -> Result<Vec<u64>, String> {
    let daemon_url = match state.get_daemon_url().await {
        Some(u) => u,
        None => {
            emit_log(
                &app,
                "Fee",
                "warn",
                "💸 estimate_fees: no daemon connected yet",
            );
            return Err("No daemon connected yet.".into());
        }
    };
    emit_log(
        &app,
        "Fee",
        "info",
        &format!("💸 Estimating fees via {}", daemon_url),
    );
    let res = match crate::wallet::scanner::read_routing_mode(&app).as_str() {
        "tor" => {
            let tor = crate::wallet::scanner::ensure_tor(&app)
                .await
                .ok_or("Tor is not available")?;
            let daemon = crate::tor::ArtiTransport::connect(tor, daemon_url)
                .await
                .map_err(|e| format!("connect over Tor failed: {:?}", e))?;
            fees_on_daemon(&daemon).await
        }
        "custom" => {
            let proxy = crate::wallet::scanner::read_proxy_address(&app);
            if proxy.trim().is_empty() {
                return Err("Custom routing selected but no proxy address is set".into());
            }
            let daemon = crate::tor::SocksTransport::connect(proxy, daemon_url)
                .await
                .map_err(|e| format!("connect via proxy failed: {:?}", e))?;
            fees_on_daemon(&daemon).await
        }
        _ => {
            let daemon =
                ReqwestTransport::connect(daemon_url, std::time::Duration::from_secs(30)).await?;
            fees_on_daemon(&daemon).await
        }
    };
    match &res {
        Ok(fees) => emit_log(
            &app,
            "Fee",
            "success",
            &format!("💸 Fee estimates (atomic): {:?}", fees),
        ),
        Err(e) => emit_log(
            &app,
            "Fee",
            "error",
            &format!("💸 estimate_fees failed: {}", e),
        ),
    }
    res
}

/// Fetch a tx over one concrete daemon transport, bind it to the requested txid, and
/// return it alongside its confirmations / mempool status. Shared by the proof- and
/// key-verification commands.
async fn fetch_tx_verified<T: HttpTransport + Sync>(
    daemon: &MoneroDaemon<T>,
    txid: [u8; 32],
    txid_hex: &str,
) -> Result<(monero_oxide::transaction::Transaction, u64, bool), String> {
    let txs = daemon
        .transactions(&[txid])
        .await
        .map_err(|e| format!("Failed to fetch transaction: {:?}", e))?;
    let tx = txs
        .into_iter()
        .next()
        .ok_or("Transaction not found on-chain — check the transaction ID")?;

    // Bind the fetched tx to the requested txid — a malicious/defective daemon must not
    // be able to hand back a different transaction for us to verify against.
    if tx.hash() != txid {
        return Err("Daemon returned a transaction whose hash doesn't match the txid".into());
    }

    let (confirmations, in_pool) = tx_confirmations(daemon, txid_hex).await;
    Ok((tx, confirmations, in_pool))
}

/// Fetch the tx over one concrete daemon transport, verify the payment proof, and
/// package the verdict + amount + confirmations for the renderer.
async fn check_proof_on_daemon<T: HttpTransport + Sync>(
    daemon: &MoneroDaemon<T>,
    txid: [u8; 32],
    txid_hex: &str,
    message: &str,
    signature: &str,
    address: &MoneroAddress,
) -> Result<serde_json::Value, String> {
    let (tx, confirmations, in_pool) = fetch_tx_verified(daemon, txid, txid_hex).await?;
    let check =
        crate::wallet::tx_proof::check_out_proof_v2(txid, message, signature, &tx, address)?;

    Ok(serde_json::json!({
        "good": check.good,
        // Atomic (piconero) — the renderer runs formatXmr() over this.
        "received": check.received,
        "amount_unavailable": check.amount_unavailable,
        "confirmations": confirmations,
        "in_pool": in_pool,
    }))
}

/// Fetch the tx over one concrete daemon transport, verify a tx SECRET key, and package
/// the verdict + amount + confirmations for the renderer.
async fn check_key_on_daemon<T: HttpTransport + Sync>(
    daemon: &MoneroDaemon<T>,
    txid: [u8; 32],
    txid_hex: &str,
    tx_key: &str,
    address: &MoneroAddress,
) -> Result<serde_json::Value, String> {
    let (tx, confirmations, in_pool) = fetch_tx_verified(daemon, txid, txid_hex).await?;
    let check = crate::wallet::tx_proof::check_tx_key_v2(tx_key, &tx, address)?;

    Ok(serde_json::json!({
        "good": check.good,
        "received": check.received,
        "amount_unavailable": check.amount_unavailable,
        "confirmations": confirmations,
        "in_pool": in_pool,
    }))
}

/// Verify an OutProofV2 payment proof against the on-chain transaction and report
/// whether it's valid, the atomic amount received by `address`, and confirmations.
/// The verify runs over the configured routing mode (Tor/proxy/clearnet) so the
/// lookup's originating IP is never exposed. UNAUDITED crypto (see wallet/tx_proof.rs).
#[tauri::command]
pub async fn check_tx_proof(
    app: AppHandle,
    state: State<'_, WalletState>,
    txid: String,
    address: String,
    message: String,
    signature: String,
) -> Result<serde_json::Value, String> {
    let txid_hex = txid.trim().to_lowercase();
    let txid_bytes: [u8; 32] = hex::decode(&txid_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("Invalid txid")?;

    let network = state.get_network().await;
    let addr = MoneroAddress::from_str(network, address.trim())
        .map_err(|e| format!("Invalid address: {:?}", e))?;

    let daemon_url = state
        .get_daemon_url()
        .await
        .ok_or("No daemon connected — open a wallet first")?;

    tx_deadline(&app, "Verify proof", async {
        match crate::wallet::scanner::read_routing_mode(&app).as_str() {
            "tor" => {
                let tor = crate::wallet::scanner::ensure_tor(&app)
                    .await
                    .ok_or("Tor is not available — refusing to query over clearnet")?;
                let daemon = crate::tor::ArtiTransport::connect(tor, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon over Tor: {:?}", e))?;
                check_proof_on_daemon(&daemon, txid_bytes, &txid_hex, &message, &signature, &addr)
                    .await
            }
            "custom" => {
                let proxy = crate::wallet::scanner::read_proxy_address(&app);
                if proxy.trim().is_empty() {
                    return Err("Custom routing selected but no proxy address is set".to_string());
                }
                let daemon = crate::tor::SocksTransport::connect(proxy, daemon_url)
                    .await
                    .map_err(|e| format!("Failed to connect to daemon via proxy: {:?}", e))?;
                check_proof_on_daemon(&daemon, txid_bytes, &txid_hex, &message, &signature, &addr)
                    .await
            }
            _ => {
                let daemon =
                    ReqwestTransport::connect(daemon_url, std::time::Duration::from_secs(60))
                        .await?;
                check_proof_on_daemon(&daemon, txid_bytes, &txid_hex, &message, &signature, &addr)
                    .await
            }
        }
    })
    .await
}

// ── Sync ──

#[tauri::command]
pub async fn get_sync_status(state: State<'_, WalletState>) -> Result<SyncStatus, String> {
    Ok(state.get_sync_status().await)
}

#[tauri::command]
pub async fn refresh(_state: State<'_, WalletState>) -> Result<(), String> {
    // TODO: Trigger immediate scan cycle
    Ok(())
}

/// Mirror of the renderer's vigilHotWallet flag: while an EJECT vigil is armed,
/// a UI lock retains the Monero spend key so the order can dispatch unattended
/// (see WalletState::lock). Advisory flag — fire-and-forget from the renderer.
/// Verify a vault password without unlocking (no scanner restart). Returns
/// true if the password decrypts the wallet file, false otherwise.
#[tauri::command]
pub async fn verify_password(
    state: State<'_, WalletState>,
    identity_id: String,
    password: String,
) -> Result<bool, String> {
    Ok(state.verify_password(&identity_id, &password).await.is_ok())
}

#[tauri::command]
pub async fn set_vigil_hot(state: State<'_, WalletState>, hot: bool) -> Result<(), String> {
    state
        .vigil_hot
        .store(hot, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Change a wallet's vault password. `old_password` is the authorization (it must
/// decrypt the vault); the wallet is then re-encrypted under `new_password`. The seed
/// is neither shown nor altered. Callable while the wallet is open or locked; if it's
/// the resident wallet, the in-memory retained password is rotated too so the next
/// auto-lock persists under the new password rather than reverting the change.
#[tauri::command]
pub async fn change_wallet_password(
    app: AppHandle,
    state: State<'_, WalletState>,
    identity_id: String,
    old_password: String,
    new_password: String,
) -> Result<(), String> {
    if new_password.is_empty() {
        return Err("New passphrase cannot be empty".into());
    }
    if new_password == old_password {
        return Err("New passphrase must differ from the current one".into());
    }
    // Distinguish a wrong current passphrase from other failures with a clean message.
    if state
        .verify_password(&identity_id, &old_password)
        .await
        .is_err()
    {
        return Err("Incorrect current passphrase".into());
    }
    state
        .change_password(&identity_id, &old_password, &new_password)
        .await?;
    emit_log(&app, "Wallet", "success", "🔑 Vault passphrase changed");
    Ok(())
}

/// Reset scan height and restart the scanner from the given height.
#[tauri::command]
pub async fn rescan(
    app: AppHandle,
    state: State<'_, WalletState>,
    height: u64,
) -> Result<(), String> {
    emit_log(
        &app,
        "Sync",
        "info",
        &format!("🔄 Rescan requested from height {}...", height),
    );

    // Reset scan height and clear cached outputs
    state.reset_scan(height).await;

    // Restart the scanner
    let app_clone = app.clone();
    BlockScanner::start(app_clone, "", "", height).await?;

    emit_log(
        &app,
        "Sync",
        "success",
        &format!("✅ Rescan started from height {}", height),
    );
    Ok(())
}


// ── Offline (sign-only) spending ──
// Two-device cold-signing flow (docs/offline-signing-plan.md §5):
//   hot:  export_watch_only ──(watchonly QR)──> cold: import_watch_only
//   hot:  export_unsigned_transfer ──(unsigned QR)──> cold: sign_offline_transfer
//        <──(signed QR)── hot: import_signed_transfer
// The spend key never leaves the cold device; the hot device holds only the
// view key + public spend point.

/// Export this wallet's watch-only pair (view key + PUBLIC spend point) as a
/// `watchonly` envelope for the cold device. Requires an unlocked wallet; the
/// spend key is never read, derived, or serialized.
#[tauri::command]
pub async fn export_watch_only(
    app: AppHandle,
    state: State<'_, WalletState>,
) -> Result<serde_json::Value, String> {
    let (id, spend_pub, view_sec) = state
        .watch_parts_from_memory()
        .await
        .ok_or("Wallet is locked — unlock before exporting the watch-only pair")?;
    let view_pair = state.get_view_pair().await.ok_or("Wallet is locked")?;
    let network = state.get_network().await;
    let address = view_pair.legacy_address(network).to_string();

    let payload = crate::wallet::offline::WatchOnlyPayload {
        view_key_hex: hex::encode(&*view_sec),
        spend_public_key_hex: hex::encode(spend_pub),
        address: address.clone(),
    };
    let envelope = crate::wallet::offline::encode_watch_only_payload(&payload)?;
    emit_log(
        &app,
        "Wallet",
        "warn",
        "📤 Watch-only pair exported — it grants VIEW access only; the spend key was never included.",
    );
    Ok(serde_json::json!({
        "envelope": envelope,
        "identityId": id,
        "address": address,
    }))
}

/// Import a `watchonly` envelope from the cold device as a NEW watch-only vault:
/// persist it under the hot device's own password, verify the envelope's claimed
/// address against the keys it actually carries (tamper guard), then unlock and
/// start scanning from genesis. Signing stays impossible — no spend key exists
/// anywhere on this device.
#[tauri::command]
pub async fn import_watch_only(
    app: AppHandle,
    state: State<'_, WalletState>,
    envelope: String,
    password: String,
    name: Option<String>,
) -> Result<serde_json::Value, String> {
    let env = crate::wallet::offline::decode_envelope(&envelope)?;
    let payload = crate::wallet::offline::decode_watch_only_payload(&env)?;

    // Tamper guard: the address the payload claims must be the address these
    // keys actually derive. A swapped spend point yields a different address.
    let spend_bytes: [u8; 32] = hex::decode(&payload.spend_public_key_hex)
        .map_err(|e| format!("Invalid public spend point: {}", e))?
        .try_into()
        .map_err(|_| "Public spend point must be 32 bytes".to_string())?;
    let spend_point = monero_oxide::ed25519::CompressedPoint::from(spend_bytes)
        .decompress()
        .ok_or("Invalid public spend point")?;
    let view_bytes: [u8; 32] = hex::decode(&payload.view_key_hex)
        .map_err(|e| format!("Invalid view key: {}", e))?
        .try_into()
        .map_err(|_| "View key must be 32 bytes".to_string())?;
    let view_key = zeroize::Zeroizing::new(monero_oxide::ed25519::Scalar::from(
        curve25519_dalek::Scalar::from_bytes_mod_order(view_bytes),
    ));
    let network = state.get_network().await;
    let view_pair = monero_wallet::ViewPair::new(spend_point, view_key)
        .map_err(|e| format!("Failed to create ViewPair: {:?}", e))?;
    let derived = view_pair.legacy_address(network).to_string();
    if !derived.eq_ignore_ascii_case(&payload.address) {
        return Err(format!(
            "REFUSED: watch-only envelope address mismatch — payload claims {} but the \
             keys derive {} (tampered or corrupted envelope)",
            payload.address, derived
        ));
    }

    let identity_id = name.unwrap_or_else(|| format!("wo-{}", &payload.spend_public_key_hex[..12]));
    let data_dir = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    crate::wallet::storage::save_watch_only_vault(
        &data_dir,
        &identity_id,
        &password,
        &payload.spend_public_key_hex,
        &payload.view_key_hex,
    )?;

    // Register the new identity so it appears in the wallet switcher and is
    // discovered for background sync (the create_wallet flow persists the
    // identity list separately in the renderer — here the import owns it).
    let now = chrono::Utc::now().timestamp_millis().max(0) as u64;
    let mut ids = crate::commands::identity::get_identities(app.clone())
        .await
        .unwrap_or_default();
    if !ids.iter().any(|i| i.id == identity_id) {
        ids.push(crate::wallet::Identity {
            id: identity_id.clone(),
            name: identity_id.clone(),
            created: now,
        });
        if let Err(e) = crate::commands::identity::save_identities(app.clone(), ids).await {
            log::warn!("identity registration for {identity_id} failed: {e}");
        }
    }

    state.unlock(&identity_id, &password).await?;
    emit_log(
        &app,
        "Wallet",
        "success",
        &format!("✅ Watch-only wallet imported: {}", identity_id),
    );

    let scan_height = state.get_scan_height().await;
    crate::wallet::BlockScanner::start(app.clone(), "", "", scan_height).await?;

    // Watch tier: persist the view pair so boot-time watch sync covers this
    // identity too (best-effort, consent-gated, encrypt-or-don't-write inside).
    if crate::wallet::scanner::read_config_bool(&app, "watchSync") {
        let view_sec = zeroize::Zeroizing::new(view_bytes);
        if let Err(e) =
            crate::wallet::storage::save_watch(&data_dir, &identity_id, &spend_bytes, &view_sec)
        {
            log::warn!("watch store write for {identity_id} failed: {e}");
        }
    }

    Ok(serde_json::json!({
        "identityId": identity_id,
        "address": derived,
        "success": true,
    }))
}

/// Step 1 of the offline flow (hot device): prepare a transfer (coins, decoys,
/// fee — all online) and export it as an `unsigned` envelope + join key. The
/// prepared spend is staged locally so the later import can prove the signed
/// transaction returned from the cold device is EXACTLY this one.
#[tauri::command]
pub async fn export_unsigned_transfer(
    app: AppHandle,
    state: State<'_, WalletState>,
    destinations: Vec<TxDestination>,
    _account_index: u32,
    priority: Option<u8>,
    selected_output_ids: Option<Vec<String>>,
) -> Result<serde_json::Value, String> {
    emit_log(&app, "Tx", "info", "📤 Preparing offline transaction...");
    let (tx_metadata, meta_key, prepared) =
        prepare_and_stage(&app, &state, destinations, priority, selected_output_ids).await?;

    let has_change = prepared
        .signable
        .payments()
        .iter()
        .any(|p| matches!(p, monero_wallet::send::InternalPayment::Change(_)));
    let staged = crate::wallet::offline::StagedTransferMeta {
        account: 0,
        payment_count: prepared.destinations.len(),
        input_count: prepared.signable.real_inputs().len(),
        has_change,
        unsigned_tx_hex: hex::encode(&tx_metadata),
        amount: prepared.amount.to_string(),
        fee: prepared.fee.to_string(),
    };
    state.stage_offline_meta(&meta_key, staged).await;

    let meta = crate::wallet::offline::EnvelopeMeta {
        to: prepared
            .destinations
            .iter()
            .map(|(addr, amt)| format!("{} {}", amt, addr))
            .collect(),
        amount: WalletState::format_xmr(prepared.amount),
        fee: WalletState::format_xmr(prepared.fee),
        account: 0,
        // Join key: the hot side re-links the signed envelope to its staged
        // spend through this (keccak of the unsigned signable). Embedded here —
        // NOT renderer-supplied at import — so the link cannot be redirected.
        tx_key: meta_key.clone(),
    };
    let envelope = crate::wallet::offline::encode_envelope(
        crate::wallet::offline::KIND_UNSIGNED,
        hex::encode(&tx_metadata),
        meta,
    )?;

    emit_log(
        &app,
        "Tx",
        "success",
        &format!(
            "✅ Offline transfer prepared: {} XMR + {} XMR fee — sign it on the cold device",
            WalletState::format_xmr(prepared.amount),
            WalletState::format_xmr(prepared.fee)
        ),
    );
    Ok(serde_json::json!({
        "envelope": envelope,
        "joinKey": meta_key,
        "destinations": prepared.destinations,
        "amount": prepared.amount,
        "fee": prepared.fee,
        "inputCount": prepared.signable.real_inputs().len(),
    }))
}

/// Step 2 of the offline flow (COLD device, no internet): verify the unsigned
/// envelope (fail-closed: foreign change output, zero payments, empty inputs)
/// and sign it with the resident spend key. Purely local — no daemon, no
/// network. A watch-only vault cannot reach this point (no spend key).
#[tauri::command]
pub async fn sign_offline_transfer(
    app: AppHandle,
    state: State<'_, WalletState>,
    envelope: String,
) -> Result<serde_json::Value, String> {
    let env = crate::wallet::offline::decode_envelope(&envelope)?;
    if env.k != crate::wallet::offline::KIND_UNSIGNED {
        return Err(format!("Expected an unsigned envelope, got kind '{}'", env.k));
    }
    let payload = crate::wallet::offline::envelope_payload(&env)?;
    let signable = monero_wallet::send::SignableTransaction::read(&mut payload.as_slice())
        .map_err(|e| format!("Invalid transaction data: {:?}", e))?;

    let view_pair = state.get_view_pair().await.ok_or("Wallet is locked")?;
    let summary =
        crate::wallet::offline::verify_before_sign(&signable, &view_pair.spend().compress())?;

    let spend_key = state
        .get_spend_key()
        .await
        .ok_or("No spend key resident — locked or watch-only wallet cannot sign")?;

    let signed = transact::sign_transaction(
        transact::PreparedTransaction {
            signable,
            fee: summary.fee,
            amount: summary.destinations.iter().map(|(_, a)| *a).sum(),
            destinations: summary.destinations.clone(),
            spent_ids: vec![],
            tx_key_hex: String::new(),
        },
        &spend_key,
    )?;

    let signed_env = crate::wallet::offline::encode_envelope(
        crate::wallet::offline::KIND_SIGNED,
        hex::encode(signed.serialize()),
        // Echo the join key back so the hot device re-links to its staged spend.
        crate::wallet::offline::EnvelopeMeta {
            tx_key: env.meta.tx_key.clone(),
            ..Default::default()
        },
    )?;

    emit_log(
        &app,
        "Tx",
        "success",
        &format!(
            "✅ Offline transaction signed: {} XMR to {} destination(s), {} XMR fee — send the QR back",
            WalletState::format_xmr(summary.destinations.iter().map(|(_, a)| *a).sum()),
            summary.destinations.len(),
            WalletState::format_xmr(summary.fee)
        ),
    );
    Ok(serde_json::json!({
        "envelope": signed_env,
        "summary": {
            "destinations": summary.destinations,
            "change": summary.change,
            "fee": summary.fee,
            "inputCount": summary.input_count,
        },
    }))
}

/// Step 3 of the offline flow (hot device): import the `signed` envelope, prove
/// it is EXACTLY the staged prepared transaction (ring-multiset bijection +
/// output shape — [R3]), show the backend-authoritative OS confirm dialog, then
/// broadcast over the configured routing mode and commit the staged spend.
/// The join key travels INSIDE the envelope (echoed by the cold device), never
/// from the renderer, so the staged-spend link cannot be redirected.
#[tauri::command]
pub async fn import_signed_transfer(
    app: AppHandle,
    state: State<'_, WalletState>,
    envelope: String,
) -> Result<String, String> {
    let env = crate::wallet::offline::decode_envelope(&envelope)?;
    if env.k != crate::wallet::offline::KIND_SIGNED {
        return Err(format!("Expected a signed envelope, got kind '{}'", env.k));
    }
    let join_key = env.meta.tx_key.clone();
    if join_key.is_empty() {
        return Err("Signed envelope carries no join key — it was not produced by this flow".into());
    }
    let payload = crate::wallet::offline::envelope_payload(&env)?;
    let signed = monero_oxide::transaction::Transaction::read(&mut payload.as_slice())
        .map_err(|e| format!("Invalid signed transaction data: {:?}", e))?;

    // Prove the signed tx matches the staged prepared tx — the core [R3] guard.
    // The comparison uses the HOT-side staged copy of the unsigned transaction
    // (never the envelope's own), so a swapped envelope cannot masquerade.
    let staged_meta = state
        .peek_offline_meta(&join_key)
        .await
        .ok_or("No staged transaction for this join key — prepare it first in this session")?;
    let staged_bytes = hex::decode(&staged_meta.unsigned_tx_hex)
        .map_err(|e| format!("Corrupt staged record: {}", e))?;
    let staged_signable =
        monero_wallet::send::SignableTransaction::read(&mut staged_bytes.as_slice())
            .map_err(|e| format!("Corrupt staged record: {:?}", e))?;
    crate::wallet::offline::verify_signed_against_staged(&signed, &staged_signable)?;

    // OS confirmation from the BACKEND-authoritative staged record (never the
    // renderer-supplied envelope text).
    {
        use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
        let staged = state.peek_pending_spend(&join_key).await;
        let body = format_spend_confirm(staged.as_ref().map(|(d, _a, f)| (d.as_slice(), *f)));
        let ok = app
            .dialog()
            .message(body)
            .title("Confirm offline transaction")
            .buttons(MessageDialogButtons::OkCancelCustom(
                "Send".into(),
                "Cancel".into(),
            ))
            .blocking_show();
        if !ok {
            state.discard_pending_spend(&join_key).await;
            state.clear_offline_meta(&join_key).await;
            emit_log(&app, "Tx", "warn", "Offline transaction cancelled at confirmation");
            return Err("Transaction cancelled".into());
        }
    }

    let result = broadcast_and_commit(&app, &state, signed, join_key.clone()).await;
    state.clear_offline_meta(&join_key).await;
    result
}

#[cfg(test)]
mod spend_confirm_tests {
    use super::format_spend_confirm;

    // The spend-confirm dialog MUST be built from the backend's staged destinations, never
    // from renderer-supplied text — otherwise a hostile renderer could show address A while
    // the prepared tx pays B. These tests pin that the body reflects the given destinations.

    #[test]
    fn body_renders_the_backend_destination_and_fee() {
        let dests = vec![("4RealDestAddr".to_string(), 1_500_000_000_000u64)]; // 1.5 XMR
        let body = format_spend_confirm(Some((&dests, 30_000_000u64))); // 0.00003 XMR fee
        assert!(
            body.contains("4RealDestAddr"),
            "must show the actual destination"
        );
        assert!(body.contains("1.5 XMR"), "must show the actual amount");
        assert!(
            body.contains("Network fee 0.00003 XMR"),
            "must show the fee"
        );
    }

    #[test]
    fn body_never_contains_an_address_not_in_the_staged_destinations() {
        // A renderer passing to="4PhishAddr" cannot influence this body — it only takes
        // the backend destinations. The phishing address must be absent.
        let dests = vec![("4RealDestAddr".to_string(), 1_000_000_000_000u64)];
        let body = format_spend_confirm(Some((&dests, 0)));
        assert!(!body.contains("4PhishAddr"));
    }

    #[test]
    fn body_lists_every_destination_for_a_multi_output_send() {
        let dests = vec![
            ("addrA".to_string(), 1_000_000_000_000u64),
            ("addrB".to_string(), 2_000_000_000_000u64),
        ];
        let body = format_spend_confirm(Some((&dests, 0)));
        assert!(
            body.contains("addrA") && body.contains("addrB"),
            "must list all destinations"
        );
    }

    #[test]
    fn fallback_body_is_generic_and_never_a_destination_line() {
        // No staged record → fail-closed generic warning. It must NOT render the
        // "Send … to …" destination format (which is the only place an address appears),
        // so no renderer-supplied text can leak through this path.
        let body = format_spend_confirm(None);
        assert!(
            body.contains("could not be"),
            "fallback must warn it couldn't verify"
        );
        assert!(
            !body.contains("Send "),
            "fallback must not render a destination line"
        );
    }
}
