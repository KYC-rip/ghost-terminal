//! Transfer-grant Tauri commands — the native EJECT autonomous-sell barrier.
//!
//! FUND SAFETY: arming a grant is the ONE human authorization (a vault-password
//! verify); every later `relay_transfer_grant` is autonomous, bounded ONLY by the
//! native ledger's caps (per-tx / budget / fills / expiry / total-armed / duration).
//! A compromised renderer can reach `relay_transfer_grant` directly via `invoke`, so
//! the ledger — not the renderer — is the sole spending barrier. The destination
//! address is renderer-trusted by design: the caps bound HOW MUCH leaves, not WHERE.
//! See ripley-os/docs/auto-eject-design.md §1/§1a/§1b and wallet::transfer_ledger.

use crate::emit_log;
use crate::wallet::transfer_ledger::{format_xmr, parse_xmr};
use crate::wallet::{TxDestination, WalletState};
use tauri::{AppHandle, Manager, State};

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Arm (or re-arm) a transfer grant. Verifies the vault password once (the sole
/// human authorization), asserts the grant's wallet is the resident one, records the
/// grant in the native ledger under its caps, and makes the spend key resident behind
/// a still-locked UI so autonomous relays can sign.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
pub async fn arm_transfer_grant(
    app: AppHandle,
    state: State<'_, WalletState>,
    id: String,
    identity_id: String,
    account_index: u32,
    budget_xmr: String,
    per_tx_xmr: String,
    max_fills: u32,
    expires_at: i64,
    password: String,
) -> Result<(), String> {
    // 1. The one human authorization — decrypt-only, no unlock/scanner restart.
    state
        .verify_password(&identity_id, &password)
        .await
        .map_err(|_| "Incorrect passphrase".to_string())?;

    // 2. The grant's wallet MUST be the resident one — else its relays would try to
    //    spend from whatever identity happens to be loaded.
    if state.get_active_identity_id().await.as_deref() != Some(identity_id.as_str()) {
        return Err(
            "This wallet is not the active identity — open it before arming a grant".into(),
        );
    }

    // 3. Parse the XMR budgets to atomic piconero.
    let budget_atomic = parse_xmr(&budget_xmr)?;
    let per_tx_atomic = parse_xmr(&per_tx_xmr)?;

    // 4. Record the grant under its caps (validates budget/per-tx/fills/expiry, clamps
    //    the duration ceiling, and enforces the total-armed exposure cap).
    let now = now_ms();
    state.transfer_grants.lock().await.arm(
        id.clone(),
        identity_id.clone(),
        account_index,
        budget_atomic,
        per_tx_atomic,
        max_fills,
        expires_at,
        now,
    )?;

    // 5. Make the spend key resident (behind the still-locked UI). If this fails after
    //    a successful verify (shouldn't happen), disarm the just-armed grant again so
    //    we never leave an armed grant with no signing path.
    if let Err(e) = state.make_hot(&identity_id, &password).await {
        state.transfer_grants.lock().await.revoke(&id);
        return Err(e);
    }

    emit_log(
        &app,
        "Grant",
        "success",
        &format!(
            "🔥 Armed transfer grant {} — budget {} XMR, expires {}",
            id,
            format_xmr(budget_atomic),
            expires_at
        ),
    );
    Ok(())
}

/// Autonomously relay up to the grant's per-tx cap to `to`. Atomic reserve-then-commit:
/// reserve under the ledger lock, broadcast OUTSIDE the lock (~90s), then commit or
/// roll back. Pre-authorized by the arm — no confirmation dialog.
#[tauri::command]
pub async fn relay_transfer_grant(
    app: AppHandle,
    state: State<'_, WalletState>,
    grant_id: String,
    to: String,
    amount_xmr: String,
) -> Result<String, String> {
    // 1. Parse the amount; snapshot the resident identity for the reserve check.
    let amount = parse_xmr(&amount_xmr)?;
    let active = state.get_active_identity_id().await;
    let now = now_ms();

    // 2. RESERVE under the lock (serializes concurrent relays), then DROP the lock —
    //    the broadcast must not hold it. The identity check binds the spend to the
    //    grant's own wallet.
    state
        .transfer_grants
        .lock()
        .await
        .reserve(&grant_id, amount, active.as_deref(), now)?;

    // 3. The spend key must be resident (armed ledger flag can outlive the key across a
    //    restart). If cold, roll the reservation back and demand a re-arm.
    if state.get_spend_key().await.is_none() {
        state
            .transfer_grants
            .lock()
            .await
            .rollback(&grant_id, amount);
        return Err("wallet not hot — re-arm required".into());
    }

    // 4. Build the tx from the grant's source account (priority 0 = Normal).
    let account_index = match state.transfer_grants.lock().await.account_index(&grant_id) {
        Some(a) => a,
        None => {
            state
                .transfer_grants
                .lock()
                .await
                .rollback(&grant_id, amount);
            return Err("grant not found".into());
        }
    };
    let prep = match crate::commands::wallet::prepare_transfer(
        app.clone(),
        app.state::<WalletState>(),
        vec![TxDestination {
            address: to.clone(),
            amount: amount.to_string(),
        }],
        account_index,
        Some(0),
        None,
    )
    .await
    {
        Ok(p) => p,
        Err(e) => {
            state
                .transfer_grants
                .lock()
                .await
                .rollback(&grant_id, amount);
            return Err(e);
        }
    };

    // 5. Sign + broadcast via the no-dialog helper (pre-authorized at arm time). On
    //    failure, roll the reservation back AND discard the pending spend prepare()
    //    staged, so the (never-broadcast) inputs return to the spendable balance.
    let tx_hash =
        match crate::commands::wallet::sign_and_broadcast(&app, &state, prep.tx_metadata.clone())
            .await
        {
            Ok(h) => h,
            Err(e) => {
                state
                    .transfer_grants
                    .lock()
                    .await
                    .rollback(&grant_id, amount);
                state
                    .discard_pending_spend(&crate::wallet::state::tx_meta_key(&prep.tx_metadata))
                    .await;
                return Err(e);
            }
        };

    // 6. COMMIT the spend under the ledger lock (moves reserved → spent, auto-disarms
    //    if exhausted). The next lock() drops the key when retention is no longer
    //    justified — nothing to clear here (the wallet may be unlocked and in use).
    state
        .transfer_grants
        .lock()
        .await
        .commit(&grant_id, amount, now_ms());

    // 7. Explicit audit line (no secrets): grant, amount, destination, tx hash.
    emit_log(
        &app,
        "Grant",
        "success",
        &format!(
            "✅ Grant {} relayed {} XMR → {} (tx {})",
            grant_id,
            format_xmr(amount),
            to,
            tx_hash
        ),
    );
    Ok(tx_hash)
}

/// Disarm a single grant (keeps its spent history for audit). If no armed grants
/// remain and the legacy vigil flag is off, drop the hot key immediately when locked.
#[tauri::command]
pub async fn revoke_transfer_grant(
    state: State<'_, WalletState>,
    id: String,
) -> Result<(), String> {
    state.transfer_grants.lock().await.revoke(&id);
    if !state.grants_armed().await && !state.vigil_hot.load(std::sync::atomic::Ordering::SeqCst) {
        state.clear_spend_key_if_locked().await;
    }
    Ok(())
}

/// PANIC-WIPE path (design §8): disarm ALL grants, clear the legacy vigil flag (a panic
/// must kill EVERY retention source), and drop the hot key when locked. Does NO network
/// I/O so it wins the ~120ms page-reload race.
#[tauri::command]
pub async fn revoke_all_transfer_grants(state: State<'_, WalletState>) -> Result<(), String> {
    state.transfer_grants.lock().await.revoke_all();
    state
        .vigil_hot
        .store(false, std::sync::atomic::Ordering::SeqCst);
    state.clear_spend_key_if_locked().await;
    Ok(())
}

/// Native source-of-truth status for a grant. `hot` reflects whether the spend key is
/// actually resident (the armed ledger flag can outlive the key across a restart, §5a).
/// Stale reservations + expiry are healed on read. Unknown id → Ok(None).
#[tauri::command]
pub async fn transfer_grant_status(
    state: State<'_, WalletState>,
    id: String,
) -> Result<Option<TransferGrantStatus>, String> {
    // `hot` must answer "can THIS grant actually sign right now" — so it's not just
    // "a spend key is resident" but "the resident key belongs to this grant's wallet".
    // Otherwise a grant armed for wallet Y would report hot=true merely because wallet
    // X (a different identity) is the one currently open, which the daemon's armed&&hot
    // gate would misread as ready-to-fire (reserve() would then correctly reject it).
    let key_resident = state.get_spend_key().await.is_some();
    let active = state.get_active_identity_id().await;
    let mut ledger = state.transfer_grants.lock().await;
    Ok(ledger.status(&id, now_ms()).map(|g| TransferGrantStatus {
        spent_xmr: format_xmr(g.spent_atomic),
        reserved_xmr: format_xmr(g.reserved_atomic),
        fills: g.fills,
        armed: g.armed,
        hot: key_resident && active.as_deref() == Some(g.identity_id.as_str()),
        expires_at: g.expires_at_ms,
    }))
}

/// Status payload. Field names serialize as-is (snake_case) to match the shipped JS
/// contract in ripley-os/src/os/platform/native.ts.
#[derive(serde::Serialize)]
pub struct TransferGrantStatus {
    spent_xmr: String,
    reserved_xmr: String,
    fills: u32,
    armed: bool,
    hot: bool,
    expires_at: i64,
}
