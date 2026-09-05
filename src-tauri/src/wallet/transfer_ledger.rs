//! Native transfer-grant ledger — the ONLY spending barrier for autonomous
//! EJECT sells (see ripley-os/docs/auto-eject-design.md §1/§1a/§1b).
//!
//! Threat model: a compromised renderer can call `relay_transfer_grant` directly,
//! so this ledger must be self-contained and race-safe. It is guarded by a single
//! `tokio::sync::Mutex` in `WalletState` and enforces an atomic **reserve-then-commit**
//! flow: a relay first RESERVES its amount under the lock (which serializes concurrent
//! calls so the second sees the first's reservation), broadcasts OUTSIDE the lock, then
//! COMMITS (or rolls back) under the lock. Caps — per-tx, total budget (reserved+spent),
//! fill count, expiry, a total-armed-exposure ceiling, and a max-armed-duration ceiling —
//! bound how much can ever leave. The destination address is renderer-trusted by design:
//! the caps bound *how much* leaves, not *where*.
//!
//! No key material is ever persisted — the JSON blob holds only ids, amounts, and
//! timestamps. Armed entries persist across restart intentionally (§5a re-arm flow:
//! `armed=true` but the spend key is not resident until a re-arm makes it hot again).

use std::collections::HashMap;
use std::path::PathBuf;

/// Hard ceiling on how long a grant may stay armed (7 days). A grant auto-disarms
/// past `armed_at + max_armed_ms` and requires a fresh re-arm (which re-verifies the
/// vault password). Bounds the window in which a resident spend key can be used.
pub const MAX_ARMED_MS: i64 = 7 * 24 * 3600 * 1000;

/// Total-armed-exposure cap across ALL armed grants (50 XMR, in piconero). A
/// deliberate NATIVE constant — not renderer-configurable — so a compromised page
/// can't arm runaway aggregate exposure by stacking many grants. The sum of the
/// budgets of all armed grants can never exceed this.
pub const MAX_TOTAL_ARMED_ATOMIC: u64 = 50_000_000_000_000; // 50 XMR

/// A reservation older than this (3 min) is considered orphaned and reaped on next
/// access. Deliberately > the 90s tx-broadcast deadline (TX_DEADLINE_SECS) so a
/// live, in-flight relay can NEVER have its reservation reaped out from under it —
/// only a reservation left behind by a crash between broadcast and commit is cleared.
pub const RESERVATION_TIMEOUT_MS: i64 = 180_000;

/// One piconero-denominated 1 XMR.
const PICONERO_PER_XMR: u64 = 1_000_000_000_000;

/// A single autonomous-spend grant. All monetary fields are atomic piconero.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferGrant {
    pub id: String,
    pub identity_id: String,
    pub account_index: u32,
    pub budget_atomic: u64,
    pub per_tx_atomic: u64,
    pub spent_atomic: u64,    // committed spend
    pub reserved_atomic: u64, // in-flight reservation
    pub reserved_at_ms: i64,  // stamp of the most recent reservation
    pub fills: u32,
    pub max_fills: u32,
    pub armed_at_ms: i64,
    pub expires_at_ms: i64,
    pub max_armed_ms: i64, // hard duration ceiling (defaults to MAX_ARMED_MS)
    pub armed: bool,
}

/// The in-memory, authoritative ledger. Persisted (best-effort) to `path` on every
/// mutation. Owned by `WalletState` behind a `tokio::sync::Mutex`.
pub struct GrantLedger {
    grants: HashMap<String, TransferGrant>,
    path: PathBuf,
}

/// Parse a decimal XMR string (e.g. "1.5", "0.000000000001") to atomic piconero.
/// Rejects empty / negative / malformed input and more than 12 fractional digits
/// (piconero precision). Uses checked arithmetic so an over-large value errors rather
/// than wraps.
pub fn parse_xmr(s: &str) -> Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("amount is empty".to_string());
    }
    if s.starts_with('-') {
        return Err("amount must be non-negative".to_string());
    }
    let (whole_str, frac_str) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if whole_str.is_empty() && frac_str.is_empty() {
        return Err("malformed amount".to_string());
    }
    if !whole_str.chars().all(|c| c.is_ascii_digit()) {
        return Err("malformed amount".to_string());
    }
    if !frac_str.chars().all(|c| c.is_ascii_digit()) {
        return Err("malformed amount".to_string());
    }
    if frac_str.len() > 12 {
        return Err("too many decimals (max 12 for piconero precision)".to_string());
    }
    let whole: u64 = if whole_str.is_empty() {
        0
    } else {
        whole_str
            .parse()
            .map_err(|_| "amount too large".to_string())?
    };
    // Right-pad the fraction to a full 12 digits so "0.5" → 500_000_000_000.
    let mut frac_padded = frac_str.to_string();
    while frac_padded.len() < 12 {
        frac_padded.push('0');
    }
    let frac: u64 = frac_padded
        .parse()
        .map_err(|_| "malformed amount".to_string())?;
    let whole_atomic = whole
        .checked_mul(PICONERO_PER_XMR)
        .ok_or_else(|| "amount too large".to_string())?;
    whole_atomic
        .checked_add(frac)
        .ok_or_else(|| "amount too large".to_string())
}

/// Format atomic piconero as a trimmed decimal XMR string. Mirror of
/// `WalletState::format_xmr` so the ledger module is self-contained/testable.
pub fn format_xmr(atomic: u64) -> String {
    let whole = atomic / PICONERO_PER_XMR;
    let frac = atomic % PICONERO_PER_XMR;
    format!("{}.{:012}", whole, frac)
        .trim_end_matches('0')
        .trim_end_matches('.')
        .to_string()
}

impl GrantLedger {
    /// Load the ledger from `path`. A missing or corrupt file yields an empty map
    /// (the feature simply starts with no grants) rather than failing startup.
    pub fn load(path: PathBuf) -> GrantLedger {
        let grants = match std::fs::read_to_string(&path) {
            Ok(data) => {
                serde_json::from_str::<HashMap<String, TransferGrant>>(&data).unwrap_or_default()
            }
            Err(_) => HashMap::new(),
        };
        GrantLedger { grants, path }
    }

    /// Best-effort persist (never blocks a spend on disk). Serializes only
    /// ids/amounts/timestamps — NO key material — so the blob is safe at rest.
    fn persist(&self) {
        if let Some(parent) = self.path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                log::warn!("transfer ledger: could not create data dir: {}", e);
                return;
            }
        }
        match serde_json::to_string_pretty(&self.grants) {
            Ok(blob) => {
                // Write to a temp file then rename: rename is atomic on the same
                // filesystem, so a crash mid-write can never leave a half-written
                // (corrupt) ledger — load() would otherwise fall back to an empty
                // map and silently drop the armed-grant audit history.
                let tmp = self.path.with_extension("json.tmp");
                if let Err(e) = std::fs::write(&tmp, blob) {
                    log::warn!("transfer ledger: persist (tmp write) failed: {}", e);
                } else if let Err(e) = std::fs::rename(&tmp, &self.path) {
                    log::warn!("transfer ledger: persist (rename) failed: {}", e);
                }
            }
            Err(e) => log::warn!("transfer ledger: serialize failed: {}", e),
        }
    }

    /// Reap a reservation orphaned by a crash between broadcast and commit
    /// (reserved > 0 and older than RESERVATION_TIMEOUT_MS). Liveness fix, not a
    /// safety hole: it only ever FREES budget the process forgot to commit/rollback,
    /// and the timeout exceeds the broadcast deadline so a live relay is never reaped.
    fn clear_stale_reservation(&mut self, id: &str, now_ms: i64) {
        let mut cleared = false;
        if let Some(g) = self.grants.get_mut(id) {
            if g.reserved_atomic > 0
                && now_ms.saturating_sub(g.reserved_at_ms) > RESERVATION_TIMEOUT_MS
            {
                log::warn!(
                    "transfer grant {}: reaping stale reservation of {} piconero (> {}ms old)",
                    id,
                    g.reserved_atomic,
                    RESERVATION_TIMEOUT_MS
                );
                g.reserved_atomic = 0;
                cleared = true;
            }
        }
        if cleared {
            self.persist();
        }
    }

    /// Arm (or re-arm) a grant. Validates the caps, clamps expiry to the
    /// max-armed-duration ceiling, and enforces the total-armed-exposure cap across
    /// all OTHER armed grants. Re-arming an existing id (§5a re-arm after restart)
    /// PRESERVES spent/reserved/fills — a re-arm can NEVER reset budget accounting,
    /// which is a fund-safety invariant.
    #[allow(clippy::too_many_arguments)]
    pub fn arm(
        &mut self,
        id: String,
        identity_id: String,
        account_index: u32,
        budget_atomic: u64,
        per_tx_atomic: u64,
        max_fills: u32,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<(), String> {
        if budget_atomic == 0 {
            return Err("budget must be greater than zero".to_string());
        }
        if per_tx_atomic == 0 {
            return Err("per-transaction amount must be greater than zero".to_string());
        }
        if per_tx_atomic > budget_atomic {
            return Err("per-transaction amount exceeds the budget".to_string());
        }
        if max_fills < 1 {
            return Err("max_fills must be at least 1".to_string());
        }
        if expires_at_ms <= now_ms {
            return Err("expiry is in the past".to_string());
        }
        // Duration ceiling: a grant can never outlive `now + MAX_ARMED_MS`.
        let expires_at_ms = expires_at_ms.min(now_ms.saturating_add(MAX_ARMED_MS));

        // Total-armed-exposure cap: the sum of the budgets of all OTHER armed grants
        // plus this one must stay under the native ceiling.
        let others: u64 = self
            .grants
            .values()
            .filter(|g| g.armed && g.id != id)
            .map(|g| g.budget_atomic)
            .fold(0u64, u64::saturating_add);
        if others.saturating_add(budget_atomic) > MAX_TOTAL_ARMED_ATOMIC {
            return Err("total armed budget exceeds the native exposure cap".to_string());
        }

        match self.grants.get_mut(&id) {
            Some(g) => {
                // Re-arm: preserve spend accounting, refresh terms + arm window.
                g.identity_id = identity_id;
                g.account_index = account_index;
                g.budget_atomic = budget_atomic;
                g.per_tx_atomic = per_tx_atomic;
                g.max_fills = max_fills;
                g.expires_at_ms = expires_at_ms;
                g.max_armed_ms = MAX_ARMED_MS;
                g.armed_at_ms = now_ms;
                g.armed = true;
            }
            None => {
                self.grants.insert(
                    id.clone(),
                    TransferGrant {
                        id,
                        identity_id,
                        account_index,
                        budget_atomic,
                        per_tx_atomic,
                        spent_atomic: 0,
                        reserved_atomic: 0,
                        reserved_at_ms: 0,
                        fills: 0,
                        max_fills,
                        armed_at_ms: now_ms,
                        expires_at_ms,
                        max_armed_ms: MAX_ARMED_MS,
                        armed: true,
                    },
                );
            }
        }
        self.persist();
        Ok(())
    }

    /// Atomically reserve `amount_atomic` against a grant (step 1 of reserve-then-commit).
    /// Reaps a stale reservation first, then asserts — in order, with distinct errors —
    /// that the grant exists, is armed, belongs to the resident identity, hasn't expired,
    /// is under its fill cap, is within the per-tx cap, and fits the remaining budget
    /// (spent + reserved + amount ≤ budget). On success bumps reserved + fills and stamps
    /// the reservation time. Concurrent calls serialize on the ledger mutex, so the second
    /// caller sees the first's reservation and is rejected — no over-spend.
    pub fn reserve(
        &mut self,
        id: &str,
        amount_atomic: u64,
        active_identity: Option<&str>,
        now_ms: i64,
    ) -> Result<(), String> {
        // Reject a zero-amount reserve: it moves no funds but consumes a `fills`
        // slot, so a compromised renderer could spam zero relays to burn the fill
        // cap and disable the grant (a DoS, not a fund leak). Mirrors the per-tx > 0
        // guard at arm time.
        if amount_atomic == 0 {
            return Err("amount must be greater than zero".to_string());
        }
        self.clear_stale_reservation(id, now_ms);

        // Validate against an immutable snapshot, decide, then mutate — keeps the
        // persist() calls off the &mut borrow of the grant.
        enum Outcome {
            Expired,
            Ok,
        }
        let outcome = {
            let g = self
                .grants
                .get(id)
                .ok_or_else(|| "unknown grant".to_string())?;
            if !g.armed {
                return Err("grant is not armed".to_string());
            }
            // CRITICAL: the resident spend key must belong to THIS grant's wallet,
            // else a grant could spend from a different identity's funds.
            if active_identity != Some(g.identity_id.as_str()) {
                return Err("resident spend key does not belong to this grant's wallet".to_string());
            }
            let deadline = g
                .expires_at_ms
                .min(g.armed_at_ms.saturating_add(g.max_armed_ms));
            if now_ms >= deadline {
                Outcome::Expired
            } else if g.fills >= g.max_fills {
                return Err("grant fill limit reached".to_string());
            } else if amount_atomic > g.per_tx_atomic {
                return Err("amount exceeds the per-transaction cap".to_string());
            } else if g
                .spent_atomic
                .saturating_add(g.reserved_atomic)
                .saturating_add(amount_atomic)
                > g.budget_atomic
            {
                return Err("amount exceeds the remaining budget".to_string());
            } else {
                Outcome::Ok
            }
        };

        match outcome {
            Outcome::Expired => {
                if let Some(g) = self.grants.get_mut(id) {
                    g.armed = false;
                }
                self.persist();
                Err("grant expired".to_string())
            }
            Outcome::Ok => {
                if let Some(g) = self.grants.get_mut(id) {
                    g.reserved_atomic = g.reserved_atomic.saturating_add(amount_atomic);
                    g.fills = g.fills.saturating_add(1);
                    g.reserved_at_ms = now_ms;
                }
                self.persist();
                Ok(())
            }
        }
    }

    /// Undo a reservation whose relay never broadcast (mirror of `reserve`): return
    /// its budget and fill to the grant.
    pub fn rollback(&mut self, id: &str, amount_atomic: u64) {
        if let Some(g) = self.grants.get_mut(id) {
            g.reserved_atomic = g.reserved_atomic.saturating_sub(amount_atomic);
            g.fills = g.fills.saturating_sub(1);
        }
        self.persist();
    }

    /// Commit a broadcast relay (step 2): move `amount_atomic` from reserved to spent,
    /// then auto-disarm if the grant is exhausted (budget can't fit another per-tx, the
    /// fill cap is reached, or it has expired).
    pub fn commit(&mut self, id: &str, amount_atomic: u64, now_ms: i64) {
        if let Some(g) = self.grants.get_mut(id) {
            g.spent_atomic = g.spent_atomic.saturating_add(amount_atomic);
            g.reserved_atomic = g.reserved_atomic.saturating_sub(amount_atomic);
            let deadline = g
                .expires_at_ms
                .min(g.armed_at_ms.saturating_add(g.max_armed_ms));
            if g.spent_atomic.saturating_add(g.per_tx_atomic) > g.budget_atomic
                || g.fills >= g.max_fills
                || now_ms >= deadline
            {
                g.armed = false;
            }
        }
        self.persist();
    }

    /// Disarm a single grant, keeping the entry + its spent history for status/audit.
    pub fn revoke(&mut self, id: &str) {
        if let Some(g) = self.grants.get_mut(id) {
            g.armed = false;
        }
        self.persist();
    }

    /// Disarm every grant (panic-wipe path, §8).
    pub fn revoke_all(&mut self) {
        for g in self.grants.values_mut() {
            g.armed = false;
        }
        self.persist();
    }

    /// Read a grant's terms after healing stale reservations + expiry (so the UI/daemon
    /// reconcile against a fresh source of truth). Returns None for an unknown id.
    pub fn status(&mut self, id: &str, now_ms: i64) -> Option<&TransferGrant> {
        self.clear_stale_reservation(id, now_ms);
        let mut changed = false;
        if let Some(g) = self.grants.get_mut(id) {
            let deadline = g
                .expires_at_ms
                .min(g.armed_at_ms.saturating_add(g.max_armed_ms));
            if g.armed && now_ms >= deadline {
                g.armed = false;
                changed = true;
            }
        }
        if changed {
            self.persist();
        }
        self.grants.get(id)
    }

    /// The source account of a grant (for building its relay tx). None for unknown id.
    pub fn account_index(&self, id: &str) -> Option<u32> {
        self.grants.get(id).map(|g| g.account_index)
    }

    /// Whether any grant is currently armed — the retention signal `lock()` reads to
    /// decide whether to keep the spend key resident.
    pub fn any_armed(&self) -> bool {
        self.grants.values().any(|g| g.armed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn temp_ledger() -> GrantLedger {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("grant_ledger_test_{}_{}.json", nanos, n));
        GrantLedger::load(path)
    }

    const XMR: u64 = 1_000_000_000_000;

    /// Arm a standard grant: budget, per_tx, max_fills, expiring far in the future.
    fn arm_std(l: &mut GrantLedger, id: &str, budget: u64, per_tx: u64, max_fills: u32, now: i64) {
        l.arm(
            id.into(),
            "alice".into(),
            0,
            budget,
            per_tx,
            max_fills,
            now + 1_000_000,
            now,
        )
        .unwrap();
    }

    #[test]
    fn parse_xmr_edge_cases() {
        assert_eq!(parse_xmr("1").unwrap(), XMR);
        assert_eq!(parse_xmr("1.5").unwrap(), XMR + 500_000_000_000);
        assert_eq!(parse_xmr("0.000000000001").unwrap(), 1);
        assert_eq!(parse_xmr("0").unwrap(), 0);
        assert!(parse_xmr("0.0000000000001").is_err()); // 13 decimals
        assert!(parse_xmr("abc").is_err());
        assert!(parse_xmr("").is_err());
        assert!(parse_xmr("-1").is_err());
        assert!(parse_xmr("1.2.3").is_err());
    }

    #[test]
    fn format_xmr_round_trip() {
        assert_eq!(format_xmr(XMR), "1");
        assert_eq!(format_xmr(XMR + 500_000_000_000), "1.5");
        assert_eq!(format_xmr(1), "0.000000000001");
        assert_eq!(format_xmr(0), "0");
    }

    #[test]
    fn per_tx_cap_rejects_oversized() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 100, 0);
        assert!(l.reserve("g", 2 * XMR, Some("alice"), 1).is_err());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
    }

    #[test]
    fn zero_amount_reserve_rejected() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 100, 0);
        // A zero reserve must fail WITHOUT consuming a fill slot (fill-burn DoS guard).
        assert!(l.reserve("g", 0, Some("alice"), 1).is_err());
        let s = l.status("g", 1).unwrap();
        assert_eq!(s.fills, 0);
    }

    #[test]
    fn budget_cap_counts_reserved_plus_spent() {
        let mut l = temp_ledger();
        // budget 2 XMR, per_tx 1 XMR — two reserves fit, a third exceeds budget.
        arm_std(&mut l, "g", 2 * XMR, 1 * XMR, 100, 0);
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_err());
    }

    #[test]
    fn fills_cap_enforced() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 2, 0);
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_err());
    }

    #[test]
    fn expiry_rejects_and_auto_disarms() {
        let mut l = temp_ledger();
        l.arm(
            "g".into(),
            "alice".into(),
            0,
            10 * XMR,
            1 * XMR,
            100,
            1_000,
            0,
        )
        .unwrap();
        // At/after expiry the reserve fails AND the grant is disarmed.
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 2_000).is_err());
        assert!(!l.any_armed());
    }

    #[test]
    fn identity_mismatch_rejected() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 100, 0);
        assert!(l.reserve("g", 1 * XMR, Some("mallory"), 1).is_err());
        assert!(l.reserve("g", 1 * XMR, None, 1).is_err());
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
    }

    #[test]
    fn rollback_restores_capacity() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 1 * XMR, 1 * XMR, 1, 0);
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
        // Budget + fills exhausted → next reserve blocked.
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_err());
        l.rollback("g", 1 * XMR);
        // Capacity + fill returned → reserve succeeds again.
        assert!(l.reserve("g", 1 * XMR, Some("alice"), 1).is_ok());
    }

    #[test]
    fn commit_auto_disarms_at_budget_exhaustion() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 1 * XMR, 1 * XMR, 100, 0);
        l.reserve("g", 1 * XMR, Some("alice"), 1).unwrap();
        l.commit("g", 1 * XMR, 2);
        // spent + per_tx (1+1) > budget (1) → disarmed.
        assert!(!l.any_armed());
    }

    #[test]
    fn commit_auto_disarms_at_fills_exhaustion() {
        let mut l = temp_ledger();
        // Large budget but only 1 fill allowed.
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 1, 0);
        l.reserve("g", 1 * XMR, Some("alice"), 1).unwrap();
        l.commit("g", 1 * XMR, 2);
        assert!(!l.any_armed());
    }

    #[test]
    fn stale_reservation_reaped_but_fresh_kept() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 2 * XMR, 1 * XMR, 100, 0);
        // Reserve at t=1000; budget now blocks a second concurrent 1 XMR + 1 XMR.
        l.reserve("g", 1 * XMR, Some("alice"), 1_000).unwrap();
        // A fresh reservation (well within the timeout) is NOT reaped: a reserve that
        // would push spent+reserved over budget is still blocked.
        assert!(l
            .reserve("g", 2 * XMR, Some("alice"), 1_000 + 1_000)
            .is_err());
        // Past the timeout the orphaned reservation is reaped, freeing the budget.
        let t = 1_000 + RESERVATION_TIMEOUT_MS + 1;
        assert!(l.reserve("g", 1 * XMR, Some("alice"), t).is_ok());
    }

    #[test]
    fn rearm_preserves_spent_and_fills() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 5, 0);
        l.reserve("g", 1 * XMR, Some("alice"), 1).unwrap();
        l.commit("g", 1 * XMR, 2);
        // Re-arm with a larger budget — spent/fills must survive.
        l.arm(
            "g".into(),
            "alice".into(),
            0,
            20 * XMR,
            1 * XMR,
            5,
            1_000_000,
            3,
        )
        .unwrap();
        let s = l.status("g", 4).unwrap();
        assert_eq!(s.spent_atomic, 1 * XMR);
        assert_eq!(s.fills, 1);
        assert!(s.armed);
        assert_eq!(s.budget_atomic, 20 * XMR);
    }

    #[test]
    fn total_armed_cap_across_two_grants() {
        let mut l = temp_ledger();
        // 40 XMR armed, then a 20 XMR arm would push the total to 60 > 50 cap.
        l.arm(
            "a".into(),
            "alice".into(),
            0,
            40 * XMR,
            1 * XMR,
            100,
            1_000_000,
            0,
        )
        .unwrap();
        assert!(l
            .arm(
                "b".into(),
                "alice".into(),
                0,
                20 * XMR,
                1 * XMR,
                100,
                1_000_000,
                0
            )
            .is_err());
        // 10 XMR fits (40 + 10 = 50).
        assert!(l
            .arm(
                "b".into(),
                "alice".into(),
                0,
                10 * XMR,
                1 * XMR,
                100,
                1_000_000,
                0
            )
            .is_ok());
    }

    #[test]
    fn revoke_keeps_history() {
        let mut l = temp_ledger();
        arm_std(&mut l, "g", 10 * XMR, 1 * XMR, 100, 0);
        l.reserve("g", 1 * XMR, Some("alice"), 1).unwrap();
        l.commit("g", 1 * XMR, 2);
        l.revoke("g");
        assert!(!l.any_armed());
        let s = l.status("g", 3).unwrap();
        assert_eq!(s.spent_atomic, 1 * XMR);
        assert!(!s.armed);
    }

    #[test]
    fn expiry_clamped_to_max_armed_ceiling() {
        let mut l = temp_ledger();
        // Ask for a 100-day expiry; it must clamp to now + MAX_ARMED_MS (7 days).
        let now = 0;
        let far = 100 * 24 * 3600 * 1000;
        l.arm(
            "g".into(),
            "alice".into(),
            0,
            10 * XMR,
            1 * XMR,
            100,
            far,
            now,
        )
        .unwrap();
        let s = l.status("g", 1).unwrap();
        assert_eq!(s.expires_at_ms, now + MAX_ARMED_MS);
    }

    // Design-mandated concurrency test: 10 tasks race to reserve against a grant
    // whose budget fits exactly 3 per-tx reservations. Exactly 3 must succeed and
    // reserved must never exceed budget, proving the mutex + reserve step is race-safe.
    #[tokio::test]
    async fn concurrent_reserves_never_overspend() {
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let per_tx = 1 * XMR;
        let budget = 3 * per_tx;
        let mut base = temp_ledger();
        base.arm(
            "g".into(),
            "alice".into(),
            0,
            budget,
            per_tx,
            100,
            1_000_000,
            0,
        )
        .unwrap();
        let ledger = Arc::new(Mutex::new(base));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let l = ledger.clone();
            handles.push(tokio::spawn(async move {
                let mut guard = l.lock().await;
                guard.reserve("g", per_tx, Some("alice"), 1).is_ok()
            }));
        }
        let mut ok = 0;
        for h in handles {
            if h.await.unwrap() {
                ok += 1;
            }
        }
        assert_eq!(ok, 3, "exactly 3 reserves should fit the budget");
        let guard = ledger.lock().await;
        let s = guard.grants.get("g").unwrap();
        assert!(
            s.reserved_atomic <= budget,
            "reserved must never exceed budget"
        );
        assert_eq!(s.reserved_atomic, budget);
    }
}
