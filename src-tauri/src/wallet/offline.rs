//! Offline (sign-only) spending: envelope encode/decode + verification helpers.
//!
//! Two-device flow — the hot (online) device prepares and broadcasts, the cold
//! (offline) device signs, and the spend key never leaves the cold device:
//!   1. hot: prepare_transfer stages the spend → `unsigned` envelope
//!   2. cold: sign_offline_transfer verifies ownership (fail-closed) → signs → `signed` envelope
//!   3. hot: import_signed_transfer verifies the signed tx against the staged record
//!      (ring-offset multiset bijection) → native confirm → broadcast → commit
//!
//! Envelope shape (the shell half of docs/offline-signing-plan.md §5.1):
//!   { "m": "RLYX1", "v": 2, "k": "unsigned"|"signed"|"watchonly",
//!     "tx": "<hex payload>", "n": 0, "c": "crc32", "ts": ms,
//!     "meta": { to, amount, fee, account, txKey } }   // meta is display-only
//! The `tx` payload of every kind is hex-encoded (QR alphanumeric mode friendly).

use serde::{Deserialize, Serialize};

use monero_oxide::ed25519::CompressedPoint;
use monero_oxide::transaction::{Input, Transaction};
use monero_address::Network;
use monero_wallet::send::{ChangeEnum, InternalPayment, SignableTransaction};

pub const ENVELOPE_MAGIC: &str = "RLYX1";
pub const ENVELOPE_VERSION: u32 = 2;

pub const KIND_UNSIGNED: &str = "unsigned";
pub const KIND_SIGNED: &str = "signed";
pub const KIND_WATCHONLY: &str = "watchonly";

/// Envelope meta is display-only on the cold device: the cold shell re-parses the
/// SignableTransaction for the authoritative destination/change/fee display.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EnvelopeMeta {
    #[serde(default)]
    pub to: Vec<String>,
    /// XMR string, display-only.
    #[serde(default)]
    pub amount: String,
    /// XMR string, display-only.
    #[serde(default)]
    pub fee: String,
    #[serde(default)]
    pub account: u32,
    /// Join key (keccak of the unsigned signable bytes, see state::tx_meta_key).
    /// Echoed back in the `signed` envelope so the hot device can relink the
    /// signed tx to the staged spend it was prepared against.
    #[serde(default)]
    pub tx_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Envelope {
    pub m: String,
    pub v: u32,
    pub k: String,
    pub tx: String,
    /// Expected frames for a fountain-coded QR stream (0 = single QR / file / clipboard).
    pub n: u32,
    /// CRC32 (lowercase hex) over the DECODED payload bytes.
    pub c: String,
    /// Created (ms). Informational freshness, NOT an expiry — Monero txs don't expire.
    pub ts: u64,
    #[serde(default)]
    pub meta: EnvelopeMeta,
}

/// Watch-only payload (kind `watchonly`): view-key scalar + PUBLIC spend point.
/// The field is `spendPublicKeyHex` — never `spendKeyHex` (one careless rename
/// away from exfiltrating the private key).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WatchOnlyPayload {
    pub view_key_hex: String,
    pub spend_public_key_hex: String,
    pub address: String,
}

/// The cold side's parsed view of a prepared transaction (destinations, change,
/// fee) — built ONLY from the signable, never from envelope `meta`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OfflineSummary {
    /// Explicit destinations (address, atomic units).
    pub destinations: Vec<(String, u64)>,
    /// Owned change output (address, atomic units) when present.
    pub change: Option<(String, u64)>,
    /// Fee in atomic units.
    pub fee: u64,
    pub account: u32,
    pub input_count: usize,
}

/// Lightweight shape of the prepared tx retained on the HOT side from the
/// prepare step, keyed by the same `tx_meta_key` as the staged spend. The
/// signed envelope is verified against THIS (input-count/output-shape/change
/// flag), not against any renderer-supplied fields, so a swapped or tampered
/// envelope can never masquerade as the staged transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StagedTransferMeta {
    pub account: u32,
    pub payment_count: usize,
    pub input_count: usize,
    pub has_change: bool,
    /// Hex of the serialized SignableTransaction the hot side prepared — the
    /// authoritative material for the ring-multiset verification of the signed
    /// envelope (never the renderer-supplied envelope's own unsigned copy).
    pub unsigned_tx_hex: String,
    /// Atomic units; display-only, used for the hot-side confirmation dialog.
    pub amount: String,
    pub fee: String,
}

/// Build the `watchonly` envelope (JSON payload hex-encoded into `tx`). The
/// payload is the view key + PUBLIC spend point — deliberately never the spend
/// key, so the envelope is safe to transport over any channel.
pub fn encode_watch_only_payload(p: &WatchOnlyPayload) -> Result<String, String> {
    let json = serde_json::to_string(p).map_err(|e| format!("Watch-only payload: {}", e))?;
    encode_envelope(KIND_WATCHONLY, hex::encode(json.as_bytes()), EnvelopeMeta::default())
}

/// Parse + validate a `watchonly` envelope back into its payload.
pub fn decode_watch_only_payload(env: &Envelope) -> Result<WatchOnlyPayload, String> {
    if env.k != KIND_WATCHONLY {
        return Err(format!("Not a watch-only envelope (kind {})", env.k));
    }
    let payload = envelope_payload(env)?;
    serde_json::from_slice(&payload).map_err(|e| format!("Invalid watch-only payload: {}", e))
}

/// CRC32 (IEEE 802.3). Payloads are a few KB; the table-less bitwise form is
/// plenty fast and dependency-free.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn crc32_hex(data: &[u8]) -> String {
    format!("{:08x}", crc32(data))
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    hex::decode(s).map_err(|e| format!("Invalid hex payload: {}", e))
}

/// Build an envelope around a hex payload. `ts` = now (ms); `n` = 0 (single unit).
pub fn encode_envelope(
    kind: &str,
    payload_hex: String,
    meta: EnvelopeMeta,
) -> Result<String, String> {
    let payload = decode_hex(&payload_hex)?;
    let env = Envelope {
        m: ENVELOPE_MAGIC.to_string(),
        v: ENVELOPE_VERSION,
        k: kind.to_string(),
        tx: payload_hex,
        n: 0,
        c: crc32_hex(&payload),
        ts: chrono::Utc::now().timestamp_millis().max(0) as u64,
        meta,
    };
    serde_json::to_string(&env).map_err(|e| format!("Envelope encode failed: {}", e))
}

/// Parse + verify an envelope: magic, version, kind, and the payload CRC.
pub fn decode_envelope(json: &str) -> Result<Envelope, String> {
    let env: Envelope =
        serde_json::from_str(json).map_err(|e| format!("Invalid envelope JSON: {}", e))?;
    if env.m != ENVELOPE_MAGIC {
        return Err(format!("Not a Ripley envelope (magic {} != {})", env.m, ENVELOPE_MAGIC));
    }
    if env.v != ENVELOPE_VERSION {
        return Err(format!(
            "Unsupported envelope version {} (expected {})",
            env.v, ENVELOPE_VERSION
        ));
    }
    let payload = decode_hex(&env.tx)?;
    let expect = crc32_hex(&payload);
    if !env.c.eq_ignore_ascii_case(&expect) {
        return Err(format!(
            "Envelope checksum mismatch (got {}, expected {}) — payload corrupted",
            env.c, expect
        ));
    }
    Ok(env)
}

/// The decoded payload bytes of a verified envelope.
pub fn envelope_payload(env: &Envelope) -> Result<Vec<u8>, String> {
    decode_hex(&env.tx)
}

/// Ring key offsets of a prepared transaction's inputs, each ring sorted, the
/// outer list sorted — the canonical form for multiset comparison. Offsets are
/// Canonical form of a ring set for multiset comparison: each ring sorted
/// internally (wire key_offsets are delta-encoded relative orderings), then the
/// rings sorted as a whole — so ordering differences introduced anywhere
/// (e.g. the signer re-sorting inputs by key image) compare equal.
fn canonical_rings(rings: Vec<Vec<u64>>) -> Vec<Vec<u64>> {
    let mut rings = rings;
    for r in &mut rings {
        r.sort_unstable();
    }
    rings.sort();
    rings
}

/// Ring key offsets of a prepared (unsigned) transaction's real inputs. The
/// decoys' offsets are the authoritative ring membership — stored internally as
/// relative/delta-encoded (byte-identical to the wire `key_offsets`), so this is
/// EXACTLY the ring membership of the signed tx's inputs.
pub fn signable_ring_offsets(s: &SignableTransaction) -> Vec<Vec<u64>> {
    canonical_rings(
        s.real_inputs()
            .iter()
            .map(|i| i.decoys().offsets().to_vec())
            .collect(),
    )
}

/// Ring key offsets of a signed transaction's inputs, in the same canonical form.
pub fn signed_ring_offsets(tx: &Transaction) -> Vec<Vec<u64>> {
    canonical_rings(
        tx.prefix()
            .inputs
            .iter()
            .map(|i| match i {
                Input::ToKey { key_offsets, .. } => key_offsets.clone(),
                // Miner inputs never appear in a wallet-signed tx; an empty ring can
                // never equal a real ring, so a forged Gen input is refused.
                Input::Gen(_) => Vec::new(),
            })
            .collect(),
    )
}

/// Sum of the real inputs' commitments (atomic units) the prepared tx spends.
pub fn signable_input_sum(s: &SignableTransaction) -> u64 {
    s.real_inputs()
        .iter()
        .fold(0u64, |acc, i| acc.saturating_add(i.commitment().amount))
}

/// Sum of the explicit (non-change) payment amounts (atomic units).
pub fn payment_sum(s: &SignableTransaction) -> u64 {
    s.payments()
        .iter()
        .fold(0u64, |acc, p| match p {
            InternalPayment::Payment(_, amt) => acc.saturating_add(*amt),
            InternalPayment::Change(_) => acc,
        })
}

/// Whether the change output (if any) returns to the wallet with spend public
/// point `our_spend` — the [R2] change-theft guard. Fail-closed: any change spec
/// whose view pair isn't ours, or that is an unverifiable AddressOnly, is refused.
/// (Change::fingerprintable(None) — the sweep shape — produces NO change output,
/// which is fine: nothing to classify.)
pub fn verify_change_ownership(
    s: &SignableTransaction,
    our_spend: &CompressedPoint,
) -> Result<(), String> {
    for p in s.payments() {
        if let InternalPayment::Change(ChangeEnum::Standard { view_pair, .. }) = p {
            let theirs = view_pair.spend().compress();
            if theirs != *our_spend {
                return Err(
                    "REFUSED: this transaction's change output does not belong to this wallet \
                     (change would be sent to a different spend key)"
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

/// The fee this transaction will actually pay, computed cold-side from the
/// signable alone (self-contained, no network): with a change output the fee is
/// exactly `necessary_fee()`; without one (sweep shape) all residue is shunted
/// to the fee. The [R3] inflation bound is `actual ≤ 5 × necessary_fee()`.
pub fn expected_fee(s: &SignableTransaction) -> u64 {
    let has_change = s
        .payments()
        .iter()
        .any(|p| matches!(p, InternalPayment::Change(_)));
    if has_change {
        s.necessary_fee()
    } else {
        signable_input_sum(s).saturating_sub(payment_sum(s))
    }
}

/// Full cold-side verification of a prepared transaction before signing.
/// Refuses (Err) on ANY of:
///   - a change output that isn't ours (spend-key mismatch)
///   - zero explicit payments (nothing the user asked for)
///   - a payment amount of 0
///   - an empty input set
pub fn verify_before_sign(
    s: &SignableTransaction,
    our_spend: &CompressedPoint,
) -> Result<OfflineSummary, String> {
    verify_change_ownership(s, our_spend)?;

    let mut destinations = Vec::new();
    for p in s.payments() {
        match p {
            InternalPayment::Payment(addr, amt) => {
                if *amt == 0 {
                    return Err("REFUSED: transaction contains a zero-amount payment".into());
                }
                destinations.push((addr.to_string(), *amt));
            }
            InternalPayment::Change(_) => {}
        }
    }
    if destinations.is_empty() {
        return Err("REFUSED: transaction has no explicit destinations".into());
    }
    let inputs = s.real_inputs();
    if inputs.is_empty() {
        return Err("REFUSED: transaction spends no inputs".into());
    }

    let fee = expected_fee(s);
    let change = if s
        .payments()
        .iter()
        .any(|p| matches!(p, InternalPayment::Change(_)))
    {
        let change_amount = signable_input_sum(s)
            .saturating_sub(payment_sum(s))
            .saturating_sub(fee);
        let addr = change_address(s)?;
        Some((addr, change_amount))
    } else {
        None
    };

    Ok(OfflineSummary {
        destinations,
        change,
        fee,
        account: 0, // filled in by the caller from the envelope meta (display aid)
        input_count: inputs.len(),
    })
}

/// The address the change output returns to (Standard change → the wallet's
/// subaddress/primary). Refused when the change spec isn't Standard — the only
/// shape prepare_transaction produces.
fn change_address(s: &SignableTransaction) -> Result<String, String> {
    for p in s.payments() {
        if let InternalPayment::Change(ChangeEnum::Standard { view_pair, subaddress }) = p {
            return Ok(match subaddress {
                Some(sub) => view_pair.subaddress(Network::Mainnet, *sub).to_string(),
                None => view_pair.legacy_address(Network::Mainnet).to_string(),
            });
        }
    }
    Err("REFUSED: cannot determine the change destination".into())
}

/// [R3] The hot-side prefix verification: prove the SIGNED tx is exactly the
/// STAGED signable, signed. Fail-closed on ANY mismatch — there is no proceed
/// path on failure:
///   1. multiset bijection over ring key offsets (order-agnostic — signing
///      re-sorts inputs by key image, so positional comparison would false-fail)
///   2. output count == explicit payments + 1 (change) — no output added/dropped
///   3. every input is a ToKey with a populated ring (≥ 2 members)
///   4. no additional timelock
/// NOT key images: a watch-only hot wallet can't compute them, and a malicious
/// cold signer can only move its own coins (same wallet), never the destinations.
pub fn verify_signed_against_staged(
    signed: &Transaction,
    staged: &SignableTransaction,
) -> Result<(), String> {
    if signed_ring_offsets(signed) != signable_ring_offsets(staged) {
        return Err(
            "REFUSED: signed transaction's ring membership differs from the prepared \
             transaction — refusing to broadcast a different spend"
                .to_string(),
        );
    }

    let expected_outputs = staged
        .payments()
        .iter()
        .filter(|p| matches!(p, InternalPayment::Payment(_, _)))
        .count()
        + usize::from(
            staged
                .payments()
                .iter()
                .any(|p| matches!(p, InternalPayment::Change(_))),
        );
    if signed.prefix().outputs.len() != expected_outputs {
        return Err(format!(
            "REFUSED: signed transaction has {} outputs, prepared had {}",
            signed.prefix().outputs.len(),
            expected_outputs
        ));
    }

    for input in &signed.prefix().inputs {
        match input {
            Input::ToKey { key_offsets, .. } if key_offsets.len() >= 2 => {}
            _ => {
                return Err(
                    "REFUSED: signed transaction contains an invalid ring input".to_string()
                );
            }
        }
    }

    use monero_oxide::transaction::Timelock;
    if signed.prefix().additional_timelock != Timelock::None {
        return Err("REFUSED: signed transaction has an additional timelock".to_string());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32_hex(b"abc"), "352441c2");
    }

    #[test]
    fn envelope_roundtrip_and_corruption() {
        let env = encode_envelope(KIND_WATCHONLY, hex::encode(b"hello".to_vec()), EnvelopeMeta::default())
            .expect("encode");
        let decoded = decode_envelope(&env).expect("decode");
        assert_eq!(decoded.k, KIND_WATCHONLY);
        assert_eq!(envelope_payload(&decoded).unwrap(), b"hello");

        // Deterministic corruption: clobber the checksum field regardless of its value.
        let mut tampered: serde_json::Value = serde_json::from_str(&env).expect("valid json");
        tampered["c"] = serde_json::Value::String("00000000".into());
        assert!(decode_envelope(&tampered.to_string()).is_err());

        let wrong_magic = env.replace(ENVELOPE_MAGIC, "XXXXX");
        assert!(decode_envelope(&wrong_magic).is_err());
    }

    #[test]
    fn envelope_rejects_unknown_version() {
        let env = encode_envelope(KIND_WATCHONLY, hex::encode([1u8, 2, 3]), EnvelopeMeta::default())
            .expect("encode");
        let bumped = env.replace("\"v\":2", "\"v\":9");
        assert!(decode_envelope(&bumped).is_err());
    }

    #[test]
    fn watch_only_payload_roundtrips() {
        let p = WatchOnlyPayload {
            view_key_hex: "aa".repeat(32),
            spend_public_key_hex: "bb".repeat(32),
            address: "4ABC".to_string(),
        };
        let env = encode_watch_only_payload(&p).expect("encode");
        let back = decode_watch_only_payload(&decode_envelope(&env).expect("decode"))
            .expect("decode payload");
        assert_eq!(back, p);
        // A non-watchonly envelope must not decode as a watch-only payload.
        let unsigned =
            encode_envelope(KIND_UNSIGNED, hex::encode(b"x"), EnvelopeMeta::default())
                .expect("encode");
        assert!(decode_watch_only_payload(&decode_envelope(&unsigned).expect("decode")).is_err());
    }

    #[test]
    fn canonical_rings_are_order_independent() {
        // Three inputs, two of them sharing an identical ring, with the inputs
        // presented in a different order and one ring's internal order reversed —
        // the exact kinds of reordering signing introduces (inputs re-sorted by
        // key image). The canonical forms must still compare equal.
        let a = canonical_rings(vec![vec![9, 1, 5], vec![3, 7], vec![9, 1, 5]]);
        let b = canonical_rings(vec![vec![1, 9, 5], vec![9, 5, 1], vec![7, 3]]);
        assert_eq!(a, b);

        // A genuinely different ring set must differ.
        let c = canonical_rings(vec![vec![9, 1, 5], vec![3, 7], vec![9, 1, 6]]);
        assert_ne!(a, c);
    }
}
