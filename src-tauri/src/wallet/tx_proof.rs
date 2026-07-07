//! Monero `OutProofV2` transaction-proof GENERATION (increment 1).
//!
//! ⚠️ UNAUDITED CRYPTO — must be validated against official Monero before being
//! relied on. A generated proof is byte-compatible iff `monero-wallet-cli
//! check_tx_proof <txid> <address> <message> <sig>` returns "Good" with the
//! correct received amount (verification needs no private keys). Until that
//! passes, treat the output as untrusted.
//!
//! Algorithm (Monero crypto.cpp generate_tx_proof, v2 / "TXPROOF_V2"), standard
//! (non-subaddress) recipient, single main tx pubkey:
//!   sep        = keccak256("TXPROOF_V2")
//!   prefix     = keccak256(txid ‖ message)
//!   R = r·G,  D = r·A,  k random,  X = k·G,  Y = k·A     (A = recipient view key)
//!   c = hash_to_scalar( prefix ‖ D ‖ X ‖ Y ‖ sep ‖ R ‖ A ‖ B )   (B = 32 zeros)
//!   sig.r = k − c·r
//!   proof  = "OutProofV2" + base58( D ‖ c ‖ sig.r )
//! where hash_to_scalar(x) = reduce_mod_l(keccak256(x)).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand_core::OsRng;

use monero_address::MoneroAddress;
use monero_oxide::ed25519::Commitment;
use monero_oxide::ringct::EncryptedAmount;
use monero_oxide::transaction::Transaction;
use monero_wallet::extra::Extra;

use super::base58_monero;

const PROOF_PREFIX: &str = "OutProofV2";

fn keccak256(data: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

/// hash_to_scalar = reduce(keccak256(data)) mod l — Monero's `hash_to_scalar`.
fn hash_to_scalar(data: &[u8]) -> Scalar {
    Scalar::from_bytes_mod_order(keccak256(data))
}

fn challenge(
    prefix: &[u8; 32],
    d: &EdwardsPoint,
    x: &EdwardsPoint,
    y: &EdwardsPoint,
    sep: &[u8; 32],
    big_r: &EdwardsPoint,
    a: &EdwardsPoint,
    b: &[u8; 32],
) -> Scalar {
    // s_comm_2 struct layout: msg ‖ D ‖ X ‖ Y ‖ sep ‖ R ‖ A ‖ B (each 32 bytes).
    let mut buf = Vec::with_capacity(32 * 8);
    buf.extend_from_slice(prefix);
    buf.extend_from_slice(&d.compress().to_bytes());
    buf.extend_from_slice(&x.compress().to_bytes());
    buf.extend_from_slice(&y.compress().to_bytes());
    buf.extend_from_slice(sep);
    buf.extend_from_slice(&big_r.compress().to_bytes());
    buf.extend_from_slice(&a.compress().to_bytes());
    buf.extend_from_slice(b);
    hash_to_scalar(&buf)
}

/// The proof's Schnorr base point, the `B` bytes hashed into the challenge, and the
/// recipient view key `A` — keyed on whether the recipient is a subaddress. This is the
/// one place standard vs subaddress proofs diverge (Monero `crypto.cpp`):
///   standard   → base = G,          B = 32 zeros,          A = view key
///   subaddress → base = spend key D, B = compress(D),       A = subaddress view key C
/// so R = r·base (r·G or r·D) and the challenge binds B. Everything else (D = r·A, the
/// amount decode) is identical, because a subaddress `MoneroAddress` already returns C
/// from `.view()` and D from `.spend()`.
fn proof_inputs(address: &MoneroAddress) -> (EdwardsPoint, [u8; 32], EdwardsPoint) {
    let a: EdwardsPoint = address.view().into();
    if address.is_subaddress() {
        let b: EdwardsPoint = address.spend().into();
        (b, b.compress().to_bytes(), a)
    } else {
        (ED25519_BASEPOINT_POINT, [0u8; 32], a)
    }
}

/// Generate an `OutProofV2` string proving the tx with `txid` paid `address`, using the
/// tx secret key `r`. Handles both standard and subaddress recipients.
pub fn generate_out_proof_v2(
    txid: [u8; 32],
    message: &str,
    r: Scalar,
    address: &MoneroAddress,
) -> Result<String, String> {
    let (base, b_hash, a) = proof_inputs(address);

    let big_r = base * r; // R = r·G (standard) or r·D (subaddress)
    let d = a * r; // D = r·A
    let k: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
    let x = base * k; // X = k·base
    let y = a * k; // Y = k·A

    let sep = keccak256(b"TXPROOF_V2");
    let prefix = {
        let mut pm = Vec::with_capacity(32 + message.len());
        pm.extend_from_slice(&txid);
        pm.extend_from_slice(message.as_bytes());
        keccak256(&pm)
    };

    let c = challenge(&prefix, &d, &x, &y, &sep, &big_r, &a, &b_hash);
    let sig_r = k - c * r;

    let mut chunk = Vec::with_capacity(96);
    chunk.extend_from_slice(&d.compress().to_bytes());
    chunk.extend_from_slice(c.as_bytes());
    chunk.extend_from_slice(sig_r.as_bytes());

    Ok(format!("{}{}", PROOF_PREFIX, base58_monero::encode(&chunk)))
}

/// Decode an `OutProofV2` string into its `(D, c, sig.r)` components. `D` is the
/// shared secret `r·A`; `c` and `sig.r` are the Schnorr challenge/response.
fn decode_proof(proof: &str) -> Result<(EdwardsPoint, Scalar, Scalar), String> {
    let body = proof
        .strip_prefix(PROOF_PREFIX)
        .ok_or("not an OutProofV2 string")?;
    let bytes = base58_monero::decode(body)?;
    if bytes.len() != 96 {
        return Err(format!("expected 96 proof bytes, got {}", bytes.len()));
    }
    let d = decompress(&bytes[0..32])?;
    let c = scalar_from(&bytes[32..64])?;
    let sig_r = scalar_from(&bytes[64..96])?;
    Ok((d, c, sig_r))
}

/// Recompute X = c·R + sig_r·base and Y = c·D + sig_r·A, re-hash, and confirm it equals
/// the embedded challenge `c`. `base`/`b_hash` are G/zeros for a standard recipient and
/// the subaddress spend key / its bytes for a subaddress (see `proof_inputs`). Operates
/// over already-decoded components so callers that also need `D` don't decode twice.
#[allow(clippy::too_many_arguments)]
fn verify_consistency_parts(
    txid: [u8; 32],
    message: &str,
    d: &EdwardsPoint,
    c: &Scalar,
    sig_r: &Scalar,
    big_r: &EdwardsPoint,
    a: &EdwardsPoint,
    base: &EdwardsPoint,
    b_hash: &[u8; 32],
) -> bool {
    let x = big_r * c + base * sig_r; // c·R + sig_r·base
    let y = d * c + a * sig_r; // c·D + sig_r·A

    let sep = keccak256(b"TXPROOF_V2");
    let prefix = {
        let mut pm = Vec::with_capacity(32 + message.len());
        pm.extend_from_slice(&txid);
        pm.extend_from_slice(message.as_bytes());
        keccak256(&pm)
    };
    let c2 = challenge(&prefix, d, &x, &y, &sep, big_r, a, b_hash);
    &c2 == c
}

/// Re-verify the Schnorr identity inside a STANDARD-recipient proof we hold the public
/// inputs for. Proves the math is internally consistent. Does NOT decode the received
/// amount. (Subaddress verification goes through `check_out_proof_v2`.)
#[allow(dead_code)]
pub fn verify_out_proof_v2_consistency(
    txid: [u8; 32],
    message: &str,
    proof: &str,
    big_r: &EdwardsPoint,
    a: &EdwardsPoint,
) -> Result<bool, String> {
    let (d, c, sig_r) = decode_proof(proof)?;
    Ok(verify_consistency_parts(
        txid, message, &d, &c, &sig_r, big_r, a, &ED25519_BASEPOINT_POINT, &[0u8; 32],
    ))
}

/// Extract the primary transaction public key `R` from a tx's raw `extra` bytes.
///
/// This is the **on-chain** R the verifier MUST bind the proof to. `check_tx_proof`
/// must never accept an R supplied by the party presenting the proof — otherwise the
/// consistency check proves nothing about the real transaction. Handles the standard
/// single-tx-pubkey case; per-output additional keys (subaddress sends) are ignored
/// here and handled when subaddress proofs land.
#[allow(dead_code)]
pub fn tx_pubkey_from_extra(extra: &[u8]) -> Result<EdwardsPoint, String> {
    let mut cursor: &[u8] = extra;
    let parsed = Extra::read(&mut cursor).map_err(|_| "unparseable tx extra".to_string())?;
    let (keys, _additional) = parsed.keys().ok_or("no tx public key in extra")?;
    let first: EdwardsPoint = keys
        .into_iter()
        .next()
        .ok_or("empty tx public key list")?
        .into();
    // `Extra::keys` substitutes the identity point for an unparseable key; reject it so
    // a malformed pubkey can never masquerade as a valid R.
    if first == EdwardsPoint::identity() {
        return Err("tx public key is the identity point (invalid)".into());
    }
    Ok(first)
}

/// Outcome of verifying a payment proof against the on-chain transaction.
pub struct ProofCheck {
    /// The Schnorr proof is internally consistent AND bound to the transaction's
    /// on-chain public key `R` (never a prover-supplied one).
    pub good: bool,
    /// Total atomic (piconero) amount the proof's recipient received in this tx.
    /// Zero when `good` is false — and legitimately zero when the proof verifies but
    /// no output actually pays the claimed address (a valid signature over an
    /// unrelated tx). This mirrors `monero-wallet-cli check_tx_proof`, which reports
    /// "Good" with "received 0.0" in that case.
    pub received: u64,
    /// The transaction's amounts were unavailable (prunable RingCT proofs stripped), so
    /// `received` could not be decoded even though the proof verified. Lets the caller
    /// distinguish "0 because no output pays this address" from "0 because unknowable".
    pub amount_unavailable: bool,
}

/// Monero-style unsigned VarInt (7 bits/byte, little-endian, high-bit = continue).
fn write_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            break;
        }
    }
}

/// The per-output shared scalar and view tag derived from the proof's shared secret
/// `d` (= r·A = a·R) for output index `o`. Mirrors monero-wallet's
/// `SharedKeyDerivations::output_derivations` for the standard (non-guaranteed) case:
///   8D  = d·cofactor
///   der = compress(8D) ‖ varint(o)
///   view_tag   = keccak256("view_tag" ‖ der)[0]
///   shared_key = hash_to_scalar(der)
fn output_derivation(d: &EdwardsPoint, o: u64) -> (Scalar, u8) {
    let eight_d = d.mul_by_cofactor().compress().to_bytes();
    let mut der = eight_d.to_vec();
    write_varint(o, &mut der);

    let mut vt_input = Vec::with_capacity(b"view_tag".len() + der.len());
    vt_input.extend_from_slice(b"view_tag");
    vt_input.extend_from_slice(&der);
    let view_tag = keccak256(&vt_input)[0];

    let shared_key = hash_to_scalar(&der);
    (shared_key, view_tag)
}

/// Decrypt one output's amount from its shared scalar and CONFIRM it by rebuilding the
/// Pedersen commitment and comparing to the on-chain commitment. Returns `Some(amount)`
/// only when the commitment matches — a wrong shared key (i.e. the output isn't really
/// ours) yields garbage that fails this check. Mirrors `SharedKeyDerivations::decrypt`.
fn decode_amount(
    shared_key: &Scalar,
    enc: &EncryptedAmount,
    on_chain_commitment: &[u8; 32],
) -> Option<u64> {
    let shared_bytes = shared_key.to_bytes();

    let (mask, amount): (Scalar, u64) = match enc {
        // Modern (BP+ era): amount is an 8-byte one-time-pad XOR; mask is deterministic.
        EncryptedAmount::Compact { amount } => {
            // commitment_mask = Hs("commitment_mask" ‖ shared_key)
            let mut cm = b"commitment_mask".to_vec();
            cm.extend_from_slice(&shared_bytes);
            let mask = hash_to_scalar(&cm);
            // amount_pad = keccak256("amount" ‖ shared_key)[..8]
            let mut am = b"amount".to_vec();
            am.extend_from_slice(&shared_bytes);
            let h = keccak256(&am);
            let mut pad = [0u8; 8];
            pad.copy_from_slice(&h[..8]);
            let value = u64::from_le_bytes(*amount) ^ u64::from_le_bytes(pad);
            (mask, value)
        }
        // Legacy: both mask and amount are 32-byte scalars offset by hashed secrets.
        EncryptedAmount::Original { mask, amount } => {
            let mask_sec = hash_to_scalar(&shared_bytes);
            let amount_sec = hash_to_scalar(&mask_sec.to_bytes());
            let out_mask = Scalar::from_bytes_mod_order(*mask) - mask_sec;
            let amount_scalar = Scalar::from_bytes_mod_order(*amount) - amount_sec;
            let mut le = [0u8; 8];
            le.copy_from_slice(&amount_scalar.to_bytes()[..8]);
            (out_mask, u64::from_le_bytes(le))
        }
    };

    // amount·H + mask·G must equal the output's on-chain commitment, else this
    // derivation is spurious (not actually an output to the recipient).
    let rebuilt = Commitment::new(monero_oxide::ed25519::Scalar::from(mask), amount)
        .commit()
        .compress()
        .to_bytes();
    (rebuilt == *on_chain_commitment).then_some(amount)
}

/// Test one output for ownership by recipient spend key `b_compressed` using the
/// proof's shared secret `d`, returning the received amount when the output pays the
/// recipient. Ownership: `P − shared_key·G == B`. This is the unit of the tx scan and
/// contains all the amount crypto, so it (not the Transaction glue) is what the tests
/// exercise.
#[allow(clippy::too_many_arguments)]
fn scan_output(
    d: &EdwardsPoint,
    b_compressed: &[u8; 32],
    o: u64,
    out_key: &[u8; 32],
    out_view_tag: Option<u8>,
    clear_amount: Option<u64>,
    enc: Option<&EncryptedAmount>,
    commitment: Option<&[u8; 32]>,
) -> Option<u64> {
    let p = decompress(out_key).ok()?;
    let (shared_key, view_tag) = output_derivation(d, o);

    // View tag is an early-out filter; the ownership check below is the real gate.
    if let Some(vt) = out_view_tag {
        if vt != view_tag {
            return None;
        }
    }

    let candidate = p - ED25519_BASEPOINT_POINT * shared_key;
    if candidate.compress().to_bytes() != *b_compressed {
        return None;
    }

    // Coinbase/miner outputs carry a cleartext amount and no commitment.
    if let Some(clear) = clear_amount {
        return Some(clear);
    }
    decode_amount(&shared_key, enc?, commitment?)
}

/// Sum the atomic amounts of all outputs in `tx` that pay `spend_b`, using the proof's
/// shared secret `d`. Standard (single main tx pubkey) recipients only — outputs
/// derivable only from an ADDITIONAL tx pubkey are skipped, so the total is a lower
/// bound for those (rare, non-subaddress) txs, never an over-count. Returns
/// `(total, amount_unavailable)` where the flag is set when the tx's RingCT amounts
/// were stripped (pruned), making the decode impossible.
fn received_amount(d: &EdwardsPoint, spend_b: &EdwardsPoint, tx: &Transaction) -> (u64, bool) {
    let base = match tx {
        Transaction::V2 { proofs: Some(proofs), .. } => Some(&proofs.base),
        // V1 (pre-RingCT) and prunable-stripped txs carry no amounts to decode here.
        _ => None,
    };
    let b_compressed = spend_b.compress().to_bytes();

    let mut total: u64 = 0;
    // Amounts are unavailable only if a non-coinbase output has no accompanying RingCT
    // base (pruned). A coinbase output carries a cleartext amount, so it's never
    // "unavailable".
    let mut amount_unavailable = false;
    for (o, out) in tx.prefix().outputs.iter().enumerate() {
        let out_key = out.key.to_bytes();
        let enc = base.and_then(|b| b.encrypted_amounts.get(o));
        let commitment = base.and_then(|b| b.commitments.get(o)).map(|c| c.to_bytes());
        if out.amount.is_none() && (enc.is_none() || commitment.is_none()) {
            amount_unavailable = true;
        }
        if let Some(amount) = scan_output(
            d,
            &b_compressed,
            o as u64,
            &out_key,
            out.view_tag,
            out.amount,
            enc,
            commitment.as_ref(),
        ) {
            total = total.saturating_add(amount);
        }
    }
    (total, amount_unavailable)
}

/// Verify an `OutProofV2` payment proof against the on-chain transaction `tx` and
/// report the amount received by `address`. The verifier holds NO private keys: it
/// binds the proof to the tx's on-chain public key `R` (from `extra`), checks the
/// Schnorr identity, then decodes the received amount by scanning the tx's outputs
/// with the proof's shared secret. Handles standard and subaddress recipients (the
/// latter differ only in the Schnorr base point and hashed B — see `proof_inputs`).
/// Single main tx pubkey; per-output additional keys (multi-dest subaddress sends) are
/// not yet handled — see the additional-key note on `received_amount`.
///
/// ⚠️ UNAUDITED CRYPTO — must agree with `monero-wallet-cli check_tx_proof` (both the
/// Good/Bad verdict and the received amount) before being relied on.
pub fn check_out_proof_v2(
    txid: [u8; 32],
    message: &str,
    proof: &str,
    tx: &Transaction,
    address: &MoneroAddress,
) -> Result<ProofCheck, String> {
    // The on-chain R the proof MUST be bound to — a prover-supplied R proves nothing.
    let big_r = tx_pubkey_from_extra(&tx.prefix().extra)?;
    // Standard vs subaddress differ only in the Schnorr base point and hashed B.
    let (base, b_hash, a) = proof_inputs(address);

    // Decode the proof once; reuse D for both the Schnorr check and the amount decode.
    let (d, c, sig_r) = decode_proof(proof)?;

    // Reject a degenerate shared secret: the identity point or a small-order/torsion
    // point yields a broken derivation and `monero-wallet-cli` (via ge_frombytes)
    // rejects such proofs outright. This never triggers for an honest proof.
    if d == EdwardsPoint::identity() || !d.is_torsion_free() {
        return Ok(ProofCheck { good: false, received: 0, amount_unavailable: false });
    }

    if !verify_consistency_parts(txid, message, &d, &c, &sig_r, &big_r, &a, &base, &b_hash) {
        return Ok(ProofCheck { good: false, received: 0, amount_unavailable: false });
    }

    // Decode the amount paid to the recipient's spend key B using the verified D.
    let spend_b: EdwardsPoint = address.spend().into();
    let (received, amount_unavailable) = received_amount(&d, &spend_b, tx);

    Ok(ProofCheck { good: true, received, amount_unavailable })
}

/// Verify a transaction SECRET key against the on-chain tx and report the amount it paid
/// `address`. Unlike a signed proof, the caller supplies the raw tx private key `r`
/// directly (anyone holding it derives the same shared secret — there is no signature).
/// `good` is true iff `r·G` reproduces the tx's on-chain public key R, i.e. `r` really is
/// this transaction's key. The amount decode reuses the exact path validated against
/// official Monero in `check_out_proof_v2`. Handles standard and subaddress recipients.
///
/// ⚠️ UNAUDITED CRYPTO — see module header.
pub fn check_tx_key_v2(
    tx_key_hex: &str,
    tx: &Transaction,
    address: &MoneroAddress,
) -> Result<ProofCheck, String> {
    let r_bytes: [u8; 32] = hex::decode(tx_key_hex.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("tx key must be 32 bytes of hex")?;
    let r: Scalar = Option::from(curve25519_dalek::Scalar::from_canonical_bytes(r_bytes))
        .ok_or("tx key is not a canonical scalar")?;

    // r is this tx's secret key iff r·base reproduces the on-chain pubkey R, where base
    // is G for a standard recipient and the subaddress spend key for a subaddress.
    let (base, _b_hash, a) = proof_inputs(address);
    let big_r = tx_pubkey_from_extra(&tx.prefix().extra)?;
    if base * r != big_r {
        return Ok(ProofCheck { good: false, received: 0, amount_unavailable: false });
    }

    // Shared secret D = r·A — identical to a proof's D, so reuse the validated decode.
    let d = a * r;
    let spend_b: EdwardsPoint = address.spend().into();
    let (received, amount_unavailable) = received_amount(&d, &spend_b, tx);
    Ok(ProofCheck { good: true, received, amount_unavailable })
}

fn decompress(bytes: &[u8]) -> Result<EdwardsPoint, String> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "bad point length")?;
    Option::from(curve25519_dalek::edwards::CompressedEdwardsY(arr).decompress())
        .ok_or_else(|| "invalid point".to_string())
}

fn scalar_from(bytes: &[u8]) -> Result<Scalar, String> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| "bad scalar length")?;
    Option::from(Scalar::from_canonical_bytes(arr)).ok_or_else(|| "non-canonical scalar".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use monero_address::{AddressType, Network};

    #[test]
    fn generated_proof_is_self_consistent() {
        // Build a standard (Legacy) recipient address from random keys.
        let g = ED25519_BASEPOINT_POINT;
        let view_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let view_pub = monero_oxide::ed25519::Point::from(g * view_sk);
        let spend_pub = monero_oxide::ed25519::Point::from(g * spend_sk);
        let address = MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend_pub, view_pub);

        // A "tx secret key" r and a fake txid.
        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let txid = [7u8; 32];
        let message = "proof-test";

        let proof = generate_out_proof_v2(txid, message, r, &address).expect("generate");
        assert!(proof.starts_with("OutProofV2"));

        // Public inputs the verifier would derive: R = r·G, A = recipient view key.
        let big_r = g * r;
        let a: EdwardsPoint = address.view().into();
        let ok = verify_out_proof_v2_consistency(txid, message, &proof, &big_r, &a)
            .expect("verify");
        assert!(ok, "Schnorr identity did not hold for generated proof");
    }

    // A verifier that only ever returns `true` is worthless. Prove it REJECTS every
    // wrong input: a substituted R, a wrong recipient view key, a tampered message,
    // and a tampered txid. These are the forgeries check_tx_proof must defeat.
    #[test]
    fn verifier_rejects_wrong_inputs() {
        let g = ED25519_BASEPOINT_POINT;
        let view_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let view_pub = monero_oxide::ed25519::Point::from(g * view_sk);
        let spend_pub = monero_oxide::ed25519::Point::from(g * spend_sk);
        let address = MoneroAddress::new(Network::Mainnet, AddressType::Legacy, spend_pub, view_pub);

        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let txid = [9u8; 32];
        let proof = generate_out_proof_v2(txid, "m", r, &address).expect("generate");
        let big_r = g * r;
        let a: EdwardsPoint = address.view().into();

        // Baseline: the honest inputs pass.
        assert!(verify_out_proof_v2_consistency(txid, "m", &proof, &big_r, &a).unwrap());
        // Substituted tx pubkey R → reject.
        assert!(!verify_out_proof_v2_consistency(txid, "m", &proof, &(g * (r + Scalar::ONE)), &a).unwrap());
        // Wrong recipient view key A → reject.
        assert!(!verify_out_proof_v2_consistency(txid, "m", &proof, &big_r, &(g * (view_sk + Scalar::ONE))).unwrap());
        // Tampered message → reject.
        assert!(!verify_out_proof_v2_consistency(txid, "m2", &proof, &big_r, &a).unwrap());
        // Tampered txid → reject.
        assert!(!verify_out_proof_v2_consistency([8u8; 32], "m", &proof, &big_r, &a).unwrap());
    }

    // The on-chain R extractor round-trips a known tx pubkey out of a minimal `extra`,
    // and never yields a silent identity/zero point for empty input.
    #[test]
    fn extracts_tx_pubkey_from_extra() {
        let g = ED25519_BASEPOINT_POINT;
        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let big_r = g * r;
        // Minimal `extra`: tag 0x01 (tx public key) + the 32-byte compressed point.
        let mut extra = vec![0x01u8];
        extra.extend_from_slice(&big_r.compress().to_bytes());
        assert_eq!(tx_pubkey_from_extra(&extra).unwrap().compress(), big_r.compress());
        // No tx pubkey present → error, not a silent identity point.
        assert!(tx_pubkey_from_extra(&[]).is_err());
    }

    // Build a Compact encrypted amount + its matching on-chain commitment for a given
    // shared scalar and value, exactly as a real wallet's SEND path would. Lets the
    // scan tests round-trip a genuine owned output without constructing a full tx.
    fn make_compact(shared_key: &Scalar, amount: u64) -> (EncryptedAmount, [u8; 32]) {
        let shared_bytes = shared_key.to_bytes();
        // Encrypted amount: value XOR keccak256("amount" ‖ shared_key)[..8].
        let mut am = b"amount".to_vec();
        am.extend_from_slice(&shared_bytes);
        let h = keccak256(&am);
        let mut pad = [0u8; 8];
        pad.copy_from_slice(&h[..8]);
        let enc = (amount ^ u64::from_le_bytes(pad)).to_le_bytes();
        // Commitment: amount·H + Hs("commitment_mask" ‖ shared_key)·G.
        let mut cm = b"commitment_mask".to_vec();
        cm.extend_from_slice(&shared_bytes);
        let mask = hash_to_scalar(&cm);
        let commitment = Commitment::new(monero_oxide::ed25519::Scalar::from(mask), amount)
            .commit()
            .compress()
            .to_bytes();
        (EncryptedAmount::Compact { amount: enc }, commitment)
    }

    // The whole point of amount decode: a genuine payment to us round-trips to the
    // exact atomic amount, and every tampered input yields None (no phantom amount).
    #[test]
    fn scans_owned_output_and_rejects_forgeries() {
        let g = ED25519_BASEPOINT_POINT;
        // Recipient keypair (A = view, B = spend) and sender tx key r → shared D = r·A.
        let view_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let a = g * view_sk;
        let b = g * spend_sk;
        let b_compressed = b.compress().to_bytes();
        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let d = a * r;

        // Construct output 0 as the sender would: P = shared·G + B, with matching
        // view tag, encrypted amount, and commitment.
        let o = 0u64;
        let (shared_key, view_tag) = output_derivation(&d, o);
        let out_key = (g * shared_key + b).compress().to_bytes();
        let amount: u64 = 1_337_000_000_000; // 1.337 XMR
        let (enc, commitment) = make_compact(&shared_key, amount);

        // Honest path: exact amount recovered.
        assert_eq!(
            scan_output(&d, &b_compressed, o, &out_key, Some(view_tag), None, Some(&enc), Some(&commitment)),
            Some(amount)
        );

        // Wrong recipient spend key B → not ours.
        let wrong_b = (g * (spend_sk + Scalar::ONE)).compress().to_bytes();
        assert_eq!(
            scan_output(&d, &wrong_b, o, &out_key, Some(view_tag), None, Some(&enc), Some(&commitment)),
            None
        );

        // Wrong shared secret D (different sender key) → ownership fails.
        let wrong_d = a * (r + Scalar::ONE);
        assert_eq!(
            scan_output(&wrong_d, &b_compressed, o, &out_key, None, None, Some(&enc), Some(&commitment)),
            None
        );

        // Tampered commitment → decrypt no longer verifies, so no amount is claimed.
        let mut bad_commitment = commitment;
        bad_commitment[0] ^= 0x01;
        assert_eq!(
            scan_output(&d, &b_compressed, o, &out_key, Some(view_tag), None, Some(&enc), Some(&bad_commitment)),
            None
        );

        // View-tag mismatch → early-out even before ownership.
        assert_eq!(
            scan_output(&d, &b_compressed, o, &out_key, Some(view_tag ^ 0xff), None, Some(&enc), Some(&commitment)),
            None
        );

        // Right ownership but wrong output index → different derivation → rejected.
        assert_eq!(
            scan_output(&d, &b_compressed, 1, &out_key, None, None, Some(&enc), Some(&commitment)),
            None
        );
    }

    // Legacy (pre-BP+) `EncryptedAmount::Original`: 32-byte mask + 32-byte amount, each
    // offset by a hashed secret. Round-trips an owned output through the Original branch
    // of decode_amount, which the Compact tests don't exercise.
    #[test]
    fn scans_owned_output_legacy_original_amount() {
        let g = ED25519_BASEPOINT_POINT;
        let view_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let a = g * view_sk;
        let b = g * spend_sk;
        let b_compressed = b.compress().to_bytes();
        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let d = a * r;

        let (shared_key, view_tag) = output_derivation(&d, 0);
        let out_key = (g * shared_key + b).compress().to_bytes();
        let amount: u64 = 42_000_000_000;

        // Encode as a sender would for the Original format:
        //   mask_sec = Hs(shared_key);  amount_sec = Hs(mask_sec)
        //   enc_mask   = out_mask + mask_sec            (out_mask random)
        //   enc_amount = to_scalar(amount_le) + amount_sec
        let shared_bytes = shared_key.to_bytes();
        let mask_sec = hash_to_scalar(&shared_bytes);
        let amount_sec = hash_to_scalar(&mask_sec.to_bytes());
        let out_mask: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let mut amount_le = [0u8; 32];
        amount_le[..8].copy_from_slice(&amount.to_le_bytes());
        let amount_scalar = Scalar::from_bytes_mod_order(amount_le);
        let enc = EncryptedAmount::Original {
            mask: (out_mask + mask_sec).to_bytes(),
            amount: (amount_scalar + amount_sec).to_bytes(),
        };
        let commitment = Commitment::new(monero_oxide::ed25519::Scalar::from(out_mask), amount)
            .commit()
            .compress()
            .to_bytes();

        assert_eq!(
            scan_output(&d, &b_compressed, 0, &out_key, Some(view_tag), None, Some(&enc), Some(&commitment)),
            Some(amount)
        );
        // Tampered commitment still rejects on the legacy path.
        let mut bad = commitment;
        bad[0] ^= 0x01;
        assert_eq!(
            scan_output(&d, &b_compressed, 0, &out_key, Some(view_tag), None, Some(&enc), Some(&bad)),
            None
        );
    }

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn h8(s: &str) -> [u8; 8] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    // C1 byte-compat validation against OFFICIAL Monero. Real mainnet tx; the proof was
    // generated by the Monero GUI's get_tx_proof, and its check_tx_proof reports
    // "Good — 0.000669 XMR received". Our verifier MUST agree on both the verdict and the
    // exact atomic amount. This is the ground-truth gate the file header demands; the tx
    // data (extra, output keys, view tags, Compact ecdh, commitments) is embedded so the
    // test is deterministic and offline.
    //   tx  406ce05548f2258e031def08c4a629f27e3014809fc02f7baa4cad3a7955e608 (block 3589957)
    //   to  4AXSdygjeWyceDnDS4oKYs3DrVkH49iuMcJxat5CTmMpLmb8ZE8SSiGP8cPX8GwJbXUcKUyye3EyJ4GNsnRkZN8cDcRJBGX
    #[test]
    fn validates_against_real_mainnet_gui_proof() {
        use monero_address::Network;

        const PROOF: &str = "OutProofV2Ux5DfmCYR72Vnoqn9Au2QPDdJTUwhtXybALj3oWQxY5jHGx8zhYRvmiPQwgAy1uXqdDJ2fDj9zyVELJdd46Dfo5Qfo4W7bmWFEaDX6dcPyykJP7yoreCxoMp9emWL3YuFubm";
        const ADDRESS: &str = "4AXSdygjeWyceDnDS4oKYs3DrVkH49iuMcJxat5CTmMpLmb8ZE8SSiGP8cPX8GwJbXUcKUyye3EyJ4GNsnRkZN8cDcRJBGX";
        let txid = h32("406ce05548f2258e031def08c4a629f27e3014809fc02f7baa4cad3a7955e608");
        // Raw tx `extra`; tx_pubkey_from_extra pulls the on-chain R out of this.
        let extra = hex::decode(
            "0178a890317542b7c23e2b7f2c0c29655dca1325ca36a83c00406f903d262088ec0209011b63f4349d5d0869",
        )
        .unwrap();

        // The tx's two RingCT outputs (key, view_tag, Compact ecdh, commitment). One pays
        // the proof's address (0.000669), the other is change to a different key.
        let outputs: [([u8; 32], u8, [u8; 8], [u8; 32]); 2] = [
            (
                h32("8a0124b1df65684efa9e331a16f38d3e58538745d3f2dfa1fc2eaabed7cc35df"),
                0x4b,
                h8("99213aaa4725a422"),
                h32("8d39bc9ce9e21489876acf195ec546e472f34e98c6c547d1a8845662d936240e"),
            ),
            (
                h32("3bf831711560f18e38c04a7061e246f85fa840def7e9049689fd296e91e5bc08"),
                0xff,
                h8("0140b6467be59789"),
                h32("374ec7fb04deeacc08eb7ad46221cdd6152ca148592f6f580b73b5fa41e64b69"),
            ),
        ];

        // 1) Verdict: extract on-chain R, verify the Schnorr proof (empty message).
        let big_r = tx_pubkey_from_extra(&extra).expect("R from extra");
        let (d, c, sig_r) = decode_proof(PROOF).expect("decode proof");
        assert!(d != EdwardsPoint::identity() && d.is_torsion_free(), "D must be a valid group element");
        let addr = MoneroAddress::from_str(Network::Mainnet, ADDRESS).expect("address");
        let a: EdwardsPoint = addr.view().into();
        assert!(
            verify_consistency_parts(
                txid, "", &d, &c, &sig_r, &big_r, &a, &ED25519_BASEPOINT_POINT, &[0u8; 32]
            ),
            "proof failed to verify against the on-chain tx pubkey"
        );

        // 2) Amount: scan the outputs with the verified D against the recipient spend key.
        let b: EdwardsPoint = addr.spend().into();
        let b_comp = b.compress().to_bytes();
        let mut total = 0u64;
        for (o, (key, view_tag, enc, commitment)) in outputs.iter().enumerate() {
            if let Some(v) = scan_output(
                &d,
                &b_comp,
                o as u64,
                key,
                Some(*view_tag),
                None,
                Some(&EncryptedAmount::Compact { amount: *enc }),
                Some(commitment),
            ) {
                total += v;
            }
        }
        // Must match monero-wallet-cli / GUI exactly: 0.000669 XMR = 669_000_000 atomic.
        assert_eq!(total, 669_000_000, "decoded received amount disagrees with official Monero");
    }

    // Same C1 validation but for a SUBADDRESS recipient (Monero GUI proof, Good/0.32 XMR).
    // Exercises the subaddress base-point path: base = spend key D, B hashed into the
    // challenge, A = subaddress view key. tx has a single main pubkey R = r·D.
    //   tx  24f512fa6da8cd3eb1181b2a8ff719e98778c96a39d7ad4179586eedee6e008e
    //   to  84hdsasxhucdGMgCdKeorq4UqjBPjfd89bnVzhh5VVn6L9dFTkUQN4NHm8jtGAocoy8XuuPRECsEyL4YgdtMGskzT7q5W78
    #[test]
    fn validates_against_real_mainnet_subaddress_gui_proof() {
        use monero_address::Network;

        const PROOF: &str = "OutProofV2j5iG1HEk6wMZYsBESv5GXN6QEdikBJ2n9GG2krNbTUL7711uj7bQNpCAnWGG6BHN827GHwEUfWDb3ezLYuWZ9F69G2yb8cvddL4HLhW2mir1QDY7VSEHTFyTBF6cqABrY1tM";
        const ADDRESS: &str = "84hdsasxhucdGMgCdKeorq4UqjBPjfd89bnVzhh5VVn6L9dFTkUQN4NHm8jtGAocoy8XuuPRECsEyL4YgdtMGskzT7q5W78";
        let txid = h32("24f512fa6da8cd3eb1181b2a8ff719e98778c96a39d7ad4179586eedee6e008e");
        let extra = hex::decode(
            "01eba96f77a6a00f5e11b2c842183fe1b65dd9a55c65691ab40b32295f4749af2f0209012914e3bdec624848",
        )
        .unwrap();

        let outputs: [([u8; 32], u8, [u8; 8], [u8; 32]); 2] = [
            (
                h32("e9c6b0612b11d549e699691474fb3e4156344efd4a9eac1251086e3da9ac9091"),
                0xb0,
                h8("7f1359980054f3f5"),
                h32("3d20d3cddaeeb21c5a014731ba2dd06d032642f2dbaea3faa3455e8ace420b2d"),
            ),
            (
                h32("b6d01d9b2f87ab450b5c52ee25deca1b5d17eddb656fd4565b7aa8683cbbf4db"),
                0x20,
                h8("d24d8a45f8921caa"),
                h32("e07a0857568664488a95c32afaac205af9fa4349dcdc813dd621ea93aebbfd66"),
            ),
        ];

        let big_r = tx_pubkey_from_extra(&extra).expect("R from extra");
        let (d, c, sig_r) = decode_proof(PROOF).expect("decode proof");
        let addr = MoneroAddress::from_str(Network::Mainnet, ADDRESS).expect("address");
        assert!(addr.is_subaddress(), "test address must be a subaddress");
        // Subaddress base point / hashed B come from proof_inputs.
        let (base, b_hash, a) = proof_inputs(&addr);
        assert!(
            verify_consistency_parts(txid, "", &d, &c, &sig_r, &big_r, &a, &base, &b_hash),
            "subaddress proof failed to verify against the on-chain tx pubkey"
        );

        let spend_b: EdwardsPoint = addr.spend().into();
        let b_comp = spend_b.compress().to_bytes();
        let mut total = 0u64;
        for (o, (key, view_tag, enc, commitment)) in outputs.iter().enumerate() {
            if let Some(v) = scan_output(
                &d,
                &b_comp,
                o as u64,
                key,
                Some(*view_tag),
                None,
                Some(&EncryptedAmount::Compact { amount: *enc }),
                Some(commitment),
            ) {
                total += v;
            }
        }
        // 0.32 XMR = 320_000_000_000 atomic, per the GUI's check_tx_proof.
        assert_eq!(total, 320_000_000_000, "decoded subaddress amount disagrees with official Monero");
    }

    // Coinbase/miner outputs carry a cleartext amount (no commitment) — still gated by
    // the ownership check.
    #[test]
    fn scans_owned_miner_output_cleartext_amount() {
        let g = ED25519_BASEPOINT_POINT;
        let view_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_sk: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let a = g * view_sk;
        let b = g * spend_sk;
        let b_compressed = b.compress().to_bytes();
        let r: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let d = a * r;

        let (shared_key, view_tag) = output_derivation(&d, 0);
        let out_key = (g * shared_key + b).compress().to_bytes();
        let reward: u64 = 600_000_000_000;
        assert_eq!(
            scan_output(&d, &b_compressed, 0, &out_key, Some(view_tag), Some(reward), None, None),
            Some(reward)
        );
        // Not our key → no reward attributed.
        let wrong_b = (g * (spend_sk + Scalar::ONE)).compress().to_bytes();
        assert_eq!(
            scan_output(&d, &wrong_b, 0, &out_key, Some(view_tag), Some(reward), None, None),
            None
        );
    }
}
