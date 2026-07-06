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

/// Generate an `OutProofV2` string proving the tx with `txid` paid `address`,
/// using the tx secret key `r`. Standard (non-subaddress) recipients only.
pub fn generate_out_proof_v2(
    txid: [u8; 32],
    message: &str,
    r: Scalar,
    address: &MoneroAddress,
) -> Result<String, String> {
    if address.is_subaddress() {
        return Err("Subaddress tx proofs are not supported yet".into());
    }

    let a: EdwardsPoint = address.view().into();
    let g = ED25519_BASEPOINT_POINT;

    let big_r = g * r; // R = r·G
    let d = a * r; // D = r·A
    let k: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
    let x = g * k; // X = k·G
    let y = a * k; // Y = k·A

    let sep = keccak256(b"TXPROOF_V2");
    let prefix = {
        let mut pm = Vec::with_capacity(32 + message.len());
        pm.extend_from_slice(&txid);
        pm.extend_from_slice(message.as_bytes());
        keccak256(&pm)
    };
    let b_zero = [0u8; 32];

    let c = challenge(&prefix, &d, &x, &y, &sep, &big_r, &a, &b_zero);
    let sig_r = k - c * r;

    let mut chunk = Vec::with_capacity(96);
    chunk.extend_from_slice(&d.compress().to_bytes());
    chunk.extend_from_slice(c.as_bytes());
    chunk.extend_from_slice(sig_r.as_bytes());

    Ok(format!("{}{}", PROOF_PREFIX, base58_monero::encode(&chunk)))
}

/// Re-verify the Schnorr identity inside a proof we hold the public inputs for:
/// recompute X = c·R + sig_r·G and Y = c·D + sig_r·A, re-hash, and confirm it
/// equals the embedded `c`. Proves the math is internally consistent (the basis
/// of the eventual check_tx_proof). Does NOT decode the received amount.
#[allow(dead_code)]
pub fn verify_out_proof_v2_consistency(
    txid: [u8; 32],
    message: &str,
    proof: &str,
    big_r: &EdwardsPoint,
    a: &EdwardsPoint,
) -> Result<bool, String> {
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

    let g = ED25519_BASEPOINT_POINT;
    let x = big_r * c + g * sig_r; // c·R + sig_r·G
    let y = d * c + a * sig_r; // c·D + sig_r·A

    let sep = keccak256(b"TXPROOF_V2");
    let prefix = {
        let mut pm = Vec::with_capacity(32 + message.len());
        pm.extend_from_slice(&txid);
        pm.extend_from_slice(message.as_bytes());
        keccak256(&pm)
    };
    let c2 = challenge(&prefix, &d, &x, &y, &sep, big_r, a, &[0u8; 32]);
    Ok(c2 == c)
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
}
