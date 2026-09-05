//! Monero message signing (`SigV1`) — the primitive behind "Sign in with Ripley".
//!
//! ⚠️ UNAUDITED CRYPTO — must be validated against official Monero before being
//! relied on. A produced signature is byte-compatible iff `monero-wallet-rpc`
//! (or `monero-wallet-cli verify`) reports **Good** over the SAME message bytes
//! and address. Until that live-`verify` gate passes, treat the output as
//! untrusted. (This mirrors `tx_proof.rs`, whose shared primitives — keccak256,
//! hash_to_scalar, base58 — are already validated against real Monero GUI proofs.)
//!
//! Algorithm (Monero `crypto.cpp` `generate_signature`, the `SigV1` message form):
//!   H    = keccak256(message)                      (cn_fast_hash of the message)
//!   pub  = the address's SPEND public key          (verify checks the sig against it)
//!   k random, comm = k·G
//!   c    = hash_to_scalar( H ‖ pub ‖ comm )        (s_comm layout: h ‖ key ‖ comm)
//!   r    = k − c·sec                                (sec = the spend secret key)
//!   signature = "SigV1" + base58_monero( c[32] ‖ r[32] )
//! where hash_to_scalar(x) = reduce_mod_l(keccak256(x)). `monero-wallet-rpc verify`
//! accepts both SigV1 and SigV2; SigV1 is the simpler, sufficient form (the address
//! binds through the pubkey the verifier checks against).

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::traits::Identity;
use curve25519_dalek::{EdwardsPoint, Scalar};
use rand_core::OsRng;

use super::base58_monero;

const SIG_PREFIX: &str = "SigV1";

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

/// Monero subaddress private spend key derivation:
/// `b_i = b + Hs("SubAddr\0" || a || major || minor)`.
/// This is the key `monero-wallet-rpc sign {address}` uses for a subaddress.
pub fn subaddress_spend_key(
    spend_sec: &Scalar,
    view_sec: &Scalar,
    account: u32,
    address: u32,
) -> Scalar {
    let mut buf = Vec::with_capacity(8 + 32 + 8);
    buf.extend_from_slice(b"SubAddr\0");
    buf.extend_from_slice(view_sec.as_bytes());
    buf.extend_from_slice(&account.to_le_bytes());
    buf.extend_from_slice(&address.to_le_bytes());
    spend_sec + hash_to_scalar(&buf)
}

/// The Schnorr challenge `c = Hs(H ‖ pub ‖ comm)` — Monero's `s_comm` struct
/// (`hash h; public_key key; ec_point comm;`), each field 32 bytes, in that order.
fn challenge(h: &[u8; 32], pub_key: &EdwardsPoint, comm: &EdwardsPoint) -> Scalar {
    let mut buf = [0u8; 96];
    buf[0..32].copy_from_slice(h);
    buf[32..64].copy_from_slice(&pub_key.compress().to_bytes());
    buf[64..96].copy_from_slice(&comm.compress().to_bytes());
    hash_to_scalar(&buf)
}

/// Sign `message` with `spend_sec` such that Monero's `verify(message, <addr whose
/// spend key is spend_pub>, signature)` returns Good. `spend_pub` MUST equal
/// `spend_sec·G` (the address's spend public key). Returns `"SigV1<base58>"`.
pub fn sign_message_v1(message: &str, spend_sec: &Scalar, spend_pub: &EdwardsPoint) -> String {
    let h = keccak256(message.as_bytes());
    // Retry loop matches crypto.cpp: c and r must both be non-zero (astronomically
    // rare to fail even once), so a bounded loop is a formality.
    loop {
        let k: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let comm = k * ED25519_BASEPOINT_POINT; // comm = k·G
        let c = challenge(&h, spend_pub, &comm);
        if c == Scalar::ZERO {
            continue;
        }
        let r = k - c * spend_sec; // r = k − c·sec
        if r == Scalar::ZERO {
            continue;
        }
        let mut chunk = [0u8; 64];
        chunk[0..32].copy_from_slice(c.as_bytes());
        chunk[32..64].copy_from_slice(r.as_bytes());
        return format!("{}{}", SIG_PREFIX, base58_monero::encode(&chunk));
    }
}

/// Verify a `SigV1` message signature against `spend_pub` — Monero's
/// `check_signature`: recompute `comm = c·pub + r·G`, re-hash, confirm it equals
/// the embedded `c`. Used for self-consistency tests and to check golden vectors
/// produced by real Monero. (The production verifier is monero-wallet-rpc; this is
/// our independent reference.)
pub fn verify_message_v1(
    message: &str,
    spend_pub: &EdwardsPoint,
    signature: &str,
) -> Result<bool, String> {
    let body = signature
        .strip_prefix(SIG_PREFIX)
        .ok_or("not a SigV1 signature")?;
    let bytes = base58_monero::decode(body)?;
    if bytes.len() != 64 {
        return Err(format!("expected 64 signature bytes, got {}", bytes.len()));
    }
    let c: Scalar = Option::from(Scalar::from_canonical_bytes(
        bytes[0..32].try_into().unwrap(),
    ))
    .ok_or("non-canonical c")?;
    let r: Scalar = Option::from(Scalar::from_canonical_bytes(
        bytes[32..64].try_into().unwrap(),
    ))
    .ok_or("non-canonical r")?;
    if c == Scalar::ZERO {
        return Ok(false);
    }
    // comm = c·pub + r·G  (== k·G for an honest signature, since pub = sec·G).
    // Variable-time is fine here: verification touches only public inputs (pub, c, r),
    // never secret key material, so there's no timing side-channel to leak.
    let comm = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, spend_pub, &r);
    if comm == EdwardsPoint::identity() {
        return Ok(false); // identity point → reject (matches crypto.cpp infinity check)
    }
    let h = keccak256(message.as_bytes());
    let c2 = challenge(&h, spend_pub, &comm);
    Ok(c2 == c)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keypair() -> (Scalar, EdwardsPoint) {
        let sec: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let pubk = sec * ED25519_BASEPOINT_POINT;
        (sec, pubk)
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sec, pubk) = keypair();
        let msg =
            "xmr.bio wants you to sign in with your Monero address:\n4Abc...\n\nNonce: deadbeef";
        let sig = sign_message_v1(msg, &sec, &pubk);
        assert!(sig.starts_with("SigV1"));
        assert!(
            verify_message_v1(msg, &pubk, &sig).unwrap(),
            "honest signature must verify"
        );
    }

    #[test]
    fn verifier_rejects_forgeries() {
        let (sec, pubk) = keypair();
        let msg = "sign in message";
        let sig = sign_message_v1(msg, &sec, &pubk);

        // Baseline passes.
        assert!(verify_message_v1(msg, &pubk, &sig).unwrap());
        // Tampered message → reject.
        assert!(!verify_message_v1("sign in messagE", &pubk, &sig).unwrap());
        // Wrong public key → reject.
        let (_s2, pub2) = keypair();
        assert!(!verify_message_v1(msg, &pub2, &sig).unwrap());
        // Tampered signature body (flip a base58 char region) → decode-or-verify fail.
        let mut bad = sig.clone();
        let last = bad.pop().unwrap();
        bad.push(if last == 'A' { 'B' } else { 'A' });
        assert!(matches!(
            verify_message_v1(msg, &pubk, &bad),
            Ok(false) | Err(_)
        ));
    }

    #[test]
    fn empty_message_signs_and_verifies() {
        let (sec, pubk) = keypair();
        let sig = sign_message_v1("", &sec, &pubk);
        assert!(verify_message_v1("", &pubk, &sig).unwrap());
    }

    #[test]
    fn subaddress_spend_key_matches_monero_address_derivation() {
        use monero_address::{Network, SubaddressIndex};
        use monero_wallet::ViewPair;
        use zeroize::Zeroizing;

        let spend_sec: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let view_sec: Scalar = monero_oxide::ed25519::Scalar::random(&mut OsRng).into();
        let spend_pub = monero_oxide::ed25519::Point::from(&spend_sec * ED25519_BASEPOINT_POINT);
        let view = Zeroizing::new(monero_oxide::ed25519::Scalar::from(view_sec));
        let vp = ViewPair::new(spend_pub, view).expect("view pair");
        let idx = SubaddressIndex::new(0, 1).unwrap();
        let addr = vp.subaddress(Network::Mainnet, idx);

        let sub_sec = subaddress_spend_key(&spend_sec, &view_sec, 0, 1);
        let sub_pub = sub_sec * ED25519_BASEPOINT_POINT;
        let target_spend: EdwardsPoint = addr.spend().into();
        assert_eq!(sub_pub, target_spend);

        let sig = sign_message_v1("subaddress siwr", &sub_sec, &sub_pub);
        assert!(verify_message_v1("subaddress siwr", &sub_pub, &sig).unwrap());
        let root_pub = spend_sec * ED25519_BASEPOINT_POINT;
        assert!(!verify_message_v1("subaddress siwr", &root_pub, &sig).unwrap());
    }

    // GOLDEN VECTOR — the byte-compat gate against OFFICIAL Monero. Paste a real
    // `monero-wallet-cli`/`monero-wallet-rpc sign` output here (its `verify` reports
    // Good) and un-`ignore` this test: our independent `verify_message_v1` MUST also
    // accept it, proving our H / s_comm layout / SigV1 encoding are byte-identical.
    // Until then this primitive is UNAUDITED (see module header) and the live
    // monero-wallet-rpc `verify` in the SIWR callback is the production gate.
    #[test]
    #[ignore = "fill in a real monero-wallet-cli SigV1 (message,address,signature) vector"]
    fn validates_against_real_monero_signature() {
        use monero_address::{MoneroAddress, Network};
        const MESSAGE: &str = "REPLACE_ME";
        const ADDRESS: &str = "REPLACE_ME";
        const SIGNATURE: &str = "SigV1REPLACE_ME";
        let addr = MoneroAddress::from_str(Network::Mainnet, ADDRESS).expect("address");
        let spend_pub: EdwardsPoint = addr.spend().into();
        assert!(
            verify_message_v1(MESSAGE, &spend_pub, SIGNATURE).unwrap(),
            "our verifier disagrees with official Monero — SigV1 layout is off"
        );
    }
}
