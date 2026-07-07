//! Monero key derivation from mnemonic seed.
//!
//! Standard Monero key derivation:
//!   seed (25 words) → entropy (32 bytes) → spend_key (Scalar) → view_key (keccak256(spend_key))

use zeroize::Zeroizing;
use tiny_keccak::{Hasher, Keccak};

use monero_oxide::ed25519::Scalar;
use monero_seed::{Language, Seed};

/// The wordlist languages we try when restoring a seed, in priority order. English first
/// (by far the most common); `DeprecatedEnglish` (the old buggy wordlist) last so a modern
/// English seed is never misread as it.
const RESTORE_LANGUAGES: [Language; 13] = [
    Language::English,
    Language::Spanish,
    Language::Portuguese,
    Language::Japanese,
    Language::Italian,
    Language::French,
    Language::German,
    Language::Russian,
    Language::Chinese,
    Language::Dutch,
    Language::Esperanto,
    Language::Lojban,
    Language::DeprecatedEnglish,
];

/// Derive spend and view keys from a 25-word mnemonic seed, auto-detecting the wordlist
/// language so seeds in any supported language restore — not just English (the previous
/// behavior silently rejected every non-English seed). The 25-word seed's checksum makes
/// a cross-language false match astronomically unlikely, so the first language that parses
/// is the right one.
pub fn keys_from_mnemonic(mnemonic: &str) -> Result<(Zeroizing<Scalar>, Zeroizing<Scalar>), String> {
    // `Seed::from_string` PANICS (not errors) on a wrong word count, so gate it here —
    // a legacy Monero seed is 24 words, or 25 with the checksum word.
    let word_count = mnemonic.split_whitespace().count();
    if word_count != 24 && word_count != 25 {
        return Err(format!(
            "Invalid mnemonic: expected 24 or 25 words, got {}",
            word_count
        ));
    }

    let mut last_err = String::from("Invalid mnemonic");
    for lang in RESTORE_LANGUAGES {
        match Seed::from_string(lang, Zeroizing::new(mnemonic.to_string())) {
            Ok(seed) => {
                let entropy = seed.entropy();
                return keys_from_entropy(&entropy);
            }
            Err(e) => last_err = format!("Invalid mnemonic: {:?}", e),
        }
    }
    Err(last_err)
}

/// Derive spend and view keys from 32-byte entropy.
pub fn keys_from_entropy(entropy: &[u8; 32]) -> Result<(Zeroizing<Scalar>, Zeroizing<Scalar>), String> {
    // For legacy Monero seeds, entropy IS the spend key (already a valid scalar).
    // Use from_canonical_bytes to match wallet2 behavior.
    // Fall back to from_bytes_mod_order for non-canonical entropy (shouldn't happen with valid seeds).
    let dalek_spend = Option::<curve25519_dalek::Scalar>::from(
        curve25519_dalek::Scalar::from_canonical_bytes(*entropy)
    ).unwrap_or_else(|| curve25519_dalek::Scalar::from_bytes_mod_order(*entropy));
    let spend_key = Scalar::from(dalek_spend);

    // view_key = keccak256(spend_key_bytes) reduced mod l
    // Use the canonical spend key bytes (not the original entropy) for the hash
    let spend_bytes: [u8; 32] = dalek_spend.to_bytes();
    let view_bytes = keccak256(&spend_bytes);
    let dalek_view = curve25519_dalek::Scalar::from_bytes_mod_order(view_bytes);
    let view_key = Scalar::from(dalek_view);

    log::info!("Key derivation: spend={}, view={}", hex::encode(spend_bytes), hex::encode(view_bytes));

    Ok((Zeroizing::new(spend_key), Zeroizing::new(view_key)))
}

/// Generate a new random mnemonic seed.
pub fn generate_mnemonic() -> (String, Zeroizing<Scalar>, Zeroizing<Scalar>) {
    let mut rng = rand::thread_rng();
    let seed = Seed::new(&mut rng, Language::English);

    let entropy = seed.entropy();
    let (spend_key, view_key) = keys_from_entropy(&entropy)
        .expect("freshly generated seed should always produce valid keys");

    let mnemonic = seed.to_string();
    ((*mnemonic).clone(), spend_key, view_key)
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    // The bug this fixes: seeds in any supported language must restore, not just English.
    #[test]
    fn restores_seed_in_any_supported_language() {
        let mut rng = rand::thread_rng();
        for lang in [
            Language::Spanish,
            Language::Japanese,
            Language::Russian,
            Language::French,
            Language::Chinese,
        ] {
            let seed = Seed::new(&mut rng, lang);
            let phrase = seed.to_string();
            assert!(
                keys_from_mnemonic(phrase.as_str()).is_ok(),
                "{:?} seed failed to restore",
                lang
            );
        }
    }

    // Malformed input must return a clean Err, never panic (the library panics on a bad
    // word count, which the guard in keys_from_mnemonic converts to an error).
    #[test]
    fn rejects_invalid_seed_without_panicking() {
        // Wrong word count.
        assert!(keys_from_mnemonic("clearly not a valid monero mnemonic phrase").is_err());
        // Right count (25 words) but not real wordlist entries.
        let fake_25 = vec!["zzzzzz"; 25].join(" ");
        assert!(keys_from_mnemonic(&fake_25).is_err());
    }
}
