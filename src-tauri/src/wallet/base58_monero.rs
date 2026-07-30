//! Monero's block-based Base58 (NOT Bitcoin Base58). Used to serialize tx-proof
//! strings (and addresses) in the format wallet2 / monerod expect.
//!
//! Data is split into 8-byte blocks; each block is read big-endian and encoded
//! to a fixed number of Base58 chars per the size table below (a full 8-byte
//! block → 11 chars). Leading positions pad with the alphabet's first char.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;
/// Base58 chars produced by a block of N bytes (N = index, 0..=8).
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];
/// Inverse: max bytes that decode from M base58 chars (M = index, 0..=11).
/// Entries that can't occur are 0 (invalid).
const DECODED_BLOCK_SIZES: [i32; 12] = [0, -1, 1, 2, -1, 3, 4, 5, -1, 6, 7, 8];

fn encode_block(data: &[u8], out: &mut Vec<u8>) {
    debug_assert!(data.len() <= FULL_BLOCK_SIZE && !data.is_empty());
    let mut num: u64 = 0;
    for &b in data {
        num = (num << 8) | b as u64;
    }
    let size = ENCODED_BLOCK_SIZES[data.len()];
    let mut block = vec![ALPHABET[0]; size];
    let mut i = size;
    while num > 0 && i > 0 {
        i -= 1;
        block[i] = ALPHABET[(num % 58) as usize];
        num /= 58;
    }
    out.extend_from_slice(&block);
}

/// Encode bytes to Monero Base58.
pub fn encode(data: &[u8]) -> String {
    let mut out = Vec::new();
    let full = data.len() / FULL_BLOCK_SIZE;
    for i in 0..full {
        encode_block(
            &data[i * FULL_BLOCK_SIZE..(i + 1) * FULL_BLOCK_SIZE],
            &mut out,
        );
    }
    let rem = data.len() % FULL_BLOCK_SIZE;
    if rem != 0 {
        encode_block(&data[full * FULL_BLOCK_SIZE..], &mut out);
    }
    // Encoding only produces alphabet bytes, so this is valid UTF-8.
    String::from_utf8(out).expect("base58 alphabet is ASCII")
}

fn char_value(c: u8) -> Option<u64> {
    ALPHABET.iter().position(|&a| a == c).map(|p| p as u64)
}

fn decode_block(data: &[u8], out: &mut Vec<u8>) -> Result<(), String> {
    if data.len() >= DECODED_BLOCK_SIZES.len() {
        return Err("invalid base58 block length".into());
    }
    let size = DECODED_BLOCK_SIZES[data.len()];
    if size <= 0 {
        return Err("invalid base58 block length".into());
    }
    let size = size as usize;
    let mut num: u128 = 0;
    for &c in data {
        let v = char_value(c).ok_or("invalid base58 character")?;
        num = num * 58 + v as u128;
    }
    if size < 8 && num >= (1u128 << (8 * size)) {
        return Err("base58 block overflow".into());
    }
    // Big-endian, `size` bytes.
    for i in (0..size).rev() {
        out.push(((num >> (8 * i)) & 0xff) as u8);
    }
    Ok(())
}

/// Decode Monero Base58. Inverse of `encode`.
pub fn decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let full = bytes.len() / FULL_ENCODED_BLOCK_SIZE;
    for i in 0..full {
        decode_block(
            &bytes[i * FULL_ENCODED_BLOCK_SIZE..(i + 1) * FULL_ENCODED_BLOCK_SIZE],
            &mut out,
        )?;
    }
    let rem = bytes.len() % FULL_ENCODED_BLOCK_SIZE;
    if rem != 0 {
        decode_block(&bytes[full * FULL_ENCODED_BLOCK_SIZE..], &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_block() {
        // One full block of zero bytes → 11 leading-alphabet chars.
        assert_eq!(encode(&[0u8; 8]), "11111111111");
    }

    #[test]
    fn roundtrip() {
        for len in [1usize, 4, 7, 8, 16, 32, 69, 96] {
            let data: Vec<u8> = (0..len).map(|i| ((i * 37 + 11) & 0xff) as u8).collect();
            let enc = encode(&data);
            let dec = decode(&enc).expect("decode");
            assert_eq!(dec, data, "roundtrip failed for len {len}");
        }
    }

    #[test]
    fn proof_chunk_length() {
        // A proof chunk is 96 bytes = 12 full blocks → 132 chars.
        let enc = encode(&[0xABu8; 96]);
        assert_eq!(enc.len(), 132);
    }
}
