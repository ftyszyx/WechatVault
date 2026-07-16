use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use sha2::Sha512;
use zeroize::Zeroize;

const PAGE_SIZE: usize = 4096;
const SQLCIPHER4_ITERATIONS: u32 = 256_000;
const SQLCIPHER3_ITERATIONS: u32 = 64_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchKind {
    SqlCipher4Raw,
    SqlCipher4Derived,
    SqlCipher3Raw,
    SqlCipher3Derived,
    SqlCipherHeaderRaw,
    SqlCipherHeaderDerived,
}

/// Verify a candidate against the first database page. On success, returns the
/// match kind **and** the candidate bytes so the caller can use them as the
/// SQLCipher key for export.
#[allow(dead_code)]
pub fn verify_candidate(candidate: &[u8; 32], page: &[u8]) -> Option<(MatchKind, [u8; 32])> {
    verify_derived_candidate(candidate, page).or_else(|| verify_raw_candidate(candidate, page))
}

pub fn verify_derived_candidate(candidate: &[u8; 32], page: &[u8]) -> Option<(MatchKind, [u8; 32])> {
    if page.len() < PAGE_SIZE {
        return None;
    }

    if verify_v4_derived(candidate, page) {
        return Some((MatchKind::SqlCipher4Derived, *candidate));
    }
    if verify_v3_derived(candidate, page) {
        return Some((MatchKind::SqlCipher3Derived, *candidate));
    }
    if verify_decrypted_header(candidate, page) {
        return Some((MatchKind::SqlCipherHeaderDerived, *candidate));
    }

    None
}

pub fn verify_raw_candidate(candidate: &[u8; 32], page: &[u8]) -> Option<(MatchKind, [u8; 32])> {
    if page.len() < PAGE_SIZE {
        return None;
    }

    let salt = &page[..16];

    let mut v4_key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(candidate, salt, SQLCIPHER4_ITERATIONS, &mut v4_key);
    let v4_match = verify_v4_derived(&v4_key, page);
    let v4_header_match = verify_decrypted_header(&v4_key, page);
    v4_key.zeroize();
    if v4_match || v4_header_match {
        if v4_header_match && !v4_match {
            return Some((MatchKind::SqlCipherHeaderRaw, *candidate));
        }
        return Some((MatchKind::SqlCipher4Raw, *candidate));
    }

    let mut v3_key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(candidate, salt, SQLCIPHER3_ITERATIONS, &mut v3_key);
    let v3_match = verify_v3_derived(&v3_key, page);
    let v3_header_match = verify_decrypted_header(&v3_key, page);
    v3_key.zeroize();
    if v3_match || v3_header_match {
        if v3_header_match && !v3_match {
            return Some((MatchKind::SqlCipherHeaderRaw, *candidate));
        }
        return Some((MatchKind::SqlCipher3Raw, *candidate));
    }

    None
}

fn verify_decrypted_header(key: &[u8; 32], page: &[u8]) -> bool {
    if page.len() < PAGE_SIZE {
        return false;
    }

    let cipher = Aes256::new(key.into());
    for reserved in [80usize, 64, 48, 36, 32, 16] {
        let iv_start = PAGE_SIZE - reserved;
        if iv_start + 16 > page.len() {
            continue;
        }

        let mut block = aes::Block::clone_from_slice(&page[16..32]);
        cipher.decrypt_block(&mut block);
        for (byte, iv) in block.iter_mut().zip(&page[iv_start..iv_start + 16]) {
            *byte ^= iv;
        }

        let valid = block[0..2] == [0x10, 0x00]
            && matches!(block[2], 1 | 2)
            && matches!(block[3], 1 | 2)
            && block[4] as usize == reserved
            && block[5..8] == [64, 32, 32];
        block.zeroize();
        if valid {
            return true;
        }
    }
    false
}

fn verify_v4_derived(key: &[u8; 32], page: &[u8]) -> bool {
    const HMAC_SIZE: usize = 64;
    let payload_end = PAGE_SIZE - HMAC_SIZE;
    let expected = &page[payload_end..PAGE_SIZE];

    // SQLCipher derives the HMAC key from the encryption key and a masked salt.
    // Providers have used both 32-byte and digest-sized output buffers, so the
    // PoC verifies both without weakening the HMAC comparison.
    verify_v4_with_mac_key::<32>(key, page, payload_end, expected)
        || verify_v4_with_mac_key::<64>(key, page, payload_end, expected)
}

fn verify_v4_with_mac_key<const N: usize>(
    key: &[u8; 32],
    page: &[u8],
    payload_end: usize,
    expected: &[u8],
) -> bool {
    let mut mac_salt = masked_salt(&page[..16]);
    let mut mac_key = [0u8; N];
    pbkdf2_hmac::<Sha512>(key, &mac_salt, 2, &mut mac_key);

    let matched = verify_hmac_sha512(&mac_key, &page[16..payload_end], expected);
    mac_salt.zeroize();
    mac_key.zeroize();
    matched
}

fn verify_v3_derived(key: &[u8; 32], page: &[u8]) -> bool {
    const RESERVED_SIZE: usize = 48;
    const HMAC_SIZE: usize = 20;
    let hmac_start = PAGE_SIZE - RESERVED_SIZE + 16;
    let expected = &page[hmac_start..hmac_start + HMAC_SIZE];

    let mut mac_salt = masked_salt(&page[..16]);
    let mut mac_key = [0u8; 32];
    pbkdf2_hmac::<Sha1>(key, &mac_salt, 2, &mut mac_key);

    let matched = verify_hmac_sha1(&mac_key, &page[16..hmac_start], expected);
    mac_salt.zeroize();
    mac_key.zeroize();
    matched
}

fn masked_salt(salt: &[u8]) -> [u8; 16] {
    let mut masked = [0u8; 16];
    for (output, input) in masked.iter_mut().zip(salt.iter()) {
        *output = input ^ 0x3a;
    }
    masked
}

fn verify_hmac_sha512(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    for page_number in [1u32.to_le_bytes(), 1u32.to_be_bytes()] {
        let mut mac =
            <Hmac<Sha512> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(data);
        mac.update(&page_number);
        if mac.verify_slice(expected).is_ok() {
            return true;
        }
    }
    false
}

fn verify_hmac_sha1(key: &[u8], data: &[u8], expected: &[u8]) -> bool {
    for page_number in [1u32.to_le_bytes(), 1u32.to_be_bytes()] {
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(data);
        mac.update(&page_number);
        if mac.verify_slice(expected).is_ok() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_a_v4_raw_key_page_authenticator() {
        let candidate = [0x42u8; 32];
        let mut page = vec![0xabu8; PAGE_SIZE];
        for (index, byte) in page[..16].iter_mut().enumerate() {
            *byte = index as u8;
        }

        let mut derived = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&candidate, &page[..16], SQLCIPHER4_ITERATIONS, &mut derived);
        let mut mac_salt = masked_salt(&page[..16]);
        let mut mac_key = [0u8; 32];
        pbkdf2_hmac::<Sha512>(&derived, &mac_salt, 2, &mut mac_key);

        let payload_end = PAGE_SIZE - 64;
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&mac_key).unwrap();
        mac.update(&page[16..payload_end]);
        mac.update(&1u32.to_le_bytes());
        page[payload_end..].copy_from_slice(&mac.finalize().into_bytes());

        assert_eq!(
            verify_candidate(&candidate, &page),
            Some((MatchKind::SqlCipher4Raw, candidate))
        );

        derived.zeroize();
        mac_salt.zeroize();
        mac_key.zeroize();
    }

    #[test]
    fn rejects_an_unrelated_key() {
        let candidate = [0x42u8; 32];
        let page = vec![0xabu8; PAGE_SIZE];
        assert_eq!(verify_candidate(&candidate, &page), None);
    }
}
use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes256;
