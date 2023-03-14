#[cfg(test)]

use crate::crypto::aes::cbc::{aes_cbc_encrypt, aes_cbc_decrypt};
use crate::crypto::common::generate_random_bytes;

// TODO: Genericise this over prefixes, etc.
pub fn attack_cbc_bitflip(oracle: impl Fn(String) -> Vec<u8>) -> Vec<u8> {
    // First get hold of a valid ciphertext. We need to ensure it has a block
    // at the beginning which we don't mind scrambling
    //
    // For this challenge, it is actually done for us by the long prefix string
    //
    // We also want to edit as few bytes as possible, so it makes the most sense to 
    // construct a block as follows:
    // INPUT:    b";dmi=ru;"
    // ESCAPED:  b"';'dmi'='ru';'"
    // MODIFIED: b"';admin=true;'"
    let block_size = 16;
    let payload = String::from(";dmi=ru;");
    let mut valid_ciphertext = oracle(payload);
    // It happens that our input starts at the beginning of a block
    // So, we can cut immdiately
    valid_ciphertext[block_size + 2]  ^= b'a' ^ b'\'';
    valid_ciphertext[block_size + 6]  ^= b'n' ^ b'\'';
    valid_ciphertext[block_size + 8]  ^= b't' ^ b'\'';
    valid_ciphertext[block_size + 11] ^= b'e' ^ b'\'';
    valid_ciphertext
}

#[test]
fn test_attack_cbc_bitflip() {
    let fixed_key: [u8; 16] = generate_random_bytes();
    let fixed_iv:  [u8; 16] = generate_random_bytes();

    let oracle = move |s: String| {
        let escaped = s.replace(";", "';'")
            .replace("=", "'='");
        let buf = escaped.as_bytes();
        let plaintext = [
            b"comment1=cooking%20MCs;userdata=",
            buf,
            b";comment2=%20like%20a%20pound%20of%20bacon",
        ].concat();
        aes_cbc_encrypt(&plaintext, &fixed_key, &fixed_iv)
            .unwrap()
    };

    let has_admin_true = move |buf: &[u8]| {
        let decrypted = aes_cbc_decrypt(&buf, &fixed_key, &fixed_iv)
            .unwrap();

        let target = b";admin=true;";
        let m = target.len();
        let n = decrypted.len() - m;
        for i in 0..n {
            if decrypted[i..(i+m)] == *target {
                return true;
            }
        }
        false
    };

    let malicious_block = attack_cbc_bitflip(oracle);
    assert!(has_admin_true(&malicious_block));
}
