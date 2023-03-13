use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};

use crate::crypto::aes::determine_block_size;
use crate::crypto::common::{generate_random_bytes, pad_pkcs_7, repeating_block};

#[test]
fn test_detect_aes_128_ecb() {
    let contents = std::fs::read_to_string("./data/8.txt")
        .expect("Should have been able to read the file");
    let expected = b"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    let results: Vec<&str> = contents
        .split("\n")
        .filter(|s| repeating_block(&s.as_bytes(), 32).is_some() )
        .collect();
    assert_eq!(1, results.len());
    assert_eq!(expected, results[0].as_bytes());
}

pub fn attack_aes_ecb(oracle: &impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    // Determine the block size
    let initial_size = oracle(&Vec::new()).len();
    let block_size = determine_block_size(oracle);
        
    // Detect cipher mode
    // Assume we're using ECB

    let mut known = Vec::new();
    for j in 0..(initial_size / block_size) {
        let offset = j*block_size;
        for i in 0..block_size {
            //let known_len = known.len();
            //let blocks_required = (known_len + 1) / block_size;
            //let required_padding = (block_size * blocks_required) - known_len;
            let required_padding = block_size - i - 1;
            let init = vec![b'A'; required_padding];
            let lookup: HashMap<Vec<u8>, u8> = (0..=u8::MAX)
                .map(|b| {
                    let mut payload = init.clone();
                    payload.extend(known.clone());
                    payload.push(b);
                    let enc = oracle(payload.as_slice());
                    let first_block = enc[offset..(offset+block_size)].to_vec();
                    (first_block, b)
                }).collect();
            let true_result = oracle(init.as_slice())[offset..(offset+block_size)].to_vec();
            let next_byte = lookup.get(&true_result);

            // We will get a fail if we have reached the end of the known string,
            // since at this point, using a shorter input will change the filling 
            // value in the padding
            match next_byte {
                Some(b) => known.push(*b),
                None    => break,
            }
        }
    }
    known.truncate(known.len() - 1);
    known
}

#[test]
fn test_attack_aes_ecb() {
    let unknown_string = b"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
    let unknown = general_purpose::STANDARD
        .decode(unknown_string)
        .expect("Base64 decoding failed");
    let fixed_key: [u8; 16] = generate_random_bytes();
    let cipher = Cipher::aes_128_ecb();

    let oracle = move |buf: &[u8]| {
        let full_buf = [buf, &unknown].concat();
        let padded = pad_pkcs_7(&full_buf, 16);
        encrypt(cipher, &fixed_key, None, &padded).unwrap()
    };

    let expected = b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n".to_vec();

    let result: Vec<u8> = attack_aes_ecb(&oracle);
    assert_eq!(result, expected);
}
