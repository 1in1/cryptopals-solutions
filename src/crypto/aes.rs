#[cfg(test)]
extern crate itertools;
use itertools::Itertools;

use crate::crypto::common::{generate_random_bytes, repeating_block};
use rand::Rng;
use openssl::symm::{encrypt, Cipher};

pub mod ecb;
pub mod cbc;

use crate::crypto::oracle::*;

// Given an oracle of the form:
// (fixed ECB or CBC) . (fixed lpad ++) . (++ fixed rpad)
// Determine whether the oracle is using ECB or CBC
pub fn detect_ecb_or_cbc(oracle: &dyn Oracle) -> Option<bool> {
    // If we pass a constant string of As, we will get a result which iterates
    // after the first block if ECB, and doesn't iterate in CBC
    let block_size = determine_block_size(oracle);

    // Take 4*block_size to ensure we aren't prevented by left or right padding
    let payload = vec![b'A'; 4*block_size];
    let encrypted = oracle(&payload);
    let repeated = repeating_block(&encrypted, block_size);
    let maybe_confident_ecb: Option<bool> = repeated.and_then(|(_, repeated_a)| {
        let payload = vec![b'B'; 4*block_size];
        let encrypted = oracle(&payload);
        let repeated = repeating_block(&encrypted, block_size);
        repeated.and_then(|(_, repeated_b)| {
            if repeated_a == repeated_b {
                Some(false)
            } else {
                Some(true)
            }
        })
    });
    match maybe_confident_ecb {
        Some(true)  => Some(true),  // We had different repeating blocks. ECB
        Some(false) => None,        // We had the same repeating block both times.
                                    // Thus, we cannot tell which mode it's in
        None        => Some(false), // We failed to reliably find repeating blocks. CBC
    }
}

#[test]
fn test_detect_ecb_or_cbc() {
    for _ in 0..100 {
        let cbc_oracle = get_id_oracle()
            .pullback_add_random_left_padding::<5,10>()
            .pullback_add_random_right_padding::<5,10>()
            .pushforward_cbc_encrypt_fixed_key();
        let ecb_oracle = get_id_oracle()
            .pullback_add_random_left_padding::<5,10>()
            .pullback_add_random_right_padding::<5,10>()
            .pushforward_ecb_encrypt_fixed_key();
        let (run_ecb, oracle) = choose_random(ecb_oracle, cbc_oracle);

        match detect_ecb_or_cbc(&oracle) {
            Some(detected_is_ecb) => assert_eq!(run_ecb, detected_is_ecb),
            None                  => assert!(false)
        };
    }
}

// Given an oracle of type
// (fixed block encryption function) . (fixed lpad ++) . (++ fixed rpad)
// Determine the block size in use
pub fn determine_block_size(oracle: &dyn Oracle) -> usize {
    let initial_size = oracle(&Vec::new()).len();
    let mut input: Vec<u8> = Vec::new();
    while oracle(&input).len() == initial_size { input.push(b'A'); }
    let block_size = input.len();
    let intermediate_size = oracle(&input).len();
    while oracle(&input).len() == intermediate_size { input.push(b'A'); }
    input.len() - block_size
}
