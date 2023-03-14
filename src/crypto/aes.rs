#[cfg(test)]
extern crate itertools;
use itertools::Itertools;

use crate::crypto::common;
use rand::Rng;
use openssl::symm::{encrypt, Cipher};

pub mod ecb;
pub mod cbc;


pub fn encryption_oracle(buf: &[u8], run_ecb: bool) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut rng = rand::thread_rng();
    let garbage_padding: [u8; 20] = common::generate_random_bytes();
    let pre_pad_len:  usize = rng.gen_range(5..=10);
    let post_pad_len: usize = rng.gen_range(5..=10);
    let padded_buf: Vec<u8> = [
        &garbage_padding[0..pre_pad_len],
        buf,
        &garbage_padding[pre_pad_len..(pre_pad_len + post_pad_len)]
    ].concat();
    let key: [u8; 16] = common::generate_random_bytes();

    if run_ecb {
        let cipher = Cipher::aes_128_ecb();
        encrypt(cipher, &key, None, &padded_buf)
    } else {
        let iv: [u8; 16] = common::generate_random_bytes();
        cbc::aes_cbc_encrypt(&padded_buf, &key, &iv)
    }
}

pub fn detect_ecb_or_cbc(oracle: &impl Fn(&[u8]) -> Vec<u8>) -> Option<bool> {
    // The prepended padding is only 5-10 bytes
    // If we pass a constant string of As, we will get a result which iterates
    // after the first block if ECB, and doesn't iterate in CBC
    // We also drop the last two blocks
    let s = vec![b'A'; 400];
    let enc = oracle(&s);
    let blocks: Vec<&[u8]> = enc.chunks(16).collect();
    let n = blocks.len();
    let unique_inner_blocks: Vec<Vec<u8>> = blocks[1..(n-2)]
        .iter()
        .map(|x| x.to_vec() )
        .unique()
        .collect();
    let unique_blocks_count = unique_inner_blocks.len();

    if unique_blocks_count == 1 { Some(true) }
    else if unique_blocks_count > 1 { Some(false) }
    else { None }
}

#[test]
fn test_detect_ecb_or_cbc() {
    let mut rng = rand::thread_rng();
    for _ in 0..100 {
        let run_ecb = rng.gen();
        let oracle = move |buf: &[u8]| {
           encryption_oracle(&buf, run_ecb).unwrap()
        };
        match detect_ecb_or_cbc(&oracle) {
            Some(detected_is_ecb) => assert_eq!(run_ecb, detected_is_ecb),
            None                  => assert!(false)
        };
    }
}

pub fn determine_block_size(oracle: &impl Fn(&[u8]) -> Vec<u8>) -> usize {
    let initial_size = oracle(&Vec::new()).len();
    let mut input: Vec<u8> = Vec::new();
    while oracle(&input).len() == initial_size { input.push(b'A'); }
    let block_size = input.len();
    let intermediate_size = oracle(&input).len();
    while oracle(&input).len() == intermediate_size { input.push(b'A'); }
    input.len() - block_size
}

