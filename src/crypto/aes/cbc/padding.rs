#[cfg(test)]
use std::iter::once;
use rand::Rng;
use crate::crypto::xor::{byte_xor, fixed_xor};
use crate::crypto::common::{generate_random_bytes, pad_pkcs_7};
use crate::crypto::aes::cbc::{aes_cbc_encrypt, aes_cbc_decrypt};


pub fn attack_cbc_padding(encrypted: &[u8], iv: [u8; 16], oracle: &impl Fn(&[u8], &[u8]) -> bool) -> Vec<u8> {
    const block_size: usize = 16;
    let n = encrypted.len() / block_size;

    let mut blocks: Vec<&[u8]> = Vec::new();
    blocks.push(&iv);
    for i in 0..n { blocks.push(&encrypted[(i*block_size)..((i+1)*block_size)]); }
    let it = iv.chunks(block_size) // Will always be a single element
        .chain(encrypted.chunks(block_size))
        .zip(encrypted.chunks(block_size));
    it.map(|(curr_iv, curr_block)| attack_cbc_padding_single_block::<{block_size}>(curr_block, curr_iv, &oracle))
        .collect::<Vec<Vec<u8>>>()
        .concat()
}

fn attack_cbc_padding_single_block<const BLOCK_SIZE: usize>(block: &[u8], iv: &[u8], oracle: &impl Fn(&[u8], &[u8]) -> bool) -> Vec<u8> {
    // Determine last byte
    let mut zero_iv = [0u8; BLOCK_SIZE];
    for i in 1..=BLOCK_SIZE {
        // Set tmp_iv so that it `should` have the right padding when we find what we want
        let mut tmp_iv = byte_xor(&zero_iv, i as u8);

        // Iterate through the possible byte choices
        for v in 0..=u8::MAX {
            tmp_iv[BLOCK_SIZE-i] = v;
            if oracle(&block, &tmp_iv) {
                // Double check we didn't just get lucky
                if i == 1 {
                    tmp_iv[BLOCK_SIZE-2] ^= 0xffu8;
                    if !oracle(&block, &tmp_iv) { continue }
                }
                zero_iv[BLOCK_SIZE-i] = v ^ (i as u8);
                break;
            }
        }
    }
    fixed_xor(&zero_iv, &iv)
}

fn is_valid_padding(buf: &[u8]) -> bool {
    //println!("{:?}", buf);
    buf[15] > 0 && buf.iter()
        .rev()
        .take(buf[15] as usize)
        .all(|x| *x == buf[15])
}


#[test]
fn test_attack_cbc_padding() {
    let strs: [&[u8]; 10] = [
        b"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        b"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        b"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        b"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        b"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        b"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        b"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        b"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        b"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        b"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    let mut rng = rand::thread_rng();
    
    let choice = rng.gen_range(0..strs.len());
    let s = strs[choice];
    let padded_s = pad_pkcs_7(&s, 16);
    let fixed_key: [u8; 16] = generate_random_bytes();
    let fixed_iv: [u8; 16] = generate_random_bytes();

    let encrypted = aes_cbc_encrypt(s, &fixed_key, &fixed_iv)
        .unwrap();

    let oracle = move |buf: &[u8], iv: &[u8]| {
        let decrypted = aes_cbc_decrypt(buf, &fixed_key, iv)
            .unwrap();
        is_valid_padding(&decrypted)
    };

    let result = attack_cbc_padding(encrypted.as_slice(), fixed_iv, &oracle);
    assert_eq!(padded_s, result);
    
}
