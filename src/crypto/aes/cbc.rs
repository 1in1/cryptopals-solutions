use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};

pub mod bitflip;

use crate::crypto::common::{pad_pkcs_7, pad_pkcs_7_if_required};
use crate::crypto::xor::fixed_xor;

pub fn aes_cbc_encrypt(buf: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    let block_size = 16;
    let blocks: Vec<Vec<u8>> = buf.chunks(block_size)
        .map(|block| pad_pkcs_7_if_required(&block, block_size) )
        .collect();
    let padded_key = pad_pkcs_7_if_required(&key, block_size);
    let padded_iv  = pad_pkcs_7_if_required(&iv,  block_size);
    let n = blocks.len();
    let mut enc_blocks: Vec<Vec<u8>> = Vec::with_capacity(n+1);
    enc_blocks.push(padded_iv);
    for i in 0..n {
        let xored = fixed_xor(&enc_blocks[i], &blocks[i]);
        let encrypted = encrypt(cipher, &padded_key, None, &xored);
        match encrypted {
            Ok(enc)  => enc_blocks.push(enc[0..block_size].to_vec()),
            Err(e)   => return Err(e),
        }
    }
    Ok(enc_blocks[1..].concat())
}

pub fn aes_cbc_decrypt(buf: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    let block_size = 16;
    let blocks: Vec<Vec<u8>> = buf.chunks(block_size)
        .map(|block| pad_pkcs_7_if_required(&block, block_size) )
        .collect();
    let padded_key = pad_pkcs_7_if_required(&key, block_size);
    let padded_iv  = pad_pkcs_7_if_required(&iv,  block_size);

    let mut decrypter = Crypter::new(cipher, Mode::Decrypt, &padded_key, None).unwrap();
    decrypter.pad(false);
    let n = blocks.len();
    let mut dec_blocks: Vec<Vec<u8>> = vec![vec![0; block_size+block_size]; n];
    for i in 0..n {
        decrypter.update(&blocks[i], &mut dec_blocks[i])?;
    }

    dec_blocks[0] = fixed_xor(&dec_blocks[0][0..block_size], &padded_iv);
    for i in 1..n {
        dec_blocks[i] = fixed_xor(&dec_blocks[i][0..block_size], &blocks[i-1]);
    }

    Ok(dec_blocks.concat())
}

#[test]
fn test_aes_cbc_decrypt() {
    let contents = std::fs::read_to_string("./data/10.txt")
        .expect("Should have been able to read the file")
        .replace("\n", "");
    let decoded: Vec<u8> = general_purpose::STANDARD.decode(contents).expect("Base64 decoding failed");
    let key = b"YELLOW SUBMARINE";
    let iv = vec![0u8; 16];
    let decrypted = aes_cbc_decrypt(decoded.as_slice(), key, &iv).unwrap();
    let as_string = std::str::from_utf8(&decrypted).unwrap();
    let expected = String::from("Say -- Play that funky music Say, go white boy, go white boy go \n");
    assert!(as_string.contains(&expected));
}

#[test]
fn test_aes_cbc_encrypt_and_decrypt() {
    let plaintext = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let key = b"YELLOW SUBMARINE";
    let iv = b"yellow submarine";
    let ciphertext = aes_cbc_encrypt(plaintext, key, iv).unwrap();
    let result = aes_cbc_decrypt(&ciphertext, key, iv).unwrap();
    assert_eq!(pad_pkcs_7(plaintext, 64).to_vec(), result);
}
