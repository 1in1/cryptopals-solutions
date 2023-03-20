use itertools::Itertools;
use base64::{Engine as _, engine::general_purpose};
use concat_arrays::concat_arrays;
use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};
use crate::crypto::xor::{byte_xor, fixed_xor, repeating_key_xor};
use crate::crypto::xor::attack::attack_single_byte_xor_cipher;
use crate::crypto::common::{generate_random_bytes, pad_pkcs_7};

// TODO: Come back and do this with streams
pub fn aes_ctr(buf: &[u8], key: &[u8], nonce: u64) -> Vec<u8> {
    const BLOCK_SIZE: usize = 16;
    let cipher = Cipher::aes_128_ecb();
    buf.chunks(BLOCK_SIZE)
        .enumerate()
        .map(|(counter, plaintext)| {
            let ctr_nonce: [u8; 16] = concat_arrays!(nonce.to_le_bytes(), counter.to_le_bytes());
            let enc = encrypt(cipher, &key, None, &pad_pkcs_7(&ctr_nonce, BLOCK_SIZE)).unwrap();
            repeating_key_xor(&enc, plaintext)[0..plaintext.len()].to_vec()
        }).concat()
}

#[test]
fn test_aes_ctr() {
    let case = b"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
    let ciphertext = general_purpose::STANDARD
        .decode(case)
        .expect("Base64 decoding failed");
    let key = b"YELLOW SUBMARINE";
    let nonce = 0u64;
    let returned = aes_ctr(&ciphertext, key, nonce);
    let expected = b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ".to_vec();
    assert_eq!(expected, returned);
}

pub fn attack_fixed_nonce_aes_ctr(ciphertexts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    // For each byte position, we pick the keystream byte choice which produces the optimal outcome
    // across all the different plaintexts
    let n = ciphertexts
        .iter()
        .map(|x| x.len())
        .max()
        .unwrap();
    let mut keystream: Vec<u8> = Vec::new();
    for i in 0..n {
        let tmp_buf: Vec<u8> = ciphertexts
            .clone()
            .iter()
            .filter(|x| x.len() > i)
            .map(|x| x[i])
            .collect();
        let chosen_byte = attack_single_byte_xor_cipher(tmp_buf.as_slice());
        keystream.push(chosen_byte);
    }
    ciphertexts
        .iter()
        .map(|x| repeating_key_xor(&x, keystream.as_slice()))
        .collect()
}

#[test]
fn test_attack_fixed_nonce_aes_ctr() {
    let plaintexts: Vec<Vec<u8>> = [
        b"SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==".to_vec(),
        b"Q29taW5nIHdpdGggdml2aWQgZmFjZXM=".to_vec(),
        b"RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==".to_vec(),
        b"RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=".to_vec(),
        b"SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk".to_vec(),
        b"T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".to_vec(),
        b"T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=".to_vec(),
        b"UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==".to_vec(),
        b"QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=".to_vec(),
        b"T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl".to_vec(),
        b"VG8gcGxlYXNlIGEgY29tcGFuaW9u".to_vec(),
        b"QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==".to_vec(),
        b"QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=".to_vec(),
        b"QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==".to_vec(),
        b"QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=".to_vec(),
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".to_vec(),
        b"VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==".to_vec(),
        b"SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==".to_vec(),
        b"SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==".to_vec(),
        b"VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==".to_vec(),
        b"V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==".to_vec(),
        b"V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==".to_vec(),
        b"U2hlIHJvZGUgdG8gaGFycmllcnM/".to_vec(),
        b"VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=".to_vec(),
        b"QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=".to_vec(),
        b"VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=".to_vec(),
        b"V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=".to_vec(),
        b"SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==".to_vec(),
        b"U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==".to_vec(),
        b"U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=".to_vec(),
        b"VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==".to_vec(),
        b"QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu".to_vec(),
        b"SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=".to_vec(),
        b"VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs".to_vec(),
        b"WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=".to_vec(),
        b"SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0".to_vec(),
        b"SW4gdGhlIGNhc3VhbCBjb21lZHk7".to_vec(),
        b"SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=".to_vec(),
        b"VHJhbnNmb3JtZWQgdXR0ZXJseTo=".to_vec(),
        b"QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=".to_vec(),
        ].iter()
        .map(|x| general_purpose::STANDARD.decode(x).expect("Base64 decoding failed"))
        .collect();
    let key: [u8; 16] = generate_random_bytes();
    let ciphertexts: Vec<Vec<u8>> = plaintexts
        .clone()
        .iter()
        .map(|x| aes_ctr(&x.as_slice(), &key, 0))
        .collect();

    let decrypted = attack_fixed_nonce_aes_ctr(&ciphertexts)
        .concat();
    println!("{:?}", std::str::from_utf8(&decrypted));

    // The output has a couple slip ups, but it's very obvious we're looking at Yeats - Easter
    // 1916, from googling the contents :)
}

#[test]
fn test_attack_fixed_nonce_aes_ctr_2() {
    let contents = std::fs::read_to_string("./data/20.txt")
        .expect("Should have been able to read the file");
    let decoded: Vec<Vec<u8>> = contents
        .split("\n")
        .map(|x| { println!("{}", x.len()); general_purpose::STANDARD.decode(x).expect("Base64 decoding failed") })
        .collect();
    let decrypted = attack_fixed_nonce_aes_ctr(&decoded[0..(decoded.len() - 1)]);
    let strs: Vec<&str> = decrypted
        .iter()
        .map(|x| std::str::from_utf8(&x).unwrap())
        .collect();
    for s in strs {
        println!("{:?}", s);
    }
}
