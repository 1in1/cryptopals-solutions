use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};
use base64::{Engine as _, engine::general_purpose};

pub mod byte_by_byte;
pub mod cut_and_paste;

#[test]
fn test_aes_ecb_decrypt() {
    let contents = std::fs::read_to_string("./data/7.txt")
        .expect("Should have been able to read the file")
        .replace("\n", "");
    let decoded = general_purpose::STANDARD.decode(contents).expect("Base64 decoding failed");
    let key = b"YELLOW SUBMARINE";
    let cipher = Cipher::aes_128_ecb();
    let plaintext = decrypt(cipher, key, None, &decoded).unwrap();
    let expected = b"I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \n";
    assert_eq!(expected, &plaintext[0..expected.len()]);
}
