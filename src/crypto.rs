use base64::{Engine as _, engine::general_purpose};
use openssl::symm::{decrypt, Cipher};

pub mod base;
pub mod attack;

#[cfg(test)]
mod generic_tests {
    use crate::crypto::*;
    use crate::util::*;

    #[test]
    fn test_detect_single_byte_xor_encoded_string() {
        let contents = std::fs::read_to_string("./data/4.txt")
            .expect("Should have been able to read the file");
        let decoded = contents.split("\n")
            .map(|x| hex::decode(x).expect("Hex decoding failed") );
        let contains = decoded
            .map(|s| base::byte_xor(&s, attack::attack_single_byte_xor_cipher(s.as_slice())) )
            .any(|s| s == b"Now that the party is jumping\n" );
        assert!(contains);
    }

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

}    
