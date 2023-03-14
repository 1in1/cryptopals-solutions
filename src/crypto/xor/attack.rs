#[cfg(test)]
use base64::{Engine as _, engine::general_purpose};

use crate::crypto::{common, xor};
use crate::util;

#[test]
fn test_detect_single_byte_xor_encoded_string() {
    let contents = std::fs::read_to_string("./data/4.txt")
        .expect("Should have been able to read the file");
    let decoded = contents.split("\n")
        .map(|x| hex::decode(x).expect("Hex decoding failed") );
    let contains = decoded
        .map(|s| xor::byte_xor(&s, xor::attack::attack_single_byte_xor_cipher(s.as_slice())) )
        .any(|s| s == b"Now that the party is jumping\n" );
    assert!(contains);
}

pub fn attack_single_byte_xor_cipher(buf: &[u8]) -> u8 {
    (0..=u8::MAX)
        .map(|x| (x, common::english_inverse_probability(&xor::byte_xor(&buf, x))) )
        .min_by(|(_, score_x), (_, score_y)| score_x.partial_cmp(score_y).unwrap() )
        .unwrap()
        .0
}

#[test]                                                                                                                             
fn test_attack_single_byte_xor_cipher() {                                                                                           
    let case: [u8; 34] = hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");                              
    let expected = b"Cooking MC's like a pound of bacon";
    let result = xor::byte_xor(&case, attack_single_byte_xor_cipher(&case));
    assert_eq!(result, expected);                                                                                               
}

pub fn attack_repeating_key_xor_cipher_fixed_keysize(buf: &[u8], keysize: usize) -> Vec<u8> {
    let blocks: Vec<&[u8]> = buf.chunks(keysize).collect();
    let transposed = util::transpose(&blocks);
    transposed.iter()
        .map(|vec| attack_single_byte_xor_cipher(vec) )
        .collect()
}

pub fn attack_repeating_key_xor_cipher(buf: &[u8]) -> Vec<u8> {
    let mut keysizes: Vec<(usize, f64)> = (2..=40)
        .map(|keysize| (keysize, common::normalised_hamming_distance(&buf[0..keysize], &buf[keysize..(2*keysize)])) )
        .collect();
    keysizes.sort_by(|&(_, score1), &(_, score2)| (&score1).partial_cmp(&score2).unwrap() );
    keysizes.iter()
        .map(|&(keysize, _)| keysize )
        .take(30)
        .map(|v| attack_repeating_key_xor_cipher_fixed_keysize(&buf, v) )
        .map(|k| (k.clone(), common::english_inverse_probability(&k)) ) // f64 does not implement Ord
        .min_by(|(_, s1), (_, s2)| s1.partial_cmp(s2).unwrap() )
        .unwrap()
        .0.to_vec()
}

#[test]
fn test_attack_repeating_key_xor_cipher() {
    let contents = std::fs::read_to_string("./data/6.txt")
        .expect("Should have been able to read the file")
        .replace("\n", "");
    let decoded = general_purpose::STANDARD.decode(contents).expect("Base64 decoding failed");
    let attacked = attack_repeating_key_xor_cipher(decoded.as_slice());
    let expected = "Terminator X: Bring the noise".to_string();
    assert_eq!(expected, std::str::from_utf8(&attacked).unwrap());
}
