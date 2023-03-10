use std::collections::HashMap;
use base64::{Engine as _, engine::general_purpose};

use crate::util;
use crate::stats;
use crate::crypto::base;

// We cannot build the HashMap statically/constantly, annoyingly
static ENGLISH_EXPECTED_FREQUENCIES: [(char, u32); 28] = [
    (' ', 1217), // whitespace
    ('a', 0609),
    ('b', 0105),
    ('c', 0284),
    ('d', 0292),
    ('e', 1136),
    ('f', 0179),
    ('g', 0138),
    ('h', 0341),
    ('i', 0544),
    ('j', 0024),
    ('k', 0041),
    ('l', 0292),
    ('m', 0276),
    ('n', 0544),
    ('o', 0600),
    ('p', 0195),
    ('q', 0024),
    ('r', 0495),
    ('s', 0568),
    ('t', 0803),
    ('u', 0243),
    ('v', 0097),
    ('w', 0138),
    ('x', 0024),
    ('y', 0130),
    ('z', 0003),
    ('*', 0657), // everything else
    ];

// We approach this as a chi-square test for homogeneity
// We treat each character as an independent variable, and 
// bucket appropriately. 
// Observe that since we're working with CDFs, which are monotone, and just want a
// "greatest p-value", we do not need to apply the CDF
fn english_inverse_probability(arr: &[u8]) -> f64 {
    if arr.iter()
        .any(|&x| !x.is_ascii() || ((x as char).is_control() && x != b'\n') ) {
        return f64::MAX;
    }

    let english_expected_frequencies_total: f64 = 
        ENGLISH_EXPECTED_FREQUENCIES
            .iter()
            .fold(0f64, |acc, (_,n)| acc + (*n as f64) );
    let english_expected_frequencies = HashMap::from(
        ENGLISH_EXPECTED_FREQUENCIES
            .map(|(k,v)| (k, (v as f64)/english_expected_frequencies_total) )
            );

    // Build hashmap of observed values
    let mut freqs = HashMap::new(); 
    arr.iter()
        .map(|x| *x as char )
        .map( |x| {
            if x.is_ascii_alphabetic() {
                x.to_ascii_lowercase()
            } else if x == ' ' || x == '\t' {
                ' '
            } else {
                '*'
            }
        }).for_each(|k| *freqs.entry(k).or_insert(0) += 1 );


    let n = arr.len() as f64;
    stats::chi_sq(
        freqs.iter()
            .map(|(i,o)| (*i, (*o as f64)/n))
            .collect(),
        english_expected_frequencies
        )
}

#[test]
fn test_english_inverse_probability() {
    let str_with_exact_frequencies: Vec<u8> = ENGLISH_EXPECTED_FREQUENCIES
        .iter()
        .map(|&(c, f)| vec![c as u8; f as usize] )
        .fold(Vec::new(), |mut acc, mut elt| {
            acc.append(&mut elt);
            acc
        });
    assert_eq!(0f64, english_inverse_probability(&str_with_exact_frequencies));
    assert_eq!(f64::MAX, english_inverse_probability(b"\0\0\0"));
}

pub fn attack_single_byte_xor_cipher(buf: &[u8]) -> u8 {
    (0..=u8::MAX)
        .map(|x| (x, english_inverse_probability(&base::byte_xor(&buf, x))) )
        .min_by(|(_, score_x), (_, score_y)| score_x.partial_cmp(score_y).unwrap() )
        .unwrap()
        .0
}

#[test]                                                                                                                             
fn test_attack_single_byte_xor_cipher() {                                                                                           
    let case: [u8; 34] = hex!("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");                              
    let expected = b"Cooking MC's like a pound of bacon";
    let result = base::byte_xor(&case, attack_single_byte_xor_cipher(&case));
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
        .map(|keysize| (keysize, base::normalised_hamming_distance(&buf[0..keysize], &buf[keysize..(2*keysize)])) )
        .collect();
    keysizes.sort_by(|&(_, score1), &(_, score2)| (&score1).partial_cmp(&score2).unwrap() );
    keysizes.iter()
        .map(|&(keysize, _)| keysize )
        .take(30)
        .map(|v| attack_repeating_key_xor_cipher_fixed_keysize(&buf, v) )
        .map(|k| (k.clone(), english_inverse_probability(&k)) ) // f64 does not implement Ord
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
