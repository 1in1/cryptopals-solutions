use rand::{Rng, RngCore};
use std::collections::HashSet;
use std::collections::HashMap;

use crate::util::Error;
use crate::stats;


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
pub fn english_inverse_probability(arr: &[u8]) -> f64 {
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

pub fn hamming_distance(buf1: &[u8], buf2: &[u8]) -> u32 {
    assert_eq!(buf1.len(), buf2.len());
    buf1.iter()
        .zip(buf2.iter())
        .map(|(x,y)| x ^ y )
        .map(|z| z.count_ones() )
        .sum()
}

#[test]
fn test_hamming_distance() {
    let s1: String = "this is a test".to_string();
    let s2: String = "wokka wokka!!!".to_string();
    let dist = hamming_distance(&s1.as_bytes(), &s2.as_bytes());
    assert_eq!(dist, 37);
}

pub fn normalised_hamming_distance(buf1: &[u8], buf2: &[u8]) -> f64 {
    (hamming_distance(buf1, buf2) as f64) / (buf1.len() as f64)
}

pub fn repeating_block(arr: &[u8], size: usize) -> Option<(usize, Vec<u8>)> {
    let mut blocks: HashSet<&[u8]> = HashSet::new();
    for (idx, block) in arr.chunks(size).enumerate() {
        if blocks.contains(block) {
            return Some((idx, block.to_vec()));
        }
        blocks.insert(block);
    }
    return None;
}

#[test]
fn test_repeating_block() {
    let arr = b"aaabbbcccaaa";
    assert_eq!(Some((3, b"aaa".to_vec())), repeating_block(arr, 3));
    assert_eq!(None,                       repeating_block(arr, 4));
}

pub fn round_up_to_nearest_multiple(n: usize, m: usize) -> usize {
    m*( (n + (m-1)) / m )
}

// TODO: Could happily make this generic and return a fixed-width array
// We pad with a whole block of 0u8 when already a multiple, to ensure
// we can decode
pub fn pad_pkcs_7(buf: &[u8], block_size: usize) -> Vec<u8> {
    let n = buf.len() % block_size;
    let padding_length = block_size - n;
    let padding_value = 
        if n == 0 { 0u8 }
        else      { padding_length as u8 };
    [buf, &vec![padding_value; padding_length]].concat()
}

#[test]
fn test_pad_pkcs_7() {
    let case = b"YELLOW SUBMARINE";
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04".to_vec();
    let result = pad_pkcs_7(case, 20);
    assert_eq!(expected, result);

    let expected_2 = [
        case.to_vec(),
        vec![0; 16],
    ].concat();
    let result_2 = pad_pkcs_7(case, case.len());
    assert_eq!(expected_2, result_2);
}

// Sometimes, we do NOT want to pad if we are already at size. E.g., for padding
// a key or IV. In these cases, simply return the value
pub fn pad_pkcs_7_if_required(buf: &[u8], block_size: usize) -> Vec<u8> {
    if buf.len() % block_size == 0 { buf.to_vec() }
    else { pad_pkcs_7(buf, block_size) }
}

pub fn strip_pad_pkcs_7(buf: &[u8], block_size: usize) -> Result<Vec<u8>, Error> {
    let &final_byte = buf.last().unwrap();
    let padding_len: usize =
        if final_byte == 0 { block_size }
        else               { final_byte as usize };
    let unpadded_len = buf.len() - padding_len;
    let mut out = buf.to_vec();
    if buf.len() % block_size != 0
        || !buf.iter()
                .rev()
                .take(padding_len)
                .all(|b|  b == &final_byte ) {
        return Err(Error::ParseError {});
    }
    out.truncate(unpadded_len);
    Ok(out)
}

#[test]
fn test_strip_pad_pkcs_7() {
    let case = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    let expected = b"YELLOW SUBMARINE".to_vec();
    let result = strip_pad_pkcs_7(case, 20);
    assert_eq!(Ok(expected.clone()), result);

    let result_2 = strip_pad_pkcs_7(case, 16);
    assert_eq!(Err(Error::ParseError {}), result_2);

    let case_3 = [b"YELLOW SUBMARINE", vec![0; 16].as_slice()].concat();
    let result_3 = strip_pad_pkcs_7(&case_3, 16);
    assert_eq!(Ok(expected), result_3);

    // Cases from Challenge 15
    let case_4 = b"ICE ICE BABY\x04\x04\x04\x04";
    let expected_4 = b"ICE ICE BABY".to_vec();
    let result_4 = strip_pad_pkcs_7(case_4, case_4.len());
    assert_eq!(Ok(expected_4), result_4);

    let case_5 = b"ICE ICE BABY\x05\x05\x05\x05";
    let result_5 = strip_pad_pkcs_7(case_5, case_5.len());
    assert_eq!(Err(Error::ParseError {}), result_5); 

    let case_6 = b"ICE ICE BABY\x05\x05\x05\x05";
    let result_6 = strip_pad_pkcs_7(case_6, case_6.len());
    assert_eq!(Err(Error::ParseError {}), result_6);
}

pub fn generate_random_bytes<const N: usize>() -> [u8; N] {
    let mut data = [0u8; N];
    rand::thread_rng().fill_bytes(&mut data);
    data
}
