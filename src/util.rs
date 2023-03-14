use base64::{Engine as _, engine::general_purpose};
use hex::FromHexError;
use snafu::prelude::*;
use std::collections::HashMap;

pub(crate) fn transpose<T>(original: &[&[T]]) -> Vec<Vec<T>> where T: Clone {
    assert!(!original.is_empty());
    let mut transposed = (0..original[0].len()).map(|_| vec![]).collect::<Vec<_>>();

    for original_row in original {
        for (item, transposed_row) in original_row.into_iter().zip(&mut transposed) {
            transposed_row.push(item.clone());
        }
    }

    transposed
}

#[test]
fn test_transpose() {
    let v1 = vec![1, 2];
    let v2 = vec![3, 4];
    let v3 = vec![5, 6];
    let blocks = vec![v1.as_slice(), v2.as_slice(), v3.as_slice()];
    let transposed = transpose(blocks.as_slice());
    assert_eq!(transposed.len(), 2);
    assert_eq!(transposed[0], vec![1, 3, 5]);
    assert_eq!(transposed[1], vec![2, 4, 6]);
}

pub fn hex_to_b64(input: String) -> Result<String, FromHexError> {
    hex::decode(input)
        .and_then(|b| Ok(general_purpose::STANDARD.encode(&b)) )
}

#[test]
fn test_hex_to_b64() {
    let case = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");    
    let expected = Ok(String::from("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"));
    let result = hex_to_b64(case);                                                                                                  
    assert_eq!(result, expected);                                                                                                   
}                                                                                                                                   

#[derive(Debug, PartialEq, Snafu)]
pub enum Error {
    #[snafu(display("Something fucked up"))]
    CryptoError {},

    #[snafu(display("Something fucked up"))]
    ParseError {},
}

pub(crate) fn key_equals_val_parse(buf: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, Error> {
    let pairs: Vec<Vec<u8>> = buf.iter()
        .fold(Vec::new(), |mut acc, &x| {
            if x == b'&' {
                acc.push(Vec::new());
                return acc
            }
            if acc.is_empty() {
                acc.push(Vec::new());
            }
            acc.last_mut()
                .unwrap()
                .push(x);
            acc
        });
    let hashmap: HashMap<Vec<u8>, Vec<u8>> = pairs.into_iter()
        .map(|v| {
            // `unwrap` forces us to find
            let loc = v.iter()
                .position(|&x| x == b'=')
                .unwrap_or(v.len());
            let (key_slice, value_slice) = v.split_at(loc);
            let key = key_slice.to_vec();
            let value = 
                if value_slice.len() > 0 {
                    value_slice[1..].to_vec()
                } else {
                    Vec::new()
                };
            (key, value)
        }).collect();
    
    if hashmap.iter()
        .any(|(_,v)| {
            v.is_empty() || v.iter().any(|&x| x == b'=')
        }) {
        return Err(Error::ParseError {});
    } else {
        return Ok(hashmap);
    }
}

#[test]
fn test_key_equals_val_parse() {
    let case = b"foo=bar&baz=qux&zap=zazzle";
    let expected = HashMap::from([
        (b"foo".to_vec(), b"bar".to_vec()),
        (b"baz".to_vec(), b"qux".to_vec()),
        (b"zap".to_vec(), b"zazzle".to_vec())
    ]);
    let result = key_equals_val_parse(case).unwrap();
    assert_eq!(expected, result);

    let invalid_case_1 = b"foo=bar&baz=qux&zap=zaz=zle";
    let invalid_case_2 = b"foo=bar&baz=qux&zap=zaz&zle";
    assert_eq!(Error::ParseError {}, key_equals_val_parse(invalid_case_1).unwrap_err());
    assert_eq!(Error::ParseError {}, key_equals_val_parse(invalid_case_2).unwrap_err());
}
