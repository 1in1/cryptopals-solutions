use base64::{Engine as _, engine::general_purpose};
use hex::FromHexError;

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
