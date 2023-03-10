use std::collections::HashSet;

pub fn fixed_xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    assert_eq!(buf1.len(), buf2.len());
    buf1.iter()
        .zip(buf2.iter())
        .map(|(x,y)| x ^ y)
        .collect()
}

#[test]
fn test_fixed_xor() {                                                                                                               
    let case_buf1 = hex!("1c0111001f010100061a024b53535009181c");                                                                   
    let case_buf2 = hex!("686974207468652062756c6c277320657965");                                                                   
    let expected = hex!("746865206b696420646f6e277420706c6179");                                                                    
    let result = fixed_xor(&case_buf1, &case_buf2);                                                                                 
    assert_eq!(result, expected);                                                                                                   
}                                                                                                                                   

pub fn byte_xor(buf: &[u8], b: u8) -> Vec<u8> {
    buf.iter()
        .map(|x| x ^ b )
        .collect()
}

pub fn repeating_key_xor(buf1: &[u8], buf2: &[u8]) -> Vec<u8> {
    let n = buf1.len();
    let m = buf2.len();
    assert!(m <= n);
    let mut out = Vec::with_capacity(n);
    for i in 0..(n-1) {
        out.push(buf1[i] ^ buf2[i % m]);
    }
    out
}

#[test]
fn test_repeating_key_xor() {
    let case = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\n";
    let key = b"ICE";
    let encoded = repeating_key_xor(case, key);
    let expected = hex!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
    assert_eq!(encoded, expected);
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

pub fn repeating_block(arr: &[u8], size: usize) -> Option<Vec<u8>> {
    let mut blocks: HashSet<&[u8]> = HashSet::new();
    for block in arr.chunks(size) {
        if blocks.contains(block) {
            return Some(block.to_vec());
        }
        blocks.insert(block);
    }
    return None;
}

#[test]
fn test_repeating_block() {
    let arr = b"aaabbbcccaaa";
    assert_eq!(Some(b"aaa".to_vec()), repeating_block(arr, 3));
    assert_eq!(None,                  repeating_block(arr, 4));
}

#[test]
fn test_detect_aes_128_ecb() {
    let contents = std::fs::read_to_string("./data/8.txt")
        .expect("Should have been able to read the file");
    let expected = b"d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";
    let results: Vec<&str> = contents
        .split("\n")
        .filter(|s| repeating_block(&s.as_bytes(), 32).is_some() )
        .collect();
    assert_eq!(1, results.len());
    assert_eq!(expected, results[0].as_bytes());
}
