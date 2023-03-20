pub mod attack;

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
    //assert!(m <= n);
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
