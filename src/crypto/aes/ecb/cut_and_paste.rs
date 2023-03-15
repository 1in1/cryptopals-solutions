use std::collections::HashMap;
use openssl::symm::{encrypt, decrypt, Cipher, Crypter, Mode};

use crate::util::Error;
use crate::util;
use crate::crypto::common::{
    generate_random_bytes, 
    pad_pkcs_7, 
    repeating_block, 
    round_up_to_nearest_multiple
};
use crate::crypto::aes::determine_block_size;
use crate::crypto::oracle::*;

#[derive(Debug, PartialEq)]
struct Profile {
    email: Vec<u8>,
    uid: Vec<u8>,
    role: Vec<u8>,
}

impl Profile {
    fn from_email(buf: &[u8]) -> Profile {
        let safe_buf = buf.iter()
            .map(|&x| x)
            .filter(|&x| !(x == b'=' || x == b'&'))
            .collect();
        Profile {
            email: safe_buf,
            uid: b"10".to_vec(),
            role: b"user".to_vec(),
        }
    }

    fn from_hashmap(hashmap: HashMap<Vec<u8>, Vec<u8>>) -> Result<Profile, Error> {
        Ok(Profile {
            email: hashmap
                .get(b"email".as_slice())
                .map(|x| x.clone())
                .ok_or(Error::ParseError {})?,
            uid: hashmap
                .get(b"uid".as_slice())
                .map(|x| x.clone())
                .ok_or(Error::ParseError {})?,
            role: hashmap
                .get(b"role".as_slice())
                .map(|x| x.clone())
                .ok_or(Error::ParseError {})?,
        })
    }

    fn encode(&self) -> Vec<u8> {
        [
            b"email=".to_vec(), self.email.clone(),
            b"&".to_vec(),
            b"uid=".to_vec(),   self.uid.clone(),
            b"&".to_vec(),
            b"role=".to_vec(),  self.role.clone(),
        ].concat()
            .to_vec()
    }    
}


// we have to assume role=admin goes at the end here...
pub fn attack_ecb_cut_and_paste(encode_and_encrypt: &dyn Oracle) -> Vec<u8> {
    let block_size = determine_block_size(&encode_and_encrypt);

    // Compute the number of dead bytes we need to pass before we get a new block, AND
    // are at a multiple of plaintext_len
    //let mut dead_bytes = Vec::new();
    //let initial_size = encode_and_encrypt(&dead_bytes).len();
    //while encode_and_encrypt(&dead_bytes).len() == initial_size { dead_bytes.push(b'A'); }
    //let left_padding_len = dead_bytes.len() - 1;
    let left_padding_len = block_size - b"email=".len();

    // Construct a malicous encrypted block
    // '&' and '=' are swallowed. But, we can construct a block which begins with 
    // "admin<padding>", and chose a username which will cause a block to finish at
    // "...&role="
    let plaintext = pad_pkcs_7(b"admin", block_size);
    let plaintext_len = plaintext.len();

    let payload = [
        vec![b'A'; left_padding_len], 
        plaintext.clone(),
        plaintext,
    ].concat();

    // Easiest to identify the _repeated block_
    let encrypted_payload = encode_and_encrypt(&payload);
    let (_, ciphertext) = repeating_block(&encrypted_payload, plaintext_len)
        .unwrap();

    let desired_user_prefix = b"evil123evil123evil123evil123000";
    let total_control_len = b"email=&uid=10&role=".len();
    let total_left_padding_len = 
        round_up_to_nearest_multiple(total_control_len, block_size)
        - total_control_len;
    let user_buffer_length = 
        total_left_padding_len
        + round_up_to_nearest_multiple(desired_user_prefix.len(), block_size)
        - desired_user_prefix.len();
    let payload_2 = [
        desired_user_prefix.to_vec(),
        vec![b'A'; user_buffer_length],
    ].concat();

    let encrypted_payload_2 = encode_and_encrypt(&payload_2);
    [
        encrypted_payload_2[0..(encrypted_payload_2.len() - ciphertext.len())]
            .to_vec(),
        ciphertext.to_vec()
    ].concat()
}

#[test]
fn test_attack_ecb_cut_and_paste() {
    let key: [u8; 16] = generate_random_bytes();
    let cipher = Cipher::aes_128_ecb();

    let encode_and_encrypt = move |buf: &[u8]| {
        let profile = Profile::from_email(buf);
        let encoded = profile.encode();
        encrypt(cipher, &key, None, &encoded).unwrap()
    };
   
    let expected_role_value = b"admin".as_slice();

    let encrypted_malicious_profile = attack_ecb_cut_and_paste(&encode_and_encrypt);
    let decrypted_malicious_profile = decrypt(cipher, &key, None, &encrypted_malicious_profile)
        .unwrap();
    let malicious_profile = util::key_equals_val_parse(&decrypted_malicious_profile)
        .unwrap();
    let malicious_profile_role = malicious_profile
        .get(b"role".as_slice())
        .unwrap();

    assert_eq!(expected_role_value, malicious_profile_role);
}
