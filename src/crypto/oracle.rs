use openssl::symm::{encrypt, Cipher};
use rand::Rng;

use crate::crypto::common::{generate_random_bytes, pad_pkcs_7};
use crate::crypto::aes::cbc::aes_cbc_encrypt;

pub trait Oracle: Fn(&[u8]) -> Vec<u8> {}
impl<T: Fn(&[u8]) -> Vec<u8>> Oracle for T {}

pub fn get_id_oracle() -> Box<dyn Oracle> {
    Box::new(move |buf: &[u8]| {
        buf.to_vec()
    })
}

pub fn choose_random<'a>(f: impl Oracle + 'a, g: impl Oracle + 'a) -> (bool, impl Oracle + 'a) {
    let mut rng = rand::thread_rng();
    let choose_f: bool = rng.gen();
    (choose_f, move |buf: &[u8]| {
        match choose_f {
            true  => f(buf),
            false => g(buf),
        }
    })
}

impl dyn Oracle {
    pub fn pullback_add_left_padding(self: Box<dyn Oracle>, lpad: &[u8]) -> Box<dyn Oracle> {
        let owned_lpad = lpad.to_owned();
        Box::new(move |buf: &[u8]| {
            let joined = [
                &owned_lpad,
                buf,
            ].concat();
            self(&joined)
        })
    }

    pub fn pullback_add_right_padding(self: Box<dyn Oracle>, rpad: &[u8]) -> Box<dyn Oracle> {
        let owned_rpad = rpad.to_owned();
        Box::new(move |buf: &[u8]| {
            let joined = [
                buf,
                &owned_rpad,
            ].concat();
            self(&joined)
        })
    }

    pub fn pullback_add_random_left_padding<const MIN: usize, const MAX: usize>(self: Box<dyn Oracle>) -> Box<dyn Oracle> {
        let mut rng = rand::thread_rng();
        let padding: [u8; MAX] = generate_random_bytes();
        let pad_len: usize = rng.gen_range(MIN..=MAX);
        self.pullback_add_left_padding(&padding[0..pad_len])
    }

    pub fn pullback_add_random_right_padding<const MIN: usize, const MAX: usize>(self: Box<dyn Oracle>) -> Box<dyn Oracle> {
        let mut rng = rand::thread_rng();
        let padding: [u8; MAX] = generate_random_bytes();
        let pad_len: usize = rng.gen_range(MIN..=MAX);
        self.pullback_add_right_padding(&padding[0..pad_len])
    }

    pub fn pushforward_ecb_encrypt_fixed_key(self: Box<dyn Oracle>) -> Box<dyn Oracle> {
        let cipher = Cipher::aes_128_ecb();
        let key: [u8; 16] = generate_random_bytes();
        Box::new(move |buf: &[u8]| {
            let plaintext = self(buf);
            encrypt(cipher, &key, None, &plaintext)
                .unwrap()
                .to_vec()
        })
    }
    
    pub fn pushforward_cbc_encrypt_fixed_key(self: Box<dyn Oracle>) -> Box<dyn Oracle> {
        let key: [u8; 16] = generate_random_bytes();
        let iv: [u8; 16] = generate_random_bytes();
        Box::new(move |buf: &[u8]| {
            let plaintext = self(buf);
            aes_cbc_encrypt(&plaintext, &key, &iv)
                .unwrap()
                .to_vec()
        })
    }

    pub fn pushforward_pkcs_7(self: Box<dyn Oracle>, block_size: usize) -> Box<dyn Oracle> {
        Box::new(move |buf: &[u8]| {
            let out = self(buf);
            pad_pkcs_7(&out, block_size).to_vec()
        })
    }
}
