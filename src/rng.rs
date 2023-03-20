use std::num::Wrapping;

pub struct MTRng<
    const W: usize, const N: usize, const M: usize, const R: usize,
    const A: u64,
    const U: u64, const D: u64,
    const S: u64, const B: u64,
    const T: u64, const C: u64,
    const L: u64,
    const F: u64
> {
    mt: [u64; N],
    idx: usize,
    lower_mask: u64,
    upper_mask: u64,
}

impl<
    const W: usize, const N: usize, const M: usize, const R: usize,
    const A: u64,
    const U: u64, const D: u64,
    const S: u64, const B: u64,
    const T: u64, const C: u64,
    const L: u64,
    const F: u64
> MTRng<
    W, N, M, R, 
    A,
    U, D, 
    S, B,
    T, C,
    L,
    F
> {
    pub fn build_seeded(seed: u64) -> Self {
        let idx = N;
        let lower_mask = (1 << R) - 1;
        let upper_mask = (u64::MAX >> (64 - (W-R))) << (64 - (W-R));
        let mut mt = [0u64; N];
        mt[0] = seed;
        let lowest_w_bitmask = 
            if W == 64 { u64::MAX }
            else { (1 << W) - 1 };
        for i in 1..N {
            mt[i] = lowest_w_bitmask & (Wrapping(F) * Wrapping((mt[i-1] ^ (mt[i-1] >> (W-2))) + (i as u64))).0;
        }
        //println!("{:?}", mt);

        Self {
            mt: mt,
            idx: idx,
            lower_mask: lower_mask,
            upper_mask: upper_mask,
        }
    }

    pub fn next(&mut self) -> u64 {
        if self.idx >= N {
            assert!(self.idx == N);
            self.twist();
        }

        let mut y: u64 = self.mt[self.idx];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        let lowest_w_bitmask = 
            if W == 64 { u64::MAX }
            else { (1 << W) - 1 };
        self.idx = self.idx + 1;
        y & lowest_w_bitmask
    }

    fn twist(&mut self) {
        for i in 0..N {
            let x = (self.mt[i] & self.upper_mask) | (self.mt[(i+1) % N] & self.lower_mask);
            let mut xA = x >> 1;
            if (x % 2) != 0 { 
                xA = xA ^ A;
            }
            self.mt[i] = self.mt[(i+M) % N] ^ xA;
        }
        self.idx = 0;
    }
}

pub fn get_mt19937(seed: u64) 
-> MTRng::<
    32, 624, 397, 31,
    0x9908b0df,
    11, 0xffffffff,
    7, 0x9d2c5680,
    15, 0xefc60000,
    18,
    1812433253
    >
{
    MTRng::build_seeded(seed)
}

pub fn get_mt19937_64(seed: u64) 
-> MTRng::<
    64, 312, 156, 31,
    0xb5026f5aa96619e9,
    29, 0x5555555555555555,
    17, 0x71d67fffeda60000,
    37, 0xfff7eee000000000,
    43,
    6364136223846793005
    >
{
    MTRng::build_seeded(seed)
}

#[test]
fn test_mt19937_64() {
    let mut rng = get_mt19937_64(1);
    println!("{:x?}", rng.upper_mask.to_ne_bytes());
    for _ in 0..100 {
        println!("{}", rng.next());
    }
}

#[test]
fn test_mt19937_32() {
    let mut rng = get_mt19937(1);
    println!("{:x?}", rng.upper_mask.to_ne_bytes());
    for _ in 0..100 {
        println!("{}", rng.next());
    }
}
