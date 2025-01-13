use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use crate::err::{XRCError, XRCResult};

#[cfg(target_pointer_width = "64")]
pub struct Cipher {
    cipher: Vec<usize>,
}

#[cfg(target_pointer_width = "64")]
impl Cipher {
    pub fn from(key: &str) -> XRCResult<Self> {
        Cipher::init(key.as_bytes().to_vec(), None)
    }

    pub fn from_bytes(key: &[u8]) -> XRCResult<Self> {
        Cipher::init(key.to_vec(), None)
    }

    pub fn from_seed(key: &[u8], seed: u64) -> XRCResult<Self> {
        Cipher::init(key.to_vec(), Some(seed))
    }

    fn init(key: Vec<u8>, seed: Option<u64>) -> XRCResult<Self> {
        if key.len() < 6 {
            return Err(XRCError::InvalidKeyLength);
        }
        let mut cipher = if let Some(seed) = seed {
            Cipher::x64_cipher_seed(key, seed)
        } else {
            Cipher::x64_cipher(key)
        };
        for i in 0..cipher.len() {
            cipher[i] = Cipher::generate_mask(cipher[i]);
        }
        Ok(Cipher { cipher })
    }

    pub fn get_cipher_byte(&self, i: usize) -> usize {
        self.cipher[i % self.cipher.len()]
    }

    pub fn get_cipher(&self) -> &[usize] {
        &self.cipher
    }

    fn generate_mask(v: usize) -> usize {
        let (mask, mut vt, mut shift) = (0x0101_0101_0101_0101usize, v, 8usize);
        let (mut bv, mut bz) = (0usize, 0x0808_0808_0808_0808usize);
        let mut bm: usize;
        while shift != 0 {
            bm = mask & vt;
            bv += bm;
            bz -= bm;
            vt >>= 1;
            shift -= 1;
        }
        ((bz << 4) | bv) ^ ((bv << 4) | bz) ^ v
    }

    fn x64_cipher(arr: Vec<u8>) -> Vec<usize> {
        let (rep, mut idx) = (
            {
                let (mut x, mut y) = (arr.len(), 8);
                while y != 0 {
                    let temp = y;
                    y = x % y;
                    x = temp;
                }
                (arr.len() / x) * 8
            },
            0usize,
        );
        let mut data = vec![0u8; rep];
        while idx != rep {
            data[idx] = arr[idx % arr.len()];
            idx += 1;
        }
        unsafe {
            let (_, cipher_64, _) = data.align_to::<usize>();
            cipher_64.to_vec()
        }
    }

    fn x64_cipher_seed(arr: Vec<u8>, seed: u64) -> Vec<usize> {
        let rep = {
            let (mut x, mut y) = (arr.len(), 8);
            while y != 0 {
                let temp = y;
                y = x % y;
                x = temp;
            }
            (arr.len() / x) * 8
        };

        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut data = vec![0u8; rep];
        for i in 0..rep {
            data[i] = arr[rng.gen_range(0..arr.len())];
        }
        unsafe {
            let (_, cipher_64, _) = data.align_to::<usize>();
            cipher_64.to_vec()
        }
    }
}
