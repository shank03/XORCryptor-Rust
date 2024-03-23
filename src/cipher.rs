#[cfg(target_pointer_width = "64")]
pub struct Cipher {
    cipher: Vec<usize>,
    cipher_len: usize,
}

#[cfg(target_pointer_width = "64")]
impl Cipher {
    pub fn from(key: &String) -> Result<Self, &str> {
        Cipher::init(key.as_bytes().to_vec())
    }

    pub fn from_bytes(key: &[u8]) -> Result<Self, &'static str> {
        Cipher::init(key.to_vec())
    }

    fn init(key: Vec<u8>) -> Result<Self, &'static str> {
        if key.len() < 6 {
            return Err("Key length less than 6");
        }
        let (mut cipher, cipher_len) = Cipher::x64_cipher(key);
        for i in 0..cipher_len {
            cipher[i] = Cipher::generate_mask(cipher[i]);
        }
        Ok(Cipher { cipher, cipher_len })
    }

    pub fn get_cipher_byte(&self, i: usize) -> usize {
        self.cipher[i % self.cipher_len]
    }

    pub fn get_cipher(&self) -> Vec<usize> {
        self.cipher.clone()
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

    fn x64_cipher(arr: Vec<u8>) -> (Vec<usize>, usize) {
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
            (cipher_64.to_vec(), rep / 8)
        }
    }
}
