//! Cipher and decipher using algorithm based on XOR bitwise operation
//!
//! # Usage
//!
//! For 64 bit CPU:
//! ```
//! use xor_cryptor::XORCryptor;
//!
//! fn main() {
//!     let sample_text = String::from("Hello World !");
//!     let key = String::from("secret_key");
//!     let buffer = sample_text.as_bytes().to_vec();
//!
//!     let res = XORCryptor::new(&key);
//!     if res.is_err() {
//!         return;
//!     }
//!     let xrc = res.unwrap();
//!
//!     let encrypted_buffer = xrc.encrypt_vec(buffer);
//!     let encrypted_string = String::from_utf8_lossy(&encrypted_buffer);
//!     println!("Encrypted: {}\n", encrypted_string);
//!
//!     // This encrypted string contains formatted non-utf8 characters
//!     // Do not use this string as vector to decrypt
//!     let decrypted_buffer = xrc.decrypt_vec(encrypted_string.as_bytes().to_vec());
//!     println!(
//!         "Decrypted from string : {:?}",
//!         String::from_utf8_lossy(&decrypted_buffer)
//!     );
//!
//!     let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
//!     println!(
//!         "Decrypted from vec    : {:?}",
//!         String::from_utf8_lossy(&decrypted_buffer)
//!     );
//! }
//! ```
//!
//! ## Output
//! ```shell
//! $ cargo run
//!   Compiling xor_cryptor v1.0.0 (XYZ)
//!    Finished dev [unoptimized + debuginfo] target(s) in 0.21s
//!     Running `target/debug/xor_cryptor.exe`
//!
//! Encrypted: W"♣'"�jMLQ�-
//!
//! Decrypted from string: "Hell:4u��D6S\u{c}\u{1e}��K"
//! Decrypted from vec   : "Hello World !"
//! ```

use std::{any::TypeId, mem};

#[cfg(target_pointer_width = "64")]
pub struct XORCryptor {
    cipher: cipher::Cipher,
    e_table: Vec<u64>,
    d_table: Vec<u64>,
}

#[cfg(target_pointer_width = "64")]
impl XORCryptor {
    /// Initialize with the key
    pub fn new(key: &String) -> Result<Self, &str> {
        let cipher = cipher::Cipher::from(key)?;
        let (mut e_table, mut d_table) = (vec![0u64; 256], vec![0u64; 0xF10]);
        XORCryptor::generate_table(&mut e_table, &mut d_table);
        Ok(XORCryptor {
            cipher,
            e_table,
            d_table,
        })
    }

    fn generate_table(e_table: &mut Vec<u64>, d_table: &mut Vec<u64>) {
        let (mut count, mut shift, mut value, mut bit_mask): (u16, u16, u16, u16);
        let (mut mask, mut mode) = (0u16, 0u16);

        for i in 0..=255 as u16 {
            (count, shift, value) = (4, 0, i);
            while count != 0 {
                bit_mask = value & 3;
                if bit_mask > 1 {
                    mask |= 1 << shift;
                }
                if bit_mask == 0 || bit_mask == 3 {
                    mode |= 1 << shift;
                }
                count -= 1;
                shift += 1;
                value >>= 2;
            }
            mask = (mode << 8) | mask;
            e_table[i as usize] = mask as u64;
            d_table[mask as usize] = i as u64;
            (mask, mode) = (0, 0);
        }
    }

    fn encrypt_bytes(&self, src: &mut Vec<u64>, b_len: usize) {
        let mut byte_count = b_len;
        for i in 0..src.len() {
            let (val, mut shift) = (src[i], 0u64);
            let (mut lxi, mut rxi) = (0u64, 0u64);
            while shift != 64 {
                if byte_count == 1 {
                    let mut mm = self.e_table[((val >> shift) & 0xFFu64) as usize];
                    mm = ((mm & 0xF00u64) >> 8) | ((mm & 0xFu64) << 4);
                    mm ^= mm >> 4;
                    rxi |= mm << shift;
                    break;
                }

                rxi |= self.e_table[((val >> shift) & 0xFFu64) as usize] << shift;
                lxi |= (self.e_table[(((val >> 8) >> shift) & 0xFFu64) as usize] << 4) << shift;
                shift += 16;
                byte_count -= 2;
                if byte_count == 0 {
                    break;
                }
            }
            lxi |= rxi;
            lxi = ((lxi & 0x00FF_00FF_00FF_00FFu64) << 8u64) ^ lxi;
            src[i] = lxi ^ self.cipher.get_cipher_byte(i);
            if byte_count == 0 {
                break;
            }
        }
    }

    fn decrypt_bytes(&self, src: &mut Vec<u64>, b_len: usize) {
        let mut byte_count = b_len;
        for i in 0..src.len() {
            src[i] ^= self.cipher.get_cipher_byte(i);
            let xi = ((src[i] & 0x00FF_00FF_00FF_00FFu64) << 8u64) ^ src[i];
            let (mut lxi, mut rxi, mut shift) = (0u64, 0u64, 0u64);
            while shift != 64 {
                if byte_count == 1 {
                    let mut mm = (xi >> shift) & 0xFF;
                    mm ^= mm >> 4;
                    mm = ((mm & 0xF0) >> 4) | ((mm & 0xF) << 8);
                    lxi |= self.d_table[mm as usize] << shift;
                    break;
                }
                lxi |= self.d_table[((xi >> shift) & 0x0F0Fu64) as usize] << shift;
                rxi |= (self.d_table[(((xi >> shift) & 0xF0F0u64) >> 4) as usize] << 8) << shift;
                shift += 16;
                byte_count -= 2;
                if byte_count == 0 {
                    break;
                }
            }
            src[i] = lxi | rxi;
            if byte_count == 0 {
                break;
            }
        }
    }

    /// Transmutes buffer from Vec<u8> to Vec<u64> and vice-versa
    fn transmute_buffer<T: Sized + 'static, R: Sized + 'static>(
        &self,
        buffer: Vec<T>,
        b_len: usize,
    ) -> Vec<R> {
        let (t, r) = (TypeId::of::<T>(), TypeId::of::<R>());
        let (t8, t64) = (TypeId::of::<u8>(), TypeId::of::<u64>());

        if (t != t8 || r != t64) && (t != t64 || r != t8) {
            return vec![];
        }

        let from_u8_u64 = t == t8 && r == t64;
        let length = if from_u8_u64 {
            if buffer.len() % 8 == 0 {
                buffer.len() / 8
            } else {
                (buffer.len() + 8) / 8
            }
        } else {
            buffer.len() * 8
        };

        let mut data: Vec<R>;
        // T and R are asserted to be either u8 or u64.
        // The length and capacity are calculated above based on
        // conversion of types.
        // Creating vector using interpreted ptr and desired length
        // will not crash.
        unsafe {
            let mutptr = buffer.as_ptr() as *mut R;
            mem::forget(buffer);
            data = Vec::from_raw_parts(mutptr, length, length)
        }
        if !from_u8_u64 && b_len != 0 {
            // Remove additional padding
            data.truncate(b_len);
        }
        data
    }

    /// Encrypts the vector
    pub fn encrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let mut src = self.transmute_buffer::<u8, u64>(buffer, 0);
        self.encrypt_bytes(&mut src, b_len);
        self.transmute_buffer(src, b_len)
    }

    /// Decrypts the vector
    pub fn decrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let mut src = self.transmute_buffer::<u8, u64>(buffer, 0);
        self.decrypt_bytes(&mut src, b_len);
        self.transmute_buffer(src, b_len)
    }

    pub fn get_cipher(&self) -> Vec<u64> {
        self.cipher.get_cipher()
    }
}

#[cfg(target_pointer_width = "64")]
mod cipher {
    pub struct Cipher {
        cipher_u64: Vec<u64>,
        cipher_len: usize,
    }

    #[cfg(target_pointer_width = "64")]
    impl Cipher {
        pub fn from(key: &String) -> Result<Self, &str> {
            if key.len() < 6 {
                return Err("Key length less than 6");
            }
            let (mut cipher_u64, cipher_len) = Cipher::x64_cipher(key.as_bytes().to_vec());
            for i in 0..cipher_len {
                cipher_u64[i] = Cipher::generate_mask(cipher_u64[i]);
            }
            Ok(Cipher {
                cipher_u64,
                cipher_len,
            })
        }

        pub fn get_cipher_byte(&self, i: usize) -> u64 {
            self.cipher_u64[i % self.cipher_len]
        }

        pub fn get_cipher(&self) -> Vec<u64> {
            self.cipher_u64.clone()
        }

        fn generate_mask(v: u64) -> u64 {
            let (mask, mut vt, mut shift) = (0x0101_0101_0101_0101u64, v, 8u64);
            let (mut bv, mut bz) = (0u64, 0x0808_0808_0808_0808u64);
            let mut bm: u64;
            while shift != 0 {
                bm = mask & vt;
                bv += bm;
                bz -= bm;
                vt >>= 1;
                shift -= 1;
            }
            ((bz << 4) | bv) ^ ((bv << 4) | bz) ^ v
        }

        fn x64_cipher(arr: Vec<u8>) -> (Vec<u64>, usize) {
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
            unsafe { (std::mem::transmute::<Vec<u8>, Vec<u64>>(data), rep / 8) }
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    fn lcm(a: usize) -> usize {
        let z = a.clone();
        let (mut x, mut y) = (a, 8);
        while y != 0 {
            let temp = y;
            y = x % y;
            x = temp;
        }
        (z / x) * 8
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check() {
        let sample_text = String::from("Hello World ! `1");
        let key = String::from("secret_k");

        assert_eq!(sample_text.len() % 8, 0);
        assert_eq!(key.len() % 8, 0);

        let buffer = sample_text.as_bytes().to_vec();
        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let buffer = xrc.encrypt_vec(buffer);
                let buffer = xrc.decrypt_vec(buffer);
                assert_eq!(xrc.get_cipher().len(), lcm(key.len()));
                assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check_padding() {
        let sample_text = String::from("Hello World ! `1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?");
        let key = String::from("secret_key");

        assert_ne!(sample_text.len() % 8, 0);
        assert_ne!(key.len() % 8, 0);

        let buffer = sample_text.as_bytes().to_vec();
        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let buffer = xrc.encrypt_vec(buffer);
                let buffer = xrc.decrypt_vec(buffer);
                assert_eq!(xrc.get_cipher().len(), lcm(key.len()));
                assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn benchmark() {
        let sample_text = String::from("Hello World !");
        let key = String::from("secret_key");

        // 128 MB * 13 chars = 1.6 GB
        const BENCH_SIZE: usize = 1024usize * 1024usize * 128usize;
        let text = sample_text.as_bytes().to_vec();

        let start = std::time::Instant::now();
        let mut buffer = Vec::<u8>::new();
        for _ in 0..BENCH_SIZE {
            for i in 0..text.len() {
                buffer.push(text[i]);
            }
        }
        println!("Allocate Buff - 1.6 GB: {} ms", start.elapsed().as_millis());

        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let start = std::time::Instant::now();
                let buffer = xrc.encrypt_vec(buffer);
                println!("Encrypted: {} ms", start.elapsed().as_millis());

                let start = std::time::Instant::now();
                let buffer = xrc.decrypt_vec(buffer);
                println!("Decrypted: {} ms", start.elapsed().as_millis());

                assert_eq!(xrc.get_cipher().len(), lcm(key.len()));
                assert_eq!(
                    sample_text,
                    String::from_utf8(buffer[0..sample_text.len()].to_vec()).unwrap()
                );
            }
            Err(err) => println!("Error {}", err),
        }
    }
}
