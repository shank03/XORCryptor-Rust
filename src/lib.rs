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

use rayon::iter::{IntoParallelIterator, ParallelIterator};

#[cfg(target_pointer_width = "64")]
pub struct XORCryptor {
    cipher: cipher::Cipher,
    e_table: Vec<usize>,
    d_table: Vec<usize>,
}

#[cfg(target_pointer_width = "64")]
impl XORCryptor {
    /// Initialize with the key
    pub fn new(key: &String) -> Result<Self, &str> {
        let cipher = cipher::Cipher::from(key)?;
        let (mut e_table, mut d_table) = (vec![0usize; 256], vec![0usize; 0xF10]);
        XORCryptor::generate_table(&mut e_table, &mut d_table);
        Ok(XORCryptor {
            cipher,
            e_table,
            d_table,
        })
    }

    fn generate_table(e_table: &mut Vec<usize>, d_table: &mut Vec<usize>) {
        let (mut count, mut shift, mut value, mut bit_mask): (u16, u16, u16, u16);
        let (mut mask, mut mode) = (0u16, 0u16);

        for i in 0..=255 as u16 {
            (count, shift, value) = (4, 0, i);
            while count != 0 {
                bit_mask = value & 3;
                let mask_shift: u16 = (bit_mask > 1).into();
                let mode_shift: u16 = (bit_mask == 0 || bit_mask == 3).into();
                mask |= mask_shift << shift;
                mode |= mode_shift << shift;

                count -= 1;
                shift += 1;
                value >>= 2;
            }
            mask = (mode << 8) | mask;
            e_table[i as usize] = mask as usize;
            d_table[mask as usize] = i as usize;
            (mask, mode) = (0, 0);
        }
    }

    fn encrypt_bytes(&self, src: &mut Vec<usize>, b_len: usize) {
        let mut byte_count = b_len;
        let odd = b_len % 8 != 0;
        let length = src.len() - if odd { 1 } else { 0 };
        let src_ptr = Ptr(src.as_mut_ptr());

        byte_count -= 8 * length;

        (0..length).into_par_iter().for_each(move |i| unsafe {
            let val = *{ src_ptr }.0.add(i);
            let mut lxi = self.e_table[val & 0xFF]
                | self.e_table[(val >> 0x8) & 0xFF] << 0x4
                | self.e_table[(val >> 0x10) & 0xFF] << 0x10
                | self.e_table[(val >> 0x18) & 0xFF] << 0x14
                | self.e_table[(val >> 0x20) & 0xFF] << 0x20
                | self.e_table[(val >> 0x28) & 0xFF] << 0x24
                | self.e_table[(val >> 0x30) & 0xFF] << 0x30
                | self.e_table[(val >> 0x38) & 0xFF] << 0x34;

            lxi = ((lxi & 0x00FF_00FF_00FF_00FF) << 8) ^ lxi;
            *{ src_ptr }.0.add(i) = lxi ^ self.cipher.get_cipher_byte(i);
        });

        if odd {
            let (val, mut shift) = (src[length], 0usize);
            let mut lxi = 0usize;
            while byte_count > 1 {
                lxi |= self.e_table[(val >> shift) & 0xFF] << shift
                    | (self.e_table[((val >> 8) >> shift) & 0xFF] << 4) << shift;
                shift += 16;
                byte_count -= 2;
            }
            let mut mm = self.e_table[(val >> shift) & 0xFF];
            mm = ((mm & 0xF00) >> 8) | ((mm & 0xF) << 4);
            mm ^= mm >> 4;
            lxi |= mm << shift;
            lxi = ((lxi & 0x00FF_00FF_00FF_00FF) << 8) ^ lxi;
            src[length] = lxi ^ self.cipher.get_cipher_byte(length);
        }
    }

    fn decrypt_bytes(&self, src: &mut Vec<usize>, b_len: usize) {
        let mut byte_count = b_len;
        let odd = b_len % 8 != 0;
        let length = src.len() - if odd { 1 } else { 0 };
        let src_ptr = Ptr(src.as_mut_ptr());

        byte_count -= 8 * length;

        (0..length).into_par_iter().for_each(move |i| unsafe {
            *{ src_ptr }.0.add(i) ^= self.cipher.get_cipher_byte(i);
            let val = *{ src_ptr }.0.add(i);
            let xi = ((val & 0x00FF_00FF_00FF_00FF) << 8) ^ val;

            *{ src_ptr }.0.add(i) = self.d_table[xi & 0x0F0F]
                | self.d_table[(xi >> 0x4) & 0x0F0F] << 0x8
                | self.d_table[(xi >> 0x10) & 0x0F0F] << 0x10
                | self.d_table[(xi >> 0x14) & 0x0F0F] << 0x18
                | self.d_table[(xi >> 0x20) & 0x0F0F] << 0x20
                | self.d_table[(xi >> 0x24) & 0x0F0F] << 0x28
                | self.d_table[(xi >> 0x30) & 0x0F0F] << 0x30
                | self.d_table[(xi >> 0x34) & 0x0F0F] << 0x38;
        });

        if odd {
            src[length] ^= self.cipher.get_cipher_byte(length);
            let xi = ((src[length] & 0x00FF_00FF_00FF_00FF) << 8) ^ src[length];
            let (mut lxi, mut shift) = (0usize, 0usize);
            while byte_count > 1 {
                lxi |= self.d_table[(xi >> shift) & 0x0F0F] << shift
                    | self.d_table[(xi >> shift >> 4) & 0x0F0F] << 8 << shift;
                shift += 0x10;
                byte_count -= 2;
            }
            let mut mm = (xi >> shift) & 0xFF;
            mm ^= mm >> 4;
            mm = ((mm & 0xF0) >> 4) | ((mm & 0xF) << 8);
            lxi |= self.d_table[mm] << shift;
            src[length] = lxi;
        }
    }

    /// Transmutes buffer from Vec<u8> to Vec<usize> and vice-versa
    fn transmute_buffer<T, R>(&self, buffer: Vec<T>, b_len: usize, default: T) -> Vec<R>
    where
        T: Sized + Clone + 'static,
        R: Sized + 'static,
    {
        let (t, r) = (TypeId::of::<T>(), TypeId::of::<R>());
        let (t8, t_usize) = (TypeId::of::<u8>(), TypeId::of::<usize>());

        if (t != t8 || r != t_usize) && (t != t_usize || r != t8) {
            return vec![];
        }

        let from_u8_usize = t == t8 && r == t_usize;
        let len = buffer.len();
        let (upper, rem) = (len + 8, len % 8);
        let rem_a = upper % 8;

        let length = if from_u8_usize {
            let rz: usize = (rem == 0).into();
            ((len * rz) + (upper * (1 - rz))) / 8
        } else {
            len * 8
        };

        let mut buffer = buffer;
        if from_u8_usize {
            buffer.resize(
                buffer.len() + if rem == 0 { 0 } else { (upper) - rem_a - len },
                default,
            );
        }

        let mut data: Vec<R>;
        // T and R are asserted to be either u8 or usize.
        // The length and capacity are calculated and padded above
        // based on conversion of types.
        // Creating vector using interpreted ptr and desired length
        // will not crash.
        unsafe {
            let mutptr = buffer.as_ptr() as *mut R;
            mem::forget(buffer);
            data = Vec::from_raw_parts(mutptr, length, length)
        }
        if !from_u8_usize && b_len != 0 {
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
        let mut src = self.transmute_buffer::<u8, usize>(buffer, 0, 0);
        self.encrypt_bytes(&mut src, b_len);
        self.transmute_buffer(src, b_len, 0)
    }

    /// Decrypts the vector
    pub fn decrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let mut src = self.transmute_buffer::<u8, usize>(buffer, 0, 0);
        self.decrypt_bytes(&mut src, b_len);
        self.transmute_buffer(src, b_len, 0)
    }

    pub fn get_cipher(&self) -> Vec<usize> {
        self.cipher.get_cipher()
    }
}

#[derive(Copy, Clone)]
struct Ptr<T>(*mut T);
unsafe impl<T> Send for Ptr<T> {}
unsafe impl<T> Sync for Ptr<T> {}

#[cfg(target_pointer_width = "64")]
mod cipher {
    pub struct Cipher {
        cipher: Vec<usize>,
        cipher_len: usize,
    }

    #[cfg(target_pointer_width = "64")]
    impl Cipher {
        pub fn from(key: &String) -> Result<Self, &str> {
            if key.len() < 6 {
                return Err("Key length less than 6");
            }
            let (mut cipher, cipher_len) = Cipher::x64_cipher(key.as_bytes().to_vec());
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
    fn test_vectors() {
        let sample_text = String::from(
            "4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e0a",
        );
        let key = String::from("01020304050607080");

        let plain_text_vector = sample_text.as_bytes().to_vec();

        let cipher_text_vector = vec![
            0x20, 0x3e, 0x21, 0x0d, 0x21, 0x8b, 0x31, 0xdb, 0x31, 0x6c, 0x31, 0x8d, 0x11, 0xf8,
            0x31, 0xe6, 0x21, 0xdc, 0x12, 0xfc, 0x11, 0x2d, 0x76, 0xcf, 0x17, 0xed, 0x60, 0x2d,
            0x63, 0x1d, 0x04, 0x2d, 0x0b, 0xcc, 0x31, 0xec, 0x21, 0xfc, 0x11, 0x9a, 0x31, 0xca,
            0x31, 0x8e, 0x31, 0x9f, 0x31, 0x08, 0x31, 0xd7, 0x31, 0xec, 0x02, 0x1f, 0x11, 0xcf,
            0x66, 0xdd, 0x07, 0x2d, 0x70, 0x3d, 0x63, 0xdc, 0x14, 0xfd, 0x0b, 0xdd, 0x31, 0xcf,
            0x31, 0xdd, 0x31, 0xab, 0x31, 0xda, 0x21, 0x8d, 0x31, 0x8d, 0x31, 0xf8, 0x31, 0xc7,
            0x11, 0xdd, 0x12, 0xcc, 0x31, 0xdd, 0x66, 0xdc, 0x07, 0xdd, 0x50, 0xdd, 0x73, 0x3d,
            0x04, 0xfd, 0x1b, 0xcf, 0x31, 0xde, 0x21, 0x3d, 0x11, 0x9a, 0x31, 0xca, 0x21, 0x5e,
            0x31, 0x8d, 0x21, 0xf9, 0x31, 0xd7, 0x31, 0xed, 0x12, 0xcf, 0x11, 0xed, 0x66, 0x2d,
            0x17, 0xcf, 0x70, 0xfd, 0x53, 0xdd, 0x14, 0xfc, 0x0b, 0xdc, 0x31, 0x0e, 0x21, 0x0d,
            0x31, 0xaa, 0x31, 0xe9, 0x31, 0xad, 0x31, 0xbf, 0x31, 0x08, 0x31, 0xe6, 0x21, 0x2d,
            0x02, 0xcc, 0x11, 0xcf, 0x56, 0xdd, 0x17, 0x3d, 0x60, 0xdd, 0x53, 0xdd, 0x14, 0xed,
            0x3b, 0xdd, 0x31, 0xce, 0x31, 0xdc, 0x31, 0x7a, 0x31, 0xca, 0x31, 0x8e, 0x31, 0xbe,
            0x31, 0xc9, 0x31, 0xe5, 0x21, 0x1d, 0x12, 0xdd, 0x01, 0xcd, 0x66, 0x2d, 0x07, 0xcc,
            0x70, 0xfd, 0x73, 0xcf, 0x14, 0xfd, 0x1b, 0xec, 0x31, 0xec, 0x31, 0xcd, 0x21, 0x6a,
            0x21, 0x3b, 0x21, 0x6c, 0x21, 0x8e, 0x31, 0xd8, 0x31, 0xe5, 0x31, 0x2d, 0x12, 0xdd,
            0x01, 0xfd, 0x76, 0x3d, 0x17, 0xdd, 0x70, 0xcf, 0x73, 0xdd, 0x04, 0x1d, 0x3b, 0xdd,
            0x31, 0xff, 0x31, 0xdc, 0x31, 0x9a, 0x31, 0x19, 0x30, 0x5e,
        ];

        let key_vector: Vec<usize> = vec![
            0x5274337454745774,
            0x5e74517436743574,
            0x7433745474577474,
            0x7451743674357452,
            0x337454745774745e,
            0x5174367435745274,
            0x7454745774745e74,
            0x7436743574527433,
            0x54745774745e7451,
            0x3674357452743374,
            0x745774745e745174,
            0x7435745274337454,
            0x5774745e74517436,
            0x3574527433745474,
            0x74745e7451743674,
            0x7452743374547457,
            0x745e745174367435,
        ];

        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let encrypted_vector = xrc.encrypt_vec(plain_text_vector.clone());
                assert_eq!(cipher_text_vector, encrypted_vector);
                let decrypted_vector = xrc.decrypt_vec(encrypted_vector.clone());
                assert_eq!(plain_text_vector, decrypted_vector);
                assert_ne!(plain_text_vector, encrypted_vector);
                assert_eq!(key_vector, xrc.get_cipher());
            }
            Err(err) => println!("Error {}", err),
        }
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
                assert_eq!(xrc.get_cipher().len() * 8, lcm(key.len()));
                assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check_padding() {
        let mut sample_text = String::from("Hello World ! `1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?#2f");
        let key = String::from("secret_key");

        while sample_text.len() % 8 != 0 {
            assert_ne!(sample_text.len() % 8, 0);
            assert_ne!(key.len() % 8, 0);

            let buffer = sample_text.as_bytes().to_vec();
            let xrc = XORCryptor::new(&key);
            match xrc {
                Ok(xrc) => {
                    let buffer = xrc.encrypt_vec(buffer);
                    let buffer = xrc.decrypt_vec(buffer);
                    assert_eq!(xrc.get_cipher().len() * 8, lcm(key.len()));
                    assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
                }
                Err(err) => println!("Error [{}] {}", sample_text.len(), err),
            }
            sample_text.pop();
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn benchmark() {
        let sample_text = String::from("Hello World !");
        let key = String::from("secret_key");

        // 128 MB * 13 chars = 1.6 GB
        const BENCH_SIZE: usize = 1024usize * 1024usize * 128usize;
        const GB_SIZE: f64 = BENCH_SIZE as f64 * 13f64 / 1024f64 / 1024f64 / 1024f64;
        let text = sample_text.as_bytes().to_vec();

        let start = std::time::Instant::now();
        let mut buffer = Vec::<u8>::new();
        for _ in 0..BENCH_SIZE {
            for i in 0..text.len() {
                buffer.push(text[i]);
            }
        }
        println!(
            "Allocate Buff - {:.2} GB: {} ms",
            GB_SIZE,
            start.elapsed().as_millis()
        );

        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let start = std::time::Instant::now();
                let buffer = xrc.encrypt_vec(buffer);
                let elapsed = start.elapsed().as_millis();
                println!(
                    "Encrypted: {} ms - {:.2} GBps",
                    elapsed,
                    GB_SIZE / elapsed as f64 * 1000f64
                );

                let start = std::time::Instant::now();
                let buffer = xrc.decrypt_vec(buffer);
                let elapsed = start.elapsed().as_millis();
                println!(
                    "Decrypted: {} ms - {:.2} GBps",
                    elapsed,
                    GB_SIZE / elapsed as f64 * 1000f64
                );

                assert_eq!(xrc.get_cipher().len() * 8, lcm(key.len()));
                assert_eq!(
                    sample_text,
                    String::from_utf8(buffer[0..sample_text.len()].to_vec()).unwrap()
                );
            }
            Err(err) => println!("Error {}", err),
        }
    }
}
