//! Cipher and decipher using algorithm based on XOR bitwise operation
//!
//! # Usage
//!
//! ### For V2:
//! ```
//! use xor_cryptor::XORCryptor;
//!
//! fn main() {
//!    let sample_text = String::from("Hello World !");
//!    let key = String::from("secret_key");
//!    let buffer = sample_text.as_bytes().to_vec();
//!
//!    let encrypted_buffer = match XORCryptor::encrypt_v2(key.as_bytes(), buffer) {
//!        Ok(enc) => enc,
//!        Err(e) => {
//!            println!("Error: {}", e);
//!            return;
//!        }
//!    };
//!
//!    let encrypted_string = String::from_utf8_lossy(&encrypted_buffer);
//!    println!("Encrypted: {}\n", encrypted_string);
//!
//!    // Never convert encrypted buffer into string
//!    // This encrypted string contains formatted non-utf8 characters
//!    // Do not use this string as vector to decrypt
//!    let decrypted_buffer =
//!        match XORCryptor::decrypt_v2(key.as_bytes(), encrypted_string.as_bytes().to_vec()) {
//!            Ok(d) => d,
//!            Err(e) => {
//!                println!("Error: {}", e);
//!                return;
//!            }
//!        };
//!    println!(
//!        "Decrypted from string : {:?}",
//!        String::from_utf8_lossy(&decrypted_buffer)
//!    );
//!
//!    let decrypted_buffer = match XORCryptor::decrypt_v2(key.as_bytes(), encrypted_buffer) {
//!        Ok(d) => d,
//!        Err(e) => {
//!            println!("Error: {}", e);
//!            return;
//!        }
//!    };
//!    println!(
//!        "Decrypted from vec    : {:?}",
//!        String::from_utf8_lossy(&decrypted_buffer)
//!    );
//! }
//! ```
//!
//! ## Output
//! ```shell
//! $ cargo run --release --bin main
//!    Compiling xor_cryptor v1.2.3 (/Users/shank/Developer/Projects/XORCryptor-Rust)
//!     Finished `release` profile [optimized] target(s) in 0.42s
//!      Running `target/release/main`
//! Encrypted: _h�OUrF�bq�h��=������
//!
//! Decrypted from string : "\u{16}Y�\u{7ac}��|�YCfOe\u{14}\u{11}�yJ �/���\u{6}h\u{15}.sY\u{17}\u{13}�k�9�c��\0�\0�\0�\0\0"
//!
//! Decrypted from vec    : "Hello World !"
//! ```
//!
//! ### For V1:
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

use err::XRCResult;
use rayon::iter::{IntoParallelIterator, ParallelIterator};

mod cipher;
mod test;
mod v2;

pub mod err;

#[cfg(target_pointer_width = "64")]
pub struct XORCryptor {
    cipher: cipher::Cipher,
    e_table: Vec<u16>,
    d_table: Vec<u16>,
}

#[cfg(target_pointer_width = "64")]
impl XORCryptor {
    /// Initialize with the key
    pub fn new(key: &str) -> XRCResult<Self> {
        let cipher = cipher::Cipher::from(key)?;
        Ok(XORCryptor::init(cipher))
    }

    pub fn new_bytes(key: &[u8]) -> XRCResult<Self> {
        let cipher = cipher::Cipher::from_bytes(key)?;
        Ok(XORCryptor::init(cipher))
    }

    pub fn init(cipher: cipher::Cipher) -> Self {
        let (mut e_table, mut d_table) = (vec![0u16; 256], vec![0u16; 0xF10]);
        Self::generate_table(&mut e_table, &mut d_table);
        XORCryptor {
            cipher,
            e_table,
            d_table,
        }
    }

    fn generate_table(e_table: &mut Vec<u16>, d_table: &mut Vec<u16>) {
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
            e_table[i as usize] = mask;
            d_table[mask as usize] = i;
            (mask, mode) = (0, 0);
        }
    }

    #[inline]
    fn encrypt_byte(&self, val: usize) -> usize {
        self.e_table[val & 0xFF] as usize
            | (self.e_table[(val >> 0x8) & 0xFF] as usize) << 0x4
            | (self.e_table[(val >> 0x10) & 0xFF] as usize) << 0x10
            | (self.e_table[(val >> 0x18) & 0xFF] as usize) << 0x14
            | (self.e_table[(val >> 0x20) & 0xFF] as usize) << 0x20
            | (self.e_table[(val >> 0x28) & 0xFF] as usize) << 0x24
            | (self.e_table[(val >> 0x30) & 0xFF] as usize) << 0x30
            | (self.e_table[(val >> 0x38) & 0xFF] as usize) << 0x34
    }

    fn encrypt_buffer(&self, src: &mut Vec<usize>, b_len: usize) {
        let mut byte_count = b_len;
        let odd = b_len % 8 != 0;
        let length = src.len() - if odd { 1 } else { 0 };
        let src_ptr = Ptr(src.as_mut_ptr());

        byte_count -= 8 * length;

        (0..length).into_par_iter().for_each(move |i| unsafe {
            let val = *{ src_ptr }.0.add(i);
            let mut lxi = self.encrypt_byte(val);

            lxi = ((lxi & 0x00FF_00FF_00FF_00FF) << 8) ^ lxi;
            *{ src_ptr }.0.add(i) = lxi ^ self.cipher.get_cipher_byte(i);
        });

        if odd {
            let (val, mut shift) = (src[length], 0usize);
            let mut lxi = 0usize;
            while byte_count > 1 {
                lxi |= (self.e_table[(val >> shift) & 0xFF] as usize) << shift
                    | ((self.e_table[((val >> 8) >> shift) & 0xFF] as usize) << 4) << shift;
                shift += 16;
                byte_count -= 2;
            }
            let mut mm = self.e_table[(val >> shift) & 0xFF] as usize;
            mm = ((mm & 0xF00) >> 8) | ((mm & 0xF) << 4);
            mm ^= mm >> 4;
            lxi |= mm << shift;
            lxi = ((lxi & 0x00FF_00FF_00FF_00FF) << 8) ^ lxi;
            src[length] = lxi ^ self.cipher.get_cipher_byte(length);
        }
    }

    #[inline]
    fn decrypt_byte(&self, val: usize) -> usize {
        self.d_table[val & 0x0F0F] as usize
            | (self.d_table[(val >> 0x4) & 0x0F0F] as usize) << 0x8
            | (self.d_table[(val >> 0x10) & 0x0F0F] as usize) << 0x10
            | (self.d_table[(val >> 0x14) & 0x0F0F] as usize) << 0x18
            | (self.d_table[(val >> 0x20) & 0x0F0F] as usize) << 0x20
            | (self.d_table[(val >> 0x24) & 0x0F0F] as usize) << 0x28
            | (self.d_table[(val >> 0x30) & 0x0F0F] as usize) << 0x30
            | (self.d_table[(val >> 0x34) & 0x0F0F] as usize) << 0x38
    }

    fn decrypt_buffer(&self, src: &mut Vec<usize>, b_len: usize) {
        let mut byte_count = b_len;
        let odd = b_len % 8 != 0;
        let length = src.len() - if odd { 1 } else { 0 };
        let src_ptr = Ptr(src.as_mut_ptr());

        byte_count -= 8 * length;

        (0..length).into_par_iter().for_each(move |i| unsafe {
            *{ src_ptr }.0.add(i) ^= self.cipher.get_cipher_byte(i);
            let val = *{ src_ptr }.0.add(i);
            let xi = ((val & 0x00FF_00FF_00FF_00FF) << 8) ^ val;

            *{ src_ptr }.0.add(i) = self.decrypt_byte(xi);
        });

        if odd {
            src[length] ^= self.cipher.get_cipher_byte(length);
            let xi = ((src[length] & 0x00FF_00FF_00FF_00FF) << 8) ^ src[length];
            let (mut lxi, mut shift) = (0usize, 0usize);
            while byte_count > 1 {
                lxi |= (self.d_table[(xi >> shift) & 0x0F0F] as usize) << shift
                    | (self.d_table[(xi >> shift >> 4) & 0x0F0F] as usize) << 8 << shift;
                shift += 0x10;
                byte_count -= 2;
            }
            let mut mm = (xi >> shift) & 0xFF;
            mm ^= mm >> 4;
            mm = ((mm & 0xF0) >> 4) | ((mm & 0xF) << 8);
            lxi |= (self.d_table[mm] as usize) << shift;
            src[length] = lxi;
        }
    }

    /// Encrypts the vector
    ///
    /// IMPORTANT!
    ///
    /// This method is NOT suitable for production use as
    /// it uses ECB. Hence, takes advantage of parallelism
    /// for higher through put
    ///
    /// [Breaking Change]: Use [`Self::encrypt_v2`] for more secure and suitable for production use
    #[deprecated]
    pub fn encrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let mut src = transmute_buffer::<u8, usize>(buffer, 0, 0, Version::V1);
        self.encrypt_buffer(&mut src, b_len);
        transmute_buffer(src, b_len, 0, Version::V1)
    }

    /// Decrypts the vector
    ///
    /// IMPORTANT!
    ///
    /// This method is NOT suitable for production use.
    ///
    /// [Breaking Change]: Use [`Self::decrypt_v2`].
    #[deprecated]
    pub fn decrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let mut src = transmute_buffer::<u8, usize>(buffer, 0, 0, Version::V1);
        self.decrypt_buffer(&mut src, b_len);
        transmute_buffer(src, b_len, 0, Version::V1)
    }

    pub fn get_cipher(&self) -> &[usize] {
        self.cipher.get_cipher()
    }
}

#[derive(Copy, Clone)]
struct Ptr<T>(*mut T);
unsafe impl<T> Send for Ptr<T> {}
unsafe impl<T> Sync for Ptr<T> {}

enum Version {
    V1,
    V2,
}

/// Transmutes buffer from Vec<u8> to Vec<usize> and vice-versa
fn transmute_buffer<T, R>(mut buffer: Vec<T>, b_len: usize, default: T, version: Version) -> Vec<R>
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

    if from_u8_usize {
        let addition = if rem == 0 { 0 } else { upper - rem_a - len };
        buffer.resize(
            buffer.len()
                + addition
                + match version {
                    Version::V1 => 0,
                    Version::V2 => 2,
                },
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
