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

mod cipher;
mod test;

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
        Ok(XORCryptor::init(cipher))
    }

    pub fn new_bytes(key: &[u8]) -> Result<Self, &str> {
        let cipher = cipher::Cipher::from_bytes(key)?;
        Ok(XORCryptor::init(cipher))
    }

    pub fn init(cipher: cipher::Cipher) -> Self {
        let (mut e_table, mut d_table) = (vec![0usize; 256], vec![0usize; 0xF10]);
        XORCryptor::generate_table(&mut e_table, &mut d_table);
        XORCryptor {
            cipher,
            e_table,
            d_table,
        }
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
