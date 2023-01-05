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
//! For rest:
//! ```no_run
//! use xor_cryptor::XORCryptor;
//!
//! fn main() {
//!    let sample_text = String::from("Hello World !");
//!    let key = String::from("secret_key");
//!
//!    let mut buffer = sample_text.as_bytes().to_vec();
//!    let res = XORCryptor::new(&key);
//!    if res.is_err() {
//!        return;
//!    }
//!    let xrc = res.unwrap();
//!    xrc.encrypt_vec(&mut buffer);
//!
//!    let encrypted_string = String::from_utf8_lossy(&buffer);
//!    println!("Encrypted: {}\n", encrypted_string);
//!
//!    // This encrypted string contains formatted non-utf8 characters
//!    // Do not use this string as vector to decrypt
//!    let mut d_buff = encrypted_string.as_bytes().to_vec();
//!    xrc.decrypt_vec(&mut d_buff);
//!    println!("Decrypted from string : {:?}", String::from_utf8_lossy(&d_buff));
//!
//!    xrc.decrypt_vec(&mut buffer);
//!    println!("Decrypted from vec    : {:?}", String::from_utf8_lossy(&buffer));
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

    fn encrypt_bytes(&self, src: &mut Vec<u64>, length: usize, b_len: usize) {
        let mut byte_count = b_len;
        for i in 0..length {
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

    fn decrypt_bytes(&self, src: &mut Vec<u64>, length: usize, b_len: usize) {
        let mut byte_count = b_len;
        for i in 0..length {
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

    /// Encrypts the vector
    pub fn encrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let length = if buffer.len() % 8 == 0 {
            buffer.len() / 8
        } else {
            (buffer.len() + 8) / 8
        };
        unsafe {
            let mut src = std::mem::transmute::<Vec<u8>, Vec<u64>>(buffer);
            self.encrypt_bytes(&mut src, length, b_len);
            std::mem::transmute::<Vec<u64>, Vec<u8>>(src)
        }
    }

    /// Decrypts the vector
    pub fn decrypt_vec(&self, buffer: Vec<u8>) -> Vec<u8> {
        if buffer.is_empty() {
            return vec![];
        }
        let b_len = buffer.len();
        let length = if buffer.len() % 8 == 0 {
            buffer.len() / 8
        } else {
            (buffer.len() + 8) / 8
        };
        unsafe {
            let mut src = std::mem::transmute::<Vec<u8>, Vec<u64>>(buffer);
            self.decrypt_bytes(&mut src, length, b_len);
            std::mem::transmute::<Vec<u64>, Vec<u8>>(src)
        }
    }

    pub fn get_cipher(&self) -> &Vec<u8> {
        &self.cipher.get_cipher()
    }
}

#[cfg(target_pointer_width = "64")]
mod cipher {
    pub struct Cipher {
        cipher_u8: Vec<u8>,
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
                cipher_u8: Cipher::get_cipher_u8(&cipher_u64, key.len()),
                cipher_u64,
                cipher_len,
            })
        }

        pub fn get_cipher_byte(&self, i: usize) -> u64 {
            self.cipher_u64[i % self.cipher_len]
        }

        pub fn get_cipher(&self) -> &Vec<u8> {
            &self.cipher_u8
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

        fn get_cipher_u8(cipher_u64: &Vec<u64>, length: usize) -> Vec<u8> {
            let mut cipher_u8 = Vec::<u8>::new();
            let (mut bytes, mut idx, mut shift) = (length, 0usize, 0usize);
            while bytes != 0 {
                cipher_u8.push(((cipher_u64[idx] >> shift) & 0xFF) as u8);
                bytes -= 1;
                shift += 8;
                if shift == 64 {
                    shift = 0;
                    idx += 1;
                }
            }
            cipher_u8
        }
    }
}

#[cfg(target_pointer_width = "32")]
#[cfg(target_pointer_width = "16")]
pub struct XORCryptor {
    cipher: Vec<u8>,
    e_table: Vec<u8>,
    d_table: Vec<u8>,
}

#[cfg(target_pointer_width = "32")]
#[cfg(target_pointer_width = "16")]
impl XORCryptor {
    /// Initialize with the key
    ///
    ///  # Example Test
    ///
    /// ```
    /// use xor_cryptor::XORCryptor;
    ///
    /// let sample_text = String::from("Hello World !");
    /// let key = String::from("secret_key");
    ///
    /// let mut buffer = sample_text.as_bytes().to_vec();
    /// let res = XORCryptor::new(&key);
    /// match res {
    ///     Ok(xrc) => {
    ///         xrc.encrypt_vec(&mut buffer);
    ///         xrc.decrypt_vec(&mut buffer);
    ///         assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
    ///     },
    ///     Err(err) => println!("Error {}", err),
    /// }
    /// ```
    pub fn new(key: &String) -> Result<Self, &str> {
        if key.len() < 6 {
            return Err("Key length less than 6");
        }

        let mut cipher = key.as_bytes().to_vec();
        for i in 0..cipher.len() {
            cipher[i] = XORCryptor::generate_mask(cipher[i]);
        }
        let (mut e_table, mut d_table) = (vec![0u8; 256], vec![0u8; 256]);
        XORCryptor::generate_table(&mut e_table, &mut d_table);
        Ok(XORCryptor {
            cipher,
            e_table,
            d_table,
        })
    }

    fn generate_mask(v: u8) -> u8 {
        let (mut mask, mut vt) = (0, v);
        while vt != 0 {
            mask += if (vt & 1) == 1 { 1 } else { 0 };
            vt >>= 1;
        }
        mask |= (8 - mask) << 4;
        mask ^= (mask >> 4) | (mask << 4);
        return mask ^ v;
    }

    fn generate_table(e_table: &mut Vec<u8>, d_table: &mut Vec<u8>) {
        let (mut count, mut shift, mut value, mut bit_mask): (u8, u8, u8, u8);
        let (mut mask, mut mode) = (0u8, 0u8);
        for i in 0..=255 as u8 {
            count = 4;
            shift = 0;
            value = i;
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
            mask = (mask << 4) | mode;
            e_table[i as usize] = mask;
            d_table[mask as usize] = i;
            (mask, mode) = (0u8, 0u8);
        }
    }

    fn encrypt_bytes(&self, src: &mut Vec<u8>) {
        let (mut i, cipher_len) = (0 as usize, self.cipher.len());
        let (mut mask, mut mode) = (0u8, 0u8);
        loop {
            if (i & 1) == 1 {
                mask |= self.e_table[src[i] as usize] & 0xF0;
                mode |= (self.e_table[src[i] as usize] & 0xF) << 4;
                mode ^= mask;

                src[i] = mode ^ self.cipher[i % cipher_len];
                src[i - 1] = mask ^ self.cipher[(i - 1) % cipher_len];
                (mask, mode) = (0u8, 0u8);
            } else {
                mask |= self.e_table[src[i] as usize] >> 4;
                mode |= self.e_table[src[i] as usize] & 0xF;
            }

            i += 1;
            if i == src.len() {
                break;
            }
        }
        if (src.len() & 1) == 1 {
            mode ^= mask;
            mask = (mask << 4) | mode;
            src[i - 1] = mask ^ self.cipher[(i - 1) % cipher_len];
        }
    }

    fn decrypt_bytes(&self, src: &mut Vec<u8>) {
        let (mut i, mut k, cipher_len, last) =
            (0 as usize, 0 as usize, self.cipher.len(), src.len() - 1);
        let odd = (src.len() & 1) == 1;
        let (mut mask, mut mode): (u8, u8);
        loop {
            mask = src[i] ^ self.cipher[i % cipher_len];
            if i == last && odd {
                mode = mask & 0xF;
                mask >>= 4;
                mode ^= mask;
            } else {
                i += 1;
                mode = src[i] ^ self.cipher[i % cipher_len];
                mode ^= mask;

                src[k] = self.d_table[(((mask & 0xF) << 4) | (mode & 0xF)) as usize];
                k += 1;
                mask >>= 4;
                mode >>= 4;
            }
            src[k] = self.d_table[(((mask & 0xF) << 4) | (mode & 0xF)) as usize];
            k += 1;

            i += 1;
            if i == src.len() {
                break;
            }
        }
    }

    /// Encrypts the vector
    pub fn encrypt_vec(&self, buffer: &mut Vec<u8>) {
        if buffer.is_empty() {
            return;
        }
        self.encrypt_bytes(buffer);
    }

    /// Decrypts the vector
    pub fn decrypt_vec(&self, buffer: &mut Vec<u8>) {
        if buffer.is_empty() {
            return;
        }
        self.decrypt_bytes(buffer);
    }

    pub fn get_cipher(&self) -> &Vec<u8> {
        &self.cipher
    }
}

#[cfg(test)]
mod test {
    use crate::*;

    #[test]
    #[cfg(target_pointer_width = "32")]
    #[cfg(target_pointer_width = "16")]
    fn integrity_check() {
        let sample_text = String::from("Hello World !");
        let key = String::from("secret_key");

        let mut buffer = sample_text.as_bytes().to_vec();
        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                xrc.encrypt_vec(&mut buffer);
                xrc.decrypt_vec(&mut buffer);
                assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check() {
        let sample_text = String::from("Hello World !");
        let key = String::from("secret_key");

        let buffer = sample_text.as_bytes().to_vec();
        let xrc = XORCryptor::new(&key);
        match xrc {
            Ok(xrc) => {
                let buffer = xrc.encrypt_vec(buffer);
                let buffer = xrc.decrypt_vec(buffer);
                assert_eq!(xrc.get_cipher().len(), key.len());
                assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }
}
