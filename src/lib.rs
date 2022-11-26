//! Cipher and decipher using XOR
//!
//! # Usage
//!
//! ```
//! fn main() {
//!    let sample_text = String::from("Hello World !");
//!    let key = String::from("secret_key");
//!
//!    let mut buffer = sample_text.as_bytes().to_vec();
//!    let res = XORCryptor::new(&key);
//!    if res.is_ok() {
//!        let xrc = res.unwrap();
//!        xrc.encrypt_vec(&mut buffer);
//!
//!        let encrypted_string = String::from_utf8_lossy(&buffer);
//!        println!("Encrypted: {}\n", encrypted_string);
//!
//!        // This encrypted string contains formatted non-utf8 characters
//!        // Do not use this string as vector to decrypt
//!        let mut d_buff = encrypted_string.as_bytes().to_vec();
//!        xrc.decrypt_vec(&mut d_buff);
//!        println!("Decrypted from string : {:?}", String::from_utf8_lossy(&d_buff));
//!
//!        xrc.decrypt_vec(&mut buffer);
//!        println!("Decrypted from vec    : {:?}", String::from_utf8_lossy(&buffer));
//!    }
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
pub struct XORCryptor {
    cipher: Vec<u8>,
    e_table: Vec<u8>,
    d_table: Vec<u8>,
}

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
}
