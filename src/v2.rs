use crate::{
    cipher,
    err::{XRCError, XRCResult},
    transmute_buffer, Version, XORCryptor,
};

#[cfg(target_pointer_width = "64")]
impl XORCryptor {
    fn encrypt_buffer_v2(&self, src: &mut Vec<usize>) {
        for l in src.iter_mut().rev().take(2) {
            *l = self.encrypt_byte(*l);
        }

        let n = src.len() - 2;
        for i in 0..n {
            let pi = (i - 1 + n) % n;
            let [mut x, y] = [src[i], src[pi]];
            let [ci, c_li] = [
                self.cipher.get_cipher_byte(i),
                self.cipher.get_cipher_byte(pi),
            ];
            let wrap = y & 0x00FF_00FF_00FF_00FF;

            x = self.encrypt_byte(x) ^ ci ^ y ^ c_li;
            src[i] = (wrap << 8) ^ x;
        }
    }

    fn decrypt_buffer_v2(&self, src: &mut Vec<usize>) {
        let n = src.len() - 2;
        for i in (0..n).rev() {
            let pi = (i - 1 + n) % n;
            let [mut x, y] = [src[i], src[pi]];
            let wrap = y & 0x00FF_00FF_00FF_00FF;
            let [ci, c_li] = [
                self.cipher.get_cipher_byte(i),
                self.cipher.get_cipher_byte(pi),
            ];

            x ^= wrap << 8;
            src[i] = self.decrypt_byte(x ^ y ^ c_li ^ ci);
        }
    }

    /// Encrypts the vector by randomizing cipher generation from keys.
    ///
    /// Slower throughput due to chaining randomized cipher.
    pub fn encrypt_v2(key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        if buffer.is_empty() {
            return Err(XRCError::EmptyInput);
        }

        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as usize;
        let seed = seed.wrapping_mul(buffer.len().wrapping_mul(buffer.len()));
        let cipher = cipher::Cipher::from_seed(key, seed as u64)?;
        let xrc = Self::init(cipher);

        let b_len = buffer.len();
        let mut src = transmute_buffer::<u8, usize>(buffer, 0, 0, Version::V2);
        src.push(seed);
        src.push(b_len);

        xrc.encrypt_buffer_v2(&mut src);
        Ok(transmute_buffer(src, 0, 0, Version::V2))
    }

    /// Decrypts the vector by generating cipher from encrypted seed.
    ///
    /// Slower throughput due to chaining randomized cipher.
    pub fn decrypt_v2(key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        if buffer.is_empty() {
            return Err(XRCError::EmptyInput);
        }

        let mut src = transmute_buffer::<u8, usize>(buffer, 0, 0, Version::V2);

        let txr = {
            let cipher = cipher::Cipher::from_bytes(b"123456").unwrap();
            Self::init(cipher)
        };
        let seed = txr.decrypt_byte(src[src.len() - 2]);
        let b_len = txr.decrypt_byte(src[src.len() - 1]);
        drop(txr);

        let cipher = cipher::Cipher::from_seed(key, seed as u64)?;
        let xrc = Self::init(cipher);

        xrc.decrypt_buffer_v2(&mut src);
        Ok(transmute_buffer(src, b_len, 0, Version::V2))
    }
}
