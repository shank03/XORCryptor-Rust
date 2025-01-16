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
        let mut ps = src[n - 1];
        let mut p_c = self.cipher.get_cipher_byte(n - 1);

        for i in 0..n {
            let wrap = ps & 0x00FF_00FF_00FF_00FF;
            let ci = self.cipher.get_cipher_byte(i);

            let x = self.encrypt_byte(src[i]) ^ ci ^ ps ^ p_c ^ (wrap << 8);
            src[i] = x;

            ps = x;
            p_c = ci;
        }
    }

    fn decrypt_buffer_v2(&self, src: &mut Vec<usize>) {
        let n = src.len() - 2;
        let mut cs = src[n - 1];
        let mut c_c = self.cipher.get_cipher_byte(n - 1);

        for r in (0..n).rev() {
            let i = if r == 0 { n - 1 } else { r - 1 };
            let y = src[i];
            let wrap = y & 0x00FF_00FF_00FF_00FF;
            let c_li = self.cipher.get_cipher_byte(i);

            src[r] = self.decrypt_byte(cs ^ (wrap << 8) ^ y ^ c_li ^ c_c);

            cs = y;
            c_c = c_li;
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
