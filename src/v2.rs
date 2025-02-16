use std::marker::PhantomData;

use crate::{
    cipher,
    err::{XRCError, XRCResult},
    transmute_buffer, Version, XORCryptor, V2,
};

#[cfg(target_pointer_width = "64")]
impl XORCryptor<V2> {
    pub fn new_v2(seed: Option<usize>) -> Self {
        let cipher = cipher::Cipher::empty();
        let (mut e_table, mut d_table) = (vec![0u16; 256], vec![0u16; 0xF10]);
        Self::generate_table(&mut e_table, &mut d_table);
        XORCryptor {
            cipher,
            e_table,
            d_table,
            raw_seed: seed.map(|s| s.max(1)).unwrap_or(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as usize,
            ),
            _marker: PhantomData,
        }
    }

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

    /// Used to for updating [`cipher::Cipher`] with
    /// `key` and `spice_seed`.
    ///
    /// `spice_seed` is multiplied by `seed` used
    /// with [`XORCryptor::new_v2`].
    ///
    /// DO NOT call this if you don't know what you are doing.
    pub fn update_cipher(&mut self, key: &[u8], spice_seed: usize) -> XRCResult<()> {
        self.cipher =
            cipher::Cipher::from_seed(key, self.raw_seed.wrapping_mul(spice_seed) as u64)?;
        Ok(())
    }

    /// Encrypts the vector by randomizing cipher generation from keys.
    ///
    /// Slower throughput due to chaining randomized cipher.
    pub fn encrypt_vec(&mut self, key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        if buffer.is_empty() {
            return Err(XRCError::EmptyInput);
        }

        let buf_len_sq = buffer.len().wrapping_mul(buffer.len());
        let seed = self.raw_seed.wrapping_mul(buf_len_sq);

        self.update_cipher(key, buf_len_sq)?;

        let buf_len = buffer.len();
        let mut src = transmute_buffer(buffer, 0, 0, Version::V2);
        src.push(seed);
        src.push(buf_len);

        self.encrypt_buffer_v2(&mut src);
        Ok(transmute_buffer(src, 0, 0, Version::V2))
    }

    /// Encrypts the vector by randomizing cipher generation from keys.
    ///
    /// Slower throughput due to chaining randomized cipher.
    pub fn encrypt_v2(key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        let mut xrc = Self::new_v2(None);
        xrc.encrypt_vec(key, buffer)
    }

    pub fn decrypt_vec(&mut self, key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        if buffer.is_empty() {
            return Err(XRCError::EmptyInput);
        }

        let mut src = transmute_buffer::<u8, usize>(buffer, 0, 0, Version::V2);

        let seed = self.decrypt_byte(src[src.len() - 2]);
        let buf_len = self.decrypt_byte(src[src.len() - 1]);

        self.raw_seed = 1;
        self.update_cipher(key, seed)?;

        self.decrypt_buffer_v2(&mut src);
        Ok(transmute_buffer(src, buf_len, 0, Version::V2))
    }

    /// Decrypts the vector by generating cipher from encrypted seed.
    ///
    /// Slower throughput due to chaining randomized cipher.
    pub fn decrypt_v2(key: &[u8], buffer: Vec<u8>) -> XRCResult<Vec<u8>> {
        let mut xrc = Self::new_v2(None);
        xrc.decrypt_vec(key, buffer)
    }
}
