#[cfg(test)]
use crate::*;

#[cfg(test)]
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
        0x20, 0x3e, 0x21, 0x0d, 0x21, 0x8b, 0x31, 0xdb, 0x31, 0x6c, 0x31, 0x8d, 0x11, 0xf8, 0x31,
        0xe6, 0x21, 0xdc, 0x12, 0xfc, 0x11, 0x2d, 0x76, 0xcf, 0x17, 0xed, 0x60, 0x2d, 0x63, 0x1d,
        0x04, 0x2d, 0x0b, 0xcc, 0x31, 0xec, 0x21, 0xfc, 0x11, 0x9a, 0x31, 0xca, 0x31, 0x8e, 0x31,
        0x9f, 0x31, 0x08, 0x31, 0xd7, 0x31, 0xec, 0x02, 0x1f, 0x11, 0xcf, 0x66, 0xdd, 0x07, 0x2d,
        0x70, 0x3d, 0x63, 0xdc, 0x14, 0xfd, 0x0b, 0xdd, 0x31, 0xcf, 0x31, 0xdd, 0x31, 0xab, 0x31,
        0xda, 0x21, 0x8d, 0x31, 0x8d, 0x31, 0xf8, 0x31, 0xc7, 0x11, 0xdd, 0x12, 0xcc, 0x31, 0xdd,
        0x66, 0xdc, 0x07, 0xdd, 0x50, 0xdd, 0x73, 0x3d, 0x04, 0xfd, 0x1b, 0xcf, 0x31, 0xde, 0x21,
        0x3d, 0x11, 0x9a, 0x31, 0xca, 0x21, 0x5e, 0x31, 0x8d, 0x21, 0xf9, 0x31, 0xd7, 0x31, 0xed,
        0x12, 0xcf, 0x11, 0xed, 0x66, 0x2d, 0x17, 0xcf, 0x70, 0xfd, 0x53, 0xdd, 0x14, 0xfc, 0x0b,
        0xdc, 0x31, 0x0e, 0x21, 0x0d, 0x31, 0xaa, 0x31, 0xe9, 0x31, 0xad, 0x31, 0xbf, 0x31, 0x08,
        0x31, 0xe6, 0x21, 0x2d, 0x02, 0xcc, 0x11, 0xcf, 0x56, 0xdd, 0x17, 0x3d, 0x60, 0xdd, 0x53,
        0xdd, 0x14, 0xed, 0x3b, 0xdd, 0x31, 0xce, 0x31, 0xdc, 0x31, 0x7a, 0x31, 0xca, 0x31, 0x8e,
        0x31, 0xbe, 0x31, 0xc9, 0x31, 0xe5, 0x21, 0x1d, 0x12, 0xdd, 0x01, 0xcd, 0x66, 0x2d, 0x07,
        0xcc, 0x70, 0xfd, 0x73, 0xcf, 0x14, 0xfd, 0x1b, 0xec, 0x31, 0xec, 0x31, 0xcd, 0x21, 0x6a,
        0x21, 0x3b, 0x21, 0x6c, 0x21, 0x8e, 0x31, 0xd8, 0x31, 0xe5, 0x31, 0x2d, 0x12, 0xdd, 0x01,
        0xfd, 0x76, 0x3d, 0x17, 0xdd, 0x70, 0xcf, 0x73, 0xdd, 0x04, 0x1d, 0x3b, 0xdd, 0x31, 0xff,
        0x31, 0xdc, 0x31, 0x9a, 0x31, 0x19, 0x30, 0x5e,
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
fn cross_key_functionality() {
    let sample_text = String::from("Hello World !");
    let key = String::from("secret_key");
    let key_bytes = key.as_bytes();

    let mut enc_buff: Vec<u8> = vec![];
    let xrc = XORCryptor::new(&key);
    match xrc {
        Ok(xrc) => {
            enc_buff = xrc.encrypt_vec(sample_text.as_bytes().to_vec());
            assert!(enc_buff.len() == sample_text.len());
        }
        Err(err) => println!("Error {}", err),
    }

    let xrc = XORCryptor::new_bytes(&key_bytes);
    match xrc {
        Ok(xrc) => {
            let dec_buff = xrc.decrypt_vec(enc_buff);
            assert_eq!(sample_text, String::from_utf8(dec_buff).unwrap());
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
    let sample_text = String::from("`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?");
    let key = String::from("secret_key");

    // 24 MB * 94 chars = 2.2 GB
    const BENCH_SIZE: usize = 1024usize * 1024usize * 24usize;
    const GB_SIZE: f64 = BENCH_SIZE as f64 * 94f64 / 1024f64 / 1024f64 / 1024f64;
    let text = sample_text.as_bytes().to_vec();

    let start = std::time::Instant::now();
    let mut buffer = vec![0u8; BENCH_SIZE * text.len()];
    for i in 0..buffer.len() {
        buffer[i] = text[i % text.len()];
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

mod v2 {
    #[test]
    #[cfg(target_pointer_width = "64")]
    fn test_vectors() {
        let sample_text = String::from(
            "4c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742c2073656420646f20656975736d6f642074656d706f7220696e6369646964756e74207574206c61626f726520657420646f6c6f7265206d61676e6120616c697175612e0a",
        );
        let key = String::from("01020304050607080");

        let plain_text_vector = sample_text.as_bytes().to_vec();
        let cipher_vector = vec![
            0x43, 0x39, 0x65, 0x07, 0x62, 0xfb, 0x75, 0x9d, 0x67, 0x27, 0x03, 0xb6, 0x04, 0x14,
            0x13, 0x15, 0x32, 0x9d, 0x6c, 0x39, 0x2a, 0x0c, 0x56, 0xf8, 0x36, 0x53, 0x33, 0x18,
            0x7f, 0x39, 0x20, 0xa2, 0x46, 0x88, 0x56, 0xd5, 0x00, 0xbd, 0x66, 0x4e, 0x26, 0x35,
            0x13, 0x3f, 0x63, 0x74, 0x23, 0x34, 0x63, 0xd3, 0x56, 0xf2, 0x10, 0x29, 0x21, 0xe9,
            0x36, 0x66, 0x03, 0xe9, 0x55, 0x35, 0x33, 0x10, 0x50, 0x9c, 0x75, 0x16, 0x10, 0xbd,
            0x50, 0xe0, 0x36, 0x3b, 0x13, 0xae, 0x66, 0x40, 0x33, 0x26, 0x73, 0xe8, 0x56, 0x61,
            0x0a, 0xea, 0x76, 0xaa, 0x16, 0x51, 0x29, 0x8b, 0x75, 0x1c, 0x13, 0x35, 0x53, 0x2c,
            0x75, 0x7d, 0x72, 0x97, 0x11, 0xe9, 0x06, 0x46, 0x16, 0xa0, 0x32, 0x38, 0x20, 0xe0,
            0x65, 0xf9, 0x66, 0x6d, 0x30, 0xc6, 0x63, 0x36, 0x06, 0x62, 0x00, 0xf7, 0x65, 0xfa,
            0x03, 0x81, 0x43, 0xa8, 0x46, 0x1b, 0x06, 0x52, 0x56, 0x38, 0x26, 0xb6, 0x30, 0x7b,
            0x27, 0xc9, 0x30, 0xd7, 0x02, 0x0c, 0x56, 0xad, 0x61, 0xb3, 0x56, 0x1a, 0x57, 0x22,
            0x29, 0x57, 0x4f, 0x2c, 0x33, 0x80, 0x53, 0x59, 0x76, 0xc3, 0x2a, 0x8c, 0x55, 0x6f,
            0x13, 0xc6, 0x13, 0x69, 0x45, 0x6d, 0x33, 0x36, 0x73, 0x2e, 0x56, 0xc6, 0x26, 0xc0,
            0x76, 0xd8, 0x36, 0xaf, 0x03, 0xaf, 0x45, 0x0a, 0x64, 0x42, 0x63, 0xbf, 0x56, 0x00,
            0x00, 0x83, 0x66, 0xfd, 0x05, 0x10, 0x30, 0x8b, 0x45, 0x7d, 0x05, 0x48, 0x73, 0x33,
            0x46, 0x87, 0x33, 0x34, 0x76, 0xc8, 0x36, 0x85, 0x03, 0x3f, 0x7f, 0x1b, 0x33, 0x10,
            0x63, 0x69, 0x6c, 0x71, 0x10, 0x88, 0x76, 0xf8, 0x26, 0x81, 0x30, 0x22, 0x37, 0x54,
            0x74, 0x60, 0x63, 0x6f, 0x73, 0x9a, 0x77, 0x6d, 0x54, 0x1d, 0x20, 0x0f, 0x89, 0xc8,
            0x92, 0x6f, 0x07, 0xe5, 0x0e, 0xfd, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,
        ];

        let encrypted_vector =
            super::XORCryptor::encrypt_v2(key.as_bytes(), plain_text_vector.clone())
                .expect("Failed encryption");

        let decrypted_vector =
            super::XORCryptor::decrypt_v2(key.as_bytes(), encrypted_vector.clone())
                .expect("Failed decryption");
        assert_eq!(plain_text_vector, decrypted_vector);
        assert_ne!(plain_text_vector, encrypted_vector);

        let decrypted_cipher_vector = super::XORCryptor::decrypt_v2(key.as_bytes(), cipher_vector)
            .expect("Failed decryption 2");
        let dec = String::from_utf8_lossy(&decrypted_cipher_vector);
        assert_eq!(sample_text, dec);

        // Not application as it is now seeded randomly
        // assert_eq!(key_vector, xrc.get_cipher());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn cross_key_functionality() {
        use super::XORCryptor;

        let sample_text = String::from("Hello World !");
        let key = String::from("secret_key");

        let mut enc_buff: Vec<u8> = vec![];
        match XORCryptor::encrypt_v2(key.as_bytes(), sample_text.as_bytes().to_vec()) {
            Ok(eb) => {
                enc_buff = eb;
                assert!(enc_buff.len() % 8 == 0);
            }
            Err(err) => println!("Error {}", err),
        }

        match XORCryptor::decrypt_v2(key.as_bytes(), enc_buff) {
            Ok(dec_buff) => {
                assert_eq!(sample_text, String::from_utf8(dec_buff).unwrap());
            }
            Err(err) => println!("Error {}", err),
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check() {
        use super::XORCryptor;

        let sample_text = String::from("Hello World ! `1");
        let key = String::from("secret_k");

        assert_eq!(sample_text.len() % 8, 0);
        assert_eq!(key.len() % 8, 0);

        let buffer = sample_text.as_bytes().to_vec();

        let buffer = XORCryptor::encrypt_v2(key.as_bytes(), buffer).expect("Failed encrpytion");
        let buffer = XORCryptor::decrypt_v2(key.as_bytes(), buffer).expect("Failed decryption");
        assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn integrity_check_padding() {
        use super::XORCryptor;

        let mut sample_text = String::from("Hello World ! `1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?#2f");
        let key = String::from("secret_key");

        while sample_text.len() % 8 != 0 {
            assert_ne!(sample_text.len() % 8, 0);
            assert_ne!(key.len() % 8, 0);

            let buffer = sample_text.as_bytes().to_vec();

            let buffer = XORCryptor::encrypt_v2(key.as_bytes(), buffer).expect("Failed encryption");
            let buffer = XORCryptor::decrypt_v2(key.as_bytes(), buffer).expect("Failed decryption");

            assert_eq!(sample_text, String::from_utf8(buffer).unwrap());
            sample_text.pop();
        }
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn benchmark() {
        use super::XORCryptor;

        let sample_text = String::from("`1234567890-=qwertyuiop[]\\asdfghjkl;'zxcvbnm,./~!@#$%^&*()_+QWERTYUIOP{}|ASDFGHJKL:\"ZXCVBNM<>?");
        let key = String::from("secret_key");

        // 24 MB * 94 chars = 2.2 GB
        const BENCH_SIZE: usize = 1024usize * 1024usize * 24usize;
        const GB_SIZE: f64 = BENCH_SIZE as f64 * 94f64 / 1024f64 / 1024f64 / 1024f64;
        let text = sample_text.as_bytes().to_vec();

        let start = std::time::Instant::now();
        let mut buffer = vec![0u8; BENCH_SIZE * text.len()];
        for i in 0..buffer.len() {
            buffer[i] = text[i % text.len()];
        }
        println!(
            "Allocate Buff - {:.2} GB: {} ms",
            GB_SIZE,
            start.elapsed().as_millis()
        );

        let start = std::time::Instant::now();
        let buffer = XORCryptor::encrypt_v2(key.as_bytes(), buffer).expect("Failed encryption");
        let elapsed = start.elapsed().as_millis();
        println!(
            "Encrypted: {} ms - {:.2} GBps",
            elapsed,
            GB_SIZE / elapsed as f64 * 1000f64
        );

        let start = std::time::Instant::now();
        let buffer = XORCryptor::decrypt_v2(key.as_bytes(), buffer).expect("Failed decryption");
        let elapsed = start.elapsed().as_millis();
        println!(
            "Decrypted: {} ms - {:.2} GBps",
            elapsed,
            GB_SIZE / elapsed as f64 * 1000f64
        );

        assert_eq!(
            sample_text,
            String::from_utf8(buffer[0..sample_text.len()].to_vec()).unwrap()
        );
    }
}
