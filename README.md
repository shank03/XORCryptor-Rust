# XORCryptor Lib

Library for encrypting and decrypting using XOR bitwise operation

[About algorithm](https://github.com/shank03/XORCryptorLib/blob/main/About.md)

[<img alt="crates.io" src="https://img.shields.io/crates/v/xor_cryptor.svg?style=for-the-badge&color=fc8d62&logo=rust" height="22">](https://crates.io/crates/xor_cryptor)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-xor_cryptor-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">](https://docs.rs/xor_cryptor)

## Usage

```rust
use xor_cryptor::XORCryptor;

fn main() {
    let sample_text = String::from("Hello World !");
    let key = String::from("secret_key");

    let mut buffer = sample_text.as_bytes().to_vec();
    let res = XORCryptor::new(&key);
    if res.is_ok() {
        let xrc = res.unwrap();
        xrc.encrypt_vec(&mut buffer);

        let encrypted_string = String::from_utf8_lossy(&buffer);
        println!("Encrypted: {}\n", encrypted_string);

        // This encrypted string contains formatted non-utf8 characters
        // Do not use this string as vector to decrypt
        let mut d_buff = encrypted_string.as_bytes().to_vec();
        xrc.decrypt_vec(&mut d_buff);
        println!(
            "Decrypted from string : {:?}",
            String::from_utf8_lossy(&d_buff)
        );

        xrc.decrypt_vec(&mut buffer);
        println!(
            "Decrypted from vec    : {:?}",
            String::from_utf8_lossy(&buffer)
        );
    }
}
```

### Output
```shell
$ cargo run
   Compiling xor_cryptor v1.0.0 (XYZ)
    Finished dev [unoptimized + debuginfo] target(s) in 0.21s
     Running `target/debug/xor_cryptor.exe`

Encrypted: W"♣'"�jMLQ�-

Decrypted from string: "Hell:4u��D6S\u{c}\u{1e}��K"
Decrypted from vec   : "Hello World !"
```