# XORCryptor Lib

Algorithm for encrypting and decrypting based on XOR bitwise operation

[<img alt="crates.io" src="https://img.shields.io/crates/v/xor_cryptor.svg?style=for-the-badge&color=fc8d62&logo=rust" height="22">](https://crates.io/crates/xor_cryptor)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-xor_cryptor-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">](https://docs.rs/xor_cryptor)


## About algorithm

![image](https://github.com/shank03/XORCryptor-Rust/assets/39261691/29904aeb-98b2-4b28-aa82-0254b8629011)

## Usage

#### For 64 bit CPU:
```rust
use xor_cryptor::XORCryptor;

fn main() {
    let sample_text = String::from("Hello World !");
    let key = String::from("secret_key");
    let buffer = sample_text.as_bytes().to_vec();

    let res = XORCryptor::new(&key);
    if res.is_err() {
        return;
    }
    let xrc = res.unwrap();

    let encrypted_buffer = xrc.encrypt_vec(buffer);
    let encrypted_string = String::from_utf8_lossy(&encrypted_buffer);
    println!("Encrypted: {}\n", encrypted_string);

    // This encrypted string contains formatted non-utf8 characters
    // Do not use this string as vector to decrypt
    let decrypted_buffer = xrc.decrypt_vec(encrypted_string.as_bytes().to_vec());
    println!(
        "Decrypted from string : {:?}",
        String::from_utf8_lossy(&decrypted_buffer)
    );

    let decrypted_buffer = xrc.decrypt_vec(encrypted_buffer);
    println!(
        "Decrypted from vec    : {:?}",
        String::from_utf8_lossy(&decrypted_buffer)
    );
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
