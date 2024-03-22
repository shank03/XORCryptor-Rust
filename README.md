# XORCryptor Lib

Algorithm for encrypting and decrypting based on XOR bitwise operation

[<img alt="crates.io" src="https://img.shields.io/crates/v/xor_cryptor.svg?style=for-the-badge&color=fc8d62&logo=rust" height="22">](https://crates.io/crates/xor_cryptor)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-xor_cryptor-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">](https://docs.rs/xor_cryptor)

## About algorithm

![image](https://github.com/shank03/XORCryptor-Rust/assets/39261691/29904aeb-98b2-4b28-aa82-0254b8629011)

## Usage

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

## Benchmark

#### System Configuration

-   OS: Windows 11
-   Processor: Intel(R) Core(TM) i5-1035G1 CPU @ 1.00 GHz 1.19 GHz
-   Installed RAM: 16.0 GB (2666 MHz - DDR4)
-   System type: 64-bit operating system, x64-based processor
-   Rustc: 1.75.0

#### Results

```bash
$ cargo test --release --package xor_cryptor --lib -- test::benchmark --exact --nocapture
    Finished release [optimized] target(s) in 0.02s
     Running unittests src/lib.rs (target/release/deps/xor_cryptor-9b9862a430980841)

running 1 test
Allocate Buff - 1.62 GB: 2054 ms
Encrypted: 502 ms - 3.24 GBps
Decrypted: 594 ms - 2.74 GBps
test test::benchmark ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 3.26s
```
