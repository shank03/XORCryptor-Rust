# XORCryptor Lib

Algorithm for encrypting and decrypting based on XOR bitwise operation using randomized chained cipher.

[<img alt="crates.io" src="https://img.shields.io/crates/v/xor_cryptor.svg?style=for-the-badge&color=fc8d62&logo=rust" height="22">](https://crates.io/crates/xor_cryptor)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-xor_cryptor-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="22">](https://docs.rs/xor_cryptor)

## About algorithm

### For V1
![image](https://github.com/shank03/XORCryptor-Rust/assets/39261691/29904aeb-98b2-4b28-aa82-0254b8629011)

## Usage

### V2
```rust
use xor_cryptor::XORCryptor;

fn main() {
    let sample_text = String::from("Hello World !");
    let key = String::from("secret_key");
    let buffer = sample_text.as_bytes().to_vec();

    let encrypted_buffer = match XORCryptor::encrypt_v2(key.as_bytes(), buffer) {
        Ok(enc) => enc,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };

    let encrypted_string = String::from_utf8_lossy(&encrypted_buffer);
    println!("Encrypted: {}\n", encrypted_string);

    // Never convert encrypted buffer into string
    // This encrypted string contains formatted non-utf8 characters
    // Do not use this string as vector to decrypt
    let decrypted_buffer =
        match XORCryptor::decrypt_v2(key.as_bytes(), encrypted_string.as_bytes().to_vec()) {
            Ok(d) => d,
            Err(e) => {
                println!("Error: {}", e);
                return;
            }
        };
    println!(
        "Decrypted from string : {:?}",
        String::from_utf8_lossy(&decrypted_buffer)
    );

    let decrypted_buffer = match XORCryptor::decrypt_v2(key.as_bytes(), encrypted_buffer) {
        Ok(d) => d,
        Err(e) => {
            println!("Error: {}", e);
            return;
        }
    };
    println!(
        "Decrypted from vec    : {:?}",
        String::from_utf8_lossy(&decrypted_buffer)
    );
}
```

### Output

> NOTE: This output will not be consistent due to randomized chained cipher

```shell
$ cargo run --release --bin main
   Compiling xor_cryptor v1.2.3 (/Users/shank/Developer/Projects/XORCryptor-Rust)
    Finished `release` profile [optimized] target(s) in 0.42s
     Running `target/release/main`
Encrypted: _h�OUrF�bq�h��=������

Decrypted from string : "\u{16}Y�\u{7ac}��|�YCfOe\u{14}\u{11}�yJ �/���\u{6}h\u{15}.sY\u{17}\u{13}�k�9�c��\0�\0�\0�\0\0"
Decrypted from vec    : "Hello World !"
```

### V1 (Deprecated due to weak cipher)

```rust
use xor_cryptor::XORCryptor;

fn main() {
    let sample_text = String::from("Hello World !");
    let key = String::from("secret_key");
    let buffer = sample_text.as_bytes().to_vec();

    let res = XORCryptor::new(&key);
    // or
    let res = XORCryptor::new_bytes(key.as_bytes());
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

-   OS: MacOS Sequoia
-   Processor: Apple M3 Pro (11 cores)
-   RAM: 18.0 GB
-   System type: 64-bit operating system, arm-based processor
-   Rustc: 1.83.0

#### Results

V2:
```bash
$ cargo test --release --package xor_cryptor --lib -- test::benchmark --exact --nocapture
    Finished release [optimized] target(s) in 0.02s
     Running unittests src/lib.rs (target/release/deps/xor_cryptor-9b9862a430980841)

running 1 test
Allocate Buff - 2.20 GB: 735 ms
Encrypted: 785 ms - 2.81 GBps
Decrypted: 978 ms - 2.25 GBps
test test::v2::benchmark ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 2.52s
```

V1:
```bash
$ cargo test --release --package xor_cryptor --lib -- test::benchmark --exact --nocapture
    Finished release [optimized] target(s) in 0.02s
     Running unittests src/lib.rs (target/release/deps/xor_cryptor-9b9862a430980841)

running 1 test
Allocate Buff - 2.20 GB: 732 ms
Encrypted: 91 ms - 24.21 GBps
Decrypted: 129 ms - 17.08 GBps
test test::benchmark ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.98s
```
