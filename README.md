# XORCryptor Lib

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