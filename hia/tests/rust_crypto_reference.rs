//! Test-only calls into the retained original crypto crate, with no copied
//! Ed25519/hash/arithmetic implementation and no production signing authority.
use std::io::{self, BufRead};
use trnm_crypto_primitives as original;

fn from_hex(value: &str) -> Vec<u8> {
    if value == "-" {
        return Vec::new();
    }
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|chunk| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => panic!("noncanonical test hex"),
            };
            digit(chunk[0]) * 16 + digit(chunk[1])
        })
        .collect()
}

fn to_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify(raw: &[u8]) -> u32 {
    if !(96..=131168).contains(&raw.len()) {
        return 100;
    }
    let public = to_hex(&raw[..32]);
    if let Err(error) = original::verifying_key_from_hex(&public) {
        if error.downcast_ref::<original::WeakEd25519Key>().is_some() {
            return 3;
        }
        return if error.to_string() == "public key is not canonical" {
            1
        } else {
            2
        };
    }
    let signature = to_hex(&raw[32..96]);
    if original::decode_signature("signature_hex", &signature).is_err() {
        return 4;
    }
    if original::verify_hex_strict(&public, &raw[96..], &signature).is_ok() {
        0
    } else {
        5
    }
}

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("test input");
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            ["V", input] => println!("{}", verify(&from_hex(input))),
            ["S", seed, message] => {
                let key = original::signing_key_from_hex(seed).expect("public deterministic test seed");
                println!(
                    "{} {}",
                    original::public_key_hex(&key),
                    original::sign_hex(&key, &from_hex(message))
                );
            }
            _ => panic!("unknown test request"),
        }
    }
}
