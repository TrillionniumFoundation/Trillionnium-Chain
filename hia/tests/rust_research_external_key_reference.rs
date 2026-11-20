//! Call the actual retained public Research protocol crate without copying its algorithms.
use std::io::{self, BufRead};
use trnm_research_protocol::{CanonicalCbor, ExternalKey, ExternalKeyError};

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let raw = unhex(&line.unwrap());
        assert!(raw.len() >= 8 && &raw[..4] == b"REK1" && raw[5] == 0);
        let n = u16::from_le_bytes(raw[6..8].try_into().unwrap()) as usize;
        let namespace = std::str::from_utf8(&raw[8..8 + n]).unwrap();
        let value = &raw[8 + n..];
        let result = match raw[4] {
            1 => ExternalKey::from_uuid(namespace, std::str::from_utf8(value).unwrap()),
            2 => ExternalKey::from_external_id(namespace, std::str::from_utf8(value).unwrap()),
            3 => {
                assert_eq!(n, 0);
                Ok(ExternalKey::from_bytes(value.try_into().unwrap()))
            }
            _ => panic!("unsupported reference operation"),
        };
        match result {
            Ok(key) => {
                let bytes = key.into_bytes();
                assert_eq!(key.as_bytes(), &bytes);
                let hex = key.to_hex();
                assert_eq!(key.to_string(), hex);
                let mut output = bytes.to_vec();
                output.extend_from_slice(hex.as_bytes());
                output.extend_from_slice(&key.canonical_bytes());
                print!("0 ");
                for byte in output {
                    print!("{byte:02x}");
                }
                println!();
            }
            Err(error) => println!(
                "{}",
                match error {
                    ExternalKeyError::InvalidNamespace => 1,
                    ExternalKeyError::InvalidUuid => 2,
                    ExternalKeyError::InvalidExternalId => 3,
                }
            ),
        }
    }
}
