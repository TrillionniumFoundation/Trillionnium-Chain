//! Test-only direct use of the original, unchanged protocol crate.
use std::io::{self, BufRead};
use trnm_protocol::pon_wire::{Envelope, WireError};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("test input read");
        let raw = if line == "-" {
            Vec::new()
        } else {
            assert!(line.len() % 2 == 0);
            (0..line.len()).step_by(2)
                .map(|i| u8::from_str_radix(&line[i..i + 2], 16).expect("test hex"))
                .collect()
        };
        let code = match Envelope::decode(&raw) {
            Ok(value) => {
                assert_eq!(value.encode().expect("decoded value must re-encode"), raw);
                0
            }
            Err(WireError::Length) => 1,
            Err(WireError::Version) => 2,
            Err(WireError::Noncanonical) => 3,
            Err(WireError::Limit) => 4,
            Err(WireError::KeyCollision) => 5,
        };
        println!("{code}");
    }
}
