//! Real original raw pin and strict JSON, plus full activation controls.
#[allow(dead_code)]
#[path = "frozen_tile_material.rs"]
mod original;
use std::io::{self, Read, Write};

fn main() {
    let mut stream = Vec::new();
    io::stdin().read_to_end(&mut stream).unwrap();
    let mut at = 0;
    let mut out = io::stdout().lock();
    while at < stream.len() {
        let size = u32::from_le_bytes(stream[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let tag = stream[at];
        let bytes = &stream[at + 1..at + size];
        at += size;
        assert_eq!(&bytes[..8], b"TAR1\0\0\0\0");
        let expected = bytes[8..40].try_into().unwrap();
        let raw = &bytes[40..];
        let result = original::raw_activation_witness(raw, expected, tag);
        let status = match result {
            Ok(tokens) => {
                assert_eq!(tokens, if tag == 0 { 0 } else { usize::from(tag) });
                0u32
            }
            Err("ACTIVATION_PIN") => 1,
            Err("STRICT_JSON") => 2,
            Err(other) => panic!("unexpected original stage {other}"),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
    }
}
