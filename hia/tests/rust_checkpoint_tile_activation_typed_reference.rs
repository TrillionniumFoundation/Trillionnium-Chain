//! Actual original private Activation serde projection, signature-free inert inputs.
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
        let frame = &stream[at..at + size];
        at += size;
        assert_eq!(&frame[..8], b"TAR1\0\0\0\0");
        let expected = frame[8..40].try_into().unwrap();
        let (status, payload) = match original::typed_activation_witness(&frame[40..], expected) {
            Ok(bytes) => (0u32, bytes),
            Err("ACTIVATION_PIN") => (1, vec![]),
            Err("STRICT_JSON") => (2, vec![]),
            Err("ACTIVATION_FIELDS") => (3, vec![]),
            Err(other) => panic!("unexpected original stage {other}"),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&payload).unwrap();
    }
}
