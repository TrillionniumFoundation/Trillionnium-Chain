//! Full original private activation on the same framed input, inert observer only.
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
        let raw_end = frame.len() - 32;
        let expected = frame[8..40].try_into().unwrap();
        let checkpoint = frame[raw_end..].try_into().unwrap();
        let (status, payload) = match original::composed_activation_witness(
            &frame[40..raw_end], expected, checkpoint
        ) {
            Ok((tokens, hidden)) => {
                let mut out = (tokens as u64).to_le_bytes().to_vec();
                out.extend(hidden);
                (0u32, out)
            },
            Err(e) => (match e {
                "ACTIVATION_PIN" => 1,
                "STRICT_JSON" => 2,
                "ACTIVATION_FIELDS" => 3,
                "ACTIVATION_PROFILE" => 4,
                "HASH_ENCODING" => 5,
                "ACTIVATION_SHAPE" => 6,
                "TOKEN_FIELDS" => 7,
                "ACTIVATION_OBSERVATION_SCOPE" => 8,
                "ACTIVATION_BITS" => 9,
                _ => panic!("unexpected original stage {e}"),
            }, vec![]),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&payload).unwrap();
    }
}
