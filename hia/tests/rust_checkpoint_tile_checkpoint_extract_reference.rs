//! Exact fragment of the frozen original on a disposable in-memory Cursor.
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
        let n = u32::from_le_bytes(stream[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let frame = &stream[at..at + n];
        at += n;
        assert_eq!(&frame[..8], b"TCE1\0\0\0\0");
        let pin = frame[8..40].try_into().unwrap();
        let len = u64::from_le_bytes(frame[40..48].try_into().unwrap());
        let (status, tile) = match original::checkpoint_extract_witness(&frame[48..], len, pin) {
            Ok(tile) => (0u32, tile),
            Err(error) => (match error {
                "CHECKPOINT_SIZE" => 1, "STRICT_JSON" => 2, "HEADER_OBJECT" => 3,
                "TENSOR_NAME" => 4, "METADATA" => 5, "TENSOR_FIELDS" => 6,
                "TENSOR_SHAPE" => 7, "TENSOR_DTYPE" => 8, "TARGET_TENSOR" => 9,
                "TENSOR_COVERAGE" => 10, "TENSOR_EXTENT" => 11, "CHECKPOINT_IO" => 12,
                "HEADER_LIMIT" => 13, "CHECKPOINT_PIN" => 14,
                _ => panic!("unexpected original checkpoint fragment status {error}"),
            }, vec![]),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(tile.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&tile).unwrap();
    }
}
