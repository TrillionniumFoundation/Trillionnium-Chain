//! Exact frozen private header oracle with supplied inert extent and no I/O.
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
        let len = u32::from_le_bytes(stream[at..at + 4].try_into().unwrap()) as usize;
        at += 4;
        let frame = &stream[at..at + len];
        at += len;
        assert_eq!(&frame[..8], b"THV1\0\0\0\0");
        let payload = u64::from_le_bytes(frame[8..16].try_into().unwrap());
        let (status, first, last, count) = match original::tensor_header_witness(&frame[16..], payload) {
            Ok(([start, end], count)) => (0u32,start,end,count as u64),
            Err(e) => (match e {
                "STRICT_JSON" => 2, "HEADER_OBJECT" => 3, "TENSOR_NAME" => 4,
                "METADATA" => 5, "TENSOR_FIELDS" => 6, "TENSOR_SHAPE" => 7,
                "TENSOR_DTYPE" => 8, "TARGET_TENSOR" => 9, "TENSOR_COVERAGE" => 10,
                "TENSOR_EXTENT" => 11,
                _ => panic!("unexpected original header stage {e}"),
            },0,0,0),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&first.to_le_bytes()).unwrap();
        out.write_all(&last.to_le_bytes()).unwrap();
        out.write_all(&count.to_le_bytes()).unwrap();
    }
}
