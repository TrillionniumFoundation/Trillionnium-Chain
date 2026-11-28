//! Frozen original activation, checkpoint scan and numerical loops; no task path.
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
        assert_eq!(&frame[..8], b"TAR1\0\0\0\0");
        let foot = n - 48;
        let actpin = frame[8..40].try_into().unwrap();
        let cppin = frame[foot..foot+32].try_into().unwrap();
        let cpsz = u64::from_le_bytes(frame[foot+32..foot+40].try_into().unwrap());
        let actn = u64::from_le_bytes(frame[foot+40..].try_into().unwrap()) as usize;
        let (status, payload) = match original::tile_model_numeric_witness(
            &frame[40..40+actn], &frame[40+actn..foot], actpin, cppin, cpsz
        ) {
            Ok((a,b,ca,cb)) => {
                let mut value = (ca as u64).to_le_bytes().to_vec();
                value.extend((cb as u64).to_le_bytes());
                value.extend(a);
                value.extend(b);
                (0u32, value)
            }
            Err(e) => (match e {
                "ACTIVATION_PIN" => 1, "STRICT_JSON" => 2, "ACTIVATION_FIELDS" => 3,
                "ACTIVATION_PROFILE" => 4, "HASH_ENCODING" => 5, "ACTIVATION_SHAPE" => 6,
                "TOKEN_FIELDS" => 7, "ACTIVATION_OBSERVATION_SCOPE" => 8, "ACTIVATION_BITS" => 9,
                "NONFINITE" => 15,
                "CHECKPOINT_SIZE" => 21, "TARGET_TENSOR" => 29, "TENSOR_COVERAGE" => 30,
                "TENSOR_EXTENT" => 31, "CHECKPOINT_IO" => 32, "HEADER_LIMIT" => 33,
                "CHECKPOINT_PIN" => 34, _ => panic!("unexpected original stage {e}"),
            }, vec![]),
        };
        out.write_all(&status.to_le_bytes()).unwrap();
        out.write_all(&(payload.len() as u32).to_le_bytes()).unwrap();
        out.write_all(&payload).unwrap();
    }
}
