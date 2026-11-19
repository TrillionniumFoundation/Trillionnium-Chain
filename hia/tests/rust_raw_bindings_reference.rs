//! Test adapter: the exact original RawBindings implementation and ensure
//! function are inserted at the markers, without editing their source bytes.
//! The surrounding shell supplies standard-library aliases and wire I/O only.
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
type Hash = [u8; 32];
type Error = Box<dyn std::error::Error>;
type Result<T> = std::result::Result<T, Error>;

// __ORIGINAL_ENSURE__
// __ORIGINAL_RAW_BINDINGS__

fn decode(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn word(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn main() {
    let stdout = io::stdout();
    let mut output = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        // These allocations outlive every borrowed value in the actual owner.
        let frames: Vec<Vec<u8>> = line.unwrap().split_whitespace().map(decode).collect();
        let mut owner: Option<RawBindings<'_>> = None;
        let mut capacity = 0;
        for frame in &frames {
            assert_eq!(&frame[..8], b"NBRV0001");
            let op = word(frame, 8);
            let a = word(frame, 16);
            let digest: Hash = frame[32..64].try_into().unwrap();
            let body = &frame[64..];
            let result = match op {
                0 => {
                    assert!(owner.is_none());
                    capacity = usize::try_from(a).unwrap();
                    owner = Some(RawBindings::new(capacity));
                    Ok(())
                }
                1 => {
                    assert_eq!(a as usize, body.len());
                    owner.as_mut().unwrap().insert(digest, body)
                }
                2 => {
                    assert_eq!(a as usize, body.len());
                    owner.as_mut().unwrap().consume(digest, body)
                }
                3 => Ok(()),
                4 => {
                    drop(owner.take().unwrap());
                    owner = Some(RawBindings::new(capacity));
                    Ok(())
                }
                5 => {
                    drop(owner.take().unwrap());
                    Ok(())
                }
                _ => panic!("unknown test operation"),
            };
            let outcome = match result {
                Ok(()) => 0,
                Err(error) => match error.to_string().as_str() {
                    "POOL_DUPLICATE_MEMBER" => 1,
                    "POOL_RECORD_LIMIT" => 2,
                    "POOL_TYPED_BINDING" => 3,
                    other => panic!("unexpected original error: {other}"),
                },
            };
            let count = owner.as_ref().map_or(0, |gate| gate.remaining.len());
            let empty = owner.as_ref().is_none_or(RawBindings::is_empty);
            assert_eq!(empty, count == 0);
            let words = [u64::from_le_bytes(*b"NBRR0001"), op, outcome, count as u64, u64::from(empty)];
            for value in words {
                for byte in value.to_le_bytes() {
                    write!(output, "{byte:02x}").unwrap();
                }
            }
            writeln!(output).unwrap();
        }
        assert!(owner.is_none(), "test must explicitly close the owner");
    }
}
