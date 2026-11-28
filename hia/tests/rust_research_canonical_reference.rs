//! Execute the complete untouched original canonical module, including its
//! private decoder cursor. The additional code only adapts the test byte ABI.
use std::io::{self, BufRead};

#[allow(dead_code)]
mod original {
    include!(env!("TRNM_RESEARCH_CANONICAL_SOURCE"));

    fn exact(decoder: &mut Decoder<'_>, n: u64) -> Result<(), CanonicalDecodeError> {
        macro_rules! sizes {
            ($($size:literal),*) => { match n {
                $($size => decoder.bytes_exact::<$size>().map(|_| ()),)*
                _ => panic!("unsupported exact-length oracle fixture"),
            } };
        }
        sizes!(0, 1, 2, 3, 4, 8, 16, 23, 24, 31, 32, 33, 64, 255, 256, 1024)
    }

    fn text(decoder: &mut Decoder<'_>, maximum: u64) -> Result<String, CanonicalDecodeError> {
        macro_rules! sizes {
            ($($size:literal),*) => { match maximum {
                $($size => decoder.text_bounded::<$size>(),)*
                u64::MAX => decoder.text_bounded::<{ usize::MAX }>(),
                _ => panic!("unsupported text-bound oracle fixture"),
            } };
        }
        sizes!(0, 1, 2, 3, 4, 5, 8, 16, 23, 24, 31, 32, 33, 64, 255, 256, 1024)
    }

    pub fn run(raw: &[u8]) -> (u64, [u64; 4], Vec<u8>) {
        if raw.starts_with(b"RCH1") {
            let n = u32::from_le_bytes(raw[4..8].try_into().unwrap()) as usize;
            return match std::str::from_utf8(&raw[8..8 + n]) {
                Ok(domain) => (0, [0; 4], canonical_hash(domain, &raw[8 + n..]).to_vec()),
                Err(_) => (5, [0; 4], Vec::new()),
            };
        }
        assert!(raw.len() >= 24 && &raw[..4] == b"RCB1");
        let op = raw[4];
        let arg = u64::from_le_bytes(raw[8..16].try_into().unwrap());
        let cursor = u64::from_le_bytes(raw[16..24].try_into().unwrap()) as usize;
        let input = &raw[24..];
        if op < 7 {
            let mut encoder = Encoder {
                bytes: vec![0xa5; cursor],
            };
            match op {
                0 => encoder.uint(arg),
                1 => encoder.bytes(input),
                2 => match std::str::from_utf8(input) {
                    Ok(value) => encoder.text(value),
                    Err(_) => return (5, [cursor as u64, 0, 0, 0], Vec::new()),
                },
                3 => encoder.array(arg as usize),
                4 => encoder.bool(arg != 0),
                5 => encoder.null(),
                6 => {
                    let value = if arg == 0 {
                        None
                    } else {
                        Some(input.try_into().unwrap())
                    };
                    encode_option_digest(&mut encoder, &value);
                }
                _ => unreachable!(),
            }
            let bytes = encoder.finish();
            return (0, [bytes.len() as u64, 0, 0, 0], bytes);
        }

        let mut decoder = Decoder { input, cursor };
        let result: Result<(u64, u64, u64), CanonicalDecodeError> = match op {
            16 => decoder.uint().map(|v| (v, 0, 0)),
            17 => decoder.array_len().map(|v| (v as u64, 0, 0)),
            18 => decoder.array(arg as usize).map(|()| (0, 0, 0)),
            19 => decoder.bytes().map(|v| {
                (
                    0,
                    (v.as_ptr() as usize - input.as_ptr() as usize) as u64,
                    v.len() as u64,
                )
            }),
            20 => exact(&mut decoder, arg).map(|()| (0, decoder.cursor as u64 - arg, arg)),
            21 => text(&mut decoder, arg)
                .map(|v| (0, (decoder.cursor - v.len()) as u64, v.len() as u64)),
            22 => decoder.bool().map(|v| (u64::from(v), 0, 0)),
            23 => decoder.option_digest().map(|v| match v {
                None => (0, 0, 0),
                Some(_) => (1, decoder.cursor as u64 - 32, 32),
            }),
            24 => {
                let final_cursor = decoder.cursor;
                let finished = decoder.finish();
                return match finished {
                    Ok(()) => (0, [final_cursor as u64, 0, 0, 0], Vec::new()),
                    Err(CanonicalDecodeError::TrailingBytes) => {
                        (10, [final_cursor as u64, 0, 0, 0], Vec::new())
                    }
                    Err(_) => unreachable!(),
                };
            }
            25 => decoder
                .head()
                .map(|(major, value)| (value, u64::from(major), 0)),
            _ => panic!("unsupported oracle operation"),
        };
        let cursor = decoder.cursor as u64;
        let (code, a, b, c) = match result {
            Ok((a, b, c)) => (0, a, b, c),
            Err(error) => match error {
                CanonicalDecodeError::UnexpectedEof => (1, 0, 0, 0),
                CanonicalDecodeError::UnexpectedType => (2, 0, 0, 0),
                CanonicalDecodeError::ForbiddenAdditionalInfo => (3, 0, 0, 0),
                CanonicalDecodeError::NonMinimalEncoding => (4, 0, 0, 0),
                CanonicalDecodeError::InvalidUtf8 => (5, 0, 0, 0),
                CanonicalDecodeError::ArrayLengthMismatch { expected, got } => {
                    (6, expected as u64, got as u64, 0)
                }
                CanonicalDecodeError::ByteLengthMismatch { expected, got } => {
                    (7, expected as u64, got as u64, 0)
                }
                _ => panic!("downstream-only error unexpectedly produced by core decoder"),
            },
        };
        (code, [cursor, a, b, c], Vec::new())
    }
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}

fn main() {
    for line in io::stdin().lock().lines() {
        let raw = unhex(&line.unwrap());
        let (code, meta, bytes) = original::run(&raw);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        println!(
            "{} {} {} {} {} {}",
            code, meta[0], meta[1], meta[2], meta[3], hex
        );
    }
}
