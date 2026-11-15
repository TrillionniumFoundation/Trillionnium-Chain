// Standalone complete-helper comparison. Not a Node/service benchmark.
use std::{hint::black_box, time::Instant};
type Error = String;
type Result<T> = std::result::Result<T, Error>;
fn ensure(condition: bool, code: &str) -> Result<()> {
    if condition { Ok(()) } else { Err(code.to_owned()) }
}
fn original(text: &str) -> Result<Vec<u8>> {
    ensure(text.len() <= 2_097_152 && text.len().is_multiple_of(2)
        && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "PACKET_HEX")?;
    hex::decode(text).map_err(|_| Error::from("PACKET_HEX"))
}
fn decode_packet_hex(text: &str) -> Result<Vec<u8>> {
    ensure(
        text.len() <= 2_097_152
            && text.len().is_multiple_of(2)
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "PACKET_HEX",
    )?;
    // The complete canonical grammar above proves every byte is 0..9 or a..f.
    // Convert that domain without reclassifying it; retain the full validation
    // before allocation and before invoking the settings/context packet codec.
    Ok(text
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = (pair[0] & 15) + 9 * (pair[0] >> 6);
            let low = (pair[1] & 15) + 9 * (pair[1] >> 6);
            (high << 4) | low
        })
        .collect())
}
fn sample(f: fn(&str) -> Result<Vec<u8>>, text: &str, repetitions: usize) -> u128 {
    let start = Instant::now();
    for _ in 0..repetitions { black_box(f(black_box(text)).unwrap()); }
    start.elapsed().as_nanos()
}
fn main() {
    for (bytes, repetitions) in [(128, 10000), (4096, 500), (1048576, 8)] {
        let raw: Vec<u8> = (0..bytes).map(|i| i as u8).collect();
        let text = hex::encode(&raw);
        assert_eq!(original(&text).unwrap(), raw);
        assert_eq!(decode_packet_hex(&text).unwrap(), raw);
        sample(original, &text, 1); sample(decode_packet_hex, &text, 1);
        for pair in 0..8 {
            let (old, new) = if pair % 2 == 0 {
                let old = sample(original, &text, repetitions);
                (old, sample(decode_packet_hex, &text, repetitions))
            } else {
                let new = sample(decode_packet_hex, &text, repetitions);
                (sample(original, &text, repetitions), new)
            };
            println!("bytes={bytes} repetitions={repetitions} pair={pair} original_ns={old} candidate_ns={new}");
        }
    }
}
