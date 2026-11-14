//! Fixed-size offline native work bridge. No process network, key or chain authority.
use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_work::*;
fn h(bytes: &[u8]) -> Result<Hash, &'static str> {
    bytes.try_into().map_err(|_| "LENGTH")
}
fn run() -> Result<(), &'static str> {
    let mode = std::env::args().nth(1).ok_or("OPERATION")?;
    let expected = match mode.as_str() {
        "prove" => 32 + 2 * CELLS * 4,
        "verify" => 96 + PROOF_BYTES,
        _ => return Err("OPERATION"),
    };
    let mut input = Vec::new();
    io::stdin()
        .take(expected as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "IO")?;
    if input.len() != expected {
        return Err("LENGTH");
    }
    let challenge = h(&input[..32])?;
    let output = if mode == "prove" {
        let elements: Vec<u32> = input[32..]
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("four-byte chunk")))
            .collect();
        prove(challenge, &elements[..CELLS], &elements[CELLS..]).map_err(|_| "WORK")?
    } else {
        let task = h(&input[32..64])?;
        let target = h(&input[64..96])?;
        verify(challenge, task, target, &input[96..]).map_err(|_| "WORK")?;
        hash(b"native-work-verification", &[&input]).to_vec()
    };
    io::stdout().write_all(&output).map_err(|_| "IO")?;
    Ok(())
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
