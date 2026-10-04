//! Fixed-size complete-proof bridge for the independent paired producer.
//! It has no network, signing, parent-admission or verification authority.
use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_work::{paired_product::PairedPreparedTask, Hash, CELLS};

fn run() -> Result<(), &'static str> {
    if std::env::args().len() != 1 {
        return Err("OPERATION");
    }
    let expected = 32 + 2 * CELLS * 4;
    let mut input = Vec::new();
    io::stdin()
        .take(expected as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| "IO")?;
    if input.len() != expected {
        return Err("LENGTH");
    }
    let challenge: Hash = input[..32].try_into().map_err(|_| "LENGTH")?;
    let elements: Vec<_> = input[32..]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte chunk")))
        .collect();
    let proof = PairedPreparedTask::new(&elements[..CELLS], &elements[CELLS..])
        .and_then(|task| task.prove(challenge))
        .map_err(|_| "WORK")?;
    io::stdout().write_all(&proof).map_err(|_| "IO")?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
