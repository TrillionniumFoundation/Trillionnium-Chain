//! Fixed-size offline differential bridge for the complete tiled producers.
//! Input/output are raw W1 material/certificate bytes, never chain authority.
use std::io::{self, Read, Write};
use trnm_crypto_primitives::pon_work::{
    structured::{TileKernel, TiledPreparedTask},
    Hash, CELLS,
};

fn run() -> Result<(), &'static str> {
    let mut arguments = std::env::args().skip(1);
    let kernel = match arguments.next().as_deref() {
        Some("classical") => TileKernel::Classical,
        Some("strassen-one-level") => TileKernel::StrassenOneLevel,
        _ => return Err("OPERATION"),
    };
    if arguments.next().is_some() {
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
    let elements: Vec<u32> = input[32..]
        .chunks_exact(4)
        .map(|bytes| u32::from_le_bytes(bytes.try_into().expect("four-byte chunk")))
        .collect();
    let proof = TiledPreparedTask::new(&elements[..CELLS], &elements[CELLS..], kernel)
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
