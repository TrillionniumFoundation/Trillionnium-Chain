//! Bounded, canonical top-level receipt decoding shared by research profiles.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use risc0_zkvm::Receipt;
pub const MAX_RECEIPT: u64 = 16 * 1024 * 1024;

pub fn decode(bytes: &[u8]) -> Result<Receipt> {
    ensure!(bytes.len() as u64 <= MAX_RECEIPT, "receipt bound");
    // Check BEFORE deserialization to rule out nested Composite assumption
    // objects, Fake and elliptic-curve Groth16 receipts at the wire boundary.
    ensure!(
        bytes.get(..4) == Some(1u32.to_le_bytes().as_slice()),
        "succinct receipt wire tag required"
    );
    // The first Succinct field is Vec<u32> seal. Refuse an impossible length
    // from the bounded slice before serde may reserve or walk the vector.
    let count = u64::from_le_bytes(
        bytes
            .get(4..12)
            .context("missing seal length")?
            .try_into()?,
    );
    let end = count.checked_mul(4).and_then(|size| size.checked_add(12));
    ensure!(
        count != 0 && end.is_some_and(|end| end <= bytes.len() as u64),
        "impossible seal length"
    );
    Ok(bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_RECEIPT)
        .reject_trailing_bytes()
        .deserialize(bytes)?)
}
