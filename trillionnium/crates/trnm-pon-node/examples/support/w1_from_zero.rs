//! The existing public_v3_from_zero attack primitive, shared by its native
//! service regression and the same-target cost report. No valid proof input.
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::{hash, Hash};

pub fn proof_prefix(a: &[u32], b: &[u32]) -> Result<Vec<u8>, pon_work::WorkError> {
    pon_work::task_id(a, b)?;
    let mut proof = Vec::with_capacity(pon_work::PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [a, b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    // C and the unverified claimed transcript start as zeros, not an evaluated
    // product or a trace acquired from a successful producer.
    proof.resize(pon_work::PROOF_BYTES, 0);
    Ok(proof)
}

pub fn trial(challenge: Hash, nonce: u64) -> (Hash, Hash) {
    let trace = hash(
        b"public-v3-from-zero-v1",
        &[&challenge, &nonce.to_le_bytes()],
    );
    let ticket = hash(b"ticket", &[&challenge, &trace]);
    (trace, ticket)
}
