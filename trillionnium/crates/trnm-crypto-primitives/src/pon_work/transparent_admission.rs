//! Complete-statement-bound transparent W1 certificate verification research.
//!
//! No full W1 replay occurs here. A successful result authenticates the complete
//! fixed-image computation under the pinned backend's assumptions, but cannot
//! create `VerifiedWork`, admit a block, select its parent/target/task, or grant
//! completion priority. The caller must obtain `expected` from its own context.
//! This optional research API is deliberately not a live public network profile.
//! In particular, bounded encoding is not a CPU deadline or PQ-128 qualification.
use anyhow::{ensure, Context, Result};
use bincode::Options;
use hex::FromHex;
use risc0_binfmt::Digestible;
use risc0_zkvm::{sha::Digest, InnerReceipt, Receipt, VerifierContext};

use super::full_relation::{self, PublicStatement, INPUT_BYTES, STATEMENT_BYTES};

mod bounds;

pub const PROFILE: &str = "pon-full-w1-transparent-admission-research-v1";
pub const MAGIC: &[u8; 8] = b"PWAI0001";
/// Total input plus seal shares the existing one-MiB packet comparison ceiling.
/// The original PNW1 codec and all live public resource limits are unchanged.
pub const MAX_CERTIFICATE_BYTES: usize = 1_048_576;
pub const IMAGE_ID: &str = "3ea1bcbf7900a32be73d7e78102de085562893732473667e1f3af07e585696b4";
const CONTROL_ROOT: &str = "a54dc85ac99f851c92d7c96d7318af41dbe7c0194edfcc37eb4d422a998c1f56";
const JOIN_ID: &str = "7a8f24092c34ed3eb81b3d0a0b796c588c615d3488ef9e61c21dbd1e4b83ea6e";

/// A cryptographically checked research observation, never a native work fact.
/// There is intentionally no conversion to the consensus `VerifiedWork` type.
#[derive(Debug)]
pub struct VerifiedCertificate {
    statement_id: super::Hash,
    certificate_bytes: usize,
}
impl VerifiedCertificate {
    pub fn statement_id(&self) -> super::Hash {
        self.statement_id
    }
    pub fn certificate_bytes(&self) -> usize {
        self.certificate_bytes
    }
}

/// Allocation-free outer framing. Parsing is not proof verification.
pub fn parts(wire: &[u8]) -> Result<(&[u8], &[u8])> {
    ensure!(
        (16..=MAX_CERTIFICATE_BYTES).contains(&wire.len()) && &wire[..8] == MAGIC,
        "W1_CERTIFICATE_ENVELOPE"
    );
    let input = u32::from_le_bytes(wire[8..12].try_into()?) as usize;
    let receipt = u32::from_le_bytes(wire[12..16].try_into()?) as usize;
    ensure!(
        input == INPUT_BYTES
            && receipt > 0
            && receipt <= MAX_CERTIFICATE_BYTES - 16 - INPUT_BYTES
            && wire.len() == 16 + INPUT_BYTES + receipt,
        "W1_CERTIFICATE_LENGTH"
    );
    Ok((&wire[16..16 + input], &wire[16 + input..]))
}

/// Verify received bytes against a separately supplied complete statement.
/// Unlike the original frozen single-input experiment, this checks any input
/// proved by the same exact guest; no accepted-input or claim digest allowlist
/// substitutes for real proof verification. Expected header/target/task/witness
/// commitment must all match before invoking the cryptographic verifier.
pub fn verify_bound(wire: &[u8], expected: &PublicStatement) -> Result<VerifiedCertificate> {
    let (input, raw) = parts(wire)?;
    ensure!(
        input[..STATEMENT_BYTES] == expected.encode(),
        "W1_CERTIFICATE_CONTEXT"
    );
    let journal = full_relation::unverified_claimed_journal(input)
        .map_err(|error| anyhow::anyhow!("W1_CERTIFICATE_STATEMENT:{error:?}"))?;
    super::precheck_proof_statement(
        super::hash(b"challenge", &[expected.header_bytes()]),
        expected.expected_task(),
        expected.expected_target(),
        &input[STATEMENT_BYTES..],
    )
    .map_err(|error| anyhow::anyhow!("W1_CERTIFICATE_ENCODING:{error:?}"))?;
    // Complete allocation-free grammar/dimension scan before any bincode Vec.
    bounds::preflight(raw)?;
    let receipt: Receipt = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit((MAX_CERTIFICATE_BYTES - 16 - INPUT_BYTES) as u64)
        .reject_trailing_bytes()
        .deserialize(raw)?;
    ensure!(receipt.journal.bytes == journal, "W1_CERTIFICATE_JOURNAL");
    let InnerReceipt::Succinct(proof) = &receipt.inner else {
        anyhow::bail!("W1_CERTIFICATE_SUCCINCT_REQUIRED")
    };
    // Reject even an ambient request for development mode before constructing
    // an SDK context (disable-dev-mode otherwise panics on some such values).
    ensure!(
        std::env::var_os("RISC0_DEV_MODE").is_none(),
        "W1_CERTIFICATE_DEV_MODE"
    );
    let context = VerifierContext::default().with_dev_mode(false);
    let parameters = context
        .succinct_verifier_parameters
        .as_ref()
        .context("W1_CERTIFICATE_PARAMETERS")?;
    ensure!(
        parameters.control_root.to_string() == CONTROL_ROOT
            && parameters.inner_control_root.is_none()
            && proof.hashfn == "poseidon2"
            && proof.control_id.to_string() == JOIN_ID
            && proof.verifier_parameters == parameters.digest::<risc0_zkvm::sha::Impl>()
            && proof.control_inclusion_proof.digests.len() == 8
            && proof.control_inclusion_proof.index < 256
            && proof.claim.as_value().is_ok(),
        "W1_CERTIFICATE_PARAMETERS"
    );
    // SDK verification also requires Halted(0), the pinned image, exactly this
    // journal and no unresolved assumptions. A raw seal-integrity check alone
    // is insufficient. Fake, Composite and Groth16 never reach this call.
    receipt
        .verify_with_context(&context, Digest::from_hex(IMAGE_ID)?)
        .context("W1_CERTIFICATE_PROOF")?;
    Ok(VerifiedCertificate {
        statement_id: expected.statement_id(),
        certificate_bytes: wire.len(),
    })
}

#[cfg(test)]
mod tests;
