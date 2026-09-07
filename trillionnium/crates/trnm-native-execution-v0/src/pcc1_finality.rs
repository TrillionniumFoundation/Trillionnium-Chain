//! Strict PoCO proof bytes joined to the existing durable application commit.
//!
//! This is not a second ledger or a new finality rule. The application's own
//! commissioned validator set and parameters are the trust context; no set,
//! state root, or acceptance boolean is taken from transport metadata.

use std::{error::Error, fmt};

use trnm_consensus_crypto::{
    decode_verify_finality_proof_strict_v0, FinalityExpectationV0, StrictFinalityErrorV0,
};
use trnm_consensus_types::{
    BlockId, Cev0AdmissionBudgetV0, DecodeError, EvidenceRoot, Height, ReceiptsRoot, StateRoot,
};
use trnm_native_application::{NativeApplicationCommitResultV0, NativeExecutedBlockV0};

use crate::{
    DurableNativeApplicationV0, FinalizedNativeApplicationCommitRequestV0,
    NativeApplicationExecutionErrorV0,
};

#[derive(Debug)]
pub enum PocoFinalityCommitErrorV0 {
    Admission(StrictFinalityErrorV0),
    ReverificationBudget(DecodeError),
    Application(NativeApplicationExecutionErrorV0),
}

impl fmt::Display for PocoFinalityCommitErrorV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Admission(error) => write!(f, "PoCO finality admission failed: {error}"),
            Self::ReverificationBudget(error) => {
                write!(f, "application finality recheck exceeds local work budget: {error}")
            }
            Self::Application(error) => write!(f, "durable application commit failed: {error}"),
        }
    }
}

impl Error for PocoFinalityCommitErrorV0 {}

impl DurableNativeApplicationV0 {
    /// Admit exact PoCO three-chain bytes and commit their oldest target through
    /// the existing durable-P/SQLite transaction and fresh-readback path.
    ///
    /// The executed carrier is not trusted merely because it has the right
    /// Rust type: the existing commit path rechecks all header/payload/receipt
    /// bindings and requires the exact previously persisted execution artifact.
    /// Invalid classes, malformed bytes, bad signatures, retargeting and budget
    /// failure return before this method calls any mutating application API.
    /// Exact successful retry is delegated to the existing idempotent commit.
    ///
    /// `authenticated_parent_timestamp_ms` must come from the caller's trusted
    /// Core/checkpoint ancestry, not an RPC field. This seam does not resolve
    /// ancestry, commission Core, publish a receipt, advance a checkpoint or
    /// activate the node. Nonzero-epoch anchor/handoff proofs remain on the
    /// separately verified epoch-transition path.
    ///
    /// The existing application commit deliberately re-verifies the proof.
    /// Both cryptographic passes are charged to the supplied local admission
    /// budget; insufficient budget is local unavailability, not deterministic
    /// consensus invalidity. No previously frozen validity rule is relaxed.
    pub fn commit_poco_finality_bytes_v0(
        &self,
        proof_class: &str,
        proof_bytes: &[u8],
        executed: NativeExecutedBlockV0,
        authenticated_parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<NativeApplicationCommitResultV0, PocoFinalityCommitErrorV0> {
        let config = self.config_v0();
        let execution = executed.request();
        let expected = FinalityExpectationV0 {
            block_id: BlockId::new(*execution.block_id().as_bytes()),
            height: Height::new(execution.height().get()),
            state_root: StateRoot::new(*execution.expected().post_state_root().as_bytes()),
            receipts_root: ReceiptsRoot::new(*execution.expected().receipts_root().as_bytes()),
            evidence_root: EvidenceRoot::new(*execution.expected().evidence_root().as_bytes()),
            parent_id: BlockId::new(*execution.parent().block_id().as_bytes()),
            parent_height: Height::new(execution.parent().height().get()),
            parent_timestamp_ms: authenticated_parent_timestamp_ms,
        };
        let verified = decode_verify_finality_proof_strict_v0(
            proof_class,
            proof_bytes,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            expected,
            budget,
        )
        .map_err(PocoFinalityCommitErrorV0::Admission)?;
        budget
            .charge_finality_proof(verified.proof())
            .map_err(PocoFinalityCommitErrorV0::ReverificationBudget)?;
        self.commit_finalized_block_v0(FinalizedNativeApplicationCommitRequestV0::new(
            executed,
            verified.proof().clone(),
            authenticated_parent_timestamp_ms,
        ))
        .map_err(PocoFinalityCommitErrorV0::Application)
    }
}

#[cfg(test)]
mod tests;
