//! Strict PoCO proof bytes joined to the existing durable application commit.
//!
//! This is not a second ledger or a new finality rule. The application's own
//! commissioned validator set and parameters are the trust context; no set,
//! state root, or acceptance boolean is taken from transport metadata.

use std::{error::Error, fmt};

use trnm_consensus_crypto::{
    decode_verify_finality_proof_strict_v0, FinalityExpectationV0, StrictFinalityErrorV0,
    StrictFinalityProofV0, POCO_THREE_CHAIN_PROOF_CLASS_V0,
};
use trnm_consensus_types::{
    BlockId, Cev0AdmissionBudgetV0, DecodeError, EvidenceRoot, Height, ReceiptsRoot, StateRoot,
};
use trnm_native_application::{HeightV0, NativeApplicationCommitResultV0, NativeExecutedBlockV0};

use crate::{
    DurableNativeApplicationV0, FinalizedNativeApplicationCommitRequestV0,
    FinalizedNativeApplicationReadV0, NativeApplicationExecutionErrorV0,
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
                write!(
                    f,
                    "application finality recheck exceeds local work budget: {error}"
                )
            }
            Self::Application(error) => write!(f, "durable application commit failed: {error}"),
        }
    }
}

impl Error for PocoFinalityCommitErrorV0 {}

/// One freshly audited committed application record joined to its exact strict
/// consensus proof. This is a read result, not permission to sign, publish an
/// unconfirmed checkpoint, modify state, or authorize an epoch transition.
///
/// No constructor, decoder, mutable accessor, or Clone implementation exists.
///
/// ```compile_fail
/// use trnm_native_execution_v0::PocoFinalizedApplicationReadV0;
/// fn require_clone<T: Clone>() {}
/// require_clone::<PocoFinalizedApplicationReadV0>();
/// ```
#[derive(Debug)]
#[must_use = "keep the authenticated proof and application readback together"]
pub struct PocoFinalizedApplicationReadV0 {
    application: FinalizedNativeApplicationReadV0,
    finality: StrictFinalityProofV0,
}

impl PocoFinalizedApplicationReadV0 {
    pub const fn application(&self) -> &FinalizedNativeApplicationReadV0 {
        &self.application
    }

    pub const fn finality(&self) -> &StrictFinalityProofV0 {
        &self.finality
    }
}

fn expected_finality_v0(
    executed: &NativeExecutedBlockV0,
    authenticated_parent_timestamp_ms: u64,
) -> FinalityExpectationV0 {
    let execution = executed.request();
    FinalityExpectationV0 {
        block_id: BlockId::new(*execution.block_id().as_bytes()),
        height: Height::new(execution.height().get()),
        state_root: StateRoot::new(*execution.expected().post_state_root().as_bytes()),
        receipts_root: ReceiptsRoot::new(*execution.expected().receipts_root().as_bytes()),
        evidence_root: EvidenceRoot::new(*execution.expected().evidence_root().as_bytes()),
        parent_id: BlockId::new(*execution.parent().block_id().as_bytes()),
        parent_height: Height::new(execution.parent().height().get()),
        parent_timestamp_ms: authenticated_parent_timestamp_ms,
    }
}

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
        let verified = decode_verify_finality_proof_strict_v0(
            proof_class,
            proof_bytes,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            expected_finality_v0(&executed, authenticated_parent_timestamp_ms),
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

    /// Read an already committed row and authenticate its exact execution
    /// target using the same proof-class, CEV0, context and signature rules as
    /// commit. A prepared row, even with a valid external finality proof, is
    /// not returned and is not implicitly committed by this read operation.
    ///
    /// The trusted parent timestamp has the same provenance requirement as
    /// commit. Existing store validation supplies the record and its parent;
    /// proof metadata cannot choose a different state or validator set. The
    /// configured node publication/checkpoint barrier is still required before
    /// an RPC host publishes this fact as the current serving head. Historical
    /// application reads do not alter that head or their proof's trust class.
    pub fn read_poco_finalized_bytes_v0(
        &self,
        proof_class: &str,
        proof_bytes: &[u8],
        height: HeightV0,
        authenticated_parent_timestamp_ms: u64,
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> Result<PocoFinalizedApplicationReadV0, PocoFinalityCommitErrorV0> {
        if proof_class != POCO_THREE_CHAIN_PROOF_CLASS_V0 {
            return Err(PocoFinalityCommitErrorV0::Admission(
                StrictFinalityErrorV0::UnsupportedProofClass,
            ));
        }
        budget
            .admit_root_bytes(proof_bytes.len())
            .map_err(|error| {
                PocoFinalityCommitErrorV0::Admission(StrictFinalityErrorV0::Decode(error))
            })?;
        let application = self
            .read_finalized_by_height_v0(height)
            .map_err(PocoFinalityCommitErrorV0::Application)?;
        let config = self.config_v0();
        let finality = decode_verify_finality_proof_strict_v0(
            proof_class,
            proof_bytes,
            config.validator_set_v0(),
            config.consensus_parameters_v0(),
            expected_finality_v0(application.executed_v0(), authenticated_parent_timestamp_ms),
            budget,
        )
        .map_err(PocoFinalityCommitErrorV0::Admission)?;
        Ok(PocoFinalizedApplicationReadV0 {
            application,
            finality,
        })
    }
}

#[cfg(test)]
mod tests;
