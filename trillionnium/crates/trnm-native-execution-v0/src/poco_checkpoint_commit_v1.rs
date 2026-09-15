//! Strict checkpoint finality -> actual native application commit. This path
//! deliberately requires no joint handoff certificate: signatures over that
//! certificate's descriptor are later consumers of the committed checkpoint.

use super::*;
use trnm_consensus_types::Cev0AdmissionBudgetV0;
use trnm_native_application::{NativeApplicationCommitRequestV0, NativeApplicationV0};

/// Local disposition, not a consensus transaction rejection. Once the atomic
/// application commit has been attempted, every error requires fresh exact
/// readback. No compensating write or second intent is authorized by this error.
#[derive(Debug)]
pub enum NativeCheckpointCommitErrorV1 {
    BeforeCommit(anyhow::Error),
    Uncertain(anyhow::Error),
}
impl std::fmt::Display for NativeCheckpointCommitErrorV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BeforeCommit(error) => write!(f, "checkpoint commit preflight: {error}"),
            Self::Uncertain(error) => {
                write!(f, "checkpoint commit requires fresh recovery: {error}")
            }
        }
    }
}
impl std::error::Error for NativeCheckpointCommitErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::BeforeCommit(error) | Self::Uncertain(error) => error.as_ref(),
        })
    }
}

impl DurableNativeApplicationV0 {
    /// Commit the exact already-executed checkpoint under its real old-set
    /// checkpoint/two-seal proof, then freshly recover the existing application
    /// and preparation-store join before returning a pre-handoff read receipt.
    ///
    /// Invalid/under-budget proofs, changed headers/body/receipts, absent P rows,
    /// a foreign or lost preparation namespace and a mismatched commissioned
    /// context cannot reach the application commit call. The supplied budget
    /// covers one strict checkpoint-proof pass; existing native/cutoff audits
    /// retain their separate bounds. No seal application row is created.
    ///
    /// A failure at or after commit is uncertain. Reconstruct preparation from
    /// the original preview request/raw cutoff proof and fresh store state, then
    /// read or retry the identical checkpoint. Do not use the next current-head
    /// preview to manufacture a replacement checkpoint. This method does not
    /// provide Core phase progression, custody, anchor activation, publication,
    /// multi-store atomicity or whole-node rollback resistance.
    pub fn commit_poco_checkpoint_for_handoff_v1(
        &self,
        prepared: PreparedNativePocoCheckpointV0,
        executed: NativeExecutedBlockV0,
        raw_checkpoint_two_seal_finality: &[u8],
        budget: &mut Cev0AdmissionBudgetV0,
    ) -> std::result::Result<CommittedNativePocoCheckpointForHandoffV0, NativeCheckpointCommitErrorV1>
    {
        let mut preflight = || -> Result<trnm_consensus_crypto::StrictCheckpointFinalityV0> {
            let authority = prepared
                .bound
                .authorized()
                .prepared()
                .commitment_authority();
            ensure!(
                authority.old_validator_set() == self.config_v0().validator_set_v0()
                    && authority.old_parameters() == self.config_v0().consensus_parameters_v0(),
                "checkpoint preparation has another commissioned old context"
            );
            let finality = trnm_consensus_crypto::decode_verify_checkpoint_finality_strict_v0(
                raw_checkpoint_two_seal_finality,
                authority.old_validator_set(),
                authority.old_parameters(),
                &authority.commitment(),
                authority.new_validator_set(),
                authority.new_parameters(),
                prepared.header(),
                authority.checkpoint_parent().header(),
                budget,
            )?;
            crate::durable::ensure_finalized_header_binding_v0(
                prepared.header(),
                executed.request(),
            )?;
            let exact = native_execution_from_receipts_v0(
                executed.request().transactions(),
                executed.receipts(),
            )?;
            ensure!(
                exact.application_payload() == prepared.body().application_payload()
                    && exact.execution_receipts() == prepared.receipts(),
                "checkpoint execution body or receipts differ from preparation"
            );
            let journal = self.poco_preparation_journal_v0()?;
            crate::poco_checkpoint_header::revalidate_durably_bound_poco_checkpoint_header_v0(
                &journal,
                &prepared.bound,
            )?;
            // Reopen the complete application and authenticate exact durable
            // artifact/snapshot/lifecycle before any commit is attempted. This
            // accepts an exact already-COMMITTED replay, not an inferred P row.
            let _confirmed_row = self.confirm_durable_execution_history_row_v0(&executed)?;
            Ok(finality)
        };
        let finality = preflight().map_err(NativeCheckpointCommitErrorV1::BeforeCommit)?;

        NativeApplicationV0::commit_block(self, NativeApplicationCommitRequestV0::new(executed))
            .map_err(|error| NativeCheckpointCommitErrorV1::Uncertain(error.into()))?;
        // Do not turn successful SQLite commit into a checkpoint receipt until
        // fresh native and sidecar readback recomputes the exact provenance.
        // The retained immutable strict proof avoids a late second budget charge.
        let (read, post_execution_authorization_id) = self
            .read_committed_poco_checkpoint_preparation_v0(&prepared)
            .map_err(NativeCheckpointCommitErrorV1::Uncertain)?;
        Ok(CommittedNativePocoCheckpointForHandoffV0 {
            prepared,
            read,
            finality,
            post_execution_authorization_id,
        })
    }
}
