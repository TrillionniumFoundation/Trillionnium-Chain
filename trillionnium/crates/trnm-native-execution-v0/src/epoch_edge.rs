//! Application coordinates derived only from a committed, strictly verified
//! native checkpoint/handoff. No alias or seal application state is published.

use anyhow::{ensure, Context, Result};
use trnm_consensus_types::{BlockHeader, BlockKind};
use trnm_native_application::ApplicationHeadV0;

use crate::{ConfirmedNativePocoCheckpointV0, DurableExecutionHistoryStatusV0};

/// Private coordinates used by the JMT adapter. These facts are not a public
/// constructor or a persistence format; recovery must recreate their authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct EpochApplicationCoordinatesV1 {
    pub(crate) checkpoint_version: u64,
    pub(crate) checkpoint_root: [u8; 32],
    pub(crate) terminal_version: u64,
    pub(crate) first_version: u64,
    pub(crate) authorization_id: [u8; 32],
}

impl EpochApplicationCoordinatesV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.authorization_id != [0; 32],
            "epoch edge lacks authorization"
        );
        ensure!(
            self.checkpoint_root != [0; 32],
            "epoch edge has zero checkpoint root"
        );
        ensure!(
            self.checkpoint_version.checked_add(2) == Some(self.terminal_version),
            "epoch edge terminal is not checkpoint plus two seals"
        );
        ensure!(
            self.checkpoint_version.checked_add(3) == Some(self.first_version),
            "epoch edge target is not the first new application block"
        );
        Ok(())
    }
}

/// Owner-affine committed application checkpoint joined to strict two-seal and
/// joint handoff evidence. No public constructor, deserializer or Clone exists.
/// The receipt keeps the application owner alive; opening the read view still
/// requires exact fresh checkpoint/source binding.
#[must_use]
pub struct AuthenticatedEpochApplicationEdgeV1 {
    checkpoint: ConfirmedNativePocoCheckpointV0,
    application_parent: ApplicationHeadV0,
    commit_sequence: u64,
    coordinates: EpochApplicationCoordinatesV1,
}

impl AuthenticatedEpochApplicationEdgeV1 {
    pub(crate) fn recovery_evidence(&self) -> &crate::epoch_recovery::EpochRecoveryEvidenceV1 {
        &self.checkpoint.recovery_evidence
    }
    pub fn preview_request_v1(
        &self,
        timestamp_ms: u64,
        transactions: Vec<Vec<u8>>,
    ) -> Result<trnm_native_application::NativeEpochBlockPreviewRequestV1> {
        use trnm_native_application::{
            BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, HeightV0, ValidatorSetIdV0,
        };
        let request = trnm_native_application::NativeEpochBlockPreviewRequestV1::new(
            ChainIdV0::new(self.consensus_parent().chain_id().as_str())?,
            GenesisHashV0::new(*self.consensus_parent().genesis_hash().as_bytes())?,
            self.application_parent.clone(),
            BlockIdV0::new(*self.consensus_parent().id().as_bytes())?,
            HeightV0::new(self.consensus_parent().height().get()),
            Hash32V0::new(self.authorization_id()),
            HeightV0::new(self.first_application_height()),
            timestamp_ms,
            ValidatorSetIdV0::new(*self.new_validator_set().id().as_bytes())?,
            transactions,
        )?;
        self.validate_request_v1(&request)?;
        Ok(request)
    }

    pub(crate) fn validate_request_v1(
        &self,
        request: &trnm_native_application::NativeEpochBlockPreviewRequestV1,
    ) -> Result<()> {
        ensure!(
            request.chain_id().as_str() == self.consensus_parent().chain_id().as_str()
                && request.genesis_hash().as_bytes()
                    == self.consensus_parent().genesis_hash().as_bytes()
                && request.application_parent() == self.application_parent()
                && request.consensus_parent_id().as_bytes()
                    == self.consensus_parent().id().as_bytes()
                && request.consensus_parent_height().get()
                    == self.consensus_parent().height().get()
                && request.edge_binding().as_bytes() == &self.authorization_id()
                && request.height().get() == self.first_application_height()
                && request.active_validator_set_id().as_bytes()
                    == self.new_validator_set().id().as_bytes(),
            "epoch request does not match authenticated application edge"
        );
        ensure!(
            request.timestamp_ms() > self.consensus_parent().timestamp_ms(),
            "first new application timestamp does not advance terminal seal"
        );
        Ok(())
    }
    pub(crate) fn from_confirmed_checkpoint(
        checkpoint: ConfirmedNativePocoCheckpointV0,
    ) -> Result<Self> {
        let row = checkpoint.durable_row();
        ensure!(
            row.status_v0() == DurableExecutionHistoryStatusV0::Committed,
            "epoch application edge requires a committed checkpoint"
        );
        let application_parent = row.target_head_v0()?;
        let commit_sequence = row
            .commit_sequence_v0()
            .context("checkpoint lacks commit sequence")?;
        let header = checkpoint.header();
        let terminal = checkpoint.terminal_old_header();
        ensure!(
            header.block_kind() == BlockKind::EpochCheckpoint,
            "epoch application parent is not a checkpoint"
        );
        ensure!(
            application_parent.height().get() == header.height().get()
                && application_parent.block_id().as_bytes() == header.id().as_bytes()
                && application_parent.state_root().as_bytes() == header.state_root().as_bytes(),
            "committed application checkpoint differs from handoff checkpoint"
        );
        let coordinates = EpochApplicationCoordinatesV1 {
            checkpoint_version: header.height().get(),
            checkpoint_root: *header.state_root().as_bytes(),
            terminal_version: terminal.height().get(),
            first_version: terminal
                .height()
                .get()
                .checked_add(1)
                .context("epoch target exhausted")?,
            authorization_id: checkpoint.handoff_authorization_id(),
        };
        coordinates.validate()?;
        Ok(Self {
            checkpoint,
            application_parent,
            commit_sequence,
            coordinates,
        })
    }

    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        &self.application_parent
    }
    pub fn consensus_parent(&self) -> &BlockHeader {
        self.checkpoint.terminal_old_header()
    }
    pub const fn first_application_height(&self) -> u64 {
        self.coordinates.first_version
    }
    pub const fn checkpoint_commit_sequence(&self) -> u64 {
        self.commit_sequence
    }
    pub fn old_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        &self.checkpoint.old_validator_set
    }
    pub fn old_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        &self.checkpoint.old_parameters
    }
    pub fn new_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        &self.checkpoint.new_validator_set
    }
    pub fn new_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        &self.checkpoint.new_parameters
    }
    pub const fn authorization_id(&self) -> [u8; 32] {
        self.coordinates.authorization_id
    }
    pub fn durable_checkpoint(&self) -> &crate::ConfirmedDurableExecutionHistoryRowV0 {
        self.checkpoint.durable_row()
    }
    pub(crate) const fn coordinates(&self) -> EpochApplicationCoordinatesV1 {
        self.coordinates
    }
}

/// Fresh, read-only confirmation for joining the native application owner to
/// Core activation. This is not an execution, signing or activation permit.
/// It borrows the strict edge and owns fresh committed readback; no public
/// constructor or Clone exists.
#[must_use]
pub struct ConfirmedEpochApplicationEdgeV1<'a> {
    edge: &'a AuthenticatedEpochApplicationEdgeV1,
    read: crate::FinalizedNativeApplicationReadV0,
    strict_activation: trnm_consensus_crypto::StrictSameVersionEpochActivationAuthorityV0,
}
impl ConfirmedEpochApplicationEdgeV1<'_> {
    /// Exact strict joint-proof binding used by Core journal9. This differs
    /// from the native execution authorization ID and grants no native ACK.
    pub fn strict_activation_binding_v1(
        &self,
    ) -> &trnm_consensus_crypto::StrictEpochActivationBindingRefV0 {
        self.strict_activation.binding_ref()
    }
    pub fn edge(&self) -> &AuthenticatedEpochApplicationEdgeV1 {
        self.edge
    }
    pub fn checkpoint_header(&self) -> &BlockHeader {
        self.edge.checkpoint.header()
    }
    pub fn terminal_old_header(&self) -> &BlockHeader {
        self.edge.consensus_parent()
    }
    pub fn durable_checkpoint(&self) -> &crate::ConfirmedDurableExecutionHistoryRowV0 {
        self.read.durable_row_v0()
    }
    pub fn old_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        self.edge.old_validator_set()
    }
    pub fn old_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        self.edge.old_parameters()
    }
    pub fn new_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        self.edge.new_validator_set()
    }
    pub fn new_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        self.edge.new_parameters()
    }
    pub fn authorization_id(&self) -> [u8; 32] {
        self.edge.authorization_id()
    }
    pub fn checkpoint_commit_sequence(&self) -> u64 {
        self.edge.checkpoint_commit_sequence()
    }
    pub fn application_parent(&self) -> &ApplicationHeadV0 {
        self.edge.application_parent()
    }
    pub fn belongs_to_application_at_path(
        &self,
        app: &crate::DurableNativeApplicationV0,
        path: &std::path::Path,
    ) -> bool {
        path == app.path()
            && self
                .read
                .durable_row_v0()
                .belongs_to_application_at_path_v0(app, path)
            && app.confirm_epoch_application_edge_v1(self.edge).is_ok()
    }
}

impl crate::DurableNativeApplicationV0 {
    /// Confirm the exact committed checkpoint and original retained preparation
    /// without executing C+3, migrating schema or writing an edge row.
    pub fn confirm_epoch_application_edge_v1<'a>(
        &self,
        edge: &'a AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<ConfirmedEpochApplicationEdgeV1<'a>> {
        self.confirm_namespace_identity_v1()?;
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(self, self.path()),
            "epoch confirmation owner mismatch"
        );
        ensure!(
            self.confirmed_committed_head_v0()? == *edge.application_parent(),
            "epoch confirmation requires current checkpoint head"
        );
        let read = self.read_finalized_by_height_v0(edge.application_parent().height())?;
        let row = read.durable_row_v0();
        ensure!(
            row.status_v0() == DurableExecutionHistoryStatusV0::Committed
                && row.target_head_v0()? == *edge.application_parent()
                && row.p_digest_v0() == edge.durable_checkpoint().p_digest_v0()
                && row.artifact_digest_v0() == edge.durable_checkpoint().artifact_digest_v0()
                && row.p_sequence_v0() > 0
                && edge.checkpoint_commit_sequence() > row.p_sequence_v0()
                && row.commit_sequence_v0() == Some(edge.checkpoint_commit_sequence()),
            "epoch confirmation checkpoint substituted"
        );
        let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open_existing(
            crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(self.path()),
        )?;
        journal.require_retained_bound(
            edge.recovery_evidence().preparation_id,
            &edge.recovery_evidence().checkpoint_header,
        )?;
        let strict_activation = edge
            .recovery_evidence()
            .audit_strict(
                edge.old_validator_set(),
                edge.old_parameters(),
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )?
            .activation;
        ensure!(
            self.confirmed_committed_head_v0()? == *edge.application_parent(),
            "epoch confirmation head changed"
        );
        self.confirm_namespace_identity_v1()?;
        Ok(ConfirmedEpochApplicationEdgeV1 {
            edge,
            read,
            strict_activation,
        })
    }

    /// Read-only execution of the real first-new application block, including
    /// the authenticated configuration/usage prefix. The preview is not a P,
    /// commit receipt or permission to vote.
    pub fn preview_epoch_block_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
        request: &trnm_native_application::NativeEpochBlockPreviewRequestV1,
    ) -> Result<crate::NativeBlockPreviewV0> {
        edge.validate_request_v1(request)?;
        let store = self.open_epoch_checkpoint_store_v1(edge)?;
        let result = crate::complete::preview_complete_epoch_block_v1(&store, edge, request)?;
        ensure!(
            self.confirmed_committed_head_v0()? == *edge.application_parent(),
            "epoch preview application head changed"
        );
        Ok(result)
    }

    pub(crate) fn open_epoch_checkpoint_store_v1(
        &self,
        edge: &AuthenticatedEpochApplicationEdgeV1,
    ) -> Result<crate::InMemoryNativeExecutionStoreV0> {
        ensure!(
            edge.durable_checkpoint()
                .belongs_to_application_at_path_v0(self, self.path()),
            "epoch edge belongs to a different application owner"
        );
        ensure!(
            self.confirmed_committed_head_v0()? == *edge.application_parent(),
            "epoch edge checkpoint is not the current committed application head"
        );
        let snapshot =
            self.confirmed_finalized_poco_snapshot_v0(edge.application_parent().height())?;
        let row = snapshot.read().durable_row_v0();
        ensure!(
            row.p_digest_v0() == edge.durable_checkpoint().p_digest_v0()
                && row.commit_sequence_v0() == Some(edge.checkpoint_commit_sequence()),
            "epoch edge checkpoint was replaced"
        );
        Ok(snapshot.store().clone())
    }
}
