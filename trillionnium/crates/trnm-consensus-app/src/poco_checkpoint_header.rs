//! Native PoCO checkpoint pre-header preparation and exact header binding.
//!
//! The first phase consumes only the cutoff-only H1/H2/candidate commitment
//! authority plus locally authorized execution results. It freezes every
//! native header field without accepting or computing a CometBFT block hash.
//! The second phase binds one exact native [`BlockHeader`] and its exact body
//! and receipts, then records only the canonical native [`BlockId`].
//!
//! Neither phase authorizes checkpoint finality, either seal, a joint handoff,
//! activation, a Core epoch transition, or any mapping between a CometBFT hash
//! and the native PoCO block ID.

use crate::{
    native_execution::AuthorizedNativeCheckpointExecutionV0,
    poco_epoch_commitment::AuthorizedPocoPreheaderNextEpochCommitmentV0,
    poco_preparation_journal::{
        poco_checkpoint_header_authorization_id_v0,
        poco_checkpoint_preparation_authorization_id_v0, PocoCheckpointBoundReplayRecordV0,
        PocoCheckpointPreparationReplayFieldsV0, PocoCheckpointPreparationReplayRecordV0,
        PocoPreparationJournalV0, PocoPreparationReservationV0, PocoPreparationTransitionBindingV0,
    },
};
use anyhow::{ensure, Context, Result};
use trnm_consensus_crypto::StrictEd25519Verifier;
use trnm_consensus_types::{
    BlockBodyV0, BlockHeader, BlockId, BlockKind, ChainId, ConsensusParametersHash,
    ConsensusParametersV0, DoubleVoteEvidenceV0, Epoch, EpochGeometryV0, EvidenceRoot,
    ExecutionReceiptsV0, GenesisHash, Height, NextEpochCommitmentHash, PayloadDigest,
    ProtocolVersion, ReceiptsRoot, StateRoot, ValidatedCheckpointCommitmentsV0, ValidatorId,
    ValidatorSetId, View,
};

/// Complete native checkpoint fields frozen before the header is constructed
/// or signed. This narrow view deliberately has no CometBFT hash field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PocoCheckpointHeaderFieldsV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    view: View,
    height: Height,
    parent_id: BlockId,
    proposer_id: ValidatorId,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    payload_root: PayloadDigest,
    state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
    timestamp_ms: u64,
    next_epoch_commitment_hash: NextEpochCommitmentHash,
}

impl PocoCheckpointHeaderFieldsV0 {
    fn replay_fields(
        &self,
        transaction_count: u32,
        evidence_count: u32,
    ) -> PocoCheckpointPreparationReplayFieldsV0 {
        PocoCheckpointPreparationReplayFieldsV0 {
            genesis_hash: self.genesis_hash,
            chain_id: self.chain_id,
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            view: self.view,
            height: self.height,
            parent_id: self.parent_id,
            proposer_id: self.proposer_id,
            validator_set_id: self.validator_set_id,
            consensus_parameters_hash: self.consensus_parameters_hash,
            payload_root: self.payload_root,
            state_root: self.state_root,
            receipts_root: self.receipts_root,
            evidence_root: self.evidence_root,
            timestamp_ms: self.timestamp_ms,
            next_epoch_commitment_hash: self.next_epoch_commitment_hash,
            transaction_count,
            evidence_count,
        }
    }

    pub(crate) const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub(crate) const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(crate) const fn view(&self) -> View {
        self.view
    }

    pub(crate) const fn height(&self) -> Height {
        self.height
    }

    pub(crate) const fn block_kind(&self) -> BlockKind {
        BlockKind::EpochCheckpoint
    }

    pub(crate) const fn parent_id(&self) -> BlockId {
        self.parent_id
    }

    pub(crate) const fn proposer_id(&self) -> ValidatorId {
        self.proposer_id
    }

    pub(crate) const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub(crate) const fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.consensus_parameters_hash
    }

    pub(crate) const fn payload_root(&self) -> PayloadDigest {
        self.payload_root
    }

    pub(crate) const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub(crate) const fn receipts_root(&self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub(crate) const fn evidence_root(&self) -> EvidenceRoot {
        self.evidence_root
    }

    pub(crate) const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub(crate) const fn next_epoch_commitment_hash(&self) -> NextEpochCommitmentHash {
        self.next_epoch_commitment_hash
    }

    pub(crate) fn exact_header(&self) -> Result<BlockHeader> {
        BlockHeader::new(
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.view,
            self.height,
            BlockKind::EpochCheckpoint,
            self.parent_id,
            self.proposer_id,
            self.validator_set_id,
            self.consensus_parameters_hash,
            self.payload_root,
            self.state_root,
            self.receipts_root,
            self.evidence_root,
            self.timestamp_ms,
            Some(self.next_epoch_commitment_hash),
        )
        .map_err(|error| anyhow::anyhow!("construct frozen checkpoint header: {error:?}"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PreparedPocoCheckpointHeaderCoreV0 {
    fields: PocoCheckpointHeaderFieldsV0,
    body: BlockBodyV0,
    receipts: ExecutionReceiptsV0,
    old_parameters: ConsensusParametersV0,
    native_execution_authorization_id: [u8; 32],
    preparation_id: [u8; 32],
}

/// Private pre-header capability. Its native body and receipts are retained so
/// the bind phase can reject a same-root or TOCTOU substitution by exact value,
/// in addition to recomputing every committed root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PreparedPocoCheckpointHeaderV0 {
    commitment_authority: AuthorizedPocoPreheaderNextEpochCommitmentV0,
    core: PreparedPocoCheckpointHeaderCoreV0,
}

impl PreparedPocoCheckpointHeaderV0 {
    pub(crate) const fn fields(&self) -> PocoCheckpointHeaderFieldsV0 {
        self.core.fields
    }

    pub(crate) const fn body(&self) -> &BlockBodyV0 {
        &self.core.body
    }

    pub(crate) const fn execution_receipts(&self) -> &ExecutionReceiptsV0 {
        &self.core.receipts
    }

    pub(crate) const fn preparation_id(&self) -> [u8; 32] {
        self.core.preparation_id
    }

    pub(crate) const fn native_execution_authorization_id(&self) -> [u8; 32] {
        self.core.native_execution_authorization_id
    }

    pub(crate) const fn commitment_authority(
        &self,
    ) -> &AuthorizedPocoPreheaderNextEpochCommitmentV0 {
        &self.commitment_authority
    }

    pub(crate) const fn checkpoint_parent(&self) -> &trnm_consensus_types::CertifiedHeaderV0 {
        self.commitment_authority.checkpoint_parent()
    }
}

/// Private authorization of one exact native checkpoint header/body/receipt
/// tuple. This capability binds the native [`BlockId`] only; it has no CometBFT
/// hash and does not authorize checkpoint finality or a handoff.
#[derive(Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Clone))]
pub(crate) struct AuthorizedPocoCheckpointHeaderV0 {
    prepared: PreparedPocoCheckpointHeaderV0,
    header: BlockHeader,
    validated_commitments: ValidatedCheckpointCommitmentsV0,
    authorization_id: [u8; 32],
}

/// Opaque proof that the exact pre-header tuple has been reserved in the
/// independent preparation sidecar. This capability is intentionally not a
/// proposal, vote, signature, finality, or handoff authorization.
#[derive(Clone, Debug)]
pub(crate) struct DurablyPreparedPocoCheckpointHeaderV0 {
    prepared: PreparedPocoCheckpointHeaderV0,
    reservation: PocoPreparationReservationV0,
}

impl DurablyPreparedPocoCheckpointHeaderV0 {
    pub(crate) const fn fields(&self) -> PocoCheckpointHeaderFieldsV0 {
        self.prepared.fields()
    }

    pub(crate) const fn body(&self) -> &BlockBodyV0 {
        self.prepared.body()
    }

    pub(crate) const fn execution_receipts(&self) -> &ExecutionReceiptsV0 {
        self.prepared.execution_receipts()
    }

    pub(crate) const fn preparation_id(&self) -> [u8; 32] {
        self.prepared.preparation_id()
    }
}

/// Opaque proof that the exact native checkpoint header has also been bound
/// to the already durable preparation slot. The retained reservation prevents
/// accidental cross-sidecar reuse; no signing or activation conversion is
/// exposed.
#[derive(Debug)]
pub(crate) struct DurablyBoundPocoCheckpointHeaderV0 {
    authorized: AuthorizedPocoCheckpointHeaderV0,
    _reservation: PocoPreparationReservationV0,
}

impl DurablyBoundPocoCheckpointHeaderV0 {
    pub(crate) const fn authorized(&self) -> &AuthorizedPocoCheckpointHeaderV0 {
        &self.authorized
    }

    pub(crate) const fn native_block_id(&self) -> BlockId {
        self.authorized.native_block_id()
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorized.authorization_id()
    }
}

impl AuthorizedPocoCheckpointHeaderV0 {
    pub(crate) const fn prepared(&self) -> &PreparedPocoCheckpointHeaderV0 {
        &self.prepared
    }

    pub(crate) const fn header(&self) -> &BlockHeader {
        &self.header
    }

    pub(crate) const fn native_block_id(&self) -> BlockId {
        self.validated_commitments.block_id()
    }

    pub(crate) const fn validated_commitments(&self) -> ValidatedCheckpointCommitmentsV0 {
        self.validated_commitments
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

/// Freezes the exact native checkpoint fields before construction/signing of
/// the checkpoint header. The commitment is never caller supplied: it can only
/// be read from the raw-H1/H2, cutoff-only candidate authority.
///
/// The state roots, payload, and receipts come only from one opaque execution
/// provenance token minted after the authenticated state transition was
/// planned. There is no caller-supplied state root or shape-only execution at
/// this authority boundary.
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_poco_checkpoint_header_v0(
    commitment_authority: AuthorizedPocoPreheaderNextEpochCommitmentV0,
    checkpoint_view: View,
    checkpoint_proposer_id: ValidatorId,
    checkpoint_timestamp_ms: u64,
    native_execution: AuthorizedNativeCheckpointExecutionV0,
    evidence: Vec<DoubleVoteEvidenceV0>,
) -> Result<PreparedPocoCheckpointHeaderV0> {
    let old_validator_set = commitment_authority.old_validator_set().clone();
    let old_parameters = *commitment_authority.old_parameters();
    let scheduled_cutoff = commitment_authority.scheduled_cutoff();
    let commitment = commitment_authority.commitment();
    let checkpoint_parent = commitment_authority.checkpoint_parent().clone();
    let exact_parent_header = checkpoint_parent.header();

    old_validator_set
        .validate_against_parameters(&old_parameters)
        .map_err(|error| anyhow::anyhow!("invalid pre-header old configuration: {error:?}"))?;
    commitment
        .validate_same_version_context(
            &old_validator_set,
            &old_parameters,
            commitment_authority.new_validator_set(),
            commitment_authority.new_parameters(),
        )
        .map_err(|error| anyhow::anyhow!("invalid pre-header commitment context: {error:?}"))?;
    let commitment_fields = commitment.fields();
    ensure!(
        commitment_fields.snapshot_cutoff_height == scheduled_cutoff.cutoff_height()
            && commitment_fields.snapshot_state_root == scheduled_cutoff.cutoff_state_root(),
        "pre-header commitment cutoff differs from scheduled cutoff authority"
    );
    let geometry = EpochGeometryV0::new(old_validator_set.epoch(), &old_parameters)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint geometry: {error:?}"))?;
    ensure!(
        scheduled_cutoff.checkpoint_height() == geometry.checkpoint_height(),
        "scheduled cutoff checkpoint height differs from epoch geometry"
    );
    exact_parent_header
        .validate_shape()
        .map_err(|error| anyhow::anyhow!("invalid exact checkpoint parent header: {error:?}"))?;
    ensure!(
        exact_parent_header.genesis_hash() == old_validator_set.genesis_hash()
            && exact_parent_header.chain_id() == old_validator_set.chain_id()
            && exact_parent_header.protocol_version() == old_validator_set.protocol_version()
            && exact_parent_header.epoch() == old_validator_set.epoch()
            && exact_parent_header.validator_set_id() == old_validator_set.id()
            && exact_parent_header.consensus_parameters_hash() == old_parameters.hash(),
        "checkpoint parent header differs from authenticated old context"
    );
    ensure!(
        exact_parent_header
            .height()
            .get()
            .checked_add(1)
            .is_some_and(|height| height == geometry.checkpoint_height().get()),
        "checkpoint parent height is not immediately before checkpoint"
    );
    ensure!(
        geometry
            .expected_block_kind(exact_parent_header.height())
            .map_err(|error| anyhow::anyhow!("checkpoint parent schedule: {error:?}"))?
            == BlockKind::Regular
            && exact_parent_header.block_kind() == BlockKind::Regular
            && exact_parent_header.next_epoch_commitment_hash().is_none(),
        "checkpoint parent is not the expected commitment-free regular block"
    );
    ensure!(
        native_execution.parent_height() == exact_parent_header.height()
            && native_execution.parent_state_root() == exact_parent_header.state_root()
            && native_execution.target_height() == geometry.checkpoint_height(),
        "authorized native execution is not the exact checkpoint-parent state transition"
    );
    ensure!(
        checkpoint_view.get() > exact_parent_header.view().get(),
        "checkpoint view does not advance beyond parent view"
    );
    let validators = old_validator_set.validators();
    let leader_index = checkpoint_view
        .get()
        .saturating_sub(1)
        .checked_rem(u64::try_from(validators.len()).context("validator count exceeds u64")?)
        .context("checkpoint leader schedule has no validators")?;
    let leader_index = usize::try_from(leader_index).context("leader index exceeds usize")?;
    ensure!(
        validators[leader_index].id() == checkpoint_proposer_id,
        "checkpoint proposer is not the scheduled authenticated old-set leader"
    );
    let maximum_timestamp = exact_parent_header
        .timestamp_ms()
        .checked_add(old_parameters.max_block_time_step_ms())
        .context("checkpoint parent timestamp plus maximum step overflow")?;
    ensure!(
        checkpoint_timestamp_ms > exact_parent_header.timestamp_ms()
            && checkpoint_timestamp_ms <= maximum_timestamp,
        "checkpoint timestamp is outside the parent-relative deterministic bound"
    );

    let body = BlockBodyV0::new(
        native_execution.execution().application_payload().clone(),
        evidence,
    )
    .map_err(|error| anyhow::anyhow!("construct exact checkpoint body: {error:?}"))?;
    body.verify_evidence(&old_validator_set, &StrictEd25519Verifier)
        .map_err(|error| anyhow::anyhow!("strict checkpoint evidence verification: {error:?}"))?;
    let receipts = native_execution.execution().execution_receipts().clone();
    receipts
        .validate_for_payload(body.application_payload())
        .map_err(|error| anyhow::anyhow!("checkpoint receipt/payload relation: {error:?}"))?;

    let fields = PocoCheckpointHeaderFieldsV0 {
        genesis_hash: old_validator_set.genesis_hash(),
        chain_id: old_validator_set.chain_id(),
        protocol_version: old_validator_set.protocol_version(),
        epoch: old_validator_set.epoch(),
        view: checkpoint_view,
        height: geometry.checkpoint_height(),
        parent_id: exact_parent_header.id(),
        proposer_id: checkpoint_proposer_id,
        validator_set_id: old_validator_set.id(),
        consensus_parameters_hash: old_parameters.hash(),
        payload_root: body
            .payload_root()
            .map_err(|error| anyhow::anyhow!("compute checkpoint payload root: {error:?}"))?,
        state_root: native_execution.post_state_root(),
        receipts_root: receipts
            .receipts_root()
            .map_err(|error| anyhow::anyhow!("compute checkpoint receipts root: {error:?}"))?,
        evidence_root: body
            .evidence_root()
            .map_err(|error| anyhow::anyhow!("compute checkpoint evidence root: {error:?}"))?,
        timestamp_ms: checkpoint_timestamp_ms,
        next_epoch_commitment_hash: commitment.id(),
    };
    let transaction_count = body.application_payload().transaction_count();
    let evidence_count =
        u32::try_from(body.evidence().len()).context("checkpoint evidence count exceeds u32")?;
    let replay_fields = fields.replay_fields(transaction_count, evidence_count);
    let preparation_id = poco_checkpoint_preparation_authorization_id_v0(
        commitment_authority.authorization_id(),
        native_execution.authorization_id(),
        &checkpoint_parent
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode certified checkpoint parent: {error:?}"))?,
        &replay_fields,
    );

    Ok(PreparedPocoCheckpointHeaderV0 {
        commitment_authority,
        core: PreparedPocoCheckpointHeaderCoreV0 {
            fields,
            body,
            receipts,
            old_parameters,
            native_execution_authorization_id: native_execution.authorization_id(),
            preparation_id,
        },
    })
}

/// Binds one exact native checkpoint header/body/receipt tuple to a prepared
/// capability. The returned ID is `BlockHeader::id()` and is never compared or
/// relabeled as a CometBFT block hash.
fn bind_prepared_poco_checkpoint_header_v0(
    prepared: PreparedPocoCheckpointHeaderV0,
    exact_header: &BlockHeader,
    exact_body: &BlockBodyV0,
    exact_receipts: &ExecutionReceiptsV0,
) -> Result<AuthorizedPocoCheckpointHeaderV0> {
    let validated_commitments = bind_prepared_poco_checkpoint_header_core_v0(
        &prepared.core,
        exact_header,
        exact_body,
        exact_receipts,
    )?;
    let header_bytes = exact_header
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode exact checkpoint header: {error:?}"))?;
    let native_block_id = validated_commitments.block_id();
    let authorization_id = poco_checkpoint_header_authorization_id_v0(
        prepared.core.preparation_id,
        &header_bytes,
        native_block_id,
    );
    Ok(AuthorizedPocoCheckpointHeaderV0 {
        prepared,
        header: exact_header.clone(),
        validated_commitments,
        authorization_id,
    })
}

/// Test-only raw binding seam used by the isolated fixture authoring module.
/// Production callers must reserve and bind through the durable sidecar APIs.
#[cfg(test)]
pub(crate) fn bind_prepared_poco_checkpoint_header_for_fixture_v0(
    prepared: PreparedPocoCheckpointHeaderV0,
    exact_header: &BlockHeader,
    exact_body: &BlockBodyV0,
    exact_receipts: &ExecutionReceiptsV0,
) -> Result<AuthorizedPocoCheckpointHeaderV0> {
    bind_prepared_poco_checkpoint_header_v0(prepared, exact_header, exact_body, exact_receipts)
}

/// Reserves one exact checkpoint preparation in the independent durable
/// sidecar. Replaying the same record is idempotent. A changed transition
/// binding or a second record for the same `(transition, kind, height, view)`
/// slot durably halts the journal before this function returns an error.
///
/// This function is a narrow host API only. It is deliberately not called by
/// the current ABCI request path because that path has no pre-header native
/// BlockId or safe proposal/signing integration seam.
pub(crate) fn reserve_prepared_poco_checkpoint_header_v0(
    journal: &PocoPreparationJournalV0,
    prepared: PreparedPocoCheckpointHeaderV0,
) -> Result<DurablyPreparedPocoCheckpointHeaderV0> {
    let replay_record = checkpoint_preparation_replay_record_v0(&prepared)?;
    let reservation = journal.reserve(&replay_record)?;
    Ok(DurablyPreparedPocoCheckpointHeaderV0 {
        prepared,
        reservation,
    })
}

/// Binds the exact native header/body/receipts and durably advances the same
/// preparation slot. The authorized header is returned only after both the
/// in-memory exact-value checks and the sidecar transaction succeed.
pub(crate) fn bind_durably_prepared_poco_checkpoint_header_v0(
    journal: &PocoPreparationJournalV0,
    durable: DurablyPreparedPocoCheckpointHeaderV0,
    exact_header: &BlockHeader,
    exact_body: &BlockBodyV0,
    exact_receipts: &ExecutionReceiptsV0,
) -> Result<DurablyBoundPocoCheckpointHeaderV0> {
    let DurablyPreparedPocoCheckpointHeaderV0 {
        prepared,
        reservation,
    } = durable;
    let authorized = bind_prepared_poco_checkpoint_header_v0(
        prepared,
        exact_header,
        exact_body,
        exact_receipts,
    )?;
    let bound_record = PocoCheckpointBoundReplayRecordV0::new(
        exact_header.try_cev0_bytes().map_err(|error| {
            anyhow::anyhow!("encode durably bound checkpoint header: {error:?}")
        })?,
        authorized.native_block_id(),
        authorized.authorization_id(),
    )?;
    journal.bind(&reservation, &bound_record)?;
    Ok(DurablyBoundPocoCheckpointHeaderV0 {
        authorized,
        _reservation: reservation,
    })
}

fn checkpoint_preparation_replay_record_v0(
    prepared: &PreparedPocoCheckpointHeaderV0,
) -> Result<PocoCheckpointPreparationReplayRecordV0> {
    let authority = prepared.commitment_authority();
    let scheduled_cutoff = authority.scheduled_cutoff();
    let old_validator_set = authority.old_validator_set();
    let old_parameters = authority.old_parameters();
    let new_validator_set = authority.new_validator_set();
    let new_parameters = authority.new_parameters();
    let commitment = authority.commitment();
    let fields = prepared.fields();
    let binding = PocoPreparationTransitionBindingV0 {
        genesis_hash: fields.genesis_hash(),
        chain_id: fields.chain_id(),
        protocol_version: fields.protocol_version(),
        old_epoch: fields.epoch(),
        checkpoint_height: fields.height(),
        cutoff_height: scheduled_cutoff.cutoff_height(),
        cutoff_state_root: scheduled_cutoff.cutoff_state_root(),
        cutoff_entries_root: scheduled_cutoff.cutoff_entries_root(),
        cutoff_entry_count: scheduled_cutoff.cutoff_entry_count(),
        old_validator_set_id: old_validator_set.id(),
        old_parameters_hash: old_parameters.hash(),
        new_validator_set_id: new_validator_set.id(),
        new_parameters_hash: new_parameters.hash(),
        commitment_hash: commitment.id(),
        scheduled_cutoff_authorization_id: scheduled_cutoff.authorization_id(),
        commitment_authorization_id: authority.authorization_id(),
        scheduled_cutoff_canonical_bytes: scheduled_cutoff.canonical_bytes(),
        old_validator_set_cev0: old_validator_set
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode journal old validator set: {error:?}"))?,
        old_parameters_cev0: old_parameters.canonical_bytes(),
        new_validator_set_cev0: new_validator_set
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode journal new validator set: {error:?}"))?,
        new_parameters_cev0: new_parameters.canonical_bytes(),
        commitment_cev0: commitment
            .try_cev0_bytes()
            .map_err(|error| anyhow::anyhow!("encode journal next-epoch commitment: {error:?}"))?,
    };
    let checkpoint_parent = prepared.checkpoint_parent();
    let checkpoint_parent_header_cev0 = checkpoint_parent
        .header()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode journal checkpoint parent header: {error:?}"))?;
    let certified_checkpoint_parent_cev0 = checkpoint_parent.try_cev0_bytes().map_err(|error| {
        anyhow::anyhow!("encode journal certified checkpoint parent: {error:?}")
    })?;
    let payload_cev0 = prepared
        .body()
        .application_payload()
        .try_cev0_bytes()
        .map_err(|error| anyhow::anyhow!("encode journal checkpoint payload: {error:?}"))?;
    let evidence_cev0 = prepared
        .body()
        .evidence()
        .iter()
        .map(|evidence| {
            evidence
                .try_cev0_bytes()
                .map_err(|error| anyhow::anyhow!("encode journal checkpoint evidence: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let receipts_cev0 = prepared
        .execution_receipts()
        .receipts()
        .iter()
        .map(|receipt| {
            receipt
                .try_cev0_bytes()
                .map_err(|error| anyhow::anyhow!("encode journal checkpoint receipt: {error:?}"))
        })
        .collect::<Result<Vec<_>>>()?;
    let transaction_count = prepared.body().application_payload().transaction_count();
    let evidence_count = u32::try_from(prepared.body().evidence().len())
        .context("journal checkpoint evidence count exceeds u32")?;
    PocoCheckpointPreparationReplayRecordV0::new(
        binding,
        fields.replay_fields(transaction_count, evidence_count),
        prepared.preparation_id(),
        prepared.native_execution_authorization_id(),
        checkpoint_parent_header_cev0,
        certified_checkpoint_parent_cev0,
        payload_cev0,
        evidence_cev0,
        receipts_cev0,
    )
}

fn bind_prepared_poco_checkpoint_header_core_v0(
    prepared: &PreparedPocoCheckpointHeaderCoreV0,
    exact_header: &BlockHeader,
    exact_body: &BlockBodyV0,
    exact_receipts: &ExecutionReceiptsV0,
) -> Result<ValidatedCheckpointCommitmentsV0> {
    ensure!(
        exact_body == &prepared.body && exact_receipts == &prepared.receipts,
        "exact checkpoint body/receipts differ from prepared native execution"
    );
    let expected_header = prepared.fields.exact_header()?;
    ensure!(
        exact_header == &expected_header,
        "exact checkpoint header differs from prepared fields"
    );
    exact_body
        .validate_checkpoint_static_commitments(
            exact_header,
            exact_receipts,
            &prepared.old_parameters,
            prepared.fields.state_root,
            prepared.fields.next_epoch_commitment_hash,
        )
        .map_err(|error| anyhow::anyhow!("validate exact checkpoint commitments: {error:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        ApplicationPayloadV0, ConsensusParametersV0, ExecutionReceiptCommitmentV0,
    };

    const TEST_CHAIN: ChainId = ChainId::from_static("trnm-preheader-test");

    fn fixture() -> (PreparedPocoCheckpointHeaderCoreV0, BlockHeader) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let payload = ApplicationPayloadV0::new(vec![b"prepared-checkpoint-tx".to_vec()]).unwrap();
        let receipts = ExecutionReceiptsV0::new(
            &payload,
            vec![
                ExecutionReceiptCommitmentV0::for_transaction(&payload, 0, 17, 23, Vec::new())
                    .unwrap(),
            ],
        )
        .unwrap();
        let body = BlockBodyV0::new(payload, Vec::new()).unwrap();
        let fields = PocoCheckpointHeaderFieldsV0 {
            genesis_hash: GenesisHash::new([1; 32]),
            chain_id: TEST_CHAIN,
            protocol_version: ProtocolVersion::V0,
            epoch: Epoch::new(2),
            view: View::new(31),
            height: Height::new(28),
            parent_id: BlockId::new([2; 32]),
            proposer_id: ValidatorId::new([3; 32]),
            validator_set_id: ValidatorSetId::new([4; 32]),
            consensus_parameters_hash: parameters.hash(),
            payload_root: body.payload_root().unwrap(),
            state_root: StateRoot::new([5; 32]),
            receipts_root: receipts.receipts_root().unwrap(),
            evidence_root: body.evidence_root().unwrap(),
            timestamp_ms: 1_000,
            next_epoch_commitment_hash: NextEpochCommitmentHash::new([6; 32]),
        };
        let header = fields.exact_header().unwrap();
        (
            PreparedPocoCheckpointHeaderCoreV0 {
                fields,
                body,
                receipts,
                old_parameters: parameters,
                native_execution_authorization_id: [10; 32],
                preparation_id: [7; 32],
            },
            header,
        )
    }

    #[derive(Default)]
    struct HeaderSubstitutionV0 {
        view: Option<View>,
        kind: Option<BlockKind>,
        parent_id: Option<BlockId>,
        proposer_id: Option<ValidatorId>,
        payload_root: Option<PayloadDigest>,
        state_root: Option<StateRoot>,
        receipts_root: Option<ReceiptsRoot>,
        evidence_root: Option<EvidenceRoot>,
        timestamp_ms: Option<u64>,
        commitment: Option<Option<NextEpochCommitmentHash>>,
    }

    fn substituted_header(
        original: &BlockHeader,
        substitution: HeaderSubstitutionV0,
    ) -> BlockHeader {
        BlockHeader::new(
            original.genesis_hash(),
            original.chain_id(),
            original.protocol_version(),
            original.epoch(),
            substitution.view.unwrap_or(original.view()),
            original.height(),
            substitution.kind.unwrap_or(original.block_kind()),
            substitution.parent_id.unwrap_or(original.parent_id()),
            substitution.proposer_id.unwrap_or(original.proposer_id()),
            original.validator_set_id(),
            original.consensus_parameters_hash(),
            substitution.payload_root.unwrap_or(original.payload_root()),
            substitution.state_root.unwrap_or(original.state_root()),
            substitution
                .receipts_root
                .unwrap_or(original.receipts_root()),
            substitution
                .evidence_root
                .unwrap_or(original.evidence_root()),
            substitution.timestamp_ms.unwrap_or(original.timestamp_ms()),
            substitution
                .commitment
                .unwrap_or(original.next_epoch_commitment_hash()),
        )
        .unwrap()
    }

    fn assert_header_substitution_rejected(
        prepared: &PreparedPocoCheckpointHeaderCoreV0,
        header: &BlockHeader,
    ) {
        let error = bind_prepared_poco_checkpoint_header_core_v0(
            prepared,
            header,
            &prepared.body,
            &prepared.receipts,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "exact checkpoint header differs from prepared fields"
        );
    }

    #[test]
    fn exact_native_checkpoint_header_body_and_receipts_bind() {
        let (prepared, header) = fixture();
        let validated = bind_prepared_poco_checkpoint_header_core_v0(
            &prepared,
            &header,
            &prepared.body,
            &prepared.receipts,
        )
        .unwrap();
        assert_eq!(validated.block_id(), header.id());
        assert_eq!(validated.state_root(), prepared.fields.state_root());
        assert_eq!(
            validated.next_epoch_commitment_hash(),
            prepared.fields.next_epoch_commitment_hash()
        );
    }

    #[test]
    fn root_kind_and_commitment_substitutions_fail_closed() {
        let (prepared, header) = fixture();
        let foreign_root_header = substituted_header(
            &header,
            HeaderSubstitutionV0 {
                payload_root: Some(PayloadDigest::new([8; 32])),
                ..HeaderSubstitutionV0::default()
            },
        );
        assert_header_substitution_rejected(&prepared, &foreign_root_header);

        let regular_header = substituted_header(
            &header,
            HeaderSubstitutionV0 {
                kind: Some(BlockKind::Regular),
                commitment: Some(None),
                ..HeaderSubstitutionV0::default()
            },
        );
        assert_header_substitution_rejected(&prepared, &regular_header);

        let foreign_commitment_header = substituted_header(
            &header,
            HeaderSubstitutionV0 {
                commitment: Some(Some(NextEpochCommitmentHash::new([9; 32]))),
                ..HeaderSubstitutionV0::default()
            },
        );
        assert_header_substitution_rejected(&prepared, &foreign_commitment_header);
    }

    #[test]
    fn parent_view_proposer_and_timestamp_substitutions_fail_at_exact_header_bind() {
        let (prepared, header) = fixture();
        let substitutions = [
            HeaderSubstitutionV0 {
                parent_id: Some(BlockId::new([11; 32])),
                ..HeaderSubstitutionV0::default()
            },
            HeaderSubstitutionV0 {
                view: Some(View::new(header.view().get() + 1)),
                ..HeaderSubstitutionV0::default()
            },
            HeaderSubstitutionV0 {
                proposer_id: Some(ValidatorId::new([12; 32])),
                ..HeaderSubstitutionV0::default()
            },
            HeaderSubstitutionV0 {
                timestamp_ms: Some(header.timestamp_ms() + 1),
                ..HeaderSubstitutionV0::default()
            },
        ];

        for substitution in substitutions {
            let substituted = substituted_header(&header, substitution);
            assert_ne!(substituted, header);
            assert_header_substitution_rejected(&prepared, &substituted);
        }
    }

    #[test]
    fn state_receipts_and_evidence_root_substitutions_fail_at_exact_header_bind() {
        let (prepared, header) = fixture();
        let substitutions = [
            HeaderSubstitutionV0 {
                state_root: Some(StateRoot::new([13; 32])),
                ..HeaderSubstitutionV0::default()
            },
            HeaderSubstitutionV0 {
                receipts_root: Some(ReceiptsRoot::new([14; 32])),
                ..HeaderSubstitutionV0::default()
            },
            HeaderSubstitutionV0 {
                evidence_root: Some(EvidenceRoot::new([15; 32])),
                ..HeaderSubstitutionV0::default()
            },
        ];

        for substitution in substitutions {
            let substituted = substituted_header(&header, substitution);
            assert_ne!(substituted, header);
            assert_header_substitution_rejected(&prepared, &substituted);
        }
    }

    #[test]
    fn canonical_body_and_receipts_toctou_substitutions_fail_at_exact_value_bind() {
        let (prepared, header) = fixture();

        let foreign_body = BlockBodyV0::new(
            ApplicationPayloadV0::new(vec![b"foreign-checkpoint-tx".to_vec()]).unwrap(),
            Vec::new(),
        )
        .unwrap();
        assert_ne!(foreign_body, prepared.body);
        let body_error = bind_prepared_poco_checkpoint_header_core_v0(
            &prepared,
            &header,
            &foreign_body,
            &prepared.receipts,
        )
        .unwrap_err();
        assert_eq!(
            body_error.to_string(),
            "exact checkpoint body/receipts differ from prepared native execution"
        );

        let foreign_receipts = ExecutionReceiptsV0::new(
            prepared.body.application_payload(),
            vec![ExecutionReceiptCommitmentV0::for_transaction(
                prepared.body.application_payload(),
                0,
                19,
                29,
                Vec::new(),
            )
            .unwrap()],
        )
        .unwrap();
        assert_ne!(foreign_receipts, prepared.receipts);
        let receipts_error = bind_prepared_poco_checkpoint_header_core_v0(
            &prepared,
            &header,
            &prepared.body,
            &foreign_receipts,
        )
        .unwrap_err();
        assert_eq!(
            receipts_error.to_string(),
            "exact checkpoint body/receipts differ from prepared native execution"
        );
    }
}
