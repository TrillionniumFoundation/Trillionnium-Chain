//! Native PoCO authorization joins over freshly verified durable application state.
//!
//! Cutoff facts are recovered from the exact committed P snapshot. Preheader
//! execution is recomputed by the live owner; a supplied artifact is accepted
//! only after exact immutable durable readback. None of these capabilities
//! alone establishes consensus finality, signing permission, or activation.

use crate::{
    poco_snapshot::PocoSnapshotEntryKindV0,
    poco_transition::{
        decode_poco_snapshot_value_parts_v0_exact, take_and_validate_production_poco_projection_v0,
        ProductionPocoProjectionV0,
    },
    validator_lifecycle::ConsensusValidatorV1,
    DurableNativeApplicationV0, NativeBlockPreviewRequestV0,
};
use anyhow::{ensure, Context, Result};
use std::{ops::Deref, sync::Arc};
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, ApplicationPayloadV0,
    BlockId, ChainId, ConsensusParametersHash, ConsensusParametersV0, Epoch, EpochGeometryV0,
    ExecutionEventAttributeV0, ExecutionEventV0, ExecutionReceiptCommitmentV0, ExecutionReceiptsV0,
    GenesisHash, Height, PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot, ValidatorSet,
    ValidatorSetId,
};
use trnm_finality_types::{decode_hash32, hash_domain};
use trnm_native_application::{HeightV0, NativeExecutedBlockV0, NativeExecutionReceiptV0};
const MAX_POCO_CHECKPOINT_INPUT_TX_BYTES: usize = 8 * 1024 * 1024;
const SCHEDULED_CUTOFF_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.scheduled-cutoff-authorization.v0";
const NATIVE_CHECKPOINT_EXECUTION_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.authorized-native-checkpoint-execution.v0";
/// Inert, exact preimage of the private scheduled-cutoff authorization seal.
///
/// This value deliberately cannot be converted into
/// [`AuthorizedPocoScheduledCutoffV0`].  It exists so durable replay can
/// exact-decode and compare the bytes emitted by the production authority
/// path without duplicating that path's manual CEV0 framing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PocoScheduledCutoffAuthorizationPreimageV0 {
    pub(crate) genesis_hash: GenesisHash,
    pub(crate) chain_id: ChainId,
    pub(crate) protocol_profile_hash: [u8; 32],
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) epoch: Epoch,
    pub(crate) checkpoint_height: Height,
    pub(crate) cutoff_height: Height,
    pub(crate) cutoff_state_root: StateRoot,
    pub(crate) cutoff_entries_root: [u8; 32],
    pub(crate) cutoff_entry_count: u32,
    pub(crate) old_validator_set_id: ValidatorSetId,
    pub(crate) old_parameters_hash: ConsensusParametersHash,
}

impl PocoScheduledCutoffAuthorizationPreimageV0 {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            !self.genesis_hash.is_zero()
                && !self.old_validator_set_id.is_zero()
                && !self.old_parameters_hash.is_zero()
                && self.protocol_profile_hash != [0; 32],
            "scheduled-cutoff preimage contains a zero consensus identifier"
        );
        ensure!(
            self.protocol_version == ProtocolVersion::V0,
            "scheduled-cutoff preimage is not protocol v0"
        );
        ensure!(
            self.cutoff_height.get() < self.checkpoint_height.get(),
            "scheduled-cutoff height is not before checkpoint"
        );
        ensure!(
            self.cutoff_entry_count > 0,
            "scheduled-cutoff manifest is empty"
        );
        Ok(())
    }

    pub(crate) fn validate_against(
        &self,
        old_validator_set: &ValidatorSet,
        old_parameters: &ConsensusParametersV0,
    ) -> Result<()> {
        self.validate()?;
        old_validator_set
            .validate_against_parameters(old_parameters)
            .map_err(|error| {
                anyhow::anyhow!("invalid scheduled-cutoff configuration: {error:?}")
            })?;
        ensure!(
            self.genesis_hash == old_validator_set.genesis_hash()
                && self.chain_id == old_validator_set.chain_id()
                && self.protocol_version == old_validator_set.protocol_version()
                && self.epoch == old_validator_set.epoch()
                && self.old_validator_set_id == old_validator_set.id()
                && self.old_parameters_hash == old_parameters.hash()
                && self.protocol_profile_hash == *old_parameters.hash().as_bytes(),
            "scheduled-cutoff preimage differs from old configuration"
        );
        let geometry = EpochGeometryV0::new(self.epoch, old_parameters)
            .map_err(|error| anyhow::anyhow!("invalid scheduled-cutoff geometry: {error:?}"))?;
        let cutoff_height = geometry
            .checkpoint_height()
            .get()
            .checked_sub(old_parameters.snapshot_lead_blocks())
            .context("scheduled-cutoff height underflow")?;
        ensure!(
            self.checkpoint_height == geometry.checkpoint_height()
                && self.cutoff_height == Height::new(cutoff_height),
            "scheduled-cutoff preimage differs from authenticated geometry"
        );
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(self.genesis_hash.as_bytes());
        encode_bytes(&mut bytes, self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.protocol_profile_hash);
        bytes.extend_from_slice(&self.protocol_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.epoch.get().to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_height.get().to_be_bytes());
        bytes.extend_from_slice(&self.cutoff_height.get().to_be_bytes());
        bytes.extend_from_slice(self.cutoff_state_root.as_bytes());
        bytes.extend_from_slice(&self.cutoff_entries_root);
        bytes.extend_from_slice(&self.cutoff_entry_count.to_be_bytes());
        bytes.extend_from_slice(self.old_validator_set_id.as_bytes());
        bytes.extend_from_slice(self.old_parameters_hash.as_bytes());
        Ok(bytes)
    }

    pub(crate) fn authorization_id(&self) -> Result<[u8; 32]> {
        Ok(hash_domain(
            SCHEDULED_CUTOFF_AUTHORIZATION_DOMAIN_V0,
            &[&self.canonical_bytes()?],
        ))
    }

    pub(crate) fn decode_exact(bytes: &[u8]) -> Result<Self> {
        struct Decoder<'a> {
            bytes: &'a [u8],
            offset: usize,
        }

        impl<'a> Decoder<'a> {
            fn take(&mut self, length: usize) -> Result<&'a [u8]> {
                let end = self
                    .offset
                    .checked_add(length)
                    .context("scheduled-cutoff decode offset overflow")?;
                ensure!(
                    end <= self.bytes.len(),
                    "truncated scheduled-cutoff preimage"
                );
                let value = &self.bytes[self.offset..end];
                self.offset = end;
                Ok(value)
            }

            fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
                self.take(N)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid scheduled-cutoff fixed field"))
            }

            fn u16(&mut self) -> Result<u16> {
                Ok(u16::from_be_bytes(self.fixed()?))
            }

            fn u32(&mut self) -> Result<u32> {
                Ok(u32::from_be_bytes(self.fixed()?))
            }

            fn u64(&mut self) -> Result<u64> {
                Ok(u64::from_be_bytes(self.fixed()?))
            }
        }

        ensure!(
            bytes.len() <= MAX_POCO_CHECKPOINT_INPUT_TX_BYTES,
            "scheduled-cutoff preimage exceeds replay bound"
        );
        let mut decoder = Decoder { bytes, offset: 0 };
        ensure!(decoder.u16()? == 0, "unsupported scheduled-cutoff schema");
        let genesis_hash = GenesisHash::new(decoder.fixed()?);
        let chain_length = usize::from(decoder.u16()?);
        let chain_id = ChainId::from_bytes(decoder.take(chain_length)?)
            .map_err(|error| anyhow::anyhow!("decode scheduled-cutoff chain ID: {error:?}"))?;
        let value = Self {
            genesis_hash,
            chain_id,
            protocol_profile_hash: decoder.fixed()?,
            protocol_version: ProtocolVersion::new(decoder.u32()?)
                .map_err(|error| anyhow::anyhow!("decode scheduled-cutoff protocol: {error:?}"))?,
            epoch: Epoch::new(decoder.u64()?),
            checkpoint_height: Height::new(decoder.u64()?),
            cutoff_height: Height::new(decoder.u64()?),
            cutoff_state_root: StateRoot::new(decoder.fixed()?),
            cutoff_entries_root: decoder.fixed()?,
            cutoff_entry_count: decoder.u32()?,
            old_validator_set_id: ValidatorSetId::new(decoder.fixed()?),
            old_parameters_hash: ConsensusParametersHash::new(decoder.fixed()?),
        };
        ensure!(
            decoder.offset == bytes.len(),
            "trailing bytes in scheduled-cutoff preimage"
        );
        value.validate()?;
        ensure!(
            value.canonical_bytes()? == bytes,
            "non-canonical scheduled-cutoff preimage"
        );
        Ok(value)
    }
}

/// A manifest height records the JMT version at which the namespace was last
/// changed or explicitly refreshed. It is therefore allowed to lag a later
/// live state version. Checkpoint immutability compares the exact ordered
/// entries, count, and root while deliberately ignoring only that timestamp.
/// The historical cutoff itself is still required to have an exact manifest
/// height by `authorize_poco_checkpoint_execution_v0`.
#[derive(Debug, Clone)]
pub(super) struct PocoProjectionContentV0 {
    projection: Arc<ProductionPocoProjectionV0>,
}

impl Deref for PocoProjectionContentV0 {
    type Target = ProductionPocoProjectionV0;

    fn deref(&self) -> &Self::Target {
        self.projection.as_ref()
    }
}

impl PartialEq for PocoProjectionContentV0 {
    fn eq(&self, other: &Self) -> bool {
        self.manifest().entry_count() == other.manifest().entry_count()
            && self.manifest().entries_root() == other.manifest().entries_root()
            && self.entries() == other.entries()
    }
}

impl Eq for PocoProjectionContentV0 {}

/// Sealed crate-internal join of one authenticated JMT version/root and the
/// exact production PoCO projection decoded from that same tree state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AuthenticatedPocoProjectionAtV0 {
    version: u64,
    state_root: [u8; 32],
    projection: PocoProjectionContentV0,
}

impl AuthenticatedPocoProjectionAtV0 {
    fn from_verified_live_state(
        version: u64,
        state_root: [u8; 32],
        projection: ProductionPocoProjectionV0,
    ) -> Result<Self> {
        ensure!(
            projection.manifest().cutoff_height().get() <= version,
            "production PoCO projection manifest is ahead of state version"
        );
        Ok(Self {
            version,
            state_root,
            projection: PocoProjectionContentV0 {
                projection: Arc::new(projection),
            },
        })
    }

    fn ensure_exact_cutoff(&self, expected_cutoff_height: u64) -> Result<()> {
        ensure!(
            self.version == expected_cutoff_height
                && self.projection.manifest().cutoff_height().get() == expected_cutoff_height,
            "authenticated projection is not the exact scheduled snapshot cutoff"
        );
        Ok(())
    }

    pub(super) const fn version(&self) -> u64 {
        self.version
    }

    pub(super) const fn state_root(&self) -> [u8; 32] {
        self.state_root
    }

    pub(super) const fn projection(&self) -> &PocoProjectionContentV0 {
        &self.projection
    }
}

/// Read the complete historical tree only through its committed durable owner.
/// The returned projection is never reconstructed from caller supplied leaves.
fn authenticated_cutoff_v0(
    application: &DurableNativeApplicationV0,
) -> Result<(AuthenticatedPocoProjectionAtV0, Vec<ConsensusValidatorV1>)> {
    let config = application.config_v0();
    let geometry = EpochGeometryV0::new(
        config.validator_set_v0().epoch(),
        config.consensus_parameters_v0(),
    )
    .map_err(|error| anyhow::anyhow!("cutoff geometry: {error:?}"))?;
    let version = geometry
        .checkpoint_height()
        .get()
        .checked_sub(config.consensus_parameters_v0().snapshot_lead_blocks())
        .context("cutoff height underflow")?;
    let snapshot = application.confirmed_finalized_poco_snapshot_v0(HeightV0::new(version))?;
    let mut live = snapshot.store().verified_live_values_v0(version)?;
    let lifecycle = crate::complete::load_validator_lifecycle_from_live_v0(&live, version)?;
    let projection = take_and_validate_production_poco_projection_v0(version, &mut live)?
        .context("committed cutoff has no authenticated PoCO namespace")?;
    let root = *snapshot
        .read()
        .executed_v0()
        .request()
        .expected()
        .post_state_root()
        .as_bytes();
    Ok((
        AuthenticatedPocoProjectionAtV0::from_verified_live_state(version, root, projection)?,
        lifecycle.active_validators,
    ))
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedPocoScheduledCutoffV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_profile_hash: [u8; 32],
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    checkpoint_height: Height,
    cutoff_height: Height,
    cutoff_state_root: StateRoot,
    cutoff_entries_root: [u8; 32],
    cutoff_entry_count: u32,
    old_validator_set: ValidatorSet,
    old_parameters: ConsensusParametersV0,
    authorization_id: [u8; 32],
}

impl AuthorizedPocoScheduledCutoffV0 {
    fn authorization_preimage(&self) -> PocoScheduledCutoffAuthorizationPreimageV0 {
        PocoScheduledCutoffAuthorizationPreimageV0 {
            genesis_hash: self.genesis_hash,
            chain_id: self.chain_id,
            protocol_profile_hash: self.protocol_profile_hash,
            protocol_version: self.protocol_version,
            epoch: self.epoch,
            checkpoint_height: self.checkpoint_height,
            cutoff_height: self.cutoff_height,
            cutoff_state_root: self.cutoff_state_root,
            cutoff_entries_root: self.cutoff_entries_root,
            cutoff_entry_count: self.cutoff_entry_count,
            old_validator_set_id: self.old_validator_set.id(),
            old_parameters_hash: self.old_parameters.hash(),
        }
    }

    pub(crate) const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub(crate) const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub(crate) const fn protocol_profile_hash(&self) -> [u8; 32] {
        self.protocol_profile_hash
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub(crate) const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(crate) const fn checkpoint_height(&self) -> Height {
        self.checkpoint_height
    }

    pub(crate) const fn cutoff_height(&self) -> Height {
        self.cutoff_height
    }

    pub(crate) const fn cutoff_state_root(&self) -> StateRoot {
        self.cutoff_state_root
    }

    pub(crate) const fn cutoff_entries_root(&self) -> [u8; 32] {
        self.cutoff_entries_root
    }

    pub(crate) const fn cutoff_entry_count(&self) -> u32 {
        self.cutoff_entry_count
    }

    pub(crate) const fn old_validator_set(&self) -> &ValidatorSet {
        &self.old_validator_set
    }

    pub(crate) const fn old_parameters(&self) -> &ConsensusParametersV0 {
        &self.old_parameters
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }

    pub(crate) fn canonical_bytes(&self) -> Vec<u8> {
        self.authorization_preimage()
            .canonical_bytes()
            .expect("production scheduled-cutoff authority stores a validated preimage")
    }
}
pub(crate) fn authorize_poco_scheduled_cutoff_v0(
    application: &DurableNativeApplicationV0,
    cutoff_state: &AuthenticatedPocoProjectionAtV0,
    active_application_validators: &[ConsensusValidatorV1],
) -> Result<AuthorizedPocoScheduledCutoffV0> {
    let config = application.config_v0();
    let chain_id = config.validator_set_v0().chain_id();
    let genesis_hash = config.validator_set_v0().genesis_hash();
    let protocol_profile_hash = *config.consensus_parameters_v0().hash().as_bytes();
    let cutoff_projection = cutoff_state.projection();
    let (old_validator_set, active_parameters) = active_consensus_configuration(cutoff_projection)?;
    ensure!(
        old_validator_set.genesis_hash() == genesis_hash,
        "configured PoCO genesis hash differs from authenticated validator set"
    );
    ensure!(
        old_validator_set.chain_id() == chain_id,
        "configured chain ID differs from authenticated validator set"
    );
    ensure!(
        old_validator_set.protocol_version() == ProtocolVersion::V0
            && active_parameters.protocol_version() == ProtocolVersion::V0.get(),
        "authenticated cutoff configuration is not protocol v0"
    );
    ensure!(
        old_validator_set.consensus_parameters_hash() == active_parameters.hash(),
        "authenticated validator set/parameter hash mismatch"
    );
    ensure!(
        protocol_profile_hash == *active_parameters.hash().as_bytes(),
        "configured protocol profile does not equal authenticated active parameters"
    );
    old_validator_set
        .validate_against_parameters(&active_parameters)
        .map_err(|error| {
            anyhow::anyhow!("invalid authenticated active configuration: {error:?}")
        })?;
    validate_application_validator_projection(&old_validator_set, active_application_validators)?;

    ensure!(
        old_validator_set == *config.validator_set_v0()
            && active_parameters == *config.consensus_parameters_v0(),
        "authenticated cutoff configuration differs from durable owner configuration"
    );
    let geometry = EpochGeometryV0::new(old_validator_set.epoch(), &active_parameters)
        .map_err(|error| anyhow::anyhow!("invalid checkpoint geometry: {error:?}"))?;
    let cutoff_height = geometry
        .checkpoint_height()
        .get()
        .checked_sub(active_parameters.snapshot_lead_blocks())
        .context("snapshot cutoff height underflow")?;
    cutoff_state.ensure_exact_cutoff(cutoff_height)?;

    let mut authorized = AuthorizedPocoScheduledCutoffV0 {
        genesis_hash,
        chain_id,
        protocol_profile_hash,
        protocol_version: ProtocolVersion::V0,
        epoch: old_validator_set.epoch(),
        checkpoint_height: geometry.checkpoint_height(),
        cutoff_height: Height::new(cutoff_height),
        cutoff_state_root: StateRoot::new(cutoff_state.state_root()),
        cutoff_entries_root: cutoff_projection.manifest().entries_root(),
        cutoff_entry_count: cutoff_projection.manifest().entry_count(),
        old_validator_set,
        old_parameters: active_parameters,
        authorization_id: [0; 32],
    };
    authorized.authorization_id = hash_domain(
        SCHEDULED_CUTOFF_AUTHORIZATION_DOMAIN_V0,
        &[&authorized.canonical_bytes()],
    );
    Ok(authorized)
}

/// It intentionally does not by itself validate the cross-entry business
/// state or authorize an epoch transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthorizedPocoCheckpointExecutionV0 {
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_profile_hash: [u8; 32],
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    checkpoint_height: Height,
    checkpoint_block_id: [u8; 32],
    checkpoint_timestamp_ms: u64,
    parent_height: Height,
    parent_state_root: StateRoot,
    cutoff_height: Height,
    cutoff_state_root: StateRoot,
    cutoff_entries_root: [u8; 32],
    cutoff_entry_count: u32,
    payload_root: [u8; 32],
    receipts_root: [u8; 32],
    next_state_root: StateRoot,
    validator_set_id: ValidatorSetId,
    consensus_parameters_hash: ConsensusParametersHash,
    execution_id: [u8; 32],
}

impl AuthorizedPocoCheckpointExecutionV0 {
    pub(crate) const fn genesis_hash(self) -> GenesisHash {
        self.genesis_hash
    }

    pub(crate) const fn chain_id(self) -> ChainId {
        self.chain_id
    }

    pub(crate) const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    pub(crate) const fn epoch(self) -> Epoch {
        self.epoch
    }

    pub(crate) const fn checkpoint_height(self) -> Height {
        self.checkpoint_height
    }

    pub(crate) const fn cutoff_height(self) -> Height {
        self.cutoff_height
    }

    pub(crate) const fn cutoff_state_root(self) -> StateRoot {
        self.cutoff_state_root
    }

    pub(crate) const fn cutoff_entries_root(self) -> [u8; 32] {
        self.cutoff_entries_root
    }

    pub(crate) const fn cutoff_entry_count(self) -> u32 {
        self.cutoff_entry_count
    }

    pub(crate) const fn payload_root(self) -> [u8; 32] {
        self.payload_root
    }

    pub(crate) const fn receipts_root(self) -> [u8; 32] {
        self.receipts_root
    }

    pub(crate) const fn next_state_root(self) -> StateRoot {
        self.next_state_root
    }

    pub(crate) const fn validator_set_id(self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub(crate) const fn consensus_parameters_hash(self) -> ConsensusParametersHash {
        self.consensus_parameters_hash
    }

    pub(crate) const fn execution_id(self) -> [u8; 32] {
        self.execution_id
    }

    pub(crate) fn canonical_bytes(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(self.genesis_hash.as_bytes());
        encode_bytes(&mut bytes, self.chain_id.as_bytes());
        bytes.extend_from_slice(&self.protocol_profile_hash);
        bytes.extend_from_slice(&self.protocol_version.get().to_be_bytes());
        bytes.extend_from_slice(&self.epoch.get().to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_height.get().to_be_bytes());
        bytes.extend_from_slice(&self.checkpoint_block_id);
        bytes.extend_from_slice(&self.checkpoint_timestamp_ms.to_be_bytes());
        bytes.extend_from_slice(&self.parent_height.get().to_be_bytes());
        bytes.extend_from_slice(self.parent_state_root.as_bytes());
        bytes.extend_from_slice(&self.cutoff_height.get().to_be_bytes());
        bytes.extend_from_slice(self.cutoff_state_root.as_bytes());
        bytes.extend_from_slice(&self.cutoff_entries_root);
        bytes.extend_from_slice(&self.cutoff_entry_count.to_be_bytes());
        bytes.extend_from_slice(&self.payload_root);
        bytes.extend_from_slice(&self.receipts_root);
        bytes.extend_from_slice(self.next_state_root.as_bytes());
        bytes.extend_from_slice(self.validator_set_id.as_bytes());
        bytes.extend_from_slice(self.consensus_parameters_hash.as_bytes());
        bytes
    }
}

pub(crate) fn authorize_poco_checkpoint_execution_v0(
    application: &DurableNativeApplicationV0,
    executed: &NativeExecutedBlockV0,
    cutoff_state: &AuthenticatedPocoProjectionAtV0,
    active_application_validators: &[ConsensusValidatorV1],
) -> Result<AuthorizedPocoCheckpointExecutionV0> {
    // Public artifacts are inert: mint only after exact fresh durable-P readback.
    let _confirmed_row = application.confirm_durable_execution_history_row_v0(executed)?;
    let input = executed.request();
    let cutoff_authority = authorize_poco_scheduled_cutoff_v0(
        application,
        cutoff_state,
        active_application_validators,
    )?;
    ensure!(
        cutoff_authority.checkpoint_height().get() == input.height().get(),
        "durable execution is not the scheduled checkpoint"
    );
    let mut value = AuthorizedPocoCheckpointExecutionV0 {
        genesis_hash: cutoff_authority.genesis_hash(),
        chain_id: cutoff_authority.chain_id(),
        protocol_profile_hash: cutoff_authority.protocol_profile_hash(),
        protocol_version: cutoff_authority.protocol_version(),
        epoch: cutoff_authority.epoch(),
        checkpoint_height: Height::new(input.height().get()),
        checkpoint_block_id: *input.block_id().as_bytes(),
        checkpoint_timestamp_ms: input.timestamp_ms(),
        parent_height: Height::new(input.parent().height().get()),
        parent_state_root: StateRoot::new(*input.parent().state_root().as_bytes()),
        cutoff_height: cutoff_authority.cutoff_height(),
        cutoff_state_root: cutoff_authority.cutoff_state_root(),
        cutoff_entries_root: cutoff_authority.cutoff_entries_root(),
        cutoff_entry_count: cutoff_authority.cutoff_entry_count(),
        payload_root: *input.expected().payload_root().as_bytes(),
        receipts_root: *input.expected().receipts_root().as_bytes(),
        next_state_root: StateRoot::new(*input.expected().post_state_root().as_bytes()),
        validator_set_id: cutoff_authority.old_validator_set().id(),
        consensus_parameters_hash: cutoff_authority.old_parameters().hash(),
        execution_id: [0; 32],
    };
    value.execution_id = hash_domain(
        "trnm.poco-bft.checkpoint-execution-id.v0",
        &[&value.canonical_bytes()],
    );
    Ok(value)
}

pub(crate) fn authorize_poco_checkpoint_candidate_selection_v0(
    application: &DurableNativeApplicationV0,
    executed: &NativeExecutedBlockV0,
) -> Result<crate::poco_application::AuthenticatedPocoCandidateSelectionV0> {
    let (cutoff_state, validators) = authenticated_cutoff_v0(application)?;
    let checkpoint =
        authorize_poco_checkpoint_execution_v0(application, executed, &cutoff_state, &validators)?;
    crate::poco_application::authorize_authenticated_poco_candidate_selection_v0(
        checkpoint,
        &cutoff_state,
    )
}

pub(crate) fn authorize_poco_cutoff_candidate_selection_v0(
    application: &DurableNativeApplicationV0,
) -> Result<crate::poco_application::AuthenticatedPocoCutoffCandidateSelectionV0> {
    let (cutoff_state, validators) = authenticated_cutoff_v0(application)?;
    let cutoff = authorize_poco_scheduled_cutoff_v0(application, &cutoff_state, &validators)?;
    crate::poco_application::authorize_authenticated_poco_cutoff_candidate_selection_v0(
        cutoff,
        &cutoff_state,
    )
}
pub(crate) fn active_consensus_configuration(
    projection: &ProductionPocoProjectionV0,
) -> Result<(ValidatorSet, ConsensusParametersV0)> {
    let mut old_set = None;
    let mut active_parameters = None;
    for entry in projection.entries() {
        if !matches!(
            entry.kind,
            PocoSnapshotEntryKindV0::ValidatorConfiguration
                | PocoSnapshotEntryKindV0::ConsensusParameters
        ) {
            continue;
        }
        let parts = decode_poco_snapshot_value_parts_v0_exact(
            entry.kind,
            &entry.logical_key,
            &entry.value,
        )?;
        ensure!(
            parts.identity.len() == 9,
            "configuration identity width drift"
        );
        let role = parts.identity[0];
        let identity_epoch = u64::from_be_bytes(
            parts.identity[1..]
                .try_into()
                .expect("configuration identity width checked"),
        );
        match entry.kind {
            PocoSnapshotEntryKindV0::ValidatorConfiguration if role == 1 => {
                ensure!(old_set.is_none(), "duplicate old validator configuration");
                let set = decode_validator_set_v0_exact(parts.payload)
                    .map_err(|error| anyhow::anyhow!("decode old validator set: {error:?}"))?;
                ensure!(
                    set.epoch().get() == identity_epoch,
                    "old set epoch mismatch"
                );
                old_set = Some(set);
            }
            PocoSnapshotEntryKindV0::ConsensusParameters if role == 1 => {
                ensure!(active_parameters.is_none(), "duplicate active parameters");
                let parameters = decode_consensus_parameters_v0_exact(parts.payload)
                    .map_err(|error| anyhow::anyhow!("decode active parameters: {error:?}"))?;
                active_parameters = Some((identity_epoch, parameters));
            }
            _ => {}
        }
    }
    let old_set = old_set.context("authenticated cutoff lacks old validator configuration")?;
    let (parameter_epoch, parameters) =
        active_parameters.context("authenticated cutoff lacks active parameters")?;
    ensure!(
        parameter_epoch == old_set.epoch().get(),
        "active parameter epoch differs from old validator set"
    );
    Ok((old_set, parameters))
}

pub(crate) fn validate_application_validator_projection(
    set: &ValidatorSet,
    application: &[ConsensusValidatorV1],
) -> Result<()> {
    let mut expected = set
        .validators()
        .iter()
        .map(|validator| {
            (
                *validator.consensus_key().as_bytes(),
                validator.voting_power().get(),
            )
        })
        .collect::<Vec<_>>();
    expected.sort_unstable();
    let mut actual = application
        .iter()
        .map(|validator| {
            let key: [u8; 32] = decode_hash32(
                "application validator public key",
                &validator.public_key_hex,
            )?;
            Ok((key, validator.voting_power))
        })
        .collect::<Result<Vec<_>>>()?;
    actual.sort_unstable();
    ensure!(
        actual == expected,
        "application validator lifecycle differs from authenticated PoCO old set"
    );
    Ok(())
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("consensus chain ID bound fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeBlockExecutionV0 {
    application_payload: ApplicationPayloadV0,
    execution_receipts: ExecutionReceiptsV0,
}
impl NativeBlockExecutionV0 {
    pub(crate) const fn application_payload(&self) -> &ApplicationPayloadV0 {
        &self.application_payload
    }
    pub(crate) const fn execution_receipts(&self) -> &ExecutionReceiptsV0 {
        &self.execution_receipts
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedNativeCheckpointExecutionV0 {
    parent_id: BlockId,
    timestamp_ms: u64,
    parent_height: Height,
    parent_state_root: StateRoot,
    target_height: Height,
    post_state_root: StateRoot,
    execution: NativeBlockExecutionV0,
    authorization_id: [u8; 32],
}

impl AuthorizedNativeCheckpointExecutionV0 {
    pub(crate) const fn parent_id(&self) -> BlockId {
        self.parent_id
    }
    pub(crate) const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub(crate) const fn parent_height(&self) -> Height {
        self.parent_height
    }

    pub(crate) const fn parent_state_root(&self) -> StateRoot {
        self.parent_state_root
    }

    pub(crate) const fn target_height(&self) -> Height {
        self.target_height
    }

    pub(crate) const fn post_state_root(&self) -> StateRoot {
        self.post_state_root
    }

    pub(crate) const fn execution(&self) -> &NativeBlockExecutionV0 {
        &self.execution
    }

    pub(crate) const fn authorization_id(&self) -> [u8; 32] {
        self.authorization_id
    }
}

/// Deterministically execute against the live owner's authenticated parent.
/// The inert public preview type is deliberately not an authorization input.
pub(crate) fn authorize_native_checkpoint_execution_v0(
    application: &DurableNativeApplicationV0,
    request: &NativeBlockPreviewRequestV0,
) -> Result<AuthorizedNativeCheckpointExecutionV0> {
    let (expected_payload, expected_receipts, expected_state, execution) =
        if application.confirmed_committed_head_v0()?.height().get() >= request.height().get() {
            // Recovery uses the exact committed P and reconstructed snapshot.
            // A historical parent is intentionally not a new live preview.
            let read = application.read_finalized_by_height_v0(request.height())?;
            let persisted = read.executed_v0().request();
            ensure!(
                persisted.chain_id() == request.chain_id()
                    && persisted.genesis_hash() == request.genesis_hash()
                    && persisted.parent() == request.parent()
                    && persisted.height() == request.height()
                    && persisted.timestamp_ms() == request.timestamp_ms()
                    && persisted.active_validator_set_id() == request.active_validator_set_id()
                    && persisted.transactions() == request.transactions(),
                "recovery request differs from exact committed native execution"
            );
            (
                persisted.expected().payload_root(),
                persisted.expected().receipts_root(),
                persisted.expected().post_state_root(),
                native_execution_from_receipts_v0(
                    persisted.transactions(),
                    read.executed_v0().receipts(),
                )?,
            )
        } else {
            let preview = application.preview_block_v0(request)?;
            (
                preview.payload_root(),
                preview.receipts_root(),
                preview.post_state_root(),
                native_execution_from_receipts_v0(request.transactions(), preview.receipts())?,
            )
        };
    let parent_height = Height::new(request.parent().height().get());
    let target_height = Height::new(request.height().get());
    let parent_state_root = StateRoot::new(*request.parent().state_root().as_bytes());
    let post_state_root = StateRoot::new(*expected_state.as_bytes());
    let payload_root = execution
        .application_payload
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("native payload encoding: {e:?}"))?;
    let receipts_bytes = execution
        .execution_receipts
        .try_cev0_bytes()
        .map_err(|e| anyhow::anyhow!("native receipt encoding: {e:?}"))?;
    let payload_digest = execution
        .application_payload
        .payload_root()
        .map_err(|e| anyhow::anyhow!("native payload digest: {e:?}"))?;
    let receipts_root = execution
        .execution_receipts
        .receipts_root()
        .map_err(|e| anyhow::anyhow!("native receipt root: {e:?}"))?;
    ensure!(
        payload_digest.as_bytes() == expected_payload.as_bytes()
            && receipts_root.as_bytes() == expected_receipts.as_bytes(),
        "native execution receipt reconstruction differs from live preview"
    );
    let authorization_id = native_checkpoint_execution_authorization_id_v0(
        parent_height,
        parent_state_root,
        target_height,
        post_state_root,
        payload_digest,
        receipts_root,
        &payload_root,
        &receipts_bytes,
    );
    Ok(AuthorizedNativeCheckpointExecutionV0 {
        parent_id: BlockId::new(*request.parent().block_id().as_bytes()),
        timestamp_ms: request.timestamp_ms(),
        parent_height,
        parent_state_root,
        target_height,
        post_state_root,
        execution,
        authorization_id,
    })
}

pub(crate) fn native_execution_from_receipts_v0(
    transactions: &[Vec<u8>],
    receipts: &[NativeExecutionReceiptV0],
) -> Result<NativeBlockExecutionV0> {
    let application_payload = ApplicationPayloadV0::new(transactions.to_vec())
        .map_err(|e| anyhow::anyhow!("native payload: {e:?}"))?;
    ensure!(
        transactions.len() == receipts.len(),
        "native receipt cardinality mismatch"
    );
    let commitments = receipts
        .iter()
        .enumerate()
        .map(|(index, receipt)| {
            ensure!(
                usize::try_from(receipt.transaction_index()).ok() == Some(index),
                "native receipt order mismatch"
            );
            let events = receipt
                .events()
                .iter()
                .map(|event| {
                    let attributes = event
                        .attributes()
                        .iter()
                        .map(|attribute| {
                            ExecutionEventAttributeV0::new(
                                attribute.key().as_bytes().to_vec(),
                                attribute.value().as_bytes().to_vec(),
                            )
                            .map_err(|e| anyhow::anyhow!("native event attribute: {e:?}"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    ExecutionEventV0::new(event.kind().as_bytes().to_vec(), attributes)
                        .map_err(|e| anyhow::anyhow!("native event: {e:?}"))
                })
                .collect::<Result<Vec<_>>>()?;
            let commitment = ExecutionReceiptCommitmentV0::for_transaction(
                &application_payload,
                receipt.transaction_index(),
                receipt.gas_used(),
                receipt.fee_charged(),
                events,
            )
            .map_err(|e| anyhow::anyhow!("native receipt: {e:?}"))?;
            let exact = commitment
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("native receipt encoding: {e:?}"))?;
            ensure!(
                commitment.payload_leaf_hash() == receipt.transaction_digest().as_bytes()
                    && hash_domain("trnm.native-application.execution-receipt.v0", &[&exact])
                        == *receipt.commitment().as_bytes(),
                "native receipt commitment mismatch"
            );
            Ok(commitment)
        })
        .collect::<Result<Vec<_>>>()?;
    let execution_receipts = ExecutionReceiptsV0::new(&application_payload, commitments)
        .map_err(|e| anyhow::anyhow!("native receipts: {e:?}"))?;
    Ok(NativeBlockExecutionV0 {
        application_payload,
        execution_receipts,
    })
}
/// Recomputes the private native-execution seal from the exact canonical
/// inputs retained by the live authority and durable replay paths. The digest
/// is inert comparison material and cannot construct execution authority.
#[allow(clippy::too_many_arguments)]
pub(crate) fn native_checkpoint_execution_authorization_id_v0(
    parent_height: Height,
    parent_state_root: StateRoot,
    target_height: Height,
    post_state_root: StateRoot,
    payload_root: PayloadDigest,
    receipts_root: ReceiptsRoot,
    payload_cev0: &[u8],
    receipts_cev0: &[u8],
) -> [u8; 32] {
    hash_domain(
        NATIVE_CHECKPOINT_EXECUTION_AUTHORIZATION_DOMAIN_V0,
        &[
            &parent_height.get().to_be_bytes(),
            parent_state_root.as_bytes(),
            &target_height.get().to_be_bytes(),
            post_state_root.as_bytes(),
            payload_root.as_bytes(),
            receipts_root.as_bytes(),
            payload_cev0,
            receipts_cev0,
        ],
    )
}

/// An exact native checkpoint prepared and bound in the durable preparation
/// journal. It is not a vote permit or evidence that the block was committed.
#[derive(Debug)]
#[must_use]
pub struct PreparedNativePocoCheckpointV0 {
    bound: crate::poco_checkpoint_header::DurablyBoundPocoCheckpointHeaderV0,
    raw_cutoff_proof: Vec<u8>,
    raw_cutoff_parent: Vec<u8>,
}
impl PreparedNativePocoCheckpointV0 {
    pub fn header(&self) -> &trnm_consensus_types::BlockHeader {
        self.bound.authorized().header()
    }
    pub fn body(&self) -> &trnm_consensus_types::BlockBodyV0 {
        self.bound.authorized().prepared().body()
    }
    pub fn receipts(&self) -> &ExecutionReceiptsV0 {
        self.bound.authorized().prepared().execution_receipts()
    }
}

/// Fresh actual P joined to the exact journal-bound checkpoint, before voting.
/// It borrows that preparation so the retained reservation cannot be replaced.
/// This is not a committed checkpoint or an independent Core Valid permit.
#[must_use]
pub struct PreparedCheckpointExecutionReceiptV1<'a> {
    prepared: &'a PreparedNativePocoCheckpointV0,
    row: crate::ConfirmedDurableExecutionHistoryRowV0,
}
impl PreparedCheckpointExecutionReceiptV1<'_> {
    pub fn header(&self) -> &trnm_consensus_types::BlockHeader {
        self.prepared.header()
    }
    pub fn durable_row(&self) -> &crate::ConfirmedDurableExecutionHistoryRowV0 {
        &self.row
    }
    pub fn validated_commitments(&self) -> trnm_consensus_types::ValidatedCheckpointCommitmentsV0 {
        self.prepared.bound.authorized().validated_commitments()
    }
    pub fn old_validator_set(&self) -> &ValidatorSet {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .old_validator_set()
    }
    pub fn new_validator_set(&self) -> &ValidatorSet {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .new_validator_set()
    }
    pub fn old_parameters(&self) -> &ConsensusParametersV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .old_parameters()
    }
    pub fn new_parameters(&self) -> &ConsensusParametersV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .new_parameters()
    }
    pub fn next_epoch_commitment(&self) -> trnm_consensus_types::NextEpochCommitmentV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .commitment()
    }
}

/// Exact committed checkpoint and strictly verified old-set two-seal finality.
/// This receipt deliberately precedes the joint handoff certificate. It does
/// not authorize signing: the signer still authenticates its own role, key,
/// intent and durable anti-equivocation state.
#[must_use]
pub struct PreHandoffCheckpointReceiptV1 {
    prepared: PreparedNativePocoCheckpointV0,
    read: crate::FinalizedNativeApplicationReadV0,
    checkpoint_finality: trnm_consensus_types::FinalityProofV0,
    post_execution_authorization_id: [u8; 32],
}

impl PreHandoffCheckpointReceiptV1 {
    /// Comparison digest of the exact committed native owner cut. This does
    /// not authorize activation/signing and must be joined to fresh owner readback.
    pub fn committed_owner_cut_ref_v1(&self) -> [u8; 32] {
        let row = self.durable_row();
        let header = self.header();
        let sequence = row
            .commit_sequence_v0()
            .expect("pre-handoff receipt retains an actual COMMITTED row");
        trnm_finality_types::hash_domain(
            "trnm.native-application.committed-owner-cut.v1",
            &[
                &row.store_id_v0(),
                &row.p_sequence_v0().to_be_bytes(),
                &row.p_digest_v0(),
                &row.artifact_digest_v0(),
                &row.overlay_digest_v0(),
                &sequence.to_be_bytes(),
                header.id().as_bytes(),
                &header.height().get().to_be_bytes(),
                header.state_root().as_bytes(),
                header.receipts_root().as_bytes(),
                &self.post_execution_authorization_id,
            ],
        )
    }

    pub fn header(&self) -> &trnm_consensus_types::BlockHeader {
        self.prepared.header()
    }

    pub fn durable_row(&self) -> &crate::ConfirmedDurableExecutionHistoryRowV0 {
        self.read.durable_row_v0()
    }

    pub fn checkpoint_finality(&self) -> &trnm_consensus_types::FinalityProofV0 {
        &self.checkpoint_finality
    }

    pub fn next_epoch_commitment(&self) -> trnm_consensus_types::NextEpochCommitmentV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .commitment()
    }

    pub fn old_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .old_validator_set()
    }

    pub fn old_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .old_parameters()
    }

    pub fn new_validator_set(&self) -> &trnm_consensus_types::ValidatorSet {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .new_validator_set()
    }

    pub fn new_parameters(&self) -> &trnm_consensus_types::ConsensusParametersV0 {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority()
            .new_parameters()
    }

    pub fn checkpoint_parent_header(&self) -> &trnm_consensus_types::BlockHeader {
        self.prepared
            .bound
            .authorized()
            .prepared()
            .checkpoint_parent()
            .header()
    }

    pub fn post_execution_authorization_id(&self) -> [u8; 32] {
        self.post_execution_authorization_id
    }
}

/// A committed native checkpoint joined to freshly verified raw H1/H2,
/// candidate derivation, checkpoint seals and handoff evidence. Its private
/// fields retain the exact durable owner-affine readback. This is not an
/// activation or signing permit; the consensus consumer must independently
/// verify its transition evidence and persist its own safety state.
#[must_use]
pub struct ConfirmedNativePocoCheckpointV0 {
    read: crate::FinalizedNativeApplicationReadV0,
    handoff: crate::poco_joint_handoff::AuthorizedPocoJointHandoffV0,
    post_execution_authorization_id: [u8; 32],
    pub(crate) old_validator_set: ValidatorSet,
    pub(crate) old_parameters: ConsensusParametersV0,
    pub(crate) new_validator_set: ValidatorSet,
    pub(crate) new_parameters: ConsensusParametersV0,
    pub(crate) recovery_evidence: crate::epoch_recovery::EpochRecoveryEvidenceV1,
}
impl ConfirmedNativePocoCheckpointV0 {
    pub fn header(&self) -> &trnm_consensus_types::BlockHeader {
        self.handoff.checkpoint_header()
    }
    pub fn durable_row(&self) -> &crate::ConfirmedDurableExecutionHistoryRowV0 {
        self.read.durable_row_v0()
    }
    pub fn executed(&self) -> &NativeExecutedBlockV0 {
        self.read.executed_v0()
    }
    pub fn handoff_authorization_id(&self) -> [u8; 32] {
        self.handoff.authorization_id()
    }
    pub fn post_execution_authorization_id(&self) -> [u8; 32] {
        self.post_execution_authorization_id
    }

    pub(crate) fn terminal_old_header(&self) -> &trnm_consensus_types::BlockHeader {
        self.handoff.terminal_old_header()
    }

    pub fn into_epoch_application_edge_v1(
        self,
    ) -> Result<crate::AuthenticatedEpochApplicationEdgeV1> {
        crate::AuthenticatedEpochApplicationEdgeV1::from_confirmed_checkpoint(self)
    }
}

impl DurableNativeApplicationV0 {
    pub fn confirm_prepared_checkpoint_execution_v1<'a>(
        &self,
        prepared: &'a PreparedNativePocoCheckpointV0,
        executed: &NativeExecutedBlockV0,
    ) -> Result<PreparedCheckpointExecutionReceiptV1<'a>> {
        let journal = self.poco_preparation_journal_v0()?;
        crate::poco_checkpoint_header::revalidate_durably_bound_poco_checkpoint_header_v0(
            &journal,
            &prepared.bound,
        )?;
        let row = self.confirm_durable_execution_history_row_v0(executed)?;
        let request = executed.request();
        let header = prepared.header();
        ensure!(
            request.chain_id().as_str() == header.chain_id().as_str()
                && request.genesis_hash().as_bytes() == header.genesis_hash().as_bytes()
                && request.block_id().as_bytes() == header.id().as_bytes()
                && request.height().get() == header.height().get()
                && request.parent().block_id().as_bytes() == header.parent_id().as_bytes()
                && request.timestamp_ms() == header.timestamp_ms()
                && request.active_validator_set_id().as_bytes()
                    == header.validator_set_id().as_bytes()
                && request.expected().payload_root().as_bytes() == header.payload_root().as_bytes()
                && request.expected().post_state_root().as_bytes()
                    == header.state_root().as_bytes()
                && request.expected().receipts_root().as_bytes()
                    == header.receipts_root().as_bytes()
                && request.expected().evidence_root().as_bytes()
                    == header.evidence_root().as_bytes(),
            "persisted checkpoint execution differs from journal-bound header"
        );
        let exact = native_execution_from_receipts_v0(request.transactions(), executed.receipts())?;
        ensure!(
            exact.application_payload() == prepared.body().application_payload()
                && exact.execution_receipts() == prepared.receipts(),
            "checkpoint body/receipt substitution"
        );
        crate::poco_checkpoint_header::revalidate_durably_bound_poco_checkpoint_header_v0(
            &journal,
            &prepared.bound,
        )?;
        ensure!(
            row.belongs_to_application_at_path_v0(self, self.path()),
            "checkpoint P owner replaced"
        );
        Ok(PreparedCheckpointExecutionReceiptV1 { prepared, row })
    }
    /// Rebuild the cutoff proof from this owner's committed JMT, strictly
    /// verify the supplied raw finality chain, execute the exact request, and
    /// reserve/bind its complete native checkpoint header before returning.
    pub fn prepare_native_poco_checkpoint_v0(
        &self,
        request: &NativeBlockPreviewRequestV0,
        view: trnm_consensus_types::View,
        proposer: trnm_consensus_types::ValidatorId,
        raw_cutoff_proof: &[u8],
        raw_cutoff_parent: &[u8],
    ) -> Result<PreparedNativePocoCheckpointV0> {
        use crate::poco_checkpoint_header::{
            bind_durably_prepared_poco_checkpoint_header_v0, prepare_poco_checkpoint_header_v0,
            reserve_prepared_poco_checkpoint_header_v0,
        };
        let candidate = authorize_poco_cutoff_candidate_selection_v0(self)?;
        let namespace = cutoff_namespace_proof_v0(self)?;
        let commitment =
            crate::poco_epoch_commitment::authorize_poco_preheader_next_epoch_commitment_v0(
                candidate,
                raw_cutoff_proof,
                raw_cutoff_parent,
                &namespace,
            )?;
        let native = authorize_native_checkpoint_execution_v0(self, request)?;
        let prepared = prepare_poco_checkpoint_header_v0(
            commitment,
            view,
            proposer,
            request.timestamp_ms(),
            native,
            Vec::new(),
        )?;
        let journal = self.poco_preparation_journal_v0()?;
        let durable = reserve_prepared_poco_checkpoint_header_v0(&journal, prepared)?;
        let header = durable.fields().exact_header()?;
        let body = durable.body().clone();
        let receipts = durable.execution_receipts().clone();
        let bound = bind_durably_prepared_poco_checkpoint_header_v0(
            &journal, durable, &header, &body, &receipts,
        )?;
        Ok(PreparedNativePocoCheckpointV0 {
            bound,
            raw_cutoff_proof: raw_cutoff_proof.to_vec(),
            raw_cutoff_parent: raw_cutoff_parent.to_vec(),
        })
    }

    /// Issue a pre-certificate receipt only after exact committed execution,
    /// cutoff-derived configuration reconstruction and strict two-seal finality.
    /// No joint certificate is accepted or required by this entry point.
    pub fn confirm_pre_handoff_checkpoint_v1(
        &self,
        prepared: PreparedNativePocoCheckpointV0,
        raw_checkpoint_two_seal_finality: &[u8],
    ) -> Result<PreHandoffCheckpointReceiptV1> {
        let journal = self.poco_preparation_journal_v0()?;
        crate::poco_checkpoint_header::revalidate_durably_bound_poco_checkpoint_header_v0(
            &journal,
            &prepared.bound,
        )?;
        let header = prepared.header();
        let read = self.read_finalized_by_height_v0(HeightV0::new(header.height().get()))?;
        let execution = read.executed_v0();
        let input = execution.request();
        ensure!(
            input.block_id().as_bytes() == header.id().as_bytes()
                && input.parent().block_id().as_bytes() == header.parent_id().as_bytes()
                && input.timestamp_ms() == header.timestamp_ms()
                && input.expected().post_state_root().as_bytes() == header.state_root().as_bytes()
                && input.expected().payload_root().as_bytes() == header.payload_root().as_bytes()
                && input.expected().receipts_root().as_bytes() == header.receipts_root().as_bytes()
                && input.expected().evidence_root().as_bytes() == header.evidence_root().as_bytes(),
            "committed native execution differs from bound checkpoint header"
        );
        let exact = native_execution_from_receipts_v0(input.transactions(), execution.receipts())?;
        ensure!(
            exact.application_payload() == prepared.body().application_payload()
                && exact.execution_receipts() == prepared.receipts(),
            "committed checkpoint payload or receipts changed since preparation"
        );
        let candidate = authorize_poco_checkpoint_candidate_selection_v0(self, execution)?;
        let namespace = cutoff_namespace_proof_v0(self)?;
        let commitment = crate::poco_epoch_commitment::authorize_poco_next_epoch_commitment_v0(
            candidate,
            &prepared.raw_cutoff_proof,
            &prepared.raw_cutoff_parent,
            &namespace,
        )?;
        let preheader = prepared
            .bound
            .authorized()
            .prepared()
            .commitment_authority();
        let checkpoint = commitment.candidate().checkpoint_execution();
        ensure!(
            checkpoint.checkpoint_height() == header.height()
                && checkpoint.payload_root() == *header.payload_root().as_bytes()
                && checkpoint.receipts_root() == *header.receipts_root().as_bytes()
                && checkpoint.next_state_root() == header.state_root()
                && checkpoint.execution_id() != [0; 32],
            "post-execution checkpoint capability differs from complete bound header"
        );
        ensure!(
            commitment.commitment() == preheader.commitment()
                && commitment.cutoff_parent_header() == preheader.cutoff_parent_header()
                && commitment.checkpoint_parent() == preheader.checkpoint_parent()
                && commitment.finalized_cutoff() == preheader.finalized_cutoff()
                && commitment.old_validator_set() == preheader.old_validator_set()
                && commitment.old_parameters() == preheader.old_parameters()
                && commitment.new_validator_set() == preheader.new_validator_set()
                && commitment.new_parameters() == preheader.new_parameters(),
            "post-execution next-epoch commitment differs from preheader authority"
        );
        let post_execution_authorization_id = commitment.authorization_id();
        let checkpoint_parent = prepared
            .bound
            .authorized()
            .prepared()
            .checkpoint_parent()
            .header();
        let checkpoint_finality = trnm_consensus_types::decode_checkpoint_finality_proof_v0_exact(
            raw_checkpoint_two_seal_finality,
            commitment.old_validator_set(),
            commitment.old_parameters(),
            &commitment.commitment(),
            checkpoint_parent.timestamp_ms(),
        )
        .map_err(|e| anyhow::anyhow!("decode pre-handoff checkpoint finality: {e:?}"))?;
        ensure!(
            checkpoint_finality.finalized_block().header() == header,
            "pre-handoff finality does not name the committed checkpoint"
        );
        let justify = checkpoint_finality
            .finalized_block()
            .justify_qc()
            .as_ordinary()
            .context("pre-handoff checkpoint justify is not ordinary")?;
        ensure!(
            justify.block_id() == checkpoint_parent.id()
                && justify.height() == checkpoint_parent.height()
                && justify.view() == checkpoint_parent.view(),
            "pre-handoff checkpoint parent differs from authenticated parent"
        );
        checkpoint_finality
            .verify_checkpoint_two_seal_kernel(
                commitment.old_validator_set(),
                commitment.old_parameters(),
                &commitment.commitment(),
                checkpoint_parent.timestamp_ms(),
                &trnm_consensus_crypto::StrictEd25519Verifier,
            )
            .map_err(|e| anyhow::anyhow!("strict pre-handoff checkpoint finality: {e}"))?;
        Ok(PreHandoffCheckpointReceiptV1 {
            prepared,
            read,
            checkpoint_finality,
            post_execution_authorization_id,
        })
    }

    /// Confirm the joint handoff only after issuing the independent committed
    /// checkpoint receipt. The ordinary public API retains its exact inputs.
    pub fn confirm_poco_checkpoint_v0(
        &self,
        prepared: PreparedNativePocoCheckpointV0,
        raw_checkpoint_two_seal_finality: &[u8],
        raw_anchor_certificate_kernel: &[u8],
    ) -> Result<ConfirmedNativePocoCheckpointV0> {
        let receipt =
            self.confirm_pre_handoff_checkpoint_v1(prepared, raw_checkpoint_two_seal_finality)?;
        let old_validator_set = receipt.old_validator_set().clone();
        let old_parameters = *receipt.old_parameters();
        let new_validator_set = receipt.new_validator_set().clone();
        let new_parameters = *receipt.new_parameters();
        let next_commitment = receipt
            .next_epoch_commitment()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("encode epoch commitment: {e:?}"))?;
        let PreHandoffCheckpointReceiptV1 {
            prepared,
            read,
            post_execution_authorization_id,
            ..
        } = receipt;
        // The immutable finality evidence must name the exact parent used by
        // the original raw cutoff chain, not a caller-selected timestamp/root.
        let parent = prepared
            .bound
            .authorized()
            .prepared()
            .checkpoint_parent()
            .header()
            .try_cev0_bytes()
            .map_err(|e| anyhow::anyhow!("checkpoint parent encoding: {e:?}"))?;
        let recovery_evidence = crate::epoch_recovery::EpochRecoveryEvidenceV1 {
            checkpoint_artifact: trnm_native_application::encode_native_executed_block_artifact_v0(
                read.executed_v0(),
            )?,
            cutoff_finality: prepared.raw_cutoff_proof,
            cutoff_parent: prepared.raw_cutoff_parent,
            checkpoint_parent: parent.clone(),
            checkpoint_header: prepared
                .bound
                .authorized()
                .header()
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("checkpoint encoding: {e:?}"))?,
            checkpoint_finality: raw_checkpoint_two_seal_finality.to_vec(),
            anchor: raw_anchor_certificate_kernel.to_vec(),
            preparation_id: prepared.bound.authorized().prepared().preparation_id(),
            old_set: old_validator_set
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("old set encoding: {e:?}"))?,
            old_parameters: old_parameters.canonical_bytes(),
            new_set: new_validator_set
                .try_cev0_bytes()
                .map_err(|e| anyhow::anyhow!("new set encoding: {e:?}"))?,
            new_parameters: new_parameters.canonical_bytes(),
            next_commitment,
        };
        recovery_evidence.encode()?;
        let handoff = crate::poco_joint_handoff::authorize_poco_checkpoint_joint_handoff_v0(
            prepared.bound,
            &parent,
            raw_checkpoint_two_seal_finality,
            raw_anchor_certificate_kernel,
        )?;
        Ok(ConfirmedNativePocoCheckpointV0 {
            read,
            handoff,
            post_execution_authorization_id,
            old_validator_set,
            old_parameters,
            new_validator_set,
            new_parameters,
            recovery_evidence,
        })
    }

    fn poco_preparation_journal_v0(
        &self,
    ) -> Result<crate::poco_preparation_journal::PocoPreparationJournalV0> {
        let path = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(self.path());
        self.confirm_namespace_identity_v1()?;
        let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open(path)?;
        self.confirm_namespace_identity_v1()?;
        // A fresh open audits every stored replay record. Halted journals can
        // never mint a new preparation, even after process restart.
        ensure!(
            !journal.is_halted()?,
            "native checkpoint preparation journal is halted"
        );
        Ok(journal)
    }
}

fn cutoff_namespace_proof_v0(
    application: &DurableNativeApplicationV0,
) -> Result<crate::poco_snapshot::PocoSnapshotNamespaceProofV0> {
    use crate::poco_snapshot::{
        poco_snapshot_manifest_key, Ics23PointProofV0, PocoSnapshotMemberProofV0,
        PocoSnapshotNamespaceProofV0,
    };
    let (cutoff, _) = authenticated_cutoff_v0(application)?;
    let snapshot =
        application.confirmed_finalized_poco_snapshot_v0(HeightV0::new(cutoff.version()))?;
    let proof = |key: Vec<u8>| -> Result<Ics23PointProofV0> {
        let (value, encoded_commitment_proof) =
            snapshot.store().prove_raw_key_v0(cutoff.version(), &key)?;
        Ok(Ics23PointProofV0 {
            version: cutoff.version(),
            root_hash: cutoff.state_root(),
            key,
            value,
            encoded_commitment_proof,
        })
    };
    let members = cutoff
        .projection()
        .entries()
        .iter()
        .map(|entry| {
            Ok(PocoSnapshotMemberProofV0 {
                entry: entry.clone(),
                proof: proof(entry.jmt_key()?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(PocoSnapshotNamespaceProofV0 {
        manifest: cutoff.projection().manifest(),
        manifest_proof: proof(poco_snapshot_manifest_key()?)?,
        members,
        absences: Vec::new(),
    })
}

#[cfg(any(test, feature = "test-fixtures"))]
#[path = "native_checkpoint_fixture_v1.rs"]
pub(crate) mod native_checkpoint_fixture_v1;

#[cfg(test)]
mod native_authorization_tests {
    use super::native_checkpoint_fixture_v1::*;
    use super::*;
    use crate::EpochEdgePhaseV1;
    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{BlockHeader, BlockKind, EvidenceRoot, View};
    use trnm_native_application::{
        BlockIdV0, ChainIdV0, GenesisHashV0, NativeApplicationCommitRequestV0, NativeApplicationV0,
        NativeBlockExecutionRequestV0, NativeBlockExecutionResultV0,
        NativeExpectedBlockCommitmentsV0,
    };

    #[test]
    fn actual_committed_cutoff_produces_native_preparation_and_reopens_exactly() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        let app = open(&path, config());
        let config = config();
        let mut headers = vec![];
        assert!(authorize_poco_cutoff_candidate_selection_v0(&app).is_err());
        for _ in 0..7 {
            let (header, executed) = execute(&app, next_request(&app), BlockKind::Regular);
            if header.height().get() == 5 {
                // A merely PREPARED row cannot establish the historical cutoff.
                assert!(authorize_poco_cutoff_candidate_selection_v0(&app).is_err());
            }
            app.commit_block(NativeApplicationCommitRequestV0::new(executed))
                .unwrap();
            headers.push(header);
        }
        let cutoff = authorize_poco_cutoff_candidate_selection_v0(&app).unwrap();
        assert!(cutoff.fallback_used());
        let raw = cutoff_proof(&headers, &config);
        let parent = headers[3].try_cev0_bytes().unwrap();
        let request = next_request(&app);
        let proposer = config.validator_set_v0().validators()[3].id();
        let prepared = app
            .prepare_native_poco_checkpoint_v0(&request, View::new(8), proposer, &raw, &parent)
            .unwrap();
        let expected = prepared.header().clone();
        assert_eq!(expected.parent_id(), headers[6].id());
        assert_eq!(expected.height().get(), 8);
        // Actual application commit is mandatory before confirmation.
        assert!(app.confirm_poco_checkpoint_v0(prepared, &[], &[]).is_err());
        drop(app);
        let reopened = DurableNativeApplicationV0::open(&path, config).unwrap();
        let prepared = reopened
            .prepare_native_poco_checkpoint_v0(&request, View::new(8), proposer, &raw, &parent)
            .unwrap();
        assert_eq!(prepared.header(), &expected);
        let mut changed = raw;
        changed.push(0);
        assert!(reopened
            .prepare_native_poco_checkpoint_v0(&request, View::new(8), proposer, &changed, &parent)
            .is_err());
    }

    #[test]
    fn incremental_gc_is_owner_bound_bounded_and_never_runs_from_block_commit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        let app = open(&path, config());
        let (header, executed) = execute(&app, next_request(&app), BlockKind::Regular);
        app.commit_block(NativeApplicationCommitRequestV0::new(executed))
            .unwrap();
        let source = app.confirmed_committed_head_v0().unwrap();
        app.upgrade_incremental_schema_v1(&source, &header).unwrap();

        let report = app.collect_incremental_nodes_v1(0).unwrap();
        assert_eq!(report.deleted_nodes, 0);
        assert!(report.audited_nodes > 0);
        let sql = rusqlite::Connection::open(&path).unwrap();
        let anchor: [u8; 32] = sql
            .query_row(
                "SELECT source_anchor FROM native_incremental_owner_v1",
                [],
                |row| {
                    let bytes: Vec<u8> = row.get(0)?;
                    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
                },
            )
            .unwrap();
        assert_eq!(report.owner_anchor, Some(anchor));
        assert_eq!(
            sql.query_row("SELECT count(*) FROM ni_gc_queue", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
            0
        );

        // The sidecar lock prevents a second owner from opening the same
        // durable namespace while the first owner is live.
        assert!(DurableNativeApplicationV0::open(&path, config()).is_err());

        // Corrupting the independently pinned owner identity fences the
        // maintenance transaction before collection; no queue mutation is
        // committed. This also proves block commit did not silently invoke GC.
        sql.execute(
            "UPDATE native_incremental_owner_v1 SET source_anchor=?1",
            [vec![0u8; 32]],
        )
        .unwrap();
        assert!(app.collect_incremental_nodes_v1(1).is_err());
        assert_eq!(
            sql.query_row("SELECT count(*) FROM ni_gc_queue", [], |row| {
                row.get::<_, u64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    fn shape_valid_unpersisted_artifact_cannot_mint_checkpoint_authority() {
        let directory = tempfile::tempdir().unwrap();
        let app = open(&directory.path().join("application.sqlite3"), config());
        let request = next_request(&app);
        let (_, real) = execute(&app, request, BlockKind::Regular);
        // Even a real ordinary execution is not the scheduled checkpoint, and
        // the cutoff cannot be supplied from an unrelated naked snapshot.
        assert!(authorize_poco_checkpoint_candidate_selection_v0(&app, &real).is_err());
        let second_directory = tempfile::tempdir().unwrap();
        let second = open(
            &second_directory.path().join("application.sqlite3"),
            config(),
        );
        assert!(second
            .confirm_durable_execution_history_row_v0(&real)
            .is_err());
    }

    #[test]
    fn real_committed_checkpoint_and_signed_two_seals_produce_exact_handoff_readback() {
        use crate::NativeExecutionStoreV0;
        let directory = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_NATIVE_EPOCH_SIGKILL_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| directory.path().join("application.sqlite3"));
        let app = open(&path, config());
        let headers = ordinary_prefix(&app);
        let prepared = preparation(&app, &headers);
        let pre_certificate_prepared = preparation(&app, &headers);
        let invalid_signature_prepared = preparation(&app, &headers);
        let header = prepared.header().clone();
        let (proof, anchor) = handoff_proofs(&prepared);
        let fixture =
            crate::poco_checkpoint_header::bind_prepared_poco_checkpoint_header_for_fixture_v0(
                prepared.bound.authorized().prepared().clone(),
                prepared.header(),
                prepared.body(),
                prepared.receipts(),
            )
            .unwrap();
        let fixture_parent = headers[6].try_cev0_bytes().unwrap();
        let fixture_handoff =
            crate::poco_joint_handoff::authorize_poco_checkpoint_joint_handoff_for_fixture_v0(
                fixture,
                &fixture_parent,
                &proof,
                &anchor,
            )
            .unwrap();
        let request = next_request(&app);
        let preview = app.preview_block_v0(&request).unwrap();
        let request = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            request.parent().clone(),
            BlockIdV0::new(*header.id().as_bytes()).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            request.transactions().to_vec(),
            NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let synthetic = NativeExecutedBlockV0::new(
            request.clone(),
            preview.payload_root(),
            preview.post_state_root(),
            preview.receipts_root(),
            preview.evidence_root(),
            Vec::new(),
        )
        .unwrap();
        assert!(app
            .confirm_prepared_checkpoint_execution_v1(&prepared, &synthetic)
            .is_err());
        let NativeBlockExecutionResultV0::Valid(executed) = app.execute_block(request).unwrap()
        else {
            panic!("checkpoint execution invalid")
        };
        let actual_p = app
            .confirm_prepared_checkpoint_execution_v1(&prepared, &executed)
            .unwrap();
        assert_eq!(
            actual_p.durable_row().status_v0(),
            crate::DurableExecutionHistoryStatusV0::Prepared
        );
        assert_eq!(actual_p.validated_commitments().block_id(), header.id());
        assert_eq!(
            actual_p.new_validator_set().epoch().get(),
            actual_p.old_validator_set().epoch().get() + 1
        );
        drop(actual_p);
        app.commit_block(NativeApplicationCommitRequestV0::new(*executed))
            .unwrap();
        // No anchor or joint certificate is supplied to this API. The receipt
        // already authenticates real committed application state and strict
        // old-set finality, so new-role signing need not depend on its output.
        let pre_certificate = app
            .confirm_pre_handoff_checkpoint_v1(pre_certificate_prepared, &proof)
            .unwrap();
        assert_eq!(pre_certificate.header(), &header);
        assert_eq!(pre_certificate.durable_row().commit_sequence_v0(), Some(17));
        assert_eq!(
            pre_certificate
                .checkpoint_finality()
                .finalized_block()
                .header(),
            &header
        );
        assert_eq!(
            pre_certificate.new_validator_set().epoch().get(),
            pre_certificate.old_validator_set().epoch().get() + 1
        );
        let mut corrupted_proof = proof.clone();
        *corrupted_proof.last_mut().unwrap() ^= 1;
        assert!(app
            .confirm_pre_handoff_checkpoint_v1(invalid_signature_prepared, &corrupted_proof)
            .is_err());
        let confirmed = app
            .confirm_poco_checkpoint_v0(prepared, &proof, &anchor)
            .unwrap();
        assert_eq!(confirmed.header(), &header);
        assert_eq!(confirmed.durable_row().commit_sequence_v0(), Some(17));
        assert_ne!(confirmed.handoff_authorization_id(), [0; 32]);
        assert_eq!(
            confirmed.handoff_authorization_id(),
            fixture_handoff.authorization_id()
        );
        assert_eq!(
            confirmed.executed().request().block_id().as_bytes(),
            header.id().as_bytes()
        );
        let edge = confirmed.into_epoch_application_edge_v1().unwrap();
        let activation_read = app.confirm_epoch_application_edge_v1(&edge).unwrap();
        assert_eq!(activation_read.checkpoint_header(), &header);
        assert_eq!(activation_read.authorization_id(), edge.authorization_id());
        assert!(activation_read.belongs_to_application_at_path(&app, &path));
        drop(activation_read);
        assert_eq!(edge.application_parent().height().get(), 8);
        assert_eq!(edge.consensus_parent().height().get(), 10);
        assert_eq!(edge.first_application_height(), 11);
        let epoch_request = edge.preview_request_v1(11_000, Vec::new()).unwrap();
        let epoch_preview = app.preview_epoch_block_v1(&edge, &epoch_request).unwrap();
        // Raw dual-parent fields are inert. Even geometrically valid requests
        // must match every capability-bound identity at the owner seam.
        for (binding, terminal, active_set) in [
            (
                [88; 32],
                epoch_request.consensus_parent_id(),
                epoch_request.active_validator_set_id(),
            ),
            (
                *epoch_request.edge_binding().as_bytes(),
                BlockIdV0::new([89; 32]).unwrap(),
                epoch_request.active_validator_set_id(),
            ),
            (
                *epoch_request.edge_binding().as_bytes(),
                epoch_request.consensus_parent_id(),
                trnm_native_application::ValidatorSetIdV0::new(
                    *edge.old_validator_set().id().as_bytes(),
                )
                .unwrap(),
            ),
        ] {
            let forged = trnm_native_application::NativeEpochBlockPreviewRequestV1::new(
                epoch_request.chain_id().clone(),
                epoch_request.genesis_hash(),
                edge.application_parent().clone(),
                terminal,
                epoch_request.consensus_parent_height(),
                trnm_native_application::Hash32V0::new(binding),
                epoch_request.height(),
                epoch_request.timestamp_ms(),
                active_set,
                Vec::new(),
            )
            .unwrap();
            assert!(app.preview_epoch_block_v1(&edge, &forged).is_err());
        }
        assert!(edge
            .preview_request_v1(edge.consensus_parent().timestamp_ms(), Vec::new())
            .is_err());
        assert_eq!(
            app.confirmed_committed_head_v0().unwrap(),
            *edge.application_parent()
        );
        assert!(NativeBlockPreviewRequestV0::new(
            epoch_request.chain_id().clone(),
            epoch_request.genesis_hash(),
            edge.application_parent().clone(),
            HeightV0::new(11),
            11_000,
            epoch_request.active_validator_set_id(),
            Vec::new(),
        )
        .is_err());
        let snapshot = app
            .confirmed_finalized_poco_snapshot_v0(HeightV0::new(8))
            .unwrap();
        let computed = crate::complete::compute_complete_epoch_native_block_v1(
            snapshot.store(),
            &edge,
            &epoch_request,
        )
        .unwrap();
        assert_eq!(computed.plan.version(), 11);
        assert_eq!(
            computed.post_state_root,
            *epoch_preview.post_state_root().as_bytes()
        );
        let mut target = snapshot.store().clone();
        target.apply_complete_state_plan_v0(computed.plan).unwrap();
        assert_ne!(
            target.parent_root_v0().unwrap().0,
            *edge.application_parent().state_root().as_bytes()
        );
        let mut live = target.verified_live_values_v0(11).unwrap();
        let normalized = take_and_validate_production_poco_projection_v0(11, &mut live)
            .unwrap()
            .unwrap();
        assert_eq!(normalized.manifest().cutoff_height().get(), 11);
        // Uncommitted first-new overlays can prepare the remaining two blocks
        // needed by three-chain finality. The durable owner still stays at C.
        let mut descendant = target.clone();
        for height in [12, 13] {
            let parent = trnm_native_application::ApplicationHeadV0::new(
                HeightV0::new(height - 1),
                BlockIdV0::new([height as u8; 32]).unwrap(),
                trnm_native_application::StateRootV0::new(descendant.parent_root_v0().unwrap().0)
                    .unwrap(),
                trnm_native_application::ApplicationCommitIdV0::new([height as u8 + 1; 32])
                    .unwrap(),
            );
            let request = NativeBlockPreviewRequestV0::new(
                epoch_request.chain_id().clone(),
                epoch_request.genesis_hash(),
                parent,
                HeightV0::new(height),
                height * 1_000,
                epoch_request.active_validator_set_id(),
                Vec::new(),
            )
            .unwrap();
            let child = crate::complete::compute_complete_native_block_v0(
                &descendant,
                edge.new_validator_set(),
                edge.new_validator_set().genesis_hash(),
                &request,
            )
            .unwrap();
            descendant.apply_complete_state_plan_v0(child.plan).unwrap();
        }
        assert_eq!(descendant.parent_version_v0().unwrap(), 13);
        let encoded = target
            .encode_epoch_authenticated_snapshot_v1(&[&edge])
            .unwrap();
        let (commands, nonces) = target.replay_sets_v0();
        let reopened_tree =
            crate::InMemoryNativeExecutionStoreV0::decode_epoch_authenticated_snapshot_v1(
                CHAIN.to_string(),
                target.authorized_signers_v0().unwrap().to_vec(),
                target.consensus_parameters_v0().unwrap(),
                commands.clone(),
                nonces.clone(),
                &encoded,
                &[&edge],
            )
            .unwrap();
        assert_eq!(reopened_tree.parent_version_v0().unwrap(), 11);
        assert_eq!(
            reopened_tree.parent_root_v0().unwrap(),
            target.parent_root_v0().unwrap()
        );
        // Schema migration is explicit, and real sparse P rows prepare the
        // entire three-chain before the first new application commit.
        app.upgrade_epoch_schema_v1(edge.application_parent())
            .unwrap();
        let new_header = |height: u64,
                          parent: trnm_consensus_types::BlockId,
                          p: &crate::NativeBlockPreviewV0| {
            let set = edge.new_validator_set();
            let view = height - 10;
            BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(view),
                Height::new(height),
                if height == 11 {
                    BlockKind::EpochHandoff
                } else {
                    BlockKind::Regular
                },
                parent,
                set.validators()[(view as usize - 1) % set.validators().len()].id(),
                set.id(),
                edge.new_parameters().hash(),
                PayloadDigest::new(*p.payload_root().as_bytes()),
                StateRoot::new(*p.post_state_root().as_bytes()),
                trnm_consensus_types::ReceiptsRoot::new(*p.receipts_root().as_bytes()),
                trnm_consensus_types::EvidenceRoot::new(*p.evidence_root().as_bytes()),
                height * 1000,
                None,
            )
            .unwrap()
        };
        let first_header = new_header(11, edge.consensus_parent().id(), &epoch_preview);
        let mut new_headers = vec![first_header.clone()];
        let first_request = trnm_native_application::NativeEpochBlockExecutionRequestV1::new(
            epoch_request.clone(),
            BlockIdV0::new(*first_header.id().as_bytes()).unwrap(),
            NativeExpectedBlockCommitmentsV0::new(
                epoch_preview.payload_root(),
                epoch_preview.post_state_root(),
                epoch_preview.receipts_root(),
                epoch_preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let first_p = app
            .execute_epoch_block_v1(&edge, first_request.clone(), &first_header)
            .unwrap();
        let retry = app
            .execute_epoch_block_v1(&edge, first_request, &first_header)
            .unwrap();
        assert_eq!(first_p.p_digest(), retry.p_digest());
        let first_readback = app.confirm_prepared_epoch_execution_v1(&first_p).unwrap();
        assert!(first_readback.belongs_to_application_at_path(&app, &path));
        assert_eq!(
            first_readback
                .application_payload_and_receipts()
                .unwrap()
                .1
                .receipts_root()
                .unwrap(),
            first_header.receipts_root()
        );
        let mut parent_p = first_p;
        for height in [12, 13] {
            let parent = parent_p.overlay_parent_head().unwrap();
            let request = NativeBlockPreviewRequestV0::new(
                epoch_request.chain_id().clone(),
                epoch_request.genesis_hash(),
                parent.clone(),
                HeightV0::new(height),
                height * 1000,
                epoch_request.active_validator_set_id(),
                Vec::new(),
            )
            .unwrap();
            let preview = app
                .preview_epoch_descendant_v1(&parent_p, &request)
                .unwrap();
            let header = new_header(
                height,
                trnm_consensus_types::BlockId::new(*parent.block_id().as_bytes()),
                &preview,
            );
            let request = NativeBlockExecutionRequestV0::new(
                request.chain_id().clone(),
                request.genesis_hash(),
                parent,
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                request.height(),
                request.timestamp_ms(),
                request.active_validator_set_id(),
                Vec::new(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            parent_p = app
                .execute_epoch_descendant_v1(&parent_p, request, &header)
                .unwrap();
            new_headers.push(header);
        }
        // Keep one additional prepared Regular descendant so the committed
        // height-12 row can be joined to an independent three-chain proof in
        // the finalized-read regression below.  It remains speculative.
        let parent = parent_p.overlay_parent_head().unwrap();
        let request = NativeBlockPreviewRequestV0::new(
            epoch_request.chain_id().clone(),
            epoch_request.genesis_hash(),
            parent.clone(),
            HeightV0::new(14),
            14_000,
            epoch_request.active_validator_set_id(),
            Vec::new(),
        )
        .unwrap();
        let preview = app
            .preview_epoch_descendant_v1(&parent_p, &request)
            .unwrap();
        let fourth_header = new_header(
            14,
            trnm_consensus_types::BlockId::new(*parent.block_id().as_bytes()),
            &preview,
        );
        let request = NativeBlockExecutionRequestV0::new(
            request.chain_id().clone(),
            request.genesis_hash(),
            parent,
            BlockIdV0::new(*fourth_header.id().as_bytes()).unwrap(),
            request.height(),
            request.timestamp_ms(),
            request.active_validator_set_id(),
            Vec::new(),
            NativeExpectedBlockCommitmentsV0::new(
                preview.payload_root(),
                preview.post_state_root(),
                preview.receipts_root(),
                preview.evidence_root(),
            )
            .unwrap(),
        )
        .unwrap();
        let _fourth_p = app
            .execute_epoch_descendant_v1(&parent_p, request, &fourth_header)
            .unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 8);
        let last_p_digest = parent_p.p_digest();
        let last_block = *parent_p
            .overlay_parent_head()
            .unwrap()
            .block_id()
            .as_bytes();
        let saved_edge = edge.authorization_id();
        // Rebuild from exact raw evidence after reopening the actual stores.
        drop(app);
        let reopened = DurableNativeApplicationV0::open(&path, config()).unwrap();
        assert!(!first_readback.belongs_to_application_at_path(&reopened, &path));
        assert!(
            reopened.confirm_epoch_application_edge_v1(&edge).is_err(),
            "old owner edge must not survive reopen"
        );
        let restored_p = reopened
            .reopen_prepared_epoch_execution_v1(last_block)
            .unwrap();
        assert_eq!(restored_p.p_digest(), last_p_digest);
        assert_eq!(restored_p.overlay_parent_head().unwrap().height().get(), 13);
        let restored_edge = reopened
            .recover_epoch_application_edge_v1(saved_edge)
            .unwrap();
        assert_eq!(restored_edge.authorization_id(), saved_edge);
        let first_p = reopened
            .reopen_prepared_epoch_execution_v1(*new_headers[0].id().as_bytes())
            .unwrap();
        let before_commit_readback = reopened
            .confirm_prepared_epoch_execution_v1(&first_p)
            .unwrap();
        let new_finality = epoch_first_finality(&restored_edge, &new_headers);
        if std::env::var_os("TRNM_NATIVE_EPOCH_SIGKILL_STORE").is_some() {
            let ids = [
                new_headers[0].id().as_bytes().as_slice(),
                last_block.as_slice(),
                saved_edge.as_slice(),
            ]
            .concat();
            std::fs::write(path.with_extension("epoch-ids"), ids).unwrap();
            std::fs::write(path.with_extension("epoch-finality"), &new_finality).unwrap();
        }
        let mut corrupted = new_finality.clone();
        *corrupted.last_mut().unwrap() ^= 1;
        assert!(reopened
            .commit_epoch_finality_bytes_v1(
                &first_p,
                &corrupted,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        assert_eq!(
            reopened
                .confirmed_committed_head_v0()
                .unwrap()
                .height()
                .get(),
            8
        );
        let committed = reopened
            .commit_epoch_finality_bytes_v1(
                &first_p,
                &new_finality,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed.head().height().get(), 11);
        assert!(committed.belongs_to_application(&reopened));
        assert!(!before_commit_readback.belongs_to_application_at_path(&reopened, &path));
        assert_eq!(
            reopened
                .confirm_prepared_epoch_execution_v1(&first_p)
                .unwrap()
                .commit_sequence(),
            Some(committed.commit_sequence())
        );
        assert!(
            reopened
                .confirm_epoch_application_edge_v1(&restored_edge)
                .is_err(),
            "consumed edge is not fresh activation authority"
        );
        assert_eq!(committed.commit_sequence(), 22);
        let retried = reopened
            .commit_epoch_finality_bytes_v1(
                &first_p,
                &new_finality,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retried.commit_sequence(), committed.commit_sequence());
        assert_eq!(retried.head(), committed.head());
        // The handoff row is committed but has no schema-4 finalized-read
        // bridge.  It must remain fail-closed while an uncommitted Regular
        // descendant at height 13 is ignored by the height lookup.
        let handoff_error = reopened
            .read_finalized_by_height_v1(HeightV0::new(11))
            .unwrap_err();
        assert!(handoff_error
            .to_string()
            .contains("checkpoint/handoff bridge required"));
        assert!(reopened
            .read_finalized_by_height_v1(HeightV0::new(13))
            .is_err());
        let second_p = reopened
            .reopen_prepared_epoch_execution_v1(*new_headers[1].id().as_bytes())
            .unwrap();
        let ordinary_finality = ordinary_epoch_finality(
            &restored_edge,
            &new_headers[0],
            &[
                new_headers[1].clone(),
                new_headers[2].clone(),
                fourth_header.clone(),
            ],
        );
        let second_committed = reopened
            .commit_epoch_finality_bytes_v1(
                &second_p,
                &ordinary_finality,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(second_committed.head().height().get(), 12);
        let ordinary_read = reopened
            .read_finalized_by_height_v1(HeightV0::new(12))
            .unwrap();
        assert_eq!(
            ordinary_read.finalized_head_v1().unwrap().height().get(),
            12
        );
        assert_eq!(ordinary_read.executed_v1().request().height().get(), 12);
        assert!(ordinary_read.belongs_to_application_at_path_v1(&reopened, &path));
        // The retained edge is exposed only through the versioned, recursively
        // audited history carrier.  Recovery by index rechecks the history
        // after reconstruction and therefore cannot attach a stale binding.
        let history = reopened.read_epoch_edge_history_v1().unwrap();
        assert_eq!(history.entries().len(), 1);
        let history_edge = &history.entries()[0];
        assert_eq!(history_edge.binding(), saved_edge);
        assert_eq!(history_edge.phase(), EpochEdgePhaseV1::Consumed);
        assert_eq!(history_edge.lineage(), &[saved_edge]);
        assert!(history.belongs_to_application_at_path_v1(&reopened, &path));
        let indexed_edge = reopened
            .recover_epoch_application_edge_at_index_v1(0)
            .unwrap();
        assert_eq!(indexed_edge.authorization_id(), saved_edge);
        assert!(reopened
            .recover_epoch_application_edge_at_index_v1(1)
            .is_err());
        // A second pending row has no authenticated lineage and is rejected
        // before it can be mistaken for a second epoch.  A malformed consumed
        // lineage is rejected by the same recursive history audit.
        let sql = rusqlite::Connection::open(&path).unwrap();
        let foreign_binding = [0x5a; 32];
        sql.execute(
            "INSERT INTO native_epoch_edge_v1(binding,store_id,checkpoint_height,checkpoint_block,checkpoint_root,checkpoint_commit_id,checkpoint_p_digest,checkpoint_commit_sequence,terminal_height,terminal_block,first_height,evidence,evidence_digest,phase,consumed_block,consumed_sequence) SELECT ?1,store_id,checkpoint_height,checkpoint_block,checkpoint_root,checkpoint_commit_id,checkpoint_p_digest,checkpoint_commit_sequence,terminal_height,terminal_block,first_height,evidence,evidence_digest,0,NULL,NULL FROM native_epoch_edge_v1 WHERE binding=?2",
            rusqlite::params![foreign_binding.as_slice(), saved_edge.as_slice()],
        )
        .unwrap();
        assert!(reopened.read_epoch_edge_history_v1().is_err());
        sql.execute(
            "DELETE FROM native_epoch_edge_v1 WHERE binding=?",
            [foreign_binding.as_slice()],
        )
        .unwrap();
        let consumed_block = history_edge.consumed_block().unwrap();
        let original_lineage: Vec<u8> = sql
            .query_row(
                "SELECT edge_lineage FROM native_durable_execution_p_v1 WHERE block_id=?",
                [consumed_block.as_slice()],
                |row| row.get(0),
            )
            .unwrap();
        sql.execute(
            "UPDATE native_durable_execution_p_v1 SET edge_lineage=zeroblob(0) WHERE block_id=?",
            [consumed_block.as_slice()],
        )
        .unwrap();
        assert!(reopened.read_epoch_edge_history_v1().is_err());
        sql.execute(
            "UPDATE native_durable_execution_p_v1 SET edge_lineage=? WHERE block_id=?",
            rusqlite::params![original_lineage, consumed_block.as_slice()],
        )
        .unwrap();
        assert_eq!(
            reopened
                .reopen_prepared_epoch_execution_v1(last_block)
                .unwrap()
                .p_digest(),
            last_p_digest
        );
        assert!(reopened
            .preview_epoch_block_v1(&edge, &epoch_request)
            .is_err());
        drop(edge);
        let parent = reopened
            .read_finalized_by_height_v0(HeightV0::new(7))
            .unwrap()
            .finalized_head_v0()
            .unwrap();
        let request = NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new([7; 32]).unwrap(),
            parent,
            HeightV0::new(8),
            8000,
            trnm_native_application::ValidatorSetIdV0::new(
                *reopened.config_v0().validator_set_v0().id().as_bytes(),
            )
            .unwrap(),
            vec![],
        )
        .unwrap();
        let reconstructed = reopened
            .prepare_native_poco_checkpoint_v0(
                &request,
                View::new(8),
                reopened.config_v0().validator_set_v0().validators()[3].id(),
                &cutoff_proof(&headers, reopened.config_v0()),
                &headers[3].try_cev0_bytes().unwrap(),
            )
            .unwrap();
        let recovered = reopened
            .confirm_poco_checkpoint_v0(reconstructed, &proof, &anchor)
            .unwrap();
        assert_eq!(recovered.header(), &header);
        drop(reopened);
        let after_commit = DurableNativeApplicationV0::open(&path, config()).unwrap();
        assert_eq!(
            after_commit
                .confirmed_committed_head_v0()
                .unwrap()
                .height()
                .get(),
            12
        );
        assert_eq!(
            after_commit
                .reopen_prepared_epoch_execution_v1(last_block)
                .unwrap()
                .p_digest(),
            last_p_digest
        );
        assert!(after_commit
            .preview_epoch_block_v1(
                &after_commit
                    .recover_epoch_application_edge_v1(saved_edge)
                    .unwrap(),
                &epoch_request
            )
            .is_err());
        // Exact digests and closed schema are checked again on every reopen.
        let connection = rusqlite::Connection::open(&path).unwrap();
        let original: Vec<u8> = connection
            .query_row(
                "SELECT evidence FROM native_epoch_edge_v1 WHERE binding=?",
                [saved_edge.as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        connection
            .execute(
                "UPDATE native_epoch_edge_v1 SET evidence=zeroblob(1) WHERE binding=?",
                [saved_edge.as_slice()],
            )
            .unwrap();
        assert!(DurableNativeApplicationV0::open(&path, config()).is_err());
        connection
            .execute(
                "UPDATE native_epoch_edge_v1 SET evidence=? WHERE binding=?",
                rusqlite::params![original, saved_edge.as_slice()],
            )
            .unwrap();
        let journal_path = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
        let journal = rusqlite::Connection::open(&journal_path).unwrap();
        journal.execute("DELETE FROM preparations", []).unwrap();
        assert!(after_commit
            .recover_epoch_application_edge_v1(saved_edge)
            .is_err());
        assert!(after_commit
            .reopen_prepared_epoch_execution_v1(last_block)
            .is_err());
        let count: i64 = journal
            .query_row("SELECT COUNT(*) FROM preparations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "recovery must not recreate a missing preparation");
        drop(journal);
        std::fs::rename(&journal_path, journal_path.with_extension("retired")).unwrap();
        assert!(after_commit
            .recover_epoch_application_edge_v1(saved_edge)
            .is_err());
        assert!(
            !journal_path.exists(),
            "recovery must not recreate a missing journal"
        );
    }

    #[cfg(unix)]
    #[test]
    fn epoch_sigkill_commit_boundaries_preserve_exact_prepared_chain() {
        for stage in [
            "epoch_before_commit",
            "epoch_after_commit",
            "epoch_after_fsync",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("application.sqlite3");
            let marker = directory.path().join("ready");
            let mut child=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","poco_checkpoint::native_authorization_tests::real_committed_checkpoint_and_signed_two_seals_produce_exact_handoff_readback","--nocapture"])
                .env("TRNM_NATIVE_EPOCH_SIGKILL_STORE",&path)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker)
                .spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("epoch child failed to reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let ids = std::fs::read(path.with_extension("epoch-ids")).unwrap();
            let first: [u8; 32] = ids[..32].try_into().unwrap();
            let last: [u8; 32] = ids[32..64].try_into().unwrap();
            let binding: [u8; 32] = ids[64..].try_into().unwrap();
            let proof = std::fs::read(path.with_extension("epoch-finality")).unwrap();
            let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                if stage == "epoch_before_commit" {
                    8
                } else {
                    11
                }
            );
            assert_eq!(
                app.recover_epoch_application_edge_v1(binding)
                    .unwrap()
                    .first_application_height(),
                11
            );
            let first = app.reopen_prepared_epoch_execution_v1(first).unwrap();
            let committed = app
                .commit_epoch_finality_bytes_v1(
                    &first,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(committed.head().height().get(), 11);
            assert_eq!(committed.commit_sequence(), 22);
            assert_eq!(
                app.reopen_prepared_epoch_execution_v1(last)
                    .unwrap()
                    .overlay_parent_head()
                    .unwrap()
                    .height()
                    .get(),
                13
            );
            let retried = app
                .commit_epoch_finality_bytes_v1(
                    &first,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(retried.commit_sequence(), 22);
        }
    }

    #[test]
    fn incremental_owner_migrates_real_history_and_commits_signed_finality_without_snapshot_rows() {
        let directory = tempfile::tempdir().unwrap();
        let path = std::env::var_os("TRNM_NATIVE_INCREMENTAL_SIGKILL_STORE")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| directory.path().join("incremental.sqlite3"));
        let app = open(&path, config());
        let mut headers = Vec::new();
        let credit = |label: &str, nonce: u64| {
            let inner = serde_json::to_vec(&trnm_protocol::CanonicalTxV1 {
                schema: trnm_protocol::CANONICAL_TX_SCHEMA_V1.into(),
                sender: "did:operator:1".into(),
                nonce,
                max_gas: 100_000,
                fee_limit: 100_000,
                command: trnm_protocol::CanonicalCommandV1::CreditAccount {
                    account: "did:operator:1".into(),
                    amount: 1_000_000,
                },
            })
            .unwrap();
            serde_json::to_vec(
                &trnm_finality_types::SignedCommandEnvelopeV1::sign(
                    CHAIN,
                    label,
                    "did:operator:1",
                    "operator",
                    nonce,
                    1000,
                    100000,
                    trnm_protocol::CANONICAL_TX_PAYLOAD_TYPE_V1,
                    &inner,
                    &SigningKey::from_bytes(&[81; 32]),
                )
                .unwrap(),
            )
            .unwrap()
        };
        for _ in 0..4 {
            let next = next_request(&app);
            let request = NativeBlockPreviewRequestV0::new(
                next.chain_id().clone(),
                next.genesis_hash(),
                next.parent().clone(),
                next.height(),
                next.timestamp_ms(),
                next.active_validator_set_id(),
                if next.height().get() == 2 {
                    vec![credit("baseline-credit", 1)]
                } else {
                    vec![]
                },
            )
            .unwrap();
            let (header, executed) = execute(&app, request, BlockKind::Regular);
            app.commit_block(NativeApplicationCommitRequestV0::new(executed))
                .unwrap();
            headers.push(header);
        }
        let source = app.confirmed_committed_head_v0().unwrap();
        app.upgrade_incremental_schema_v1(&source, &headers[3])
            .unwrap();
        app.upgrade_incremental_schema_v1(&source, &headers[3])
            .unwrap();
        let sql = rusqlite::Connection::open(&path).unwrap();
        let old_bytes: i64 = sql
            .query_row(
                "SELECT sum(length(target_snapshot)) FROM native_durable_execution_p_v0",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            sql.query_row(
                "SELECT length(authenticated_snapshot) FROM native_application_metadata_v0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        let mut parent = source.clone();
        let mut pids = Vec::new();
        let mut first_request = None;
        for height in 5..=7 {
            let preview_request = NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(CHAIN).unwrap(),
                GenesisHashV0::new([7; 32]).unwrap(),
                parent.clone(),
                HeightV0::new(height),
                height * 1000,
                trnm_native_application::ValidatorSetIdV0::new(
                    *app.config_v0().validator_set_v0().id().as_bytes(),
                )
                .unwrap(),
                if height == 5 {
                    vec![credit("incremental-credit", 2)]
                } else {
                    vec![]
                },
            )
            .unwrap();
            let preview = app.preview_incremental_block_v1(&preview_request).unwrap();
            let set = app.config_v0().validator_set_v0();
            let header = BlockHeader::new(
                set.genesis_hash(),
                set.chain_id(),
                set.protocol_version(),
                set.epoch(),
                View::new(height),
                Height::new(height),
                BlockKind::Regular,
                BlockId::new(*parent.block_id().as_bytes()),
                set.validators()[((height - 1) % 4) as usize].id(),
                set.id(),
                set.consensus_parameters_hash(),
                PayloadDigest::new(*preview.payload_root().as_bytes()),
                StateRoot::new(*preview.post_state_root().as_bytes()),
                ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
                EvidenceRoot::new(*preview.evidence_root().as_bytes()),
                height * 1000,
                None,
            )
            .unwrap();
            let request = NativeBlockExecutionRequestV0::new(
                preview_request.chain_id().clone(),
                preview_request.genesis_hash(),
                parent,
                BlockIdV0::new(*header.id().as_bytes()).unwrap(),
                HeightV0::new(height),
                height * 1000,
                preview_request.active_validator_set_id(),
                preview_request.transactions().to_vec(),
                NativeExpectedBlockCommitmentsV0::new(
                    preview.payload_root(),
                    preview.post_state_root(),
                    preview.receipts_root(),
                    preview.evidence_root(),
                )
                .unwrap(),
            )
            .unwrap();
            if height == 5 {
                first_request = Some(request.clone());
            }
            let p = app
                .execute_incremental_block_v1(request.clone(), &header)
                .unwrap();
            let retry = app.execute_incremental_block_v1(request, &header).unwrap();
            assert_eq!(p.p_digest(), retry.p_digest());
            parent = p.target_head().unwrap();
            pids.push((*header.id().as_bytes(), p.p_digest()));
            headers.push(header);
        }
        let first = first_request.unwrap();
        let h = &headers[4];
        let fork_header = BlockHeader::new(
            h.genesis_hash(),
            h.chain_id(),
            h.protocol_version(),
            h.epoch(),
            View::new(9),
            h.height(),
            h.block_kind(),
            h.parent_id(),
            h.proposer_id(),
            h.validator_set_id(),
            h.consensus_parameters_hash(),
            h.payload_digest(),
            h.state_root(),
            h.receipts_root(),
            h.evidence_root(),
            h.timestamp_ms(),
            None,
        )
        .unwrap();
        let fork_request = NativeBlockExecutionRequestV0::new(
            first.chain_id().clone(),
            first.genesis_hash(),
            first.parent().clone(),
            BlockIdV0::new(*fork_header.id().as_bytes()).unwrap(),
            first.height(),
            first.timestamp_ms(),
            first.active_validator_set_id(),
            first.transactions().to_vec(),
            first.expected(),
        )
        .unwrap();
        let fork = app
            .execute_incremental_block_v1(fork_request, &fork_header)
            .unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap(), source);
        let replay_request = |label: &str| {
            NativeBlockPreviewRequestV0::new(
                ChainIdV0::new(CHAIN).unwrap(),
                GenesisHashV0::new([7; 32]).unwrap(),
                parent.clone(),
                HeightV0::new(8),
                8000,
                trnm_native_application::ValidatorSetIdV0::new(
                    *app.config_v0().validator_set_v0().id().as_bytes(),
                )
                .unwrap(),
                vec![credit(label, 3)],
            )
            .unwrap()
        };
        assert!(app
            .preview_incremental_block_v1(&replay_request("baseline-credit"))
            .unwrap_err()
            .to_string()
            .contains("command"));
        assert!(app
            .preview_incremental_block_v1(&replay_request("incremental-credit"))
            .unwrap_err()
            .to_string()
            .contains("command"));

        assert!(app
            .preview_incremental_block_v1(&replay_request("fresh-credit"))
            .is_ok());
        drop(app);
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        let p = app
            .reopen_prepared_incremental_execution_v1(pids[0].0)
            .unwrap();
        assert_eq!(p.p_digest(), pids[0].1);
        let before_commit_readback = app.confirm_prepared_incremental_execution_v1(&p).unwrap();
        assert!(before_commit_readback.belongs_to_application_at_path(&app, &path));
        assert_eq!(
            before_commit_readback.prepared().persist_sequence(),
            p.persist_sequence()
        );
        assert_eq!(
            before_commit_readback
                .application_payload_and_receipts()
                .unwrap()
                .1
                .receipts_root()
                .unwrap(),
            headers[4].receipts_root()
        );
        let proof = cutoff_proof(&headers, app.config_v0());
        if std::env::var_os("TRNM_NATIVE_INCREMENTAL_SIGKILL_STORE").is_some() {
            std::fs::write(
                path.with_extension("incremental-ids"),
                [
                    pids[0].0.as_slice(),
                    pids[2].0.as_slice(),
                    fork.storage_artifact().as_slice(),
                ]
                .concat(),
            )
            .unwrap();
            std::fs::write(path.with_extension("incremental-finality"), &proof).unwrap();
        }
        let mut bad = proof.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(app
            .commit_incremental_finality_bytes_v1(
                &p,
                &bad,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0()
            )
            .is_err());
        let committed = app
            .commit_incremental_finality_bytes_v1(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(committed.head().height().get(), 5);
        assert_eq!(committed.commit_sequence(), 14);
        assert!(committed.belongs_to_application(&app));
        assert!(!before_commit_readback.belongs_to_application_at_path(&app, &path));
        assert_eq!(
            app.confirm_prepared_incremental_execution_v1(&p)
                .unwrap()
                .commit_sequence(),
            Some(14)
        );
        let retry = app
            .commit_incremental_finality_bytes_v1(
                &p,
                &proof,
                &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
            )
            .unwrap();
        assert_eq!(retry.commit_sequence(), 14);
        // A coherent local sequence rewrite preserves the application head;
        // it must nevertheless invalidate a receipt for the earlier exact cut.
        type OwnerDigestColumns = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
        let columns: OwnerDigestColumns = sql.query_row(
            "SELECT source_anchor,storage_checksum,replay_version,replay_root,owner_checksum FROM native_incremental_owner_v1", [],
            |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
        let head = committed.head();
        let head_bytes = [
            head.height().get().to_be_bytes().as_slice(),
            head.block_id().as_bytes(),
            head.state_root().as_bytes(),
            head.commit_id().as_bytes(),
        ]
        .concat();
        let replaced = trnm_finality_types::hash_domain(
            "trnm.native-application.incremental-owner.v1",
            &[
                &columns.0,
                &head_bytes,
                &15u64.to_be_bytes(),
                &columns.1,
                &columns.2,
                &columns.3,
            ],
        );
        for (sequence, checksum) in [(15u64, replaced.as_slice()), (14u64, columns.4.as_slice())] {
            sql.execute(
                "UPDATE native_incremental_p_v1 SET commit_sequence=? WHERE status=1",
                [sequence.to_be_bytes().as_slice()],
            )
            .unwrap();
            sql.execute(
                "UPDATE native_application_metadata_v0 SET durable_sequence=?",
                [sequence.to_be_bytes().as_slice()],
            )
            .unwrap();
            sql.execute(
                "UPDATE native_incremental_owner_v1 SET head_commit_sequence=?,owner_checksum=?",
                rusqlite::params![sequence.to_be_bytes().as_slice(), checksum],
            )
            .unwrap();
            assert_eq!(
                &app.confirmed_committed_head_v0().unwrap(),
                committed.head()
            );
            assert_eq!(committed.belongs_to_application(&app), sequence == 14);
        }
        assert_eq!(
            app.reopen_prepared_incremental_execution_v1(pids[2].0)
                .unwrap()
                .p_digest(),
            pids[2].1
        );
        assert!(app
            .reopen_prepared_incremental_execution_v1(*fork_header.id().as_bytes())
            .is_err());
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM ni_prepared WHERE artifact=?1",
                [fork.storage_artifact().as_slice()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row(
                "SELECT count(*) FROM ni_pin WHERE owner=?1",
                [fork.storage_artifact().as_slice()],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        assert_eq!(
            sql.query_row(
                "SELECT sum(length(target_snapshot)) FROM native_durable_execution_p_v0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            old_bytes
        );
        assert_eq!(
            sql.query_row("SELECT count(*) FROM native_incremental_p_v1", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            3
        );
        assert_eq!(
            sql.query_row(
                "SELECT length(authenticated_snapshot) FROM native_application_metadata_v0",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
        drop(app);
        let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
        assert_eq!(app.confirmed_committed_head_v0().unwrap().height().get(), 5);
        assert!(!committed.belongs_to_application(&app));
        assert!(!before_commit_readback.belongs_to_application_at_path(&app, &path));
        assert_eq!(
            app.reopen_prepared_incremental_execution_v1(pids[2].0)
                .unwrap()
                .p_digest(),
            pids[2].1
        );
    }

    #[cfg(unix)]
    #[test]
    fn incremental_sigkill_commit_boundaries_preserve_state_replay_and_forks() {
        for stage in [
            "incremental_before_commit",
            "incremental_after_commit",
            "incremental_after_fsync",
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("incremental.sqlite3");
            let marker = directory.path().join("ready");
            let mut child=std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact","poco_checkpoint::native_authorization_tests::incremental_owner_migrates_real_history_and_commits_signed_finality_without_snapshot_rows","--nocapture"])
                .env("TRNM_NATIVE_INCREMENTAL_SIGKILL_STORE",&path)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_STAGE",stage)
                .env("TRNM_NATIVE_EXECUTION_TEST_KILL_MARKER",&marker).spawn().unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(45);
            while !marker.exists() && std::time::Instant::now() < deadline {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            if !marker.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("incremental child failed to reach {stage}");
            }
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            let ids = std::fs::read(path.with_extension("incremental-ids")).unwrap();
            let first: [u8; 32] = ids[..32].try_into().unwrap();
            let last: [u8; 32] = ids[32..64].try_into().unwrap();
            let fork: [u8; 32] = ids[64..].try_into().unwrap();
            let proof = std::fs::read(path.with_extension("incremental-finality")).unwrap();
            let app = DurableNativeApplicationV0::open(&path, config()).unwrap();
            assert_eq!(
                app.confirmed_committed_head_v0().unwrap().height().get(),
                if stage == "incremental_before_commit" {
                    4
                } else {
                    5
                }
            );
            let sql = rusqlite::Connection::open(&path).unwrap();
            assert_eq!(
                sql.query_row(
                    "SELECT count(*) FROM ni_prepared WHERE artifact=?1",
                    [fork.as_slice()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                if stage == "incremental_before_commit" {
                    1
                } else {
                    0
                }
            );
            let p = app.reopen_prepared_incremental_execution_v1(first).unwrap();
            let result = app
                .commit_incremental_finality_bytes_v1(
                    &p,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(result.commit_sequence(), 14);
            assert_eq!(
                app.reopen_prepared_incremental_execution_v1(last)
                    .unwrap()
                    .target_head()
                    .unwrap()
                    .height()
                    .get(),
                7
            );
            assert_eq!(
                sql.query_row(
                    "SELECT count(*) FROM ni_prepared WHERE artifact=?1",
                    [fork.as_slice()],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            assert_eq!(
                sql.query_row(
                    "SELECT length(authenticated_snapshot) FROM native_application_metadata_v0",
                    [],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
                0
            );
            let retry = app
                .commit_incremental_finality_bytes_v1(
                    &p,
                    &proof,
                    &mut trnm_consensus_types::Cev0AdmissionBudgetV0::protocol_v0(),
                )
                .unwrap();
            assert_eq!(retry.commit_sequence(), 14);
            drop(sql);
            drop(app);
            assert_eq!(
                DurableNativeApplicationV0::open(&path, config())
                    .unwrap()
                    .confirmed_committed_head_v0()
                    .unwrap()
                    .height()
                    .get(),
                5
            );
        }
    }

    #[test]
    fn held_preparation_cannot_survive_halt_missing_row_replacement_or_owner_change() {
        for fault in ["halt", "delete", "replace", "owner"] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("application.sqlite3");
            let app = open(&path, config());
            let headers = ordinary_prefix(&app);
            let prepared = preparation(&app, &headers);
            let journal_path =
                crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(&path);
            let error = if fault == "owner" {
                let other_directory = tempfile::tempdir().unwrap();
                let other = open(
                    &other_directory.path().join("application.sqlite3"),
                    config(),
                );
                let _ = ordinary_prefix(&other);
                other
                    .confirm_poco_checkpoint_v0(prepared, &[], &[])
                    .err()
                    .unwrap()
                    .to_string()
            } else {
                if fault == "replace" {
                    std::fs::rename(&journal_path, journal_path.with_extension("retired")).unwrap();
                } else {
                    let connection = rusqlite::Connection::open(&journal_path).unwrap();
                    if fault == "delete" {
                        connection.execute("DELETE FROM preparations", []).unwrap();
                    } else {
                        connection.execute("INSERT INTO safety_halt(singleton,reason,conflict_checksum) VALUES (1,'test halt',?1)",[&[1u8;32][..]]).unwrap();
                    }
                }
                app.confirm_poco_checkpoint_v0(prepared, &[], &[])
                    .err()
                    .unwrap()
                    .to_string()
            };
            if fault == "replace" {
                // The live native namespace pin now fences a removed sidecar
                // before reopening its journal or interpreting supplied proof.
                assert!(
                    error.contains("ReplacedStore:namespace.path_metadata"),
                    "{error}"
                );
            } else {
                assert!(
                    error.contains("journal")
                        || error.contains("sidecar")
                        || error.contains("preparation")
                        || error.contains("reservation"),
                    "{fault} rejected at wrong boundary: {error}"
                );
            }
        }
    }
}
