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

fn native_execution_from_receipts_v0(
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
}

impl DurableNativeApplicationV0 {
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

    /// Confirm a prepared checkpoint only after the exact native execution has
    /// become a committed P row in this owner and both frozen handoff proof
    /// layers independently verify. Reopen callers must reconstruct preparation
    /// from the raw inputs, which idempotently revalidates the durable journal.
    pub fn confirm_poco_checkpoint_v0(
        &self,
        prepared: PreparedNativePocoCheckpointV0,
        raw_checkpoint_two_seal_finality: &[u8],
        raw_anchor_certificate_kernel: &[u8],
    ) -> Result<ConfirmedNativePocoCheckpointV0> {
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
        })
    }

    fn poco_preparation_journal_v0(
        &self,
    ) -> Result<crate::poco_preparation_journal::PocoPreparationJournalV0> {
        let path = crate::poco_preparation_journal::poco_preparation_sidecar_path_v0(self.path());
        let journal = crate::poco_preparation_journal::PocoPreparationJournalV0::open(path)?;
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

#[cfg(test)]
mod native_authorization_tests {
    use super::*;
    use crate::{
        validator_lifecycle::{
            ValidatorGovernanceV1, ValidatorLifecycleStateV1, VALIDATOR_GOVERNANCE_SCHEMA_V1,
        },
        AuthorizedSignerV0, NativeApplicationConfigV0, NativeStateWriteV0,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use trnm_consensus_types::{
        BlockHeader, BlockKind, CertifiedHeaderV0, ConsensusPublicKey, EvidenceRoot,
        FinalityProofV0, ProposalWitnessV0, QcReferenceV0, QuorumCertificate, Signature64,
        Validator, ValidatorId, View, Vote, VotingPower,
    };
    use trnm_native_application::{
        BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0, NativeApplicationCommitRequestV0,
        NativeApplicationGenesisRequestV0, NativeApplicationV0, NativeBlockExecutionRequestV0,
        NativeBlockExecutionResultV0, NativeExpectedBlockCommitmentsV0, StateRootV0,
    };

    const CHAIN: &str = "native-poco-authorization-test";
    fn key(index: usize) -> SigningKey {
        SigningKey::from_bytes(&[20 + index as u8; 32])
    }

    fn config() -> NativeApplicationConfigV0 {
        let mut fields = ConsensusParametersV0::reference_shadow_v0().fields();
        fields.epoch_length_blocks = 10;
        fields.snapshot_lead_blocks = 3;
        let parameters = ConsensusParametersV0::new(fields).unwrap();
        let set = ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::new(CHAIN).unwrap(),
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            (0..4)
                .map(|index| {
                    Validator::new(
                        ValidatorId::from_bytes(format!("validator-{index}").as_bytes()).unwrap(),
                        ConsensusPublicKey::new(key(index).verifying_key().to_bytes()),
                        VotingPower::new(1).unwrap(),
                    )
                    .unwrap()
                })
                .collect(),
        )
        .unwrap();
        let signers = vec![AuthorizedSignerV0::new(
            "did:operator:1",
            "operator",
            hex::encode(SigningKey::from_bytes(&[81; 32]).verifying_key().to_bytes()),
        )
        .unwrap()];
        let lifecycle = ValidatorLifecycleStateV1::from_genesis(
            CHAIN.to_string(),
            1,
            hex::encode(crate::signer_policy_commitment_v0(&signers).unwrap()),
            ValidatorGovernanceV1 {
                schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_string(),
                signer_id: "did:operator:1".to_string(),
                min_activation_delay_blocks: 2,
                unsafe_allow_single_validator_genesis: false,
            },
            set.validators()
                .iter()
                .map(|v| ConsensusValidatorV1 {
                    public_key_hex: hex::encode(v.consensus_key().as_bytes()),
                    voting_power: v.voting_power().get(),
                })
                .collect(),
        )
        .unwrap();
        let mut entries = vec![];
        let mut identity = vec![1];
        identity.extend_from_slice(&0u64.to_be_bytes());
        for (kind, raw) in [
            (
                PocoSnapshotEntryKindV0::ValidatorConfiguration,
                set.try_cev0_bytes().unwrap(),
            ),
            (
                PocoSnapshotEntryKindV0::ConsensusParameters,
                parameters.canonical_bytes(),
            ),
        ] {
            let (logical_key, value) =
                crate::poco_transition::encode_poco_snapshot_value_envelope_v0(
                    kind, 1, &identity, &raw,
                )
                .unwrap();
            entries.push(
                crate::poco_snapshot::PocoSnapshotEntryV0::new(kind, logical_key, value).unwrap(),
            );
        }
        entries
            .push(crate::poco_application::genesis_poco_application_authority_entry_v0().unwrap());
        entries.sort_by(|a, b| (a.kind, &a.logical_key).cmp(&(b.kind, &b.logical_key)));
        let writes = crate::poco_transition::genesis_poco_snapshot_writes_v0(&entries)
            .unwrap()
            .into_iter()
            .map(|write| {
                NativeStateWriteV0::raw(write.key().to_vec(), write.value().unwrap().to_vec())
                    .unwrap()
            })
            .collect();
        NativeApplicationConfigV0::new(
            CHAIN,
            [7; 32],
            [8; 32],
            [11; 32],
            [9; 32],
            [10; 32],
            set,
            parameters,
            serde_json::to_vec(&lifecycle).unwrap(),
            signers,
            writes,
        )
        .unwrap()
    }

    fn open(
        path: &std::path::Path,
        config: NativeApplicationConfigV0,
    ) -> DurableNativeApplicationV0 {
        let application = DurableNativeApplicationV0::open(path, config).unwrap();
        let config = application.config_v0();
        application
            .initialize(
                NativeApplicationGenesisRequestV0::new(
                    ChainIdV0::new(CHAIN).unwrap(),
                    GenesisHashV0::new([7; 32]).unwrap(),
                    Hash32V0::new([8; 32]),
                    Hash32V0::new(config.signer_policy_commitment_v0()),
                    StateRootV0::new(config.initial_state_root()).unwrap(),
                    config.initial_validator_set().clone(),
                )
                .unwrap(),
            )
            .unwrap();
        application
    }

    fn next_request(app: &DurableNativeApplicationV0) -> NativeBlockPreviewRequestV0 {
        let parent = app.confirmed_committed_head_v0().unwrap();
        let height = parent.height().checked_next().unwrap();
        NativeBlockPreviewRequestV0::new(
            ChainIdV0::new(CHAIN).unwrap(),
            GenesisHashV0::new([7; 32]).unwrap(),
            parent,
            height,
            height.get() * 1000,
            trnm_native_application::ValidatorSetIdV0::new(
                *app.config_v0().validator_set_v0().id().as_bytes(),
            )
            .unwrap(),
            vec![],
        )
        .unwrap()
    }

    fn execute(
        app: &DurableNativeApplicationV0,
        preview_request: NativeBlockPreviewRequestV0,
        kind: BlockKind,
    ) -> (BlockHeader, NativeExecutedBlockV0) {
        let preview = app.preview_block_v0(&preview_request).unwrap();
        let height = preview_request.height().get();
        let set = app.config_v0().validator_set_v0();
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(height),
            Height::new(height),
            kind,
            BlockId::new(*preview_request.parent().block_id().as_bytes()),
            set.validators()[((height - 1) % 4) as usize].id(),
            set.id(),
            set.consensus_parameters_hash(),
            PayloadDigest::new(*preview.payload_root().as_bytes()),
            StateRoot::new(*preview.post_state_root().as_bytes()),
            ReceiptsRoot::new(*preview.receipts_root().as_bytes()),
            EvidenceRoot::new(*preview.evidence_root().as_bytes()),
            preview_request.timestamp_ms(),
            None,
        )
        .unwrap();
        let request = NativeBlockExecutionRequestV0::new(
            preview_request.chain_id().clone(),
            preview_request.genesis_hash(),
            preview_request.parent().clone(),
            BlockIdV0::new(*header.id().as_bytes()).unwrap(),
            preview_request.height(),
            preview_request.timestamp_ms(),
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
        let NativeBlockExecutionResultV0::Valid(executed) = app.execute_block(request).unwrap()
        else {
            panic!("valid empty native execution rejected")
        };
        (header, *executed)
    }

    fn qc(header: &BlockHeader, set: &ValidatorSet) -> QuorumCertificate {
        let votes = set
            .validators()
            .iter()
            .enumerate()
            .take(3)
            .map(|(index, v)| {
                let root =
                    Vote::signing_root_for_set(set, header.view(), header.height(), header.id())
                        .unwrap();
                Vote::new(
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    header.view(),
                    header.height(),
                    header.id(),
                    set.id(),
                    v.id(),
                    Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                    set,
                )
                .unwrap()
            })
            .collect();
        QuorumCertificate::new(
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            header.view(),
            header.height(),
            header.id(),
            set.id(),
            votes,
            set,
        )
        .unwrap()
    }

    fn cutoff_proof(headers: &[BlockHeader], config: &NativeApplicationConfigV0) -> Vec<u8> {
        let set = config.validator_set_v0();
        let parameters = config.consensus_parameters_v0();
        let certified = |index: usize| {
            let header = headers[index].clone();
            let justify = QcReferenceV0::ordinary(qc(&headers[index - 1], set));
            let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
            let signer = set
                .validators()
                .iter()
                .position(|v| v.id() == header.proposer_id())
                .unwrap();
            CertifiedHeaderV0::new(
                header.clone(),
                justify,
                None,
                None,
                Signature64::from_array(key(signer).sign(root.as_bytes()).to_bytes()),
                qc(&header, set),
                set,
                None,
                parameters,
                headers[index - 1].timestamp_ms(),
            )
            .unwrap()
        };
        FinalityProofV0::new(
            certified(4),
            certified(5),
            certified(6),
            set,
            None,
            parameters,
            headers[3].timestamp_ms(),
        )
        .unwrap()
        .try_cev0_bytes()
        .unwrap()
    }

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

    fn handoff_proofs(prepared: &PreparedNativePocoCheckpointV0) -> (Vec<u8>, Vec<u8>) {
        use trnm_consensus_types::{
            HandoffCertificateV0, HandoffDescriptorV0, HandoffDescriptorV0Fields, SignatureShareV0,
        };
        let preheader = prepared.bound.authorized().prepared();
        let authority = preheader.commitment_authority();
        let set = authority.old_validator_set();
        let parameters = authority.old_parameters();
        let checkpoint = prepared.header().clone();
        let parent = preheader.checkpoint_parent().header();
        let mut chain = vec![checkpoint.clone()];
        for (height, kind) in [(9, BlockKind::EpochSeal1), (10, BlockKind::EpochSeal2)] {
            chain.push(
                BlockHeader::new(
                    set.genesis_hash(),
                    set.chain_id(),
                    set.protocol_version(),
                    set.epoch(),
                    View::new(height),
                    Height::new(height),
                    kind,
                    chain.last().unwrap().id(),
                    set.validators()[((height - 1) % 4) as usize].id(),
                    set.id(),
                    parameters.hash(),
                    checkpoint.payload_digest(),
                    checkpoint.state_root(),
                    checkpoint.receipts_root(),
                    checkpoint.evidence_root(),
                    height * 1000,
                    Some(authority.commitment().id()),
                )
                .unwrap(),
            );
        }
        let certified = |index: usize| {
            let header = chain[index].clone();
            let parent_header = if index == 0 {
                parent
            } else {
                &chain[index - 1]
            };
            let justify = QcReferenceV0::ordinary(qc(parent_header, set));
            let root = ProposalWitnessV0::signing_root_for(&header, &justify, None, None).unwrap();
            let index = set
                .validators()
                .iter()
                .position(|v| v.id() == header.proposer_id())
                .unwrap();
            CertifiedHeaderV0::new(
                header.clone(),
                justify,
                None,
                None,
                Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                qc(&header, set),
                set,
                None,
                parameters,
                parent_header.timestamp_ms(),
            )
            .unwrap()
        };
        let finality = FinalityProofV0::new(
            certified(0),
            certified(1),
            certified(2),
            set,
            None,
            parameters,
            parent.timestamp_ms(),
        )
        .unwrap();
        let terminal = &chain[2];
        let terminal_qc = qc(terminal, set);
        let new_set = authority.new_validator_set();
        let descriptor = HandoffDescriptorV0::new(HandoffDescriptorV0Fields {
            genesis_hash: set.genesis_hash(),
            chain_id: set.chain_id(),
            old_epoch: set.epoch(),
            new_epoch: new_set.epoch(),
            old_protocol_version: set.protocol_version(),
            new_protocol_version: new_set.protocol_version(),
            old_validator_set_hash: set.id(),
            new_validator_set_hash: new_set.id(),
            old_consensus_parameters_hash: parameters.hash(),
            new_consensus_parameters_hash: authority.new_parameters().hash(),
            checkpoint_height: checkpoint.height(),
            checkpoint_block_id: checkpoint.id(),
            checkpoint_state_root: checkpoint.state_root(),
            next_epoch_commitment_digest: authority.commitment().id(),
            terminal_old_height: terminal.height(),
            terminal_old_block_id: terminal.id(),
            terminal_old_qc_digest: terminal_qc.id(),
            terminal_old_view: terminal.view(),
            activation_height: Height::new(11),
            initial_new_view: View::new(1),
        })
        .unwrap();
        let shares = |old: bool| {
            let root = if old {
                descriptor.old_set_signing_root()
            } else {
                descriptor.new_set_signing_root()
            };
            (0..4)
                .map(|index| {
                    SignatureShareV0::new(
                        set.validators()[index].id(),
                        Signature64::from_array(key(index).sign(root.as_bytes()).to_bytes()),
                    )
                    .unwrap()
                })
                .collect()
        };
        let certificate = HandoffCertificateV0::new(
            descriptor.clone(),
            shares(true),
            shares(false),
            set,
            new_set,
        )
        .unwrap();
        let mut anchor = terminal.try_cev0_bytes().unwrap();
        anchor.extend_from_slice(&terminal_qc.try_cev0_bytes().unwrap());
        anchor.extend_from_slice(&certificate.try_cev0_bytes().unwrap());
        (finality.try_cev0_bytes().unwrap(), anchor)
    }

    fn ordinary_prefix(app: &DurableNativeApplicationV0) -> Vec<BlockHeader> {
        (0..7)
            .map(|_| {
                let (header, executed) = execute(app, next_request(app), BlockKind::Regular);
                app.commit_block(NativeApplicationCommitRequestV0::new(executed))
                    .unwrap();
                header
            })
            .collect()
    }

    fn preparation(
        app: &DurableNativeApplicationV0,
        headers: &[BlockHeader],
    ) -> PreparedNativePocoCheckpointV0 {
        app.prepare_native_poco_checkpoint_v0(
            &next_request(app),
            View::new(8),
            app.config_v0().validator_set_v0().validators()[3].id(),
            &cutoff_proof(headers, app.config_v0()),
            &headers[3].try_cev0_bytes().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn real_committed_checkpoint_and_signed_two_seals_produce_exact_handoff_readback() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("application.sqlite3");
        let app = open(&path, config());
        let headers = ordinary_prefix(&app);
        let prepared = preparation(&app, &headers);
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
        let NativeBlockExecutionResultV0::Valid(executed) = app.execute_block(request).unwrap()
        else {
            panic!("checkpoint execution invalid")
        };
        app.commit_block(NativeApplicationCommitRequestV0::new(*executed))
            .unwrap();
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
        // Rebuild from exact raw evidence after reopening the actual stores.
        drop(confirmed);
        drop(app);
        let reopened = DurableNativeApplicationV0::open(&path, config()).unwrap();
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
