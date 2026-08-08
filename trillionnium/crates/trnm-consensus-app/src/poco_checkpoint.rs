//! Production checkpoint execution binding for PoCO-BFT v0.
//!
//! H3b2a closes the authority context which must exist before application
//! semantics or candidate selection may consume a persisted PoCO projection.
//! The resulting capability has private fields and is created only from the
//! configured genesis/profile, the committed parent AppHash, an authenticated
//! cutoff projection, the actual CometBFT block hash/body, deterministic ABCI
//! execution results, and the exact post-execution AppHash.

use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};

use anyhow::{ensure, Context, Result};
use bytes::Bytes;
use prost::Message;
use serde::{Deserialize, Serialize};
use tendermint_proto::v0_38::abci::ExecTxResult;
use trnm_consensus_types::{
    decode_consensus_parameters_v0_exact, decode_validator_set_v0_exact, ChainId,
    ConsensusParametersHash, ConsensusParametersV0, Epoch, EpochGeometryV0, GenesisHash, Height,
    ProtocolVersion, StateRoot, ValidatorSet, ValidatorSetId,
};
use trnm_finality_types::{decode_hash32, hash_domain};

use crate::{
    auth_tree::InMemoryAuthTree,
    poco_snapshot::PocoSnapshotEntryKindV0,
    poco_transition::{
        decode_poco_snapshot_value_parts_v0_exact, take_and_validate_production_poco_projection_v0,
        ProductionPocoProjectionV0,
    },
    store::ApplicationStore,
    validator_lifecycle::ConsensusValidatorV1,
};

pub const POCO_AUTHORITY_CONFIG_SCHEMA_V0: &str = "trnm_poco_authority_config_v0";
pub(crate) const MAX_POCO_CHECKPOINT_INPUT_TX_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES: usize = 8 * 1024 * 1024;
const SCHEDULED_CUTOFF_AUTHORIZATION_DOMAIN_V0: &str =
    "trnm.poco-bft.scheduled-cutoff-authorization.v0";

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PocoAuthorityConfigV0 {
    pub schema: String,
    pub genesis_hash_hex: String,
    pub protocol_profile_hash_hex: String,
}

impl PocoAuthorityConfigV0 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema == POCO_AUTHORITY_CONFIG_SCHEMA_V0,
            "unsupported PoCO authority config schema"
        );
        ensure!(
            decode_hash32("PoCO genesis hash", &self.genesis_hash_hex)? != [0; 32],
            "PoCO genesis hash is zero"
        );
        ensure!(
            decode_hash32(
                "PoCO protocol profile hash",
                &self.protocol_profile_hash_hex
            )? != [0; 32],
            "PoCO protocol profile hash is zero"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PocoCheckpointExecutionInputV0<'a> {
    pub(crate) chain_id: &'a str,
    pub(crate) parent_height: u64,
    pub(crate) parent_state_root: [u8; 32],
    pub(crate) block_height: u64,
    pub(crate) block_hash: &'a [u8],
    pub(crate) timestamp_ms: u64,
    pub(crate) txs: &'a [Bytes],
    pub(crate) tx_results: &'a [ExecTxResult],
    pub(crate) next_state_root: [u8; 32],
}

/// Content view used by the checkpoint join.
///
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

/// Loads one historical authenticated state and seals its version, root, and
/// decoded production projection before any caller can observe them as
/// independent values. The pre-activation empty namespace remains explicit,
/// so ordinary legacy blocks continue while an H3b2b1 operation or scheduled
/// cutoff cannot silently manufacture an authority head.
pub(super) fn maybe_authenticated_poco_projection_at_v0(
    store: Option<&ApplicationStore>,
    auth_tree: &Mutex<InMemoryAuthTree>,
    version: u64,
) -> Result<Option<AuthenticatedPocoProjectionAtV0>> {
    if let Some(store) = store {
        let (root, projection) = store.production_poco_projection(version)?;
        return projection
            .map(|projection| {
                AuthenticatedPocoProjectionAtV0::from_verified_live_state(
                    version,
                    root.into(),
                    projection,
                )
            })
            .transpose();
    }

    let tree = auth_tree
        .lock()
        .map_err(|_| anyhow::anyhow!("authenticated state tree lock poisoned"))?;
    let root = tree
        .root_hash(version)
        .with_context(|| format!("missing authenticated root at version {version}"))?;
    let mut live = tree.verified_live_values(version)?;
    take_and_validate_production_poco_projection_v0(version, &mut live)?
        .map(|projection| {
            AuthenticatedPocoProjectionAtV0::from_verified_live_state(
                version,
                root.into(),
                projection,
            )
        })
        .transpose()
}

/// Private-field authority for the exact scheduled PoCO snapshot cutoff.
///
/// Unlike checkpoint execution authority, this value is available before a
/// checkpoint block exists: it binds only configured chain/genesis/profile,
/// the authenticated historical projection, the active consensus
/// configuration recovered from that projection, and the application
/// validator lifecycle mirror. It deliberately contains no block hash,
/// timestamp, body, receipt, parent, or post-execution state fact.
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

/// Authorizes the exact historical cutoff needed by pre-header candidate
/// selection. The runtime chain ID remains an explicit input because the
/// persisted authority config intentionally stores only genesis/profile; it
/// is checked against the chain ID sealed in the authenticated old set.
pub(crate) fn authorize_poco_scheduled_cutoff_v0(
    authority: &PocoAuthorityConfigV0,
    chain_id: &str,
    cutoff_state: &AuthenticatedPocoProjectionAtV0,
    active_application_validators: &[ConsensusValidatorV1],
) -> Result<AuthorizedPocoScheduledCutoffV0> {
    authority.validate()?;
    let chain_id = ChainId::from_bytes(chain_id.as_bytes())
        .map_err(|error| anyhow::anyhow!("invalid authoritative chain ID: {error:?}"))?;
    let genesis_hash = GenesisHash::new(decode_hash32(
        "PoCO genesis hash",
        &authority.genesis_hash_hex,
    )?);
    let protocol_profile_hash = decode_hash32(
        "PoCO protocol profile hash",
        &authority.protocol_profile_hash_hex,
    )?;
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

/// Private-field proof that one real application checkpoint execution was
/// joined to the exact finalized-cutoff projection and configured authority.
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
    checkpoint_block_hash: [u8; 32],
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
        bytes.extend_from_slice(&self.checkpoint_block_hash);
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

/// Exact ordered block-body evidence shared by checkpoint authorization and
/// the application-sequence conformance consumer.  The private fields cannot
/// construct a checkpoint capability; they only expose hashes/bytes already
/// recomputed from bounded production inputs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CheckpointBodyEvidenceV0 {
    payload_root: [u8; 32],
    encoded_receipts: Vec<Vec<u8>>,
    receipts_root: [u8; 32],
}

impl CheckpointBodyEvidenceV0 {
    pub(crate) const fn payload_root(&self) -> [u8; 32] {
        self.payload_root
    }

    #[cfg(test)]
    pub(crate) fn encoded_receipts(&self) -> &[Vec<u8>] {
        &self.encoded_receipts
    }

    pub(crate) const fn receipts_root(&self) -> [u8; 32] {
        self.receipts_root
    }
}

/// Performs the one bounded protobuf encoding and ordered-root computation
/// used everywhere checkpoint body evidence is needed.
pub(crate) fn checkpoint_body_evidence_v0(
    txs: &[Bytes],
    results: &[ExecTxResult],
) -> Result<CheckpointBodyEvidenceV0> {
    validate_checkpoint_body_bounds(txs, results)?;
    let payload_root = ordered_root("trnm.poco-bft.checkpoint-payload.v0", txs)?;
    let encoded_receipts = results
        .iter()
        .map(Message::encode_to_vec)
        .collect::<Vec<_>>();
    let receipts_root = ordered_root("trnm.poco-bft.checkpoint-receipts.v0", &encoded_receipts)?;
    Ok(CheckpointBodyEvidenceV0 {
        payload_root,
        encoded_receipts,
        receipts_root,
    })
}

pub(crate) fn authorize_poco_checkpoint_execution_v0(
    authority: &PocoAuthorityConfigV0,
    input: PocoCheckpointExecutionInputV0<'_>,
    cutoff_state: &AuthenticatedPocoProjectionAtV0,
    active_application_validators: &[ConsensusValidatorV1],
) -> Result<AuthorizedPocoCheckpointExecutionV0> {
    ensure!(
        input.parent_height.checked_add(1) == Some(input.block_height),
        "PoCO checkpoint parent height is not contiguous"
    );
    ensure!(input.parent_state_root != [0; 32], "zero parent AppHash");
    ensure!(input.next_state_root != [0; 32], "zero checkpoint AppHash");
    let checkpoint_block_hash: [u8; 32] = input
        .block_hash
        .try_into()
        .context("PoCO checkpoint block hash must be 32 bytes")?;
    ensure!(
        checkpoint_block_hash != [0; 32],
        "zero checkpoint block hash"
    );
    ensure!(input.timestamp_ms > 0, "zero checkpoint timestamp");
    let body_evidence = checkpoint_body_evidence_v0(input.txs, input.tx_results)?;
    let cutoff_authority = authorize_poco_scheduled_cutoff_v0(
        authority,
        input.chain_id,
        cutoff_state,
        active_application_validators,
    )?;
    ensure!(
        cutoff_authority.checkpoint_height().get() == input.block_height,
        "application block is not the authenticated epoch checkpoint"
    );
    ensure!(
        input.parent_height == input.block_height.saturating_sub(1),
        "checkpoint parent does not immediately precede checkpoint"
    );

    let mut value = AuthorizedPocoCheckpointExecutionV0 {
        genesis_hash: cutoff_authority.genesis_hash(),
        chain_id: cutoff_authority.chain_id(),
        protocol_profile_hash: cutoff_authority.protocol_profile_hash(),
        protocol_version: cutoff_authority.protocol_version(),
        epoch: cutoff_authority.epoch(),
        checkpoint_height: Height::new(input.block_height),
        checkpoint_block_hash,
        checkpoint_timestamp_ms: input.timestamp_ms,
        parent_height: Height::new(input.parent_height),
        parent_state_root: StateRoot::new(input.parent_state_root),
        cutoff_height: cutoff_authority.cutoff_height(),
        cutoff_state_root: cutoff_authority.cutoff_state_root(),
        cutoff_entries_root: cutoff_authority.cutoff_entries_root(),
        cutoff_entry_count: cutoff_authority.cutoff_entry_count(),
        payload_root: body_evidence.payload_root(),
        receipts_root: body_evidence.receipts_root(),
        next_state_root: StateRoot::new(input.next_state_root),
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

/// Single production join for checkpoint execution and application-
/// authenticated B2-G reconstruction. The cutoff projection never leaves the
/// call between the two authorizations, and no old inert B2-G token is an
/// input.
pub(crate) fn authorize_poco_checkpoint_candidate_selection_v0(
    authority: &PocoAuthorityConfigV0,
    input: PocoCheckpointExecutionInputV0<'_>,
    cutoff_state: &AuthenticatedPocoProjectionAtV0,
    active_application_validators: &[ConsensusValidatorV1],
) -> Result<crate::poco_application::AuthenticatedPocoCandidateSelectionV0> {
    let checkpoint = authorize_poco_checkpoint_execution_v0(
        authority,
        input,
        cutoff_state,
        active_application_validators,
    )?;
    crate::poco_application::authorize_authenticated_poco_candidate_selection_v0(
        checkpoint,
        cutoff_state,
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

fn validate_checkpoint_body_cardinality(tx_count: usize, result_count: usize) -> Result<u32> {
    ensure!(
        tx_count == result_count,
        "checkpoint transaction/result cardinality mismatch"
    );
    u32::try_from(tx_count).context("checkpoint transaction/result count exceeds u32")
}

fn validate_checkpoint_body_byte_totals(tx_bytes: usize, receipt_bytes: usize) -> Result<()> {
    ensure!(
        tx_bytes <= MAX_POCO_CHECKPOINT_INPUT_TX_BYTES,
        "checkpoint transaction bytes exceed protocol bound"
    );
    ensure!(
        receipt_bytes <= MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES,
        "checkpoint encoded receipt bytes exceed protocol bound"
    );
    Ok(())
}

fn validate_checkpoint_body_bounds(txs: &[Bytes], results: &[ExecTxResult]) -> Result<u32> {
    let count = validate_checkpoint_body_cardinality(txs.len(), results.len())?;
    let tx_bytes = txs.iter().try_fold(0usize, |total, tx| {
        let total = total
            .checked_add(tx.len())
            .context("checkpoint transaction byte total overflow")?;
        ensure!(
            total <= MAX_POCO_CHECKPOINT_INPUT_TX_BYTES,
            "checkpoint transaction bytes exceed protocol bound"
        );
        Ok::<_, anyhow::Error>(total)
    })?;
    let receipt_bytes = results.iter().try_fold(0usize, |total, result| {
        let total = total
            .checked_add(result.encoded_len())
            .context("checkpoint encoded receipt byte total overflow")?;
        ensure!(
            total <= MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES,
            "checkpoint encoded receipt bytes exceed protocol bound"
        );
        Ok::<_, anyhow::Error>(total)
    })?;
    validate_checkpoint_body_byte_totals(tx_bytes, receipt_bytes)?;
    Ok(count)
}

fn ordered_root<T: AsRef<[u8]>>(domain: &str, values: &[T]) -> Result<[u8; 32]> {
    let count = u32::try_from(values.len()).context("ordered-root value count exceeds u32")?;
    let mut layer = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let index = u32::try_from(index).expect("ordered-root count was checked before hashing");
        layer.push(hash_domain(
            &format!("{domain}.leaf"),
            &[&index.to_be_bytes(), value.as_ref()],
        ));
    }
    let mut level = 0u32;
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        for pair in layer.chunks(2) {
            let right = pair.get(1).unwrap_or(&pair[0]);
            next.push(hash_domain(
                &format!("{domain}.node"),
                &[&level.to_be_bytes(), &pair[0], right],
            ));
        }
        layer = next;
        level = level
            .checked_add(1)
            .context("ordered-root level overflow")?;
    }
    let count = count.to_be_bytes();
    Ok(match layer.first() {
        Some(root) => hash_domain(domain, &[&count, &[1], root]),
        None => hash_domain(domain, &[&count, &[0]]),
    })
}

fn encode_bytes(output: &mut Vec<u8>, value: &[u8]) {
    let length = u16::try_from(value.len()).expect("consensus chain ID bound fits u16");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::Value;

    use super::*;
    use crate::{
        poco_application::{
            authorize_authenticated_poco_cutoff_candidate_selection_v0,
            genesis_poco_application_authority_entry_v0,
        },
        poco_snapshot::{
            poco_snapshot_entry_key, poco_snapshot_manifest_key, PocoSnapshotEntryV0,
            PocoSnapshotManifestV0,
        },
        poco_transition::take_and_validate_production_poco_projection_v0,
    };

    const TRANSITION_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-snapshot-transition-v0.json"
    );
    const CHECKPOINT_VECTOR: &str = include_str!(
        "../../../../docs/protocol/poco-bft-v0/vectors/poco-checkpoint-execution-v0.json"
    );

    struct Fixture {
        authority: PocoAuthorityConfigV0,
        projection: ProductionPocoProjectionV0,
        validators: Vec<ConsensusValidatorV1>,
        chain_id: String,
        checkpoint_height: u64,
        cutoff_height: u64,
        txs: Vec<Bytes>,
        results: Vec<ExecTxResult>,
    }

    impl Fixture {
        fn input(&self) -> PocoCheckpointExecutionInputV0<'_> {
            PocoCheckpointExecutionInputV0 {
                chain_id: &self.chain_id,
                parent_height: self.checkpoint_height - 1,
                parent_state_root: [3; 32],
                block_height: self.checkpoint_height,
                block_hash: &[4; 32],
                timestamp_ms: 1_700_000_000_000,
                txs: &self.txs,
                tx_results: &self.results,
                next_state_root: [5; 32],
            }
        }

        fn cutoff(&self) -> AuthenticatedPocoProjectionAtV0 {
            AuthenticatedPocoProjectionAtV0::from_verified_live_state(
                self.cutoff_height,
                [6; 32],
                self.projection.clone(),
            )
            .unwrap()
        }
    }

    fn fixture() -> Fixture {
        let vector: Value = serde_json::from_str(TRANSITION_VECTOR).unwrap();
        let positives = vector["semantic_layout_corpus"]["positive_fixtures"]
            .as_array()
            .unwrap();
        let mut entries = Vec::new();
        for kind in [13_u8, 14_u8] {
            let source = positives
                .iter()
                .find(|fixture| fixture["kind"].as_u64() == Some(u64::from(kind)))
                .unwrap();
            entries.push(
                PocoSnapshotEntryV0::new(
                    PocoSnapshotEntryKindV0::from_u8(kind).unwrap(),
                    hex::decode(source["logical_key_hex"].as_str().unwrap()).unwrap(),
                    hex::decode(source["value_cev0_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap(),
            );
        }
        entries.sort_by(|left, right| {
            (left.kind, left.logical_key.as_slice())
                .cmp(&(right.kind, right.logical_key.as_slice()))
        });
        let parameter_entry = entries
            .iter()
            .find(|entry| entry.kind == PocoSnapshotEntryKindV0::ConsensusParameters)
            .unwrap();
        let parameter_parts = decode_poco_snapshot_value_parts_v0_exact(
            parameter_entry.kind,
            &parameter_entry.logical_key,
            &parameter_entry.value,
        )
        .unwrap();
        let parameters = decode_consensus_parameters_v0_exact(parameter_parts.payload).unwrap();
        let checkpoint_height = EpochGeometryV0::new(Epoch::new(0), &parameters)
            .unwrap()
            .checkpoint_height()
            .get();
        let cutoff_height = checkpoint_height - parameters.snapshot_lead_blocks();
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(cutoff_height), &entries).unwrap();
        let mut live = BTreeMap::new();
        live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
        for entry in &entries {
            live.insert(
                poco_snapshot_entry_key(entry.kind, &entry.logical_key).unwrap(),
                entry.value.clone(),
            );
        }
        let projection = take_and_validate_production_poco_projection_v0(cutoff_height, &mut live)
            .unwrap()
            .unwrap();
        assert!(live.is_empty());
        let (set, parameters) = active_consensus_configuration(&projection).unwrap();
        let validators = set
            .validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect();
        Fixture {
            authority: PocoAuthorityConfigV0 {
                schema: POCO_AUTHORITY_CONFIG_SCHEMA_V0.to_string(),
                genesis_hash_hex: hex::encode(set.genesis_hash().as_bytes()),
                protocol_profile_hash_hex: hex::encode(parameters.hash().as_bytes()),
            },
            projection,
            validators,
            chain_id: String::from_utf8(set.chain_id().as_bytes().to_vec()).unwrap(),
            checkpoint_height,
            cutoff_height,
            txs: vec![Bytes::from_static(b"tx-a"), Bytes::from_static(b"tx-b")],
            results: vec![ExecTxResult::default(), ExecTxResult::default()],
        }
    }

    fn projection_from_entries_at(
        entries: &[PocoSnapshotEntryV0],
        manifest_height: u64,
        state_height: u64,
    ) -> ProductionPocoProjectionV0 {
        let manifest =
            PocoSnapshotManifestV0::from_entries(Height::new(manifest_height), entries).unwrap();
        let mut live = BTreeMap::new();
        live.insert(poco_snapshot_manifest_key().unwrap(), manifest.encode());
        for entry in entries {
            live.insert(
                poco_snapshot_entry_key(entry.kind, &entry.logical_key).unwrap(),
                entry.value.clone(),
            );
        }
        let projection = take_and_validate_production_poco_projection_v0(state_height, &mut live)
            .unwrap()
            .unwrap();
        assert!(live.is_empty());
        projection
    }

    #[test]
    fn checkpoint_execution_binds_authority_parent_cutoff_body_receipts_and_next_root() {
        let fixture = fixture();
        let capability = authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            fixture.input(),
            &fixture.cutoff(),
            &fixture.validators,
        )
        .unwrap();
        assert_eq!(capability.epoch(), Epoch::new(0));
        assert_eq!(
            capability.checkpoint_height(),
            Height::new(fixture.checkpoint_height)
        );
        assert_eq!(
            capability.cutoff_height(),
            Height::new(fixture.cutoff_height)
        );
        assert_ne!(capability.payload_root(), [0; 32]);
        assert_ne!(capability.receipts_root(), [0; 32]);
        assert_ne!(capability.execution_id(), [0; 32]);
        assert_eq!(capability.canonical_bytes().len(), 425);
        let vector: Value = serde_json::from_str(CHECKPOINT_VECTOR).unwrap();
        let valid = &vector["valid_case"];
        assert_eq!(valid["chain_id"].as_str().unwrap(), fixture.chain_id);
        assert_eq!(
            valid["genesis_hash_hex"].as_str().unwrap(),
            fixture.authority.genesis_hash_hex
        );
        assert_eq!(
            valid["protocol_profile_hash_hex"].as_str().unwrap(),
            fixture.authority.protocol_profile_hash_hex
        );
        assert_eq!(
            valid["payload_root_hex"].as_str().unwrap(),
            hex::encode(capability.payload_root())
        );
        assert_eq!(
            valid["receipts_root_hex"].as_str().unwrap(),
            hex::encode(capability.receipts_root())
        );
        assert_eq!(
            valid["cutoff_manifest_entries_root_hex"].as_str().unwrap(),
            hex::encode(capability.cutoff_entries_root())
        );
        assert_eq!(
            valid["cutoff_manifest_entry_count"].as_u64().unwrap(),
            u64::from(capability.cutoff_entry_count())
        );
        assert_eq!(
            valid["canonical_hex"].as_str().unwrap(),
            hex::encode(capability.canonical_bytes())
        );
        assert_eq!(
            valid["execution_id_hex"].as_str().unwrap(),
            hex::encode(capability.execution_id())
        );

        let mut reordered = fixture.input();
        let reversed = fixture.txs.iter().cloned().rev().collect::<Vec<_>>();
        reordered.txs = &reversed;
        let other = authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            reordered,
            &fixture.cutoff(),
            &fixture.validators,
        )
        .unwrap();
        assert_ne!(other.payload_root(), capability.payload_root());
        assert_ne!(other.execution_id(), capability.execution_id());
    }

    #[test]
    fn scheduled_cutoff_authority_binds_configuration_geometry_and_validator_mirror() {
        let fixture = fixture();
        let cutoff = fixture.cutoff();
        let authorized = authorize_poco_scheduled_cutoff_v0(
            &fixture.authority,
            &fixture.chain_id,
            &cutoff,
            &fixture.validators,
        )
        .unwrap();
        assert_eq!(authorized.epoch(), Epoch::new(0));
        assert_eq!(
            authorized.checkpoint_height(),
            Height::new(fixture.checkpoint_height)
        );
        assert_eq!(
            authorized.cutoff_height(),
            Height::new(fixture.cutoff_height)
        );
        assert_eq!(authorized.cutoff_state_root(), StateRoot::new([6; 32]));
        assert_eq!(
            authorized.old_validator_set().consensus_parameters_hash(),
            authorized.old_parameters().hash()
        );
        assert_ne!(authorized.authorization_id(), [0; 32]);

        let mut bad_genesis = fixture.authority.clone();
        bad_genesis.genesis_hash_hex = hex::encode([9; 32]);
        assert!(authorize_poco_scheduled_cutoff_v0(
            &bad_genesis,
            &fixture.chain_id,
            &cutoff,
            &fixture.validators,
        )
        .is_err());

        let mut bad_profile = fixture.authority.clone();
        bad_profile.protocol_profile_hash_hex = hex::encode([8; 32]);
        assert!(authorize_poco_scheduled_cutoff_v0(
            &bad_profile,
            &fixture.chain_id,
            &cutoff,
            &fixture.validators,
        )
        .is_err());

        assert!(authorize_poco_scheduled_cutoff_v0(
            &fixture.authority,
            "wrong-chain",
            &cutoff,
            &fixture.validators,
        )
        .is_err());

        let mut wrong_validators = fixture.validators.clone();
        wrong_validators[0].voting_power += 1;
        assert!(authorize_poco_scheduled_cutoff_v0(
            &fixture.authority,
            &fixture.chain_id,
            &cutoff,
            &wrong_validators,
        )
        .is_err());

        // The same projection content at a later live version is not the
        // scheduled historical cutoff tuple.
        let advanced = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            fixture.cutoff_height + 1,
            [7; 32],
            fixture.projection.clone(),
        )
        .unwrap();
        assert!(authorize_poco_scheduled_cutoff_v0(
            &fixture.authority,
            &fixture.chain_id,
            &advanced,
            &fixture.validators,
        )
        .is_err());
    }

    #[test]
    fn live_parent_projection_may_lag_cutoff_manifest_without_weakening_exact_cutoff() {
        let fixture = fixture();
        let parent_height = fixture.checkpoint_height - 1;
        assert!(fixture.checkpoint_height - fixture.cutoff_height > 1);
        assert!(parent_height > fixture.cutoff_height);

        // An ordinary post-cutoff no-op keeps the manifest at the cutoff
        // height even though the authenticated JMT state has advanced.
        let live_parent = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            parent_height,
            [7; 32],
            fixture.projection.clone(),
        )
        .unwrap();
        let cutoff = fixture.cutoff();
        assert_eq!(live_parent.version(), parent_height);
        assert_eq!(
            live_parent.projection().manifest().cutoff_height().get(),
            fixture.cutoff_height
        );
        assert_eq!(cutoff.projection(), live_parent.projection());

        // An explicit later refresh changes only the manifest timestamp. It
        // still represents the same ordered namespace content for the
        // checkpoint freeze comparison.
        let refreshed_projection =
            projection_from_entries_at(fixture.projection.entries(), parent_height, parent_height);
        let refreshed_parent = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            parent_height,
            [8; 32],
            refreshed_projection,
        )
        .unwrap();
        assert_eq!(cutoff.projection(), refreshed_parent.projection());

        // The live parent can never be substituted for the scheduled cutoff:
        // cutoff authorization retains exact JMT-version/manifest-height
        // equality even when the namespace content is unchanged.
        assert!(authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            fixture.input(),
            &live_parent,
            &fixture.validators,
        )
        .is_err());

        // A manifest from the future is invalid even on the live path.
        let future_projection = projection_from_entries_at(
            fixture.projection.entries(),
            parent_height + 1,
            parent_height + 1,
        );
        assert!(AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            parent_height,
            [9; 32],
            future_projection,
        )
        .is_err());
    }

    #[test]
    fn checkpoint_projection_content_comparison_rejects_post_cutoff_changes() {
        let fixture = fixture();
        let parent_height = fixture.checkpoint_height - 1;
        let cutoff = fixture.cutoff();
        let mut changed_entries = fixture.projection.entries().to_vec();
        changed_entries
            .pop()
            .expect("fixture has configuration entries");
        let changed_projection =
            projection_from_entries_at(&changed_entries, fixture.cutoff_height, parent_height);
        let changed_parent = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            parent_height,
            [10; 32],
            changed_projection,
        )
        .unwrap();

        assert_ne!(cutoff.projection(), changed_parent.projection());
    }

    #[test]
    fn candidate_join_rejects_legacy_cutoff_without_application_authority() {
        let fixture = fixture();
        assert!(authorize_poco_checkpoint_candidate_selection_v0(
            &fixture.authority,
            fixture.input(),
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());
    }

    #[test]
    fn authenticated_empty_authority_produces_bound_b2g_fallback() {
        let fixture = fixture();
        let mut entries = fixture.projection.entries().to_vec();
        entries.push(genesis_poco_application_authority_entry_v0().unwrap());
        let projection =
            projection_from_entries_at(&entries, fixture.cutoff_height, fixture.cutoff_height);
        let cutoff = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            fixture.cutoff_height,
            [6; 32],
            projection,
        )
        .unwrap();
        let capability = authorize_poco_checkpoint_candidate_selection_v0(
            &fixture.authority,
            fixture.input(),
            &cutoff,
            &fixture.validators,
        )
        .unwrap();
        assert!(capability.fallback_used());
        assert_eq!(
            capability.fallback_reason(),
            trnm_consensus_types::EpochFallbackReasonV0::TooFewEligibleValidators
        );
        assert_ne!(capability.transcript_digest(), [0; 32]);
        assert_ne!(capability.result_digest(), [0; 32]);
        assert_ne!(capability.authorization_id(), [0; 32]);
    }

    #[test]
    fn cutoff_only_candidate_matches_post_execution_computation_and_rejects_splice() {
        let fixture = fixture();
        let mut entries = fixture.projection.entries().to_vec();
        entries.push(genesis_poco_application_authority_entry_v0().unwrap());
        let projection =
            projection_from_entries_at(&entries, fixture.cutoff_height, fixture.cutoff_height);
        let cutoff = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            fixture.cutoff_height,
            [6; 32],
            projection.clone(),
        )
        .unwrap();
        let cutoff_authority = authorize_poco_scheduled_cutoff_v0(
            &fixture.authority,
            &fixture.chain_id,
            &cutoff,
            &fixture.validators,
        )
        .unwrap();
        let pre_header = authorize_authenticated_poco_cutoff_candidate_selection_v0(
            cutoff_authority.clone(),
            &cutoff,
        )
        .unwrap();
        let post_execution = authorize_poco_checkpoint_candidate_selection_v0(
            &fixture.authority,
            fixture.input(),
            &cutoff,
            &fixture.validators,
        )
        .unwrap();

        assert_eq!(
            pre_header.scheduled_cutoff().authorization_id(),
            cutoff_authority.authorization_id()
        );
        assert_eq!(
            pre_header.old_validator_set(),
            post_execution.old_validator_set()
        );
        assert_eq!(pre_header.old_parameters(), post_execution.old_parameters());
        assert_eq!(pre_header.fallback_used(), post_execution.fallback_used());
        assert_eq!(
            pre_header.fallback_reason(),
            post_execution.fallback_reason()
        );
        assert_eq!(
            pre_header.effective_validator_set(),
            post_execution.effective_validator_set()
        );
        assert_eq!(
            pre_header.effective_parameters(),
            post_execution.effective_parameters()
        );
        assert_eq!(
            pre_header.candidate_parameters_hash(),
            post_execution.candidate_parameters_hash()
        );
        assert_eq!(
            pre_header.transcript_canonical_bytes(),
            post_execution.transcript_canonical_bytes()
        );
        assert_eq!(
            pre_header.result_canonical_bytes(),
            post_execution.result_canonical_bytes()
        );
        assert_eq!(
            pre_header.transcript_digest(),
            post_execution.transcript_digest()
        );
        assert_eq!(pre_header.result_digest(), post_execution.result_digest());
        assert_eq!(
            pre_header.computed_candidate_ids(),
            post_execution.computed_candidate_ids()
        );
        assert_ne!(pre_header.authorization_id(), [0; 32]);
        assert_ne!(
            pre_header.authorization_id(),
            post_execution.authorization_id()
        );

        let spliced_cutoff = AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            fixture.cutoff_height,
            [7; 32],
            projection,
        )
        .unwrap();
        assert!(authorize_authenticated_poco_cutoff_candidate_selection_v0(
            cutoff_authority,
            &spliced_cutoff,
        )
        .is_err());
    }

    #[test]
    fn checkpoint_execution_authority_relations_fail_closed() {
        let fixture = fixture();
        let mut bad_authority = fixture.authority.clone();
        bad_authority.genesis_hash_hex = hex::encode([9; 32]);
        assert!(authorize_poco_checkpoint_execution_v0(
            &bad_authority,
            fixture.input(),
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());

        let mut bad_profile = fixture.authority.clone();
        bad_profile.protocol_profile_hash_hex = hex::encode([8; 32]);
        assert!(authorize_poco_checkpoint_execution_v0(
            &bad_profile,
            fixture.input(),
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());

        let mut bad_parent = fixture.input();
        bad_parent.parent_height -= 1;
        assert!(authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            bad_parent,
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());

        assert!(AuthenticatedPocoProjectionAtV0::from_verified_live_state(
            fixture.cutoff_height - 1,
            [6; 32],
            fixture.projection.clone(),
        )
        .is_err());

        let mut wrong_validators = fixture.validators.clone();
        wrong_validators[0].voting_power += 1;
        assert!(authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            fixture.input(),
            &fixture.cutoff(),
            &wrong_validators,
        )
        .is_err());

        let short_hash = [1_u8; 31];
        let mut bad_hash = fixture.input();
        bad_hash.block_hash = &short_hash;
        assert!(authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            bad_hash,
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());

        let short_results = [ExecTxResult::default()];
        let mut bad_results = fixture.input();
        bad_results.tx_results = &short_results;
        assert!(authorize_poco_checkpoint_execution_v0(
            &fixture.authority,
            bad_results,
            &fixture.cutoff(),
            &fixture.validators,
        )
        .is_err());
    }

    #[test]
    fn checkpoint_body_resource_bounds_are_exact_and_allocation_free() {
        let exact_u32_count = usize::try_from(u64::from(u32::MAX)).unwrap();
        assert_eq!(
            validate_checkpoint_body_cardinality(exact_u32_count, exact_u32_count).unwrap(),
            u32::MAX
        );
        assert!(validate_checkpoint_body_cardinality(1, 0).is_err());
        if let Ok(over_u32_count) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert!(validate_checkpoint_body_cardinality(over_u32_count, over_u32_count).is_err());
        }

        assert!(validate_checkpoint_body_byte_totals(
            MAX_POCO_CHECKPOINT_INPUT_TX_BYTES,
            MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES,
        )
        .is_ok());
        assert!(validate_checkpoint_body_byte_totals(
            MAX_POCO_CHECKPOINT_INPUT_TX_BYTES + 1,
            MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES,
        )
        .is_err());
        assert!(validate_checkpoint_body_byte_totals(
            MAX_POCO_CHECKPOINT_INPUT_TX_BYTES,
            MAX_POCO_CHECKPOINT_ENCODED_RECEIPT_BYTES + 1,
        )
        .is_err());

        assert_eq!(
            validate_checkpoint_body_bounds(
                &[Bytes::from_static(b"a")],
                &[ExecTxResult::default()],
            )
            .unwrap(),
            1
        );
        assert!(ordered_root("trnm.poco-bft.test-resource-root.v0", &[b"a"]).is_ok());
    }
}
