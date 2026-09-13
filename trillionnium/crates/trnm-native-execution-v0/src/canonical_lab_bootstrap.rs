//! Canonical chain-level laboratory genesis and the empty h1-h3 prefix.
//!
//! Chain genesis is derived only from frozen consensus and application-policy
//! inputs. Deployment identity is deliberately absent. The prefix owner is
//! memory-only, carries no signing key, and keeps the complete state plan
//! private until one exact regular block is committed.

use std::{collections::BTreeSet, sync::Arc};

use anyhow::{anyhow, ensure, Context, Result};
use trnm_consensus_types::{
    validate_root_bound_regular_body_v0, Block, BlockId, ChainId, ConsensusParametersV0, Epoch,
    EvidenceRoot, GenesisHash, Height, PayloadDigest, ProtocolVersion, ReceiptsRoot, StateRoot,
    Validator, ValidatorSet,
};
use trnm_finality_types::{crypto::decode_hash32, hash_domain};
use trnm_native_application::{
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, HeightV0,
    StateRootV0, ValidatorSetIdV0,
};

use crate::{
    complete::{
        compute_complete_native_block_v0, ComputedCompleteExecutionV0, NativeBlockPreviewRequestV0,
    },
    store::InMemoryNativeExecutionStoreV0,
    validator_lifecycle::{
        ConsensusValidatorV1, ValidatorGovernanceV1, ValidatorLifecycleStateV1,
        VALIDATOR_GOVERNANCE_SCHEMA_V1,
    },
    AuthorizedSignerV0,
};

const LAB_CHAIN_DESCRIPTOR_DOMAIN_V0: &str =
    "trnm.native-application.canonical-lab-chain-descriptor.v0";
const LAB_GENESIS_HASH_DOMAIN_V0: &str = "trnm.native-application.canonical-lab-genesis-hash.v0";
const LAB_LIFECYCLE_DOMAIN_V0: &str = "trnm.native-application.canonical-lab-lifecycle.v0";
const LAB_INITIAL_COMMIT_DOMAIN_V0: &str =
    "trnm.native-application.canonical-lab-initial-commit.v0";
const LAB_EMPTY_PREFIX_COMMIT_DOMAIN_V0: &str =
    "trnm.native-application.canonical-lab-empty-prefix-commit.v0";
const CANONICAL_LAB_GENESIS_TIMESTAMP_MS_V0: u64 = 0;
const CANONICAL_EMPTY_PREFIX_LAST_HEIGHT_V0: u64 = 3;

/// Derives the canonical lab genesis hash from chain identity, the frozen
/// consensus-parameter preimage, and one canonical validator inventory.
///
/// Deployment facts are absent by construction: this API cannot accept a run
/// ID, coordinator, topology, source revision, local validator, store ID, or
/// filesystem path. The returned hash is therefore safe to place in consensus
/// headers shared by byte-identical deployments of the same chain material.
pub fn derive_canonical_lab_genesis_hash_v0(
    chain_id: ChainId,
    consensus_parameters: ConsensusParametersV0,
    validators: &[Validator],
) -> Result<GenesisHash> {
    consensus_parameters
        .validate_safety_invariants()
        .map_err(crate::consensus_error)?;
    crate::validate_poco_parameter_retention_v0(&consensus_parameters)?;

    // Reuse ValidatorSet's frozen canonical-order, uniqueness, power, and
    // parameter-bound validation instead of maintaining a second validator
    // admission implementation. The sentinel is not hashed below.
    let validation_set = ValidatorSet::new(
        GenesisHash::new([0xff; 32]),
        chain_id,
        ProtocolVersion::V0,
        Epoch::new(0),
        consensus_parameters.hash(),
        validators.to_vec(),
    )
    .map_err(crate::consensus_error)?;
    validation_set
        .validate_against_parameters(&consensus_parameters)
        .map_err(crate::consensus_error)?;

    let validator_count = u32::try_from(validators.len())
        .context("canonical lab validator count exceeds u32")?
        .to_be_bytes();
    let mut validator_inventory = Vec::new();
    for validator in validators {
        let id = validator.id();
        let id_length = u16::try_from(id.as_bytes().len())
            .context("canonical lab validator ID exceeds u16")?
            .to_be_bytes();
        validator_inventory.extend_from_slice(&id_length);
        validator_inventory.extend_from_slice(id.as_bytes());
        validator_inventory.extend_from_slice(validator.consensus_key().as_bytes());
        validator_inventory.extend_from_slice(&validator.voting_power().get().to_be_bytes());
    }
    let protocol_version = ProtocolVersion::V0.get().to_be_bytes();
    let epoch = 0_u64.to_be_bytes();
    let hash = hash_domain(
        LAB_GENESIS_HASH_DOMAIN_V0,
        &[
            chain_id.as_bytes(),
            &protocol_version,
            &epoch,
            consensus_parameters.hash().as_bytes(),
            &validator_count,
            &validator_inventory,
        ],
    );
    ensure!(hash != [0; 32], "canonical lab genesis hash is zero");
    Ok(GenesisHash::new(hash))
}

/// Closed, deployment-independent inputs for canonical laboratory chain
/// genesis.
///
/// This value contains public verification keys only. It accepts no run ID,
/// host identity, local path, process identity, clock, or secret key material.
#[derive(Debug, Clone)]
pub struct CanonicalLabNativeChainGenesisInputsV0 {
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    application_signers: Vec<AuthorizedSignerV0>,
    governance_signer_id: String,
}

impl CanonicalLabNativeChainGenesisInputsV0 {
    pub fn new(
        validator_set: ValidatorSet,
        consensus_parameters: ConsensusParametersV0,
        application_signers: Vec<AuthorizedSignerV0>,
        governance_signer_id: impl Into<String>,
    ) -> Result<Self> {
        let governance_signer_id = governance_signer_id.into();
        consensus_parameters
            .validate_safety_invariants()
            .map_err(crate::consensus_error)?;
        validator_set
            .validate_against_parameters(&consensus_parameters)
            .map_err(crate::consensus_error)?;
        crate::validate_poco_parameter_retention_v0(&consensus_parameters)?;
        ensure!(
            validator_set.protocol_version() == ProtocolVersion::V0
                && validator_set.epoch().get() == 0,
            "canonical lab application requires frozen-v0 epoch zero"
        );
        ensure!(
            !application_signers.is_empty() && application_signers.len() <= 100,
            "canonical lab application signer policy is outside bounds"
        );
        ensure!(
            !governance_signer_id.is_empty()
                && governance_signer_id.len() <= 256
                && governance_signer_id == governance_signer_id.trim(),
            "canonical lab governance signer id is not canonical"
        );
        Ok(Self {
            validator_set,
            consensus_parameters,
            application_signers,
            governance_signer_id,
        })
    }
}

/// The five chain-invariant canonical laboratory genesis facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalLabNativeChainGenesisFactsV0 {
    chain_descriptor_hash: [u8; 32],
    signer_policy_commitment: [u8; 32],
    initial_block_id: [u8; 32],
    initial_state_root: [u8; 32],
    initial_commit_id: [u8; 32],
}

impl CanonicalLabNativeChainGenesisFactsV0 {
    pub(crate) const fn new_for_config_v0(
        chain_descriptor_hash: [u8; 32],
        signer_policy_commitment: [u8; 32],
        initial_block_id: [u8; 32],
        initial_state_root: [u8; 32],
        initial_commit_id: [u8; 32],
    ) -> Self {
        Self {
            chain_descriptor_hash,
            signer_policy_commitment,
            initial_block_id,
            initial_state_root,
            initial_commit_id,
        }
    }

    pub const fn chain_descriptor_hash_v0(self) -> [u8; 32] {
        self.chain_descriptor_hash
    }

    pub const fn signer_policy_commitment_v0(self) -> [u8; 32] {
        self.signer_policy_commitment
    }

    pub const fn initial_block_id_v0(self) -> [u8; 32] {
        self.initial_block_id
    }

    pub const fn initial_state_root_v0(self) -> [u8; 32] {
        self.initial_state_root
    }

    pub const fn initial_commit_id_v0(self) -> [u8; 32] {
        self.initial_commit_id
    }
}

pub(crate) struct CanonicalLabNativeChainGenesisMaterialV0 {
    pub(crate) facts: CanonicalLabNativeChainGenesisFactsV0,
    pub(crate) validator_set: ValidatorSet,
    pub(crate) consensus_parameters: ConsensusParametersV0,
    pub(crate) application_signers: Vec<AuthorizedSignerV0>,
    pub(crate) initial_snapshot: Vec<u8>,
    pub(crate) initial_store: InMemoryNativeExecutionStoreV0,
}

/// Derives only the inert chain-level genesis facts. No store owner or
/// execution authority is returned.
pub fn derive_canonical_lab_native_chain_genesis_v0(
    inputs: CanonicalLabNativeChainGenesisInputsV0,
) -> Result<CanonicalLabNativeChainGenesisFactsV0> {
    Ok(derive_canonical_lab_native_chain_genesis_material_v0(inputs)?.facts)
}

pub(crate) fn derive_canonical_lab_native_chain_genesis_material_v0(
    inputs: CanonicalLabNativeChainGenesisInputsV0,
) -> Result<CanonicalLabNativeChainGenesisMaterialV0> {
    let CanonicalLabNativeChainGenesisInputsV0 {
        validator_set,
        consensus_parameters,
        mut application_signers,
        governance_signer_id,
    } = inputs;

    application_signers.sort();
    let signer_policy_commitment = crate::signer_policy_commitment_v0(&application_signers)?;
    let consensus_keys: BTreeSet<[u8; 32]> = validator_set
        .validators()
        .iter()
        .map(|validator| validator.consensus_key().into_bytes())
        .collect();
    for signer in &application_signers {
        ensure!(
            signer.signer_id() == signer.signer_id().trim() && signer.signer_id().len() <= 256,
            "canonical lab application signer id is not canonical"
        );
        let application_key = decode_hash32(
            "canonical lab application public key",
            signer.public_key_hex(),
        )?;
        ensure!(
            !consensus_keys.contains(&application_key),
            "application signer key overlaps a consensus key"
        );
    }
    let governance_signer = application_signers
        .iter()
        .find(|signer| signer.signer_id() == governance_signer_id)
        .ok_or_else(|| anyhow!("governance signer is absent from application policy"))?;
    ensure!(
        governance_signer.signer_role() == "operator",
        "governance signer must have the operator role"
    );

    let lifecycle = ValidatorLifecycleStateV1::from_genesis(
        validator_set.chain_id().as_str().to_owned(),
        1,
        hex::encode(signer_policy_commitment),
        ValidatorGovernanceV1 {
            schema: VALIDATOR_GOVERNANCE_SCHEMA_V1.to_owned(),
            signer_id: governance_signer_id,
            min_activation_delay_blocks: 2,
            unsafe_allow_single_validator_genesis: false,
        },
        validator_set
            .validators()
            .iter()
            .map(|validator| ConsensusValidatorV1 {
                public_key_hex: hex::encode(validator.consensus_key().as_bytes()),
                voting_power: validator.voting_power().get(),
            })
            .collect(),
    )?;
    lifecycle.validate()?;
    crate::complete::validate_application_validator_projection_v0(
        &validator_set,
        &lifecycle.active_validators,
    )?;
    let lifecycle_json = serde_json::to_vec(&lifecycle)?;
    let decoded_lifecycle: ValidatorLifecycleStateV1 =
        serde_json::from_slice(&lifecycle_json).context("decode canonical lab lifecycle")?;
    ensure!(
        serde_json::to_vec(&decoded_lifecycle)? == lifecycle_json,
        "canonical lab lifecycle is not canonical JSON"
    );
    let lifecycle_digest = hash_domain(LAB_LIFECYCLE_DOMAIN_V0, &[&lifecycle_json]);
    let protocol_version = validator_set.protocol_version().get().to_be_bytes();
    let epoch = validator_set.epoch().get().to_be_bytes();
    let chain_descriptor_hash = hash_domain(
        LAB_CHAIN_DESCRIPTOR_DOMAIN_V0,
        &[
            validator_set.chain_id().as_bytes(),
            validator_set.genesis_hash().as_bytes(),
            &protocol_version,
            &epoch,
            validator_set.id().as_bytes(),
            consensus_parameters.hash().as_bytes(),
            &signer_policy_commitment,
            &lifecycle_digest,
        ],
    );
    let initial_block_id = *validator_set.genesis_hash().as_bytes();

    let mut initial_store = InMemoryNativeExecutionStoreV0::new(
        validator_set.chain_id().as_str().to_owned(),
        application_signers.clone(),
        consensus_parameters,
    )?;
    let seed_write = crate::complete::validator_lifecycle_seed_write_v0(0, &lifecycle)?;
    let initial_state_root = initial_store.apply_seed_v0(0, vec![seed_write])?.0;
    let initial_snapshot = initial_store.encode_authenticated_snapshot_v0()?;
    let initial_commit_id = hash_domain(
        LAB_INITIAL_COMMIT_DOMAIN_V0,
        &[
            &chain_descriptor_hash,
            &initial_block_id,
            &initial_state_root,
            &lifecycle_digest,
        ],
    );
    ensure!(
        [
            chain_descriptor_hash,
            signer_policy_commitment,
            initial_block_id,
            initial_state_root,
            initial_commit_id,
        ]
        .into_iter()
        .all(|fact| fact != [0; 32]),
        "canonical lab chain genesis contains a zero fact"
    );

    Ok(CanonicalLabNativeChainGenesisMaterialV0 {
        facts: CanonicalLabNativeChainGenesisFactsV0::new_for_config_v0(
            chain_descriptor_hash,
            signer_policy_commitment,
            initial_block_id,
            initial_state_root,
            initial_commit_id,
        ),
        validator_set,
        consensus_parameters,
        application_signers,
        initial_snapshot,
        initial_store,
    })
}

/// Public commitments needed to construct and audit one empty prefix block.
/// The underlying execution plan and authenticated store remain private.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalLabNativeEmptyBootstrapBlockFactsV0 {
    parent_block_id: BlockId,
    height: Height,
    timestamp_ms: u64,
    payload_root: PayloadDigest,
    post_state_root: StateRoot,
    receipts_root: ReceiptsRoot,
    evidence_root: EvidenceRoot,
}

impl CanonicalLabNativeEmptyBootstrapBlockFactsV0 {
    pub const fn parent_block_id_v0(self) -> BlockId {
        self.parent_block_id
    }

    pub const fn height_v0(self) -> Height {
        self.height
    }

    pub const fn timestamp_ms_v0(self) -> u64 {
        self.timestamp_ms
    }

    pub const fn payload_root_v0(self) -> PayloadDigest {
        self.payload_root
    }

    pub const fn post_state_root_v0(self) -> StateRoot {
        self.post_state_root
    }

    pub const fn receipts_root_v0(self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub const fn evidence_root_v0(self) -> EvidenceRoot {
        self.evidence_root
    }
}

/// One owner-bound, non-cloneable complete execution plan for an empty prefix
/// block. It is inert until consumed by the matching prefix owner together
/// with the exact transport block.
#[must_use = "a prepared prefix block must be exact-committed or discarded"]
pub struct PreparedCanonicalLabNativeEmptyBootstrapBlockV0 {
    owner_affinity: Arc<()>,
    parent: ApplicationHeadV0,
    facts: CanonicalLabNativeEmptyBootstrapBlockFactsV0,
    computed: ComputedCompleteExecutionV0,
}

impl PreparedCanonicalLabNativeEmptyBootstrapBlockV0 {
    pub const fn facts_v0(&self) -> CanonicalLabNativeEmptyBootstrapBlockFactsV0 {
        self.facts
    }
}

/// Linear, in-memory, keyless owner of the canonical empty h1-h3 application
/// prefix.
///
/// A commit error consumes the owner. Consequently, no caller can continue
/// from a state whose exact-block binding or in-memory state transition was
/// uncertain.
pub struct CanonicalLabNativeEmptyBootstrapPrefixV0 {
    facts: CanonicalLabNativeChainGenesisFactsV0,
    validator_set: ValidatorSet,
    consensus_parameters: ConsensusParametersV0,
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    store: InMemoryNativeExecutionStoreV0,
    head: ApplicationHeadV0,
    last_timestamp_ms: u64,
    owner_affinity: Arc<()>,
}

impl CanonicalLabNativeEmptyBootstrapPrefixV0 {
    pub fn new(inputs: CanonicalLabNativeChainGenesisInputsV0) -> Result<Self> {
        let material = derive_canonical_lab_native_chain_genesis_material_v0(inputs)?;
        let CanonicalLabNativeChainGenesisMaterialV0 {
            facts,
            validator_set,
            consensus_parameters,
            initial_store,
            ..
        } = material;
        let chain_id = ChainIdV0::new(validator_set.chain_id().as_str())
            .map_err(|error| anyhow!("construct canonical lab chain id: {error}"))?;
        let genesis_hash = GenesisHashV0::new(*validator_set.genesis_hash().as_bytes())
            .map_err(|error| anyhow!("construct canonical lab genesis hash: {error}"))?;
        let head = ApplicationHeadV0::new(
            HeightV0::GENESIS,
            BlockIdV0::new(facts.initial_block_id_v0())
                .map_err(|error| anyhow!("construct canonical lab initial block id: {error}"))?,
            StateRootV0::new(facts.initial_state_root_v0())
                .map_err(|error| anyhow!("construct canonical lab initial state root: {error}"))?,
            ApplicationCommitIdV0::new(facts.initial_commit_id_v0())
                .map_err(|error| anyhow!("construct canonical lab initial commit id: {error}"))?,
        );
        Ok(Self {
            facts,
            validator_set,
            consensus_parameters,
            chain_id,
            genesis_hash,
            store: initial_store,
            head,
            last_timestamp_ms: CANONICAL_LAB_GENESIS_TIMESTAMP_MS_V0,
            owner_affinity: Arc::new(()),
        })
    }

    pub const fn chain_genesis_facts_v0(&self) -> CanonicalLabNativeChainGenesisFactsV0 {
        self.facts
    }

    pub const fn committed_height_v0(&self) -> Height {
        Height::new(self.head.height().get())
    }

    pub const fn is_complete_v0(&self) -> bool {
        self.head.height().get() == CANONICAL_EMPTY_PREFIX_LAST_HEIGHT_V0
    }

    /// Executes the real complete/lifecycle transition for the next empty
    /// height while retaining the resulting state plan privately.
    pub fn prepare_next_empty_block_v0(
        &self,
        timestamp_ms: u64,
    ) -> Result<PreparedCanonicalLabNativeEmptyBootstrapBlockV0> {
        ensure!(
            self.head.height().get() < CANONICAL_EMPTY_PREFIX_LAST_HEIGHT_V0,
            "canonical empty bootstrap prefix is already complete"
        );
        ensure!(
            timestamp_ms > self.last_timestamp_ms,
            "canonical empty bootstrap timestamp is not strictly increasing"
        );
        let maximum_timestamp_ms = self
            .last_timestamp_ms
            .checked_add(self.consensus_parameters.max_block_time_step_ms())
            .context("canonical empty bootstrap timestamp bound exhausted")?;
        ensure!(
            timestamp_ms <= maximum_timestamp_ms,
            "canonical empty bootstrap timestamp exceeds the committed maximum step"
        );
        let height = self
            .head
            .height()
            .checked_next()
            .map_err(|error| anyhow!("advance canonical empty bootstrap height: {error}"))?;
        let active_validator_set_id = ValidatorSetIdV0::new(*self.validator_set.id().as_bytes())
            .map_err(|error| anyhow!("construct canonical lab validator-set id: {error}"))?;
        let request = NativeBlockPreviewRequestV0::new(
            self.chain_id.clone(),
            self.genesis_hash,
            self.head.clone(),
            height,
            timestamp_ms,
            active_validator_set_id,
            Vec::new(),
        )?;
        let computed = compute_complete_native_block_v0(
            &self.store,
            &self.validator_set,
            GenesisHash::new(*self.genesis_hash.as_bytes()),
            &request,
        )?;
        ensure!(
            computed.native_receipts.is_empty() && computed.replay_identities.is_empty(),
            "empty bootstrap execution produced transaction authority"
        );
        computed.final_lifecycle.validate()?;
        let facts = CanonicalLabNativeEmptyBootstrapBlockFactsV0 {
            parent_block_id: BlockId::new(*self.head.block_id().as_bytes()),
            height: Height::new(height.get()),
            timestamp_ms,
            payload_root: PayloadDigest::new(computed.payload_root),
            post_state_root: StateRoot::new(computed.post_state_root),
            receipts_root: ReceiptsRoot::new(computed.receipts_root),
            evidence_root: EvidenceRoot::new(computed.evidence_root),
        };
        Ok(PreparedCanonicalLabNativeEmptyBootstrapBlockV0 {
            owner_affinity: Arc::clone(&self.owner_affinity),
            parent: self.head.clone(),
            facts,
            computed,
        })
    }

    /// Consumes this owner and one prepared plan, validates the exact regular
    /// transport block, then applies the private plan. Any failure destroys
    /// the caller's authority to continue this prefix.
    pub fn commit_exact_block_v0(
        mut self,
        prepared: PreparedCanonicalLabNativeEmptyBootstrapBlockV0,
        exact_block: &Block,
    ) -> Result<Self> {
        let PreparedCanonicalLabNativeEmptyBootstrapBlockV0 {
            owner_affinity,
            parent,
            facts,
            computed,
        } = prepared;
        ensure!(
            Arc::ptr_eq(&self.owner_affinity, &owner_affinity),
            "prepared empty bootstrap block belongs to another owner"
        );
        ensure!(
            parent == self.head,
            "prepared empty bootstrap block is stale"
        );
        ensure!(
            facts.height.get()
                == self
                    .head
                    .height()
                    .get()
                    .checked_add(1)
                    .context("canonical empty bootstrap height exhausted")?,
            "prepared empty bootstrap height is not contiguous"
        );
        ensure!(
            facts.height.get() <= CANONICAL_EMPTY_PREFIX_LAST_HEIGHT_V0,
            "prepared block exceeds the canonical empty bootstrap prefix"
        );

        let header = exact_block.header();
        ensure!(
            header.height() == facts.height,
            "exact empty bootstrap block height mismatch"
        );
        ensure!(
            header.parent_id() == facts.parent_block_id,
            "exact empty bootstrap parent block mismatch"
        );
        ensure!(
            header.timestamp_ms() == facts.timestamp_ms,
            "exact empty bootstrap timestamp mismatch"
        );
        ensure!(
            self.validator_set.validator(header.proposer_id()).is_some(),
            "exact empty bootstrap proposer is outside the active validator set"
        );
        ensure!(
            header.payload_root() == facts.payload_root
                && header.state_root() == facts.post_state_root
                && header.receipts_root() == facts.receipts_root
                && header.evidence_root() == facts.evidence_root,
            "exact empty bootstrap commitments mismatch"
        );
        let body = validate_root_bound_regular_body_v0(
            exact_block,
            &self.validator_set,
            &self.consensus_parameters,
        )
        .map_err(|error| anyhow!("validate exact empty bootstrap body: {error}"))?;
        ensure!(
            body.transaction_count() == 0 && body.evidence_count() == 0,
            "exact bootstrap block body is not empty"
        );
        ensure!(
            body.block_id() == exact_block.id(),
            "exact bootstrap block id binding mismatch"
        );

        let block_id = exact_block.id();
        let next_block_id = BlockIdV0::new(block_id.into_bytes())
            .map_err(|error| anyhow!("construct exact bootstrap block id: {error}"))?;
        let prefix_commit_id = hash_domain(
            LAB_EMPTY_PREFIX_COMMIT_DOMAIN_V0,
            &[
                &self.facts.chain_descriptor_hash_v0(),
                &facts.height.get().to_be_bytes(),
                block_id.as_bytes(),
                facts.post_state_root.as_bytes(),
            ],
        );
        let next_commit_id = ApplicationCommitIdV0::new(prefix_commit_id)
            .map_err(|error| anyhow!("construct exact bootstrap commit id: {error}"))?;
        let next_state_root = StateRootV0::new(facts.post_state_root.into_bytes())
            .map_err(|error| anyhow!("construct committed bootstrap state root: {error}"))?;
        ensure!(
            computed.native_receipts.is_empty() && computed.replay_identities.is_empty(),
            "prepared empty bootstrap execution carries transaction authority"
        );
        computed.final_lifecycle.validate()?;
        let applied_root = self.store.apply_complete_state_plan_v0(computed.plan)?;
        ensure!(
            applied_root == facts.post_state_root,
            "committed empty bootstrap state root mismatch"
        );
        self.head = ApplicationHeadV0::new(
            HeightV0::new(facts.height.get()),
            next_block_id,
            next_state_root,
            next_commit_id,
        );
        self.last_timestamp_ms = facts.timestamp_ms;
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use ed25519_dalek::SigningKey;
    use trnm_consensus_types::{
        ApplicationPayloadV0, BlockHeader, BlockKind, ChainId, ConsensusPublicKey, Epoch,
        ProtocolVersion, Validator, ValidatorId, View, VotingPower,
    };
    use trnm_finality_types::crypto::public_key_hex;

    use super::*;
    use crate::{CanonicalLabNativeApplicationConfigInputsV0, NativeApplicationConfigV0};

    const CHAIN: &str = "trnm-native-canonical-lab-bootstrap-test";

    #[derive(Clone, Copy)]
    struct DeploymentVariationV0 {
        run_id: &'static str,
        coordinator: u8,
        topology: u8,
        validator_manifest: u8,
        source: u8,
        local_index: usize,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PrefixRootsV0 {
        payload: [u8; 32],
        state: [u8; 32],
        receipts: [u8; 32],
        evidence: [u8; 32],
    }

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn application_signers(reversed: bool) -> Vec<AuthorizedSignerV0> {
        let mut signers = vec![
            AuthorizedSignerV0::new(
                "did:operator:canonical-lab",
                "operator",
                public_key_hex(&signing_key(81)),
            )
            .unwrap(),
            AuthorizedSignerV0::new(
                "did:hepta:canonical-lab",
                "hepta",
                public_key_hex(&signing_key(82)),
            )
            .unwrap(),
        ];
        if reversed {
            signers.reverse();
        }
        signers
    }

    fn validator_set(parameters: &ConsensusParametersV0, voting_powers: [u64; 7]) -> ValidatorSet {
        let validators: Vec<_> = voting_powers
            .into_iter()
            .enumerate()
            .map(|(index, voting_power)| {
                Validator::new(
                    ValidatorId::from_bytes(format!("validator-{index:03}").as_bytes()).unwrap(),
                    ConsensusPublicKey::new(
                        signing_key(20 + u8::try_from(index).unwrap())
                            .verifying_key()
                            .to_bytes(),
                    ),
                    VotingPower::new(voting_power).unwrap(),
                )
                .unwrap()
            })
            .collect();
        let chain_id = ChainId::new(CHAIN).unwrap();
        let genesis_hash =
            derive_canonical_lab_genesis_hash_v0(chain_id, *parameters, &validators).unwrap();
        ValidatorSet::new(
            genesis_hash,
            chain_id,
            ProtocolVersion::V0,
            Epoch::new(0),
            parameters.hash(),
            validators,
        )
        .unwrap()
    }

    fn chain_inputs(
        set: ValidatorSet,
        parameters: ConsensusParametersV0,
        reversed_signers: bool,
    ) -> CanonicalLabNativeChainGenesisInputsV0 {
        CanonicalLabNativeChainGenesisInputsV0::new(
            set,
            parameters,
            application_signers(reversed_signers),
            "did:operator:canonical-lab",
        )
        .unwrap()
    }

    fn deployment_config(
        set: ValidatorSet,
        parameters: ConsensusParametersV0,
        variation: DeploymentVariationV0,
    ) -> NativeApplicationConfigV0 {
        NativeApplicationConfigV0::from_canonical_lab_inputs_v0(
            CanonicalLabNativeApplicationConfigInputsV0::new(
                variation.run_id,
                [variation.coordinator; 32],
                [variation.topology; 32],
                [variation.validator_manifest; 32],
                [variation.source; 32],
                set.validators()[variation.local_index].id(),
                set,
                parameters,
                application_signers(false),
                "did:operator:canonical-lab",
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn exact_empty_block(
        set: &ValidatorSet,
        parameters: &ConsensusParametersV0,
        facts: CanonicalLabNativeEmptyBootstrapBlockFactsV0,
    ) -> Block {
        let proposer_index =
            usize::try_from(facts.height_v0().get() - 1).unwrap() % set.validators().len();
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(facts.height_v0().get()),
            facts.height_v0(),
            BlockKind::Regular,
            facts.parent_block_id_v0(),
            set.validators()[proposer_index].id(),
            set.id(),
            parameters.hash(),
            facts.payload_root_v0(),
            facts.post_state_root_v0(),
            facts.receipts_root_v0(),
            facts.evidence_root_v0(),
            facts.timestamp_ms_v0(),
            None,
        )
        .unwrap();
        let payload = ApplicationPayloadV0::new(Vec::new())
            .unwrap()
            .try_cev0_bytes()
            .unwrap();
        Block::new(header, payload, Vec::new()).unwrap()
    }

    fn execute_empty_prefix(
        set: &ValidatorSet,
        parameters: ConsensusParametersV0,
        reversed_signers: bool,
    ) -> (CanonicalLabNativeChainGenesisFactsV0, Vec<PrefixRootsV0>) {
        let mut owner = CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs(
            set.clone(),
            parameters,
            reversed_signers,
        ))
        .unwrap();
        let genesis_facts = owner.chain_genesis_facts_v0();
        let mut roots = Vec::new();
        for height in 1..=CANONICAL_EMPTY_PREFIX_LAST_HEIGHT_V0 {
            let prepared = owner.prepare_next_empty_block_v0(height * 1_000).unwrap();
            let facts = prepared.facts_v0();
            roots.push(PrefixRootsV0 {
                payload: facts.payload_root_v0().into_bytes(),
                state: facts.post_state_root_v0().into_bytes(),
                receipts: facts.receipts_root_v0().into_bytes(),
                evidence: facts.evidence_root_v0().into_bytes(),
            });
            let block = exact_empty_block(set, &parameters, facts);
            owner = owner.commit_exact_block_v0(prepared, &block).unwrap();
            assert_eq!(owner.committed_height_v0(), Height::new(height));
        }
        assert!(owner.is_complete_v0());
        assert!(owner.prepare_next_empty_block_v0(4_000).is_err());
        (genesis_facts, roots)
    }

    fn assert_deployment_and_prefix_invariance(voting_powers: [u64; 7]) {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters, voting_powers);
        let variations = [
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0x91,
                topology: 0x92,
                validator_manifest: 0x93,
                source: 0x94,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-002",
                coordinator: 0x91,
                topology: 0x92,
                validator_manifest: 0x93,
                source: 0x94,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0xa1,
                topology: 0x92,
                validator_manifest: 0x93,
                source: 0x94,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0x91,
                topology: 0xa2,
                validator_manifest: 0x93,
                source: 0x94,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0x91,
                topology: 0x92,
                validator_manifest: 0xa3,
                source: 0x94,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0x91,
                topology: 0x92,
                validator_manifest: 0x93,
                source: 0xa4,
                local_index: 0,
            },
            DeploymentVariationV0 {
                run_id: "g3-canonical-run-001",
                coordinator: 0x91,
                topology: 0x92,
                validator_manifest: 0x93,
                source: 0x94,
                local_index: 1,
            },
        ];

        let mut expected_genesis = None;
        let mut expected_roots = None;
        let mut store_ids = BTreeSet::new();
        for variation in variations {
            assert_eq!(
                derive_canonical_lab_genesis_hash_v0(set.chain_id(), parameters, set.validators(),)
                    .unwrap(),
                set.genesis_hash(),
                "deployment-only variation changed canonical genesis"
            );
            let config = deployment_config(set.clone(), parameters, variation);
            let (prefix_genesis, prefix_roots) = execute_empty_prefix(&set, parameters, false);
            assert_eq!(config.chain_genesis_facts_v0(), prefix_genesis);
            if let Some(expected) = expected_genesis {
                assert_eq!(config.chain_genesis_facts_v0(), expected);
            } else {
                expected_genesis = Some(config.chain_genesis_facts_v0());
            }
            if let Some(expected) = &expected_roots {
                assert_eq!(&prefix_roots, expected);
            } else {
                expected_roots = Some(prefix_roots);
            }
            assert!(store_ids.insert(config.store_id()));
        }
        assert_eq!(store_ids.len(), variations.len());

        let direct_reordered = derive_canonical_lab_native_chain_genesis_v0(chain_inputs(
            set.clone(),
            parameters,
            true,
        ))
        .unwrap();
        let (reordered_genesis, reordered_roots) = execute_empty_prefix(&set, parameters, true);
        assert_eq!(Some(direct_reordered), expected_genesis);
        assert_eq!(direct_reordered, reordered_genesis);
        assert_eq!(Some(reordered_roots), expected_roots);
    }

    #[test]
    fn canonical_lab_genesis_matches_independent_cross_language_vector_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        assert_eq!(
            hex::encode(parameters.hash().as_bytes()),
            "49e6ddaf2ef8e59844b0fd8fc78322019cd04ce3b704466d71c5f7b8d8e0b885"
        );
        let validators = (1_u8..=4)
            .map(|value| {
                Validator::new(
                    ValidatorId::new([value; 32]),
                    ConsensusPublicKey::new([value * 0x11; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();

        let genesis = derive_canonical_lab_genesis_hash_v0(
            ChainId::new("trnm-poco-g3-lab-v0").unwrap(),
            parameters,
            &validators,
        )
        .unwrap();
        assert_eq!(
            hex::encode(genesis.as_bytes()),
            "6f860345cc7966ba0dcec54fd57d19b12f8c768283d35c823c5506b6b2e339ce"
        );
    }

    #[test]
    fn seven_validator_equal_deployments_preserve_genesis_and_empty_h1_h3_roots_v0() {
        assert_deployment_and_prefix_invariance([1; 7]);
    }

    #[test]
    fn seven_validator_bounded_unequal_deployments_preserve_genesis_and_empty_h1_h3_roots_v0() {
        assert_deployment_and_prefix_invariance([1, 2, 2, 3, 3, 4, 4]);
    }

    #[test]
    fn canonical_genesis_changes_or_rejects_chain_validator_identity_key_and_power_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters, [1; 7]);
        let base = set.genesis_hash();
        let canonical_set_id = |chain_id: ChainId, validators: &[Validator]| {
            let genesis =
                derive_canonical_lab_genesis_hash_v0(chain_id, parameters, validators).unwrap();
            ValidatorSet::new(
                genesis,
                chain_id,
                ProtocolVersion::V0,
                Epoch::new(0),
                parameters.hash(),
                validators.to_vec(),
            )
            .unwrap()
            .id()
        };

        let changed_chain = ChainId::new("trnm-native-canonical-lab-bootstrap-test-other").unwrap();
        assert_ne!(
            derive_canonical_lab_genesis_hash_v0(changed_chain, parameters, set.validators())
                .unwrap(),
            base
        );
        assert_ne!(canonical_set_id(changed_chain, set.validators()), set.id());

        let mut changed_id = set.validators().to_vec();
        changed_id[0] = Validator::new(
            ValidatorId::from_bytes(b"validator-000a").unwrap(),
            changed_id[0].consensus_key(),
            changed_id[0].voting_power(),
        )
        .unwrap();
        assert_ne!(
            derive_canonical_lab_genesis_hash_v0(set.chain_id(), parameters, &changed_id).unwrap(),
            base
        );
        assert_ne!(canonical_set_id(set.chain_id(), &changed_id), set.id());

        let mut changed_key = set.validators().to_vec();
        changed_key[0] = Validator::new(
            changed_key[0].id(),
            ConsensusPublicKey::new(signing_key(99).verifying_key().to_bytes()),
            changed_key[0].voting_power(),
        )
        .unwrap();
        assert_ne!(
            derive_canonical_lab_genesis_hash_v0(set.chain_id(), parameters, &changed_key).unwrap(),
            base
        );
        assert_ne!(canonical_set_id(set.chain_id(), &changed_key), set.id());

        let mut changed_power = set.validators().to_vec();
        changed_power[0] = Validator::new(
            changed_power[0].id(),
            changed_power[0].consensus_key(),
            VotingPower::new(2).unwrap(),
        )
        .unwrap();
        assert_ne!(
            derive_canonical_lab_genesis_hash_v0(set.chain_id(), parameters, &changed_power,)
                .unwrap(),
            base
        );
        assert_ne!(canonical_set_id(set.chain_id(), &changed_power), set.id());

        changed_key[1] = Validator::new(
            changed_key[1].id(),
            changed_key[0].consensus_key(),
            changed_key[1].voting_power(),
        )
        .unwrap();
        assert!(
            derive_canonical_lab_genesis_hash_v0(set.chain_id(), parameters, &changed_key,)
                .is_err()
        );
    }

    #[test]
    fn empty_prefix_exact_commit_rejects_a_root_mismatch_v0() {
        let parameters = ConsensusParametersV0::reference_shadow_v0();
        let set = validator_set(&parameters, [1; 7]);
        let owner = CanonicalLabNativeEmptyBootstrapPrefixV0::new(chain_inputs(
            set.clone(),
            parameters,
            false,
        ))
        .unwrap();
        let prepared = owner.prepare_next_empty_block_v0(1_000).unwrap();
        let facts = prepared.facts_v0();
        let mut wrong_state_root = facts.post_state_root_v0().into_bytes();
        wrong_state_root[0] ^= 1;
        let header = BlockHeader::new(
            set.genesis_hash(),
            set.chain_id(),
            set.protocol_version(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            BlockKind::Regular,
            facts.parent_block_id_v0(),
            set.validators()[0].id(),
            set.id(),
            parameters.hash(),
            facts.payload_root_v0(),
            StateRoot::new(wrong_state_root),
            facts.receipts_root_v0(),
            facts.evidence_root_v0(),
            facts.timestamp_ms_v0(),
            None,
        )
        .unwrap();
        let payload = ApplicationPayloadV0::new(Vec::new())
            .unwrap()
            .try_cev0_bytes()
            .unwrap();
        let wrong_block = Block::new(header, payload, Vec::new()).unwrap();
        assert!(owner.commit_exact_block_v0(prepared, &wrong_block).is_err());
    }
}
