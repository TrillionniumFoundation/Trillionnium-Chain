use core::fmt;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    BlockId, ChainId, ConsensusParametersHash, Epoch, EvidenceRoot, GenesisHash, Height,
    PayloadDigest, ProtocolVersion, ReceiptsRoot, SigningRoot, StateRoot, ValidatorId,
    ValidatorSetId, View,
};

use crate::{
    ApplicationValidationGenerationV1, ProcessGenerationV1, WholeNodeCheckpointChecksumV1,
    WholeNodeCheckpointGenerationV1, WholeNodeCheckpointScopeV1, WholeNodeCheckpointTypeErrorV1,
    WholeNodeCutDigestV1,
};

/// Frozen schema carried by every canonical v1 record.
pub const WHOLE_NODE_CHECKPOINT_SCHEMA_V1: u16 = 1;

const APPLICATION_VALIDATION_STATEMENT_DOMAIN_V1: &[u8] =
    b"trnm.whole-node-checkpoint.application-validation-statement.v1\0";

pub type WholeNodeCheckpointResultV1<T> = Result<T, WholeNodeCheckpointErrorV1>;

/// Closed error surface for data construction, exact decoding, and FSM checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WholeNodeCheckpointErrorV1 {
    Type(WholeNodeCheckpointTypeErrorV1),
    WrongMagic,
    UnsupportedSchema,
    LengthLimitExceeded,
    UnexpectedEnd,
    TrailingBytes,
    ReservedTag(&'static str),
    ChecksumMismatch,
    NonCanonicalEncoding,
    InvalidField(&'static str),
    InvalidPhaseShape(&'static str),
    InvalidSuccessor(&'static str),
}

impl From<WholeNodeCheckpointTypeErrorV1> for WholeNodeCheckpointErrorV1 {
    fn from(error: WholeNodeCheckpointTypeErrorV1) -> Self {
        Self::Type(error)
    }
}

impl fmt::Display for WholeNodeCheckpointErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Type(error) => write!(formatter, "whole-node checkpoint type error: {error}"),
            Self::WrongMagic => formatter.write_str("whole-node checkpoint magic differs"),
            Self::UnsupportedSchema => {
                formatter.write_str("whole-node checkpoint schema is unsupported")
            }
            Self::LengthLimitExceeded => {
                formatter.write_str("whole-node checkpoint exceeds its byte bound")
            }
            Self::UnexpectedEnd => formatter.write_str("whole-node checkpoint is truncated"),
            Self::TrailingBytes => formatter.write_str("whole-node checkpoint has trailing bytes"),
            Self::ReservedTag(field) => write!(formatter, "reserved {field} tag"),
            Self::ChecksumMismatch => formatter.write_str("whole-node checkpoint checksum differs"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("whole-node checkpoint encoding is non-canonical")
            }
            Self::InvalidField(field) => {
                write!(formatter, "whole-node checkpoint has invalid {field}")
            }
            Self::InvalidPhaseShape(field) => {
                write!(
                    formatter,
                    "whole-node checkpoint phase shape has invalid {field}"
                )
            }
            Self::InvalidSuccessor(field) => {
                write!(
                    formatter,
                    "whole-node checkpoint successor has invalid {field}"
                )
            }
        }
    }
}

/// Frozen whole-node checkpoint phase taxonomy.
///
/// The full [`WholeNodeCheckpointV1`] payload schema is deliberately limited
/// to the first four signing-cycle phases. `EpochActivationPrepared` and
/// `EpochActive` are reserved for the unique fixed-width
/// [`crate::WholeNodeCheckpointRefV1`] lineage and cannot be encoded as full
/// v1 records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WholeNodeCheckpointPhaseV1 {
    Commissioned,
    AppValidated,
    SafetyPrepared,
    SignatureCommitted,
    EpochActivationPrepared,
    EpochActive,
}

impl WholeNodeCheckpointPhaseV1 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Commissioned => 0,
            Self::AppValidated => 1,
            Self::SafetyPrepared => 2,
            Self::SignatureCommitted => 3,
            Self::EpochActivationPrepared => 4,
            Self::EpochActive => 5,
        }
    }

    pub(crate) const fn is_signing_cycle_record_phase(self) -> bool {
        matches!(
            self,
            Self::Commissioned
                | Self::AppValidated
                | Self::SafetyPrepared
                | Self::SignatureCommitted
        )
    }

    pub(crate) fn from_tag(tag: u8) -> WholeNodeCheckpointResultV1<Self> {
        match tag {
            0 => Ok(Self::Commissioned),
            1 => Ok(Self::AppValidated),
            2 => Ok(Self::SafetyPrepared),
            3 => Ok(Self::SignatureCommitted),
            4 => Ok(Self::EpochActivationPrepared),
            5 => Ok(Self::EpochActive),
            _ => Err(WholeNodeCheckpointErrorV1::ReservedTag("phase")),
        }
    }
}

/// Complete immutable Chain coordinate shared by one checkpoint lineage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainCutRefV1 {
    pub(crate) genesis_hash: GenesisHash,
    pub(crate) chain_id: ChainId,
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) epoch: Epoch,
    pub(crate) validator_set_id: ValidatorSetId,
    pub(crate) consensus_parameters_hash: ConsensusParametersHash,
    pub(crate) author: ValidatorId,
}

impl ChainCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        genesis_hash: GenesisHash,
        chain_id: ChainId,
        protocol_version: ProtocolVersion,
        epoch: Epoch,
        validator_set_id: ValidatorSetId,
        consensus_parameters_hash: ConsensusParametersHash,
        author: ValidatorId,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if genesis_hash.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField("genesis hash"));
        }
        if validator_set_id.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField("validator set id"));
        }
        if consensus_parameters_hash.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "consensus parameters hash",
            ));
        }
        if author.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField("author"));
        }
        Ok(Self {
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            consensus_parameters_hash,
            author,
        })
    }

    pub const fn genesis_hash(&self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }

    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn consensus_parameters_hash(&self) -> ConsensusParametersHash {
        self.consensus_parameters_hash
    }

    pub const fn author(&self) -> ValidatorId {
        self.author
    }
}

/// Public process-generation and lease fence facts for one service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessFenceRefV1 {
    pub(crate) process_generation: ProcessGenerationV1,
    pub(crate) lease_id: WholeNodeCutDigestV1,
    pub(crate) lease_grant_checksum: WholeNodeCutDigestV1,
    pub(crate) external_fence_head_checksum: WholeNodeCutDigestV1,
}

impl ProcessFenceRefV1 {
    pub const fn new(
        process_generation: ProcessGenerationV1,
        lease_id: WholeNodeCutDigestV1,
        lease_grant_checksum: WholeNodeCutDigestV1,
        external_fence_head_checksum: WholeNodeCutDigestV1,
    ) -> Self {
        Self {
            process_generation,
            lease_id,
            lease_grant_checksum,
            external_fence_head_checksum,
        }
    }

    pub const fn process_generation(&self) -> ProcessGenerationV1 {
        self.process_generation
    }

    pub const fn lease_id(&self) -> WholeNodeCutDigestV1 {
        self.lease_id
    }

    pub const fn lease_grant_checksum(&self) -> WholeNodeCutDigestV1 {
        self.lease_grant_checksum
    }

    pub const fn external_fence_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.external_fence_head_checksum
    }

    fn validate_same_or_generation_handoff(
        &self,
        predecessor: &Self,
    ) -> WholeNodeCheckpointResultV1<()> {
        if self == predecessor {
            return Ok(());
        }
        let expected = predecessor.process_generation.get().checked_add(1).ok_or(
            WholeNodeCheckpointErrorV1::InvalidSuccessor("process generation overflow"),
        )?;
        if self.process_generation.get() != expected {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "process generation",
            ));
        }
        if self.lease_id == predecessor.lease_id
            || self.lease_grant_checksum == predecessor.lease_grant_checksum
            || self.external_fence_head_checksum == predecessor.external_fence_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "generation handoff fence",
            ));
        }
        Ok(())
    }
}

/// Complete node, application-attestor, and remote-signer process fences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessFencesCutRefV1 {
    pub(crate) node: ProcessFenceRefV1,
    pub(crate) application_attestor: ProcessFenceRefV1,
    pub(crate) remote_signer: ProcessFenceRefV1,
}

impl ProcessFencesCutRefV1 {
    pub const fn new(
        node: ProcessFenceRefV1,
        application_attestor: ProcessFenceRefV1,
        remote_signer: ProcessFenceRefV1,
    ) -> Self {
        Self {
            node,
            application_attestor,
            remote_signer,
        }
    }

    pub const fn node(&self) -> ProcessFenceRefV1 {
        self.node
    }

    pub const fn application_attestor(&self) -> ProcessFenceRefV1 {
        self.application_attestor
    }

    pub const fn remote_signer(&self) -> ProcessFenceRefV1 {
        self.remote_signer
    }

    fn validate_same_or_generation_handoff(
        &self,
        predecessor: &Self,
    ) -> WholeNodeCheckpointResultV1<()> {
        self.node
            .validate_same_or_generation_handoff(&predecessor.node)?;
        self.application_attestor
            .validate_same_or_generation_handoff(&predecessor.application_attestor)?;
        self.remote_signer
            .validate_same_or_generation_handoff(&predecessor.remote_signer)
    }
}

/// Complete role/profile and public-key-reference cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoleBindingsCutRefV1 {
    pub(crate) node_role_bindings_checksum: WholeNodeCutDigestV1,
    pub(crate) node_adapter_checksum: WholeNodeCutDigestV1,
    pub(crate) consensus_purpose_profile_digest: WholeNodeCutDigestV1,
    pub(crate) remote_role_profile_ref: WholeNodeCutDigestV1,
    pub(crate) remote_service_profile_ref: WholeNodeCutDigestV1,
    pub(crate) remote_client_profile_ref: WholeNodeCutDigestV1,
    pub(crate) application_attestor_role_profile_ref: WholeNodeCutDigestV1,
    pub(crate) application_validation_purpose_profile_digest: WholeNodeCutDigestV1,
    pub(crate) application_attestor_public_key_ref: WholeNodeCutDigestV1,
}

impl RoleBindingsCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        node_role_bindings_checksum: WholeNodeCutDigestV1,
        node_adapter_checksum: WholeNodeCutDigestV1,
        consensus_purpose_profile_digest: WholeNodeCutDigestV1,
        remote_role_profile_ref: WholeNodeCutDigestV1,
        remote_service_profile_ref: WholeNodeCutDigestV1,
        remote_client_profile_ref: WholeNodeCutDigestV1,
        application_attestor_role_profile_ref: WholeNodeCutDigestV1,
        application_validation_purpose_profile_digest: WholeNodeCutDigestV1,
        application_attestor_public_key_ref: WholeNodeCutDigestV1,
    ) -> Self {
        Self {
            node_role_bindings_checksum,
            node_adapter_checksum,
            consensus_purpose_profile_digest,
            remote_role_profile_ref,
            remote_service_profile_ref,
            remote_client_profile_ref,
            application_attestor_role_profile_ref,
            application_validation_purpose_profile_digest,
            application_attestor_public_key_ref,
        }
    }

    pub const fn node_role_bindings_checksum(&self) -> WholeNodeCutDigestV1 {
        self.node_role_bindings_checksum
    }

    pub const fn node_adapter_checksum(&self) -> WholeNodeCutDigestV1 {
        self.node_adapter_checksum
    }

    pub const fn consensus_purpose_profile_digest(&self) -> WholeNodeCutDigestV1 {
        self.consensus_purpose_profile_digest
    }

    pub const fn remote_role_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.remote_role_profile_ref
    }

    pub const fn remote_service_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.remote_service_profile_ref
    }

    pub const fn remote_client_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.remote_client_profile_ref
    }

    pub const fn application_attestor_role_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.application_attestor_role_profile_ref
    }

    pub const fn application_validation_purpose_profile_digest(&self) -> WholeNodeCutDigestV1 {
        self.application_validation_purpose_profile_digest
    }

    pub const fn application_attestor_public_key_ref(&self) -> WholeNodeCutDigestV1 {
        self.application_attestor_public_key_ref
    }
}

/// Core Safety durable cut and checkpoint-to-checkpoint head link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreSafetyCutRefV1 {
    pub(crate) journal_id: WholeNodeCutDigestV1,
    pub(crate) verifier_profile_ref: WholeNodeCutDigestV1,
    pub(crate) config_ref: WholeNodeCutDigestV1,
    pub(crate) revision: u64,
    pub(crate) state_record_checksum: WholeNodeCutDigestV1,
    pub(crate) record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) pending_intent_checksum: Option<WholeNodeCutDigestV1>,
}

impl CoreSafetyCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        journal_id: WholeNodeCutDigestV1,
        verifier_profile_ref: WholeNodeCutDigestV1,
        config_ref: WholeNodeCutDigestV1,
        revision: u64,
        state_record_checksum: WholeNodeCutDigestV1,
        record_chain_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
        checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
        pending_intent_checksum: Option<WholeNodeCutDigestV1>,
    ) -> Self {
        Self {
            journal_id,
            verifier_profile_ref,
            config_ref,
            revision,
            state_record_checksum,
            record_chain_checksum,
            active_head_checksum,
            checkpoint_predecessor_head_checksum,
            pending_intent_checksum,
        }
    }

    pub const fn journal_id(&self) -> WholeNodeCutDigestV1 {
        self.journal_id
    }

    pub const fn verifier_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.verifier_profile_ref
    }

    pub const fn config_ref(&self) -> WholeNodeCutDigestV1 {
        self.config_ref
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn state_record_checksum(&self) -> WholeNodeCutDigestV1 {
        self.state_record_checksum
    }

    pub const fn record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_chain_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    pub const fn checkpoint_predecessor_head_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.checkpoint_predecessor_head_checksum
    }

    pub const fn pending_intent_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.pending_intent_checksum
    }

    fn validate_advance_from(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if self.journal_id != predecessor.journal_id
            || self.verifier_profile_ref != predecessor.verifier_profile_ref
            || self.config_ref != predecessor.config_ref
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "Core Safety identity",
            ));
        }
        if self.revision <= predecessor.revision
            || self.checkpoint_predecessor_head_checksum != Some(predecessor.active_head_checksum)
            || self.state_record_checksum == predecessor.state_record_checksum
            || self.record_chain_checksum == predecessor.record_chain_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "Core Safety head",
            ));
        }
        Ok(())
    }
}

/// Exact application-validation artifact and statement coordinate.
///
/// The derived statement digest covers every field below, but it remains
/// unsigned public data. This crate neither verifies nor produces an
/// application-validation attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationValidationCutRefV1 {
    pub(crate) generation: ApplicationValidationGenerationV1,
    pub(crate) validation_store_scope: WholeNodeCutDigestV1,
    pub(crate) validation_id: WholeNodeCutDigestV1,
    pub(crate) validation_record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) validation_active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) validation_predecessor_record_chain_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) validation_predecessor_active_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) block_id: BlockId,
    pub(crate) parent_block_id: BlockId,
    pub(crate) height: Height,
    pub(crate) view: View,
    pub(crate) payload_digest: PayloadDigest,
    pub(crate) result_state_root: StateRoot,
    pub(crate) receipts_root: ReceiptsRoot,
    pub(crate) evidence_root: EvidenceRoot,
    pub(crate) overlay_checksum: WholeNodeCutDigestV1,
    pub(crate) source_artifact_checksum: WholeNodeCutDigestV1,
    pub(crate) validation_artifact_checksum: WholeNodeCutDigestV1,
    pub(crate) application_head_checksum: WholeNodeCutDigestV1,
    pub(crate) core_safety_record_checksum: WholeNodeCutDigestV1,
    pub(crate) whole_node_predecessor_checksum: WholeNodeCheckpointChecksumV1,
    pub(crate) statement_digest: WholeNodeCutDigestV1,
}

impl ApplicationValidationCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        generation: ApplicationValidationGenerationV1,
        validation_store_scope: WholeNodeCutDigestV1,
        validation_id: WholeNodeCutDigestV1,
        validation_record_chain_checksum: WholeNodeCutDigestV1,
        validation_active_head_checksum: WholeNodeCutDigestV1,
        validation_predecessor_record_chain_checksum: Option<WholeNodeCutDigestV1>,
        validation_predecessor_active_head_checksum: Option<WholeNodeCutDigestV1>,
        block_id: BlockId,
        parent_block_id: BlockId,
        height: Height,
        view: View,
        payload_digest: PayloadDigest,
        result_state_root: StateRoot,
        receipts_root: ReceiptsRoot,
        evidence_root: EvidenceRoot,
        overlay_checksum: WholeNodeCutDigestV1,
        source_artifact_checksum: WholeNodeCutDigestV1,
        validation_artifact_checksum: WholeNodeCutDigestV1,
        application_head_checksum: WholeNodeCutDigestV1,
        core_safety_record_checksum: WholeNodeCutDigestV1,
        whole_node_predecessor_checksum: WholeNodeCheckpointChecksumV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if block_id.is_zero() || parent_block_id.is_zero() || block_id == parent_block_id {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "application validation block edge",
            ));
        }
        if payload_digest.is_zero()
            || result_state_root.is_zero()
            || receipts_root.is_zero()
            || evidence_root.is_zero()
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "application validation commitment",
            ));
        }

        let mut value = Self {
            generation,
            validation_store_scope,
            validation_id,
            validation_record_chain_checksum,
            validation_active_head_checksum,
            validation_predecessor_record_chain_checksum,
            validation_predecessor_active_head_checksum,
            block_id,
            parent_block_id,
            height,
            view,
            payload_digest,
            result_state_root,
            receipts_root,
            evidence_root,
            overlay_checksum,
            source_artifact_checksum,
            validation_artifact_checksum,
            application_head_checksum,
            core_safety_record_checksum,
            whole_node_predecessor_checksum,
            statement_digest: WholeNodeCutDigestV1::from_exact_bytes([1; 32])?,
        };
        value.statement_digest = value.recompute_statement_digest()?;
        Ok(value)
    }

    fn recompute_statement_digest(&self) -> WholeNodeCheckpointResultV1<WholeNodeCutDigestV1> {
        let mut hash = Sha256::new();
        hash.update(APPLICATION_VALIDATION_STATEMENT_DOMAIN_V1);
        hash.update(self.generation.get().to_be_bytes());
        hash.update(self.validation_store_scope.as_bytes());
        hash.update(self.validation_id.as_bytes());
        hash.update(self.validation_record_chain_checksum.as_bytes());
        hash.update(self.validation_active_head_checksum.as_bytes());
        hash.update([u8::from(
            self.validation_predecessor_record_chain_checksum.is_some(),
        )]);
        if let Some(checksum) = self.validation_predecessor_record_chain_checksum {
            hash.update(checksum.as_bytes());
        }
        hash.update([u8::from(
            self.validation_predecessor_active_head_checksum.is_some(),
        )]);
        if let Some(checksum) = self.validation_predecessor_active_head_checksum {
            hash.update(checksum.as_bytes());
        }
        hash.update(self.block_id.as_bytes());
        hash.update(self.parent_block_id.as_bytes());
        hash.update(self.height.get().to_be_bytes());
        hash.update(self.view.get().to_be_bytes());
        hash.update(self.payload_digest.as_bytes());
        hash.update(self.result_state_root.as_bytes());
        hash.update(self.receipts_root.as_bytes());
        hash.update(self.evidence_root.as_bytes());
        hash.update(self.overlay_checksum.as_bytes());
        hash.update(self.source_artifact_checksum.as_bytes());
        hash.update(self.validation_artifact_checksum.as_bytes());
        hash.update(self.application_head_checksum.as_bytes());
        hash.update(self.core_safety_record_checksum.as_bytes());
        hash.update(self.whole_node_predecessor_checksum.as_bytes());
        WholeNodeCutDigestV1::from_exact_bytes(hash.finalize().into()).map_err(Into::into)
    }

    pub(crate) fn validate_statement_digest(&self) -> WholeNodeCheckpointResultV1<()> {
        if self.statement_digest != self.recompute_statement_digest()? {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "application validation statement digest",
            ));
        }
        Ok(())
    }

    pub const fn generation(&self) -> ApplicationValidationGenerationV1 {
        self.generation
    }

    pub const fn validation_store_scope(&self) -> WholeNodeCutDigestV1 {
        self.validation_store_scope
    }

    pub const fn validation_id(&self) -> WholeNodeCutDigestV1 {
        self.validation_id
    }

    pub const fn validation_record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.validation_record_chain_checksum
    }

    pub const fn validation_active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.validation_active_head_checksum
    }

    pub const fn validation_predecessor_record_chain_checksum(
        &self,
    ) -> Option<WholeNodeCutDigestV1> {
        self.validation_predecessor_record_chain_checksum
    }

    pub const fn validation_predecessor_active_head_checksum(
        &self,
    ) -> Option<WholeNodeCutDigestV1> {
        self.validation_predecessor_active_head_checksum
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn parent_block_id(&self) -> BlockId {
        self.parent_block_id
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn payload_digest(&self) -> PayloadDigest {
        self.payload_digest
    }

    pub const fn result_state_root(&self) -> StateRoot {
        self.result_state_root
    }

    pub const fn receipts_root(&self) -> ReceiptsRoot {
        self.receipts_root
    }

    pub const fn evidence_root(&self) -> EvidenceRoot {
        self.evidence_root
    }

    pub const fn overlay_checksum(&self) -> WholeNodeCutDigestV1 {
        self.overlay_checksum
    }

    pub const fn source_artifact_checksum(&self) -> WholeNodeCutDigestV1 {
        self.source_artifact_checksum
    }

    pub const fn validation_artifact_checksum(&self) -> WholeNodeCutDigestV1 {
        self.validation_artifact_checksum
    }

    pub const fn application_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.application_head_checksum
    }

    pub const fn core_safety_record_checksum(&self) -> WholeNodeCutDigestV1 {
        self.core_safety_record_checksum
    }

    pub const fn whole_node_predecessor_checksum(&self) -> WholeNodeCheckpointChecksumV1 {
        self.whole_node_predecessor_checksum
    }

    pub const fn statement_digest(&self) -> WholeNodeCutDigestV1 {
        self.statement_digest
    }

    pub const fn lineage_cut(&self) -> ApplicationValidationLineageCutRefV1 {
        ApplicationValidationLineageCutRefV1::new(
            self.validation_store_scope,
            self.generation,
            self.validation_id,
            self.validation_record_chain_checksum,
            self.validation_active_head_checksum,
        )
    }
}

/// Persistent validation lineage retained even when a TimeoutVote has no
/// current application-validation artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationValidationLineageCutRefV1 {
    pub(crate) validation_store_scope: WholeNodeCutDigestV1,
    pub(crate) last_generation: ApplicationValidationGenerationV1,
    pub(crate) last_validation_id: WholeNodeCutDigestV1,
    pub(crate) record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
}

impl ApplicationValidationLineageCutRefV1 {
    pub const fn new(
        validation_store_scope: WholeNodeCutDigestV1,
        last_generation: ApplicationValidationGenerationV1,
        last_validation_id: WholeNodeCutDigestV1,
        record_chain_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
    ) -> Self {
        Self {
            validation_store_scope,
            last_generation,
            last_validation_id,
            record_chain_checksum,
            active_head_checksum,
        }
    }

    pub const fn validation_store_scope(&self) -> WholeNodeCutDigestV1 {
        self.validation_store_scope
    }

    pub const fn last_generation(&self) -> ApplicationValidationGenerationV1 {
        self.last_generation
    }

    pub const fn last_validation_id(&self) -> WholeNodeCutDigestV1 {
        self.last_validation_id
    }

    pub const fn record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_chain_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    fn validate_advance_from(
        &self,
        predecessor: Option<Self>,
        current_validation: ApplicationValidationCutRefV1,
    ) -> WholeNodeCheckpointResultV1<()> {
        if *self != current_validation.lineage_cut() {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application validation lineage/current cut",
            ));
        }
        let Some(predecessor) = predecessor else {
            if current_validation
                .validation_predecessor_record_chain_checksum
                .is_some()
                || current_validation
                    .validation_predecessor_active_head_checksum
                    .is_some()
            {
                return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                    "initial application validation predecessor",
                ));
            }
            return Ok(());
        };
        if self.validation_store_scope != predecessor.validation_store_scope {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application validation store scope",
            ));
        }
        if self.last_generation.get() <= predecessor.last_generation.get() {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application validation generation watermark",
            ));
        }
        if self.last_validation_id == predecessor.last_validation_id {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application validation identity",
            ));
        }
        if self.record_chain_checksum == predecessor.record_chain_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
            || current_validation.validation_predecessor_record_chain_checksum
                != Some(predecessor.record_chain_checksum)
            || current_validation.validation_predecessor_active_head_checksum
                != Some(predecessor.active_head_checksum)
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application validation lineage head",
            ));
        }
        Ok(())
    }
}

/// Complete durable Application head, persistent validation lineage, and
/// optional current validation cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplicationCutRefV1 {
    pub(crate) host_config_ref: WholeNodeCutDigestV1,
    pub(crate) projection_profile_ref: WholeNodeCutDigestV1,
    pub(crate) safety_binding_manifest_checksum: WholeNodeCutDigestV1,
    pub(crate) store_scope: WholeNodeCutDigestV1,
    pub(crate) committed_sequence: u64,
    pub(crate) committed_head_row_checksum: WholeNodeCutDigestV1,
    pub(crate) recovery_closure_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) block_id: BlockId,
    pub(crate) height: Height,
    pub(crate) state_root: StateRoot,
    pub(crate) view: View,
    pub(crate) timestamp_ms: u64,
    pub(crate) validation_lineage: Option<ApplicationValidationLineageCutRefV1>,
    pub(crate) validation: Option<ApplicationValidationCutRefV1>,
}

impl ApplicationCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        host_config_ref: WholeNodeCutDigestV1,
        projection_profile_ref: WholeNodeCutDigestV1,
        safety_binding_manifest_checksum: WholeNodeCutDigestV1,
        store_scope: WholeNodeCutDigestV1,
        committed_sequence: u64,
        committed_head_row_checksum: WholeNodeCutDigestV1,
        recovery_closure_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
        checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
        block_id: BlockId,
        height: Height,
        state_root: StateRoot,
        view: View,
        timestamp_ms: u64,
        validation_lineage: Option<ApplicationValidationLineageCutRefV1>,
        validation: Option<ApplicationValidationCutRefV1>,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if block_id.is_zero() || state_root.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField(
                "Application committed coordinate",
            ));
        }
        let value = Self {
            host_config_ref,
            projection_profile_ref,
            safety_binding_manifest_checksum,
            store_scope,
            committed_sequence,
            committed_head_row_checksum,
            recovery_closure_checksum,
            active_head_checksum,
            checkpoint_predecessor_head_checksum,
            block_id,
            height,
            state_root,
            view,
            timestamp_ms,
            validation_lineage,
            validation,
        };
        value.validate_local_shape()?;
        Ok(value)
    }

    pub const fn host_config_ref(&self) -> WholeNodeCutDigestV1 {
        self.host_config_ref
    }

    pub const fn projection_profile_ref(&self) -> WholeNodeCutDigestV1 {
        self.projection_profile_ref
    }

    pub const fn safety_binding_manifest_checksum(&self) -> WholeNodeCutDigestV1 {
        self.safety_binding_manifest_checksum
    }

    pub const fn store_scope(&self) -> WholeNodeCutDigestV1 {
        self.store_scope
    }

    pub const fn committed_sequence(&self) -> u64 {
        self.committed_sequence
    }

    pub const fn committed_head_row_checksum(&self) -> WholeNodeCutDigestV1 {
        self.committed_head_row_checksum
    }

    pub const fn recovery_closure_checksum(&self) -> WholeNodeCutDigestV1 {
        self.recovery_closure_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    pub const fn checkpoint_predecessor_head_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.checkpoint_predecessor_head_checksum
    }

    pub const fn block_id(&self) -> BlockId {
        self.block_id
    }

    pub const fn height(&self) -> Height {
        self.height
    }

    pub const fn state_root(&self) -> StateRoot {
        self.state_root
    }

    pub const fn view(&self) -> View {
        self.view
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Persistent application-validation lineage retained even when the
    /// current operation is a TimeoutVote.
    pub const fn validation_lineage(&self) -> Option<ApplicationValidationLineageCutRefV1> {
        self.validation_lineage
    }

    pub const fn last_validation_generation(&self) -> Option<ApplicationValidationGenerationV1> {
        match self.validation_lineage {
            None => None,
            Some(lineage) => Some(lineage.last_generation),
        }
    }

    pub const fn validation(&self) -> Option<ApplicationValidationCutRefV1> {
        self.validation
    }

    pub(crate) fn validate_local_shape(&self) -> WholeNodeCheckpointResultV1<()> {
        if let Some(validation) = self.validation {
            validation.validate_statement_digest()?;
            if self.validation_lineage != Some(validation.lineage_cut()) {
                return Err(WholeNodeCheckpointErrorV1::InvalidField(
                    "Application validation lineage/current cut",
                ));
            }
        }
        Ok(())
    }

    fn persistent_head_equal(&self, predecessor: &Self) -> bool {
        self.host_config_ref == predecessor.host_config_ref
            && self.projection_profile_ref == predecessor.projection_profile_ref
            && self.safety_binding_manifest_checksum == predecessor.safety_binding_manifest_checksum
            && self.store_scope == predecessor.store_scope
            && self.committed_sequence == predecessor.committed_sequence
            && self.committed_head_row_checksum == predecessor.committed_head_row_checksum
            && self.recovery_closure_checksum == predecessor.recovery_closure_checksum
            && self.active_head_checksum == predecessor.active_head_checksum
            && self.checkpoint_predecessor_head_checksum
                == predecessor.checkpoint_predecessor_head_checksum
            && self.block_id == predecessor.block_id
            && self.height == predecessor.height
            && self.state_root == predecessor.state_root
            && self.view == predecessor.view
            && self.timestamp_ms == predecessor.timestamp_ms
    }

    fn validate_persistent_same_or_advance_from(
        &self,
        predecessor: &Self,
    ) -> WholeNodeCheckpointResultV1<()> {
        // The validation watermark and current validation are intentionally
        // checked by the operation edge: they may change while the durable
        // Application head remains exact.
        if self.persistent_head_equal(predecessor) {
            return Ok(());
        }
        if self.host_config_ref != predecessor.host_config_ref
            || self.projection_profile_ref != predecessor.projection_profile_ref
            || self.safety_binding_manifest_checksum != predecessor.safety_binding_manifest_checksum
            || self.store_scope != predecessor.store_scope
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "Application identity",
            ));
        }
        if self.committed_sequence <= predecessor.committed_sequence
            || self.height.get() < predecessor.height.get()
            || self.view.get() < predecessor.view.get()
            || self.timestamp_ms < predecessor.timestamp_ms
            || self.checkpoint_predecessor_head_checksum != Some(predecessor.active_head_checksum)
            || self.committed_head_row_checksum == predecessor.committed_head_row_checksum
            || self.recovery_closure_checksum == predecessor.recovery_closure_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "Application durable head",
            ));
        }
        Ok(())
    }
}

/// Application-attestor journal and external-fence cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppAttestorCutRefV1 {
    pub(crate) journal_id: WholeNodeCutDigestV1,
    pub(crate) profile_checksum: WholeNodeCutDigestV1,
    pub(crate) store_scope: WholeNodeCutDigestV1,
    pub(crate) sequence: u64,
    pub(crate) record_checksum: WholeNodeCutDigestV1,
    pub(crate) record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) attestation_digest: Option<WholeNodeCutDigestV1>,
}

impl AppAttestorCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        journal_id: WholeNodeCutDigestV1,
        profile_checksum: WholeNodeCutDigestV1,
        store_scope: WholeNodeCutDigestV1,
        sequence: u64,
        record_checksum: WholeNodeCutDigestV1,
        record_chain_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
        checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
        attestation_digest: Option<WholeNodeCutDigestV1>,
    ) -> Self {
        Self {
            journal_id,
            profile_checksum,
            store_scope,
            sequence,
            record_checksum,
            record_chain_checksum,
            active_head_checksum,
            checkpoint_predecessor_head_checksum,
            attestation_digest,
        }
    }

    pub const fn journal_id(&self) -> WholeNodeCutDigestV1 {
        self.journal_id
    }

    pub const fn profile_checksum(&self) -> WholeNodeCutDigestV1 {
        self.profile_checksum
    }

    pub const fn store_scope(&self) -> WholeNodeCutDigestV1 {
        self.store_scope
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn record_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_checksum
    }

    pub const fn record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_chain_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    pub const fn checkpoint_predecessor_head_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.checkpoint_predecessor_head_checksum
    }

    pub const fn attestation_digest(&self) -> Option<WholeNodeCutDigestV1> {
        self.attestation_digest
    }

    fn validate_advance_from(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if self.journal_id != predecessor.journal_id
            || self.profile_checksum != predecessor.profile_checksum
            || self.store_scope != predecessor.store_scope
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application-attestor identity",
            ));
        }
        if self.sequence <= predecessor.sequence
            || self.checkpoint_predecessor_head_checksum != Some(predecessor.active_head_checksum)
            || self.record_checksum == predecessor.record_checksum
            || self.record_chain_checksum == predecessor.record_chain_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "application-attestor head",
            ));
        }
        Ok(())
    }
}

/// Remote SafetyRules durable state, journal, and prepared-transition cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSafetyCutRefV1 {
    pub(crate) store_scope: WholeNodeCutDigestV1,
    pub(crate) journal_id: WholeNodeCutDigestV1,
    pub(crate) profile_checksum: WholeNodeCutDigestV1,
    pub(crate) revision: u64,
    pub(crate) state_digest: WholeNodeCutDigestV1,
    pub(crate) record_checksum: WholeNodeCutDigestV1,
    pub(crate) record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) prepared_transition_digest: Option<WholeNodeCutDigestV1>,
}

impl RemoteSafetyCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        store_scope: WholeNodeCutDigestV1,
        journal_id: WholeNodeCutDigestV1,
        profile_checksum: WholeNodeCutDigestV1,
        revision: u64,
        state_digest: WholeNodeCutDigestV1,
        record_checksum: WholeNodeCutDigestV1,
        record_chain_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
        checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
        prepared_transition_digest: Option<WholeNodeCutDigestV1>,
    ) -> Self {
        Self {
            store_scope,
            journal_id,
            profile_checksum,
            revision,
            state_digest,
            record_checksum,
            record_chain_checksum,
            active_head_checksum,
            checkpoint_predecessor_head_checksum,
            prepared_transition_digest,
        }
    }

    pub const fn store_scope(&self) -> WholeNodeCutDigestV1 {
        self.store_scope
    }

    pub const fn journal_id(&self) -> WholeNodeCutDigestV1 {
        self.journal_id
    }

    pub const fn profile_checksum(&self) -> WholeNodeCutDigestV1 {
        self.profile_checksum
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn state_digest(&self) -> WholeNodeCutDigestV1 {
        self.state_digest
    }

    pub const fn record_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_checksum
    }

    pub const fn record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_chain_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    pub const fn checkpoint_predecessor_head_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.checkpoint_predecessor_head_checksum
    }

    pub const fn prepared_transition_digest(&self) -> Option<WholeNodeCutDigestV1> {
        self.prepared_transition_digest
    }

    fn validate_advance_from(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if self.store_scope != predecessor.store_scope
            || self.journal_id != predecessor.journal_id
            || self.profile_checksum != predecessor.profile_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "remote SafetyRules identity",
            ));
        }
        if self.revision <= predecessor.revision
            || self.checkpoint_predecessor_head_checksum != Some(predecessor.active_head_checksum)
            || self.state_digest == predecessor.state_digest
            || self.record_checksum == predecessor.record_checksum
            || self.record_chain_checksum == predecessor.record_chain_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "remote SafetyRules head",
            ));
        }
        Ok(())
    }
}

/// Data-only signer journal status carried by a checkpoint cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignerJournalStateV1 {
    Stable,
    Prepared,
    Signed,
}

impl SignerJournalStateV1 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Stable => 0,
            Self::Prepared => 1,
            Self::Signed => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> WholeNodeCheckpointResultV1<Self> {
        match tag {
            0 => Ok(Self::Stable),
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Signed),
            _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(
                "signer journal state",
            )),
        }
    }
}

/// Signer journal, request replay, signature-event, and external-fence cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignerCutRefV1 {
    pub(crate) journal_id: WholeNodeCutDigestV1,
    pub(crate) profile_checksum: WholeNodeCutDigestV1,
    pub(crate) store_scope: WholeNodeCutDigestV1,
    pub(crate) sequence: u64,
    pub(crate) event_checksum: WholeNodeCutDigestV1,
    pub(crate) record_chain_checksum: WholeNodeCutDigestV1,
    pub(crate) active_head_checksum: WholeNodeCutDigestV1,
    pub(crate) checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
    pub(crate) state: SignerJournalStateV1,
    pub(crate) request_fingerprint: Option<WholeNodeCutDigestV1>,
    pub(crate) signature_digest: Option<WholeNodeCutDigestV1>,
}

impl SignerCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        journal_id: WholeNodeCutDigestV1,
        profile_checksum: WholeNodeCutDigestV1,
        store_scope: WholeNodeCutDigestV1,
        sequence: u64,
        event_checksum: WholeNodeCutDigestV1,
        record_chain_checksum: WholeNodeCutDigestV1,
        active_head_checksum: WholeNodeCutDigestV1,
        checkpoint_predecessor_head_checksum: Option<WholeNodeCutDigestV1>,
        state: SignerJournalStateV1,
        request_fingerprint: Option<WholeNodeCutDigestV1>,
        signature_digest: Option<WholeNodeCutDigestV1>,
    ) -> Self {
        Self {
            journal_id,
            profile_checksum,
            store_scope,
            sequence,
            event_checksum,
            record_chain_checksum,
            active_head_checksum,
            checkpoint_predecessor_head_checksum,
            state,
            request_fingerprint,
            signature_digest,
        }
    }

    pub const fn journal_id(&self) -> WholeNodeCutDigestV1 {
        self.journal_id
    }

    pub const fn profile_checksum(&self) -> WholeNodeCutDigestV1 {
        self.profile_checksum
    }

    pub const fn store_scope(&self) -> WholeNodeCutDigestV1 {
        self.store_scope
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn event_checksum(&self) -> WholeNodeCutDigestV1 {
        self.event_checksum
    }

    pub const fn record_chain_checksum(&self) -> WholeNodeCutDigestV1 {
        self.record_chain_checksum
    }

    pub const fn active_head_checksum(&self) -> WholeNodeCutDigestV1 {
        self.active_head_checksum
    }

    pub const fn checkpoint_predecessor_head_checksum(&self) -> Option<WholeNodeCutDigestV1> {
        self.checkpoint_predecessor_head_checksum
    }

    pub const fn state(&self) -> SignerJournalStateV1 {
        self.state
    }

    pub const fn request_fingerprint(&self) -> Option<WholeNodeCutDigestV1> {
        self.request_fingerprint
    }

    pub const fn signature_digest(&self) -> Option<WholeNodeCutDigestV1> {
        self.signature_digest
    }

    fn validate_advance_from(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if self.journal_id != predecessor.journal_id
            || self.profile_checksum != predecessor.profile_checksum
            || self.store_scope != predecessor.store_scope
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "signer identity",
            ));
        }
        if self.sequence <= predecessor.sequence
            || self.checkpoint_predecessor_head_checksum != Some(predecessor.active_head_checksum)
            || self.event_checksum == predecessor.event_checksum
            || self.record_chain_checksum == predecessor.record_chain_checksum
            || self.active_head_checksum == predecessor.active_head_checksum
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "signer journal head",
            ));
        }
        Ok(())
    }
}

/// Only vote and timeout-vote operations are representable in schema 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SignOperationKindV1 {
    Vote,
    TimeoutVote,
}

impl SignOperationKindV1 {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Vote => 0,
            Self::TimeoutVote => 1,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> WholeNodeCheckpointResultV1<Self> {
        match tag {
            0 => Ok(Self::Vote),
            1 => Ok(Self::TimeoutVote),
            _ => Err(WholeNodeCheckpointErrorV1::ReservedTag(
                "sign operation kind",
            )),
        }
    }
}

/// Complete public operation binding retained throughout one three-phase cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignOperationCutRefV1 {
    pub(crate) kind: SignOperationKindV1,
    pub(crate) operation_id: WholeNodeCutDigestV1,
    pub(crate) request_nonce: WholeNodeCutDigestV1,
    pub(crate) request_fingerprint: WholeNodeCutDigestV1,
    pub(crate) canonical_intent_checksum: WholeNodeCutDigestV1,
    pub(crate) signing_root: SigningRoot,
    pub(crate) safety_transition_digest: WholeNodeCutDigestV1,
    pub(crate) cycle_predecessor_checkpoint_checksum: WholeNodeCheckpointChecksumV1,
    pub(crate) application_validation_statement_digest: Option<WholeNodeCutDigestV1>,
}

impl SignOperationCutRefV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: SignOperationKindV1,
        operation_id: WholeNodeCutDigestV1,
        request_nonce: WholeNodeCutDigestV1,
        request_fingerprint: WholeNodeCutDigestV1,
        canonical_intent_checksum: WholeNodeCutDigestV1,
        signing_root: SigningRoot,
        safety_transition_digest: WholeNodeCutDigestV1,
        cycle_predecessor_checkpoint_checksum: WholeNodeCheckpointChecksumV1,
        application_validation_statement_digest: Option<WholeNodeCutDigestV1>,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if signing_root.is_zero() {
            return Err(WholeNodeCheckpointErrorV1::InvalidField("signing root"));
        }
        match kind {
            SignOperationKindV1::Vote if application_validation_statement_digest.is_none() => {
                return Err(WholeNodeCheckpointErrorV1::InvalidField(
                    "vote application validation statement",
                ));
            }
            SignOperationKindV1::TimeoutVote
                if application_validation_statement_digest.is_some() =>
            {
                return Err(WholeNodeCheckpointErrorV1::InvalidField(
                    "timeout application validation statement",
                ));
            }
            _ => {}
        }
        Ok(Self {
            kind,
            operation_id,
            request_nonce,
            request_fingerprint,
            canonical_intent_checksum,
            signing_root,
            safety_transition_digest,
            cycle_predecessor_checkpoint_checksum,
            application_validation_statement_digest,
        })
    }

    pub const fn kind(&self) -> SignOperationKindV1 {
        self.kind
    }

    pub const fn operation_id(&self) -> WholeNodeCutDigestV1 {
        self.operation_id
    }

    pub const fn request_nonce(&self) -> WholeNodeCutDigestV1 {
        self.request_nonce
    }

    pub const fn request_fingerprint(&self) -> WholeNodeCutDigestV1 {
        self.request_fingerprint
    }

    pub const fn canonical_intent_checksum(&self) -> WholeNodeCutDigestV1 {
        self.canonical_intent_checksum
    }

    pub const fn signing_root(&self) -> SigningRoot {
        self.signing_root
    }

    pub const fn safety_transition_digest(&self) -> WholeNodeCutDigestV1 {
        self.safety_transition_digest
    }

    pub const fn cycle_predecessor_checkpoint_checksum(&self) -> WholeNodeCheckpointChecksumV1 {
        self.cycle_predecessor_checkpoint_checksum
    }

    pub const fn application_validation_statement_digest(&self) -> Option<WholeNodeCutDigestV1> {
        self.application_validation_statement_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WholeNodeCheckpointPartsV1 {
    pub(crate) scope: WholeNodeCheckpointScopeV1,
    pub(crate) generation: WholeNodeCheckpointGenerationV1,
    pub(crate) phase: WholeNodeCheckpointPhaseV1,
    pub(crate) predecessor_checksum: Option<WholeNodeCheckpointChecksumV1>,
    pub(crate) chain: ChainCutRefV1,
    pub(crate) fences: ProcessFencesCutRefV1,
    pub(crate) roles: RoleBindingsCutRefV1,
    pub(crate) core_safety: CoreSafetyCutRefV1,
    pub(crate) application: ApplicationCutRefV1,
    pub(crate) application_attestor: AppAttestorCutRefV1,
    pub(crate) remote_safety: RemoteSafetyCutRefV1,
    pub(crate) signer: SignerCutRefV1,
    pub(crate) operation: Option<SignOperationCutRefV1>,
}

/// Canonical, cumulative, freely copyable data record.
///
/// Private fields prevent partial struct literals, but neither the constructors
/// nor exact decoding mint a committed or non-Clone authority capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WholeNodeCheckpointV1 {
    pub(crate) parts: WholeNodeCheckpointPartsV1,
    pub(crate) checkpoint_checksum: WholeNodeCheckpointChecksumV1,
}

impl WholeNodeCheckpointV1 {
    /// Builds the only generation-zero phase.
    #[allow(clippy::too_many_arguments)]
    pub fn commissioned(
        scope: WholeNodeCheckpointScopeV1,
        chain: ChainCutRefV1,
        fences: ProcessFencesCutRefV1,
        roles: RoleBindingsCutRefV1,
        core_safety: CoreSafetyCutRefV1,
        application: ApplicationCutRefV1,
        application_attestor: AppAttestorCutRefV1,
        remote_safety: RemoteSafetyCutRefV1,
        signer: SignerCutRefV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        Self::from_parts(WholeNodeCheckpointPartsV1 {
            scope,
            generation: WholeNodeCheckpointGenerationV1::ZERO,
            phase: WholeNodeCheckpointPhaseV1::Commissioned,
            predecessor_checksum: None,
            chain,
            fences,
            roles,
            core_safety,
            application,
            application_attestor,
            remote_safety,
            signer,
            operation: None,
        })
    }

    /// Begins one operation cycle after application validation (or timeout
    /// preparation) while retaining the predecessor's remote-safety and signer
    /// cuts exactly.
    #[allow(clippy::too_many_arguments)]
    pub fn app_validated_successor(
        predecessor: &Self,
        fences: ProcessFencesCutRefV1,
        operation: SignOperationCutRefV1,
        core_safety: CoreSafetyCutRefV1,
        application: ApplicationCutRefV1,
        application_attestor: AppAttestorCutRefV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if !matches!(
            predecessor.phase(),
            WholeNodeCheckpointPhaseV1::Commissioned
                | WholeNodeCheckpointPhaseV1::SignatureCommitted
        ) {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "AppValidated predecessor phase",
            ));
        }
        let value = Self::from_parts(WholeNodeCheckpointPartsV1 {
            scope: predecessor.parts.scope,
            generation: predecessor.parts.generation.checked_next()?,
            phase: WholeNodeCheckpointPhaseV1::AppValidated,
            predecessor_checksum: Some(predecessor.checkpoint_checksum),
            chain: predecessor.parts.chain,
            fences,
            roles: predecessor.parts.roles,
            core_safety,
            application,
            application_attestor,
            remote_safety: predecessor.parts.remote_safety,
            signer: predecessor.parts.signer,
            operation: Some(operation),
        })?;
        value.validate_successor_of(predecessor)?;
        Ok(value)
    }

    /// Advances only the remote SafetyRules and signer-journal cuts into the
    /// prepared phase. No private-key operation is performed.
    pub fn safety_prepared_successor(
        predecessor: &Self,
        remote_safety: RemoteSafetyCutRefV1,
        signer: SignerCutRefV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if predecessor.phase() != WholeNodeCheckpointPhaseV1::AppValidated {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SafetyPrepared predecessor phase",
            ));
        }
        let value = Self::from_parts(WholeNodeCheckpointPartsV1 {
            scope: predecessor.parts.scope,
            generation: predecessor.parts.generation.checked_next()?,
            phase: WholeNodeCheckpointPhaseV1::SafetyPrepared,
            predecessor_checksum: Some(predecessor.checkpoint_checksum),
            chain: predecessor.parts.chain,
            fences: predecessor.parts.fences,
            roles: predecessor.parts.roles,
            core_safety: predecessor.parts.core_safety,
            application: predecessor.parts.application,
            application_attestor: predecessor.parts.application_attestor,
            remote_safety,
            signer,
            operation: predecessor.parts.operation,
        })?;
        value.validate_successor_of(predecessor)?;
        Ok(value)
    }

    /// Advances only the signer cut to a stored signature event. The signature
    /// digest remains unverified data and no response authority is produced.
    pub fn signature_committed_successor(
        predecessor: &Self,
        signer: SignerCutRefV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        if predecessor.phase() != WholeNodeCheckpointPhaseV1::SafetyPrepared {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SignatureCommitted predecessor phase",
            ));
        }
        let value = Self::from_parts(WholeNodeCheckpointPartsV1 {
            scope: predecessor.parts.scope,
            generation: predecessor.parts.generation.checked_next()?,
            phase: WholeNodeCheckpointPhaseV1::SignatureCommitted,
            predecessor_checksum: Some(predecessor.checkpoint_checksum),
            chain: predecessor.parts.chain,
            fences: predecessor.parts.fences,
            roles: predecessor.parts.roles,
            core_safety: predecessor.parts.core_safety,
            application: predecessor.parts.application,
            application_attestor: predecessor.parts.application_attestor,
            remote_safety: predecessor.parts.remote_safety,
            signer,
            operation: predecessor.parts.operation,
        })?;
        value.validate_successor_of(predecessor)?;
        Ok(value)
    }

    pub(crate) fn from_parts(
        parts: WholeNodeCheckpointPartsV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        let mut value = Self {
            parts,
            checkpoint_checksum: WholeNodeCheckpointChecksumV1::from_digest([1; 32]),
        };
        value.validate_local_shape()?;
        value.checkpoint_checksum = crate::codec::recompute_checkpoint_checksum_v1(&value)?;
        Ok(value)
    }

    pub(crate) fn from_decoded_parts(
        parts: WholeNodeCheckpointPartsV1,
        checkpoint_checksum: WholeNodeCheckpointChecksumV1,
    ) -> WholeNodeCheckpointResultV1<Self> {
        let value = Self {
            parts,
            checkpoint_checksum,
        };
        value.validate_local_shape()?;
        Ok(value)
    }

    pub const fn schema(&self) -> u16 {
        WHOLE_NODE_CHECKPOINT_SCHEMA_V1
    }

    pub const fn scope(&self) -> WholeNodeCheckpointScopeV1 {
        self.parts.scope
    }

    pub const fn generation(&self) -> WholeNodeCheckpointGenerationV1 {
        self.parts.generation
    }

    pub const fn phase(&self) -> WholeNodeCheckpointPhaseV1 {
        self.parts.phase
    }

    pub const fn predecessor_checksum(&self) -> Option<WholeNodeCheckpointChecksumV1> {
        self.parts.predecessor_checksum
    }

    pub const fn chain(&self) -> ChainCutRefV1 {
        self.parts.chain
    }

    pub const fn fences(&self) -> ProcessFencesCutRefV1 {
        self.parts.fences
    }

    pub const fn roles(&self) -> RoleBindingsCutRefV1 {
        self.parts.roles
    }

    pub const fn core_safety(&self) -> CoreSafetyCutRefV1 {
        self.parts.core_safety
    }

    pub const fn application(&self) -> ApplicationCutRefV1 {
        self.parts.application
    }

    pub const fn application_attestor(&self) -> AppAttestorCutRefV1 {
        self.parts.application_attestor
    }

    pub const fn remote_safety(&self) -> RemoteSafetyCutRefV1 {
        self.parts.remote_safety
    }

    pub const fn signer(&self) -> SignerCutRefV1 {
        self.parts.signer
    }

    pub const fn operation(&self) -> Option<SignOperationCutRefV1> {
        self.parts.operation
    }

    pub const fn checkpoint_checksum(&self) -> WholeNodeCheckpointChecksumV1 {
        self.checkpoint_checksum
    }

    pub fn validate_successor_of(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        self.validate_local_shape()?;
        predecessor.validate_local_shape()?;
        if self.scope() != predecessor.scope() {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor("scope"));
        }
        if self.generation() != predecessor.generation().checked_next()? {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "checkpoint generation",
            ));
        }
        if self.predecessor_checksum() != Some(predecessor.checkpoint_checksum()) {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "predecessor checksum",
            ));
        }
        if self.chain() != predecessor.chain() {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor("Chain cut"));
        }
        if self.roles() != predecessor.roles() {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "role bindings cut",
            ));
        }

        match self.phase() {
            WholeNodeCheckpointPhaseV1::Commissioned => Err(
                WholeNodeCheckpointErrorV1::InvalidSuccessor("repeated Commissioned phase"),
            ),
            WholeNodeCheckpointPhaseV1::AppValidated => {
                self.validate_app_validated_edge(predecessor)
            }
            WholeNodeCheckpointPhaseV1::SafetyPrepared => {
                self.validate_safety_prepared_edge(predecessor)
            }
            WholeNodeCheckpointPhaseV1::SignatureCommitted => {
                self.validate_signature_committed_edge(predecessor)
            }
            WholeNodeCheckpointPhaseV1::EpochActivationPrepared
            | WholeNodeCheckpointPhaseV1::EpochActive => {
                Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                    "epoch-transition phase is reference-only",
                ))
            }
        }
    }

    pub(crate) fn validate_local_shape(&self) -> WholeNodeCheckpointResultV1<()> {
        self.parts.chain.validate_reconstructed()?;
        self.parts.application.validate_local_shape()?;
        match self.phase() {
            WholeNodeCheckpointPhaseV1::Commissioned => {
                if self.generation() != WholeNodeCheckpointGenerationV1::ZERO
                    || self.predecessor_checksum().is_some()
                    || self.operation().is_some()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Commissioned generation/link/operation",
                    ));
                }
                if self
                    .parts
                    .core_safety
                    .checkpoint_predecessor_head_checksum
                    .is_some()
                    || self
                        .parts
                        .application
                        .checkpoint_predecessor_head_checksum
                        .is_some()
                    || self
                        .parts
                        .application_attestor
                        .checkpoint_predecessor_head_checksum
                        .is_some()
                    || self
                        .parts
                        .remote_safety
                        .checkpoint_predecessor_head_checksum
                        .is_some()
                    || self
                        .parts
                        .signer
                        .checkpoint_predecessor_head_checksum
                        .is_some()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Commissioned cut predecessor",
                    ));
                }
                if self.parts.core_safety.pending_intent_checksum.is_some()
                    || self.parts.application.validation.is_some()
                    || self.parts.application.validation_lineage.is_some()
                    || self.parts.application_attestor.attestation_digest.is_some()
                    || self
                        .parts
                        .remote_safety
                        .prepared_transition_digest
                        .is_some()
                    || self.parts.signer.state != SignerJournalStateV1::Stable
                    || self.parts.signer.request_fingerprint.is_some()
                    || self.parts.signer.signature_digest.is_some()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Commissioned active operation facts",
                    ));
                }
                Ok(())
            }
            WholeNodeCheckpointPhaseV1::AppValidated => {
                self.require_noninitial_link()?;
                let operation = self.require_operation()?;
                if self.predecessor_checksum()
                    != Some(operation.cycle_predecessor_checkpoint_checksum)
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "AppValidated cycle predecessor",
                    ));
                }
                self.validate_operation_application_binding(operation)
            }
            WholeNodeCheckpointPhaseV1::SafetyPrepared => {
                self.require_noninitial_link()?;
                let operation = self.require_operation()?;
                self.validate_operation_application_binding(operation)?;
                if self.parts.remote_safety.prepared_transition_digest
                    != Some(operation.safety_transition_digest)
                    || self.parts.signer.state != SignerJournalStateV1::Prepared
                    || self.parts.signer.request_fingerprint != Some(operation.request_fingerprint)
                    || self.parts.signer.signature_digest.is_some()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "SafetyPrepared remote/signer binding",
                    ));
                }
                Ok(())
            }
            WholeNodeCheckpointPhaseV1::SignatureCommitted => {
                self.require_noninitial_link()?;
                let operation = self.require_operation()?;
                self.validate_operation_application_binding(operation)?;
                if self.parts.remote_safety.prepared_transition_digest
                    != Some(operation.safety_transition_digest)
                    || self.parts.signer.state != SignerJournalStateV1::Signed
                    || self.parts.signer.request_fingerprint != Some(operation.request_fingerprint)
                    || self.parts.signer.signature_digest.is_none()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "SignatureCommitted remote/signer binding",
                    ));
                }
                Ok(())
            }
            WholeNodeCheckpointPhaseV1::EpochActivationPrepared
            | WholeNodeCheckpointPhaseV1::EpochActive => {
                Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                    "epoch-transition reference-only phase",
                ))
            }
        }
    }

    fn require_noninitial_link(&self) -> WholeNodeCheckpointResultV1<()> {
        if self.generation() == WholeNodeCheckpointGenerationV1::ZERO
            || self.predecessor_checksum().is_none()
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                "noninitial generation/link",
            ));
        }
        Ok(())
    }

    fn require_operation(&self) -> WholeNodeCheckpointResultV1<SignOperationCutRefV1> {
        self.operation()
            .ok_or(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                "missing operation",
            ))
    }

    fn validate_operation_application_binding(
        &self,
        operation: SignOperationCutRefV1,
    ) -> WholeNodeCheckpointResultV1<()> {
        if self.parts.core_safety.pending_intent_checksum
            != Some(operation.canonical_intent_checksum)
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                "Core pending intent",
            ));
        }
        match operation.kind {
            SignOperationKindV1::Vote => {
                let validation = self.parts.application.validation.ok_or(
                    WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Vote application validation cut",
                    ),
                )?;
                if validation.statement_digest
                    != operation.application_validation_statement_digest.ok_or(
                        WholeNodeCheckpointErrorV1::InvalidPhaseShape("Vote validation statement"),
                    )?
                    || validation.application_head_checksum
                        != self.parts.application.active_head_checksum
                    || validation.core_safety_record_checksum
                        != self.parts.core_safety.state_record_checksum
                    || validation.whole_node_predecessor_checksum
                        != operation.cycle_predecessor_checkpoint_checksum
                    || self.parts.application.validation_lineage != Some(validation.lineage_cut())
                    || self.parts.application_attestor.attestation_digest
                        != Some(validation.statement_digest)
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Vote validation/attestation binding",
                    ));
                }
                Ok(())
            }
            SignOperationKindV1::TimeoutVote => {
                if operation.application_validation_statement_digest.is_some()
                    || self.parts.application.validation.is_some()
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidPhaseShape(
                        "Timeout application validation",
                    ));
                }
                Ok(())
            }
        }
    }

    fn validate_app_validated_edge(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if !matches!(
            predecessor.phase(),
            WholeNodeCheckpointPhaseV1::Commissioned
                | WholeNodeCheckpointPhaseV1::SignatureCommitted
        ) {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "AppValidated phase order",
            ));
        }
        if predecessor.phase() == WholeNodeCheckpointPhaseV1::Commissioned {
            if self.fences() != predecessor.fences() {
                return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                    "commissioned fences",
                ));
            }
        } else {
            self.parts
                .fences
                .validate_same_or_generation_handoff(&predecessor.parts.fences)?;
        }
        self.parts
            .core_safety
            .validate_advance_from(&predecessor.parts.core_safety)?;
        self.parts
            .application
            .validate_persistent_same_or_advance_from(&predecessor.parts.application)?;
        if self.parts.remote_safety != predecessor.parts.remote_safety
            || self.parts.signer != predecessor.parts.signer
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "AppValidated remote/signer stability",
            ));
        }
        let operation = self.require_operation()?;
        if let Some(previous_operation) = predecessor.parts.operation {
            if operation.operation_id == previous_operation.operation_id
                || operation.request_nonce == previous_operation.request_nonce
                || operation.request_fingerprint == previous_operation.request_fingerprint
            {
                return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                    "new operation identity",
                ));
            }
        }
        match operation.kind {
            SignOperationKindV1::Vote => {
                self.parts
                    .application_attestor
                    .validate_advance_from(&predecessor.parts.application_attestor)?;
                let current_validation = self.parts.application.validation.ok_or(
                    WholeNodeCheckpointErrorV1::InvalidSuccessor("application validation cut"),
                )?;
                self.parts
                    .application
                    .validation_lineage
                    .ok_or(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                        "application validation lineage",
                    ))?
                    .validate_advance_from(
                        predecessor.parts.application.validation_lineage,
                        current_validation,
                    )?;
            }
            SignOperationKindV1::TimeoutVote => {
                if self.parts.application.validation_lineage
                    != predecessor.parts.application.validation_lineage
                {
                    return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                        "timeout application validation lineage",
                    ));
                }
                if self.parts.application_attestor != predecessor.parts.application_attestor {
                    return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                        "timeout application-attestor stability",
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_safety_prepared_edge(&self, predecessor: &Self) -> WholeNodeCheckpointResultV1<()> {
        if predecessor.phase() != WholeNodeCheckpointPhaseV1::AppValidated {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SafetyPrepared phase order",
            ));
        }
        if self.parts.fences != predecessor.parts.fences
            || self.parts.core_safety != predecessor.parts.core_safety
            || self.parts.application != predecessor.parts.application
            || self.parts.application_attestor != predecessor.parts.application_attestor
            || self.parts.operation != predecessor.parts.operation
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SafetyPrepared stable cumulative cut",
            ));
        }
        self.parts
            .remote_safety
            .validate_advance_from(&predecessor.parts.remote_safety)?;
        self.parts
            .signer
            .validate_advance_from(&predecessor.parts.signer)?;
        Ok(())
    }

    fn validate_signature_committed_edge(
        &self,
        predecessor: &Self,
    ) -> WholeNodeCheckpointResultV1<()> {
        if predecessor.phase() != WholeNodeCheckpointPhaseV1::SafetyPrepared {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SignatureCommitted phase order",
            ));
        }
        if self.parts.fences != predecessor.parts.fences
            || self.parts.core_safety != predecessor.parts.core_safety
            || self.parts.application != predecessor.parts.application
            || self.parts.application_attestor != predecessor.parts.application_attestor
            || self.parts.remote_safety != predecessor.parts.remote_safety
            || self.parts.operation != predecessor.parts.operation
        {
            return Err(WholeNodeCheckpointErrorV1::InvalidSuccessor(
                "SignatureCommitted stable cumulative cut",
            ));
        }
        self.parts
            .signer
            .validate_advance_from(&predecessor.parts.signer)
    }
}

impl ChainCutRefV1 {
    pub(crate) fn validate_reconstructed(&self) -> WholeNodeCheckpointResultV1<()> {
        Self::new(
            self.genesis_hash,
            self.chain_id,
            self.protocol_version,
            self.epoch,
            self.validator_set_id,
            self.consensus_parameters_hash,
            self.author,
        )?;
        Ok(())
    }
}
