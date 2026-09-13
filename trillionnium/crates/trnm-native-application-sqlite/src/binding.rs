use sha2::{Digest, Sha256};
use trnm_native_application::{
    ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0, Hash32V0,
    HeightV0, NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0, ValidatorSetIdV0,
};

use crate::error::{error, ValidationStoreErrorCodeV0, ValidationStoreResultV0};

const VALIDATION_ID_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_PROPOSAL_VALIDATION_ID_V0";
const CORE_DELIVERY_DIGEST_DOMAIN_V0: &[u8] = b"TRNM_NATIVE_CORE_DELIVERY_DIGEST_V0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NonZeroDigestV0([u8; 32]);

impl NonZeroDigestV0 {
    pub fn new(bytes: [u8; 32]) -> ValidationStoreResultV0<Self> {
        if bytes == [0; 32] {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "nonzero_digest",
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProposalValidationOwnerIdV0(NonZeroDigestV0);

impl ProposalValidationOwnerIdV0 {
    pub fn new(bytes: [u8; 32]) -> ValidationStoreResultV0<Self> {
        Ok(Self(NonZeroDigestV0::new(bytes)?))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ValidationIdV0([u8; 32]);

impl ValidationIdV0 {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ProposalRouteV0 {
    Proposal = 1,
    Synced = 2,
}

impl ProposalRouteV0 {
    pub(crate) const fn tag(self) -> u8 {
        self as u8
    }

    pub(crate) fn from_tag(tag: u8) -> ValidationStoreResultV0<Self> {
        match tag {
            1 => Ok(Self::Proposal),
            2 => Ok(Self::Synced),
            _ => Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "proposal_route",
            )),
        }
    }
}

/// Exact identity of one proposal payload-validation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalValidationBindingV0 {
    validation_id: ValidationIdV0,
    chain_id: ChainIdV0,
    genesis_hash: GenesisHashV0,
    parent: ApplicationHeadV0,
    block_id: BlockIdV0,
    height: HeightV0,
    timestamp_ms: u64,
    active_validator_set_id: ValidatorSetIdV0,
    view: u64,
    generation: u64,
    route: ProposalRouteV0,
    commitments: NativeExpectedBlockCommitmentsV0,
}

impl ProposalValidationBindingV0 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: ChainIdV0,
        genesis_hash: GenesisHashV0,
        parent: ApplicationHeadV0,
        block_id: BlockIdV0,
        height: HeightV0,
        timestamp_ms: u64,
        active_validator_set_id: ValidatorSetIdV0,
        view: u64,
        generation: u64,
        route: ProposalRouteV0,
        commitments: NativeExpectedBlockCommitmentsV0,
    ) -> ValidationStoreResultV0<Self> {
        if height.get() == 0
            || height
                != parent.height().checked_next().map_err(|_| {
                    error(
                        ValidationStoreErrorCodeV0::InvalidBinding,
                        "binding.parent_height",
                    )
                })?
        {
            return Err(error(
                ValidationStoreErrorCodeV0::InvalidBinding,
                "binding.height",
            ));
        }
        if block_id == parent.block_id() {
            return Err(error(
                ValidationStoreErrorCodeV0::InvalidBinding,
                "binding.block_id",
            ));
        }
        if generation == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "binding.generation",
            ));
        }

        let validation_id = derive_validation_id_v0(
            &chain_id,
            genesis_hash,
            &parent,
            block_id,
            height,
            timestamp_ms,
            active_validator_set_id,
            view,
            generation,
            route,
            commitments,
        );
        Ok(Self {
            validation_id,
            chain_id,
            genesis_hash,
            parent,
            block_id,
            height,
            timestamp_ms,
            active_validator_set_id,
            view,
            generation,
            route,
            commitments,
        })
    }

    pub const fn validation_id(&self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn chain_id(&self) -> &ChainIdV0 {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> GenesisHashV0 {
        self.genesis_hash
    }

    pub const fn parent(&self) -> &ApplicationHeadV0 {
        &self.parent
    }

    pub const fn block_id(&self) -> BlockIdV0 {
        self.block_id
    }

    pub const fn height(&self) -> HeightV0 {
        self.height
    }

    pub const fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    pub const fn active_validator_set_id(&self) -> ValidatorSetIdV0 {
        self.active_validator_set_id
    }

    pub const fn view(&self) -> u64 {
        self.view
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn route(&self) -> ProposalRouteV0 {
        self.route
    }

    pub const fn commitments(&self) -> NativeExpectedBlockCommitmentsV0 {
        self.commitments
    }

    pub(crate) fn to_record(&self) -> BindingRecordV0 {
        BindingRecordV0 {
            validation_id: *self.validation_id.as_bytes(),
            chain_id: self.chain_id.as_str().to_owned(),
            genesis_hash: *self.genesis_hash.as_bytes(),
            parent_height: self.parent.height().get(),
            parent_block_id: *self.parent.block_id().as_bytes(),
            parent_state_root: *self.parent.state_root().as_bytes(),
            parent_commit_id: *self.parent.commit_id().as_bytes(),
            block_id: *self.block_id.as_bytes(),
            height: self.height.get(),
            timestamp_ms: self.timestamp_ms,
            active_validator_set_id: *self.active_validator_set_id.as_bytes(),
            view: self.view,
            generation: self.generation,
            route: self.route.tag(),
            payload_root: *self.commitments.payload_root().as_bytes(),
            post_state_root: *self.commitments.post_state_root().as_bytes(),
            receipts_root: *self.commitments.receipts_root().as_bytes(),
            evidence_root: *self.commitments.evidence_root().as_bytes(),
        }
    }

    pub(crate) fn from_record(record: &BindingRecordV0) -> ValidationStoreResultV0<Self> {
        let chain_id = ChainIdV0::new(record.chain_id.clone()).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "binding_record.chain_id",
            )
        })?;
        let genesis_hash = GenesisHashV0::new(record.genesis_hash).map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "binding_record.genesis_hash",
            )
        })?;
        let parent = ApplicationHeadV0::new(
            HeightV0::new(record.parent_height),
            BlockIdV0::new(record.parent_block_id).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.parent_block_id",
                )
            })?,
            StateRootV0::new(record.parent_state_root).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.parent_state_root",
                )
            })?,
            ApplicationCommitIdV0::new(record.parent_commit_id).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.parent_commit_id",
                )
            })?,
        );
        let commitments = NativeExpectedBlockCommitmentsV0::new(
            Hash32V0::new(record.payload_root),
            StateRootV0::new(record.post_state_root).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.post_state_root",
                )
            })?,
            ReceiptsRootV0::new(record.receipts_root).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.receipts_root",
                )
            })?,
            Hash32V0::new(record.evidence_root),
        )
        .map_err(|_| {
            error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "binding_record.commitments",
            )
        })?;
        let binding = Self::new(
            chain_id,
            genesis_hash,
            parent,
            BlockIdV0::new(record.block_id).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.block_id",
                )
            })?,
            HeightV0::new(record.height),
            record.timestamp_ms,
            ValidatorSetIdV0::new(record.active_validator_set_id).map_err(|_| {
                error(
                    ValidationStoreErrorCodeV0::CorruptStore,
                    "binding_record.active_validator_set_id",
                )
            })?,
            record.view,
            record.generation,
            ProposalRouteV0::from_tag(record.route)?,
            commitments,
        )?;
        if binding.validation_id.as_bytes() != &record.validation_id {
            return Err(error(
                ValidationStoreErrorCodeV0::CorruptStore,
                "binding_record.validation_id",
            ));
        }
        Ok(binding)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BindingRecordV0 {
    pub(crate) validation_id: [u8; 32],
    pub(crate) chain_id: String,
    pub(crate) genesis_hash: [u8; 32],
    pub(crate) parent_height: u64,
    pub(crate) parent_block_id: [u8; 32],
    pub(crate) parent_state_root: [u8; 32],
    pub(crate) parent_commit_id: [u8; 32],
    pub(crate) block_id: [u8; 32],
    pub(crate) height: u64,
    pub(crate) timestamp_ms: u64,
    pub(crate) active_validator_set_id: [u8; 32],
    pub(crate) view: u64,
    pub(crate) generation: u64,
    pub(crate) route: u8,
    pub(crate) payload_root: [u8; 32],
    pub(crate) post_state_root: [u8; 32],
    pub(crate) receipts_root: [u8; 32],
    pub(crate) evidence_root: [u8; 32],
}

/// Exact durable Core-delivery fact (`D`).
///
/// This is application recovery evidence, not Safety authority. There is no
/// external constructor until the Node-private Core acceptance carrier is
/// integrated:
///
/// ```compile_fail
/// use trnm_native_application::{
///     ApplicationCommitIdV0, ApplicationHeadV0, BlockIdV0, ChainIdV0, GenesisHashV0,
///     Hash32V0, HeightV0, NativeExpectedBlockCommitmentsV0, ReceiptsRootV0, StateRootV0,
///     ValidatorSetIdV0,
/// };
/// use trnm_native_application_sqlite::{
///     CoreDeliveryConfirmationV0, NonZeroDigestV0, ProposalRouteV0,
///     ProposalValidationBindingV0,
/// };
///
/// let parent = ApplicationHeadV0::new(
///     HeightV0::GENESIS,
///     BlockIdV0::new([1; 32]).unwrap(),
///     StateRootV0::new([2; 32]).unwrap(),
///     ApplicationCommitIdV0::new([3; 32]).unwrap(),
/// );
/// let commitments = NativeExpectedBlockCommitmentsV0::new(
///     Hash32V0::new([4; 32]),
///     StateRootV0::new([5; 32]).unwrap(),
///     ReceiptsRootV0::new([6; 32]).unwrap(),
///     Hash32V0::new([7; 32]),
/// ).unwrap();
/// let binding = ProposalValidationBindingV0::new(
///     ChainIdV0::new("trnm-doctest").unwrap(),
///     GenesisHashV0::new([8; 32]).unwrap(),
///     parent,
///     BlockIdV0::new([9; 32]).unwrap(),
///     HeightV0::new(1),
///     1_700_000_000_000,
///     ValidatorSetIdV0::new([10; 32]).unwrap(),
///     1,
///     1,
///     ProposalRouteV0::Proposal,
///     commitments,
/// ).unwrap();
/// let digest = NonZeroDigestV0::new([7; 32]).unwrap();
/// let _forged = CoreDeliveryConfirmationV0::new(
///     binding.validation_id(), 1, digest, digest,
/// ).unwrap();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoreDeliveryConfirmationV0 {
    validation_id: ValidationIdV0,
    core_revision: u64,
    core_state_digest: NonZeroDigestV0,
    accepted_validation_digest: NonZeroDigestV0,
}

impl CoreDeliveryConfirmationV0 {
    pub(crate) fn new(
        validation_id: ValidationIdV0,
        core_revision: u64,
        core_state_digest: NonZeroDigestV0,
        accepted_validation_digest: NonZeroDigestV0,
    ) -> ValidationStoreResultV0<Self> {
        if core_revision == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "core_delivery.revision",
            ));
        }
        Ok(Self {
            validation_id,
            core_revision,
            core_state_digest,
            accepted_validation_digest,
        })
    }

    pub const fn validation_id(self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn core_revision(self) -> u64 {
        self.core_revision
    }

    pub const fn core_state_digest(self) -> NonZeroDigestV0 {
        self.core_state_digest
    }

    pub const fn accepted_validation_digest(self) -> NonZeroDigestV0 {
        self.accepted_validation_digest
    }

    pub fn digest(self) -> NonZeroDigestV0 {
        let mut hasher = Sha256::new();
        hasher.update(CORE_DELIVERY_DIGEST_DOMAIN_V0);
        hasher.update(self.validation_id.as_bytes());
        hasher.update(self.core_revision.to_be_bytes());
        hasher.update(self.core_state_digest.as_bytes());
        hasher.update(self.accepted_validation_digest.as_bytes());
        NonZeroDigestV0::new(hasher.finalize().into())
            .expect("SHA-256 domain digest is treated as nonzero")
    }
}

/// Exact query passed to the trusted Safety-store readback adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafetyConfirmationReadRequestV0 {
    validation_id: ValidationIdV0,
    core_delivery_digest: NonZeroDigestV0,
    expected_safety_revision: u64,
}

impl SafetyConfirmationReadRequestV0 {
    pub(crate) const fn new(
        validation_id: ValidationIdV0,
        core_delivery_digest: NonZeroDigestV0,
        expected_safety_revision: u64,
    ) -> Self {
        Self {
            validation_id,
            core_delivery_digest,
            expected_safety_revision,
        }
    }

    pub const fn validation_id(self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn core_delivery_digest(self) -> NonZeroDigestV0 {
        self.core_delivery_digest
    }

    pub const fn expected_safety_revision(self) -> u64 {
        self.expected_safety_revision
    }
}

/// Untrusted data returned by a Safety-store readback adapter.
///
/// Constructing this value does not confer Safety authority. The validation
/// store compares its request binding exactly and only then creates the
/// non-constructible, request-bound C-shaped confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UntrustedSafetyConfirmationReadbackV0 {
    validation_id: ValidationIdV0,
    core_delivery_digest: NonZeroDigestV0,
    safety_revision: u64,
    safety_record_digest: NonZeroDigestV0,
    vote_intent_digest: NonZeroDigestV0,
}

impl UntrustedSafetyConfirmationReadbackV0 {
    pub fn new(
        validation_id: ValidationIdV0,
        core_delivery_digest: NonZeroDigestV0,
        safety_revision: u64,
        safety_record_digest: NonZeroDigestV0,
        vote_intent_digest: NonZeroDigestV0,
    ) -> ValidationStoreResultV0<Self> {
        if safety_revision == 0 {
            return Err(error(
                ValidationStoreErrorCodeV0::ZeroValue,
                "safety_readback.revision",
            ));
        }
        Ok(Self {
            validation_id,
            core_delivery_digest,
            safety_revision,
            safety_record_digest,
            vote_intent_digest,
        })
    }
}

/// Trusted adapter boundary for an exact, independently durable Safety read.
///
/// Implementations belong to the node TCB. The raw return value is still
/// treated as untrusted and is compared against the exact request.
pub trait SafetyConfirmationReadbackV0 {
    fn read_exact_safety_confirmation_v0(
        &mut self,
        request: SafetyConfirmationReadRequestV0,
    ) -> ValidationStoreResultV0<UntrustedSafetyConfirmationReadbackV0>;
}

/// Request-bound, C-shaped Safety readback data.
///
/// This value proves only that the adapter returned the exact validation ID,
/// Core-D digest, and Core completion revision requested by the journal. It is
/// not SafetyStore authority and cannot authorize signing or advance Core.
/// There is intentionally no public constructor.
///
/// ```compile_fail
/// use trnm_native_application_sqlite::RequestBoundSafetyConfirmationV0;
///
/// let _forged = RequestBoundSafetyConfirmationV0::new();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestBoundSafetyConfirmationV0 {
    validation_id: ValidationIdV0,
    core_delivery_digest: NonZeroDigestV0,
    safety_revision: u64,
    safety_record_digest: NonZeroDigestV0,
    vote_intent_digest: NonZeroDigestV0,
}

impl RequestBoundSafetyConfirmationV0 {
    pub(crate) const fn from_confirmed_authority(
        validation_id: ValidationIdV0,
        core_delivery_digest: NonZeroDigestV0,
        safety_revision: u64,
        safety_record_digest: NonZeroDigestV0,
        vote_intent_digest: NonZeroDigestV0,
    ) -> Self {
        Self {
            validation_id,
            core_delivery_digest,
            safety_revision,
            safety_record_digest,
            vote_intent_digest,
        }
    }

    pub(crate) fn verify_readback(
        request: SafetyConfirmationReadRequestV0,
        readback: UntrustedSafetyConfirmationReadbackV0,
    ) -> ValidationStoreResultV0<Self> {
        if readback.validation_id != request.validation_id
            || readback.core_delivery_digest != request.core_delivery_digest
            || readback.safety_revision != request.expected_safety_revision
        {
            return Err(error(
                ValidationStoreErrorCodeV0::BindingMismatch,
                "safety_readback.request",
            ));
        }
        Ok(Self {
            validation_id: readback.validation_id,
            core_delivery_digest: readback.core_delivery_digest,
            safety_revision: readback.safety_revision,
            safety_record_digest: readback.safety_record_digest,
            vote_intent_digest: readback.vote_intent_digest,
        })
    }

    pub const fn validation_id(self) -> ValidationIdV0 {
        self.validation_id
    }

    pub const fn core_delivery_digest(self) -> NonZeroDigestV0 {
        self.core_delivery_digest
    }

    pub const fn safety_revision(self) -> u64 {
        self.safety_revision
    }

    pub const fn safety_record_digest(self) -> NonZeroDigestV0 {
        self.safety_record_digest
    }

    pub const fn vote_intent_digest(self) -> NonZeroDigestV0 {
        self.vote_intent_digest
    }
}

#[allow(clippy::too_many_arguments)]
fn derive_validation_id_v0(
    chain_id: &ChainIdV0,
    genesis_hash: GenesisHashV0,
    parent: &ApplicationHeadV0,
    block_id: BlockIdV0,
    height: HeightV0,
    timestamp_ms: u64,
    active_validator_set_id: ValidatorSetIdV0,
    view: u64,
    generation: u64,
    route: ProposalRouteV0,
    commitments: NativeExpectedBlockCommitmentsV0,
) -> ValidationIdV0 {
    let mut hasher = Sha256::new();
    hasher.update(VALIDATION_ID_DOMAIN_V0);
    let chain_bytes = chain_id.as_str().as_bytes();
    hasher.update((chain_bytes.len() as u32).to_be_bytes());
    hasher.update(chain_bytes);
    hasher.update(genesis_hash.as_bytes());
    hasher.update(parent.height().get().to_be_bytes());
    hasher.update(parent.block_id().as_bytes());
    hasher.update(parent.state_root().as_bytes());
    hasher.update(parent.commit_id().as_bytes());
    hasher.update(block_id.as_bytes());
    hasher.update(height.get().to_be_bytes());
    hasher.update(timestamp_ms.to_be_bytes());
    hasher.update(active_validator_set_id.as_bytes());
    hasher.update(view.to_be_bytes());
    hasher.update(generation.to_be_bytes());
    hasher.update([route.tag()]);
    hasher.update(commitments.payload_root().as_bytes());
    hasher.update(commitments.post_state_root().as_bytes());
    hasher.update(commitments.receipts_root().as_bytes());
    hasher.update(commitments.evidence_root().as_bytes());
    ValidationIdV0::from_bytes(hasher.finalize().into())
}
