use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature, VerifyingKey};

use crate::{
    codec::{canonical_bytes, digest_bytes_value, digest_value},
    error::{error, DaErrorCodeV1, DaResultV1},
};

pub const PROTOCOL_VERSION_V1: u32 = 1;
pub const STRICT_ED25519_SCHEME_V1: u16 = 0;
pub const TRANSACTION_BATCH_NAMESPACE_V1: u8 = 0;
pub const ARTIFACT_EVIDENCE_NAMESPACE_V1: u8 = 1;

const BATCH_DOMAIN: &str = "trnm.poco-ai.da-batch.v1";
const CHUNK_ID_DOMAIN: &str = "trnm.poco-ai.da-chunk-id.v1";
const CHUNK_BYTES_DOMAIN: &str = "trnm.poco-ai.da-chunk-bytes.v1";
const TRANSACTION_ITEM_DOMAIN: &str = "trnm.poco-ai.da-transaction-item.candidate.v1";
const CONTENT_LEAF_DOMAIN: &str = "trnm.poco-ai.da-content-leaf.candidate.v1";
pub(crate) const CHUNK_LEAF_DOMAIN: &str = "trnm.poco-ai.da-chunk-leaf.candidate.v1";
pub(crate) const MERKLE_PARENT_DOMAIN: &str = "trnm.poco-ai.da-merkle-parent.candidate.v1";
pub(crate) const MERKLE_ROOT_DOMAIN: &str = "trnm.poco-ai.da-merkle-root.candidate.v1";
const MEMBER_DOMAIN: &str = "trnm.poco-ai.da-member.v1";
const COMMITTEE_DOMAIN: &str = "trnm.poco-ai.da-committee.v1";
const POLICY_DOMAIN: &str = "trnm.poco-ai.da-policy.candidate.v1";
const AUTHOR_STATEMENT_DOMAIN: &str = "trnm.poco-ai.da-batch-author-signature.v1";
const ATTESTATION_DOMAIN: &str = "trnm.poco-ai.da-attestation.v1";
const ATTESTATION_SIGNATURE_DOMAIN: &str = "trnm.poco-ai.da-attestation-signature.v1";
const CERTIFICATE_DOMAIN: &str = "trnm.poco-ai.availability-certificate.v1";
const OBLIGATION_DOMAIN: &str = "trnm.poco-ai.da-obligation.v1";
const WITHHOLDING_DOMAIN: &str = "trnm.poco-ai.da-withholding-evidence.candidate.v1";
const MAX_AUTHOR_ID_BYTES_V1: usize = 256;

#[derive(
    Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, BorshDeserialize, BorshSerialize,
)]
pub struct Hash32V1(pub(crate) [u8; 32]);

impl Hash32V1 {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

macro_rules! typed_hash_id {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, BorshDeserialize, BorshSerialize,
        )]
        pub struct $name(Hash32V1);

        impl $name {
            pub(crate) const fn from_hash(hash: Hash32V1) -> Self {
                Self(hash)
            }

            pub const fn as_hash(&self) -> Hash32V1 {
                self.0
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                self.0.as_bytes()
            }
        }
    };
}

typed_hash_id!(DaCommitteeIdV1);
typed_hash_id!(BatchIdV1);
typed_hash_id!(ChunkIdV1);
typed_hash_id!(DaAttestationIdV1);
typed_hash_id!(AvailabilityCertificateIdV1);
typed_hash_id!(DaObligationIdV1);
typed_hash_id!(WithholdingEvidenceIdV1);

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaNamespaceV1(u8);

impl DaNamespaceV1 {
    pub const TRANSACTION_BATCH: Self = Self(TRANSACTION_BATCH_NAMESPACE_V1);

    pub fn transaction_batch_only(tag: u8) -> DaResultV1<Self> {
        match tag {
            TRANSACTION_BATCH_NAMESPACE_V1 => Ok(Self::TRANSACTION_BATCH),
            ARTIFACT_EVIDENCE_NAMESPACE_V1 => Err(error(
                DaErrorCodeV1::UnsupportedNamespace,
                "ArtifactEvidence is outside this candidate tranche",
            )),
            _ => Err(error(
                DaErrorCodeV1::UnsupportedNamespace,
                "unknown DA namespace",
            )),
        }
    }

    pub const fn tag(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaObjectKindV1(u16);

impl DaObjectKindV1 {
    pub const BATCH: Self = Self(1);
    pub const CHUNK: Self = Self(2);
    pub const ATTESTATION: Self = Self(3);
    pub const CERTIFICATE: Self = Self(4);
    pub const OBLIGATION: Self = Self(5);
    pub const WITHHOLDING_EVIDENCE: Self = Self(6);

    pub const fn tag(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct TypedDaObjectIdV1 {
    namespace: DaNamespaceV1,
    kind: DaObjectKindV1,
    digest: Hash32V1,
}

impl TypedDaObjectIdV1 {
    pub const fn new(namespace: DaNamespaceV1, kind: DaObjectKindV1, digest: Hash32V1) -> Self {
        Self {
            namespace,
            kind,
            digest,
        }
    }

    pub const fn namespace(self) -> DaNamespaceV1 {
        self.namespace
    }

    pub const fn kind(self) -> DaObjectKindV1 {
        self.kind
    }

    pub const fn digest(self) -> Hash32V1 {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ProtocolContextV1 {
    schema_version: u16,
    genesis_hash: Hash32V1,
    chain_id: String,
    protocol_version: u32,
    stack_profile_hash: Hash32V1,
}

impl ProtocolContextV1 {
    pub fn new(
        genesis_hash: Hash32V1,
        chain_id: impl Into<String>,
        stack_profile_hash: Hash32V1,
    ) -> DaResultV1<Self> {
        let context = Self {
            schema_version: 1,
            genesis_hash,
            chain_id: chain_id.into(),
            protocol_version: PROTOCOL_VERSION_V1,
            stack_profile_hash,
        };
        context.validate()?;
        Ok(context)
    }

    pub(crate) fn validate(&self) -> DaResultV1<()> {
        if self.schema_version != 1 || self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(error(
                DaErrorCodeV1::InvalidContext,
                "unsupported context version",
            ));
        }
        if self.chain_id.is_empty() || self.chain_id.len() > 128 || !self.chain_id.is_ascii() {
            return Err(error(
                DaErrorCodeV1::InvalidContext,
                "chain ID must be bounded nonempty ASCII",
            ));
        }
        Ok(())
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub const fn genesis_hash(&self) -> Hash32V1 {
        self.genesis_hash
    }

    pub const fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    pub const fn stack_profile_hash(&self) -> Hash32V1 {
        self.stack_profile_hash
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaMemberBodyV1 {
    attestation_key_scheme: u16,
    attestation_public_key: [u8; 32],
    weight: u128,
    validator_id: Option<Vec<u8>>,
    storage_service_commitment: Hash32V1,
    slashable_bond_reference: Hash32V1,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaMemberV1 {
    body: DaMemberBodyV1,
    member_definition_hash: Hash32V1,
}

impl DaMemberV1 {
    pub fn new(
        public_key: [u8; 32],
        weight: u128,
        validator_id: Option<Vec<u8>>,
        storage_service_commitment: Hash32V1,
        slashable_bond_reference: Hash32V1,
    ) -> DaResultV1<Self> {
        if weight == 0 {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "DA member weight must be positive",
            ));
        }
        VerifyingKey::from_bytes(&public_key).map_err(|_| {
            error(
                DaErrorCodeV1::InvalidCommittee,
                "DA member key is not strict Ed25519",
            )
        })?;
        if VerifyingKey::from_bytes(&public_key)
            .map_err(|_| error(DaErrorCodeV1::InvalidCommittee, "invalid DA member key"))?
            .is_weak()
        {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "weak DA member key is forbidden",
            ));
        }
        let body = DaMemberBodyV1 {
            attestation_key_scheme: STRICT_ED25519_SCHEME_V1,
            attestation_public_key: public_key,
            weight,
            validator_id,
            storage_service_commitment,
            slashable_bond_reference,
        };
        let member_definition_hash = digest_value(MEMBER_DOMAIN, &body)?;
        Ok(Self {
            body,
            member_definition_hash,
        })
    }

    pub const fn definition_hash(&self) -> Hash32V1 {
        self.member_definition_hash
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.body.attestation_public_key
    }

    pub const fn weight(&self) -> u128 {
        self.body.weight
    }

    pub(crate) fn validate(&self) -> DaResultV1<()> {
        if self.body.attestation_key_scheme != STRICT_ED25519_SCHEME_V1
            || self.body.weight == 0
            || digest_value(MEMBER_DOMAIN, &self.body)? != self.member_definition_hash
        {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "invalid DA member definition",
            ));
        }
        let key = VerifyingKey::from_bytes(&self.body.attestation_public_key).map_err(|_| {
            error(
                DaErrorCodeV1::InvalidCommittee,
                "invalid DA member Ed25519 key",
            )
        })?;
        if key.is_weak() {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "weak DA member key is forbidden",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaCommitteeDescriptorV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    members: Vec<DaMemberV1>,
    threshold_weight: u128,
    retention_epochs: u32,
    max_author_bytes: u64,
    max_batch_bytes: u64,
    max_batch_items: u32,
    max_outstanding_sequences: u32,
}

impl DaCommitteeDescriptorV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_transaction_batch(
        context: ProtocolContextV1,
        epoch: u64,
        members: Vec<DaMemberV1>,
        retention_epochs: u32,
        max_author_bytes: u64,
        max_batch_bytes: u64,
        max_batch_items: u32,
        max_outstanding_sequences: u32,
    ) -> DaResultV1<Self> {
        let total = checked_member_total(&members)?;
        let doubled = total.checked_mul(2).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "committee quorum multiplication overflow",
            )
        })?;
        let threshold_weight = doubled
            .checked_div(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "committee quorum calculation overflow",
                )
            })?;
        let descriptor = Self {
            schema_version: 1,
            context,
            namespace: DaNamespaceV1::TRANSACTION_BATCH,
            epoch,
            members,
            threshold_weight,
            retention_epochs,
            max_author_bytes,
            max_batch_bytes,
            max_batch_items,
            max_outstanding_sequences,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    pub(crate) fn validate(&self) -> DaResultV1<()> {
        self.context.validate()?;
        DaNamespaceV1::transaction_batch_only(self.namespace.tag())?;
        if self.schema_version != 1
            || self.retention_epochs == 0
            || self.max_author_bytes == 0
            || self.max_batch_bytes == 0
            || self.max_batch_items == 0
            || self.max_outstanding_sequences == 0
        {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "invalid committee bounds",
            ));
        }
        let total = checked_member_total(&self.members)?;
        let expected = total
            .checked_mul(2)
            .and_then(|value| value.checked_div(3))
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "committee quorum calculation overflow",
                )
            })?;
        if self.threshold_weight != expected || self.threshold_weight > total {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "committee threshold is not floor(2W/3)+1",
            ));
        }
        Ok(())
    }

    pub fn committee_id(&self) -> DaResultV1<DaCommitteeIdV1> {
        self.validate()?;
        Ok(DaCommitteeIdV1::from_hash(digest_value(
            COMMITTEE_DOMAIN,
            self,
        )?))
    }

    pub fn member(&self, id: Hash32V1) -> Option<&DaMemberV1> {
        self.members
            .binary_search_by_key(&id, DaMemberV1::definition_hash)
            .ok()
            .map(|index| &self.members[index])
    }

    pub fn members(&self) -> &[DaMemberV1] {
        &self.members
    }

    pub const fn threshold_weight(&self) -> u128 {
        self.threshold_weight
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn retention_epochs(&self) -> u32 {
        self.retention_epochs
    }

    pub const fn max_batch_bytes(&self) -> u64 {
        self.max_batch_bytes
    }

    pub const fn max_batch_items(&self) -> u32 {
        self.max_batch_items
    }

    pub const fn max_author_bytes(&self) -> u64 {
        self.max_author_bytes
    }

    pub const fn max_outstanding_sequences(&self) -> u32 {
        self.max_outstanding_sequences
    }

    pub fn context(&self) -> &ProtocolContextV1 {
        &self.context
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }
}

fn checked_member_total(members: &[DaMemberV1]) -> DaResultV1<u128> {
    if members.is_empty() {
        return Err(error(
            DaErrorCodeV1::InvalidCommittee,
            "DA committee must not be empty",
        ));
    }
    let mut prior = None;
    let mut keys = BTreeSet::new();
    let mut total = 0u128;
    for member in members {
        member.validate()?;
        if prior.is_some_and(|value| value >= member.definition_hash())
            || !keys.insert(*member.public_key())
        {
            return Err(error(
                DaErrorCodeV1::InvalidCommittee,
                "DA members must be strictly ordered with unique keys",
            ));
        }
        prior = Some(member.definition_hash());
        total = total.checked_add(member.weight()).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "DA committee weight overflow",
            )
        })?;
    }
    Ok(total)
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaAuthorAuthorityV1 {
    author_id: Vec<u8>,
    author_public_key: [u8; 32],
    first_sequence: u64,
    maximum_sequence: u64,
    max_author_bytes: u64,
    max_outstanding_sequences: u32,
}

impl DaAuthorAuthorityV1 {
    pub fn new(
        author_id: Vec<u8>,
        author_public_key: [u8; 32],
        first_sequence: u64,
        maximum_sequence: u64,
        max_author_bytes: u64,
        max_outstanding_sequences: u32,
    ) -> DaResultV1<Self> {
        let authority = Self {
            author_id,
            author_public_key,
            first_sequence,
            maximum_sequence,
            max_author_bytes,
            max_outstanding_sequences,
        };
        authority.validate()?;
        Ok(authority)
    }

    pub fn author_id(&self) -> &[u8] {
        &self.author_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.author_public_key
    }

    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    pub const fn maximum_sequence(&self) -> u64 {
        self.maximum_sequence
    }

    pub const fn max_author_bytes(&self) -> u64 {
        self.max_author_bytes
    }

    pub const fn max_outstanding_sequences(&self) -> u32 {
        self.max_outstanding_sequences
    }

    /// Validate every field of an authority, including values that can be
    /// obtained through a canonical decode rather than the constructor.
    ///
    /// Policy validation must not trust that all authorities were created by
    /// `new`: a malformed authority can otherwise enter a decoded policy with
    /// a zero watermark, an inverted sequence interval, or an invalid key.
    pub(crate) fn validate(&self) -> DaResultV1<()> {
        if self.author_id.is_empty()
            || self.author_id.len() > MAX_AUTHOR_ID_BYTES_V1
            || self.first_sequence == 0
            || self.maximum_sequence < self.first_sequence
            || self.max_author_bytes == 0
            || self.max_outstanding_sequences == 0
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "invalid DA author authority",
            ));
        }
        let author_key = VerifyingKey::from_bytes(&self.author_public_key).map_err(|_| {
            error(
                DaErrorCodeV1::InvalidSignature,
                "author key is not strict Ed25519",
            )
        })?;
        if author_key.is_weak() {
            return Err(error(
                DaErrorCodeV1::InvalidSignature,
                "weak author key is forbidden",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaPolicyV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    authorities: Vec<DaAuthorAuthorityV1>,
    max_batch_bytes: u64,
    max_batch_items: u32,
    max_chunk_bytes: u32,
    max_chunks_per_batch: u32,
    max_queue_batches: u32,
    max_queue_bytes: u64,
    retrieval_window_blocks: u64,
    repair_window_blocks: u64,
}

impl DaPolicyV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_transaction_batch(
        committee: &DaCommitteeDescriptorV1,
        authorities: Vec<DaAuthorAuthorityV1>,
        max_chunk_bytes: u32,
        max_chunks_per_batch: u32,
        max_queue_batches: u32,
        max_queue_bytes: u64,
        retrieval_window_blocks: u64,
        repair_window_blocks: u64,
    ) -> DaResultV1<Self> {
        let policy = Self {
            schema_version: 1,
            context: committee.context.clone(),
            epoch: committee.epoch,
            committee_id: committee.committee_id()?,
            authorities,
            max_batch_bytes: committee.max_batch_bytes,
            max_batch_items: committee.max_batch_items,
            max_chunk_bytes,
            max_chunks_per_batch,
            max_queue_batches,
            max_queue_bytes,
            retrieval_window_blocks,
            repair_window_blocks,
        };
        policy.validate(committee)?;
        Ok(policy)
    }

    pub(crate) fn validate(&self, committee: &DaCommitteeDescriptorV1) -> DaResultV1<()> {
        if self.schema_version != 1
            || self.context != committee.context
            || self.epoch != committee.epoch
            || self.committee_id != committee.committee_id()?
            || self.max_batch_bytes != committee.max_batch_bytes
            || self.max_batch_items != committee.max_batch_items
            || self.max_chunk_bytes == 0
            || self.max_chunks_per_batch == 0
            || self.max_queue_batches == 0
            || self.max_queue_bytes == 0
            || self.retrieval_window_blocks == 0
            || self.repair_window_blocks == 0
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "invalid transaction-batch DA policy",
            ));
        }
        if u64::from(self.max_chunk_bytes) > self.max_batch_bytes {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "chunk bound exceeds batch bound",
            ));
        }
        let mut prior: Option<&[u8]> = None;
        let mut keys = BTreeSet::new();
        for authority in &self.authorities {
            authority.validate()?;
            if prior.is_some_and(|value| value >= authority.author_id.as_slice())
                || !keys.insert(authority.author_public_key)
                || authority.max_author_bytes > committee.max_author_bytes
                || authority.max_outstanding_sequences > committee.max_outstanding_sequences
            {
                return Err(error(
                    DaErrorCodeV1::InvalidBounds,
                    "authorities must be canonical and within committee limits",
                ));
            }
            prior = Some(&authority.author_id);
        }
        if self.authorities.is_empty() {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "DA policy requires an author authority",
            ));
        }
        Ok(())
    }

    pub fn policy_hash(&self) -> DaResultV1<Hash32V1> {
        digest_value(POLICY_DOMAIN, self)
    }

    pub fn authority(&self, author_id: &[u8]) -> Option<&DaAuthorAuthorityV1> {
        self.authorities
            .binary_search_by(|candidate| candidate.author_id.as_slice().cmp(author_id))
            .ok()
            .map(|index| &self.authorities[index])
    }

    pub const fn max_chunk_bytes(&self) -> u32 {
        self.max_chunk_bytes
    }

    pub const fn max_chunks_per_batch(&self) -> u32 {
        self.max_chunks_per_batch
    }

    pub const fn max_queue_batches(&self) -> u32 {
        self.max_queue_batches
    }

    pub const fn max_queue_bytes(&self) -> u64 {
        self.max_queue_bytes
    }

    pub const fn retrieval_window_blocks(&self) -> u64 {
        self.retrieval_window_blocks
    }

    pub const fn repair_window_blocks(&self) -> u64 {
        self.repair_window_blocks
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaChunkCoordinateV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    author_id: Vec<u8>,
    author_sequence: u64,
    chunking_profile_id: Hash32V1,
    chunk_index: u32,
    exact_byte_length: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaChunkV1 {
    coordinate: DaChunkCoordinateV1,
    chunk_id: ChunkIdV1,
    bytes: Vec<u8>,
    bytes_digest: Hash32V1,
}

impl DaChunkV1 {
    pub(crate) fn new(coordinate: DaChunkCoordinateV1, bytes: Vec<u8>) -> DaResultV1<Self> {
        if bytes.is_empty() || coordinate.exact_byte_length != bytes.len() as u64 {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "chunk bytes/coordinate length mismatch",
            ));
        }
        let chunk_id = ChunkIdV1::from_hash(digest_value(CHUNK_ID_DOMAIN, &coordinate)?);
        let bytes_digest = digest_bytes_value(CHUNK_BYTES_DOMAIN, &bytes)?;
        Ok(Self {
            coordinate,
            chunk_id,
            bytes,
            bytes_digest,
        })
    }

    pub const fn chunk_id(&self) -> ChunkIdV1 {
        self.chunk_id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn index(&self) -> u32 {
        self.coordinate.chunk_index
    }

    pub(crate) fn coordinate(&self) -> &DaChunkCoordinateV1 {
        &self.coordinate
    }

    pub(crate) const fn bytes_digest(&self) -> Hash32V1 {
        self.bytes_digest
    }

    pub(crate) fn validate(&self) -> DaResultV1<()> {
        let expected = Self::new(self.coordinate.clone(), self.bytes.clone())?;
        if expected.chunk_id != self.chunk_id || expected.bytes_digest != self.bytes_digest {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "chunk identifier or digest mismatch",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaBatchEnvelopeV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    author_id: Vec<u8>,
    author_sequence: u64,
    content_kind: u16,
    content_codec_id: Hash32V1,
    item_count: u32,
    uncompressed_bytes: u64,
    content_root: Hash32V1,
    chunking_profile_id: Hash32V1,
    chunk_count: u32,
    chunk_root: Hash32V1,
    retention_end_epoch: u64,
}

impl DaBatchEnvelopeV1 {
    pub fn batch_id(&self) -> DaResultV1<BatchIdV1> {
        self.validate_shape()?;
        Ok(BatchIdV1::from_hash(digest_value(BATCH_DOMAIN, self)?))
    }

    pub(crate) fn validate_shape(&self) -> DaResultV1<()> {
        self.context.validate()?;
        DaNamespaceV1::transaction_batch_only(self.namespace.tag())?;
        if self.schema_version != 1
            || self.author_id.is_empty()
            || self.author_sequence == 0
            || self.content_kind != 0
            || self.item_count == 0
            || self.uncompressed_bytes == 0
            || self.chunk_count == 0
            || self.retention_end_epoch <= self.epoch
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "invalid transaction-batch envelope",
            ));
        }
        Ok(())
    }

    pub const fn namespace(&self) -> DaNamespaceV1 {
        self.namespace
    }

    pub fn context(&self) -> &ProtocolContextV1 {
        &self.context
    }

    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    pub const fn committee_id(&self) -> DaCommitteeIdV1 {
        self.committee_id
    }

    pub fn author_id(&self) -> &[u8] {
        &self.author_id
    }

    pub const fn author_sequence(&self) -> u64 {
        self.author_sequence
    }

    pub const fn content_root(&self) -> Hash32V1 {
        self.content_root
    }

    pub const fn chunk_root(&self) -> Hash32V1 {
        self.chunk_root
    }

    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub const fn retention_end_epoch(&self) -> u64 {
        self.retention_end_epoch
    }

    pub const fn item_count(&self) -> u32 {
        self.item_count
    }

    pub const fn uncompressed_bytes(&self) -> u64 {
        self.uncompressed_bytes
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaBatchAuthorStatementV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    author_id: Vec<u8>,
    author_sequence: u64,
    batch_id: BatchIdV1,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaBatchAuthorV1 {
    statement: DaBatchAuthorStatementV1,
    author_key_scheme: u16,
    author_public_key: [u8; 32],
    signature: Vec<u8>,
}

impl DaBatchAuthorV1 {
    pub fn from_signature(
        envelope: &DaBatchEnvelopeV1,
        public_key: [u8; 32],
        signature: Vec<u8>,
    ) -> DaResultV1<Self> {
        let statement = DaBatchAuthorStatementV1 {
            schema_version: 1,
            context: envelope.context.clone(),
            namespace: envelope.namespace,
            epoch: envelope.epoch,
            committee_id: envelope.committee_id,
            author_id: envelope.author_id.clone(),
            author_sequence: envelope.author_sequence,
            batch_id: envelope.batch_id()?,
        };
        let value = Self {
            statement,
            author_key_scheme: STRICT_ED25519_SCHEME_V1,
            author_public_key: public_key,
            signature,
        };
        value.verify(envelope)?;
        Ok(value)
    }

    pub fn signing_root(envelope: &DaBatchEnvelopeV1) -> DaResultV1<Hash32V1> {
        let statement = DaBatchAuthorStatementV1 {
            schema_version: 1,
            context: envelope.context.clone(),
            namespace: envelope.namespace,
            epoch: envelope.epoch,
            committee_id: envelope.committee_id,
            author_id: envelope.author_id.clone(),
            author_sequence: envelope.author_sequence,
            batch_id: envelope.batch_id()?,
        };
        digest_value(AUTHOR_STATEMENT_DOMAIN, &statement)
    }

    pub(crate) fn verify(&self, envelope: &DaBatchEnvelopeV1) -> DaResultV1<()> {
        if self.author_key_scheme != STRICT_ED25519_SCHEME_V1
            || self.statement.context != envelope.context
            || self.statement.namespace != envelope.namespace
            || self.statement.epoch != envelope.epoch
            || self.statement.committee_id != envelope.committee_id
            || self.statement.author_id != envelope.author_id
            || self.statement.author_sequence != envelope.author_sequence
            || self.statement.batch_id != envelope.batch_id()?
        {
            return Err(error(
                DaErrorCodeV1::InvalidSignature,
                "author statement does not bind the envelope",
            ));
        }
        verify_strict(
            &self.author_public_key,
            DaBatchAuthorV1::signing_root(envelope)?.as_bytes(),
            &self.signature,
        )
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }

    pub(crate) const fn public_key(&self) -> &[u8; 32] {
        &self.author_public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnsignedTransactionBatchV1 {
    envelope: DaBatchEnvelopeV1,
    batch_id: BatchIdV1,
    content_bytes: Vec<u8>,
    chunks: Vec<DaChunkV1>,
}

impl UnsignedTransactionBatchV1 {
    pub fn build(
        committee: &DaCommitteeDescriptorV1,
        policy: &DaPolicyV1,
        author_id: Vec<u8>,
        author_sequence: u64,
        transactions: Vec<Vec<u8>>,
    ) -> DaResultV1<Self> {
        committee.validate()?;
        policy.validate(committee)?;
        let authority = policy.authority(&author_id).ok_or_else(|| {
            error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "author is not in the committed DA policy",
            )
        })?;
        if author_sequence < authority.first_sequence
            || author_sequence > authority.maximum_sequence
        {
            return Err(error(
                DaErrorCodeV1::SequenceConflict,
                "author sequence is outside authority range",
            ));
        }
        if transactions.is_empty()
            || transactions.len() > usize::try_from(policy.max_batch_items).unwrap_or(usize::MAX)
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "invalid transaction item count",
            ));
        }
        let mut unique = BTreeSet::new();
        for transaction in &transactions {
            if transaction.is_empty() || !unique.insert(transaction.clone()) {
                return Err(error(
                    DaErrorCodeV1::NonCanonical,
                    "transaction entries must be nonempty and duplicate-free",
                ));
            }
        }
        let content_bytes = canonical_bytes(&transactions)?;
        let total_bytes = u64::try_from(content_bytes.len()).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "transaction batch length exceeds u64",
            )
        })?;
        if total_bytes > policy.max_batch_bytes {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "transaction batch exceeds max_batch_bytes",
            ));
        }
        let content_codec_id = digest_value(
            "trnm.poco-ai.da-codec.v1",
            &(1u16, TRANSACTION_BATCH_NAMESPACE_V1),
        )?;
        let chunking_profile_id = digest_value(
            "trnm.poco-ai.da-chunking-profile.v1",
            &(1u16, 0u8, policy.max_chunk_bytes),
        )?;
        let content_leaves = transactions
            .iter()
            .enumerate()
            .map(|(index, transaction)| {
                let item_id = digest_bytes_value(TRANSACTION_ITEM_DOMAIN, transaction)?;
                digest_value(
                    CONTENT_LEAF_DOMAIN,
                    &(
                        u32::try_from(index).map_err(|_| {
                            error(
                                DaErrorCodeV1::ArithmeticOverflow,
                                "transaction index exceeds u32",
                            )
                        })?,
                        item_id,
                        digest_bytes_value(TRANSACTION_ITEM_DOMAIN, transaction)?,
                    ),
                )
            })
            .collect::<DaResultV1<Vec<_>>>()?;
        let content_root = merkle_root(CONTENT_LEAF_DOMAIN, content_leaves)?;
        let chunk_size = usize::try_from(policy.max_chunk_bytes).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "chunk bound exceeds usize",
            )
        })?;
        let chunk_count = content_bytes.len().div_ceil(chunk_size);
        if chunk_count == 0
            || chunk_count > usize::try_from(policy.max_chunks_per_batch).unwrap_or(usize::MAX)
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "transaction batch chunk count exceeds policy",
            ));
        }
        let committee_id = committee.committee_id()?;
        let chunks = content_bytes
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, bytes)| {
                DaChunkV1::new(
                    DaChunkCoordinateV1 {
                        schema_version: 1,
                        context: committee.context.clone(),
                        namespace: DaNamespaceV1::TRANSACTION_BATCH,
                        epoch: committee.epoch,
                        committee_id,
                        author_id: author_id.clone(),
                        author_sequence,
                        chunking_profile_id,
                        chunk_index: u32::try_from(index).map_err(|_| {
                            error(DaErrorCodeV1::ArithmeticOverflow, "chunk index exceeds u32")
                        })?,
                        exact_byte_length: bytes.len() as u64,
                    },
                    bytes.to_vec(),
                )
            })
            .collect::<DaResultV1<Vec<_>>>()?;
        let chunk_leaves = chunks
            .iter()
            .map(|chunk| {
                digest_value(
                    CHUNK_LEAF_DOMAIN,
                    &(chunk.index(), chunk.chunk_id(), chunk.bytes_digest),
                )
            })
            .collect::<DaResultV1<Vec<_>>>()?;
        let chunk_root = merkle_root(CHUNK_LEAF_DOMAIN, chunk_leaves)?;
        let retention_end_epoch = committee
            .epoch
            .checked_add(u64::from(committee.retention_epochs))
            .ok_or_else(|| error(DaErrorCodeV1::ArithmeticOverflow, "retention end overflow"))?;
        let envelope = DaBatchEnvelopeV1 {
            schema_version: 1,
            context: committee.context.clone(),
            namespace: DaNamespaceV1::TRANSACTION_BATCH,
            epoch: committee.epoch,
            committee_id,
            author_id,
            author_sequence,
            content_kind: 0,
            content_codec_id,
            item_count: u32::try_from(transactions.len()).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "transaction count exceeds u32",
                )
            })?,
            uncompressed_bytes: total_bytes,
            content_root,
            chunking_profile_id,
            chunk_count: u32::try_from(chunks.len())
                .map_err(|_| error(DaErrorCodeV1::ArithmeticOverflow, "chunk count exceeds u32"))?,
            chunk_root,
            retention_end_epoch,
        };
        let batch_id = envelope.batch_id()?;
        Ok(Self {
            envelope,
            batch_id,
            content_bytes,
            chunks,
        })
    }

    pub fn envelope(&self) -> &DaBatchEnvelopeV1 {
        &self.envelope
    }

    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub fn content_bytes(&self) -> &[u8] {
        &self.content_bytes
    }

    pub fn chunks(&self) -> &[DaChunkV1] {
        &self.chunks
    }

    pub(crate) fn verify_exact(
        &self,
        committee: &DaCommitteeDescriptorV1,
        policy: &DaPolicyV1,
    ) -> DaResultV1<()> {
        for chunk in &self.chunks {
            chunk.validate()?;
        }
        let transactions: Vec<Vec<u8>> = crate::codec::strict_decode(&self.content_bytes)?;
        let rebuilt = Self::build(
            committee,
            policy,
            self.envelope.author_id.clone(),
            self.envelope.author_sequence,
            transactions,
        )?;
        if &rebuilt != self {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "batch content/chunks do not exactly derive the envelope",
            ));
        }
        Ok(())
    }

    pub(crate) fn from_stored(
        committee: &DaCommitteeDescriptorV1,
        policy: &DaPolicyV1,
        envelope_bytes: &[u8],
        content_bytes: Vec<u8>,
        chunks_bytes: &[u8],
    ) -> DaResultV1<Self> {
        let envelope: DaBatchEnvelopeV1 = crate::codec::strict_decode(envelope_bytes)?;
        let chunks: Vec<DaChunkV1> = crate::codec::strict_decode(chunks_bytes)?;
        let value = Self {
            batch_id: envelope.batch_id()?,
            envelope,
            content_bytes,
            chunks,
        };
        value.verify_exact(committee, policy)?;
        Ok(value)
    }

    pub(crate) fn chunks_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(&self.chunks)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaAttestationBodyV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    batch_id: BatchIdV1,
    content_root: Hash32V1,
    chunk_root: Hash32V1,
    retention_end_epoch: u64,
    attestor_id: Hash32V1,
    author_id: Vec<u8>,
    author_sequence: u64,
    attestation_sequence: u64,
    storage_record_checksum: Hash32V1,
}

impl DaAttestationBodyV1 {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        envelope: &DaBatchEnvelopeV1,
        batch_id: BatchIdV1,
        attestor_id: Hash32V1,
        attestation_sequence: u64,
        storage_record_checksum: Hash32V1,
    ) -> Self {
        Self {
            schema_version: 1,
            context: envelope.context.clone(),
            namespace: envelope.namespace,
            epoch: envelope.epoch,
            committee_id: envelope.committee_id,
            batch_id,
            content_root: envelope.content_root,
            chunk_root: envelope.chunk_root,
            retention_end_epoch: envelope.retention_end_epoch,
            attestor_id,
            author_id: envelope.author_id.clone(),
            author_sequence: envelope.author_sequence,
            attestation_sequence,
            storage_record_checksum,
        }
    }

    pub const fn attestor_id(&self) -> Hash32V1 {
        self.attestor_id
    }

    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub fn conflict_coordinate(&self) -> DaResultV1<Hash32V1> {
        digest_value(
            "trnm.poco-ai.da-attestation-conflict-coordinate.candidate.v1",
            &(
                self.context.clone(),
                self.namespace,
                self.epoch,
                self.attestor_id,
                self.author_id.clone(),
                self.author_sequence,
            ),
        )
    }

    pub const fn attestation_sequence(&self) -> u64 {
        self.attestation_sequence
    }

    pub const fn storage_record_checksum(&self) -> Hash32V1 {
        self.storage_record_checksum
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }

    pub(crate) fn validate(&self, committee: &DaCommitteeDescriptorV1) -> DaResultV1<()> {
        self.context.validate()?;
        DaNamespaceV1::transaction_batch_only(self.namespace.tag())?;
        if self.schema_version != 1
            || self.context != committee.context
            || self.epoch != committee.epoch
            || self.committee_id != committee.committee_id()?
            || self.author_id.is_empty()
            || self.author_sequence == 0
            || self.attestation_sequence == 0
            || self.retention_end_epoch <= self.epoch
        {
            return Err(error(
                DaErrorCodeV1::InvalidContext,
                "attestation does not bind the exact committed DA context",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaAttestationV1 {
    body: DaAttestationBodyV1,
    attestation_id: DaAttestationIdV1,
    signature_scheme: u16,
    signature: Vec<u8>,
}

impl DaAttestationV1 {
    pub fn signing_root(body: &DaAttestationBodyV1) -> DaResultV1<Hash32V1> {
        let id = DaAttestationIdV1::from_hash(digest_value(ATTESTATION_DOMAIN, body)?);
        digest_value(ATTESTATION_SIGNATURE_DOMAIN, &id)
    }

    pub fn from_signature(
        committee: &DaCommitteeDescriptorV1,
        body: DaAttestationBodyV1,
        signature: Vec<u8>,
    ) -> DaResultV1<Self> {
        body.validate(committee)?;
        let member = committee.member(body.attestor_id).ok_or_else(|| {
            error(
                DaErrorCodeV1::InvalidCommittee,
                "attestor is not a committee member",
            )
        })?;
        verify_strict(
            member.public_key(),
            Self::signing_root(&body)?.as_bytes(),
            &signature,
        )?;
        Ok(Self {
            attestation_id: DaAttestationIdV1::from_hash(digest_value(ATTESTATION_DOMAIN, &body)?),
            body,
            signature_scheme: STRICT_ED25519_SCHEME_V1,
            signature,
        })
    }

    pub fn verify(&self, committee: &DaCommitteeDescriptorV1) -> DaResultV1<()> {
        self.body.validate(committee)?;
        if self.signature_scheme != STRICT_ED25519_SCHEME_V1
            || self.attestation_id
                != DaAttestationIdV1::from_hash(digest_value(ATTESTATION_DOMAIN, &self.body)?)
        {
            return Err(error(
                DaErrorCodeV1::IdentifierMismatch,
                "attestation ID or scheme mismatch",
            ));
        }
        let member = committee.member(self.body.attestor_id).ok_or_else(|| {
            error(
                DaErrorCodeV1::InvalidCommittee,
                "attestor is not a committee member",
            )
        })?;
        verify_strict(
            member.public_key(),
            Self::signing_root(&self.body)?.as_bytes(),
            &self.signature,
        )
    }

    pub fn body(&self) -> &DaAttestationBodyV1 {
        &self.body
    }

    pub const fn attestation_id(&self) -> DaAttestationIdV1 {
        self.attestation_id
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct AvailabilityCertificateBodyV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    namespace: DaNamespaceV1,
    epoch: u64,
    committee_id: DaCommitteeIdV1,
    envelope: DaBatchEnvelopeV1,
    author: DaBatchAuthorV1,
    attestations: Vec<DaAttestationV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct AvailabilityCertificateV1 {
    body: AvailabilityCertificateBodyV1,
    certificate_id: AvailabilityCertificateIdV1,
}

impl AvailabilityCertificateV1 {
    pub fn build(
        committee: &DaCommitteeDescriptorV1,
        envelope: DaBatchEnvelopeV1,
        author: DaBatchAuthorV1,
        attestations: Vec<DaAttestationV1>,
    ) -> DaResultV1<Self> {
        committee.validate()?;
        envelope.validate_shape()?;
        if envelope.context != committee.context
            || envelope.epoch != committee.epoch
            || envelope.committee_id != committee.committee_id()?
            || envelope.namespace != DaNamespaceV1::TRANSACTION_BATCH
        {
            return Err(error(
                DaErrorCodeV1::InvalidContext,
                "certificate envelope differs from committed DA context",
            ));
        }
        author.verify(&envelope)?;
        if attestations.is_empty() {
            return Err(error(
                DaErrorCodeV1::InsufficientWeight,
                "availability certificate signer set is empty",
            ));
        }
        let batch_id = envelope.batch_id()?;
        let mut prior = None;
        let mut weight = 0u128;
        for attestation in &attestations {
            attestation.verify(committee)?;
            let body = attestation.body();
            if prior.is_some_and(|value| value >= body.attestor_id)
                || body.context != envelope.context
                || body.namespace != envelope.namespace
                || body.epoch != envelope.epoch
                || body.committee_id != envelope.committee_id
                || body.batch_id != batch_id
                || body.content_root != envelope.content_root
                || body.chunk_root != envelope.chunk_root
                || body.retention_end_epoch != envelope.retention_end_epoch
                || body.author_id != envelope.author_id
                || body.author_sequence != envelope.author_sequence
            {
                return Err(error(
                    DaErrorCodeV1::Conflict,
                    "certificate attestation does not exactly bind envelope",
                ));
            }
            prior = Some(body.attestor_id);
            let member = committee.member(body.attestor_id).ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidCommittee,
                    "unknown certificate signer",
                )
            })?;
            weight = weight.checked_add(member.weight()).ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "certificate weight overflow",
                )
            })?;
        }
        if weight < committee.threshold_weight {
            return Err(error(
                DaErrorCodeV1::InsufficientWeight,
                "availability certificate is below weighted threshold",
            ));
        }
        let body = AvailabilityCertificateBodyV1 {
            schema_version: 1,
            context: envelope.context.clone(),
            namespace: envelope.namespace,
            epoch: envelope.epoch,
            committee_id: envelope.committee_id,
            envelope,
            author,
            attestations,
        };
        let certificate_id =
            AvailabilityCertificateIdV1::from_hash(digest_value(CERTIFICATE_DOMAIN, &body)?);
        Ok(Self {
            body,
            certificate_id,
        })
    }

    pub const fn certificate_id(&self) -> AvailabilityCertificateIdV1 {
        self.certificate_id
    }

    pub fn envelope(&self) -> &DaBatchEnvelopeV1 {
        &self.body.envelope
    }

    pub fn author(&self) -> &DaBatchAuthorV1 {
        &self.body.author
    }

    pub fn attestations(&self) -> &[DaAttestationV1] {
        &self.body.attestations
    }

    pub fn verify(&self, committee: &DaCommitteeDescriptorV1) -> DaResultV1<()> {
        let rebuilt = Self::build(
            committee,
            self.body.envelope.clone(),
            self.body.author.clone(),
            self.body.attestations.clone(),
        )?;
        if rebuilt != *self {
            return Err(error(
                DaErrorCodeV1::IdentifierMismatch,
                "availability certificate does not round-trip exactly",
            ));
        }
        Ok(())
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaObligationV1 {
    obligation_id: DaObligationIdV1,
    batch_id: BatchIdV1,
    certificate_id: AvailabilityCertificateIdV1,
    version: u64,
    retain_until_epoch: u64,
    hold_until_height: u64,
    status: u8,
    gc_tombstone_height: Option<u64>,
}

impl DaObligationV1 {
    pub(crate) fn certificate_minimum(
        batch_id: BatchIdV1,
        certificate_id: AvailabilityCertificateIdV1,
        retain_until_epoch: u64,
    ) -> DaResultV1<Self> {
        let obligation_id = DaObligationIdV1::from_hash(digest_value(
            OBLIGATION_DOMAIN,
            &(1u16, batch_id, certificate_id, 0u16),
        )?);
        Ok(Self {
            obligation_id,
            batch_id,
            certificate_id,
            version: 0,
            retain_until_epoch,
            hold_until_height: 0,
            status: 0,
            gc_tombstone_height: None,
        })
    }

    pub const fn obligation_id(&self) -> DaObligationIdV1 {
        self.obligation_id
    }

    pub const fn status(&self) -> u8 {
        self.status
    }

    pub const fn retain_until_epoch(&self) -> u64 {
        self.retain_until_epoch
    }

    pub const fn hold_until_height(&self) -> u64 {
        self.hold_until_height
    }

    pub const fn version(&self) -> u64 {
        self.version
    }

    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub const fn certificate_id(&self) -> AvailabilityCertificateIdV1 {
        self.certificate_id
    }

    pub(crate) fn extend(
        &self,
        retain_until_epoch: u64,
        hold_until_height: u64,
    ) -> DaResultV1<Self> {
        if self.status != 0
            || retain_until_epoch < self.retain_until_epoch
            || hold_until_height < self.hold_until_height
        {
            return Err(error(
                DaErrorCodeV1::RetentionViolation,
                "retention obligations are monotonic while active",
            ));
        }
        let mut next = self.clone();
        next.version = next.version.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "obligation version overflow",
            )
        })?;
        next.retain_until_epoch = retain_until_epoch;
        next.hold_until_height = hold_until_height;
        Ok(next)
    }

    pub(crate) fn release(&self, current_epoch: u64, finalized_height: u64) -> DaResultV1<Self> {
        if self.status != 0
            || current_epoch <= self.retain_until_epoch
            || finalized_height <= self.hold_until_height
        {
            return Err(error(
                DaErrorCodeV1::RetentionViolation,
                "obligation cannot release before both retention bounds expire",
            ));
        }
        let mut next = self.clone();
        next.version = next.version.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "obligation version overflow",
            )
        })?;
        next.status = 1;
        Ok(next)
    }

    pub(crate) fn garbage_collected(&self, finalized_height: u64) -> DaResultV1<Self> {
        if self.status != 1 || self.gc_tombstone_height.is_some() {
            return Err(error(
                DaErrorCodeV1::EarlyGarbageCollection,
                "only a released obligation can receive a GC tombstone",
            ));
        }
        let mut next = self.clone();
        next.version = next.version.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "obligation version overflow",
            )
        })?;
        next.status = 2;
        next.gc_tombstone_height = Some(finalized_height);
        Ok(next)
    }

    pub(crate) fn canonical_bytes(&self) -> DaResultV1<Vec<u8>> {
        canonical_bytes(self)
    }

    pub(crate) fn validate(&self) -> DaResultV1<()> {
        let expected = DaObligationIdV1::from_hash(digest_value(
            OBLIGATION_DOMAIN,
            &(1u16, self.batch_id, self.certificate_id, 0u16),
        )?);
        if self.obligation_id != expected
            || self.retain_until_epoch == 0
            || self.status > 2
            || self.version < u64::from(self.status)
            || (self.status < 2 && self.gc_tombstone_height.is_some())
            || (self.status == 2 && self.gc_tombstone_height.is_none_or(|height| height == 0))
        {
            return Err(error(
                DaErrorCodeV1::TamperDetected,
                "retention obligation ID/status is invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct AttestorEquivocationEvidenceV1 {
    schema_version: u16,
    left: DaAttestationV1,
    right: DaAttestationV1,
    evidence_id: WithholdingEvidenceIdV1,
}

impl AttestorEquivocationEvidenceV1 {
    pub fn new(
        committee: &DaCommitteeDescriptorV1,
        left: DaAttestationV1,
        right: DaAttestationV1,
    ) -> DaResultV1<Self> {
        left.verify(committee)?;
        right.verify(committee)?;
        if left.body.conflict_coordinate()? != right.body.conflict_coordinate()?
            || left.body.batch_id == right.body.batch_id
            || left.attestation_id == right.attestation_id
        {
            return Err(error(
                DaErrorCodeV1::InvalidWithholdingEvidence,
                "attestations are not a signed conflict on one coordinate",
            ));
        }
        let (left, right) = if left.attestation_id <= right.attestation_id {
            (left, right)
        } else {
            (right, left)
        };
        let mut evidence = Self {
            schema_version: 1,
            left,
            right,
            evidence_id: WithholdingEvidenceIdV1::from_hash(Hash32V1::default()),
        };
        evidence.evidence_id = WithholdingEvidenceIdV1::from_hash(digest_value(
            WITHHOLDING_DOMAIN,
            &(
                evidence.schema_version,
                evidence.left.clone(),
                evidence.right.clone(),
            ),
        )?);
        Ok(evidence)
    }

    pub const fn evidence_id(&self) -> WithholdingEvidenceIdV1 {
        self.evidence_id
    }

    /// Recompute the canonical evidence ID and both signed statements before
    /// accepting a decoded/transported evidence object.  Construction alone
    /// is not sufficient because callers may receive a Borsh value from an
    /// untrusted source after the original constructor has run.
    pub fn verify(&self, committee: &DaCommitteeDescriptorV1) -> DaResultV1<()> {
        let rebuilt = Self::new(committee, self.left.clone(), self.right.clone())?;
        if rebuilt != *self {
            return Err(error(
                DaErrorCodeV1::InvalidWithholdingEvidence,
                "equivocation evidence ID or ordering does not recompute",
            ));
        }
        Ok(())
    }
}

pub(crate) fn verify_strict(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> DaResultV1<()> {
    let key = VerifyingKey::from_bytes(public_key).map_err(|_| {
        error(
            DaErrorCodeV1::InvalidSignature,
            "invalid Ed25519 public key",
        )
    })?;
    if key.is_weak() {
        return Err(error(
            DaErrorCodeV1::InvalidSignature,
            "weak Ed25519 public key",
        ));
    }
    let signature = Signature::from_slice(signature).map_err(|_| {
        error(
            DaErrorCodeV1::InvalidSignature,
            "invalid Ed25519 signature length",
        )
    })?;
    key.verify_strict(message, &signature).map_err(|_| {
        error(
            DaErrorCodeV1::InvalidSignature,
            "strict Ed25519 verification failed",
        )
    })
}

pub(crate) fn merkle_root(domain: &str, mut leaves: Vec<Hash32V1>) -> DaResultV1<Hash32V1> {
    if leaves.is_empty() {
        return Err(error(
            DaErrorCodeV1::InvalidBounds,
            "candidate DA root cannot be empty",
        ));
    }
    let count = u32::try_from(leaves.len()).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "Merkle leaf count exceeds u32",
        )
    })?;
    let mut level = 0u32;
    while leaves.len() > 1 {
        let mut parents = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            parents.push(digest_value(
                MERKLE_PARENT_DOMAIN,
                &(domain.to_string(), level, left, right),
            )?);
        }
        leaves = parents;
        level = level
            .checked_add(1)
            .ok_or_else(|| error(DaErrorCodeV1::ArithmeticOverflow, "Merkle level overflow"))?;
    }
    digest_value(MERKLE_ROOT_DOMAIN, &(domain.to_string(), count, leaves[0]))
}
