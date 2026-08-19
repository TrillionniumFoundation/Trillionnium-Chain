//! Signed full-range retrieval proof and exact-repair candidate.
//!
//! This module intentionally implements only the full certified chunk range.
//! Each returned chunk carries a canonical inclusion path to that certificate.
//! It is a transport-independent verifier/repair primitive, not a network
//! service, requester registry, withholding adjudicator, or normative CEV1
//! proof implementation.

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::VerifyingKey;

use crate::{
    codec::{digest_value, strict_decode},
    error::{error, DaErrorCodeV1, DaResultV1},
    types::{
        merkle_root, verify_strict, AvailabilityCertificateV1, BatchIdV1, DaBatchAuthorV1,
        DaChunkCoordinateV1, DaChunkV1, DaCommitteeDescriptorV1, DaMemberV1, DaPolicyV1, Hash32V1,
        ProtocolContextV1, UnsignedTransactionBatchV1, CHUNK_LEAF_DOMAIN, MERKLE_PARENT_DOMAIN,
        MERKLE_ROOT_DOMAIN, STRICT_ED25519_SCHEME_V1,
    },
    AvailabilityCertificateIdV1,
};

const REQUEST_ID_DOMAIN_V1: &str = "trnm.poco-ai.retrieval-request.candidate.v1";
const REQUEST_SIGNATURE_DOMAIN_V1: &str = "trnm.poco-ai.retrieval-request-signature.candidate.v1";
const RECEIPT_ID_DOMAIN_V1: &str = "trnm.poco-ai.retrieval-receipt.candidate.v1";
const RECEIPT_SIGNATURE_DOMAIN_V1: &str = "trnm.poco-ai.retrieval-receipt-signature.candidate.v1";
const RETURNED_CHUNK_LEAF_DOMAIN_V1: &str = "trnm.poco-ai.returned-chunk-leaf.candidate.v1";
const MAX_ID_BYTES_V1: usize = 256;

/// Out-of-band requester trust pin for this bounded candidate.
///
/// A later Node/epoch registry must authenticate this same identity/key. This
/// local pin is deliberately not represented as consensus state authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetrievalRequesterAuthorityV1 {
    requester_id: Vec<u8>,
    public_key: [u8; 32],
    max_chunk_count: u32,
    max_response_bytes: u64,
    max_window_blocks: u64,
}

impl RetrievalRequesterAuthorityV1 {
    pub fn new(
        requester_id: Vec<u8>,
        public_key: [u8; 32],
        max_chunk_count: u32,
        max_response_bytes: u64,
        max_window_blocks: u64,
    ) -> DaResultV1<Self> {
        if requester_id.is_empty()
            || requester_id.len() > MAX_ID_BYTES_V1
            || max_chunk_count == 0
            || max_response_bytes == 0
            || max_window_blocks == 0
        {
            return Err(error(
                DaErrorCodeV1::InvalidBounds,
                "retrieval requester authority bounds are invalid",
            ));
        }
        let key = VerifyingKey::from_bytes(&public_key).map_err(|_| {
            error(
                DaErrorCodeV1::InvalidSignature,
                "retrieval requester key is invalid",
            )
        })?;
        if key.is_weak() {
            return Err(error(
                DaErrorCodeV1::InvalidSignature,
                "retrieval requester key is weak",
            ));
        }
        Ok(Self {
            requester_id,
            public_key,
            max_chunk_count,
            max_response_bytes,
            max_window_blocks,
        })
    }

    pub fn requester_id(&self) -> &[u8] {
        &self.requester_id
    }

    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RetrievalRequestBodyV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    requester_id: Vec<u8>,
    certificate_id: AvailabilityCertificateIdV1,
    batch_id: BatchIdV1,
    first_chunk_index: u32,
    chunk_count: u32,
    request_nonce: Hash32V1,
    request_height: u64,
    request_expiry_height: u64,
}

impl RetrievalRequestBodyV1 {
    pub fn new_full_range(
        certificate: &AvailabilityCertificateV1,
        requester_id: Vec<u8>,
        request_nonce: Hash32V1,
        request_height: u64,
        request_expiry_height: u64,
        policy: &DaPolicyV1,
    ) -> DaResultV1<Self> {
        let window = request_expiry_height
            .checked_sub(request_height)
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidRange,
                    "retrieval request expiry precedes request height",
                )
            })?;
        if requester_id.is_empty()
            || requester_id.len() > MAX_ID_BYTES_V1
            || request_nonce == Hash32V1::new([0; 32])
            || certificate.envelope().chunk_count() == 0
            || window > policy.retrieval_window_blocks()
        {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "full-range retrieval request is invalid",
            ));
        }
        Ok(Self {
            schema_version: 1,
            context: certificate.envelope().context().clone(),
            requester_id,
            certificate_id: certificate.certificate_id(),
            batch_id: certificate.envelope().batch_id()?,
            first_chunk_index: 0,
            chunk_count: certificate.envelope().chunk_count(),
            request_nonce,
            request_height,
            request_expiry_height,
        })
    }

    pub fn requester_id(&self) -> &[u8] {
        &self.requester_id
    }

    pub const fn certificate_id(&self) -> AvailabilityCertificateIdV1 {
        self.certificate_id
    }

    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch_id
    }

    pub const fn first_chunk_index(&self) -> u32 {
        self.first_chunk_index
    }

    pub const fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    pub const fn request_height(&self) -> u64 {
        self.request_height
    }

    pub const fn request_expiry_height(&self) -> u64 {
        self.request_expiry_height
    }

    pub fn signing_root(&self) -> DaResultV1<Hash32V1> {
        digest_value(REQUEST_SIGNATURE_DOMAIN_V1, self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RetrievalRequestV1 {
    body: RetrievalRequestBodyV1,
    request_id: Hash32V1,
    requester_key_scheme: u16,
    requester_public_key: [u8; 32],
    signature: Vec<u8>,
}

impl RetrievalRequestV1 {
    pub fn from_signature(
        body: RetrievalRequestBodyV1,
        authority: &RetrievalRequesterAuthorityV1,
        signature: Vec<u8>,
    ) -> DaResultV1<Self> {
        let request = Self {
            request_id: digest_value(REQUEST_ID_DOMAIN_V1, &body)?,
            body,
            requester_key_scheme: STRICT_ED25519_SCHEME_V1,
            requester_public_key: authority.public_key,
            signature,
        };
        request.verify(authority)?;
        Ok(request)
    }

    pub fn body(&self) -> &RetrievalRequestBodyV1 {
        &self.body
    }

    pub const fn request_id(&self) -> Hash32V1 {
        self.request_id
    }

    fn verify(&self, authority: &RetrievalRequesterAuthorityV1) -> DaResultV1<()> {
        if self.body.schema_version != 1
            || self.body.requester_id != authority.requester_id
            || self.requester_key_scheme != STRICT_ED25519_SCHEME_V1
            || self.requester_public_key != authority.public_key
            || self.request_id != digest_value(REQUEST_ID_DOMAIN_V1, &self.body)?
            || self.body.chunk_count == 0
            || self.body.chunk_count > authority.max_chunk_count
            || self.body.request_nonce == Hash32V1::new([0; 32])
        {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval request binding is invalid",
            ));
        }
        let window = self
            .body
            .request_expiry_height
            .checked_sub(self.body.request_height)
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::InvalidRange,
                    "retrieval request expiry precedes request height",
                )
            })?;
        if window > authority.max_window_blocks {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval request exceeds requester window",
            ));
        }
        verify_strict(
            &self.requester_public_key,
            self.body.signing_root()?.as_bytes(),
            &self.signature,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct MerkleStepV1 {
    level: u32,
    sibling_side: u8,
    sibling_hash: Hash32V1,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct DaChunkInclusionProofV1 {
    global_chunk_index: u32,
    chunk_item_count: u32,
    merkle_path: Vec<MerkleStepV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ReturnedChunkEntryV1 {
    chunk_index: u32,
    coordinate: DaChunkCoordinateV1,
    chunk_bytes: Vec<u8>,
    inclusion_proof: DaChunkInclusionProofV1,
}

impl ReturnedChunkEntryV1 {
    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    pub fn chunk_bytes(&self) -> &[u8] {
        &self.chunk_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RetrievalReceiptBodyV1 {
    schema_version: u16,
    context: ProtocolContextV1,
    request_id: Hash32V1,
    requester_id: Vec<u8>,
    responder_id: Vec<u8>,
    certificate_id: AvailabilityCertificateIdV1,
    batch_id: BatchIdV1,
    first_chunk_index: u32,
    chunk_count: u32,
    returned_chunks_root: Hash32V1,
    response_height: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RetrievalResponseV1 {
    body: RetrievalReceiptBodyV1,
    receipt_id: Hash32V1,
    returned_chunks: Vec<ReturnedChunkEntryV1>,
    responder_key_scheme: u16,
    responder_public_key: [u8; 32],
    signature: Vec<u8>,
}

impl RetrievalResponseV1 {
    pub fn body(&self) -> &RetrievalReceiptBodyV1 {
        &self.body
    }

    pub const fn receipt_id(&self) -> Hash32V1 {
        self.receipt_id
    }

    pub fn returned_chunks(&self) -> &[ReturnedChunkEntryV1] {
        &self.returned_chunks
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_chunk_for_test(&mut self) {
        self.returned_chunks[0].chunk_bytes[0] ^= 1;
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_merkle_step_for_test(&mut self) {
        self.returned_chunks[0].inclusion_proof.merkle_path[0].sibling_side ^= 1;
    }
}

/// Readback-bound response preimage. It is refreshed from the local certified
/// bytes before `PocoDaStoreV1` can release the signed response.
#[derive(Debug)]
pub struct RetrievalResponseIntentV1 {
    pub(crate) scope_id: Hash32V1,
    pub(crate) store_id: Hash32V1,
    pub(crate) config_hash: Hash32V1,
    pub(crate) request: RetrievalRequestV1,
    pub(crate) requester_authority: RetrievalRequesterAuthorityV1,
    pub(crate) body: RetrievalReceiptBodyV1,
    pub(crate) receipt_id: Hash32V1,
    pub(crate) returned_chunks: Vec<ReturnedChunkEntryV1>,
    pub(crate) responder_public_key: [u8; 32],
}

impl RetrievalResponseIntentV1 {
    pub fn signing_root(&self) -> DaResultV1<Hash32V1> {
        digest_value(RECEIPT_SIGNATURE_DOMAIN_V1, &self.receipt_id)
    }

    pub const fn receipt_id(&self) -> Hash32V1 {
        self.receipt_id
    }

    pub(crate) const fn response_height(&self) -> u64 {
        self.body.response_height
    }

    pub(crate) fn exact_payload_eq(&self, other: &Self) -> bool {
        self.scope_id == other.scope_id
            && self.store_id == other.store_id
            && self.config_hash == other.config_hash
            && self.request == other.request
            && self.requester_authority == other.requester_authority
            && self.body == other.body
            && self.receipt_id == other.receipt_id
            && self.returned_chunks == other.returned_chunks
            && self.responder_public_key == other.responder_public_key
    }
}

#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct RetrievalProofV1 {
    request: RetrievalRequestV1,
    response: RetrievalResponseV1,
    certificate: AvailabilityCertificateV1,
    policy: DaPolicyV1,
}

impl RetrievalProofV1 {
    pub fn new(
        request: RetrievalRequestV1,
        response: RetrievalResponseV1,
        certificate: AvailabilityCertificateV1,
        policy: DaPolicyV1,
    ) -> Self {
        Self {
            request,
            response,
            certificate,
            policy,
        }
    }

    pub fn request(&self) -> &RetrievalRequestV1 {
        &self.request
    }

    pub fn response(&self) -> &RetrievalResponseV1 {
        &self.response
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_chunk_for_test(&mut self) {
        self.response.corrupt_first_chunk_for_test();
    }

    #[cfg(test)]
    pub(crate) fn corrupt_first_merkle_step_for_test(&mut self) {
        self.response.corrupt_first_merkle_step_for_test();
    }
}

/// Exact full-range proof verified against one store's immutable config.
///
/// The fields are private and the carrier is neither `Clone` nor `Copy`.
#[derive(Debug)]
pub struct VerifiedRetrievalProofV1 {
    pub(crate) scope_id: Hash32V1,
    pub(crate) store_id: Hash32V1,
    pub(crate) config_hash: Hash32V1,
    pub(crate) request_id: Hash32V1,
    pub(crate) receipt_id: Hash32V1,
    pub(crate) certificate_id: AvailabilityCertificateIdV1,
    pub(crate) verified_at_height: u64,
    pub(crate) fresh_until_height: u64,
    pub(crate) batch: UnsignedTransactionBatchV1,
    pub(crate) author: DaBatchAuthorV1,
}

impl VerifiedRetrievalProofV1 {
    pub const fn request_id(&self) -> Hash32V1 {
        self.request_id
    }

    pub const fn receipt_id(&self) -> Hash32V1 {
        self.receipt_id
    }

    pub const fn certificate_id(&self) -> AvailabilityCertificateIdV1 {
        self.certificate_id
    }

    pub const fn verified_at_height(&self) -> u64 {
        self.verified_at_height
    }

    pub const fn fresh_until_height(&self) -> u64 {
        self.fresh_until_height
    }

    pub const fn batch_id(&self) -> BatchIdV1 {
        self.batch.batch_id()
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_full_range_response_v1(
    scope_id: Hash32V1,
    store_id: Hash32V1,
    config_hash: Hash32V1,
    request: &RetrievalRequestV1,
    requester_authority: &RetrievalRequesterAuthorityV1,
    response_height: u64,
    batch: &UnsignedTransactionBatchV1,
    certificate: &AvailabilityCertificateV1,
    responder: &DaMemberV1,
) -> DaResultV1<RetrievalResponseIntentV1> {
    request.verify(requester_authority)?;
    if request.body.context != *certificate.envelope().context()
        || request.body.certificate_id != certificate.certificate_id()
        || request.body.batch_id != batch.batch_id()
        || request.body.batch_id != certificate.envelope().batch_id()?
        || request.body.first_chunk_index != 0
        || request.body.chunk_count != certificate.envelope().chunk_count()
        || request.body.chunk_count
            != u32::try_from(batch.chunks().len()).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval chunk count exceeds u32",
                )
            })?
        || response_height < request.body.request_height
        || response_height > request.body.request_expiry_height
    {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "retrieval response does not cover the exact certified range",
        ));
    }
    let total_bytes = batch.chunks().iter().try_fold(0u64, |sum, chunk| {
        sum.checked_add(u64::try_from(chunk.bytes().len()).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "retrieval chunk bytes exceed u64",
            )
        })?)
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "retrieval response byte total overflows",
            )
        })
    })?;
    if total_bytes > requester_authority.max_response_bytes {
        return Err(error(
            DaErrorCodeV1::InvalidBounds,
            "retrieval response exceeds requester byte bound",
        ));
    }
    let leaves = batch
        .chunks()
        .iter()
        .map(chunk_leaf_v1)
        .collect::<DaResultV1<Vec<_>>>()?;
    let returned_chunks = batch
        .chunks()
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            let index = u32::try_from(index).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval chunk index exceeds u32",
                )
            })?;
            Ok(ReturnedChunkEntryV1 {
                chunk_index: index,
                coordinate: chunk.coordinate().clone(),
                chunk_bytes: chunk.bytes().to_vec(),
                inclusion_proof: DaChunkInclusionProofV1 {
                    global_chunk_index: index,
                    chunk_item_count: request.body.chunk_count,
                    merkle_path: merkle_path_v1(&leaves, index)?,
                },
            })
        })
        .collect::<DaResultV1<Vec<_>>>()?;
    let returned_chunks_root = returned_chunks_root_v1(&returned_chunks)?;
    let body = RetrievalReceiptBodyV1 {
        schema_version: 1,
        context: request.body.context.clone(),
        request_id: request.request_id,
        requester_id: request.body.requester_id.clone(),
        responder_id: responder.definition_hash().as_bytes().to_vec(),
        certificate_id: request.body.certificate_id,
        batch_id: request.body.batch_id,
        first_chunk_index: 0,
        chunk_count: request.body.chunk_count,
        returned_chunks_root,
        response_height,
    };
    let receipt_id = digest_value(RECEIPT_ID_DOMAIN_V1, &body)?;
    Ok(RetrievalResponseIntentV1 {
        scope_id,
        store_id,
        config_hash,
        request: request.clone(),
        requester_authority: requester_authority.clone(),
        body,
        receipt_id,
        returned_chunks,
        responder_public_key: *responder.public_key(),
    })
}

pub(crate) fn complete_response_v1(
    intent: RetrievalResponseIntentV1,
    signature: Vec<u8>,
) -> DaResultV1<RetrievalResponseV1> {
    verify_strict(
        &intent.responder_public_key,
        intent.signing_root()?.as_bytes(),
        &signature,
    )?;
    Ok(RetrievalResponseV1 {
        body: intent.body,
        receipt_id: intent.receipt_id,
        returned_chunks: intent.returned_chunks,
        responder_key_scheme: STRICT_ED25519_SCHEME_V1,
        responder_public_key: intent.responder_public_key,
        signature,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn verify_full_range_proof_v1(
    proof: &RetrievalProofV1,
    committee: &DaCommitteeDescriptorV1,
    policy: &DaPolicyV1,
    requester_authority: &RetrievalRequesterAuthorityV1,
    validation_height: u64,
    scope_id: Hash32V1,
    store_id: Hash32V1,
    config_hash: Hash32V1,
) -> DaResultV1<VerifiedRetrievalProofV1> {
    committee.validate()?;
    policy.validate(committee)?;
    proof.certificate.verify(committee)?;
    proof.request.verify(requester_authority)?;
    let committed_author = policy
        .authority(proof.certificate.envelope().author_id())
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::UnauthorizedAuthor,
                "retrieval certificate author is absent from the committed policy",
            )
        })?;
    if committed_author.public_key() != proof.certificate.author().public_key() {
        return Err(error(
            DaErrorCodeV1::UnauthorizedAuthor,
            "retrieval certificate author key differs from committed policy",
        ));
    }
    if proof.policy != *policy
        || proof.request.body.context != *proof.certificate.envelope().context()
        || proof.request.body.certificate_id != proof.certificate.certificate_id()
        || proof.request.body.batch_id != proof.certificate.envelope().batch_id()?
        || proof.request.body.first_chunk_index != 0
        || proof.request.body.chunk_count != proof.certificate.envelope().chunk_count()
        || proof.request.body.chunk_count > requester_authority.max_chunk_count
    {
        return Err(error(
            DaErrorCodeV1::InvalidContext,
            "retrieval proof request/certificate/policy binding differs",
        ));
    }
    let policy_window = proof
        .request
        .body
        .request_expiry_height
        .checked_sub(proof.request.body.request_height)
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::InvalidRange,
                "retrieval proof request window underflows",
            )
        })?;
    if policy_window > policy.retrieval_window_blocks() {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "retrieval proof exceeds committed policy window",
        ));
    }
    verify_response_v1(
        &proof.response,
        &proof.request,
        &proof.certificate,
        committee,
        requester_authority,
    )?;
    let fresh_until_height = proof.request.body.request_expiry_height.min(
        proof
            .response
            .body
            .response_height
            .checked_add(policy.repair_window_blocks())
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval freshness height overflows",
                )
            })?,
    );
    if validation_height < proof.response.body.response_height
        || validation_height > fresh_until_height
    {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "retrieval proof is future-dated or stale at validation height",
        ));
    }
    let content_bytes = proof
        .response
        .returned_chunks
        .iter()
        .flat_map(|entry| entry.chunk_bytes.iter().copied())
        .collect::<Vec<_>>();
    let content_length = u64::try_from(content_bytes.len()).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "retrieved content length exceeds u64",
        )
    })?;
    if content_length != proof.certificate.envelope().uncompressed_bytes()
        || content_length > requester_authority.max_response_bytes
    {
        return Err(error(
            DaErrorCodeV1::InvalidBounds,
            "retrieval proof content length differs from certificate",
        ));
    }
    let transactions: Vec<Vec<u8>> = strict_decode(&content_bytes)?;
    let batch = UnsignedTransactionBatchV1::build(
        committee,
        policy,
        proof.certificate.envelope().author_id().to_vec(),
        proof.certificate.envelope().author_sequence(),
        transactions,
    )?;
    if batch.envelope() != proof.certificate.envelope()
        || batch.batch_id() != proof.request.body.batch_id
        || batch.chunks().len() != proof.response.returned_chunks.len()
    {
        return Err(error(
            DaErrorCodeV1::IdentifierMismatch,
            "retrieval proof does not reconstruct the certified batch",
        ));
    }
    for (chunk, entry) in batch.chunks().iter().zip(&proof.response.returned_chunks) {
        if chunk.index() != entry.chunk_index
            || chunk.coordinate() != &entry.coordinate
            || chunk.bytes() != entry.chunk_bytes.as_slice()
        {
            return Err(error(
                DaErrorCodeV1::IdentifierMismatch,
                "retrieval proof chunk differs from reconstructed batch",
            ));
        }
    }
    Ok(VerifiedRetrievalProofV1 {
        scope_id,
        store_id,
        config_hash,
        request_id: proof.request.request_id,
        receipt_id: proof.response.receipt_id,
        certificate_id: proof.certificate.certificate_id(),
        verified_at_height: validation_height,
        fresh_until_height,
        batch,
        author: proof.certificate.author().clone(),
    })
}

fn verify_response_v1(
    response: &RetrievalResponseV1,
    request: &RetrievalRequestV1,
    certificate: &AvailabilityCertificateV1,
    committee: &DaCommitteeDescriptorV1,
    requester_authority: &RetrievalRequesterAuthorityV1,
) -> DaResultV1<()> {
    let responder_hash: [u8; 32] =
        response
            .body
            .responder_id
            .as_slice()
            .try_into()
            .map_err(|_| {
                error(
                    DaErrorCodeV1::InvalidCommittee,
                    "retrieval responder ID is not a member hash",
                )
            })?;
    let responder = committee
        .member(Hash32V1::new(responder_hash))
        .ok_or_else(|| {
            error(
                DaErrorCodeV1::InvalidCommittee,
                "retrieval responder is not an active committee member",
            )
        })?;
    if response.body.schema_version != 1
        || response.body.context != request.body.context
        || response.body.request_id != request.request_id
        || response.body.requester_id != request.body.requester_id
        || response.body.certificate_id != request.body.certificate_id
        || response.body.batch_id != request.body.batch_id
        || response.body.first_chunk_index != request.body.first_chunk_index
        || response.body.chunk_count != request.body.chunk_count
        || response.body.response_height < request.body.request_height
        || response.body.response_height > request.body.request_expiry_height
        || response.body.certificate_id != certificate.certificate_id()
        || response.responder_key_scheme != STRICT_ED25519_SCHEME_V1
        || response.responder_public_key != *responder.public_key()
        || response.receipt_id != digest_value(RECEIPT_ID_DOMAIN_V1, &response.body)?
        || response.returned_chunks.len()
            != usize::try_from(request.body.chunk_count).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval request count exceeds usize",
                )
            })?
        || response.body.returned_chunks_root != returned_chunks_root_v1(&response.returned_chunks)?
    {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "retrieval response does not exactly echo the request",
        ));
    }
    let total_bytes = response
        .returned_chunks
        .iter()
        .try_fold(0u64, |sum, entry| {
            sum.checked_add(u64::try_from(entry.chunk_bytes.len()).map_err(|_| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval entry bytes exceed u64",
                )
            })?)
            .ok_or_else(|| {
                error(
                    DaErrorCodeV1::ArithmeticOverflow,
                    "retrieval response bytes overflow",
                )
            })
        })?;
    if total_bytes > requester_authority.max_response_bytes {
        return Err(error(
            DaErrorCodeV1::InvalidBounds,
            "retrieval response exceeds requester byte bound",
        ));
    }
    for (index, entry) in response.returned_chunks.iter().enumerate() {
        let index = u32::try_from(index).map_err(|_| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "retrieval entry index exceeds u32",
            )
        })?;
        if entry.chunk_index != index
            || entry.inclusion_proof.global_chunk_index != index
            || entry.inclusion_proof.chunk_item_count != request.body.chunk_count
        {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval entries are not gap-free over the full range",
            ));
        }
        let chunk = DaChunkV1::new(entry.coordinate.clone(), entry.chunk_bytes.clone())?;
        if chunk.index() != index {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "retrieval chunk coordinate index differs",
            ));
        }
        verify_merkle_path_v1(
            chunk_leaf_v1(&chunk)?,
            &entry.inclusion_proof,
            certificate.envelope().chunk_root(),
        )?;
    }
    verify_strict(
        &response.responder_public_key,
        digest_value(RECEIPT_SIGNATURE_DOMAIN_V1, &response.receipt_id)?.as_bytes(),
        &response.signature,
    )
}

fn chunk_leaf_v1(chunk: &DaChunkV1) -> DaResultV1<Hash32V1> {
    digest_value(
        CHUNK_LEAF_DOMAIN,
        &(chunk.index(), chunk.chunk_id(), chunk.bytes_digest()),
    )
}

fn returned_chunks_root_v1(entries: &[ReturnedChunkEntryV1]) -> DaResultV1<Hash32V1> {
    let leaves = entries
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            let chunk = DaChunkV1::new(entry.coordinate.clone(), entry.chunk_bytes.clone())?;
            digest_value(
                RETURNED_CHUNK_LEAF_DOMAIN_V1,
                &(
                    u32::try_from(index).map_err(|_| {
                        error(
                            DaErrorCodeV1::ArithmeticOverflow,
                            "returned chunk index exceeds u32",
                        )
                    })?,
                    chunk.chunk_id(),
                    chunk.bytes_digest(),
                ),
            )
        })
        .collect::<DaResultV1<Vec<_>>>()?;
    merkle_root(RETURNED_CHUNK_LEAF_DOMAIN_V1, leaves)
}

fn merkle_path_v1(leaves: &[Hash32V1], index: u32) -> DaResultV1<Vec<MerkleStepV1>> {
    let mut position = usize::try_from(index).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "Merkle index exceeds usize",
        )
    })?;
    if leaves.is_empty() || position >= leaves.len() {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "Merkle proof index is out of bounds",
        ));
    }
    let mut level_hashes = leaves.to_vec();
    let mut level = 0u32;
    let mut path = Vec::new();
    while level_hashes.len() > 1 {
        let (sibling_index, sibling_side) = if position % 2 == 0 {
            (
                if position + 1 < level_hashes.len() {
                    position + 1
                } else {
                    position
                },
                1,
            )
        } else {
            (position - 1, 0)
        };
        path.push(MerkleStepV1 {
            level,
            sibling_side,
            sibling_hash: level_hashes[sibling_index],
        });
        let mut parents = Vec::with_capacity(level_hashes.len().div_ceil(2));
        for pair in level_hashes.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            parents.push(digest_value(
                MERKLE_PARENT_DOMAIN,
                &(CHUNK_LEAF_DOMAIN.to_string(), level, left, right),
            )?);
        }
        level_hashes = parents;
        position /= 2;
        level = level.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "Merkle path level overflows",
            )
        })?;
    }
    Ok(path)
}

fn verify_merkle_path_v1(
    mut running: Hash32V1,
    proof: &DaChunkInclusionProofV1,
    expected_root: Hash32V1,
) -> DaResultV1<()> {
    if proof.chunk_item_count == 0 || proof.global_chunk_index >= proof.chunk_item_count {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "chunk proof coordinate is out of bounds",
        ));
    }
    let mut width = usize::try_from(proof.chunk_item_count).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "chunk proof count exceeds usize",
        )
    })?;
    let mut position = usize::try_from(proof.global_chunk_index).map_err(|_| {
        error(
            DaErrorCodeV1::ArithmeticOverflow,
            "chunk proof index exceeds usize",
        )
    })?;
    let mut step_index = 0usize;
    let mut level = 0u32;
    while width > 1 {
        let step = proof
            .merkle_path
            .get(step_index)
            .ok_or_else(|| error(DaErrorCodeV1::InvalidRange, "chunk proof path is truncated"))?;
        let expected_side = if position % 2 == 0 { 1 } else { 0 };
        if step.level != level || step.sibling_side != expected_side {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "chunk proof level/side is non-canonical",
            ));
        }
        if position % 2 == 0 && position + 1 == width && step.sibling_hash != running {
            return Err(error(
                DaErrorCodeV1::InvalidRange,
                "chunk proof violates duplicate-final rule",
            ));
        }
        let (left, right) = if step.sibling_side == 0 {
            (step.sibling_hash, running)
        } else {
            (running, step.sibling_hash)
        };
        running = digest_value(
            MERKLE_PARENT_DOMAIN,
            &(CHUNK_LEAF_DOMAIN.to_string(), level, left, right),
        )?;
        width = width.div_ceil(2);
        position /= 2;
        step_index += 1;
        level = level.checked_add(1).ok_or_else(|| {
            error(
                DaErrorCodeV1::ArithmeticOverflow,
                "chunk proof verification level overflows",
            )
        })?;
    }
    if step_index != proof.merkle_path.len() {
        return Err(error(
            DaErrorCodeV1::InvalidRange,
            "chunk proof path has trailing steps",
        ));
    }
    let root = digest_value(
        MERKLE_ROOT_DOMAIN,
        &(
            CHUNK_LEAF_DOMAIN.to_string(),
            proof.chunk_item_count,
            running,
        ),
    )?;
    if root != expected_root {
        return Err(error(
            DaErrorCodeV1::IdentifierMismatch,
            "chunk proof root differs from certified envelope",
        ));
    }
    Ok(())
}
