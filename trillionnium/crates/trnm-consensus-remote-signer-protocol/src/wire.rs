use alloc::vec::Vec;
use core::fmt;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    decode_canonical_sign_intent_v0_exact, ChainId, Epoch, GenesisHash, ProtocolVersion,
    SignatureBytes, ValidatorId, ValidatorSet, ValidatorSetId,
    MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES, MAX_CONSENSUS_STRING_BYTES, MAX_VALIDATOR_ID_BYTES,
};

use crate::{
    vote_timeout_purpose_profile_digest_v1, ProcessGenerationV1, RemoteConsensusCommandKindV1,
    RemoteConsensusCommandV1, RemoteConsensusCommandValidationErrorV1,
    RemoteSignerCheckpointWitnessV1, RemoteSignerClientProfileRefV1, RemoteSignerIdErrorV1,
    RemoteSignerLeaseIdV1, RemoteSignerPurposeProfileDigestV1, RemoteSignerRequestFingerprintV1,
    RemoteSignerRequestNonceV1, RemoteSignerResponseFingerprintV1, RemoteSignerRoleProfileRefV1,
    RemoteSignerServiceProfileRefV1,
};

const REQUEST_MAGIC_V1: &[u8; 8] = b"TRNMRQ01";
const RESPONSE_MAGIC_V1: &[u8; 8] = b"TRNMRS01";
const CONSENSUS_ROLE_TAG_V1: u8 = 1;
const UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1: u8 = 0;
const REQUEST_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.request-fingerprint.v1\0";
const RESPONSE_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.response-fingerprint.v1\0";

pub const REMOTE_SIGNER_REQUEST_SCHEMA_V1: u16 = 1;
pub const REMOTE_SIGNER_RESPONSE_SCHEMA_V1: u16 = 1;

const MAX_BINDING_BYTES_V1: usize =
    // Purpose profile, role/service/client profiles, generation, lease,
    // checkpoint generation/checksum/witness digest, and nonce.
    (32 * 4) + 8 + 32 + 8 + 32 + 32 + 32
    // Chain, protocol, epoch, set ID, and author.
    + 32 + 2 + MAX_CONSENSUS_STRING_BYTES + 4 + 8 + 32 + 2 + MAX_VALIDATOR_ID_BYTES;

pub const MAX_REMOTE_SIGNER_REQUEST_BYTES_V1: usize = REQUEST_MAGIC_V1.len()
    + 2
    + 1
    + 1
    + 1
    + MAX_BINDING_BYTES_V1
    + 4
    + MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES
    + 32;

pub const MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1: usize =
    RESPONSE_MAGIC_V1.len() + 2 + 1 + 1 + 1 + 1 + MAX_BINDING_BYTES_V1 + 32 + 64 + 32;

/// Expected public binding shared by both sides of one request.
///
/// The type is data-only. It neither acquires nor activates `lease_id` or
/// `process_generation`; a future service must authenticate both against an
/// independent monotonic store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteSignerRequestBindingV1 {
    purpose_profile_digest: RemoteSignerPurposeProfileDigestV1,
    role_profile_ref: RemoteSignerRoleProfileRefV1,
    service_profile_ref: RemoteSignerServiceProfileRefV1,
    client_profile_ref: RemoteSignerClientProfileRefV1,
    process_generation: ProcessGenerationV1,
    lease_id: RemoteSignerLeaseIdV1,
    checkpoint_witness: RemoteSignerCheckpointWitnessV1,
    genesis_hash: GenesisHash,
    chain_id: ChainId,
    protocol_version: ProtocolVersion,
    epoch: Epoch,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
}

impl RemoteSignerRequestBindingV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_set: &ValidatorSet,
        author: ValidatorId,
        role_profile_ref: RemoteSignerRoleProfileRefV1,
        service_profile_ref: RemoteSignerServiceProfileRefV1,
        client_profile_ref: RemoteSignerClientProfileRefV1,
        process_generation: ProcessGenerationV1,
        lease_id: RemoteSignerLeaseIdV1,
        checkpoint_witness: RemoteSignerCheckpointWitnessV1,
    ) -> Result<Self, RemoteSignerProtocolErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidValidatorSet)?;
        if validator_set.validator(author).is_none() {
            return Err(RemoteSignerProtocolErrorV1::UnknownAuthor);
        }
        Ok(Self {
            purpose_profile_digest: vote_timeout_purpose_profile_digest_v1(),
            role_profile_ref,
            service_profile_ref,
            client_profile_ref,
            process_generation,
            lease_id,
            checkpoint_witness,
            genesis_hash: validator_set.genesis_hash(),
            chain_id: validator_set.chain_id(),
            protocol_version: validator_set.protocol_version(),
            epoch: validator_set.epoch(),
            validator_set_id: validator_set.id(),
            author,
        })
    }

    pub const fn purpose_profile_digest(self) -> RemoteSignerPurposeProfileDigestV1 {
        self.purpose_profile_digest
    }

    pub const fn role_profile_ref(self) -> RemoteSignerRoleProfileRefV1 {
        self.role_profile_ref
    }

    pub const fn service_profile_ref(self) -> RemoteSignerServiceProfileRefV1 {
        self.service_profile_ref
    }

    pub const fn client_profile_ref(self) -> RemoteSignerClientProfileRefV1 {
        self.client_profile_ref
    }

    pub const fn process_generation(self) -> ProcessGenerationV1 {
        self.process_generation
    }

    pub const fn lease_id(self) -> RemoteSignerLeaseIdV1 {
        self.lease_id
    }

    pub const fn checkpoint_witness(self) -> RemoteSignerCheckpointWitnessV1 {
        self.checkpoint_witness
    }

    pub const fn chain_id(self) -> ChainId {
        self.chain_id
    }

    pub const fn genesis_hash(self) -> GenesisHash {
        self.genesis_hash
    }

    pub const fn protocol_version(self) -> ProtocolVersion {
        self.protocol_version
    }

    pub const fn epoch(self) -> Epoch {
        self.epoch
    }

    pub const fn validator_set_id(self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn author(self) -> ValidatorId {
        self.author
    }

    fn validate_against(
        self,
        validator_set: &ValidatorSet,
    ) -> Result<(), RemoteSignerProtocolErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidValidatorSet)?;
        if self.purpose_profile_digest != vote_timeout_purpose_profile_digest_v1() {
            return Err(RemoteSignerProtocolErrorV1::PurposeProfileMismatch);
        }
        if self.genesis_hash != validator_set.genesis_hash()
            || self.chain_id != validator_set.chain_id()
            || self.protocol_version != validator_set.protocol_version()
            || self.epoch != validator_set.epoch()
            || self.validator_set_id != validator_set.id()
        {
            return Err(RemoteSignerProtocolErrorV1::ValidatorSetContextMismatch);
        }
        if validator_set.validator(self.author).is_none() {
            return Err(RemoteSignerProtocolErrorV1::UnknownAuthor);
        }
        Ok(())
    }
}

/// Exact, owned, data-only remote-signer request.
///
/// Successful construction proves canonical shape and public context only. It
/// does not prove that Core persisted the intent or that SafetyRules admitted
/// the vote/timeout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerRequestV1 {
    binding: RemoteSignerRequestBindingV1,
    command: RemoteConsensusCommandV1,
    nonce: RemoteSignerRequestNonceV1,
    fingerprint: RemoteSignerRequestFingerprintV1,
}

impl RemoteSignerRequestV1 {
    pub fn new(
        command: RemoteConsensusCommandV1,
        validator_set: &ValidatorSet,
        binding: RemoteSignerRequestBindingV1,
        nonce: RemoteSignerRequestNonceV1,
    ) -> Result<Self, RemoteSignerProtocolErrorV1> {
        binding.validate_against(validator_set)?;
        // Reclassify at the request boundary as defense in depth. The command
        // is opaque, but request admission must not rely on that representation
        // detail to bind the command tag to the exact canonical preimage kind.
        let command = RemoteConsensusCommandV1::from_canonical_intent(
            command.intent().clone(),
            validator_set,
        )?;
        if command.intent().preimage().context().genesis_hash() != binding.genesis_hash
            || command.intent().chain_id() != binding.chain_id
            || command.intent().protocol_version() != binding.protocol_version
            || command.intent().epoch() != binding.epoch
            || command.intent().validator_set_id() != binding.validator_set_id
            || command.intent().author() != binding.author
        {
            return Err(RemoteSignerProtocolErrorV1::RequestBindingMismatch);
        }
        let mut value = Self {
            binding,
            command,
            nonce,
            fingerprint: RemoteSignerRequestFingerprintV1::from_exact_bytes([0; 32]),
        };
        value.fingerprint = request_fingerprint_v1(&value.try_bytes_without_fingerprint()?);
        Ok(value)
    }

    pub const fn binding(&self) -> RemoteSignerRequestBindingV1 {
        self.binding
    }

    pub const fn command(&self) -> &RemoteConsensusCommandV1 {
        &self.command
    }

    pub const fn nonce(&self) -> RemoteSignerRequestNonceV1 {
        self.nonce
    }

    pub const fn fingerprint(&self) -> RemoteSignerRequestFingerprintV1 {
        self.fingerprint
    }

    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = self.try_bytes_without_fingerprint()?;
        encoded.extend_from_slice(self.fingerprint.as_bytes());
        if encoded.len() > MAX_REMOTE_SIGNER_REQUEST_BYTES_V1 {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        Ok(encoded)
    }

    fn try_bytes_without_fingerprint(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let intent_bytes = self
            .command
            .intent()
            .canonical_bytes()
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidCanonicalIntent)?;
        if intent_bytes.len() > MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        let mut encoded = Vec::with_capacity(MAX_REMOTE_SIGNER_REQUEST_BYTES_V1);
        encoded.extend_from_slice(REQUEST_MAGIC_V1);
        encoded.extend_from_slice(&REMOTE_SIGNER_REQUEST_SCHEMA_V1.to_be_bytes());
        encoded.push(CONSENSUS_ROLE_TAG_V1);
        encoded.push(self.command.kind().tag());
        encoded.push(self.command.kind().tag());
        encode_binding_v1(&mut encoded, self.binding, self.nonce)?;
        encoded.extend_from_slice(
            &u32::try_from(intent_bytes.len())
                .map_err(|_| RemoteSignerProtocolErrorV1::LengthLimitExceeded)?
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&intent_bytes);
        Ok(encoded)
    }
}

/// Data-only response envelope containing unverified signature wire bytes.
///
/// Exact decoding validates only canonical shape and request bindings. It does
/// not perform Ed25519 verification and cannot grant journal, signer, Core, or
/// runtime authority. A later service/client boundary must verify these bytes
/// against the exact request signing root and configured consensus public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedRemoteSignerResponseV1 {
    binding: RemoteSignerRequestBindingV1,
    command_kind: RemoteConsensusCommandKindV1,
    nonce: RemoteSignerRequestNonceV1,
    request_fingerprint: RemoteSignerRequestFingerprintV1,
    signature: SignatureBytes,
    fingerprint: RemoteSignerResponseFingerprintV1,
}

impl UnverifiedRemoteSignerResponseV1 {
    /// Wraps signature wire bytes without cryptographically verifying them.
    pub fn from_unverified_signature_bytes(
        request: &RemoteSignerRequestV1,
        signature: SignatureBytes,
    ) -> Result<Self, RemoteSignerProtocolErrorV1> {
        signature
            .validate_shape()
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidSignature)?;
        if signature.as_bytes() == &[0; 64] {
            return Err(RemoteSignerProtocolErrorV1::InvalidSignature);
        }
        let mut value = Self {
            binding: request.binding,
            command_kind: request.command.kind(),
            nonce: request.nonce,
            request_fingerprint: request.fingerprint,
            signature,
            fingerprint: RemoteSignerResponseFingerprintV1::from_exact_bytes([0; 32]),
        };
        value.fingerprint = response_fingerprint_v1(&value.try_bytes_without_fingerprint()?);
        Ok(value)
    }

    pub const fn binding(&self) -> RemoteSignerRequestBindingV1 {
        self.binding
    }

    pub const fn command_kind(&self) -> RemoteConsensusCommandKindV1 {
        self.command_kind
    }

    pub const fn nonce(&self) -> RemoteSignerRequestNonceV1 {
        self.nonce
    }

    pub const fn request_fingerprint(&self) -> RemoteSignerRequestFingerprintV1 {
        self.request_fingerprint
    }

    /// Returns shape-checked, cryptographically unverified wire bytes.
    pub const fn unverified_signature_bytes(&self) -> SignatureBytes {
        self.signature
    }

    pub const fn fingerprint(&self) -> RemoteSignerResponseFingerprintV1 {
        self.fingerprint
    }

    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = self.try_bytes_without_fingerprint()?;
        encoded.extend_from_slice(self.fingerprint.as_bytes());
        if encoded.len() > MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1 {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        Ok(encoded)
    }

    fn try_bytes_without_fingerprint(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = Vec::with_capacity(MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1);
        encoded.extend_from_slice(RESPONSE_MAGIC_V1);
        encoded.extend_from_slice(&REMOTE_SIGNER_RESPONSE_SCHEMA_V1.to_be_bytes());
        encoded.push(UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1);
        encoded.push(CONSENSUS_ROLE_TAG_V1);
        encoded.push(self.command_kind.tag());
        encoded.push(self.command_kind.tag());
        encode_binding_v1(&mut encoded, self.binding, self.nonce)?;
        encoded.extend_from_slice(self.request_fingerprint.as_bytes());
        encoded.extend_from_slice(self.signature.as_bytes());
        Ok(encoded)
    }
}

/// Decodes canonical request data against an expected public binding.
///
/// Only command tags 0 (vote) and 1 (timeout vote) are admitted. Reserved
/// proposal/handoff and unknown tags are rejected before nested intent decode;
/// this crate has no storage or other effects. Success is not Core/SafetyRules
/// authorization.
pub fn decode_remote_signer_request_v1_exact(
    encoded: &[u8],
    validator_set: &ValidatorSet,
    expected_binding: RemoteSignerRequestBindingV1,
) -> Result<RemoteSignerRequestV1, RemoteSignerProtocolErrorV1> {
    if encoded.len() > MAX_REMOTE_SIGNER_REQUEST_BYTES_V1 {
        return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
    }
    expected_binding.validate_against(validator_set)?;
    let mut cursor = CursorV1::new(encoded);
    if cursor.take(REQUEST_MAGIC_V1.len())? != REQUEST_MAGIC_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidMagic);
    }
    let schema = cursor.u16()?;
    if schema != REMOTE_SIGNER_REQUEST_SCHEMA_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidSchemaVersion(schema));
    }
    if cursor.u8()? != CONSENSUS_ROLE_TAG_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidRoleTag);
    }
    let command_kind = RemoteConsensusCommandKindV1::from_tag(cursor.u8()?)?;
    let purpose_tag = cursor.u8()?;
    if purpose_tag != command_kind.tag() {
        return Err(RemoteSignerProtocolErrorV1::CommandPurposeMismatch);
    }
    let (decoded_binding, nonce) = decode_binding_v1(&mut cursor)?;
    if decoded_binding.purpose_profile_digest != vote_timeout_purpose_profile_digest_v1() {
        return Err(RemoteSignerProtocolErrorV1::PurposeProfileMismatch);
    }
    if decoded_binding != expected_binding {
        return Err(RemoteSignerProtocolErrorV1::RequestBindingMismatch);
    }
    let intent_length = usize::try_from(cursor.u32()?)
        .map_err(|_| RemoteSignerProtocolErrorV1::LengthLimitExceeded)?;
    if intent_length > MAX_CEV0_CANONICAL_SIGN_INTENT_BYTES {
        return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
    }
    let intent_bytes = cursor.take(intent_length)?;
    let supplied_fingerprint =
        RemoteSignerRequestFingerprintV1::from_exact_bytes(cursor.array32()?);
    cursor.finish()?;

    let intent = decode_canonical_sign_intent_v0_exact(intent_bytes, validator_set)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidCanonicalIntentEncoding)?;
    let command = RemoteConsensusCommandV1::from_canonical_intent(intent, validator_set)?;
    if command.kind() != command_kind {
        return Err(RemoteSignerProtocolErrorV1::CommandKindMismatch);
    }
    let value = RemoteSignerRequestV1::new(command, validator_set, decoded_binding, nonce)?;
    if value.fingerprint != supplied_fingerprint {
        return Err(RemoteSignerProtocolErrorV1::RequestFingerprintMismatch);
    }
    if value.try_exact_bytes()?.as_slice() != encoded {
        return Err(RemoteSignerProtocolErrorV1::NonCanonicalEncoding);
    }
    Ok(value)
}

/// Decodes an exact response envelope without authenticating its signature.
///
/// The returned type is deliberately inert and must not be passed to Core or
/// treated as signing authority.
pub fn decode_unverified_remote_signer_response_v1_exact(
    encoded: &[u8],
    expected_request: &RemoteSignerRequestV1,
) -> Result<UnverifiedRemoteSignerResponseV1, RemoteSignerProtocolErrorV1> {
    if encoded.len() > MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1 {
        return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
    }
    let mut cursor = CursorV1::new(encoded);
    if cursor.take(RESPONSE_MAGIC_V1.len())? != RESPONSE_MAGIC_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidMagic);
    }
    let schema = cursor.u16()?;
    if schema != REMOTE_SIGNER_RESPONSE_SCHEMA_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidSchemaVersion(schema));
    }
    if cursor.u8()? != UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidResponseTag);
    }
    if cursor.u8()? != CONSENSUS_ROLE_TAG_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidRoleTag);
    }
    let command_kind = RemoteConsensusCommandKindV1::from_tag(cursor.u8()?)?;
    let purpose_tag = cursor.u8()?;
    if purpose_tag != command_kind.tag() {
        return Err(RemoteSignerProtocolErrorV1::CommandPurposeMismatch);
    }
    let (binding, nonce) = decode_binding_v1(&mut cursor)?;
    let request_fingerprint = RemoteSignerRequestFingerprintV1::from_exact_bytes(cursor.array32()?);
    let signature = SignatureBytes::from_slice(cursor.take(64)?)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidSignature)?;
    let supplied_fingerprint =
        RemoteSignerResponseFingerprintV1::from_exact_bytes(cursor.array32()?);
    cursor.finish()?;

    if binding != expected_request.binding
        || command_kind != expected_request.command.kind()
        || nonce != expected_request.nonce
        || request_fingerprint != expected_request.fingerprint
    {
        return Err(RemoteSignerProtocolErrorV1::ResponseRequestMismatch);
    }
    let value = UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
        expected_request,
        signature,
    )?;
    if value.fingerprint != supplied_fingerprint {
        return Err(RemoteSignerProtocolErrorV1::ResponseFingerprintMismatch);
    }
    if value.try_exact_bytes()?.as_slice() != encoded {
        return Err(RemoteSignerProtocolErrorV1::NonCanonicalEncoding);
    }
    Ok(value)
}

fn encode_binding_v1(
    encoded: &mut Vec<u8>,
    binding: RemoteSignerRequestBindingV1,
    nonce: RemoteSignerRequestNonceV1,
) -> Result<(), RemoteSignerProtocolErrorV1> {
    encoded.extend_from_slice(binding.purpose_profile_digest.as_bytes());
    encoded.extend_from_slice(binding.role_profile_ref.as_bytes());
    encoded.extend_from_slice(binding.service_profile_ref.as_bytes());
    encoded.extend_from_slice(binding.client_profile_ref.as_bytes());
    encoded.extend_from_slice(&binding.process_generation.get().to_be_bytes());
    encoded.extend_from_slice(binding.lease_id.as_bytes());
    encoded.extend_from_slice(&binding.checkpoint_witness.generation().to_be_bytes());
    encoded.extend_from_slice(&binding.checkpoint_witness.checkpoint_checksum());
    encoded.extend_from_slice(&binding.checkpoint_witness.witness_digest());
    encoded.extend_from_slice(nonce.as_bytes());
    encoded.extend_from_slice(binding.genesis_hash.as_bytes());
    put_bounded_u16_v1(encoded, binding.chain_id.as_bytes())?;
    encoded.extend_from_slice(&binding.protocol_version.get().to_be_bytes());
    encoded.extend_from_slice(&binding.epoch.get().to_be_bytes());
    encoded.extend_from_slice(binding.validator_set_id.as_bytes());
    put_bounded_u16_v1(encoded, binding.author.as_bytes())?;
    Ok(())
}

fn decode_binding_v1(
    cursor: &mut CursorV1<'_>,
) -> Result<(RemoteSignerRequestBindingV1, RemoteSignerRequestNonceV1), RemoteSignerProtocolErrorV1>
{
    let purpose_profile_digest =
        RemoteSignerPurposeProfileDigestV1::from_exact_bytes(cursor.array32()?)?;
    let role_profile_ref = RemoteSignerRoleProfileRefV1::from_exact_bytes(cursor.array32()?)?;
    let service_profile_ref = RemoteSignerServiceProfileRefV1::from_exact_bytes(cursor.array32()?)?;
    let client_profile_ref = RemoteSignerClientProfileRefV1::from_exact_bytes(cursor.array32()?)?;
    let process_generation = ProcessGenerationV1::new(cursor.u64()?)?;
    let lease_id = RemoteSignerLeaseIdV1::from_exact_bytes(cursor.array32()?)?;
    let checkpoint_witness = RemoteSignerCheckpointWitnessV1::from_exact_parts(
        cursor.u64()?,
        cursor.array32()?,
        cursor.array32()?,
    )?;
    let nonce = RemoteSignerRequestNonceV1::from_exact_bytes(cursor.array32()?)?;
    let genesis_hash = GenesisHash::new(cursor.array32()?);
    if genesis_hash.is_zero() {
        return Err(RemoteSignerProtocolErrorV1::ValidatorSetContextMismatch);
    }
    let chain_bytes = cursor.bounded_u16(MAX_CONSENSUS_STRING_BYTES)?;
    let chain_id = ChainId::from_bytes(chain_bytes)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidChainId)?;
    let protocol_version = ProtocolVersion::new(cursor.u32()?)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidProtocolVersion)?;
    let epoch = Epoch::new(cursor.u64()?);
    let validator_set_id = ValidatorSetId::new(cursor.array32()?);
    let author_bytes = cursor.bounded_u16(MAX_VALIDATOR_ID_BYTES)?;
    let author = ValidatorId::from_bytes(author_bytes)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidAuthor)?;
    Ok((
        RemoteSignerRequestBindingV1 {
            purpose_profile_digest,
            role_profile_ref,
            service_profile_ref,
            client_profile_ref,
            process_generation,
            lease_id,
            checkpoint_witness,
            genesis_hash,
            chain_id,
            protocol_version,
            epoch,
            validator_set_id,
            author,
        },
        nonce,
    ))
}

fn put_bounded_u16_v1(
    encoded: &mut Vec<u8>,
    bytes: &[u8],
) -> Result<(), RemoteSignerProtocolErrorV1> {
    let length =
        u16::try_from(bytes.len()).map_err(|_| RemoteSignerProtocolErrorV1::LengthLimitExceeded)?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

fn request_fingerprint_v1(bytes_without_fingerprint: &[u8]) -> RemoteSignerRequestFingerprintV1 {
    RemoteSignerRequestFingerprintV1::from_exact_bytes(domain_hash_v1(
        REQUEST_FINGERPRINT_DOMAIN_V1,
        bytes_without_fingerprint,
    ))
}

fn response_fingerprint_v1(bytes_without_fingerprint: &[u8]) -> RemoteSignerResponseFingerprintV1 {
    RemoteSignerResponseFingerprintV1::from_exact_bytes(domain_hash_v1(
        RESPONSE_FINGERPRINT_DOMAIN_V1,
        bytes_without_fingerprint,
    ))
}

fn domain_hash_v1(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(
        u32::try_from(bytes.len())
            .expect("bounded remote signer protocol bytes fit u32")
            .to_be_bytes(),
    );
    hash.update(bytes);
    hash.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSignerProtocolErrorV1 {
    LengthLimitExceeded,
    TruncatedEncoding,
    TrailingBytes,
    InvalidMagic,
    InvalidSchemaVersion(u16),
    InvalidResponseTag,
    InvalidRoleTag,
    UnsupportedCommandTag(u8),
    CommandPurposeMismatch,
    PurposeProfileMismatch,
    InvalidValidatorSet,
    ValidatorSetContextMismatch,
    UnknownAuthor,
    InvalidChainId,
    InvalidProtocolVersion,
    InvalidAuthor,
    InvalidCanonicalIntent,
    InvalidCanonicalIntentEncoding,
    CommandKindMismatch,
    RequestBindingMismatch,
    RequestFingerprintMismatch,
    ResponseRequestMismatch,
    ResponseFingerprintMismatch,
    InvalidSignature,
    InvalidIdentifier(RemoteSignerIdErrorV1),
    NonCanonicalEncoding,
}

impl fmt::Display for RemoteSignerProtocolErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthLimitExceeded => {
                formatter.write_str("remote signer encoding exceeds its bound")
            }
            Self::TruncatedEncoding => formatter.write_str("remote signer encoding is truncated"),
            Self::TrailingBytes => formatter.write_str("remote signer encoding has trailing bytes"),
            Self::InvalidMagic => formatter.write_str("remote signer encoding magic differs"),
            Self::InvalidSchemaVersion(version) => {
                write!(formatter, "unsupported remote signer schema {version}")
            }
            Self::InvalidResponseTag => {
                formatter.write_str("unsupported remote signer response tag")
            }
            Self::InvalidRoleTag => formatter.write_str("remote signer role tag is not consensus"),
            Self::UnsupportedCommandTag(tag) => {
                write!(formatter, "unsupported remote signer command tag {tag}")
            }
            Self::CommandPurposeMismatch => {
                formatter.write_str("remote signer command and purpose tags differ")
            }
            Self::PurposeProfileMismatch => {
                formatter.write_str("remote signer purpose profile differs")
            }
            Self::InvalidValidatorSet => formatter.write_str("validator set is invalid"),
            Self::ValidatorSetContextMismatch => {
                formatter.write_str("remote signer validator-set context differs")
            }
            Self::UnknownAuthor => formatter.write_str("remote signer author is unknown"),
            Self::InvalidChainId => formatter.write_str("remote signer chain ID is invalid"),
            Self::InvalidProtocolVersion => {
                formatter.write_str("remote signer protocol version is invalid")
            }
            Self::InvalidAuthor => formatter.write_str("remote signer author encoding is invalid"),
            Self::InvalidCanonicalIntent => {
                formatter.write_str("canonical remote signer intent is invalid")
            }
            Self::InvalidCanonicalIntentEncoding => {
                formatter.write_str("canonical remote signer intent encoding is invalid")
            }
            Self::CommandKindMismatch => {
                formatter.write_str("command tag differs from canonical intent kind")
            }
            Self::RequestBindingMismatch => {
                formatter.write_str("remote signer request binding differs")
            }
            Self::RequestFingerprintMismatch => {
                formatter.write_str("remote signer request fingerprint differs")
            }
            Self::ResponseRequestMismatch => {
                formatter.write_str("remote signer response differs from its request")
            }
            Self::ResponseFingerprintMismatch => {
                formatter.write_str("remote signer response fingerprint differs")
            }
            Self::InvalidSignature => formatter.write_str("remote signer signature is invalid"),
            Self::InvalidIdentifier(error) => write!(formatter, "{error}"),
            Self::NonCanonicalEncoding => {
                formatter.write_str("remote signer encoding is not canonical")
            }
        }
    }
}

impl From<RemoteSignerIdErrorV1> for RemoteSignerProtocolErrorV1 {
    fn from(error: RemoteSignerIdErrorV1) -> Self {
        Self::InvalidIdentifier(error)
    }
}

impl From<RemoteConsensusCommandValidationErrorV1> for RemoteSignerProtocolErrorV1 {
    fn from(error: RemoteConsensusCommandValidationErrorV1) -> Self {
        match error {
            RemoteConsensusCommandValidationErrorV1::InvalidValidatorSet => {
                Self::InvalidValidatorSet
            }
            RemoteConsensusCommandValidationErrorV1::InvalidCanonicalIntent => {
                Self::InvalidCanonicalIntent
            }
            RemoteConsensusCommandValidationErrorV1::ContextMismatch => {
                Self::ValidatorSetContextMismatch
            }
            RemoteConsensusCommandValidationErrorV1::UnknownAuthor => Self::UnknownAuthor,
            RemoteConsensusCommandValidationErrorV1::UnsupportedCommandTag(tag) => {
                Self::UnsupportedCommandTag(tag)
            }
            RemoteConsensusCommandValidationErrorV1::CommandKindMismatch => {
                Self::CommandKindMismatch
            }
        }
    }
}

struct CursorV1<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> CursorV1<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RemoteSignerProtocolErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RemoteSignerProtocolErrorV1::TruncatedEncoding)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(RemoteSignerProtocolErrorV1::TruncatedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RemoteSignerProtocolErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RemoteSignerProtocolErrorV1> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| RemoteSignerProtocolErrorV1::TruncatedEncoding)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, RemoteSignerProtocolErrorV1> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| RemoteSignerProtocolErrorV1::TruncatedEncoding)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, RemoteSignerProtocolErrorV1> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| RemoteSignerProtocolErrorV1::TruncatedEncoding)?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], RemoteSignerProtocolErrorV1> {
        self.take(32)?
            .try_into()
            .map_err(|_| RemoteSignerProtocolErrorV1::TruncatedEncoding)
    }

    fn bounded_u16(&mut self, maximum: usize) -> Result<&'a [u8], RemoteSignerProtocolErrorV1> {
        let length = usize::from(self.u16()?);
        if length == 0 || length > maximum {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        self.take(length)
    }

    fn finish(self) -> Result<(), RemoteSignerProtocolErrorV1> {
        if self.offset != self.encoded.len() {
            return Err(RemoteSignerProtocolErrorV1::TrailingBytes);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        BlockId, CertificateId, ConsensusParametersHash, ConsensusPublicKey, GenesisHash, Height,
        QcRef, Validator, View, VotingPower,
    };

    const ROLE_TAG_OFFSET: usize = REQUEST_MAGIC_V1.len() + 2;
    const COMMAND_TAG_OFFSET: usize = ROLE_TAG_OFFSET + 1;
    const PURPOSE_TAG_OFFSET: usize = COMMAND_TAG_OFFSET + 1;
    const PURPOSE_PROFILE_OFFSET: usize = PURPOSE_TAG_OFFSET + 1;
    const ROLE_PROFILE_OFFSET: usize = PURPOSE_PROFILE_OFFSET + 32;
    const SERVICE_PROFILE_OFFSET: usize = ROLE_PROFILE_OFFSET + 32;
    const CLIENT_PROFILE_OFFSET: usize = SERVICE_PROFILE_OFFSET + 32;
    const GENERATION_OFFSET: usize = CLIENT_PROFILE_OFFSET + 32;
    const LEASE_OFFSET: usize = GENERATION_OFFSET + 8;
    const CHECKPOINT_GENERATION_OFFSET: usize = LEASE_OFFSET + 32;
    const CHECKPOINT_CHECKSUM_OFFSET: usize = CHECKPOINT_GENERATION_OFFSET + 8;
    const CHECKPOINT_WITNESS_DIGEST_OFFSET: usize = CHECKPOINT_CHECKSUM_OFFSET + 32;
    const NONCE_OFFSET: usize = CHECKPOINT_WITNESS_DIGEST_OFFSET + 32;
    const GENESIS_OFFSET: usize = NONCE_OFFSET + 32;
    const CHAIN_LENGTH_OFFSET: usize = GENESIS_OFFSET + 32;
    const RESPONSE_STATUS_TAG_OFFSET: usize = RESPONSE_MAGIC_V1.len() + 2;
    const RESPONSE_ROLE_TAG_OFFSET: usize = RESPONSE_STATUS_TAG_OFFSET + 1;
    const RESPONSE_COMMAND_TAG_OFFSET: usize = RESPONSE_ROLE_TAG_OFFSET + 1;
    const RESPONSE_PURPOSE_TAG_OFFSET: usize = RESPONSE_COMMAND_TAG_OFFSET + 1;
    const RESPONSE_BINDING_OFFSET_DELTA: usize = 1;

    fn validator_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::from_static("trnm-remote-signer-wire-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([8; 32]),
            alloc::vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    trnm_consensus_types::ConsensusPublicKey::new([2; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    ValidatorId::new([3; 32]),
                    ConsensusPublicKey::new([4; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    fn binding(set: &ValidatorSet) -> RemoteSignerRequestBindingV1 {
        RemoteSignerRequestBindingV1::new(
            set,
            ValidatorId::new([1; 32]),
            RemoteSignerRoleProfileRefV1::from_public_descriptor(b"consensus-role-v1").unwrap(),
            RemoteSignerServiceProfileRefV1::from_public_descriptor(b"service-a-v1").unwrap(),
            RemoteSignerClientProfileRefV1::from_public_descriptor(b"client-a-v1").unwrap(),
            ProcessGenerationV1::new(7).unwrap(),
            RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"lease-a-v1").unwrap(),
            RemoteSignerCheckpointWitnessV1::new(9, [10; 32]).unwrap(),
        )
        .unwrap()
    }

    fn vote_request(set: &ValidatorSet) -> RemoteSignerRequestV1 {
        let intent = trnm_consensus_types::CanonicalSignIntentV0::vote(
            set,
            ValidatorId::new([1; 32]),
            11,
            View::new(12),
            Height::new(13),
            BlockId::new([14; 32]),
        )
        .unwrap();
        RemoteSignerRequestV1::new(
            RemoteConsensusCommandV1::from_canonical_intent(intent, set).unwrap(),
            set,
            binding(set),
            RemoteSignerRequestNonceV1::from_public_nonce_material(b"request-a-v1").unwrap(),
        )
        .unwrap()
    }

    fn timeout_request(set: &ValidatorSet) -> RemoteSignerRequestV1 {
        let intent = trnm_consensus_types::CanonicalSignIntentV0::timeout_vote(
            set,
            ValidatorId::new([1; 32]),
            12,
            View::new(13),
            QcRef::new(
                CertificateId::new([15; 32]),
                set.epoch(),
                View::new(12),
                Height::new(11),
                BlockId::new([16; 32]),
                set.id(),
            ),
        )
        .unwrap();
        RemoteSignerRequestV1::new(
            RemoteConsensusCommandV1::from_canonical_intent(intent, set).unwrap(),
            set,
            binding(set),
            RemoteSignerRequestNonceV1::from_public_nonce_material(b"request-b-v1").unwrap(),
        )
        .unwrap()
    }

    fn replace_request_fingerprint(mut encoded: Vec<u8>) -> Vec<u8> {
        let fingerprint_offset = encoded.len() - 32;
        let fingerprint = request_fingerprint_v1(&encoded[..fingerprint_offset]);
        encoded[fingerprint_offset..].copy_from_slice(fingerprint.as_bytes());
        encoded
    }

    fn chain_dependent_offsets(encoded: &[u8]) -> (usize, usize, usize, usize, usize, usize) {
        let chain_length = usize::from(u16::from_be_bytes(
            encoded[CHAIN_LENGTH_OFFSET..CHAIN_LENGTH_OFFSET + 2]
                .try_into()
                .unwrap(),
        ));
        let chain_offset = CHAIN_LENGTH_OFFSET + 2;
        let protocol_offset = chain_offset + chain_length;
        let epoch_offset = protocol_offset + 4;
        let set_offset = epoch_offset + 8;
        let author_length_offset = set_offset + 32;
        let author_offset = author_length_offset + 2;
        (
            chain_offset,
            protocol_offset,
            epoch_offset,
            set_offset,
            author_length_offset,
            author_offset,
        )
    }

    #[test]
    fn vote_timeout_request_and_unverified_response_round_trip_exactly() {
        let set = validator_set();
        for request in [vote_request(&set), timeout_request(&set)] {
            let request_bytes = request.try_exact_bytes().unwrap();
            let decoded =
                decode_remote_signer_request_v1_exact(&request_bytes, &set, request.binding())
                    .unwrap();
            assert_eq!(decoded, request);
            assert_eq!(decoded.try_exact_bytes().unwrap(), request_bytes);

            let response = UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
                &decoded,
                SignatureBytes::from_array([21; 64]),
            )
            .unwrap();
            let response_bytes = response.try_exact_bytes().unwrap();
            let decoded_response =
                decode_unverified_remote_signer_response_v1_exact(&response_bytes, &decoded)
                    .unwrap();
            assert_eq!(decoded_response, response);
            assert_eq!(decoded_response.try_exact_bytes().unwrap(), response_bytes);
        }
    }

    #[test]
    fn wire_lengths_hashes_and_fingerprints_are_frozen_v1() {
        fn sha256(bytes: &[u8]) -> [u8; 32] {
            let mut hash = Sha256::new();
            hash.update(bytes);
            hash.finalize().into()
        }

        const VOTE_REQUEST_SHA256_V1: [u8; 32] = [
            69, 152, 94, 52, 148, 165, 221, 126, 60, 203, 171, 233, 204, 22, 170, 38, 84, 189, 83,
            15, 51, 220, 123, 201, 74, 123, 38, 182, 243, 202, 127, 197,
        ];
        const VOTE_REQUEST_FINGERPRINT_V1: [u8; 32] = [
            171, 19, 146, 224, 145, 61, 104, 192, 125, 58, 60, 69, 180, 74, 20, 173, 133, 108, 141,
            88, 254, 187, 105, 78, 152, 112, 58, 96, 41, 26, 208, 160,
        ];
        const TIMEOUT_REQUEST_SHA256_V1: [u8; 32] = [
            151, 113, 196, 144, 207, 253, 65, 214, 231, 238, 39, 9, 46, 237, 85, 44, 144, 55, 239,
            92, 41, 173, 87, 187, 66, 175, 96, 175, 54, 68, 154, 189,
        ];
        const TIMEOUT_REQUEST_FINGERPRINT_V1: [u8; 32] = [
            145, 109, 243, 123, 193, 9, 186, 254, 54, 129, 246, 197, 101, 67, 135, 112, 173, 243,
            8, 56, 147, 20, 19, 118, 34, 5, 150, 104, 95, 208, 201, 46,
        ];
        const VOTE_RESPONSE_SHA256_V1: [u8; 32] = [
            37, 255, 224, 46, 35, 6, 235, 4, 97, 145, 163, 60, 120, 19, 226, 8, 42, 51, 27, 56, 14,
            142, 146, 239, 86, 70, 2, 46, 147, 67, 164, 132,
        ];
        const VOTE_RESPONSE_FINGERPRINT_V1: [u8; 32] = [
            103, 103, 214, 144, 150, 134, 224, 93, 45, 203, 24, 82, 124, 79, 38, 24, 43, 228, 107,
            199, 116, 154, 94, 114, 228, 23, 52, 52, 39, 186, 117, 25,
        ];
        const TIMEOUT_RESPONSE_SHA256_V1: [u8; 32] = [
            158, 34, 98, 107, 59, 208, 77, 41, 175, 243, 230, 203, 103, 222, 155, 241, 157, 120,
            241, 114, 187, 219, 89, 120, 249, 239, 184, 104, 158, 114, 82, 95,
        ];
        const TIMEOUT_RESPONSE_FINGERPRINT_V1: [u8; 32] = [
            124, 7, 225, 86, 201, 6, 189, 156, 236, 113, 96, 8, 65, 187, 247, 33, 194, 194, 252, 0,
            232, 153, 232, 209, 85, 145, 74, 92, 231, 164, 6, 92,
        ];

        let set = validator_set();
        let vote = vote_request(&set);
        let timeout = timeout_request(&set);
        let vote_response = UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
            &vote,
            SignatureBytes::from_array([21; 64]),
        )
        .unwrap();
        let timeout_response = UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
            &timeout,
            SignatureBytes::from_array([21; 64]),
        )
        .unwrap();
        let vote_bytes = vote.try_exact_bytes().unwrap();
        let timeout_bytes = timeout.try_exact_bytes().unwrap();
        let vote_response_bytes = vote_response.try_exact_bytes().unwrap();
        let timeout_response_bytes = timeout_response.try_exact_bytes().unwrap();

        assert_eq!(vote_bytes.len(), 803);
        assert_eq!(sha256(&vote_bytes), VOTE_REQUEST_SHA256_V1);
        assert_eq!(*vote.fingerprint().as_bytes(), VOTE_REQUEST_FINGERPRINT_V1);
        assert_eq!(timeout_bytes.len(), 851);
        assert_eq!(sha256(&timeout_bytes), TIMEOUT_REQUEST_SHA256_V1);
        assert_eq!(
            *timeout.fingerprint().as_bytes(),
            TIMEOUT_REQUEST_FINGERPRINT_V1
        );
        assert_eq!(vote_response_bytes.len(), 554);
        assert_eq!(sha256(&vote_response_bytes), VOTE_RESPONSE_SHA256_V1);
        assert_eq!(
            *vote_response.fingerprint().as_bytes(),
            VOTE_RESPONSE_FINGERPRINT_V1
        );
        assert_eq!(timeout_response_bytes.len(), 554);
        assert_eq!(sha256(&timeout_response_bytes), TIMEOUT_RESPONSE_SHA256_V1);
        assert_eq!(
            *timeout_response.fingerprint().as_bytes(),
            TIMEOUT_RESPONSE_FINGERPRINT_V1
        );
    }

    #[test]
    fn request_decoder_rejects_trailing_reserved_and_oversize_before_admission() {
        let set = validator_set();
        let request = vote_request(&set);
        let exact = request.try_exact_bytes().unwrap();

        let mut trailing = exact.clone();
        trailing.push(0);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&trailing, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::TrailingBytes)
        );
        assert_eq!(
            decode_remote_signer_request_v1_exact(
                &alloc::vec![0; MAX_REMOTE_SIGNER_REQUEST_BYTES_V1 + 1],
                &set,
                request.binding(),
            ),
            Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded)
        );

        for reserved in [2, 3, 4, u8::MAX] {
            let mut mutant = exact.clone();
            mutant[COMMAND_TAG_OFFSET] = reserved;
            assert_eq!(
                decode_remote_signer_request_v1_exact(&mutant, &set, request.binding()),
                Err(RemoteSignerProtocolErrorV1::UnsupportedCommandTag(reserved))
            );
        }
    }

    #[test]
    fn kind_role_and_purpose_mutants_fail_closed() {
        let set = validator_set();
        let request = vote_request(&set);
        let exact = request.try_exact_bytes().unwrap();

        let mut role = exact.clone();
        role[ROLE_TAG_OFFSET] = 0;
        assert_eq!(
            decode_remote_signer_request_v1_exact(&role, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::InvalidRoleTag)
        );

        let mut purpose = exact.clone();
        purpose[PURPOSE_TAG_OFFSET] = 1;
        assert_eq!(
            decode_remote_signer_request_v1_exact(&purpose, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::CommandPurposeMismatch)
        );

        let mut kind = exact;
        kind[COMMAND_TAG_OFFSET] = 1;
        kind[PURPOSE_TAG_OFFSET] = 1;
        let kind = replace_request_fingerprint(kind);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&kind, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::CommandKindMismatch)
        );
    }

    #[test]
    fn every_trusted_request_binding_substitution_is_rejected() {
        let set = validator_set();
        let request = vote_request(&set);
        let exact = request.try_exact_bytes().unwrap();
        let (chain_offset, protocol_offset, epoch_offset, set_offset, _, author_offset) =
            chain_dependent_offsets(&exact);

        for offset in [
            ROLE_PROFILE_OFFSET,
            SERVICE_PROFILE_OFFSET,
            CLIENT_PROFILE_OFFSET,
            GENERATION_OFFSET + 7,
            LEASE_OFFSET,
            GENESIS_OFFSET,
            chain_offset,
            protocol_offset + 3,
            epoch_offset + 7,
            set_offset,
            author_offset,
        ] {
            let mut mutant = exact.clone();
            mutant[offset] ^= 1;
            let mutant = replace_request_fingerprint(mutant);
            assert_eq!(
                decode_remote_signer_request_v1_exact(&mutant, &set, request.binding()),
                Err(RemoteSignerProtocolErrorV1::RequestBindingMismatch),
                "substitution offset {offset}"
            );
        }

        let mut purpose_profile = exact.clone();
        purpose_profile[PURPOSE_PROFILE_OFFSET] ^= 1;
        let purpose_profile = replace_request_fingerprint(purpose_profile);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&purpose_profile, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::PurposeProfileMismatch)
        );

        let mut checkpoint_checksum = exact.clone();
        checkpoint_checksum[CHECKPOINT_CHECKSUM_OFFSET] ^= 1;
        let checkpoint_checksum = replace_request_fingerprint(checkpoint_checksum);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&checkpoint_checksum, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::InvalidIdentifier(
                RemoteSignerIdErrorV1::CheckpointWitnessDigestMismatch
            ))
        );

        let mut checkpoint_generation = exact.clone();
        checkpoint_generation[CHECKPOINT_GENERATION_OFFSET + 7] ^= 1;
        let checkpoint_generation = replace_request_fingerprint(checkpoint_generation);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&checkpoint_generation, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::InvalidIdentifier(
                RemoteSignerIdErrorV1::CheckpointWitnessDigestMismatch
            ))
        );

        let mut checkpoint_digest = exact.clone();
        checkpoint_digest[CHECKPOINT_WITNESS_DIGEST_OFFSET] ^= 1;
        let checkpoint_digest = replace_request_fingerprint(checkpoint_digest);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&checkpoint_digest, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::InvalidIdentifier(
                RemoteSignerIdErrorV1::CheckpointWitnessDigestMismatch
            ))
        );

        // The same fields fail without repairing the fingerprint. Admission
        // never treats the request fingerprint as trusted binding context.
        for offset in [
            ROLE_PROFILE_OFFSET,
            SERVICE_PROFILE_OFFSET,
            CLIENT_PROFILE_OFFSET,
            GENERATION_OFFSET + 7,
            LEASE_OFFSET,
            CHECKPOINT_CHECKSUM_OFFSET,
            GENESIS_OFFSET,
            chain_offset,
            protocol_offset + 3,
            epoch_offset + 7,
            set_offset,
            author_offset,
        ] {
            let mut mutant = exact.clone();
            mutant[offset] ^= 1;
            assert!(
                decode_remote_signer_request_v1_exact(&mutant, &set, request.binding()).is_err(),
                "unrepaired substitution offset {offset}"
            );
        }
    }

    #[test]
    fn nonce_intent_and_request_fingerprint_mutants_are_rejected() {
        let set = validator_set();
        let request = vote_request(&set);
        let exact = request.try_exact_bytes().unwrap();

        let mut nonce = exact.clone();
        nonce[NONCE_OFFSET] ^= 1;
        assert_eq!(
            decode_remote_signer_request_v1_exact(&nonce, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::RequestFingerprintMismatch)
        );

        let fingerprint_offset = exact.len() - 32;
        let mut fingerprint = exact.clone();
        fingerprint[fingerprint_offset] ^= 1;
        assert_eq!(
            decode_remote_signer_request_v1_exact(&fingerprint, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::RequestFingerprintMismatch)
        );

        let (_, _, _, _, author_length_offset, author_offset) = chain_dependent_offsets(&exact);
        let author_length = usize::from(u16::from_be_bytes(
            exact[author_length_offset..author_length_offset + 2]
                .try_into()
                .unwrap(),
        ));
        let intent_length_offset = author_offset + author_length;
        let intent_offset = intent_length_offset + 4;
        let mut intent = exact;
        intent[intent_offset] ^= 1;
        let intent = replace_request_fingerprint(intent);
        assert_eq!(
            decode_remote_signer_request_v1_exact(&intent, &set, request.binding()),
            Err(RemoteSignerProtocolErrorV1::InvalidCanonicalIntentEncoding)
        );
    }

    #[test]
    fn arbitrary_high_revision_well_formed_request_is_inert_not_safety_authority() {
        let set = validator_set();
        let public_intent = trnm_consensus_types::CanonicalSignIntentV0::vote(
            &set,
            ValidatorId::new([1; 32]),
            u64::MAX,
            View::new(77),
            Height::new(78),
            BlockId::new([79; 32]),
        )
        .unwrap();
        let request = RemoteSignerRequestV1::new(
            RemoteConsensusCommandV1::from_canonical_intent(public_intent, &set).unwrap(),
            &set,
            binding(&set),
            RemoteSignerRequestNonceV1::from_public_nonce_material(b"untrusted-high-revision")
                .unwrap(),
        )
        .unwrap();

        assert_eq!(
            request.command().intent().authorizing_safety_revision(),
            u64::MAX
        );
        assert!(!crate::REMOTE_SIGNER_PROTOCOL_CORE_SAFETY_AUTHORITY_V1);
        assert!(!crate::REMOTE_SIGNER_PROTOCOL_SAFETY_RULES_EVALUATION_V1);
        assert!(!crate::REMOTE_SIGNER_PROTOCOL_SAFE_VOTE_AUTHORITY_V1);
    }

    #[test]
    fn response_substitution_trailing_unknown_and_oversize_are_rejected() {
        let set = validator_set();
        let request = vote_request(&set);
        let response = UnverifiedRemoteSignerResponseV1::from_unverified_signature_bytes(
            &request,
            SignatureBytes::from_array([22; 64]),
        )
        .unwrap();
        let exact = response.try_exact_bytes().unwrap();

        let mut trailing = exact.clone();
        trailing.push(0);
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&trailing, &request),
            Err(RemoteSignerProtocolErrorV1::TrailingBytes)
        );
        let mut unknown = exact.clone();
        unknown[RESPONSE_STATUS_TAG_OFFSET] = 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&unknown, &request),
            Err(RemoteSignerProtocolErrorV1::InvalidResponseTag)
        );
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(
                &alloc::vec![0; MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1 + 1],
                &request,
            ),
            Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded)
        );

        for reserved in 2u8..=u8::MAX {
            let mut mutant = exact.clone();
            mutant[RESPONSE_COMMAND_TAG_OFFSET] = reserved;
            assert_eq!(
                decode_unverified_remote_signer_response_v1_exact(&mutant, &request),
                Err(RemoteSignerProtocolErrorV1::UnsupportedCommandTag(reserved))
            );
        }

        let mut role = exact.clone();
        role[RESPONSE_ROLE_TAG_OFFSET] = 0;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&role, &request),
            Err(RemoteSignerProtocolErrorV1::InvalidRoleTag)
        );

        let mut purpose = exact.clone();
        purpose[RESPONSE_PURPOSE_TAG_OFFSET] = 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&purpose, &request),
            Err(RemoteSignerProtocolErrorV1::CommandPurposeMismatch)
        );

        let mut wrong_kind = exact.clone();
        wrong_kind[RESPONSE_COMMAND_TAG_OFFSET] = 1;
        wrong_kind[RESPONSE_PURPOSE_TAG_OFFSET] = 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&wrong_kind, &request),
            Err(RemoteSignerProtocolErrorV1::ResponseRequestMismatch)
        );

        for request_binding_offset in [
            ROLE_PROFILE_OFFSET,
            SERVICE_PROFILE_OFFSET,
            CLIENT_PROFILE_OFFSET,
            GENERATION_OFFSET + 7,
            LEASE_OFFSET,
            NONCE_OFFSET,
        ] {
            let mut mutant = exact.clone();
            mutant[request_binding_offset + RESPONSE_BINDING_OFFSET_DELTA] ^= 1;
            assert_eq!(
                decode_unverified_remote_signer_response_v1_exact(&mutant, &request),
                Err(RemoteSignerProtocolErrorV1::ResponseRequestMismatch),
                "response binding substitution offset {request_binding_offset}"
            );
        }

        let mut request_fingerprint = exact.clone();
        let request_fingerprint_offset = request_fingerprint.len() - 32 - 64 - 32;
        request_fingerprint[request_fingerprint_offset] ^= 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&request_fingerprint, &request),
            Err(RemoteSignerProtocolErrorV1::ResponseRequestMismatch)
        );

        let signature_offset = exact.len() - 32 - 64;
        let mut signature = exact.clone();
        signature[signature_offset] ^= 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&signature, &request),
            Err(RemoteSignerProtocolErrorV1::ResponseFingerprintMismatch)
        );

        let mut response_fingerprint = exact;
        let response_fingerprint_offset = response_fingerprint.len() - 32;
        response_fingerprint[response_fingerprint_offset] ^= 1;
        assert_eq!(
            decode_unverified_remote_signer_response_v1_exact(&response_fingerprint, &request),
            Err(RemoteSignerProtocolErrorV1::ResponseFingerprintMismatch)
        );
    }
}
