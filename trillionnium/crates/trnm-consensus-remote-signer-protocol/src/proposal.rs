use alloc::vec::Vec;

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    BlockId, Epoch, Height, SignatureBytes, SigningRoot, ValidatorId, ValidatorSet, ValidatorSetId,
    View,
};

use crate::{
    proposal_purpose_profile_digest_v1, RemoteSignerRequestBindingV1,
    RemoteSignerRequestFingerprintV1, RemoteSignerRequestNonceV1,
    RemoteSignerResponseFingerprintV1,
};
use crate::{
    wire::{decode_binding_v1, encode_binding_v1, CursorV1},
    RemoteSignerProtocolErrorV1,
};

const PROPOSAL_REQUEST_MAGIC_V1: &[u8; 8] = b"TRNMPR01";
const PROPOSAL_RESPONSE_MAGIC_V1: &[u8; 8] = b"TRNMPS01";
const CONSENSUS_ROLE_TAG_V1: u8 = 1;
const PROPOSAL_PURPOSE_TAG_V1: u8 = 2;
const UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1: u8 = 0;
const PROPOSAL_REQUEST_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.proposal-request-fingerprint.v1\0";
const PROPOSAL_RESPONSE_FINGERPRINT_DOMAIN_V1: &[u8] =
    b"trnm.remote-signer.protocol.proposal-response-fingerprint.v1\0";

/// Conservative bounds for one canonical proposal witness request/response.
/// The payload is fixed-shape; the generous bound leaves room for bounded
/// chain identifiers/profile references without making the Unix transport
/// unbounded.
pub const MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1: usize = 2048;
pub const MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1: usize = 4096;

/// Exact proposal identity and signing root presented to an independent
/// proposal signer. Construction is shape validation only; it is not Core or
/// SafetyRules admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteProposalSignatureRequestV1 {
    binding: RemoteSignerRequestBindingV1,
    proposal_id: BlockId,
    parent_id: BlockId,
    validator_set_id: ValidatorSetId,
    author: ValidatorId,
    epoch: Epoch,
    view: View,
    height: Height,
    signing_root: SigningRoot,
    expected_consensus_public_key: [u8; 32],
    signer_profile_ref: [u8; 32],
    nonce: RemoteSignerRequestNonceV1,
    fingerprint: RemoteSignerRequestFingerprintV1,
}

impl RemoteProposalSignatureRequestV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        binding: RemoteSignerRequestBindingV1,
        proposal_id: BlockId,
        parent_id: BlockId,
        validator_set_id: ValidatorSetId,
        author: ValidatorId,
        epoch: Epoch,
        view: View,
        height: Height,
        signing_root: SigningRoot,
        expected_consensus_public_key: [u8; 32],
        signer_profile_ref: [u8; 32],
        nonce: RemoteSignerRequestNonceV1,
        validator_set: &ValidatorSet,
    ) -> Result<Self, RemoteSignerProtocolErrorV1> {
        binding.validate_against_profile(validator_set, proposal_purpose_profile_digest_v1())?;
        validator_set
            .validator(author)
            .ok_or(RemoteSignerProtocolErrorV1::UnknownAuthor)?;
        let expected_key = *validator_set
            .validator(author)
            .ok_or(RemoteSignerProtocolErrorV1::UnknownAuthor)?
            .consensus_key()
            .as_bytes();
        if proposal_id.is_zero()
            || parent_id.is_zero()
            || validator_set_id.is_zero()
            || author.is_zero()
            || signing_root.is_zero()
            || expected_consensus_public_key == [0; 32]
            || signer_profile_ref == [0; 32]
            || nonce.as_bytes() == &[0; 32]
            || view.get() == 0
            || height.get() == 0
            || validator_set_id != binding.validator_set_id()
            || epoch != binding.epoch()
            || author != binding.author()
            || expected_key != expected_consensus_public_key
        {
            return Err(RemoteSignerProtocolErrorV1::ProposalBindingMismatch);
        }
        let mut value = Self {
            binding,
            proposal_id,
            parent_id,
            validator_set_id,
            author,
            epoch,
            view,
            height,
            signing_root,
            expected_consensus_public_key,
            signer_profile_ref,
            nonce,
            fingerprint: RemoteSignerRequestFingerprintV1::from_exact_bytes([0; 32]),
        };
        value.fingerprint =
            proposal_request_fingerprint_v1(&value.try_bytes_without_fingerprint()?);
        Ok(value)
    }

    pub const fn binding(&self) -> RemoteSignerRequestBindingV1 {
        self.binding
    }
    pub const fn proposal_id(&self) -> BlockId {
        self.proposal_id
    }
    pub const fn parent_id(&self) -> BlockId {
        self.parent_id
    }
    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }
    pub const fn author(&self) -> ValidatorId {
        self.author
    }
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }
    pub const fn view(&self) -> View {
        self.view
    }
    pub const fn height(&self) -> Height {
        self.height
    }
    pub const fn signing_root(&self) -> SigningRoot {
        self.signing_root
    }
    pub const fn expected_consensus_public_key(&self) -> [u8; 32] {
        self.expected_consensus_public_key
    }
    pub const fn signer_profile_ref(&self) -> [u8; 32] {
        self.signer_profile_ref
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
        if encoded.len() > MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1 {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        Ok(encoded)
    }

    fn try_bytes_without_fingerprint(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = Vec::with_capacity(MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1);
        encoded.extend_from_slice(PROPOSAL_REQUEST_MAGIC_V1);
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.push(CONSENSUS_ROLE_TAG_V1);
        encoded.push(PROPOSAL_PURPOSE_TAG_V1);
        encode_binding_v1(&mut encoded, self.binding, self.nonce)?;
        encode_proposal_fields_v1(&mut encoded, self)?;
        Ok(encoded)
    }
}

/// Shape-checked response carrying only unverified signature bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnverifiedRemoteProposalSignerResponseV1 {
    request: RemoteProposalSignatureRequestV1,
    signature: SignatureBytes,
    fingerprint: RemoteSignerResponseFingerprintV1,
}

impl UnverifiedRemoteProposalSignerResponseV1 {
    pub fn from_unverified_signature_bytes(
        request: &RemoteProposalSignatureRequestV1,
        signature: SignatureBytes,
    ) -> Result<Self, RemoteSignerProtocolErrorV1> {
        signature
            .validate_shape()
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidSignature)?;
        if signature.as_bytes() == &[0; 64] {
            return Err(RemoteSignerProtocolErrorV1::InvalidSignature);
        }
        let mut value = Self {
            request: *request,
            signature,
            fingerprint: RemoteSignerResponseFingerprintV1::from_exact_bytes([0; 32]),
        };
        value.fingerprint =
            proposal_response_fingerprint_v1(&value.try_bytes_without_fingerprint()?);
        Ok(value)
    }

    pub const fn request(&self) -> &RemoteProposalSignatureRequestV1 {
        &self.request
    }
    pub const fn unverified_signature_bytes(&self) -> SignatureBytes {
        self.signature
    }
    pub const fn fingerprint(&self) -> RemoteSignerResponseFingerprintV1 {
        self.fingerprint
    }

    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = self.try_bytes_without_fingerprint()?;
        encoded.extend_from_slice(self.fingerprint.as_bytes());
        if encoded.len() > MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1 {
            return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
        }
        Ok(encoded)
    }

    fn try_bytes_without_fingerprint(&self) -> Result<Vec<u8>, RemoteSignerProtocolErrorV1> {
        let mut encoded = Vec::with_capacity(MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1);
        encoded.extend_from_slice(PROPOSAL_RESPONSE_MAGIC_V1);
        encoded.extend_from_slice(&1u16.to_be_bytes());
        encoded.push(UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1);
        encoded.push(CONSENSUS_ROLE_TAG_V1);
        encoded.push(PROPOSAL_PURPOSE_TAG_V1);
        encode_binding_v1(&mut encoded, self.request.binding, self.request.nonce)?;
        encode_proposal_fields_v1(&mut encoded, &self.request)?;
        encoded.extend_from_slice(self.request.fingerprint.as_bytes());
        encoded.extend_from_slice(self.signature.as_bytes());
        Ok(encoded)
    }
}

pub fn decode_remote_proposal_signer_request_v1_exact(
    encoded: &[u8],
    validator_set: &ValidatorSet,
    expected_binding: RemoteSignerRequestBindingV1,
) -> Result<RemoteProposalSignatureRequestV1, RemoteSignerProtocolErrorV1> {
    if encoded.len() > MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1 {
        return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
    }
    expected_binding
        .validate_against_profile(validator_set, proposal_purpose_profile_digest_v1())?;
    let mut cursor = CursorV1::new(encoded);
    if cursor.take(PROPOSAL_REQUEST_MAGIC_V1.len())? != PROPOSAL_REQUEST_MAGIC_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidMagic);
    }
    if cursor.u16()? != 1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidSchemaVersion(1));
    }
    if cursor.u8()? != CONSENSUS_ROLE_TAG_V1 || cursor.u8()? != PROPOSAL_PURPOSE_TAG_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidRoleTag);
    }
    let (binding, nonce) = decode_binding_v1(&mut cursor)?;
    if binding != expected_binding {
        return Err(RemoteSignerProtocolErrorV1::RequestBindingMismatch);
    }
    let proposal_id = BlockId::new(cursor.array32()?);
    let parent_id = BlockId::new(cursor.array32()?);
    let validator_set_id = ValidatorSetId::new(cursor.array32()?);
    let author =
        ValidatorId::from_bytes(cursor.bounded_u16(trnm_consensus_types::MAX_VALIDATOR_ID_BYTES)?)
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidAuthor)?;
    let epoch = Epoch::new(cursor.u64()?);
    let view = View::new(cursor.u64()?);
    let height = Height::new(cursor.u64()?);
    let signing_root = SigningRoot::new(cursor.array32()?);
    let expected_key = cursor.array32()?;
    let signer_profile_ref = cursor.array32()?;
    let supplied_fingerprint =
        RemoteSignerRequestFingerprintV1::from_exact_bytes(cursor.array32()?);
    cursor.finish()?;
    let request = RemoteProposalSignatureRequestV1::new(
        binding,
        proposal_id,
        parent_id,
        validator_set_id,
        author,
        epoch,
        view,
        height,
        signing_root,
        expected_key,
        signer_profile_ref,
        nonce,
        validator_set,
    )?;
    if request.fingerprint != supplied_fingerprint {
        return Err(RemoteSignerProtocolErrorV1::RequestFingerprintMismatch);
    }
    if request.try_exact_bytes()?.as_slice() != encoded {
        return Err(RemoteSignerProtocolErrorV1::NonCanonicalEncoding);
    }
    Ok(request)
}

pub fn decode_unverified_remote_proposal_signer_response_v1_exact(
    encoded: &[u8],
    expected_request: &RemoteProposalSignatureRequestV1,
) -> Result<UnverifiedRemoteProposalSignerResponseV1, RemoteSignerProtocolErrorV1> {
    if encoded.len() > MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1 {
        return Err(RemoteSignerProtocolErrorV1::LengthLimitExceeded);
    }
    let mut cursor = CursorV1::new(encoded);
    if cursor.take(PROPOSAL_RESPONSE_MAGIC_V1.len())? != PROPOSAL_RESPONSE_MAGIC_V1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidMagic);
    }
    if cursor.u16()? != 1 {
        return Err(RemoteSignerProtocolErrorV1::InvalidSchemaVersion(1));
    }
    if cursor.u8()? != UNVERIFIED_SIGNATURE_RESPONSE_TAG_V1
        || cursor.u8()? != CONSENSUS_ROLE_TAG_V1
        || cursor.u8()? != PROPOSAL_PURPOSE_TAG_V1
    {
        return Err(RemoteSignerProtocolErrorV1::InvalidResponseTag);
    }
    let (binding, nonce) = decode_binding_v1(&mut cursor)?;
    let proposal_id = BlockId::new(cursor.array32()?);
    let parent_id = BlockId::new(cursor.array32()?);
    let validator_set_id = ValidatorSetId::new(cursor.array32()?);
    let author =
        ValidatorId::from_bytes(cursor.bounded_u16(trnm_consensus_types::MAX_VALIDATOR_ID_BYTES)?)
            .map_err(|_| RemoteSignerProtocolErrorV1::InvalidAuthor)?;
    let epoch = Epoch::new(cursor.u64()?);
    let view = View::new(cursor.u64()?);
    let height = Height::new(cursor.u64()?);
    let signing_root = SigningRoot::new(cursor.array32()?);
    let expected_key = cursor.array32()?;
    let signer_profile_ref = cursor.array32()?;
    let request_fingerprint = RemoteSignerRequestFingerprintV1::from_exact_bytes(cursor.array32()?);
    let signature = SignatureBytes::from_slice(cursor.take(64)?)
        .map_err(|_| RemoteSignerProtocolErrorV1::InvalidSignature)?;
    let supplied_fingerprint =
        RemoteSignerResponseFingerprintV1::from_exact_bytes(cursor.array32()?);
    cursor.finish()?;
    if binding != expected_request.binding
        || nonce != expected_request.nonce
        || proposal_id != expected_request.proposal_id
        || parent_id != expected_request.parent_id
        || validator_set_id != expected_request.validator_set_id
        || author != expected_request.author
        || epoch != expected_request.epoch
        || view != expected_request.view
        || height != expected_request.height
        || signing_root != expected_request.signing_root
        || expected_key != expected_request.expected_consensus_public_key
        || signer_profile_ref != expected_request.signer_profile_ref
        || request_fingerprint != expected_request.fingerprint
    {
        return Err(RemoteSignerProtocolErrorV1::ResponseRequestMismatch);
    }
    let value = UnverifiedRemoteProposalSignerResponseV1::from_unverified_signature_bytes(
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

pub fn is_remote_proposal_request_v1(encoded: &[u8]) -> bool {
    encoded.len() >= PROPOSAL_REQUEST_MAGIC_V1.len()
        && encoded[..PROPOSAL_REQUEST_MAGIC_V1.len()] == *PROPOSAL_REQUEST_MAGIC_V1
}

fn encode_proposal_fields_v1(
    encoded: &mut Vec<u8>,
    request: &RemoteProposalSignatureRequestV1,
) -> Result<(), RemoteSignerProtocolErrorV1> {
    encoded.extend_from_slice(request.proposal_id.as_bytes());
    encoded.extend_from_slice(request.parent_id.as_bytes());
    encoded.extend_from_slice(request.validator_set_id.as_bytes());
    // ValidatorId is a bounded variable-length identifier, unlike the fixed
    // 32-byte block/set/root fields. Its length prefix is part of the exact
    // canonical proposal wire so decoders cannot drift into the epoch field.
    let author_len = u16::try_from(request.author.as_bytes().len())
        .map_err(|_| RemoteSignerProtocolErrorV1::LengthLimitExceeded)?;
    encoded.extend_from_slice(&author_len.to_be_bytes());
    encoded.extend_from_slice(request.author.as_bytes());
    encoded.extend_from_slice(&request.epoch.get().to_be_bytes());
    encoded.extend_from_slice(&request.view.get().to_be_bytes());
    encoded.extend_from_slice(&request.height.get().to_be_bytes());
    encoded.extend_from_slice(request.signing_root.as_bytes());
    encoded.extend_from_slice(&request.expected_consensus_public_key);
    encoded.extend_from_slice(&request.signer_profile_ref);
    Ok(())
}

fn proposal_request_fingerprint_v1(bytes: &[u8]) -> RemoteSignerRequestFingerprintV1 {
    RemoteSignerRequestFingerprintV1::from_exact_bytes(proposal_hash_v1(
        PROPOSAL_REQUEST_FINGERPRINT_DOMAIN_V1,
        bytes,
    ))
}

fn proposal_response_fingerprint_v1(bytes: &[u8]) -> RemoteSignerResponseFingerprintV1 {
    RemoteSignerResponseFingerprintV1::from_exact_bytes(proposal_hash_v1(
        PROPOSAL_RESPONSE_FINGERPRINT_DOMAIN_V1,
        bytes,
    ))
}

fn proposal_hash_v1(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
    hash.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        ChainId, ConsensusParametersHash, ConsensusPublicKey, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    fn fixture() -> (ValidatorSet, RemoteSignerRequestBindingV1) {
        let author = ValidatorId::from_bytes(b"proposal-author").unwrap();
        let validator = Validator::new(
            author,
            ConsensusPublicKey::new([0x22; 32]),
            VotingPower::new(1).unwrap(),
        )
        .unwrap();
        let set = ValidatorSet::new(
            GenesisHash::new([0x31; 32]),
            ChainId::from_static("trnm-proposal-wire-test"),
            ProtocolVersion::V0,
            Epoch::new(4),
            ConsensusParametersHash::new([0x42; 32]),
            alloc::vec![validator],
        )
        .unwrap();
        let binding = RemoteSignerRequestBindingV1::new_with_purpose_profile_v1(
            &set,
            author,
            crate::RemoteSignerRoleProfileRefV1::from_public_descriptor(b"proposal-role").unwrap(),
            crate::RemoteSignerServiceProfileRefV1::from_public_descriptor(b"proposal-service")
                .unwrap(),
            crate::RemoteSignerClientProfileRefV1::from_public_descriptor(b"proposal-client")
                .unwrap(),
            crate::ProcessGenerationV1::new(2).unwrap(),
            crate::RemoteSignerLeaseIdV1::from_public_grant_descriptor(b"proposal-lease").unwrap(),
            crate::RemoteSignerCheckpointWitnessV1::new(1, [0x52; 32]).unwrap(),
            proposal_purpose_profile_digest_v1(),
        )
        .unwrap();
        (set, binding)
    }

    #[test]
    fn proposal_wire_round_trips_variable_length_author_exactly() {
        let (set, binding) = fixture();
        let request = RemoteProposalSignatureRequestV1::new(
            binding,
            BlockId::new([0x81; 32]),
            BlockId::new([0x82; 32]),
            set.id(),
            binding.author(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            SigningRoot::new([0x83; 32]),
            [0x22; 32],
            [0x84; 32],
            crate::RemoteSignerRequestNonceV1::from_public_nonce_material(b"proposal-wire")
                .unwrap(),
            &set,
        )
        .unwrap();
        let encoded = request.try_exact_bytes().unwrap();
        let decoded = decode_remote_proposal_signer_request_v1_exact(&encoded, &set, binding)
            .expect("proposal request exact decode");
        assert_eq!(decoded, request);
        let response = UnverifiedRemoteProposalSignerResponseV1::from_unverified_signature_bytes(
            &request,
            SignatureBytes::from_array([0x91; 64]),
        )
        .unwrap();
        let response_bytes = response.try_exact_bytes().unwrap();
        let decoded_response =
            decode_unverified_remote_proposal_signer_response_v1_exact(&response_bytes, &request)
                .expect("proposal response exact decode");
        assert_eq!(decoded_response, response);
    }

    #[test]
    fn proposal_magic_is_distinct_and_profile_mutation_fails_closed() {
        let (set, binding) = fixture();
        let mut request = RemoteProposalSignatureRequestV1::new(
            binding,
            BlockId::new([0x81; 32]),
            BlockId::new([0x82; 32]),
            set.id(),
            binding.author(),
            set.epoch(),
            View::new(1),
            Height::new(1),
            SigningRoot::new([0x83; 32]),
            [0x22; 32],
            [0x84; 32],
            crate::RemoteSignerRequestNonceV1::from_public_nonce_material(b"proposal-profile")
                .unwrap(),
            &set,
        )
        .unwrap()
        .try_exact_bytes()
        .unwrap();
        assert!(is_remote_proposal_request_v1(&request));
        request[12] ^= 0x01;
        assert_eq!(
            decode_remote_proposal_signer_request_v1_exact(&request, &set, binding),
            Err(RemoteSignerProtocolErrorV1::RequestBindingMismatch)
        );
    }
}
