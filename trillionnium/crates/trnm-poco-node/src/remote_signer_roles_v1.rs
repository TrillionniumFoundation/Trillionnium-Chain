//! Inert Stage-1 key-role and remote-signer configuration boundary.
//!
//! This module deliberately contains no private-key type, PKCS#8 decoder,
//! credential bytes, network client, or signing implementation.  It binds
//! three independently identified public signing roles:
//!
//! * P2P session identity;
//! * consensus vote, timeout-vote, and proposal authority; and
//! * operator/recovery control authority.
//!
//! Endpoint and signer-profile references are distinct domain-separated hashes
//! of bounded public descriptors; the descriptors themselves are not retained.
//! The types cannot prove that operator-supplied descriptor semantics are free
//! of credentials or private material.  A future process owner must enforce
//! that policy through an authenticated resolver and must keep credentials
//! outside the node configuration represented here.
//!
//! Only existing canonical sign intents can cross the typed vote and timeout
//! command boundary. Those intents are publicly constructible and the typed
//! wrappers prove only canonical shape, validator-set context, author, and
//! command kind. They do not observe locked-QC state, justify ancestry,
//! persist-before-sign state, or any other HotStuff SafetyRules witness.
//! Proposal and old/new handoff remain classified purposes, not sign commands:
//! they require complete journal intents and durable Safety witnesses first.
//! There is intentionally no `sign(bytes)` trait or callback.
//! No runtime consumes these types yet; P2P, consensus, operator/recovery, and
//! remote-signer activation remain closed until the signer journal, whole-node
//! checkpoint, and wire protocols can enforce the same role split.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_types::{
    CanonicalSignIntentV0, CanonicalSignPreimageV0, ConsensusPublicKey, SigningRoot, ValidatorId,
    ValidatorSet, ValidatorSetId,
};

const ROLE_BINDINGS_MAGIC_V1: &[u8; 8] = b"TRNMSR01";
const ROLE_BINDINGS_CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.poco-node.remote-signer-role-bindings.v1\0";
const REMOTE_SIGNER_PURPOSE_PROFILE_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.remote-signer-purpose-profile.v1\0";
const REMOTE_SIGNER_PROFILE_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.remote-signer-profile-descriptor.v1\0";
const REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_DOMAIN_V1: &[u8] =
    b"trnm.poco-node.remote-signer-endpoint-descriptor.v1\0";
const REMOTE_SIGNER_REFERENCE_BYTES_V1: usize = 32;
const ROLE_RECORD_BYTES_V1: usize = 1
    + REMOTE_SIGNER_REFERENCE_BYTES_V1
    + REMOTE_SIGNER_REFERENCE_BYTES_V1
    + REMOTE_SIGNER_REFERENCE_BYTES_V1;
const FIXED_BINDINGS_BYTES_WITHOUT_VALIDATOR_ID_V1: usize =
    ROLE_BINDINGS_MAGIC_V1.len() + 2 + 32 + 32 + 2 + (ROLE_RECORD_BYTES_V1 * 3) + 32;

/// Frozen exact-encoding schema for [`PocoNodeRemoteSignerRoleBindingsV1`].
pub const REMOTE_SIGNER_ROLE_BINDINGS_SCHEMA_V1: u16 = 1;

/// Maximum exact encoding size, including the largest bounded validator ID.
pub const MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1: usize =
    FIXED_BINDINGS_BYTES_WITHOUT_VALIDATOR_ID_V1 + trnm_consensus_types::MAX_VALIDATOR_ID_BYTES;

/// Maximum canonical public descriptor accepted for a signer profile digest.
pub const MAX_REMOTE_SIGNER_PROFILE_DESCRIPTOR_BYTES_V1: usize = 1024;

/// Maximum canonical public descriptor accepted for an endpoint digest.
pub const MAX_REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_BYTES_V1: usize = 1024;

/// Production runtime activation remains deliberately closed.
pub const REMOTE_SIGNER_RUNTIME_ACTIVATION_V1: bool = false;

/// Production-facing role bindings cannot contain private keys or PKCS#8.
pub const REMOTE_SIGNER_RUNTIME_PRIVATE_KEY_CONFIG_V1: bool = false;

/// This boundary exposes no caller-selected byte signing operation.
pub const REMOTE_SIGNER_GENERIC_SIGN_BYTES_V1: bool = false;

/// Typed Vote/Timeout command construction does not evaluate locked-QC or any
/// other HotStuff SafetyRules state.
pub const REMOTE_SIGNER_SAFETY_RULES_EVALUATION_V1: bool = false;

/// A publicly constructible, well-formed canonical Vote intent is not safe-vote
/// authority and cannot be passed directly to a signature producer.
pub const REMOTE_SIGNER_SAFE_VOTE_AUTHORITY_V1: bool = false;

/// Disjoint authority classes retained by the node configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RemoteSignerRoleV1 {
    P2pIdentity,
    Consensus,
    OperatorRecoveryControl,
}

impl RemoteSignerRoleV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::P2pIdentity => 0,
            Self::Consensus => 1,
            Self::OperatorRecoveryControl => 2,
        }
    }
}

/// Closed P2P use classification.  No corresponding runtime signer exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum P2pIdentitySigningPurposeV1 {
    SessionChallenge,
    SessionHello,
    SessionFinished,
    AuthenticatedFrame,
    RelayOrigin,
}

impl P2pIdentitySigningPurposeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::SessionChallenge => 0,
            Self::SessionHello => 1,
            Self::SessionFinished => 2,
            Self::AuthenticatedFrame => 3,
            Self::RelayOrigin => 4,
        }
    }
}

const P2P_IDENTITY_PURPOSES_V1: &[P2pIdentitySigningPurposeV1] = &[
    P2pIdentitySigningPurposeV1::SessionChallenge,
    P2pIdentitySigningPurposeV1::SessionHello,
    P2pIdentitySigningPurposeV1::SessionFinished,
    P2pIdentitySigningPurposeV1::AuthenticatedFrame,
    P2pIdentitySigningPurposeV1::RelayOrigin,
];

/// Closed consensus use classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConsensusSignerPurposeV1 {
    Vote,
    TimeoutVote,
    Proposal,
    OldSetHandoffVote,
    NewSetHandoffVote,
}

impl ConsensusSignerPurposeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::Vote => 0,
            Self::TimeoutVote => 1,
            Self::Proposal => 2,
            Self::OldSetHandoffVote => 3,
            Self::NewSetHandoffVote => 4,
        }
    }
}

const CONSENSUS_PURPOSES_V1: &[ConsensusSignerPurposeV1] = &[
    ConsensusSignerPurposeV1::Vote,
    ConsensusSignerPurposeV1::TimeoutVote,
    ConsensusSignerPurposeV1::Proposal,
    ConsensusSignerPurposeV1::OldSetHandoffVote,
    ConsensusSignerPurposeV1::NewSetHandoffVote,
];

/// Closed operator/recovery use classification.  Existing Lab wire values
/// still verify against consensus keys and are not wired to this role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperatorRecoverySigningPurposeV1 {
    RuntimeEvidence,
    RestartControl,
    RecoveryReady,
    RecoveryStart,
}

impl OperatorRecoverySigningPurposeV1 {
    const fn tag(self) -> u8 {
        match self {
            Self::RuntimeEvidence => 0,
            Self::RestartControl => 1,
            Self::RecoveryReady => 2,
            Self::RecoveryStart => 3,
        }
    }
}

const OPERATOR_RECOVERY_PURPOSES_V1: &[OperatorRecoverySigningPurposeV1] = &[
    OperatorRecoverySigningPurposeV1::RuntimeEvidence,
    OperatorRecoverySigningPurposeV1::RestartControl,
    OperatorRecoverySigningPurposeV1::RecoveryReady,
    OperatorRecoverySigningPurposeV1::RecoveryStart,
];

/// Domain-separated digest of one bounded, public signer-profile descriptor.
///
/// This type hashes the descriptor rather than retaining it.  It cannot prove
/// that an operator did not place sensitive semantics in the descriptor; the
/// future authenticated resolver must enforce that policy before activation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerProfileRefV1([u8; REMOTE_SIGNER_REFERENCE_BYTES_V1]);

impl RemoteSignerProfileRefV1 {
    pub fn from_public_descriptor(
        descriptor: &[u8],
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if descriptor.is_empty() {
            return Err(RemoteSignerRoleConfigErrorV1::EmptyProfileDescriptor);
        }
        if descriptor.len() > MAX_REMOTE_SIGNER_PROFILE_DESCRIPTOR_BYTES_V1 {
            return Err(RemoteSignerRoleConfigErrorV1::ProfileDescriptorTooLarge);
        }
        Self::from_exact_digest(digest_public_descriptor_v1(
            REMOTE_SIGNER_PROFILE_DESCRIPTOR_DOMAIN_V1,
            descriptor,
        ))
    }

    fn from_exact_digest(
        bytes: [u8; REMOTE_SIGNER_REFERENCE_BYTES_V1],
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if bytes == [0; REMOTE_SIGNER_REFERENCE_BYTES_V1] {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroProfileReference);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; REMOTE_SIGNER_REFERENCE_BYTES_V1] {
        &self.0
    }
}

/// Domain-separated digest of one bounded, public endpoint descriptor.
///
/// The descriptor must identify routing only.  This type does not retain the
/// descriptor and cannot prove that its operator-supplied semantics are free
/// of credentials; the future authenticated resolver must enforce that rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RemoteSignerEndpointRefV1([u8; REMOTE_SIGNER_REFERENCE_BYTES_V1]);

impl RemoteSignerEndpointRefV1 {
    pub fn from_public_descriptor(
        descriptor: &[u8],
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if descriptor.is_empty() {
            return Err(RemoteSignerRoleConfigErrorV1::EmptyEndpointDescriptor);
        }
        if descriptor.len() > MAX_REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_BYTES_V1 {
            return Err(RemoteSignerRoleConfigErrorV1::EndpointDescriptorTooLarge);
        }
        Self::from_exact_digest(digest_public_descriptor_v1(
            REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_DOMAIN_V1,
            descriptor,
        ))
    }

    fn from_exact_digest(
        bytes: [u8; REMOTE_SIGNER_REFERENCE_BYTES_V1],
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if bytes == [0; REMOTE_SIGNER_REFERENCE_BYTES_V1] {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroEndpointReference);
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; REMOTE_SIGNER_REFERENCE_BYTES_V1] {
        &self.0
    }
}

/// P2P Ed25519 public key, kept distinct from the consensus key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct P2pIdentityPublicKeyV1([u8; 32]);

impl P2pIdentityPublicKeyV1 {
    pub fn new(bytes: [u8; 32]) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if bytes == [0; 32] {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroPublicKey(
                RemoteSignerRoleV1::P2pIdentity,
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Operator/recovery Ed25519 public key, not a validator consensus key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OperatorRecoveryPublicKeyV1([u8; 32]);

impl OperatorRecoveryPublicKeyV1 {
    pub fn new(bytes: [u8; 32]) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if bytes == [0; 32] {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroPublicKey(
                RemoteSignerRoleV1::OperatorRecoveryControl,
            ));
        }
        Ok(Self(bytes))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// P2P role profile.  All fields are public facts or non-secret references.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct P2pIdentityRemoteSignerProfileV1 {
    profile_ref: RemoteSignerProfileRefV1,
    endpoint_ref: RemoteSignerEndpointRefV1,
    public_key: P2pIdentityPublicKeyV1,
}

impl P2pIdentityRemoteSignerProfileV1 {
    pub const fn new(
        profile_ref: RemoteSignerProfileRefV1,
        endpoint_ref: RemoteSignerEndpointRefV1,
        public_key: P2pIdentityPublicKeyV1,
    ) -> Self {
        Self {
            profile_ref,
            endpoint_ref,
            public_key,
        }
    }

    pub const fn profile_ref(self) -> RemoteSignerProfileRefV1 {
        self.profile_ref
    }

    pub const fn endpoint_ref(self) -> RemoteSignerEndpointRefV1 {
        self.endpoint_ref
    }

    pub const fn public_key(self) -> P2pIdentityPublicKeyV1 {
        self.public_key
    }

    pub const fn purposes(self) -> &'static [P2pIdentitySigningPurposeV1] {
        P2P_IDENTITY_PURPOSES_V1
    }
}

/// Consensus role profile.  The public key must equal the committed key for
/// `author` in the bound validator set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusRemoteSignerProfileV1 {
    profile_ref: RemoteSignerProfileRefV1,
    endpoint_ref: RemoteSignerEndpointRefV1,
    author: ValidatorId,
    public_key: ConsensusPublicKey,
}

impl ConsensusRemoteSignerProfileV1 {
    pub fn new(
        profile_ref: RemoteSignerProfileRefV1,
        endpoint_ref: RemoteSignerEndpointRefV1,
        author: ValidatorId,
        public_key: ConsensusPublicKey,
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        if author.is_zero() {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroValidatorId);
        }
        if public_key.is_zero() {
            return Err(RemoteSignerRoleConfigErrorV1::ZeroPublicKey(
                RemoteSignerRoleV1::Consensus,
            ));
        }
        Ok(Self {
            profile_ref,
            endpoint_ref,
            author,
            public_key,
        })
    }

    pub const fn profile_ref(self) -> RemoteSignerProfileRefV1 {
        self.profile_ref
    }

    pub const fn endpoint_ref(self) -> RemoteSignerEndpointRefV1 {
        self.endpoint_ref
    }

    pub const fn author(self) -> ValidatorId {
        self.author
    }

    pub const fn public_key(self) -> ConsensusPublicKey {
        self.public_key
    }

    pub const fn purposes(self) -> &'static [ConsensusSignerPurposeV1] {
        CONSENSUS_PURPOSES_V1
    }
}

/// Operator/recovery role profile.  No current Lab recovery wire object is
/// authorized by this profile; that migration requires a separately reviewed
/// protocol change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorRecoveryRemoteSignerProfileV1 {
    profile_ref: RemoteSignerProfileRefV1,
    endpoint_ref: RemoteSignerEndpointRefV1,
    public_key: OperatorRecoveryPublicKeyV1,
}

impl OperatorRecoveryRemoteSignerProfileV1 {
    pub const fn new(
        profile_ref: RemoteSignerProfileRefV1,
        endpoint_ref: RemoteSignerEndpointRefV1,
        public_key: OperatorRecoveryPublicKeyV1,
    ) -> Self {
        Self {
            profile_ref,
            endpoint_ref,
            public_key,
        }
    }

    pub const fn profile_ref(self) -> RemoteSignerProfileRefV1 {
        self.profile_ref
    }

    pub const fn endpoint_ref(self) -> RemoteSignerEndpointRefV1 {
        self.endpoint_ref
    }

    pub const fn public_key(self) -> OperatorRecoveryPublicKeyV1 {
        self.public_key
    }

    pub const fn purposes(self) -> &'static [OperatorRecoverySigningPurposeV1] {
        OPERATOR_RECOVERY_PURPOSES_V1
    }
}

/// Exact, validator-set-bound public configuration for the three roles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PocoNodeRemoteSignerRoleBindingsV1 {
    purpose_profile_digest: [u8; 32],
    validator_set_id: ValidatorSetId,
    p2p_identity: P2pIdentityRemoteSignerProfileV1,
    consensus: ConsensusRemoteSignerProfileV1,
    operator_recovery: OperatorRecoveryRemoteSignerProfileV1,
    profile_checksum: [u8; 32],
}

impl PocoNodeRemoteSignerRoleBindingsV1 {
    pub fn new(
        validator_set: &ValidatorSet,
        p2p_identity: P2pIdentityRemoteSignerProfileV1,
        consensus: ConsensusRemoteSignerProfileV1,
        operator_recovery: OperatorRecoveryRemoteSignerProfileV1,
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        validator_set
            .validate_shape()
            .map_err(|_| RemoteSignerRoleConfigErrorV1::InvalidValidatorSet)?;
        let validator = validator_set
            .validator(consensus.author())
            .ok_or(RemoteSignerRoleConfigErrorV1::ConsensusAuthorAbsent)?;
        if validator.consensus_key() != consensus.public_key() {
            return Err(RemoteSignerRoleConfigErrorV1::ConsensusPublicKeyMismatch);
        }
        require_distinct_profile_references_v1(
            p2p_identity.profile_ref(),
            consensus.profile_ref(),
            operator_recovery.profile_ref(),
        )?;
        require_distinct_public_keys_v1(
            *p2p_identity.public_key().as_bytes(),
            consensus.public_key().into_bytes(),
            *operator_recovery.public_key().as_bytes(),
        )?;
        let mut value = Self {
            purpose_profile_digest: purpose_profile_digest_v1(),
            validator_set_id: validator_set.id(),
            p2p_identity,
            consensus,
            operator_recovery,
            profile_checksum: [0; 32],
        };
        value.profile_checksum = checksum_v1(&value.encode_without_checksum());
        Ok(value)
    }

    /// Digest of the complete, ordered purpose taxonomy accepted by schema 1.
    pub const fn purpose_profile_digest(&self) -> [u8; 32] {
        self.purpose_profile_digest
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.consensus.author()
    }

    pub const fn p2p_identity(&self) -> P2pIdentityRemoteSignerProfileV1 {
        self.p2p_identity
    }

    pub const fn consensus(&self) -> ConsensusRemoteSignerProfileV1 {
        self.consensus
    }

    pub const fn operator_recovery(&self) -> OperatorRecoveryRemoteSignerProfileV1 {
        self.operator_recovery
    }

    pub const fn profile_checksum(&self) -> [u8; 32] {
        self.profile_checksum
    }

    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, RemoteSignerRoleConfigErrorV1> {
        let mut encoded = self.encode_without_checksum();
        encoded.extend_from_slice(&self.profile_checksum);
        if encoded.len() > MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1 {
            return Err(RemoteSignerRoleConfigErrorV1::EncodingTooLarge);
        }
        Ok(encoded)
    }

    fn encode_without_checksum(&self) -> Vec<u8> {
        let consensus_author = self.consensus.author();
        let validator_id = consensus_author.as_bytes();
        let mut encoded =
            Vec::with_capacity(FIXED_BINDINGS_BYTES_WITHOUT_VALIDATOR_ID_V1 + validator_id.len());
        encoded.extend_from_slice(ROLE_BINDINGS_MAGIC_V1);
        encoded.extend_from_slice(&REMOTE_SIGNER_ROLE_BINDINGS_SCHEMA_V1.to_be_bytes());
        encoded.extend_from_slice(&self.purpose_profile_digest);
        encoded.extend_from_slice(self.validator_set_id.as_bytes());
        encoded.extend_from_slice(&(validator_id.len() as u16).to_be_bytes());
        encoded.extend_from_slice(validator_id);
        encode_role_record_v1(
            &mut encoded,
            RemoteSignerRoleV1::P2pIdentity,
            self.p2p_identity.profile_ref(),
            self.p2p_identity.endpoint_ref(),
            self.p2p_identity.public_key().as_bytes(),
        );
        encode_role_record_v1(
            &mut encoded,
            RemoteSignerRoleV1::Consensus,
            self.consensus.profile_ref(),
            self.consensus.endpoint_ref(),
            self.consensus.public_key().as_bytes(),
        );
        encode_role_record_v1(
            &mut encoded,
            RemoteSignerRoleV1::OperatorRecoveryControl,
            self.operator_recovery.profile_ref(),
            self.operator_recovery.endpoint_ref(),
            self.operator_recovery.public_key().as_bytes(),
        );
        encoded
    }
}

/// Exact decoder requiring the committed validator set out of band.
pub fn decode_remote_signer_role_bindings_v1_exact(
    encoded: &[u8],
    validator_set: &ValidatorSet,
) -> Result<PocoNodeRemoteSignerRoleBindingsV1, RemoteSignerRoleConfigErrorV1> {
    if encoded.len() > MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1 {
        return Err(RemoteSignerRoleConfigErrorV1::EncodingTooLarge);
    }
    if encoded.len() < FIXED_BINDINGS_BYTES_WITHOUT_VALIDATOR_ID_V1 + 1 {
        return Err(RemoteSignerRoleConfigErrorV1::TruncatedEncoding);
    }
    let mut cursor = DecoderCursorV1::new(encoded);
    if cursor.take(ROLE_BINDINGS_MAGIC_V1.len())? != ROLE_BINDINGS_MAGIC_V1 {
        return Err(RemoteSignerRoleConfigErrorV1::InvalidMagic);
    }
    let schema = cursor.u16()?;
    if schema != REMOTE_SIGNER_ROLE_BINDINGS_SCHEMA_V1 {
        return Err(RemoteSignerRoleConfigErrorV1::InvalidSchemaVersion(schema));
    }
    let supplied_purpose_profile_digest = cursor.array32()?;
    if supplied_purpose_profile_digest != purpose_profile_digest_v1() {
        return Err(RemoteSignerRoleConfigErrorV1::PurposeProfileMismatch);
    }
    let validator_set_id = ValidatorSetId::new(cursor.array32()?);
    if validator_set_id != validator_set.id() {
        return Err(RemoteSignerRoleConfigErrorV1::ValidatorSetMismatch);
    }
    let author_length = usize::from(cursor.u16()?);
    if author_length == 0 || author_length > trnm_consensus_types::MAX_VALIDATOR_ID_BYTES {
        return Err(RemoteSignerRoleConfigErrorV1::InvalidValidatorIdLength);
    }
    let author = ValidatorId::from_bytes(cursor.take(author_length)?)
        .map_err(|_| RemoteSignerRoleConfigErrorV1::InvalidValidatorIdLength)?;
    let p2p = decode_role_record_v1(&mut cursor, RemoteSignerRoleV1::P2pIdentity)?;
    let consensus = decode_role_record_v1(&mut cursor, RemoteSignerRoleV1::Consensus)?;
    let operator = decode_role_record_v1(&mut cursor, RemoteSignerRoleV1::OperatorRecoveryControl)?;
    let supplied_checksum = cursor.array32()?;
    if !cursor.is_finished() {
        return Err(RemoteSignerRoleConfigErrorV1::TrailingBytes);
    }

    let value = PocoNodeRemoteSignerRoleBindingsV1::new(
        validator_set,
        P2pIdentityRemoteSignerProfileV1::new(
            RemoteSignerProfileRefV1::from_exact_digest(p2p.profile_ref)?,
            RemoteSignerEndpointRefV1::from_exact_digest(p2p.endpoint_ref)?,
            P2pIdentityPublicKeyV1::new(p2p.public_key)?,
        ),
        ConsensusRemoteSignerProfileV1::new(
            RemoteSignerProfileRefV1::from_exact_digest(consensus.profile_ref)?,
            RemoteSignerEndpointRefV1::from_exact_digest(consensus.endpoint_ref)?,
            author,
            ConsensusPublicKey::new(consensus.public_key),
        )?,
        OperatorRecoveryRemoteSignerProfileV1::new(
            RemoteSignerProfileRefV1::from_exact_digest(operator.profile_ref)?,
            RemoteSignerEndpointRefV1::from_exact_digest(operator.endpoint_ref)?,
            OperatorRecoveryPublicKeyV1::new(operator.public_key)?,
        ),
    )?;
    if value.purpose_profile_digest() != supplied_purpose_profile_digest
        || value.validator_set_id() != validator_set_id
        || value.profile_checksum() != supplied_checksum
        || checksum_v1(&encoded[..encoded.len() - 32]) != supplied_checksum
    {
        return Err(RemoteSignerRoleConfigErrorV1::ChecksumMismatch);
    }
    Ok(value)
}

/// Typed vote-shaped data. Construction rejects timeout intents and requires
/// the exact configured validator-set/author binding, but it does not inspect
/// locked-QC/justify state or grant safe-vote/signature-producer authority.
#[derive(Debug, Clone, Copy)]
pub struct ConsensusVoteSignCommandV1<'a> {
    intent: &'a CanonicalSignIntentV0,
}

impl<'a> ConsensusVoteSignCommandV1<'a> {
    pub fn new(
        intent: &'a CanonicalSignIntentV0,
        validator_set: &ValidatorSet,
        roles: &PocoNodeRemoteSignerRoleBindingsV1,
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        validate_consensus_intent_binding_v1(intent, validator_set, roles)?;
        if !matches!(intent.preimage(), CanonicalSignPreimageV0::Vote(_)) {
            return Err(RemoteSignerRoleConfigErrorV1::WrongConsensusCommandKind);
        }
        Ok(Self { intent })
    }

    pub const fn intent(self) -> &'a CanonicalSignIntentV0 {
        self.intent
    }

    pub const fn signing_root(self) -> SigningRoot {
        self.intent.signing_root()
    }
}

/// Typed timeout-vote-shaped data. Construction rejects ordinary vote intents,
/// but it does not evaluate SafetyRules or grant signature-producer authority.
#[derive(Debug, Clone, Copy)]
pub struct ConsensusTimeoutSignCommandV1<'a> {
    intent: &'a CanonicalSignIntentV0,
}

impl<'a> ConsensusTimeoutSignCommandV1<'a> {
    pub fn new(
        intent: &'a CanonicalSignIntentV0,
        validator_set: &ValidatorSet,
        roles: &PocoNodeRemoteSignerRoleBindingsV1,
    ) -> Result<Self, RemoteSignerRoleConfigErrorV1> {
        validate_consensus_intent_binding_v1(intent, validator_set, roles)?;
        if !matches!(intent.preimage(), CanonicalSignPreimageV0::TimeoutVote(_)) {
            return Err(RemoteSignerRoleConfigErrorV1::WrongConsensusCommandKind);
        }
        Ok(Self { intent })
    }

    pub const fn intent(self) -> &'a CanonicalSignIntentV0 {
        self.intent
    }

    pub const fn signing_root(self) -> SigningRoot {
        self.intent.signing_root()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteSignerRoleConfigErrorV1 {
    EmptyProfileDescriptor,
    ProfileDescriptorTooLarge,
    EmptyEndpointDescriptor,
    EndpointDescriptorTooLarge,
    ZeroProfileReference,
    ZeroEndpointReference,
    ZeroPublicKey(RemoteSignerRoleV1),
    ZeroValidatorId,
    DuplicateProfileReference,
    DuplicatePublicKey,
    InvalidValidatorSet,
    ConsensusAuthorAbsent,
    ConsensusPublicKeyMismatch,
    ConsensusAuthorMismatch,
    InvalidConsensusIntent,
    WrongConsensusCommandKind,
    ValidatorSetMismatch,
    InvalidMagic,
    InvalidSchemaVersion(u16),
    PurposeProfileMismatch,
    InvalidValidatorIdLength,
    TruncatedEncoding,
    TrailingBytes,
    EncodingTooLarge,
    InvalidRoleTag,
    ChecksumMismatch,
}

impl fmt::Display for RemoteSignerRoleConfigErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyProfileDescriptor => {
                formatter.write_str("remote signer profile descriptor is empty")
            }
            Self::ProfileDescriptorTooLarge => {
                formatter.write_str("remote signer profile descriptor exceeds its bound")
            }
            Self::EmptyEndpointDescriptor => {
                formatter.write_str("remote signer endpoint descriptor is empty")
            }
            Self::EndpointDescriptorTooLarge => {
                formatter.write_str("remote signer endpoint descriptor exceeds its bound")
            }
            Self::ZeroProfileReference => {
                formatter.write_str("remote signer profile reference is zero")
            }
            Self::ZeroEndpointReference => {
                formatter.write_str("remote signer endpoint reference is zero")
            }
            Self::ZeroPublicKey(role) => write!(formatter, "{role:?} public key is zero"),
            Self::ZeroValidatorId => formatter.write_str("consensus validator ID is zero"),
            Self::DuplicateProfileReference => {
                formatter.write_str("signer roles reuse one profile reference")
            }
            Self::DuplicatePublicKey => formatter.write_str("signer roles reuse one public key"),
            Self::InvalidValidatorSet => formatter.write_str("validator set is invalid"),
            Self::ConsensusAuthorAbsent => {
                formatter.write_str("consensus author is absent from validator set")
            }
            Self::ConsensusPublicKeyMismatch => {
                formatter.write_str("consensus public key differs from validator set")
            }
            Self::ConsensusAuthorMismatch => {
                formatter.write_str("consensus command author differs from configured author")
            }
            Self::InvalidConsensusIntent => {
                formatter.write_str("consensus sign intent is invalid for the bound set")
            }
            Self::WrongConsensusCommandKind => {
                formatter.write_str("consensus sign intent has the wrong typed command kind")
            }
            Self::ValidatorSetMismatch => {
                formatter.write_str("remote signer binding validator set differs")
            }
            Self::InvalidMagic => formatter.write_str("remote signer binding magic differs"),
            Self::InvalidSchemaVersion(actual) => write!(
                formatter,
                "unsupported remote signer binding schema {actual}"
            ),
            Self::PurposeProfileMismatch => {
                formatter.write_str("remote signer purpose profile differs")
            }
            Self::InvalidValidatorIdLength => {
                formatter.write_str("remote signer binding validator ID length is invalid")
            }
            Self::TruncatedEncoding => {
                formatter.write_str("remote signer binding encoding is truncated")
            }
            Self::TrailingBytes => {
                formatter.write_str("remote signer binding encoding has trailing bytes")
            }
            Self::EncodingTooLarge => {
                formatter.write_str("remote signer binding encoding exceeds its bound")
            }
            Self::InvalidRoleTag => {
                formatter.write_str("remote signer binding role tag or order differs")
            }
            Self::ChecksumMismatch => formatter.write_str("remote signer binding checksum differs"),
        }
    }
}

impl Error for RemoteSignerRoleConfigErrorV1 {}

fn validate_role_set_binding_v1(
    validator_set: &ValidatorSet,
    roles: &PocoNodeRemoteSignerRoleBindingsV1,
) -> Result<(), RemoteSignerRoleConfigErrorV1> {
    validator_set
        .validate_shape()
        .map_err(|_| RemoteSignerRoleConfigErrorV1::InvalidValidatorSet)?;
    if validator_set.id() != roles.validator_set_id() {
        return Err(RemoteSignerRoleConfigErrorV1::ValidatorSetMismatch);
    }
    let validator = validator_set
        .validator(roles.local_validator())
        .ok_or(RemoteSignerRoleConfigErrorV1::ConsensusAuthorAbsent)?;
    if validator.consensus_key() != roles.consensus().public_key() {
        return Err(RemoteSignerRoleConfigErrorV1::ConsensusPublicKeyMismatch);
    }
    Ok(())
}

fn validate_consensus_intent_binding_v1(
    intent: &CanonicalSignIntentV0,
    validator_set: &ValidatorSet,
    roles: &PocoNodeRemoteSignerRoleBindingsV1,
) -> Result<(), RemoteSignerRoleConfigErrorV1> {
    validate_role_set_binding_v1(validator_set, roles)?;
    intent
        .validate(validator_set)
        .map_err(|_| RemoteSignerRoleConfigErrorV1::InvalidConsensusIntent)?;
    if intent.validator_set_id() != roles.validator_set_id()
        || intent.author() != roles.local_validator()
    {
        return Err(RemoteSignerRoleConfigErrorV1::ConsensusAuthorMismatch);
    }
    Ok(())
}

fn require_distinct_profile_references_v1(
    p2p: RemoteSignerProfileRefV1,
    consensus: RemoteSignerProfileRefV1,
    operator: RemoteSignerProfileRefV1,
) -> Result<(), RemoteSignerRoleConfigErrorV1> {
    if p2p == consensus || p2p == operator || consensus == operator {
        return Err(RemoteSignerRoleConfigErrorV1::DuplicateProfileReference);
    }
    Ok(())
}

fn require_distinct_public_keys_v1(
    p2p: [u8; 32],
    consensus: [u8; 32],
    operator: [u8; 32],
) -> Result<(), RemoteSignerRoleConfigErrorV1> {
    if p2p == consensus || p2p == operator || consensus == operator {
        return Err(RemoteSignerRoleConfigErrorV1::DuplicatePublicKey);
    }
    Ok(())
}

fn digest_public_descriptor_v1(domain: &[u8], descriptor: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(
        u32::try_from(descriptor.len())
            .expect("public descriptor bounds fit u32")
            .to_be_bytes(),
    );
    hash.update(descriptor);
    hash.finalize().into()
}

fn purpose_profile_digest_v1() -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(REMOTE_SIGNER_PURPOSE_PROFILE_DOMAIN_V1);
    hash.update(REMOTE_SIGNER_ROLE_BINDINGS_SCHEMA_V1.to_be_bytes());
    hash.update([RemoteSignerRoleV1::P2pIdentity.tag()]);
    hash.update(
        u16::try_from(P2P_IDENTITY_PURPOSES_V1.len())
            .expect("P2P purpose count fits u16")
            .to_be_bytes(),
    );
    for purpose in P2P_IDENTITY_PURPOSES_V1 {
        hash.update([purpose.tag()]);
    }
    hash.update([RemoteSignerRoleV1::Consensus.tag()]);
    hash.update(
        u16::try_from(CONSENSUS_PURPOSES_V1.len())
            .expect("consensus purpose count fits u16")
            .to_be_bytes(),
    );
    for purpose in CONSENSUS_PURPOSES_V1 {
        hash.update([purpose.tag()]);
    }
    hash.update([RemoteSignerRoleV1::OperatorRecoveryControl.tag()]);
    hash.update(
        u16::try_from(OPERATOR_RECOVERY_PURPOSES_V1.len())
            .expect("operator/recovery purpose count fits u16")
            .to_be_bytes(),
    );
    for purpose in OPERATOR_RECOVERY_PURPOSES_V1 {
        hash.update([purpose.tag()]);
    }
    hash.finalize().into()
}

fn checksum_v1(encoded_without_checksum: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ROLE_BINDINGS_CHECKSUM_DOMAIN_V1);
    hash.update(encoded_without_checksum);
    hash.finalize().into()
}

fn encode_role_record_v1(
    encoded: &mut Vec<u8>,
    role: RemoteSignerRoleV1,
    profile_ref: RemoteSignerProfileRefV1,
    endpoint_ref: RemoteSignerEndpointRefV1,
    public_key: &[u8; 32],
) {
    encoded.push(role.tag());
    encoded.extend_from_slice(profile_ref.as_bytes());
    encoded.extend_from_slice(endpoint_ref.as_bytes());
    encoded.extend_from_slice(public_key);
}

#[derive(Debug, Clone, Copy)]
struct DecodedRoleRecordV1 {
    profile_ref: [u8; 32],
    endpoint_ref: [u8; 32],
    public_key: [u8; 32],
}

fn decode_role_record_v1(
    cursor: &mut DecoderCursorV1<'_>,
    expected_role: RemoteSignerRoleV1,
) -> Result<DecodedRoleRecordV1, RemoteSignerRoleConfigErrorV1> {
    if cursor.u8()? != expected_role.tag() {
        return Err(RemoteSignerRoleConfigErrorV1::InvalidRoleTag);
    }
    Ok(DecodedRoleRecordV1 {
        profile_ref: cursor.array32()?,
        endpoint_ref: cursor.array32()?,
        public_key: cursor.array32()?,
    })
}

struct DecoderCursorV1<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> DecoderCursorV1<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RemoteSignerRoleConfigErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RemoteSignerRoleConfigErrorV1::TruncatedEncoding)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(RemoteSignerRoleConfigErrorV1::TruncatedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RemoteSignerRoleConfigErrorV1> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RemoteSignerRoleConfigErrorV1> {
        let bytes: [u8; 2] = self
            .take(2)?
            .try_into()
            .map_err(|_| RemoteSignerRoleConfigErrorV1::TruncatedEncoding)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn array32(&mut self) -> Result<[u8; 32], RemoteSignerRoleConfigErrorV1> {
        self.take(32)?
            .try_into()
            .map_err(|_| RemoteSignerRoleConfigErrorV1::TruncatedEncoding)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use trnm_consensus_types::{
        BlockId, ChainId, ConsensusParametersHash, GenesisHash, Height, ProtocolVersion, QcRef,
        Validator, View, VotingPower,
    };

    const PURPOSE_PROFILE_DIGEST_V1: [u8; 32] = [
        0xdc, 0x71, 0x93, 0xba, 0x02, 0x6a, 0x89, 0x8f, 0xb0, 0x36, 0xce, 0x8b, 0x29, 0x41, 0x2d,
        0x98, 0x33, 0x4b, 0x10, 0x2e, 0xe2, 0x52, 0xe9, 0x2b, 0x6d, 0x4d, 0x0a, 0x3b, 0x5a, 0xdd,
        0x28, 0xc0,
    ];
    const SCHEMA_OFFSET: usize = ROLE_BINDINGS_MAGIC_V1.len();
    const PURPOSE_PROFILE_OFFSET: usize = SCHEMA_OFFSET + 2;
    const VALIDATOR_SET_OFFSET: usize = PURPOSE_PROFILE_OFFSET + 32;
    const AUTHOR_LENGTH_OFFSET: usize = VALIDATOR_SET_OFFSET + 32;
    const AUTHOR_OFFSET: usize = AUTHOR_LENGTH_OFFSET + 2;

    fn profile(descriptor: &[u8]) -> RemoteSignerProfileRefV1 {
        RemoteSignerProfileRefV1::from_public_descriptor(descriptor).unwrap()
    }

    fn endpoint(descriptor: &[u8]) -> RemoteSignerEndpointRefV1 {
        RemoteSignerEndpointRefV1::from_public_descriptor(descriptor).unwrap()
    }

    fn validator_set_for_author(author: ValidatorId, key: u8) -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::from_static("trnm-signer-role-test"),
            ProtocolVersion::V0,
            trnm_consensus_types::Epoch::new(0),
            ConsensusParametersHash::new([8; 32]),
            vec![Validator::new(
                author,
                ConsensusPublicKey::new([key; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn validator_set(key: u8) -> ValidatorSet {
        validator_set_for_author(ValidatorId::new([1; 32]), key)
    }

    fn two_validator_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::from_static("trnm-signer-role-test"),
            ProtocolVersion::V0,
            trnm_consensus_types::Epoch::new(0),
            ConsensusParametersHash::new([8; 32]),
            vec![
                Validator::new(
                    ValidatorId::new([1; 32]),
                    ConsensusPublicKey::new([32; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
                Validator::new(
                    ValidatorId::new([2; 32]),
                    ConsensusPublicKey::new([34; 32]),
                    VotingPower::new(1).unwrap(),
                )
                .unwrap(),
            ],
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn bindings_with(
        set: &ValidatorSet,
        author: ValidatorId,
        p2p_profile: RemoteSignerProfileRefV1,
        consensus_profile: RemoteSignerProfileRefV1,
        operator_profile: RemoteSignerProfileRefV1,
        p2p_key: u8,
        operator_key: u8,
    ) -> Result<PocoNodeRemoteSignerRoleBindingsV1, RemoteSignerRoleConfigErrorV1> {
        let consensus_key = set
            .validator(author)
            .expect("fixture author belongs to set")
            .consensus_key();
        PocoNodeRemoteSignerRoleBindingsV1::new(
            set,
            P2pIdentityRemoteSignerProfileV1::new(
                p2p_profile,
                endpoint(b"shared-public-endpoint-v1"),
                P2pIdentityPublicKeyV1::new([p2p_key; 32]).unwrap(),
            ),
            ConsensusRemoteSignerProfileV1::new(
                consensus_profile,
                endpoint(b"shared-public-endpoint-v1"),
                author,
                consensus_key,
            )
            .unwrap(),
            OperatorRecoveryRemoteSignerProfileV1::new(
                operator_profile,
                endpoint(b"shared-public-endpoint-v1"),
                OperatorRecoveryPublicKeyV1::new([operator_key; 32]).unwrap(),
            ),
        )
    }

    fn bindings(set: &ValidatorSet) -> PocoNodeRemoteSignerRoleBindingsV1 {
        bindings_with(
            set,
            set.validators()[0].id(),
            profile(b"p2p-public-profile-v1"),
            profile(b"consensus-public-profile-v1"),
            profile(b"operator-public-profile-v1"),
            31,
            33,
        )
        .unwrap()
    }

    fn role_records_offset(encoded: &[u8]) -> usize {
        let author_length = usize::from(u16::from_be_bytes(
            encoded[AUTHOR_LENGTH_OFFSET..AUTHOR_OFFSET]
                .try_into()
                .unwrap(),
        ));
        AUTHOR_OFFSET + author_length
    }

    fn replace_checksum(encoded: &mut [u8]) {
        let checksum_offset = encoded.len() - 32;
        let checksum = checksum_v1(&encoded[..checksum_offset]);
        encoded[checksum_offset..].copy_from_slice(&checksum);
    }

    #[test]
    fn exact_schema_round_trips_and_allows_shared_endpoint_only() {
        let set = validator_set(32);
        let value = bindings(&set);
        let encoded = value.try_exact_bytes().unwrap();
        assert!(encoded.len() <= MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1);
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&encoded, &set).unwrap(),
            value
        );
        assert_eq!(
            value.p2p_identity().endpoint_ref(),
            value.consensus().endpoint_ref()
        );
        assert_eq!(value.purpose_profile_digest(), PURPOSE_PROFILE_DIGEST_V1);
        assert_eq!(
            &encoded[PURPOSE_PROFILE_OFFSET..VALIDATOR_SET_OFFSET],
            &PURPOSE_PROFILE_DIGEST_V1
        );
        const {
            assert!(!REMOTE_SIGNER_RUNTIME_ACTIVATION_V1);
            assert!(!REMOTE_SIGNER_RUNTIME_PRIVATE_KEY_CONFIG_V1);
            assert!(!REMOTE_SIGNER_GENERIC_SIGN_BYTES_V1);
            assert!(!REMOTE_SIGNER_SAFETY_RULES_EVALUATION_V1);
            assert!(!REMOTE_SIGNER_SAFE_VOTE_AUTHORITY_V1);
        }
    }

    #[test]
    fn purpose_taxonomy_and_digest_are_frozen_exactly() {
        let set = validator_set(32);
        let value = bindings(&set);
        assert_eq!(
            value.p2p_identity().purposes(),
            &[
                P2pIdentitySigningPurposeV1::SessionChallenge,
                P2pIdentitySigningPurposeV1::SessionHello,
                P2pIdentitySigningPurposeV1::SessionFinished,
                P2pIdentitySigningPurposeV1::AuthenticatedFrame,
                P2pIdentitySigningPurposeV1::RelayOrigin,
            ]
        );
        assert_eq!(
            value.consensus().purposes(),
            &[
                ConsensusSignerPurposeV1::Vote,
                ConsensusSignerPurposeV1::TimeoutVote,
                ConsensusSignerPurposeV1::Proposal,
                ConsensusSignerPurposeV1::OldSetHandoffVote,
                ConsensusSignerPurposeV1::NewSetHandoffVote,
            ]
        );
        assert_eq!(
            value.operator_recovery().purposes(),
            &[
                OperatorRecoverySigningPurposeV1::RuntimeEvidence,
                OperatorRecoverySigningPurposeV1::RestartControl,
                OperatorRecoverySigningPurposeV1::RecoveryReady,
                OperatorRecoverySigningPurposeV1::RecoveryStart,
            ]
        );
        assert_eq!(purpose_profile_digest_v1(), PURPOSE_PROFILE_DIGEST_V1);

        let mut wrong_purpose_profile = value.try_exact_bytes().unwrap();
        wrong_purpose_profile[PURPOSE_PROFILE_OFFSET] ^= 1;
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&wrong_purpose_profile, &set),
            Err(RemoteSignerRoleConfigErrorV1::PurposeProfileMismatch)
        );
    }

    #[test]
    fn public_descriptor_domains_and_bounds_fail_closed() {
        assert_ne!(
            profile(b"same-public-descriptor").as_bytes(),
            endpoint(b"same-public-descriptor").as_bytes()
        );
        assert_eq!(
            RemoteSignerProfileRefV1::from_public_descriptor(b""),
            Err(RemoteSignerRoleConfigErrorV1::EmptyProfileDescriptor)
        );
        assert_eq!(
            RemoteSignerEndpointRefV1::from_public_descriptor(b""),
            Err(RemoteSignerRoleConfigErrorV1::EmptyEndpointDescriptor)
        );
        assert_eq!(
            RemoteSignerProfileRefV1::from_public_descriptor(&vec![
                1;
                MAX_REMOTE_SIGNER_PROFILE_DESCRIPTOR_BYTES_V1
                    + 1
            ]),
            Err(RemoteSignerRoleConfigErrorV1::ProfileDescriptorTooLarge)
        );
        assert_eq!(
            RemoteSignerEndpointRefV1::from_public_descriptor(&vec![
                1;
                MAX_REMOTE_SIGNER_ENDPOINT_DESCRIPTOR_BYTES_V1
                    + 1
            ]),
            Err(RemoteSignerRoleConfigErrorV1::EndpointDescriptorTooLarge)
        );
        assert_eq!(
            RemoteSignerProfileRefV1::from_exact_digest([0; 32]),
            Err(RemoteSignerRoleConfigErrorV1::ZeroProfileReference)
        );
        assert_eq!(
            RemoteSignerEndpointRefV1::from_exact_digest([0; 32]),
            Err(RemoteSignerRoleConfigErrorV1::ZeroEndpointReference)
        );
    }

    #[test]
    fn zero_keys_and_every_pairwise_role_reuse_fail_closed() {
        assert_eq!(
            P2pIdentityPublicKeyV1::new([0; 32]),
            Err(RemoteSignerRoleConfigErrorV1::ZeroPublicKey(
                RemoteSignerRoleV1::P2pIdentity
            ))
        );

        let set = validator_set(32);
        let p = profile(b"p");
        let c = profile(b"c");
        let o = profile(b"o");
        for result in [
            bindings_with(&set, set.validators()[0].id(), p, p, o, 31, 33),
            bindings_with(&set, set.validators()[0].id(), p, c, p, 31, 33),
            bindings_with(&set, set.validators()[0].id(), p, c, c, 31, 33),
        ] {
            assert_eq!(
                result,
                Err(RemoteSignerRoleConfigErrorV1::DuplicateProfileReference)
            );
        }
        for result in [
            bindings_with(&set, set.validators()[0].id(), p, c, o, 32, 33),
            bindings_with(&set, set.validators()[0].id(), p, c, o, 33, 33),
            bindings_with(&set, set.validators()[0].id(), p, c, o, 31, 32),
        ] {
            assert_eq!(
                result,
                Err(RemoteSignerRoleConfigErrorV1::DuplicatePublicKey)
            );
        }
    }

    #[test]
    fn wrong_consensus_key_set_and_author_are_rejected() {
        let set = validator_set(32);
        let wrong_key = ConsensusRemoteSignerProfileV1::new(
            profile(b"consensus-public-profile-v1"),
            endpoint(b"consensus-public-endpoint-v1"),
            ValidatorId::new([1; 32]),
            ConsensusPublicKey::new([99; 32]),
        )
        .unwrap();
        assert_eq!(
            PocoNodeRemoteSignerRoleBindingsV1::new(
                &set,
                bindings(&set).p2p_identity(),
                wrong_key,
                bindings(&set).operator_recovery(),
            ),
            Err(RemoteSignerRoleConfigErrorV1::ConsensusPublicKeyMismatch)
        );

        let absent_author = ConsensusRemoteSignerProfileV1::new(
            profile(b"consensus-public-profile-v1"),
            endpoint(b"consensus-public-endpoint-v1"),
            ValidatorId::new([2; 32]),
            ConsensusPublicKey::new([32; 32]),
        )
        .unwrap();
        assert_eq!(
            PocoNodeRemoteSignerRoleBindingsV1::new(
                &set,
                bindings(&set).p2p_identity(),
                absent_author,
                bindings(&set).operator_recovery(),
            ),
            Err(RemoteSignerRoleConfigErrorV1::ConsensusAuthorAbsent)
        );

        let other_set = validator_set(42);
        let encoded = bindings(&set).try_exact_bytes().unwrap();
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&encoded, &other_set),
            Err(RemoteSignerRoleConfigErrorV1::ValidatorSetMismatch)
        );
    }

    #[test]
    fn exact_decoder_rejects_magic_schema_id_lengths_and_every_role_tag() {
        let set = validator_set(32);
        let encoded = bindings(&set).try_exact_bytes().unwrap();

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&bad_magic, &set),
            Err(RemoteSignerRoleConfigErrorV1::InvalidMagic)
        );

        let mut bad_schema = encoded.clone();
        bad_schema[SCHEMA_OFFSET..PURPOSE_PROFILE_OFFSET].copy_from_slice(&2u16.to_be_bytes());
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&bad_schema, &set),
            Err(RemoteSignerRoleConfigErrorV1::InvalidSchemaVersion(2))
        );

        let mut zero_author_length = encoded.clone();
        zero_author_length[AUTHOR_LENGTH_OFFSET..AUTHOR_OFFSET]
            .copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&zero_author_length, &set),
            Err(RemoteSignerRoleConfigErrorV1::InvalidValidatorIdLength)
        );
        let mut oversized_author_length = encoded.clone();
        oversized_author_length[AUTHOR_LENGTH_OFFSET..AUTHOR_OFFSET]
            .copy_from_slice(&129u16.to_be_bytes());
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&oversized_author_length, &set),
            Err(RemoteSignerRoleConfigErrorV1::InvalidValidatorIdLength)
        );

        let role_offset = role_records_offset(&encoded);
        for (index, expected) in [
            RemoteSignerRoleV1::P2pIdentity,
            RemoteSignerRoleV1::Consensus,
            RemoteSignerRoleV1::OperatorRecoveryControl,
        ]
        .into_iter()
        .enumerate()
        {
            let mut bad_tag = encoded.clone();
            bad_tag[role_offset + (index * ROLE_RECORD_BYTES_V1)] = expected.tag() ^ 0x80;
            assert_eq!(
                decode_remote_signer_role_bindings_v1_exact(&bad_tag, &set),
                Err(RemoteSignerRoleConfigErrorV1::InvalidRoleTag)
            );
        }
    }

    #[test]
    fn exact_decoder_rejects_mutation_truncation_trailing_and_oversize() {
        let set = validator_set(32);
        let encoded = bindings(&set).try_exact_bytes().unwrap();

        let mut bad_checksum = encoded.clone();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&bad_checksum, &set),
            Err(RemoteSignerRoleConfigErrorV1::ChecksumMismatch)
        );
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&encoded[..encoded.len() - 1], &set),
            Err(RemoteSignerRoleConfigErrorV1::TruncatedEncoding)
        );

        let mut body_mutation = encoded.clone();
        let p2p_endpoint_offset = role_records_offset(&encoded) + 1 + 32;
        body_mutation[p2p_endpoint_offset] ^= 1;
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&body_mutation, &set),
            Err(RemoteSignerRoleConfigErrorV1::ChecksumMismatch)
        );

        let mut recomputed_semantic_mutation = encoded.clone();
        let consensus_key_offset =
            role_records_offset(&encoded) + ROLE_RECORD_BYTES_V1 + 1 + 32 + 32;
        recomputed_semantic_mutation[consensus_key_offset] ^= 1;
        replace_checksum(&mut recomputed_semantic_mutation);
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&recomputed_semantic_mutation, &set),
            Err(RemoteSignerRoleConfigErrorV1::ConsensusPublicKeyMismatch)
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&trailing, &set),
            Err(RemoteSignerRoleConfigErrorV1::TrailingBytes)
        );

        let mut oversized = encoded;
        oversized.resize(MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1 + 1, 0);
        assert_eq!(
            decode_remote_signer_role_bindings_v1_exact(&oversized, &set),
            Err(RemoteSignerRoleConfigErrorV1::EncodingTooLarge)
        );
    }

    #[test]
    fn minimum_and_maximum_validator_ids_round_trip_at_exact_bounds() {
        for (author, expected_maximum) in [
            (ValidatorId::from_bytes(&[1]).unwrap(), false),
            (
                ValidatorId::from_bytes(&[0x41; trnm_consensus_types::MAX_VALIDATOR_ID_BYTES])
                    .unwrap(),
                true,
            ),
        ] {
            let set = validator_set_for_author(author, 32);
            let encoded = bindings(&set).try_exact_bytes().unwrap();
            assert_eq!(
                encoded.len() == MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1,
                expected_maximum
            );
            assert_eq!(
                decode_remote_signer_role_bindings_v1_exact(&encoded, &set)
                    .unwrap()
                    .local_validator(),
                author
            );
        }
    }

    #[test]
    fn vote_and_timeout_commands_cannot_cross_kinds_or_authors() {
        let set = validator_set(32);
        let roles = bindings(&set);
        let vote = CanonicalSignIntentV0::vote(
            &set,
            roles.local_validator(),
            1,
            View::new(1),
            Height::new(1),
            BlockId::new([41; 32]),
        )
        .unwrap();
        assert_eq!(
            ConsensusVoteSignCommandV1::new(&vote, &set, &roles)
                .unwrap()
                .signing_root(),
            vote.signing_root()
        );
        assert!(matches!(
            ConsensusTimeoutSignCommandV1::new(&vote, &set, &roles),
            Err(RemoteSignerRoleConfigErrorV1::WrongConsensusCommandKind)
        ));

        let high_qc = QcRef::new(
            trnm_consensus_types::CertificateId::new([51; 32]),
            set.epoch(),
            View::new(0),
            Height::new(0),
            BlockId::new([52; 32]),
            set.id(),
        );
        let timeout = CanonicalSignIntentV0::timeout_vote(
            &set,
            roles.local_validator(),
            2,
            View::new(2),
            high_qc,
        )
        .unwrap();
        assert!(ConsensusTimeoutSignCommandV1::new(&timeout, &set, &roles).is_ok());
        assert!(matches!(
            ConsensusVoteSignCommandV1::new(&timeout, &set, &roles),
            Err(RemoteSignerRoleConfigErrorV1::WrongConsensusCommandKind)
        ));

        let two_set = two_validator_set();
        let roles = bindings(&two_set);
        let other_author_vote = CanonicalSignIntentV0::vote(
            &two_set,
            two_set.validators()[1].id(),
            3,
            View::new(3),
            Height::new(1),
            BlockId::new([61; 32]),
        )
        .unwrap();
        assert!(matches!(
            ConsensusVoteSignCommandV1::new(&other_author_vote, &two_set, &roles),
            Err(RemoteSignerRoleConfigErrorV1::ConsensusAuthorMismatch)
        ));
    }

    #[test]
    fn production_boundary_source_excludes_secret_material_and_generic_byte_signer() {
        let source = include_str!("remote_signer_roles_v1.rs");
        let forbidden = [
            concat!("Signing", "Key"),
            concat!("from_", "pkcs8"),
            concat!("secret", "_key"),
            concat!("private", "_key"),
            concat!("fn sign", "(&mut self, bytes"),
            concat!("ConsensusProposal", "SignCommandV1"),
            concat!("pub fn into_", "bytes"),
        ];
        for token in forbidden {
            assert!(
                !source.contains(token),
                "forbidden private-key boundary token: {token}"
            );
        }
    }
}
