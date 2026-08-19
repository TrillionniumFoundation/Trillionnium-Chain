//! Inert, data-only mapping from the Node signer-role profile to remote-signer
//! protocol schema 1.
//!
//! The Node role profile and the remote-signer protocol deliberately use
//! different hash domains and different taxonomies. The Node profile also
//! discards the public descriptors used to derive its references. This module
//! therefore never compares those references for equality, never attempts to
//! recover a descriptor, and never claims descriptor equivalence. Instead it
//! binds the complete canonical Node role-profile bytes to three explicit
//! protocol-local public references and to the protocol's frozen Vote/Timeout
//! purpose digest.
//!
//! Only the semantic pairs `Vote -> Vote` and `TimeoutVote -> TimeoutVote` are
//! recorded. Node Proposal, old/new handoff, P2P, and operator/recovery
//! purposes have no mapping here. Constructing or decoding the record grants
//! no request, lease, process generation, checkpoint, SafetyRules, signer, or
//! runtime authority.
//!
//! A future Node request-binding constructor must consume a freshly decoded,
//! exact stored [`PocoNodeRemoteSignerProtocolAdapterV1`] and obtain all three
//! protocol references from it. Accepting the same three bare public
//! references as an alternative input would create a second configuration
//! source and is forbidden. This tranche intentionally provides no such
//! request-binding constructor.
//!
//! The protocol crate itself remains Node-independent and correctly continues
//! to report that it contains no in-crate Node adapter. This module is the
//! one-way external adapter owned by the Node crate; it introduces no reverse
//! dependency and does not turn the two packages into an authority source.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};
use trnm_consensus_remote_signer_protocol::{
    vote_timeout_purpose_profile_digest_v1, RemoteConsensusCommandKindV1,
    RemoteSignerClientProfileRefV1, RemoteSignerPurposeProfileDigestV1,
    RemoteSignerRoleProfileRefV1, RemoteSignerServiceProfileRefV1, REMOTE_SIGNER_REQUEST_SCHEMA_V1,
};
use trnm_consensus_types::{ValidatorId, ValidatorSet, ValidatorSetId};

use crate::remote_signer_roles_v1::{
    decode_remote_signer_role_bindings_v1_exact, ConsensusSignerPurposeV1,
    PocoNodeRemoteSignerRoleBindingsV1, RemoteSignerEndpointRefV1, RemoteSignerProfileRefV1,
    RemoteSignerRoleConfigErrorV1, MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1,
};

const ADAPTER_MAGIC_V1: &[u8; 8] = b"TRNMRA01";
const ADAPTER_CHECKSUM_DOMAIN_V1: &[u8] = b"trnm.poco-node.remote-signer-protocol-adapter.v1\0";
const ADAPTER_MAPPING_COUNT_V1: u16 = 2;
const ADAPTER_NODE_VOTE_TAG_V1: u8 = 0;
const ADAPTER_PROTOCOL_VOTE_TAG_V1: u8 = 0;
const ADAPTER_NODE_TIMEOUT_VOTE_TAG_V1: u8 = 1;
const ADAPTER_PROTOCOL_TIMEOUT_VOTE_TAG_V1: u8 = 1;
const ADAPTER_CHECKSUM_BYTES_V1: usize = 32;
const FIXED_ADAPTER_BYTES_EXCLUDING_NODE_AND_VALIDATOR_ID_V1: usize = ADAPTER_MAGIC_V1.len()
        + 2
        + 4
        // Node profile checksum, validator-set ID, Node purpose profile,
        // Node consensus profile/endpoint refs, protocol purpose profile,
        // protocol role/service/client refs.
        + (32 * 9)
        + 2
        + 2
        + 2
        + 4
        + ADAPTER_CHECKSUM_BYTES_V1;

/// Frozen exact-encoding schema for the inert Node-to-protocol adapter.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_SCHEMA_V1: u16 = 1;

/// Maximum exact adapter bytes, including maximum Node bindings and validator
/// ID encodings.
pub const MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1: usize =
    FIXED_ADAPTER_BYTES_EXCLUDING_NODE_AND_VALIDATOR_ID_V1
        + MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1
        + trnm_consensus_types::MAX_VALIDATOR_ID_BYTES;

/// The two source descriptor domains are not equivalent and their discarded
/// descriptor preimages cannot be recovered by this adapter.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_DESCRIPTOR_EQUIVALENCE_V1: bool = false;

/// No authenticated resolver attests that Node and protocol references name
/// the same external service configuration.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_RESOLVER_ATTESTATION_V1: bool = false;

/// This mapping does not evaluate locked-QC or any HotStuff SafetyRules state.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_SAFETY_RULES_V1: bool = false;

/// This mapping does not acquire, transfer, or activate a signer lease.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_LEASE_AUTHORITY_V1: bool = false;

/// This mapping cannot construct or authorize a remote-signer request.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_REQUEST_AUTHORITY_V1: bool = false;

/// Bare protocol refs are not an alternative Node request-binding source. A
/// later binding constructor must consume the exact decoded adapter instead.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_BARE_REF_BINDING_SOURCE_V1: bool = false;

/// Outside this module, the typed adapter cannot be constructed directly from
/// bare refs. Authoring produces bytes; only strict exact decoding yields the
/// typed value.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_DIRECT_CONSTRUCTOR_V1: bool = false;

/// No Node runtime consumes this adapter in this tranche.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_RUNTIME_ACTIVATION_V1: bool = false;

/// The adapter is not a production consensus capability.
pub const REMOTE_SIGNER_PROTOCOL_ADAPTER_PRODUCTION_ACTIVATION_V1: bool = false;

/// Exact, inactive mapping between one complete Node role binding and the
/// protocol schema-1 Vote/Timeout profile.
///
/// This is configuration data, not an authority token. It is deliberately not
/// `Clone` or `Copy`; that representation choice does not make the value
/// unforgeable or grant it runtime meaning.
#[derive(Debug, PartialEq, Eq)]
pub struct PocoNodeRemoteSignerProtocolAdapterV1 {
    node_role_bindings_exact: Vec<u8>,
    node_profile_checksum: [u8; 32],
    validator_set_id: ValidatorSetId,
    local_validator: ValidatorId,
    node_purpose_profile_digest: [u8; 32],
    node_consensus_profile_ref: RemoteSignerProfileRefV1,
    node_consensus_endpoint_ref: RemoteSignerEndpointRefV1,
    protocol_request_schema: u16,
    protocol_purpose_profile_digest: RemoteSignerPurposeProfileDigestV1,
    protocol_role_profile_ref: RemoteSignerRoleProfileRefV1,
    protocol_service_profile_ref: RemoteSignerServiceProfileRefV1,
    protocol_client_profile_ref: RemoteSignerClientProfileRefV1,
    adapter_checksum: [u8; 32],
}

impl PocoNodeRemoteSignerProtocolAdapterV1 {
    /// Creates an inert exact mapping. The complete Node role binding is
    /// freshly decoded against `validator_set` before any fields are retained.
    fn new(
        validator_set: &ValidatorSet,
        node_role_bindings: &PocoNodeRemoteSignerRoleBindingsV1,
        protocol_role_profile_ref: RemoteSignerRoleProfileRefV1,
        protocol_service_profile_ref: RemoteSignerServiceProfileRefV1,
        protocol_client_profile_ref: RemoteSignerClientProfileRefV1,
    ) -> Result<Self, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        let node_role_bindings_exact = node_role_bindings
            .try_exact_bytes()
            .map_err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeRoleBindings)?;
        let freshly_decoded =
            decode_remote_signer_role_bindings_v1_exact(&node_role_bindings_exact, validator_set)
                .map_err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeRoleBindings)?;
        if &freshly_decoded != node_role_bindings {
            return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactNodeRoleBindingsMismatch);
        }

        let consensus = freshly_decoded.consensus();
        let mut value = Self {
            node_role_bindings_exact,
            node_profile_checksum: freshly_decoded.profile_checksum(),
            validator_set_id: freshly_decoded.validator_set_id(),
            local_validator: freshly_decoded.local_validator(),
            node_purpose_profile_digest: freshly_decoded.purpose_profile_digest(),
            node_consensus_profile_ref: consensus.profile_ref(),
            node_consensus_endpoint_ref: consensus.endpoint_ref(),
            protocol_request_schema: REMOTE_SIGNER_REQUEST_SCHEMA_V1,
            protocol_purpose_profile_digest: vote_timeout_purpose_profile_digest_v1(),
            protocol_role_profile_ref,
            protocol_service_profile_ref,
            protocol_client_profile_ref,
            adapter_checksum: [0; 32],
        };
        value.adapter_checksum = adapter_checksum_v1(&value.encode_without_checksum());
        Ok(value)
    }

    /// Complete canonical Node role-binding bytes, including P2P and
    /// operator/recovery roles. Their presence binds the source configuration;
    /// it does not map those roles into the protocol.
    pub fn node_role_bindings_exact(&self) -> &[u8] {
        &self.node_role_bindings_exact
    }

    pub const fn node_profile_checksum(&self) -> [u8; 32] {
        self.node_profile_checksum
    }

    pub const fn validator_set_id(&self) -> ValidatorSetId {
        self.validator_set_id
    }

    pub const fn local_validator(&self) -> ValidatorId {
        self.local_validator
    }

    pub const fn node_purpose_profile_digest(&self) -> [u8; 32] {
        self.node_purpose_profile_digest
    }

    pub const fn node_consensus_profile_ref(&self) -> RemoteSignerProfileRefV1 {
        self.node_consensus_profile_ref
    }

    pub const fn node_consensus_endpoint_ref(&self) -> RemoteSignerEndpointRefV1 {
        self.node_consensus_endpoint_ref
    }

    pub const fn protocol_request_schema(&self) -> u16 {
        self.protocol_request_schema
    }

    pub const fn protocol_purpose_profile_digest(&self) -> RemoteSignerPurposeProfileDigestV1 {
        self.protocol_purpose_profile_digest
    }

    /// Public protocol role reference retained by the exact adapter. A future
    /// Node binding path must obtain this from the freshly decoded adapter, not
    /// accept a caller-supplied bare reference as an alternative source.
    pub const fn protocol_role_profile_ref(&self) -> RemoteSignerRoleProfileRefV1 {
        self.protocol_role_profile_ref
    }

    /// Public protocol service reference retained by the exact adapter.
    pub const fn protocol_service_profile_ref(&self) -> RemoteSignerServiceProfileRefV1 {
        self.protocol_service_profile_ref
    }

    /// Public protocol client reference retained by the exact adapter.
    pub const fn protocol_client_profile_ref(&self) -> RemoteSignerClientProfileRefV1 {
        self.protocol_client_profile_ref
    }

    pub const fn adapter_checksum(&self) -> [u8; 32] {
        self.adapter_checksum
    }

    /// Returns the only protocol command kind mapped from one Node consensus
    /// purpose. Proposal and both handoff purposes always return `None`.
    pub const fn mapped_protocol_command_kind(
        &self,
        purpose: ConsensusSignerPurposeV1,
    ) -> Option<RemoteConsensusCommandKindV1> {
        match purpose {
            ConsensusSignerPurposeV1::Vote => Some(RemoteConsensusCommandKindV1::Vote),
            ConsensusSignerPurposeV1::TimeoutVote => {
                Some(RemoteConsensusCommandKindV1::TimeoutVote)
            }
            ConsensusSignerPurposeV1::Proposal
            | ConsensusSignerPurposeV1::OldSetHandoffVote
            | ConsensusSignerPurposeV1::NewSetHandoffVote => None,
        }
    }

    pub fn try_exact_bytes(&self) -> Result<Vec<u8>, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        let mut encoded = self.encode_without_checksum();
        encoded.extend_from_slice(&self.adapter_checksum);
        if encoded.len() > MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1 {
            return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::EncodingTooLarge);
        }
        Ok(encoded)
    }

    fn encode_without_checksum(&self) -> Vec<u8> {
        let validator_id = self.local_validator.as_bytes();
        let mut encoded = Vec::with_capacity(
            FIXED_ADAPTER_BYTES_EXCLUDING_NODE_AND_VALIDATOR_ID_V1
                + self.node_role_bindings_exact.len()
                + validator_id.len()
                - ADAPTER_CHECKSUM_BYTES_V1,
        );
        encoded.extend_from_slice(ADAPTER_MAGIC_V1);
        encoded.extend_from_slice(&REMOTE_SIGNER_PROTOCOL_ADAPTER_SCHEMA_V1.to_be_bytes());
        encoded.extend_from_slice(
            &u32::try_from(self.node_role_bindings_exact.len())
                .expect("bounded Node role binding length fits u32")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(&self.node_role_bindings_exact);
        encoded.extend_from_slice(&self.node_profile_checksum);
        encoded.extend_from_slice(self.validator_set_id.as_bytes());
        encoded.extend_from_slice(
            &u16::try_from(validator_id.len())
                .expect("bounded validator ID length fits u16")
                .to_be_bytes(),
        );
        encoded.extend_from_slice(validator_id);
        encoded.extend_from_slice(&self.node_purpose_profile_digest);
        encoded.extend_from_slice(self.node_consensus_profile_ref.as_bytes());
        encoded.extend_from_slice(self.node_consensus_endpoint_ref.as_bytes());
        encoded.extend_from_slice(&self.protocol_request_schema.to_be_bytes());
        encoded.extend_from_slice(self.protocol_purpose_profile_digest.as_bytes());
        encoded.extend_from_slice(self.protocol_role_profile_ref.as_bytes());
        encoded.extend_from_slice(self.protocol_service_profile_ref.as_bytes());
        encoded.extend_from_slice(self.protocol_client_profile_ref.as_bytes());
        encoded.extend_from_slice(&ADAPTER_MAPPING_COUNT_V1.to_be_bytes());
        encoded.extend_from_slice(&[
            ADAPTER_NODE_VOTE_TAG_V1,
            ADAPTER_PROTOCOL_VOTE_TAG_V1,
            ADAPTER_NODE_TIMEOUT_VOTE_TAG_V1,
            ADAPTER_PROTOCOL_TIMEOUT_VOTE_TAG_V1,
        ]);
        encoded
    }
}

/// Authors canonical adapter bytes without releasing a typed adapter value.
/// This is configuration serialization only. It grants no resolver, request,
/// lease, signer, or runtime authority; strict decoding against all expected
/// inputs is still required before a future Node path may retain the mapping.
pub fn prepare_remote_signer_protocol_adapter_v1_exact(
    validator_set: &ValidatorSet,
    node_role_bindings: &PocoNodeRemoteSignerRoleBindingsV1,
    protocol_role_profile_ref: RemoteSignerRoleProfileRefV1,
    protocol_service_profile_ref: RemoteSignerServiceProfileRefV1,
    protocol_client_profile_ref: RemoteSignerClientProfileRefV1,
) -> Result<Vec<u8>, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
    PocoNodeRemoteSignerProtocolAdapterV1::new(
        validator_set,
        node_role_bindings,
        protocol_role_profile_ref,
        protocol_service_profile_ref,
        protocol_client_profile_ref,
    )?
    .try_exact_bytes()
}

/// Strict exact decoder. All expected identities are supplied out of band so
/// that a different, internally valid Node profile or different protocol refs
/// cannot replace the configured mapping merely by recomputing its checksum.
pub fn decode_remote_signer_protocol_adapter_v1_exact(
    encoded: &[u8],
    validator_set: &ValidatorSet,
    expected_node_role_bindings: &PocoNodeRemoteSignerRoleBindingsV1,
    expected_protocol_role_profile_ref: RemoteSignerRoleProfileRefV1,
    expected_protocol_service_profile_ref: RemoteSignerServiceProfileRefV1,
    expected_protocol_client_profile_ref: RemoteSignerClientProfileRefV1,
) -> Result<PocoNodeRemoteSignerProtocolAdapterV1, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
    if encoded.len() > MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1 {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::EncodingTooLarge);
    }
    if encoded.len() < FIXED_ADAPTER_BYTES_EXCLUDING_NODE_AND_VALIDATOR_ID_V1 + 2 {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding);
    }

    let mut cursor = AdapterDecoderCursorV1::new(encoded);
    if cursor.take(ADAPTER_MAGIC_V1.len())? != ADAPTER_MAGIC_V1 {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidMagic);
    }
    let schema = cursor.u16()?;
    if schema != REMOTE_SIGNER_PROTOCOL_ADAPTER_SCHEMA_V1 {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidSchemaVersion(schema));
    }

    let node_role_bindings_length = usize::try_from(cursor.u32()?)
        .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidNodeRoleBindingsLength)?;
    if node_role_bindings_length == 0
        || node_role_bindings_length > MAX_REMOTE_SIGNER_ROLE_BINDINGS_BYTES_V1
    {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidNodeRoleBindingsLength);
    }
    let node_role_bindings_exact = cursor.take(node_role_bindings_length)?;
    let supplied_node_profile_checksum = cursor.array32()?;
    let supplied_validator_set_id = ValidatorSetId::new(cursor.array32()?);
    let local_validator_length = usize::from(cursor.u16()?);
    if local_validator_length == 0
        || local_validator_length > trnm_consensus_types::MAX_VALIDATOR_ID_BYTES
    {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidLocalValidatorLength);
    }
    let supplied_local_validator = ValidatorId::from_bytes(cursor.take(local_validator_length)?)
        .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidLocalValidatorLength)?;
    let supplied_node_purpose_profile_digest = cursor.array32()?;
    let supplied_node_consensus_profile_ref = cursor.array32()?;
    let supplied_node_consensus_endpoint_ref = cursor.array32()?;
    let supplied_protocol_request_schema = cursor.u16()?;
    let supplied_protocol_purpose_profile_digest = cursor.array32()?;
    let supplied_protocol_role_profile_ref = cursor.array32()?;
    let supplied_protocol_service_profile_ref = cursor.array32()?;
    let supplied_protocol_client_profile_ref = cursor.array32()?;
    let supplied_mapping_count = cursor.u16()?;
    let supplied_mapping_rows = cursor.array4()?;
    let checksum_offset = cursor.position();
    let supplied_adapter_checksum = cursor.array32()?;
    if !cursor.is_finished() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::TrailingBytes);
    }
    if adapter_checksum_v1(&encoded[..checksum_offset]) != supplied_adapter_checksum {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ChecksumMismatch);
    }

    let expected_node_exact = expected_node_role_bindings
        .try_exact_bytes()
        .map_err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeRoleBindings)?;
    if node_role_bindings_exact != expected_node_exact.as_slice() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactNodeRoleBindingsMismatch);
    }
    let decoded_node_role_bindings =
        decode_remote_signer_role_bindings_v1_exact(node_role_bindings_exact, validator_set)
            .map_err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeRoleBindings)?;
    if &decoded_node_role_bindings != expected_node_role_bindings {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactNodeRoleBindingsMismatch);
    }
    let decoded_consensus = decoded_node_role_bindings.consensus();
    if supplied_node_profile_checksum != decoded_node_role_bindings.profile_checksum() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeProfileChecksumMismatch);
    }
    if supplied_validator_set_id != decoded_node_role_bindings.validator_set_id() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ValidatorSetMismatch);
    }
    if supplied_local_validator != decoded_node_role_bindings.local_validator() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::LocalValidatorMismatch);
    }
    if supplied_node_purpose_profile_digest != decoded_node_role_bindings.purpose_profile_digest() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodePurposeProfileMismatch);
    }
    if supplied_node_consensus_profile_ref != *decoded_consensus.profile_ref().as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeConsensusProfileRefMismatch);
    }
    if supplied_node_consensus_endpoint_ref != *decoded_consensus.endpoint_ref().as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeConsensusEndpointRefMismatch);
    }

    if supplied_protocol_request_schema != REMOTE_SIGNER_REQUEST_SCHEMA_V1 {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolSchemaMismatch);
    }
    let protocol_purpose_profile_digest = vote_timeout_purpose_profile_digest_v1();
    if supplied_protocol_purpose_profile_digest != *protocol_purpose_profile_digest.as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolPurposeProfileMismatch);
    }
    if supplied_protocol_role_profile_ref != *expected_protocol_role_profile_ref.as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolRoleProfileRefMismatch);
    }
    if supplied_protocol_service_profile_ref != *expected_protocol_service_profile_ref.as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolServiceProfileRefMismatch);
    }
    if supplied_protocol_client_profile_ref != *expected_protocol_client_profile_ref.as_bytes() {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolClientProfileRefMismatch);
    }
    if supplied_mapping_count != ADAPTER_MAPPING_COUNT_V1
        || supplied_mapping_rows
            != [
                ADAPTER_NODE_VOTE_TAG_V1,
                ADAPTER_PROTOCOL_VOTE_TAG_V1,
                ADAPTER_NODE_TIMEOUT_VOTE_TAG_V1,
                ADAPTER_PROTOCOL_TIMEOUT_VOTE_TAG_V1,
            ]
    {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::PurposeMappingMismatch);
    }

    let value = PocoNodeRemoteSignerProtocolAdapterV1::new(
        validator_set,
        expected_node_role_bindings,
        expected_protocol_role_profile_ref,
        expected_protocol_service_profile_ref,
        expected_protocol_client_profile_ref,
    )?;
    if value.adapter_checksum() != supplied_adapter_checksum
        || value.try_exact_bytes()?.as_slice() != encoded
    {
        return Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactMappingMismatch);
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PocoNodeRemoteSignerProtocolAdapterErrorV1 {
    NodeRoleBindings(RemoteSignerRoleConfigErrorV1),
    InvalidMagic,
    InvalidSchemaVersion(u16),
    InvalidNodeRoleBindingsLength,
    InvalidLocalValidatorLength,
    TruncatedEncoding,
    TrailingBytes,
    EncodingTooLarge,
    ChecksumMismatch,
    ExactNodeRoleBindingsMismatch,
    NodeProfileChecksumMismatch,
    ValidatorSetMismatch,
    LocalValidatorMismatch,
    NodePurposeProfileMismatch,
    NodeConsensusProfileRefMismatch,
    NodeConsensusEndpointRefMismatch,
    ProtocolSchemaMismatch,
    ProtocolPurposeProfileMismatch,
    ProtocolRoleProfileRefMismatch,
    ProtocolServiceProfileRefMismatch,
    ProtocolClientProfileRefMismatch,
    PurposeMappingMismatch,
    ExactMappingMismatch,
}

impl fmt::Display for PocoNodeRemoteSignerProtocolAdapterErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NodeRoleBindings(error) => {
                write!(
                    formatter,
                    "Node remote-signer role bindings differ: {error}"
                )
            }
            Self::InvalidMagic => {
                formatter.write_str("remote-signer protocol adapter magic differs")
            }
            Self::InvalidSchemaVersion(actual) => write!(
                formatter,
                "unsupported remote-signer protocol adapter schema {actual}"
            ),
            Self::InvalidNodeRoleBindingsLength => {
                formatter.write_str("Node role-bindings length is invalid")
            }
            Self::InvalidLocalValidatorLength => {
                formatter.write_str("adapter local-validator length is invalid")
            }
            Self::TruncatedEncoding => {
                formatter.write_str("remote-signer protocol adapter is truncated")
            }
            Self::TrailingBytes => {
                formatter.write_str("remote-signer protocol adapter has trailing bytes")
            }
            Self::EncodingTooLarge => {
                formatter.write_str("remote-signer protocol adapter exceeds its bound")
            }
            Self::ChecksumMismatch => {
                formatter.write_str("remote-signer protocol adapter checksum differs")
            }
            Self::ExactNodeRoleBindingsMismatch => {
                formatter.write_str("exact Node role bindings differ from the expected profile")
            }
            Self::NodeProfileChecksumMismatch => {
                formatter.write_str("explicit Node role-profile checksum differs")
            }
            Self::ValidatorSetMismatch => formatter.write_str("adapter validator-set ID differs"),
            Self::LocalValidatorMismatch => formatter.write_str("adapter local validator differs"),
            Self::NodePurposeProfileMismatch => {
                formatter.write_str("adapter Node purpose profile differs")
            }
            Self::NodeConsensusProfileRefMismatch => {
                formatter.write_str("adapter Node consensus profile reference differs")
            }
            Self::NodeConsensusEndpointRefMismatch => {
                formatter.write_str("adapter Node consensus endpoint reference differs")
            }
            Self::ProtocolSchemaMismatch => {
                formatter.write_str("adapter remote-signer request schema differs")
            }
            Self::ProtocolPurposeProfileMismatch => {
                formatter.write_str("adapter protocol purpose profile differs")
            }
            Self::ProtocolRoleProfileRefMismatch => {
                formatter.write_str("adapter protocol role-profile reference differs")
            }
            Self::ProtocolServiceProfileRefMismatch => {
                formatter.write_str("adapter protocol service-profile reference differs")
            }
            Self::ProtocolClientProfileRefMismatch => {
                formatter.write_str("adapter protocol client-profile reference differs")
            }
            Self::PurposeMappingMismatch => {
                formatter.write_str("adapter Vote/Timeout mapping differs")
            }
            Self::ExactMappingMismatch => {
                formatter.write_str("adapter exact bytes differ from the expected mapping")
            }
        }
    }
}

impl Error for PocoNodeRemoteSignerProtocolAdapterErrorV1 {}

fn adapter_checksum_v1(encoded_without_checksum: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(ADAPTER_CHECKSUM_DOMAIN_V1);
    hash.update(encoded_without_checksum);
    hash.finalize().into()
}

struct AdapterDecoderCursorV1<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> AdapterDecoderCursorV1<'a> {
    const fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
    ) -> Result<&'a [u8], PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or(PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        let bytes = self
            .take(2)?
            .try_into()
            .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        let bytes = self
            .take(4)?
            .try_into()
            .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn array4(&mut self) -> Result<[u8; 4], PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        self.take(4)?
            .try_into()
            .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)
    }

    fn array32(&mut self) -> Result<[u8; 32], PocoNodeRemoteSignerProtocolAdapterErrorV1> {
        self.take(32)?
            .try_into()
            .map_err(|_| PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)
    }

    const fn position(&self) -> usize {
        self.offset
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.encoded.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_signer_roles_v1::{
        ConsensusRemoteSignerProfileV1, OperatorRecoveryPublicKeyV1,
        OperatorRecoveryRemoteSignerProfileV1, P2pIdentityPublicKeyV1,
        P2pIdentityRemoteSignerProfileV1,
    };
    use trnm_consensus_remote_signer_protocol::{
        RemoteSignerClientProfileRefV1, RemoteSignerRoleProfileRefV1,
        RemoteSignerServiceProfileRefV1,
    };
    use trnm_consensus_types::{
        ChainId, ConsensusParametersHash, ConsensusPublicKey, Epoch, GenesisHash, ProtocolVersion,
        Validator, VotingPower,
    };

    const PROTOCOL_PURPOSE_PROFILE_GOLDEN_V1: [u8; 32] = [
        0x56, 0x11, 0xbc, 0xe3, 0xe7, 0x3e, 0x29, 0x4a, 0xa4, 0xfe, 0xce, 0xf8, 0x42, 0xf6, 0xbe,
        0xcd, 0x05, 0x1e, 0x53, 0xc2, 0xbb, 0x62, 0x00, 0x13, 0xf8, 0x4a, 0x9a, 0x17, 0x25, 0xe8,
        0x3e, 0xf4,
    ];
    const NODE_PURPOSE_PROFILE_GOLDEN_V1: [u8; 32] = [
        0xdc, 0x71, 0x93, 0xba, 0x02, 0x6a, 0x89, 0x8f, 0xb0, 0x36, 0xce, 0x8b, 0x29, 0x41, 0x2d,
        0x98, 0x33, 0x4b, 0x10, 0x2e, 0xe2, 0x52, 0xe9, 0x2b, 0x6d, 0x4d, 0x0a, 0x3b, 0x5a, 0xdd,
        0x28, 0xc0,
    ];
    const ADAPTER_EXACT_BYTES_GOLDEN_LENGTH_V1: usize = 807;
    const ADAPTER_CHECKSUM_GOLDEN_V1: [u8; 32] = [
        0x5d, 0xf0, 0xfa, 0xfe, 0x1a, 0xd5, 0x02, 0xf4, 0x47, 0x7d, 0x1c, 0xca, 0xe7, 0x68, 0x65,
        0xed, 0x4d, 0x1d, 0x94, 0x7d, 0x4e, 0xe1, 0x08, 0x1f, 0xda, 0xcd, 0x31, 0x3d, 0x45, 0x71,
        0xdd, 0xf8,
    ];
    const ADAPTER_EXACT_SHA256_GOLDEN_V1: [u8; 32] = [
        0xbf, 0x7c, 0x5f, 0xea, 0x04, 0x77, 0xfa, 0xb7, 0xf4, 0x6d, 0x6f, 0xc5, 0x3d, 0x65, 0x8b,
        0x7a, 0x9e, 0xec, 0x2a, 0x3d, 0xbb, 0xbd, 0xe3, 0x66, 0x25, 0x3e, 0x8d, 0xfa, 0x46, 0x40,
        0x48, 0xab,
    ];

    #[derive(Clone, Copy)]
    struct ProtocolRefsV1 {
        role: RemoteSignerRoleProfileRefV1,
        service: RemoteSignerServiceProfileRefV1,
        client: RemoteSignerClientProfileRefV1,
    }

    #[derive(Clone, Copy)]
    struct AdapterOffsetsV1 {
        node_length: usize,
        node_exact: usize,
        node_profile_checksum: usize,
        validator_set_id: usize,
        local_validator_length: usize,
        local_validator: usize,
        node_purpose_profile: usize,
        node_consensus_profile: usize,
        node_consensus_endpoint: usize,
        protocol_schema: usize,
        protocol_purpose_profile: usize,
        protocol_role: usize,
        protocol_service: usize,
        protocol_client: usize,
        mapping_count: usize,
        mapping_rows: usize,
        checksum: usize,
    }

    fn validator_set() -> ValidatorSet {
        ValidatorSet::new(
            GenesisHash::new([7; 32]),
            ChainId::from_static("trnm-node-remote-protocol-adapter-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            ConsensusParametersHash::new([8; 32]),
            vec![Validator::new(
                ValidatorId::new([1; 32]),
                ConsensusPublicKey::new([32; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    fn node_profile(descriptor: &[u8]) -> RemoteSignerProfileRefV1 {
        RemoteSignerProfileRefV1::from_public_descriptor(descriptor).unwrap()
    }

    fn node_endpoint(descriptor: &[u8]) -> RemoteSignerEndpointRefV1 {
        RemoteSignerEndpointRefV1::from_public_descriptor(descriptor).unwrap()
    }

    fn node_role_bindings(
        set: &ValidatorSet,
        suffix: &[u8],
        p2p_key: u8,
        operator_key: u8,
    ) -> PocoNodeRemoteSignerRoleBindingsV1 {
        let mut p2p_descriptor = b"adapter-p2p-profile-".to_vec();
        p2p_descriptor.extend_from_slice(suffix);
        let mut consensus_descriptor = b"adapter-consensus-profile-".to_vec();
        consensus_descriptor.extend_from_slice(suffix);
        let mut operator_descriptor = b"adapter-operator-profile-".to_vec();
        operator_descriptor.extend_from_slice(suffix);
        PocoNodeRemoteSignerRoleBindingsV1::new(
            set,
            P2pIdentityRemoteSignerProfileV1::new(
                node_profile(&p2p_descriptor),
                node_endpoint(b"adapter-p2p-endpoint"),
                P2pIdentityPublicKeyV1::new([p2p_key; 32]).unwrap(),
            ),
            ConsensusRemoteSignerProfileV1::new(
                node_profile(&consensus_descriptor),
                node_endpoint(b"adapter-consensus-endpoint"),
                set.validators()[0].id(),
                set.validators()[0].consensus_key(),
            )
            .unwrap(),
            OperatorRecoveryRemoteSignerProfileV1::new(
                node_profile(&operator_descriptor),
                node_endpoint(b"adapter-operator-endpoint"),
                OperatorRecoveryPublicKeyV1::new([operator_key; 32]).unwrap(),
            ),
        )
        .unwrap()
    }

    fn protocol_refs(prefix: &[u8]) -> ProtocolRefsV1 {
        let mut role = b"adapter-protocol-role-".to_vec();
        role.extend_from_slice(prefix);
        let mut service = b"adapter-protocol-service-".to_vec();
        service.extend_from_slice(prefix);
        let mut client = b"adapter-protocol-client-".to_vec();
        client.extend_from_slice(prefix);
        ProtocolRefsV1 {
            role: RemoteSignerRoleProfileRefV1::from_public_descriptor(&role).unwrap(),
            service: RemoteSignerServiceProfileRefV1::from_public_descriptor(&service).unwrap(),
            client: RemoteSignerClientProfileRefV1::from_public_descriptor(&client).unwrap(),
        }
    }

    fn adapter(
        set: &ValidatorSet,
        roles: &PocoNodeRemoteSignerRoleBindingsV1,
        refs: ProtocolRefsV1,
    ) -> PocoNodeRemoteSignerProtocolAdapterV1 {
        let exact = prepare_remote_signer_protocol_adapter_v1_exact(
            set,
            roles,
            refs.role,
            refs.service,
            refs.client,
        )
        .unwrap();
        decode(&exact, set, roles, refs).unwrap()
    }

    fn decode(
        encoded: &[u8],
        set: &ValidatorSet,
        roles: &PocoNodeRemoteSignerRoleBindingsV1,
        refs: ProtocolRefsV1,
    ) -> Result<PocoNodeRemoteSignerProtocolAdapterV1, PocoNodeRemoteSignerProtocolAdapterErrorV1>
    {
        decode_remote_signer_protocol_adapter_v1_exact(
            encoded,
            set,
            roles,
            refs.role,
            refs.service,
            refs.client,
        )
    }

    fn offsets(encoded: &[u8]) -> AdapterOffsetsV1 {
        let node_length_offset = ADAPTER_MAGIC_V1.len() + 2;
        let node_exact = node_length_offset + 4;
        let node_length = usize::try_from(u32::from_be_bytes(
            encoded[node_length_offset..node_exact].try_into().unwrap(),
        ))
        .unwrap();
        let node_profile_checksum = node_exact + node_length;
        let validator_set_id = node_profile_checksum + 32;
        let local_validator_length_offset = validator_set_id + 32;
        let local_validator = local_validator_length_offset + 2;
        let local_validator_length = usize::from(u16::from_be_bytes(
            encoded[local_validator_length_offset..local_validator]
                .try_into()
                .unwrap(),
        ));
        let node_purpose_profile = local_validator + local_validator_length;
        let node_consensus_profile = node_purpose_profile + 32;
        let node_consensus_endpoint = node_consensus_profile + 32;
        let protocol_schema = node_consensus_endpoint + 32;
        let protocol_purpose_profile = protocol_schema + 2;
        let protocol_role = protocol_purpose_profile + 32;
        let protocol_service = protocol_role + 32;
        let protocol_client = protocol_service + 32;
        let mapping_count = protocol_client + 32;
        let mapping_rows = mapping_count + 2;
        let checksum = mapping_rows + 4;
        assert_eq!(checksum + 32, encoded.len());
        AdapterOffsetsV1 {
            node_length: node_length_offset,
            node_exact,
            node_profile_checksum,
            validator_set_id,
            local_validator_length: local_validator_length_offset,
            local_validator,
            node_purpose_profile,
            node_consensus_profile,
            node_consensus_endpoint,
            protocol_schema,
            protocol_purpose_profile,
            protocol_role,
            protocol_service,
            protocol_client,
            mapping_count,
            mapping_rows,
            checksum,
        }
    }

    fn replace_checksum(encoded: &mut [u8]) {
        let checksum = encoded.len() - 32;
        let replacement = adapter_checksum_v1(&encoded[..checksum]);
        encoded[checksum..].copy_from_slice(&replacement);
    }

    #[test]
    fn exact_adapter_round_trips_and_binds_both_frozen_profiles() {
        let set = validator_set();
        let roles = node_role_bindings(&set, b"primary", 31, 33);
        let refs = protocol_refs(b"primary");
        let value = adapter(&set, &roles, refs);
        let exact = value.try_exact_bytes().unwrap();
        let expected_node_exact = roles.try_exact_bytes().unwrap();
        let exact_sha256: [u8; 32] = Sha256::digest(&exact).into();
        assert!(exact.len() <= MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1);
        assert_eq!(exact.len(), ADAPTER_EXACT_BYTES_GOLDEN_LENGTH_V1);
        assert_eq!(exact_sha256, ADAPTER_EXACT_SHA256_GOLDEN_V1);
        assert_eq!(decode(&exact, &set, &roles, refs).unwrap(), value);
        assert_eq!(
            value.node_role_bindings_exact(),
            expected_node_exact.as_slice()
        );
        assert_eq!(value.node_profile_checksum(), roles.profile_checksum());
        assert_eq!(value.validator_set_id(), set.id());
        assert_eq!(value.local_validator(), set.validators()[0].id());
        assert_eq!(
            value.node_purpose_profile_digest(),
            NODE_PURPOSE_PROFILE_GOLDEN_V1
        );
        assert_eq!(
            value.node_consensus_profile_ref(),
            roles.consensus().profile_ref()
        );
        assert_eq!(
            value.node_consensus_endpoint_ref(),
            roles.consensus().endpoint_ref()
        );
        assert_eq!(
            *value.protocol_purpose_profile_digest().as_bytes(),
            PROTOCOL_PURPOSE_PROFILE_GOLDEN_V1
        );
        assert_eq!(
            value.protocol_request_schema(),
            REMOTE_SIGNER_REQUEST_SCHEMA_V1
        );
        assert_eq!(value.protocol_role_profile_ref(), refs.role);
        assert_eq!(value.protocol_service_profile_ref(), refs.service);
        assert_eq!(value.protocol_client_profile_ref(), refs.client);
        assert_eq!(value.adapter_checksum(), ADAPTER_CHECKSUM_GOLDEN_V1);
    }

    #[test]
    fn adapter_maps_only_vote_and_timeout_vote() {
        let set = validator_set();
        let roles = node_role_bindings(&set, b"primary", 31, 33);
        let value = adapter(&set, &roles, protocol_refs(b"primary"));
        assert_eq!(
            value.mapped_protocol_command_kind(ConsensusSignerPurposeV1::Vote),
            Some(RemoteConsensusCommandKindV1::Vote)
        );
        assert_eq!(
            value.mapped_protocol_command_kind(ConsensusSignerPurposeV1::TimeoutVote),
            Some(RemoteConsensusCommandKindV1::TimeoutVote)
        );
        for unmapped in [
            ConsensusSignerPurposeV1::Proposal,
            ConsensusSignerPurposeV1::OldSetHandoffVote,
            ConsensusSignerPurposeV1::NewSetHandoffVote,
        ] {
            assert_eq!(value.mapped_protocol_command_kind(unmapped), None);
        }
    }

    #[test]
    fn every_redundant_identity_and_mapping_substitution_fails_after_resigning() {
        let set = validator_set();
        let roles = node_role_bindings(&set, b"primary", 31, 33);
        let refs = protocol_refs(b"primary");
        let exact = adapter(&set, &roles, refs).try_exact_bytes().unwrap();
        let offsets = offsets(&exact);
        let substitutions = [
            (
                offsets.node_profile_checksum,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeProfileChecksumMismatch,
            ),
            (
                offsets.validator_set_id,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ValidatorSetMismatch,
            ),
            (
                offsets.local_validator,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::LocalValidatorMismatch,
            ),
            (
                offsets.node_purpose_profile,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::NodePurposeProfileMismatch,
            ),
            (
                offsets.node_consensus_profile,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeConsensusProfileRefMismatch,
            ),
            (
                offsets.node_consensus_endpoint,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeConsensusEndpointRefMismatch,
            ),
            (
                offsets.protocol_schema,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolSchemaMismatch,
            ),
            (
                offsets.protocol_purpose_profile,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolPurposeProfileMismatch,
            ),
            (
                offsets.protocol_role,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolRoleProfileRefMismatch,
            ),
            (
                offsets.protocol_service,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolServiceProfileRefMismatch,
            ),
            (
                offsets.protocol_client,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolClientProfileRefMismatch,
            ),
            (
                offsets.mapping_count,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::PurposeMappingMismatch,
            ),
            (
                offsets.mapping_rows,
                PocoNodeRemoteSignerProtocolAdapterErrorV1::PurposeMappingMismatch,
            ),
        ];
        for (offset, expected) in substitutions {
            let mut mutant = exact.clone();
            mutant[offset] ^= 1;
            replace_checksum(&mut mutant);
            assert_eq!(decode(&mutant, &set, &roles, refs), Err(expected));
        }

        let mut node_mutant = exact.clone();
        node_mutant[offsets.node_exact] ^= 1;
        replace_checksum(&mut node_mutant);
        assert_eq!(
            decode(&node_mutant, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactNodeRoleBindingsMismatch)
        );
    }

    #[test]
    fn complete_valid_role_or_protocol_reference_substitution_still_fails() {
        let set = validator_set();
        let roles = node_role_bindings(&set, b"primary", 31, 33);
        let refs = protocol_refs(b"primary");
        let exact = adapter(&set, &roles, refs).try_exact_bytes().unwrap();

        let alternative_roles = node_role_bindings(&set, b"alternative", 41, 43);
        let alternative_exact = adapter(&set, &alternative_roles, refs)
            .try_exact_bytes()
            .unwrap();
        assert_eq!(
            decode(&alternative_exact, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ExactNodeRoleBindingsMismatch)
        );

        let other_set = ValidatorSet::new(
            GenesisHash::new([9; 32]),
            ChainId::from_static("trnm-node-remote-protocol-adapter-test"),
            ProtocolVersion::V0,
            Epoch::new(0),
            ConsensusParametersHash::new([8; 32]),
            vec![Validator::new(
                ValidatorId::new([1; 32]),
                ConsensusPublicKey::new([32; 32]),
                VotingPower::new(1).unwrap(),
            )
            .unwrap()],
        )
        .unwrap();
        assert_eq!(
            decode(&exact, &other_set, &roles, refs),
            Err(
                PocoNodeRemoteSignerProtocolAdapterErrorV1::NodeRoleBindings(
                    RemoteSignerRoleConfigErrorV1::ValidatorSetMismatch
                )
            )
        );

        let alternative_refs = protocol_refs(b"alternative");
        assert_eq!(
            decode(
                &exact,
                &set,
                &roles,
                ProtocolRefsV1 {
                    role: alternative_refs.role,
                    ..refs
                }
            ),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolRoleProfileRefMismatch)
        );
        assert_eq!(
            decode(
                &exact,
                &set,
                &roles,
                ProtocolRefsV1 {
                    service: alternative_refs.service,
                    ..refs
                }
            ),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolServiceProfileRefMismatch)
        );
        assert_eq!(
            decode(
                &exact,
                &set,
                &roles,
                ProtocolRefsV1 {
                    client: alternative_refs.client,
                    ..refs
                }
            ),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ProtocolClientProfileRefMismatch)
        );
    }

    #[test]
    fn framing_checksum_and_bounds_fail_closed() {
        let set = validator_set();
        let roles = node_role_bindings(&set, b"primary", 31, 33);
        let refs = protocol_refs(b"primary");
        let exact = adapter(&set, &roles, refs).try_exact_bytes().unwrap();
        let offsets = offsets(&exact);

        let mut magic = exact.clone();
        magic[0] ^= 1;
        assert_eq!(
            decode(&magic, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidMagic)
        );
        let mut schema = exact.clone();
        schema[ADAPTER_MAGIC_V1.len() + 1] = 2;
        assert_eq!(
            decode(&schema, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidSchemaVersion(2))
        );
        let mut zero_node_length = exact.clone();
        zero_node_length[offsets.node_length..offsets.node_exact].fill(0);
        assert_eq!(
            decode(&zero_node_length, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidNodeRoleBindingsLength)
        );
        let mut zero_validator_length = exact.clone();
        zero_validator_length[offsets.local_validator_length..offsets.local_validator].fill(0);
        assert_eq!(
            decode(&zero_validator_length, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::InvalidLocalValidatorLength)
        );
        let mut checksum = exact.clone();
        checksum[offsets.checksum] ^= 1;
        assert_eq!(
            decode(&checksum, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::ChecksumMismatch)
        );
        let mut trailing = exact.clone();
        trailing.push(0);
        assert_eq!(
            decode(&trailing, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::TrailingBytes)
        );
        assert_eq!(
            decode(&exact[..exact.len() - 1], &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::TruncatedEncoding)
        );
        let oversized = vec![0; MAX_REMOTE_SIGNER_PROTOCOL_ADAPTER_BYTES_V1 + 1];
        assert_eq!(
            decode(&oversized, &set, &roles, refs),
            Err(PocoNodeRemoteSignerProtocolAdapterErrorV1::EncodingTooLarge)
        );
    }

    #[test]
    fn adapter_and_node_typed_commands_expose_no_safety_or_runtime_authority() {
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_DESCRIPTOR_EQUIVALENCE_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_RESOLVER_ATTESTATION_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_SAFETY_RULES_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_LEASE_AUTHORITY_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_REQUEST_AUTHORITY_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_BARE_REF_BINDING_SOURCE_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_DIRECT_CONSTRUCTOR_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_RUNTIME_ACTIVATION_V1);
        assert!(!REMOTE_SIGNER_PROTOCOL_ADAPTER_PRODUCTION_ACTIVATION_V1);
        assert!(!crate::REMOTE_SIGNER_SAFETY_RULES_EVALUATION_V1);
        assert!(!crate::REMOTE_SIGNER_SAFE_VOTE_AUTHORITY_V1);

        let source = include_str!("remote_signer_protocol_adapter_v1.rs");
        for forbidden in [
            concat!("RemoteSigner", "RequestV1"),
            concat!("RemoteSigner", "RequestBindingV1"),
            concat!("RemoteSigner", "LeaseIdV1"),
            concat!("Process", "GenerationV1"),
            concat!("RemoteSigner", "CheckpointWitnessV1"),
            concat!("Signing", "Key"),
            concat!("Signature", "Producer"),
            concat!("fn sign", "("),
            concat!("pub fn ", "new("),
        ] {
            assert!(
                !source.contains(forbidden),
                "inert adapter gained forbidden authority surface: {forbidden}"
            );
        }

        let manifest = include_str!("../Cargo.toml");
        for required_true in [
            "remote_signer_node_protocol_adapter = true",
            "remote_signer_node_protocol_adapter_exact = true",
        ] {
            assert!(manifest.contains(required_true));
        }
        for required_false in [
            "remote_signer_node_protocol_descriptor_equivalence = false",
            "remote_signer_node_protocol_resolver_attestation = false",
            "remote_signer_node_protocol_safety_rules = false",
            "remote_signer_node_protocol_lease_authority = false",
            "remote_signer_node_protocol_request_authority = false",
            "remote_signer_node_protocol_bare_ref_binding_source = false",
            "remote_signer_node_protocol_direct_constructor = false",
            "remote_signer_node_protocol_runtime_activation = false",
            "remote_signer_node_protocol_production_activation = false",
            "remote_signer_safety_rules_evaluation = false",
            "remote_signer_safe_vote_authority = false",
            "production_candidate = false",
            "production_consensus_activation = false",
        ] {
            assert!(manifest.contains(required_false));
        }
    }
}
