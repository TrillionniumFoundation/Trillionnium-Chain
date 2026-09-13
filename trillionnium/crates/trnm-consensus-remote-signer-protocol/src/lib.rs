#![no_std]
#![forbid(unsafe_code)]
//! Data-only protocol boundary for a future independent consensus signer.
//!
//! The crate owns no socket, credential, journal, monotonic store, private
//! key, signature producer, or runtime activation. It admits complete
//! canonical PoCO-BFT vote/timeout intents plus an explicitly separate,
//! proposal-purpose witness envelope. Proposal bytes use a distinct magic and
//! purpose profile; the old command decoder still rejects them.
//!
//! Profile, generation, lease, checkpoint, and nonce values in this crate are
//! public protocol facts.  Constructing or decoding them grants no lease and
//! no authority to sign.  A later service must authenticate them against its
//! own journal, external monotonic store, and process-generation fence before
//! reaching a private key provider. Even those fences do not evaluate the
//! HotStuff locked-QC/safe-vote rule. The future signer trust domain must also
//! own and advance SafetyRules/SafetyState, or consume an unforgeable durable
//! safety authorization. A well-formed decoded request is never Core authority.

extern crate alloc;

mod command;
mod ids;
mod proposal;
mod wire;

pub use command::{
    RemoteConsensusCommandKindV1, RemoteConsensusCommandV1, RemoteConsensusCommandValidationErrorV1,
};
pub use ids::{
    proposal_purpose_profile_digest_v1, vote_timeout_purpose_profile_digest_v1,
    ProcessGenerationV1, RemoteSignerCheckpointWitnessV1, RemoteSignerClientProfileRefV1,
    RemoteSignerIdErrorV1, RemoteSignerLeaseIdV1, RemoteSignerPurposeProfileDigestV1,
    RemoteSignerRequestFingerprintV1, RemoteSignerRequestNonceV1,
    RemoteSignerResponseFingerprintV1, RemoteSignerRoleProfileRefV1,
    RemoteSignerServiceProfileRefV1, MAX_REMOTE_SIGNER_PUBLIC_DESCRIPTOR_BYTES_V1,
};
pub use proposal::{
    decode_remote_proposal_signer_request_v1_exact,
    decode_unverified_remote_proposal_signer_response_v1_exact, is_remote_proposal_request_v1,
    RemoteProposalSignatureRequestV1, UnverifiedRemoteProposalSignerResponseV1,
    MAX_REMOTE_PROPOSAL_SIGNER_REQUEST_BYTES_V1, MAX_REMOTE_PROPOSAL_SIGNER_RESPONSE_BYTES_V1,
};
pub use wire::{
    decode_remote_signer_request_v1_exact, decode_unverified_remote_signer_response_v1_exact,
    RemoteSignerProtocolErrorV1, RemoteSignerRequestBindingV1, RemoteSignerRequestV1,
    UnverifiedRemoteSignerResponseV1, MAX_REMOTE_SIGNER_REQUEST_BYTES_V1,
    MAX_REMOTE_SIGNER_RESPONSE_BYTES_V1, REMOTE_SIGNER_REQUEST_SCHEMA_V1,
    REMOTE_SIGNER_RESPONSE_SCHEMA_V1,
};

/// This crate is data-only and cannot activate a remote signer runtime.
pub const REMOTE_SIGNER_PROTOCOL_RUNTIME_ACTIVATION_V1: bool = false;

/// This crate contains no credential resolver or credential bytes.
pub const REMOTE_SIGNER_PROTOCOL_CREDENTIAL_HANDLING_V1: bool = false;

/// This crate contains no private-key type or signature producer.
pub const REMOTE_SIGNER_PROTOCOL_PRIVATE_KEY_HANDLING_V1: bool = false;

/// Caller-selected arbitrary bytes cannot cross this protocol boundary.
pub const REMOTE_SIGNER_PROTOCOL_GENERIC_SIGN_BYTES_V1: bool = false;

/// Constructing protocol data does not grant or activate a signer lease.
pub const REMOTE_SIGNER_PROTOCOL_LEASE_AUTHORITY_V1: bool = false;

/// Response decoding validates only canonical envelope shape and bindings.
/// It does not authenticate the contained Ed25519 signature.
pub const REMOTE_SIGNER_PROTOCOL_RESPONSE_SIGNATURE_VERIFICATION_V1: bool = false;

/// Nonce derivation is deterministic data shaping, not freshness or replay
/// authority. A future service must enforce nonce uniqueness in durable state.
pub const REMOTE_SIGNER_PROTOCOL_NONCE_FRESHNESS_AUTHORITY_V1: bool = false;

/// Canonical request shape is not an unforgeable Core/Safety authorization.
pub const REMOTE_SIGNER_PROTOCOL_CORE_SAFETY_AUTHORITY_V1: bool = false;

/// This data-only crate does not evaluate locked-QC or safe-vote rules.
pub const REMOTE_SIGNER_PROTOCOL_SAFETY_RULES_EVALUATION_V1: bool = false;

/// A well-formed request does not prove the HotStuff safe-vote rule.
pub const REMOTE_SIGNER_PROTOCOL_SAFE_VOTE_AUTHORITY_V1: bool = false;

/// Protocol-local profile references are not yet adapted to the Node role
/// binding checksum or full purpose taxonomy.
pub const REMOTE_SIGNER_PROTOCOL_NODE_ROLE_BINDING_ADAPTER_V1: bool = false;

/// Node role configuration and this wire crate do not yet form one shared,
/// checksum-bound authority source.
pub const REMOTE_SIGNER_PROTOCOL_SHARED_AUTHORITY_SOURCE_V1: bool = false;

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn source_and_manifest_expose_no_generic_signing_or_runtime_boundary() {
        let sources = [
            include_str!("lib.rs"),
            include_str!("command.rs"),
            include_str!("ids.rs"),
            include_str!("wire.rs"),
            include_str!("proposal.rs"),
        ]
        .concat();
        let manifest = include_str!("../Cargo.toml");

        for forbidden in [
            concat!("pub fn ", "sign("),
            concat!("pub fn ", "sign_bytes"),
            concat!("pub trait ", "SignatureProducer"),
            concat!("pub fn ", "from_signing_root"),
            concat!("pub fn ", "new_from_root"),
            concat!("Signing", "Key"),
            concat!("Secret", "Key"),
            concat!("Pkcs", "8"),
            concat!("Unix", "Stream"),
            concat!("Tcp", "Stream"),
            concat!("pub enum ", "RemoteConsensusCommandV1"),
            concat!("pub kind", ": RemoteConsensusCommandKindV1"),
            concat!("pub intent", ": CanonicalSignIntentV0"),
        ] {
            assert!(
                !sources.contains(forbidden),
                "forbidden remote-signer protocol API/source token: {forbidden}"
            );
        }

        for forbidden_dependency in [
            concat!("ed25519", "-dalek"),
            concat!("rusq", "lite"),
            concat!("tok", "io"),
            concat!("rust", "ls"),
            concat!("trnm-poco", "-node"),
        ] {
            assert!(
                !manifest.contains(forbidden_dependency),
                "data-only protocol gained forbidden dependency: {forbidden_dependency}"
            );
        }

        for required_false_truth in [
            "socket_transport = false",
            "credential_handling = false",
            "private_key_handling = false",
            "generic_sign_bytes = false",
            "lease_authority = false",
            "response_signature_verification = false",
            "nonce_freshness_authority = false",
            "core_safety_authority = false",
            "safety_rules_evaluation = false",
            "safe_vote_authority = false",
            "node_role_binding_adapter = false",
            "shared_authority_source = false",
            "remote_signer_runtime_activation = false",
            "production_signature_producer = false",
            "production_candidate = false",
            "production_consensus_activation = false",
        ] {
            assert!(manifest.contains(required_false_truth));
        }
        assert!(sources.contains("pub struct RemoteConsensusCommandV1"));
        let readme = include_str!("../README.md");
        for required_boundary in [
            "only an untrusted,\nwell-formed request",
            "does not carry enough locked-QC/justify state",
            "No future service may pass this wire request to a signature producer",
            "cryptographically unverified signature wire bytes",
            "does not provide freshness or uniqueness",
            "They must not be compared directly or\nsubstituted for one another",
            "explicitly binds the Node role-bindings checksum",
        ] {
            assert!(readme.contains(required_boundary));
        }
    }
}
