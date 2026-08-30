#![forbid(unsafe_code)]
//! Cross-process external peer lease/fencing authority.
//!
//! This crate supplies a deliberately narrow Unix daemon/client boundary for
//! authenticated P2P admission.  The daemon owns an append-only, SHA-256
//! hash-chain journal and allocates strictly increasing generations for a
//! `(local, remote, direction, epoch, validator-set)` scope.  Restart,
//! tampering, truncation and stale tokens fail closed.
//!
//! It does **not** carry consensus payloads, evaluate SafetyRules, attest a
//! host, resolve a private key, or activate a validator runtime.  A P2P node
//! must explicitly consume and revalidate a token before each worker/generation
//! action; this crate cannot make that runtime integration implicitly safe.

mod payload;
mod payload_recovery;
mod protocol;
mod store;

#[cfg(unix)]
mod unix;

pub use payload::{
    payload_replay_run_id_hash_v1, PayloadReplayDirectionV1, PayloadReplayErrorV1,
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PayloadReplayReceiptV1, PayloadReplayStoreV1,
    PAYLOAD_REPLAY_APPEND_ONLY_HASH_CHAIN_V1, PAYLOAD_REPLAY_CANDIDATE_V1,
    PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1, PAYLOAD_REPLAY_MAX_RECORDS_V1,
    PAYLOAD_REPLAY_PRODUCTION_ACTIVATION_V1,
};
pub use payload_recovery::{
    PayloadReplayCoreAckReceiptV1, PayloadReplayCoreAcknowledgementV1,
    PayloadReplayRecoveryErrorV1, PayloadReplayRecoveryOwnerV1, PayloadReplayRecoveryStatusV1,
    PayloadReplayRecoveryTargetV1, PAYLOAD_REPLAY_CORE_ACK_ATOMIC_WITH_CORE_V1,
    PAYLOAD_REPLAY_CORE_ACK_LEDGER_CANDIDATE_V1,
    PAYLOAD_REPLAY_EXTERNAL_RECOVERY_OWNER_CANDIDATE_V1,
    PAYLOAD_REPLAY_RECOVERY_PRODUCTION_ACTIVATION_V1,
};
pub use protocol::{
    LeaseRejectCodeV1, PeerLeaseDirectionV1, PeerLeaseErrorV1, PeerLeaseScopeV1, PeerLeaseTokenV1,
    ProtocolErrorV1, MAX_FRAME_BYTES_V1, PEER_LEASE_SCHEMA_V1,
};
pub use store::PeerLeaseStoreV1;

#[cfg(unix)]
pub use unix::{
    run_daemon, ExternalPeerLeaseAuthorityV1, PeerLeaseAuthorityDaemonV1, PeerLeaseClientV1,
    UnixPeerLeaseClientV1, UnixPeerLeaseDaemonV1,
};

/// Metadata truth flags.  Every authority beyond the lease itself remains
/// deliberately disabled until a separately reviewed Core/P2P integration is
/// proven on real nodes.
pub const PEER_LEASE_UNIX_SOCKET_TRANSPORT_V1: bool = true;
pub const PEER_LEASE_APPEND_ONLY_HASH_CHAIN_V1: bool = true;
pub const PEER_LEASE_CROSS_PROCESS_FENCING_V1: bool = true;
pub const PEER_LEASE_HOST_ATTESTATION_V1: bool = false;
pub const PEER_LEASE_PRIVATE_KEY_HANDLING_V1: bool = false;
pub const PEER_LEASE_CONSENSUS_PAYLOAD_TRANSPORT_V1: bool = false;
pub const PEER_LEASE_CONSENSUS_RUNTIME_V1: bool = false;
pub const PEER_LEASE_CORE_SAFETY_AUTHORITY_V1: bool = false;
pub const PEER_LEASE_PRODUCTION_ACTIVATION_V1: bool = false;

#[cfg(test)]
mod source_truth_tests {
    #[test]
    fn activation_and_credential_boundaries_remain_false() {
        let manifest = include_str!("../Cargo.toml");
        for required_false in [
            "local_private_key_handling = false",
            "host_attestation = false",
            "consensus_runtime = false",
            "consensus_payload_transport = false",
            "core_safety_authority = false",
            "payload_replay_core_ack_atomic_with_core = false",
            "payload_replay_recovery_production_activation = false",
            "production_activation = false",
            "production_candidate = false",
        ] {
            assert!(
                manifest.contains(required_false),
                "missing truth flag: {required_false}"
            );
        }
        for required_true in [
            "payload_replay_append_only_hash_chain = true",
            "payload_replay_candidate = true",
            "payload_replay_external_recovery_owner_candidate = true",
            "payload_replay_core_ack_ledger_candidate = true",
        ] {
            assert!(
                manifest.contains(required_true),
                "missing payload replay truth flag: {required_true}"
            );
        }
        assert!(!include_str!("lib.rs").contains(concat!("Signing", "Key")));
    }
}
