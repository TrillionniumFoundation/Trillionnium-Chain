//! Candidate-only durable authenticated payload replay integration.
//!
//! The durable owner itself lives in `trnm-consensus-peer-lease` so its WAL
//! and lock can be commissioned independently of the lab process. This
//! module is the lab-facing vocabulary and intentionally re-exports only the
//! narrow record/namespace types. `PersistentAuthenticatedPeerMeshV0` exposes
//! the explicit `receive_timeout_with_payload_replay_v1` boundary that
//! consumes a `MeshInboundFrameV0` owner before returning it to a caller.

pub use trnm_consensus_peer_lease::{
    payload_replay_run_id_hash_v1, PayloadReplayDirectionV1, PayloadReplayErrorV1,
    PayloadReplayFrameV1, PayloadReplayNamespaceV1, PayloadReplayReceiptV1, PayloadReplayStoreV1,
    PAYLOAD_REPLAY_APPEND_ONLY_HASH_CHAIN_V1, PAYLOAD_REPLAY_CANDIDATE_V1,
    PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1, PAYLOAD_REPLAY_MAX_RECORDS_V1,
    PAYLOAD_REPLAY_PRODUCTION_ACTIVATION_V1,
};

/// This adapter does not own sockets, leases, Core, SafetyRules, or activation.
pub const PAYLOAD_REPLAY_MESH_INTEGRATION_CANDIDATE_V1: bool = true;
pub const PAYLOAD_REPLAY_MESH_INTEGRATION_PRODUCTION_ACTIVATION_V1: bool = false;
