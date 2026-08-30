//! Candidate-only external payload-replay recovery and Core acknowledgement boundary.
//!
//! The implementation is split into included, item-complete source units so
//! the recovery contract, WAL verifier, acknowledgement ledger and tests remain
//! reviewable without creating public submodule authority.

include!("payload_recovery/part_01_types.rs");
include!("payload_recovery/part_02_owner.rs");
include!("payload_recovery/part_03_wal.rs");
include!("payload_recovery/part_04_io_ack.rs");
include!("payload_recovery/part_05_tests.rs");
include!("payload_recovery/part_06_projection.rs");
#[cfg(unix)]
#[path = "payload_recovery/part_07_socket.rs"]
mod recovery_socket;
#[cfg(unix)]
pub use recovery_socket::{
    PayloadReplayRecoveryClientV1, PayloadReplayRecoveryDaemonV1, PayloadReplayRecoverySocketAckV1,
    PayloadReplayRecoverySocketErrorV1, PayloadReplayRecoverySocketStatusV1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_CANDIDATE_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_CLIENT_TRANSPORT_ERRORS_NON_FATAL_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_MAX_CONCURRENT_CONNECTIONS_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_PRODUCTION_ACTIVATION_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1,
};
