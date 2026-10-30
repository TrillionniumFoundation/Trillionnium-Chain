//! Candidate-only external payload-replay recovery and Core acknowledgement boundary.
//!
//! Private Rust modules expose each source unit to semantic analysis. The
//! original public API is re-exported here; internal sharing stays within
//! this recovery owner and its tests.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use fs2::FileExt;
use sha2::{Digest, Sha256};

use crate::{
    payload::{
        payload_replay_generation_successor_v1, PayloadReplayDirectionV1,
        PayloadReplayDirectoryIdentityV1, PayloadReplayFrameV1, PayloadReplayNamespaceV1,
        PayloadReplayReceiptV1, PAYLOAD_REPLAY_MAX_PAYLOAD_BYTES_V1, PAYLOAD_REPLAY_MAX_RECORDS_V1,
        PAYLOAD_REPLAY_MAX_TEMPORARY_FILES_V1, PAYLOAD_REPLAY_MAX_TEMPORARY_SCAN_ENTRIES_V1,
        PAYLOAD_REPLAY_MAX_WAL_BYTES_V1,
    },
    protocol::PeerLeaseDirectionV1,
    store::ensure_private_directory,
};

#[path = "payload_recovery/part_01_types.rs"]
mod types;
use types::{
    descriptor_identity, path_identity, verify_bound_directory_identity,
    verify_bound_file_identity, verify_bound_path_identity, AuthorityPathIdentityV1, ACK_BYTES_V1,
    ACK_DOMAIN_V1, ACK_LOCK_NAME_V1, ACK_MAGIC_V1, ACK_PREFIX_BYTES_V1, ACK_VERSION_V1,
    HEAD_BYTES_V1, HEAD_DOMAIN_V1, HEAD_MAGIC_V1, HEAD_PREFIX_BYTES_V1, HEAD_VERSION_V1,
    LOG_FRAME_KIND_V1, LOG_GENESIS_KIND_V1, LOG_MAGIC_V1, LOG_VERSION_V1, NAMESPACE_DOMAIN_V1,
    PRIVATE_FILE_MODE_V1, RECORD_BYTES_V1, RECORD_DOMAIN_V1, RECORD_PREFIX_BYTES_V1, TEMP_NONCE_V1,
};
pub use types::{
    PayloadReplayCoreAckReceiptV1, PayloadReplayCoreAcknowledgementV1,
    PayloadReplayRecoveryErrorV1, PayloadReplayRecoveryStatusV1, PayloadReplayRecoveryTargetV1,
    PAYLOAD_REPLAY_CORE_ACK_ATOMIC_WITH_CORE_V1, PAYLOAD_REPLAY_CORE_ACK_LEDGER_CANDIDATE_V1,
    PAYLOAD_REPLAY_EXTERNAL_RECOVERY_OWNER_CANDIDATE_V1,
    PAYLOAD_REPLAY_RECOVERY_ENDPOINT_IDENTITY_SCHEMA_V1,
    PAYLOAD_REPLAY_RECOVERY_PRODUCTION_ACTIVATION_V1,
};
#[path = "payload_recovery/part_02_owner.rs"]
mod owner;
pub use owner::PayloadReplayRecoveryOwnerV1;
use owner::{
    AckFactsV1, DecodedRecordV1, PayloadHeadV1, PayloadSnapshotV1, PeerKeyV1, ReplayStateV1,
};
#[path = "payload_recovery/part_03_wal.rs"]
mod wal;
use wal::{
    bounded_count, decode_record, namespace_digest, persist_head, quarantine_temporaries,
    read_head_with_identity, read_snapshot, scan_head_temporaries,
};
#[path = "payload_recovery/part_04_io_ack.rs"]
mod io_ack;
#[cfg(test)]
use io_ack::scan_ack_temporaries;
use io_ack::{
    ack_path, ack_temp_path, encode_ack, map_peer_lease_error, open_private_file,
    open_private_lock, private_directory, private_file_mode, private_parent, private_parent_mode,
    read_ack, read_ack_if_present, set_private_options, sidecar_path, try_lock, utf8_filename,
    validate_private_file, write_ack_temp,
};
#[cfg(test)]
use wal::encode_head;
#[path = "payload_recovery/part_06_projection.rs"]
mod projection;
#[cfg(test)]
#[path = "payload_recovery/part_05_tests.rs"]
mod tests;
pub use projection::{
    PayloadReplayRecoveryStatusProjectionV1,
    PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_CANDIDATE_V1,
    PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_PRODUCTION_ACTIVATION_V1,
    PAYLOAD_REPLAY_RECOVERY_STATUS_PROJECTION_SCHEMA_V1,
};
#[cfg(all(unix, feature = "candidate-recovery-socket"))]
#[path = "payload_recovery/part_07_socket.rs"]
mod recovery_socket;
#[cfg(all(unix, feature = "candidate-recovery-socket"))]
pub use recovery_socket::{
    PayloadReplayRecoveryClientV1, PayloadReplayRecoveryDaemonV1, PayloadReplayRecoverySocketAckV1,
    PayloadReplayRecoverySocketErrorV1, PayloadReplayRecoverySocketStatusV1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_CANDIDATE_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_CLIENT_TRANSPORT_ERRORS_NON_FATAL_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_MAX_CONCURRENT_CONNECTIONS_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_PRODUCTION_ACTIVATION_V1,
    PAYLOAD_REPLAY_RECOVERY_SOCKET_SCHEMA_V1,
};
