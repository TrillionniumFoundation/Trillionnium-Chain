//! Standalone, node-local SQLite journal for exact Core `SafetyState` records.
//!
//! This crate is deliberately separate from application state, AppHash,
//! snapshots, and state-sync replacement. It adds an explicit lifetime writer
//! lock, SQLite WAL transactions with `synchronous=FULL`, a monotonic revision
//! chain, exact active-head readback, and two-revision retention around Core's
//! inert schema-8 record codec.
//!
//! Stored records and transition contexts remain comparison facts. They never
//! mint validation, callback, signing, finalization, or obligation-replay
//! authority. The journal also cannot detect an adversary restoring the whole
//! database, persistent WAL, and lock sidecar to an older self-consistent
//! image; a production host must cross-check an independent monotonic
//! signer/host watermark.
//!
//! Journal v1 is Linux-only and assumes a local filesystem with reliable
//! SQLite POSIX byte locks, `flock`, `fsync`, and atomic namespace operations.
//! NFS, SMB, FUSE, overlay filesystems, fork-after-open, and an untrusted
//! same-EUID process are not certified. The store pins its protected directory,
//! main database, persistent WAL, SHM, and lock sidecar, but a production host
//! must still place them in a dedicated owner-controlled namespace.

mod error;
mod hash;
mod schema;
mod sqlite;
mod transition_context;

pub use error::{SafetyStoreConflictV0, SafetyStoreErrorV0};
pub use sqlite::{
    RecoveredSafetyStateV0, SafetyPersistDispositionV0, SafetyStateStoreProfileV0,
    SqliteSafetyStateStoreV0,
};
pub use transition_context::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    transition_context_checksum_v0, validate_transition_context_against_state_v0,
    NativeDeterministicInvalidTransitionV0, SafetyTransitionContextV0,
    NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0, NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0,
};
