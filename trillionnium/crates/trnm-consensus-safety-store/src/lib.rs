//! Standalone, node-local SQLite journal for exact Core `SafetyState` records.
//!
//! This crate is deliberately separate from application state, AppHash,
//! snapshots, and state-sync replacement. It adds an explicit lifetime writer
//! lock, SQLite WAL transactions with `synchronous=FULL`, a monotonic revision
//! chain, exact active-head readback, and two-revision retention around Core's
//! inert schema-12 record codec. Journal v6 is the first and only journal
//! schema which accepts Core safety schema 12; v2/v3/v4/v5 images are rejected
//! without implicit migration.
//!
//! Stored records and transition contexts remain comparison facts. Dedicated
//! non-cloneable exact-readback capabilities can attest that the fully
//! validated active head carries a native deterministic-invalid, Valid, or
//! finalization-applied context, but they never mint application, callback,
//! Core, signing, finalization, deferred-effect, or obligation-replay
//! authority by themselves. The journal also cannot detect an adversary
//! restoring the whole database, persistent WAL, and lock sidecar to an older
//! self-consistent image; a production host must cross-check an independent
//! monotonic signer/host watermark.
//!
//! Journal v6 is Linux-only and assumes a local filesystem with reliable
//! SQLite POSIX byte locks, `flock`, `fsync`, and atomic namespace operations.
//! NFS, SMB, FUSE, overlay filesystems, fork-after-open, and an untrusted
//! same-EUID process are not certified. Neither is a second raw/SQLite
//! connection to the same main/SHM inode pair inside the owner process: POSIX
//! record locks and SQLite's `unixShmNode` are process-scoped. The store pins
//! its protected directory, main database, persistent WAL, SHM, and lock
//! sidecar, but a production host must still place them behind one dedicated
//! process owner in an owner-controlled namespace.

mod error;
mod hash;
mod schema;
mod sqlite;
mod transition_context;

pub use error::{SafetyStoreConflictV0, SafetyStoreErrorV0};
pub use sqlite::{
    AuthenticatedGenesisApplicationH1ExistingCutV0,
    AuthenticatedGenesisApplicationH1ObligationLineageReadbackV0,
    AuthenticatedGenesisApplicationH1StableNativeValidLineageReadbackV0,
    AuthenticatedGenesisApplicationInitializationDispositionV0,
    ConfirmedAnchoredSuccessorHistoricalValidV0,
    ConfirmedAuthenticatedGenesisApplicationBootstrapHeadV0,
    ConfirmedAuthenticatedGenesisApplicationH1ObligationHeadV0,
    ConfirmedAuthenticatedGenesisApplicationH1StableNativeValidHeadV0,
    ConfirmedNativeDeterministicInvalidHeadV0, ConfirmedNativeFinalizationAppliedHeadV0,
    ConfirmedNativeValidHeadV0, ConfirmedSafetyNodeCheckpointFactsV0,
    ConfirmedStateSyncCheckpointBootstrapHeadV0, NativeFinalizationAppliedSafetyStatePreflightV0,
    NativeValidSafetyStatePreflightV0, RecoveredSafetyStateV0, SafetyBootstrapInitializationKindV0,
    SafetyPersistDispositionV0, SafetyStateStoreProfileV0, SqliteSafetyStateStoreV0,
    StateSyncCheckpointInitializationDispositionV0,
};
pub use transition_context::{
    decode_transition_context_v0_exact, encode_transition_context_v0,
    native_valid_result_checksum_v0, state_sync_anchor_checksum_v0, transition_context_checksum_v0,
    validate_transition_context_against_state_v0,
    AuthenticatedGenesisApplicationBootstrapTransitionV0, NativeDeterministicInvalidTransitionV0,
    NativeFinalizationAppliedTransitionV0, NativeValidTransitionV0, SafetyTransitionContextV0,
    StateSyncAnchorOrdinaryPromotionTransitionV0, StateSyncCheckpointBootstrapTransitionV0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_REQUEST_SIGNATURE_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_ARM_VIEW_TIMER_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_FINALIZE_V0, NATIVE_FINALIZATION_APPLIED_POST_ACK_NONE_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_SIGNATURE_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_STANDALONE_QC_SYNC_V0,
    NATIVE_FINALIZATION_APPLIED_POST_ACK_REQUEST_TC_HIGH_QC_SYNC_V0,
    NATIVE_INVALID_REASON_RECEIPTS_ROOT_MISMATCH_V0, NATIVE_INVALID_REASON_STATE_ROOT_MISMATCH_V0,
    NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_THEN_FINALIZE_V0,
    NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_THEN_STANDALONE_QC_SYNC_V0,
    NATIVE_VALID_POST_ACK_ARM_VIEW_TIMER_V0, NATIVE_VALID_POST_ACK_NONE_V0,
    NATIVE_VALID_POST_ACK_REQUEST_SIGNATURE_V0,
    NATIVE_VALID_POST_ACK_REQUEST_STANDALONE_QC_SYNC_V0,
    NATIVE_VALID_POST_ACK_REQUEST_TC_HIGH_QC_SYNC_V0,
    NATIVE_VALID_POST_ACK_SAFETY_HALTED_CONFLICT_V0, SAFETY_TRANSITION_CONTEXT_CODEC_VERSION_V0,
};
