use std::{error::Error, fmt, io};

use trnm_consensus_core::{CoreError, SafetyStateRecordErrorV0};

/// A durable-journal conflict which must never be retried as a new Core
/// transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafetyStoreConflictV0 {
    RevisionRegression { active: u64, incoming: u64 },
    RevisionGap { active: u64, incoming: u64 },
    SameRevisionDifferentRecord { revision: u64 },
    HeadChanged,
    CommitReadbackConflict,
    FileIdentityChanged,
    ProcessChanged,
}

/// Typed failure surface for the standalone safety-state journal.
#[derive(Debug)]
pub enum SafetyStoreErrorV0 {
    InvalidProfile(&'static str),
    AlreadyExists(&'static str),
    Missing(&'static str),
    Locked,
    CoreAlreadyBound,
    CoreNotBound,
    CoreAffinityMismatch,
    MissingNativeDeterministicInvalidTransition {
        revision: u64,
    },
    NativeDeterministicInvalidHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    MissingNativeValidTransition {
        revision: u64,
    },
    NativeValidHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    MissingNativeValidPostAckAction {
        revision: u64,
    },
    NativeValidPostAckActionMismatch {
        revision: u64,
        core_action_code: u32,
        context_action_code: u32,
    },
    MissingNativeFinalizationAppliedTransition {
        revision: u64,
    },
    NativeFinalizationAppliedHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    MissingNativeFinalizationAppliedManifest {
        revision: u64,
    },
    NativeFinalizationAppliedManifestMismatch {
        revision: u64,
    },
    NativeFinalizationAppliedPredecessorMismatch {
        revision: u64,
    },
    MissingStateSyncCheckpointBootstrapTransition {
        revision: u64,
    },
    StateSyncCheckpointBootstrapHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    MissingAuthenticatedGenesisApplicationBootstrapTransition {
        revision: u64,
    },
    AuthenticatedGenesisApplicationBootstrapHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    AuthenticatedGenesisApplicationActivationUnavailable,
    AuthenticatedGenesisApplicationH1OfflineBindingMismatch,
    AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence,
    AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    SafetyNodeCheckpointHeadMismatch {
        expected_revision: u64,
        actual_revision: u64,
    },
    StateSyncInitializationPending,
    StateSyncInitializationIntentMismatch,
    UnsupportedPlatform,
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Sqlite {
        stage: &'static str,
        source: rusqlite::Error,
    },
    Record {
        stage: &'static str,
        source: SafetyStateRecordErrorV0,
    },
    Core {
        stage: &'static str,
        source: CoreError,
    },
    SchemaMismatch,
    MetadataMismatch,
    IntegrityFailure,
    ForeignKeyFailure,
    PersistedRepresentationMalformed(&'static str),
    DurableHalt,
    Conflict(SafetyStoreConflictV0),
    ConflictHaltUncertain {
        conflict: SafetyStoreConflictV0,
        source: Box<SafetyStoreErrorV0>,
    },
    CommitNotApplied {
        commit: rusqlite::Error,
    },
    CommitUncertain {
        commit: rusqlite::Error,
        confirmation: Box<SafetyStoreErrorV0>,
    },
    HeadWatermarkUncertain {
        source: Box<SafetyStoreErrorV0>,
    },
}

impl SafetyStoreErrorV0 {
    pub(crate) fn io(stage: &'static str, source: io::Error) -> Self {
        Self::Io { stage, source }
    }

    pub(crate) fn sqlite(stage: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { stage, source }
    }

    pub(crate) fn record(stage: &'static str, source: SafetyStateRecordErrorV0) -> Self {
        Self::Record { stage, source }
    }

    pub(crate) fn core(stage: &'static str, source: CoreError) -> Self {
        Self::Core { stage, source }
    }
}

impl fmt::Display for SafetyStoreErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(reason) => {
                write!(formatter, "invalid safety-store profile: {reason}")
            }
            Self::AlreadyExists(target) => {
                write!(formatter, "safety-store {target} already exists")
            }
            Self::Missing(target) => write!(formatter, "safety-store {target} is missing"),
            Self::Locked => formatter.write_str("safety-store lifetime lock is already held"),
            Self::CoreAlreadyBound => {
                formatter.write_str("safety-store already has a designated Core binding")
            }
            Self::CoreNotBound => {
                formatter.write_str("safety-store has no designated Core binding")
            }
            Self::CoreAffinityMismatch => formatter
                .write_str("safety-state persistence request came from a foreign Core instance"),
            Self::MissingNativeDeterministicInvalidTransition { revision } => write!(
                formatter,
                "safety-state revision {revision} has no native deterministic-invalid transition"
            ),
            Self::NativeDeterministicInvalidHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "native deterministic-invalid head differs from the exact expected state/context: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::MissingNativeValidTransition { revision } => write!(
                formatter,
                "safety-state revision {revision} has no native Valid transition"
            ),
            Self::NativeValidHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "native Valid head differs from the exact expected state/context: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::MissingNativeValidPostAckAction { revision } => write!(
                formatter,
                "native Valid SafetyState persistence revision {revision} has no Core-owned post-ack action"
            ),
            Self::NativeValidPostAckActionMismatch {
                revision,
                core_action_code,
                context_action_code,
            } => write!(
                formatter,
                "native Valid SafetyState persistence revision {revision} post-ack action differs: Core code {core_action_code}, transition-context code {context_action_code}"
            ),
            Self::MissingNativeFinalizationAppliedTransition { revision } => write!(
                formatter,
                "safety-state revision {revision} has no native finalization-applied transition"
            ),
            Self::NativeFinalizationAppliedHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "native finalization-applied head differs from the exact expected state/context: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::MissingNativeFinalizationAppliedManifest { revision } => write!(
                formatter,
                "native finalization-applied SafetyState persistence revision {revision} has no Core-owned transition manifest"
            ),
            Self::NativeFinalizationAppliedManifestMismatch { revision } => write!(
                formatter,
                "native finalization-applied SafetyState persistence revision {revision} differs from the Core-owned App readback or post-ack manifest"
            ),
            Self::NativeFinalizationAppliedPredecessorMismatch { revision } => write!(
                formatter,
                "native finalization-applied SafetyState persistence revision {revision} does not directly succeed the authenticated journal head"
            ),
            Self::MissingStateSyncCheckpointBootstrapTransition { revision } => write!(
                formatter,
                "safety-state revision {revision} has no state-sync checkpoint bootstrap transition"
            ),
            Self::StateSyncCheckpointBootstrapHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "state-sync checkpoint bootstrap head differs from the exact expected state/context: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::MissingAuthenticatedGenesisApplicationBootstrapTransition { revision } => write!(
                formatter,
                "safety-state revision {revision} has no authenticated-genesis application bootstrap transition"
            ),
            Self::AuthenticatedGenesisApplicationBootstrapHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "authenticated-genesis application bootstrap head differs from the exact expected state/context: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::AuthenticatedGenesisApplicationActivationUnavailable => formatter.write_str(
                "authenticated-genesis application state is fenced from the generic SafetyStore activation surface",
            ),
            Self::AuthenticatedGenesisApplicationH1OfflineBindingMismatch => formatter.write_str(
                "authenticated-genesis h1 offline Core binding differs from the exact live tag-5 journal",
            ),
            Self::AuthenticatedGenesisApplicationH1OfflineRequiresDedicatedPersistence => formatter.write_str(
                "authenticated-genesis h1 offline state is fenced from generic SafetyStore persistence",
            ),
            Self::AuthenticatedGenesisApplicationH1OfflinePersistenceMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "authenticated-genesis h1 offline persistence differs from the exact bound phase: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::SafetyNodeCheckpointHeadMismatch {
                expected_revision,
                actual_revision,
            } => write!(
                formatter,
                "safety node-checkpoint head differs from the exact expected SafetyState: expected revision {expected_revision}, actual revision {actual_revision}"
            ),
            Self::StateSyncInitializationPending => formatter.write_str(
                "safety-store h1 state-sync initialization has a durable unfinished intent",
            ),
            Self::StateSyncInitializationIntentMismatch => formatter.write_str(
                "safety-store h1 state-sync initialization intent differs from the exact bundle/profile",
            ),
            Self::UnsupportedPlatform => {
                formatter.write_str("safety-store lifetime locking is unsupported on this platform")
            }
            Self::Io { stage, source } => {
                write!(formatter, "safety-store I/O at {stage}: {source}")
            }
            Self::Sqlite { stage, source } => {
                write!(
                    formatter,
                    "safety-store SQLite failure at {stage}: {source}"
                )
            }
            Self::Record { stage, source } => {
                write!(
                    formatter,
                    "safety-state record failure at {stage}: {source}"
                )
            }
            Self::Core { stage, source } => {
                write!(
                    formatter,
                    "persisted Core state failure at {stage}: {source}"
                )
            }
            Self::SchemaMismatch => {
                formatter.write_str("safety-store schema differs from journal v6")
            }
            Self::MetadataMismatch => {
                formatter.write_str("safety-store metadata or binding differs")
            }
            Self::IntegrityFailure => formatter.write_str("safety-store integrity check failed"),
            Self::ForeignKeyFailure => formatter.write_str("safety-store foreign-key check failed"),
            Self::PersistedRepresentationMalformed(reason) => {
                write!(formatter, "malformed safety-store representation: {reason}")
            }
            Self::DurableHalt => formatter.write_str("safety-store is durably halted"),
            Self::Conflict(conflict) => write!(formatter, "safety-store conflict: {conflict:?}"),
            Self::ConflictHaltUncertain { conflict, source } => write!(
                formatter,
                "safety-store conflict {conflict:?} could not persist its halt: {source}"
            ),
            Self::CommitNotApplied { commit } => {
                write!(formatter, "safety-store commit was not applied: {commit}")
            }
            Self::CommitUncertain {
                commit,
                confirmation,
            } => {
                write!(
                    formatter,
                    "safety-store commit remains unconfirmed after {commit}: {confirmation}"
                )
            }
            Self::HeadWatermarkUncertain { source } => write!(
                formatter,
                "safety-store database advanced but its head watermark is unconfirmed: {source}"
            ),
        }
    }
}

impl Error for SafetyStoreErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Sqlite { source, .. } => Some(source),
            Self::ConflictHaltUncertain { source, .. } => Some(source.as_ref()),
            Self::CommitNotApplied { commit } | Self::CommitUncertain { commit, .. } => {
                Some(commit)
            }
            Self::HeadWatermarkUncertain { source } => Some(source.as_ref()),
            Self::Record { .. } | Self::Core { .. } => None,
            _ => None,
        }
    }
}
