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
            Self::SchemaMismatch => formatter.write_str("safety-store schema differs from v1"),
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
