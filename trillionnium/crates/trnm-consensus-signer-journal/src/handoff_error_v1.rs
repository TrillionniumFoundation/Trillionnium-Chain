use std::{error::Error, fmt, io};

use crate::{ExternalWatermarkErrorV0, SignatureProducerErrorV0};

/// Safety conflicts in the independent handoff-capable schema1 journal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffSignerJournalConflictV1 {
    FileIdentityChanged,
    ProcessChanged,
    ExternalWatermarkMissing,
    ExternalWatermarkMismatch,
    PreparedIntentPending,
    SameRoundDifferentIntent {
        epoch: u64,
        view: u64,
        kind: u8,
    },
    HandoffTransitionDifferentIntent {
        old_epoch: u64,
        new_epoch: u64,
        role: u8,
    },
    SafetyRevisionRegression {
        maximum: u64,
        incoming: u64,
    },
    ViewRegression {
        kind: u8,
        maximum: u64,
        incoming: u64,
    },
    TerminalOldEpochFence {
        old_epoch: u64,
    },
    CommitReadbackConflict,
}

/// Closed failures for schema1 profile, admission, persistence, and signing.
#[derive(Debug)]
pub enum HandoffSignerJournalErrorV1 {
    InvalidProfile(&'static str),
    InvalidAdmission(&'static str),
    AdmissionMismatch(&'static str),
    NewSetAdmissionUnavailable,
    LegacySchemaReadOnly,
    AlreadyExists,
    Missing,
    Locked,
    UnsupportedPlatform,
    Io {
        stage: &'static str,
        source: io::Error,
    },
    Sqlite {
        stage: &'static str,
        source: rusqlite::Error,
    },
    Intent(&'static str),
    IntentTooLarge {
        actual: usize,
        maximum: usize,
    },
    SchemaMismatch,
    MetadataMismatch,
    IntegrityFailure,
    CapacityExhausted,
    PersistedRepresentationMalformed(&'static str),
    Conflict(HandoffSignerJournalConflictV1),
    ExternalWatermark {
        stage: &'static str,
        source: ExternalWatermarkErrorV0,
    },
    SignatureProducer(SignatureProducerErrorV0),
    InvalidProducedSignature,
}

impl HandoffSignerJournalErrorV1 {
    pub(crate) fn io(stage: &'static str, source: io::Error) -> Self {
        Self::Io { stage, source }
    }

    pub(crate) fn sqlite(stage: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { stage, source }
    }

    pub(crate) fn external(stage: &'static str, source: ExternalWatermarkErrorV0) -> Self {
        Self::ExternalWatermark { stage, source }
    }
}

impl fmt::Display for HandoffSignerJournalErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(reason) => write!(formatter, "invalid schema1 profile: {reason}"),
            Self::InvalidAdmission(reason) => {
                write!(formatter, "invalid strict handoff admission: {reason}")
            }
            Self::AdmissionMismatch(field) => {
                write!(formatter, "strict handoff admission differs at {field}")
            }
            Self::NewSetAdmissionUnavailable => formatter.write_str(
                "new-set strict pre-certificate handoff admission is not implemented in schema1",
            ),
            Self::LegacySchemaReadOnly => formatter.write_str(
                "legacy schema0 signer journal is identifiable only and cannot be reinterpreted as schema1",
            ),
            Self::AlreadyExists => formatter.write_str("schema1 signer journal already exists"),
            Self::Missing => formatter.write_str("schema1 signer journal is missing"),
            Self::Locked => formatter.write_str("schema1 signer journal lifetime lock is held"),
            Self::UnsupportedPlatform => {
                formatter.write_str("schema1 signer journal is supported only on Linux")
            }
            Self::Io { stage, source } => write!(formatter, "schema1 journal I/O at {stage}: {source}"),
            Self::Sqlite { stage, source } => {
                write!(formatter, "schema1 journal SQLite failure at {stage}: {source}")
            }
            Self::Intent(reason) => write!(formatter, "canonical signer intent rejected: {reason}"),
            Self::IntentTooLarge { actual, maximum } => {
                write!(formatter, "canonical signer intent is {actual} bytes, above {maximum}")
            }
            Self::SchemaMismatch => formatter.write_str("signer journal schema is not exact schema1"),
            Self::MetadataMismatch => formatter.write_str("schema1 metadata/profile binding differs"),
            Self::IntegrityFailure => formatter.write_str("schema1 journal integrity check failed"),
            Self::CapacityExhausted => formatter.write_str("schema1 journal capacity exhausted"),
            Self::PersistedRepresentationMalformed(reason) => {
                write!(formatter, "malformed schema1 journal representation: {reason}")
            }
            Self::Conflict(conflict) => write!(formatter, "schema1 journal conflict: {conflict:?}"),
            Self::ExternalWatermark { stage, source } => {
                write!(formatter, "schema1 external watermark failed at {stage}: {source:?}")
            }
            Self::SignatureProducer(source) => {
                write!(formatter, "schema1 signature producer failed: {source:?}")
            }
            Self::InvalidProducedSignature => {
                formatter.write_str("schema1 producer returned an invalid Ed25519 signature")
            }
        }
    }
}

impl Error for HandoffSignerJournalErrorV1 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Sqlite { source, .. } => Some(source),
            _ => None,
        }
    }
}
