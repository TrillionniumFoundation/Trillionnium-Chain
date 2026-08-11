use std::{error::Error, fmt, io};

use trnm_consensus_types::ValidationError;

/// Closed failures reported by an independently administered monotonic store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalWatermarkErrorV0 {
    Unavailable,
    CompareFailed,
    InvalidPersistedState,
    CapacityExhausted,
}

/// Closed failure surface for an injected private-key/HSM/KMS adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureProducerErrorV0 {
    Unavailable,
    Rejected,
    Internal,
}

/// A conflict is a safety event, not a retryable signing failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerJournalConflictV0 {
    FileIdentityChanged,
    ProcessChanged,
    ExternalWatermarkMissing,
    ExternalWatermarkRollback,
    ExternalWatermarkAhead,
    ExternalWatermarkFork,
    SafetyRevisionRegression {
        maximum: u64,
        incoming: u64,
    },
    ViewRegression {
        kind: u8,
        maximum: u64,
        incoming: u64,
    },
    SameRoundDifferentIntent {
        epoch: u64,
        view: u64,
        kind: u8,
    },
    PreparedIntentPending,
    CommitReadbackConflict,
}

/// Typed failure surface for the standalone signer journal.
#[derive(Debug)]
pub enum SignerJournalErrorV0 {
    InvalidProfile(&'static str),
    AlreadyExists(&'static str),
    Missing(&'static str),
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
    Intent {
        stage: &'static str,
        source: ValidationError,
    },
    IntentProfileDrift(&'static str),
    IntentTooLarge {
        actual: usize,
        maximum: usize,
    },
    SchemaMismatch,
    MetadataMismatch,
    IntegrityFailure,
    ForeignKeyFailure,
    CapacityExhausted,
    PersistedRepresentationMalformed(&'static str),
    Conflict(SignerJournalConflictV0),
    ExternalWatermark {
        stage: &'static str,
        source: ExternalWatermarkErrorV0,
    },
    SignatureProducer(SignatureProducerErrorV0),
    InvalidProducedSignature,
    CommitNotApplied {
        commit: rusqlite::Error,
    },
    CommitUncertain {
        commit: rusqlite::Error,
        reason: &'static str,
    },
}

impl SignerJournalErrorV0 {
    pub(crate) fn io(stage: &'static str, source: io::Error) -> Self {
        Self::Io { stage, source }
    }

    pub(crate) fn sqlite(stage: &'static str, source: rusqlite::Error) -> Self {
        Self::Sqlite { stage, source }
    }

    pub(crate) fn intent(stage: &'static str, source: ValidationError) -> Self {
        Self::Intent { stage, source }
    }

    pub(crate) fn external(stage: &'static str, source: ExternalWatermarkErrorV0) -> Self {
        Self::ExternalWatermark { stage, source }
    }
}

impl fmt::Display for SignerJournalErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProfile(reason) => write!(formatter, "invalid signer profile: {reason}"),
            Self::AlreadyExists(target) => write!(formatter, "signer journal {target} exists"),
            Self::Missing(target) => write!(formatter, "signer journal {target} is missing"),
            Self::Locked => formatter.write_str("signer journal lifetime lock is held"),
            Self::UnsupportedPlatform => {
                formatter.write_str("signer journal v0 is supported only on Linux")
            }
            Self::Io { stage, source } => {
                write!(formatter, "signer journal I/O at {stage}: {source}")
            }
            Self::Sqlite { stage, source } => {
                write!(
                    formatter,
                    "signer journal SQLite failure at {stage}: {source}"
                )
            }
            Self::Intent { stage, source } => {
                write!(
                    formatter,
                    "canonical sign intent failed at {stage}: {source}"
                )
            }
            Self::IntentProfileDrift(field) => {
                write!(
                    formatter,
                    "canonical sign intent {field} differs from signer profile"
                )
            }
            Self::IntentTooLarge { actual, maximum } => write!(
                formatter,
                "canonical sign intent is {actual} bytes, above bound {maximum}"
            ),
            Self::SchemaMismatch => formatter.write_str("signer journal schema differs from v0"),
            Self::MetadataMismatch => {
                formatter.write_str("signer journal metadata or profile binding differs")
            }
            Self::IntegrityFailure => formatter.write_str("signer journal integrity check failed"),
            Self::ForeignKeyFailure => {
                formatter.write_str("signer journal foreign-key check failed")
            }
            Self::CapacityExhausted => formatter.write_str("signer journal capacity exhausted"),
            Self::PersistedRepresentationMalformed(reason) => {
                write!(
                    formatter,
                    "malformed signer journal representation: {reason}"
                )
            }
            Self::Conflict(conflict) => write!(formatter, "signer journal conflict: {conflict:?}"),
            Self::ExternalWatermark { stage, source } => {
                write!(
                    formatter,
                    "external signer watermark failed at {stage}: {source:?}"
                )
            }
            Self::SignatureProducer(source) => {
                write!(formatter, "signature producer failed: {source:?}")
            }
            Self::InvalidProducedSignature => {
                formatter.write_str("signature producer returned an invalid signature")
            }
            Self::CommitNotApplied { commit } => {
                write!(formatter, "signer journal commit was not applied: {commit}")
            }
            Self::CommitUncertain { commit, reason } => write!(
                formatter,
                "signer journal commit remains uncertain after {commit}: {reason}"
            ),
        }
    }
}

impl Error for SignerJournalErrorV0 {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Sqlite { source, .. } => Some(source),
            Self::CommitNotApplied { commit } | Self::CommitUncertain { commit, .. } => {
                Some(commit)
            }
            _ => None,
        }
    }
}
