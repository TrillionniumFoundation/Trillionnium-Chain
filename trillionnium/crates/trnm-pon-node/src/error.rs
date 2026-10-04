//! Internal failure identity. Display and existing wire error strings stay unchanged.
use std::{error, fmt};

/// An observation category, not blanket permission to retry or restart an owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorKind {
    ProtocolInvalid,
    Capacity,
    Cancelled,
    StaleContext,
    IdentityConflict,
    PolicyRefusal,
    LocalStructure,
    DependencyUnavailable,
    Transport,
    Serialization,
    RemoteRefusal,
    /// Legacy formatted failures remain explicit until their producer is migrated.
    Unclassified,
}

macro_rules! error_codes {
    ($($variant:ident => ($wire:literal, $kind:ident)),+ $(,)?) => {
        /// Exact identities needed by current admission, accounting and recovery paths.
        /// Unknown strings are never recognized by a prefix or by an OS error message.
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        #[non_exhaustive]
        pub enum ErrorCode { $($variant),+ }
        impl ErrorCode {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire),+ }
            }
            fn kind(self) -> ErrorKind {
                match self { $(Self::$variant => ErrorKind::$kind),+ }
            }
            pub(crate) fn parse(message: &str) -> Option<Self> {
                match message { $($wire => Some(Self::$variant)),+, _ => None }
            }
        }
    };
}

error_codes! {
    Hash => ("HASH", ProtocolInvalid),
    HeaderCodec => ("HEADER_CODEC", ProtocolInvalid),
    TransactionCodec => ("TRANSACTION_CODEC", ProtocolInvalid),
    PacketLimit => ("PACKET_LIMIT", ProtocolInvalid),
    TransactionLimit => ("TRANSACTION_LIMIT", ProtocolInvalid),
    DuplicateContent => ("DUPLICATE_CONTENT", IdentityConflict),
    StateCapacity => ("STATE_CAPACITY", Capacity),
    ContinuityProfile => ("CONTINUITY_PROFILE", ProtocolInvalid),
    ContinuityState => ("CONTINUITY_STATE", ProtocolInvalid),
    ContinuityRewardQueue => ("CONTINUITY_REWARD_QUEUE", ProtocolInvalid),
    ContinuityMaintenance => ("CONTINUITY_MAINTENANCE", ProtocolInvalid),
    ContinuityMaterial => ("CONTINUITY_MATERIAL", ProtocolInvalid),
    ContinuityTaskReserved => ("CONTINUITY_TASK_RESERVED", ProtocolInvalid),
    ModelEvidenceState => ("MODEL_EVIDENCE_STATE", ProtocolInvalid),
    ModelEvidenceHash => ("MODEL_EVIDENCE_HASH", ProtocolInvalid),
    ModelEvidenceConfig => ("MODEL_EVIDENCE_CONFIG", StaleContext),
    ModelEvidenceProfile => ("MODEL_EVIDENCE_PROFILE", StaleContext),
    ModelEvidenceTaskAlias => ("MODEL_EVIDENCE_TASK_ALIAS", IdentityConflict),
    ModelEvidenceTask => ("MODEL_EVIDENCE_TASK", ProtocolInvalid),
    ModelEvidenceControl => ("MODEL_EVIDENCE_CONTROL", ProtocolInvalid),
    ModelEvidenceSource => ("MODEL_EVIDENCE_SOURCE", PolicyRefusal),
    ModelEvidenceArithmetic => ("MODEL_EVIDENCE_ARITHMETIC", ProtocolInvalid),
    ModelEvidenceMissing => ("MODEL_EVIDENCE_MISSING", PolicyRefusal),
    ModelEvidenceSourceLimit => ("MODEL_EVIDENCE_SOURCE_LIMIT", Capacity),
    ModelEvidenceSourceBudget => ("MODEL_EVIDENCE_SOURCE_BUDGET", Capacity),
    ModelEvidenceDuplicate => ("MODEL_EVIDENCE_DUPLICATE", IdentityConflict),
    ModelEvidenceReveal => ("MODEL_EVIDENCE_REVEAL", ProtocolInvalid),
    ModelEvidenceBinding => ("MODEL_EVIDENCE_BINDING", IdentityConflict),
    ModelEvidenceGain => ("MODEL_EVIDENCE_GAIN", PolicyRefusal),
    ModelEvidenceReviewHold => ("MODEL_EVIDENCE_REVIEW_HOLD", PolicyRefusal),
    FrameEof => ("FRAME_EOF", Transport),
    FrameDeadline => ("FRAME_DEADLINE", Cancelled),
    PublicEof => ("PUBLIC_EOF", Transport),
    PublicClientDeadline => ("PUBLIC_CLIENT_DEADLINE", Cancelled),
    PeerPollCancelled => ("PEER_POLL_CANCELLED", Cancelled),
    PublicRequestCancelled => ("PUBLIC_REQUEST_CANCELLED", Cancelled),
    PublicRequestDeadline => ("PUBLIC_REQUEST_DEADLINE", Cancelled),
    SubmitRecoveryDeadline => ("SUBMIT_RECOVERY_DEADLINE", Cancelled),
    PublicMutationCpuBudget => ("PUBLIC_MUTATION_CPU_BUDGET", Capacity),
    PublicMutationCpuUnavailable => ("PUBLIC_MUTATION_CPU_UNAVAILABLE", DependencyUnavailable),
    PublicSpentCapacity => ("PUBLIC_SPENT_CAPACITY", Capacity),
    PublicBufferCapacity => ("PUBLIC_BUFFER_CAPACITY", Capacity),
    PublicQueueBusy => ("PUBLIC_QUEUE_BUSY", Capacity),
    ReservedReadOnlyBusy => ("ADMISSION_BUSY_READ_ONLY_RESERVED", Capacity),
    PublicTicketReplay => ("PUBLIC_TICKET_REPLAY", IdentityConflict),
    PublicCookieExpired => ("PUBLIC_COOKIE_EXPIRED", StaleContext),
    PublicCookieContext => ("PUBLIC_COOKIE_CONTEXT", StaleContext),
    PublicChallengeContext => ("PUBLIC_CHALLENGE_CONTEXT", StaleContext),
    PublicResponseContext => ("PUBLIC_RESPONSE_CONTEXT", StaleContext),
    PublicChallengeSignature => ("PUBLIC_CHALLENGE_SIGNATURE", ProtocolInvalid),
    PublicResponseSignature => ("PUBLIC_RESPONSE_SIGNATURE", ProtocolInvalid),
    UnknownParent => ("UNKNOWN_PARENT", StaleContext),
    TimeDeferred => ("TIME_DEFERRED", StaleContext),
    Cursor => ("CURSOR", StaleContext),
    SubmitRecoveryStaleHead => ("SUBMIT_RECOVERY_STALE_HEAD", StaleContext),
    SubmitRecoveryStaleBranch => ("SUBMIT_RECOVERY_STALE_BRANCH", StaleContext),
    OwnerPoisoned => ("OWNER_POISONED", LocalStructure),
    NamespaceChanged => ("NAMESPACE_CHANGED", IdentityConflict),
    DatabaseReplaced => ("DATABASE_REPLACED", IdentityConflict),
    OwnerReplaced => ("OWNER_REPLACED", IdentityConflict),
    ReorgInProgress => ("REORG_IN_PROGRESS", LocalStructure),
    StorageContext => ("STORAGE_CONTEXT", LocalStructure),
    StorageHash => ("STORAGE_HASH", LocalStructure),
    StoragePacket => ("STORAGE_PACKET", LocalStructure),
    StorageWork => ("STORAGE_WORK", LocalStructure),
    AncestryIndexBudget => ("ANCESTRY_INDEX_BUDGET", Capacity),
    AncestryIndexGenesis => ("ANCESTRY_INDEX_GENESIS", LocalStructure),
    AncestryIndexHash => ("ANCESTRY_INDEX_HASH", LocalStructure),
    AncestryIndexHeader => ("ANCESTRY_INDEX_HEADER", LocalStructure),
    AncestryIndexLevel => ("ANCESTRY_INDEX_LEVEL", LocalStructure),
    AncestryIndexMetadata => ("ANCESTRY_INDEX_METADATA", LocalStructure),
    AncestryIndexMissing => ("ANCESTRY_INDEX_MISSING", LocalStructure),
    AncestryIndexPacketBytes => ("ANCESTRY_INDEX_PACKET_BYTES", LocalStructure),
    AncestryIndexParent => ("ANCESTRY_INDEX_PARENT", LocalStructure),
    AncestryIndexSeal => ("ANCESTRY_INDEX_SEAL", LocalStructure),
    AncestryIndexStructure => ("ANCESTRY_INDEX_STRUCTURE", LocalStructure),
    AncestryIndexUnknownBlock => ("ANCESTRY_INDEX_UNKNOWN_BLOCK", StaleContext),
    RemoteTerminal => ("REMOTE_TERMINAL", RemoteRefusal),
    RemoteRetryable => ("REMOTE_RETRYABLE", RemoteRefusal),
}

#[derive(Debug)]
pub struct Error {
    code: Option<ErrorCode>,
    kind: ErrorKind,
    message: String,
    source: Option<Box<dyn error::Error + Send + Sync>>,
}
impl Error {
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code: Some(code),
            kind: code.kind(),
            message: code.as_str().into(),
            source: None,
        }
    }
    pub fn code(&self) -> Option<ErrorCode> {
        self.code
    }
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }
    pub fn is(&self, code: ErrorCode) -> bool {
        self.code == Some(code)
    }
    /// Only local owner/DB/history failures stop pinned polling. A peer's signed
    /// refusal is still a remote observation, even if it names a structural code.
    /// Ancestry budget exhaustion retains its existing fatal policy without being
    /// mislabeled as corrupt storage. Capacity alone never authorizes a retry.
    pub fn requires_owner_stop(&self) -> bool {
        if self.kind == ErrorKind::RemoteRefusal {
            return false;
        }
        self.kind == ErrorKind::LocalStructure
            || matches!(
                self.code,
                Some(
                    ErrorCode::NamespaceChanged
                        | ErrorCode::DatabaseReplaced
                        | ErrorCode::OwnerReplaced
                        | ErrorCode::AncestryIndexBudget
                )
            )
    }
    /// Parse only after the caller has established its required reply authentication.
    /// Construction itself authenticates nothing and gives no local failure authority.
    pub(crate) fn remote(message: impl Into<String>) -> Self {
        let mut error = Self::from(message.into());
        error.kind = ErrorKind::RemoteRefusal;
        error
    }
    pub(crate) fn authenticated_remote(terminal: bool, message: &str) -> Self {
        let code = if terminal {
            ErrorCode::RemoteTerminal
        } else {
            ErrorCode::RemoteRetryable
        };
        let mut error = Self::new(code);
        error.message = format!("{}:{message}", code.as_str());
        error
    }
    fn caused_by(
        kind: ErrorKind,
        prefix: &str,
        source: impl error::Error + Send + Sync + 'static,
    ) -> Self {
        Self {
            code: None,
            kind,
            message: format!("{prefix}: {source}"),
            source: Some(Box::new(source)),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn error::Error + 'static))
    }
}
impl From<&str> for Error {
    fn from(message: &str) -> Self {
        Self::from(message.to_owned())
    }
}
impl From<String> for Error {
    fn from(message: String) -> Self {
        let code = ErrorCode::parse(&message);
        Self {
            code,
            kind: code.map_or(ErrorKind::Unclassified, ErrorCode::kind),
            message,
            source: None,
        }
    }
}
impl From<std::io::Error> for Error {
    fn from(source: std::io::Error) -> Self {
        Self::caused_by(ErrorKind::Transport, "IO", source)
    }
}
impl From<rusqlite::Error> for Error {
    fn from(source: rusqlite::Error) -> Self {
        Self::caused_by(ErrorKind::LocalStructure, "STORAGE", source)
    }
}
impl From<serde_json::Error> for Error {
    fn from(source: serde_json::Error) -> Self {
        Self::caused_by(ErrorKind::Serialization, "JSON", source)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_changes_cannot_change_typed_retry_or_owner_stop_identity() {
        let mut budget = Error::new(ErrorCode::PublicMutationCpuBudget);
        assert_eq!(budget.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
        budget.message = "receiver CPU reservation temporarily unavailable".into();
        assert!(budget.is(ErrorCode::PublicMutationCpuBudget));
        assert_eq!(budget.kind(), ErrorKind::Capacity);
        assert!(!budget.requires_owner_stop());
        let mut storage = Error::new(ErrorCode::StoragePacket);
        storage.message = "invalid retained packet bytes".into();
        assert!(storage.requires_owner_stop());
        let mut eof = Error::new(ErrorCode::FrameEof);
        eof.message = "peer closed the socket".into();
        assert!(eof.is(ErrorCode::FrameEof));
    }

    #[test]
    fn prefix_lookalikes_and_remote_failures_cannot_stop_local_owner() {
        for message in [
            "STORAGE_REPORTED_BY_PEER",
            "ANCESTRY_INDEX_REPORTED_BY_PEER",
            "STORAGE: remote text",
            "FRAME_EOF: remote text",
        ] {
            let error = Error::from(message);
            assert_eq!(error.code(), None);
            assert_eq!(error.kind(), ErrorKind::Unclassified);
            assert!(!error.requires_owner_stop());
            assert_eq!(error.to_string(), message);
        }
        for message in ["STORAGE_PACKET", "OWNER_REPLACED", "ANCESTRY_INDEX_SEAL"] {
            let local = Error::from(message);
            assert!(local.requires_owner_stop());
            let remote = Error::remote(message);
            assert_eq!(remote.code(), local.code());
            assert_eq!(remote.kind(), ErrorKind::RemoteRefusal);
            assert!(!remote.requires_owner_stop());
            assert_eq!(remote.to_string(), message);
        }
        assert!(!Error::from("ANCESTRY_INDEX_UNKNOWN_BLOCK").requires_owner_stop());
        let budget = Error::from("ANCESTRY_INDEX_BUDGET");
        assert_eq!(budget.kind(), ErrorKind::Capacity);
        assert!(budget.requires_owner_stop());
    }

    #[test]
    fn typed_causes_preserve_source_and_display_without_parsing_source_text() {
        let io = std::io::Error::other("FRAME_EOF");
        let error = Error::from(io);
        assert_eq!(error.to_string(), "IO: FRAME_EOF");
        assert_eq!(error.kind(), ErrorKind::Transport);
        assert_eq!(error.code(), None);
        assert!(error.source().unwrap().is::<std::io::Error>());
        assert!(!error.requires_owner_stop());
        let sqlite = rusqlite::Error::InvalidQuery;
        let expected = format!("STORAGE: {sqlite}");
        let error = Error::from(sqlite);
        assert_eq!(error.to_string(), expected);
        assert!(error.source().unwrap().is::<rusqlite::Error>());
        assert!(error.requires_owner_stop());
        let json = serde_json::from_str::<bool>("[").unwrap_err();
        let expected = format!("JSON: {json}");
        let error = Error::from(json);
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.kind(), ErrorKind::Serialization);
        assert!(error.source().unwrap().is::<serde_json::Error>());
    }

    #[test]
    fn authenticated_reply_terminality_controls_remote_retry_identity() {
        let retry = Error::authenticated_remote(false, "REMOTE_TERMINAL: misleading text");
        assert!(retry.is(ErrorCode::RemoteRetryable));
        assert_eq!(
            retry.to_string(),
            "REMOTE_RETRYABLE:REMOTE_TERMINAL: misleading text"
        );
        let terminal = Error::authenticated_remote(true, "REMOTE_RETRYABLE: misleading text");
        assert!(terminal.is(ErrorCode::RemoteTerminal));
        assert_eq!(
            terminal.to_string(),
            "REMOTE_TERMINAL:REMOTE_RETRYABLE: misleading text"
        );
        assert!(!terminal.requires_owner_stop());
    }
}
