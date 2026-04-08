use super::{fmt, CapabilityScope, SettlementStatus};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InteropIdentityError {
    InvalidSettlementTransition {
        from: SettlementStatus,
        to: SettlementStatus,
    },
    InvalidSettlementHeightRegression {
        current_at: u64,
        next_at: u64,
    },
    SettlementTerminalPayloadConflict {
        status: SettlementStatus,
        existing: String,
        provided: String,
    },
    InvalidSettlementReceiptStatus {
        expected: u8,
        got: u8,
    },
    DidAlreadyExists {
        did: String,
    },
    InvalidIdentityValue {
        field: &'static str,
        value: String,
    },
    DidNotFound {
        did: String,
    },
    DidRevoked {
        did: String,
    },
    UnauthorizedActor {
        actor: String,
        did: String,
        controller: String,
    },
    CapabilityNotFound {
        token_id: u64,
    },
    CapabilityScopeMismatch {
        token_id: u64,
        expected: CapabilityScope,
        actual: CapabilityScope,
    },
    CapabilityInactive {
        token_id: u64,
        at_height: u64,
        issued_at: u64,
        expires_at: Option<u64>,
        revoked_at: Option<u64>,
    },
    InvalidCapabilityExpiry {
        issued_at: u64,
        expires_at: u64,
    },
    CapabilityRenewalRegression {
        current_expires_at: u64,
        requested_expires_at: u64,
    },
    CapabilityRenewalCannotClearExpiry {
        current_expires_at: u64,
    },
    InvalidCapabilityRevocationHeight {
        issued_at: u64,
        revoked_at: u64,
    },
    InvalidCapabilityIssueHeight {
        did: String,
        created_at: u64,
        issued_at: u64,
    },
    InvalidDidRevocationHeight {
        created_at: u64,
        revoked_at: u64,
    },
    MissingSettlementTx,
    MissingRevertReason,
}

impl fmt::Display for InteropIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InteropIdentityError::InvalidSettlementTransition { from, to } => {
                write!(f, "illegal settlement transition: {:?} -> {:?}", from, to)
            }
            InteropIdentityError::InvalidSettlementHeightRegression {
                current_at,
                next_at,
            } => {
                write!(
                    f,
                    "invalid settlement height regression: next_at {} < current_at {}",
                    next_at, current_at
                )
            }
            InteropIdentityError::SettlementTerminalPayloadConflict {
                status,
                existing,
                provided,
            } => {
                write!(
                    f,
                    "terminal settlement payload conflict for {:?}: existing {:?}, provided {:?}",
                    status, existing, provided
                )
            }
            InteropIdentityError::InvalidSettlementReceiptStatus { expected, got } => {
                write!(
                    f,
                    "invalid settlement receipt status: expected {}, got {}",
                    expected, got
                )
            }
            InteropIdentityError::DidAlreadyExists { did } => {
                write!(f, "did already exists: {}", did)
            }
            InteropIdentityError::InvalidIdentityValue { field, value } => {
                write!(f, "invalid identity value for {}: {:?}", field, value)
            }
            InteropIdentityError::DidNotFound { did } => {
                write!(f, "did not found: {}", did)
            }
            InteropIdentityError::DidRevoked { did } => {
                write!(f, "did revoked: {}", did)
            }
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } => {
                write!(
                    f,
                    "unauthorized actor {} for did {} (controller: {})",
                    actor, did, controller
                )
            }
            InteropIdentityError::CapabilityNotFound { token_id } => {
                write!(f, "capability not found: {}", token_id)
            }
            InteropIdentityError::CapabilityScopeMismatch {
                token_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "capability scope mismatch for token {}: expected {:?}, got {:?}",
                    token_id, expected, actual
                )
            }
            InteropIdentityError::CapabilityInactive {
                token_id,
                at_height,
                issued_at,
                expires_at,
                revoked_at,
            } => {
                write!(
                    f,
                    "capability inactive for token {} at height {} (issued_at={}, expires_at={:?}, revoked_at={:?})",
                    token_id, at_height, issued_at, expires_at, revoked_at
                )
            }
            InteropIdentityError::InvalidCapabilityExpiry {
                issued_at,
                expires_at,
            } => {
                write!(
                    f,
                    "invalid capability expiry: expires_at {} < issued_at {}",
                    expires_at, issued_at
                )
            }
            InteropIdentityError::CapabilityRenewalRegression {
                current_expires_at,
                requested_expires_at,
            } => {
                write!(
                    f,
                    "capability renewal regression: requested expiry {} < current expiry {}",
                    requested_expires_at, current_expires_at
                )
            }
            InteropIdentityError::CapabilityRenewalCannotClearExpiry { current_expires_at } => {
                write!(
                    f,
                    "capability renewal cannot clear existing expiry {}",
                    current_expires_at
                )
            }
            InteropIdentityError::InvalidCapabilityRevocationHeight {
                issued_at,
                revoked_at,
            } => {
                write!(
                    f,
                    "invalid capability revocation height: revoked_at {} < issued_at {}",
                    revoked_at, issued_at
                )
            }
            InteropIdentityError::InvalidCapabilityIssueHeight {
                did,
                created_at,
                issued_at,
            } => {
                write!(
                    f,
                    "invalid capability issue height for {}: issued_at {} < did created_at {}",
                    did, issued_at, created_at
                )
            }
            InteropIdentityError::InvalidDidRevocationHeight {
                created_at,
                revoked_at,
            } => {
                write!(
                    f,
                    "invalid did revocation height: revoked_at {} < created_at {}",
                    revoked_at, created_at
                )
            }
            InteropIdentityError::MissingSettlementTx => {
                write!(f, "finalized settlement requires non-empty settlement_tx")
            }
            InteropIdentityError::MissingRevertReason => {
                write!(f, "reverted settlement requires non-empty revert_reason")
            }
        }
    }
}

impl std::error::Error for InteropIdentityError {}
