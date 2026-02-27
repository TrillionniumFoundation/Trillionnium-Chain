use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

/// Chain-pair abstraction for cross-chain bridge settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRoute {
    pub route_id: String,
    pub source_chain: String,
    pub target_chain: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SettlementStatus {
    Pending,
    Finalized,
    Reverted,
}

impl SettlementStatus {
    pub fn can_transition_to(self, to: Self) -> bool {
        if self == to {
            return true;
        }

        matches!(
            (self, to),
            (SettlementStatus::Pending, SettlementStatus::Finalized)
                | (SettlementStatus::Pending, SettlementStatus::Reverted)
        )
    }

    pub fn transition(self, to: Self) -> Result<Self, InteropIdentityError> {
        if self.can_transition_to(to) {
            return Ok(to);
        }
        Err(InteropIdentityError::InvalidSettlementTransition {
            from: self,
            to,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRecord {
    pub settlement_id: u64,
    pub route: BridgeRoute,
    pub status: SettlementStatus,
    pub at_height: u64,
    pub settlement_tx: Option<String>,
    pub revert_reason: Option<String>,
}

impl SettlementRecord {
    pub fn apply_status(
        &mut self,
        to: SettlementStatus,
        at_height: u64,
        settlement_tx: Option<String>,
        revert_reason: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        if at_height < self.at_height {
            return Err(InteropIdentityError::InvalidSettlementHeightRegression {
                current_at: self.at_height,
                next_at: at_height,
            });
        }

        let next_status = self.status.transition(to)?;

        let (next_settlement_tx, next_revert_reason) = match to {
            SettlementStatus::Finalized => {
                let tx = settlement_tx
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .or_else(|| self.settlement_tx.clone())
                    .ok_or(InteropIdentityError::MissingSettlementTx)?;
                (Some(tx), None)
            }
            SettlementStatus::Reverted => {
                let reason = revert_reason
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .or_else(|| self.revert_reason.clone())
                    .ok_or(InteropIdentityError::MissingRevertReason)?;
                (None, Some(reason))
            }
            SettlementStatus::Pending => (self.settlement_tx.clone(), self.revert_reason.clone()),
        };

        self.status = next_status;
        self.at_height = at_height;
        self.settlement_tx = next_settlement_tx;
        self.revert_reason = next_revert_reason;

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CapabilityScope {
    BridgeSettle,
    BridgeRevert,
    AuditRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DidRecord {
    pub did: String,
    pub controller: String,
    pub created_at: u64,
    pub revoked_at: Option<u64>,
}

impl DidRecord {
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityToken {
    pub token_id: u64,
    pub subject_did: String,
    pub scope: CapabilityScope,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

impl CapabilityToken {
    pub fn is_active_at(&self, at_height: u64) -> bool {
        if at_height < self.issued_at {
            return false;
        }

        if let Some(revoked_at) = self.revoked_at {
            if at_height >= revoked_at {
                return false;
            }
        }

        match self.expires_at {
            Some(exp) => at_height <= exp,
            None => true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditAction {
    DidRegistered,
    DidRevoked,
    CapabilityIssued,
    CapabilityRevoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub seq: u64,
    pub action: AuditAction,
    pub actor: String,
    pub subject: String,
    pub at_height: u64,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityRegistry {
    dids: BTreeMap<String, DidRecord>,
    capabilities: BTreeMap<u64, CapabilityToken>,
    audit_trail: Vec<AuditEvent>,
    next_capability_id: u64,
}

impl IdentityRegistry {
    fn validate_identity_field(
        field: &'static str,
        value: &str,
    ) -> Result<(), InteropIdentityError> {
        if value.trim().is_empty() || value.trim() != value {
            return Err(InteropIdentityError::InvalidIdentityValue {
                field,
                value: value.to_string(),
            });
        }
        Ok(())
    }

    pub fn register_did(
        &mut self,
        did: String,
        controller: String,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("did", &did)?;
        Self::validate_identity_field("controller", &controller)?;

        if self.dids.contains_key(&did) {
            return Err(InteropIdentityError::DidAlreadyExists { did });
        }
        self.dids.insert(
            did.clone(),
            DidRecord {
                did: did.clone(),
                controller: controller.clone(),
                created_at: at_height,
                revoked_at: None,
            },
        );
        self.push_audit(
            AuditAction::DidRegistered,
            controller,
            did,
            at_height,
            None,
        );
        Ok(())
    }

    pub fn issue_capability(
        &mut self,
        actor: String,
        subject_did: String,
        scope: CapabilityScope,
        at_height: u64,
        expires_at: Option<u64>,
    ) -> Result<u64, InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;
        Self::validate_identity_field("subject_did", &subject_did)?;

        if let Some(exp) = expires_at {
            if exp < at_height {
                return Err(InteropIdentityError::InvalidCapabilityExpiry {
                    issued_at: at_height,
                    expires_at: exp,
                });
            }
        }

        match self.dids.get(&subject_did) {
            Some(did) if did.is_active() => {
                if at_height < did.created_at {
                    return Err(InteropIdentityError::InvalidCapabilityIssueHeight {
                        did: subject_did.clone(),
                        created_at: did.created_at,
                        issued_at: at_height,
                    });
                }
            }
            Some(_) => {
                return Err(InteropIdentityError::DidRevoked {
                    did: subject_did.clone(),
                });
            }
            None => {
                return Err(InteropIdentityError::DidNotFound {
                    did: subject_did.clone(),
                });
            }
        }

        self.next_capability_id += 1;
        let token_id = self.next_capability_id;
        self.capabilities.insert(
            token_id,
            CapabilityToken {
                token_id,
                subject_did: subject_did.clone(),
                scope,
                issued_at: at_height,
                expires_at,
                revoked_at: None,
            },
        );
        self.push_audit(
            AuditAction::CapabilityIssued,
            actor,
            subject_did,
            at_height,
            Some(format!("token_id={}", token_id)),
        );
        Ok(token_id)
    }

    pub fn revoke_capability(
        &mut self,
        actor: String,
        token_id: u64,
        at_height: u64,
        note: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;

        let subject = {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if token.revoked_at.is_some() {
                return Ok(());
            }
            if at_height < token.issued_at {
                return Err(InteropIdentityError::InvalidCapabilityRevocationHeight {
                    issued_at: token.issued_at,
                    revoked_at: at_height,
                });
            }
            token.revoked_at = Some(at_height);
            token.subject_did.clone()
        };
        self.push_audit(
            AuditAction::CapabilityRevoked,
            actor,
            subject,
            at_height,
            note,
        );
        Ok(())
    }

    pub fn revoke_did(
        &mut self,
        actor: String,
        did: &str,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;
        Self::validate_identity_field("did", did)?;

        let did_rec = self
            .dids
            .get_mut(did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: did.to_string(),
            })?;

        if did_rec.revoked_at.is_some() {
            return Ok(());
        }

        if at_height < did_rec.created_at {
            return Err(InteropIdentityError::InvalidDidRevocationHeight {
                created_at: did_rec.created_at,
                revoked_at: at_height,
            });
        }

        did_rec.revoked_at = Some(at_height);
        self.push_audit(
            AuditAction::DidRevoked,
            actor,
            did.to_string(),
            at_height,
            None,
        );

        let to_revoke: Vec<u64> = self
            .capabilities
            .iter()
            .filter_map(|(token_id, token)| {
                (token.subject_did == did && token.revoked_at.is_none()).then_some(*token_id)
            })
            .collect();

        for token_id in to_revoke {
            let subject = {
                let Some(token) = self.capabilities.get_mut(&token_id) else {
                    continue;
                };
                token.revoked_at = Some(at_height);
                token.subject_did.clone()
            };
            self.push_audit(
                AuditAction::CapabilityRevoked,
                "system:cascade".to_string(),
                subject,
                at_height,
                Some(format!("cascade_on_did_revoke token_id={}", token_id)),
            );
        }

        Ok(())
    }

    pub fn did(&self, did: &str) -> Option<&DidRecord> {
        self.dids.get(did)
    }

    pub fn capability(&self, token_id: u64) -> Option<&CapabilityToken> {
        self.capabilities.get(&token_id)
    }

    pub fn audit_trail(&self) -> &[AuditEvent] {
        &self.audit_trail
    }

    fn push_audit(
        &mut self,
        action: AuditAction,
        actor: String,
        subject: String,
        at_height: u64,
        note: Option<String>,
    ) {
        let seq = self.audit_trail.len() as u64 + 1;
        self.audit_trail.push(AuditEvent {
            seq,
            action,
            actor,
            subject,
            at_height,
            note,
        });
    }
}

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
    CapabilityNotFound {
        token_id: u64,
    },
    InvalidCapabilityExpiry {
        issued_at: u64,
        expires_at: u64,
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
            InteropIdentityError::CapabilityNotFound { token_id } => {
                write!(f, "capability not found: {}", token_id)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_state_machine_enforces_pending_terminal_model() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 7,
            route,
            status: SettlementStatus::Pending,
            at_height: 100,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Finalized,
            105,
            Some("0xabc".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(rec.status, SettlementStatus::Finalized);
        assert_eq!(rec.settlement_tx.as_deref(), Some("0xabc"));

        let err = rec
            .apply_status(
                SettlementStatus::Reverted,
                106,
                None,
                Some("late fraud proof".to_string()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidSettlementTransition {
                from: SettlementStatus::Finalized,
                to: SettlementStatus::Reverted
            }
        ));
    }

    #[test]
    fn settlement_reapply_same_terminal_status_is_idempotent() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut finalized = SettlementRecord {
            settlement_id: 8,
            route: route.clone(),
            status: SettlementStatus::Pending,
            at_height: 100,
            settlement_tx: None,
            revert_reason: None,
        };
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                101,
                Some("0xabc".to_string()),
                None,
            )
            .unwrap();
        finalized
            .apply_status(SettlementStatus::Finalized, 102, None, None)
            .unwrap();
        assert_eq!(finalized.status, SettlementStatus::Finalized);
        assert_eq!(finalized.settlement_tx.as_deref(), Some("0xabc"));
        assert_eq!(finalized.revert_reason, None);

        let mut reverted = SettlementRecord {
            settlement_id: 9,
            route,
            status: SettlementStatus::Pending,
            at_height: 200,
            settlement_tx: None,
            revert_reason: None,
        };
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                201,
                None,
                Some("fraud-proof".to_string()),
            )
            .unwrap();
        reverted
            .apply_status(SettlementStatus::Reverted, 202, None, None)
            .unwrap();
        assert_eq!(reverted.status, SettlementStatus::Reverted);
        assert_eq!(reverted.settlement_tx, None);
        assert_eq!(reverted.revert_reason.as_deref(), Some("fraud-proof"));
    }

    #[test]
    fn settlement_revert_and_finalize_fields_are_mutually_exclusive() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 9,
            route,
            status: SettlementStatus::Pending,
            at_height: 100,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            101,
            Some("0xshould-be-ignored".to_string()),
            Some("executor_sla_timeout".to_string()),
        )
        .unwrap();
        assert_eq!(rec.status, SettlementStatus::Reverted);
        assert_eq!(rec.revert_reason.as_deref(), Some("executor_sla_timeout"));
        assert_eq!(rec.settlement_tx, None);

        let mut rec2 = SettlementRecord {
            settlement_id: 10,
            route: BridgeRoute {
                route_id: "eth->trnm".to_string(),
                source_chain: "ethereum".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 200,
            settlement_tx: Some("0xstale".to_string()),
            revert_reason: Some("stale-reason".to_string()),
        };

        rec2.apply_status(
            SettlementStatus::Finalized,
            201,
            Some("0xfinal".to_string()),
            Some("should-be-cleared".to_string()),
        )
        .unwrap();
        assert_eq!(rec2.status, SettlementStatus::Finalized);
        assert_eq!(rec2.settlement_tx.as_deref(), Some("0xfinal"));
        assert_eq!(rec2.revert_reason, None);
    }

    #[test]
    fn settlement_finalize_requires_non_empty_settlement_tx() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 11,
            route,
            status: SettlementStatus::Pending,
            at_height: 100,
            settlement_tx: None,
            revert_reason: None,
        };

        let err = rec
            .apply_status(SettlementStatus::Finalized, 101, Some("   ".to_string()), None)
            .unwrap_err();

        assert!(matches!(err, InteropIdentityError::MissingSettlementTx));
        assert_eq!(rec.status, SettlementStatus::Pending);
    }

    #[test]
    fn settlement_revert_requires_non_empty_reason() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 12,
            route,
            status: SettlementStatus::Pending,
            at_height: 200,
            settlement_tx: None,
            revert_reason: None,
        };

        let err = rec
            .apply_status(
                SettlementStatus::Reverted,
                201,
                None,
                Some("\n\t".to_string()),
            )
            .unwrap_err();

        assert!(matches!(err, InteropIdentityError::MissingRevertReason));
        assert_eq!(rec.status, SettlementStatus::Pending);
    }

    #[test]
    fn settlement_terminal_payloads_are_trimmed_before_persisting() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut finalized = SettlementRecord {
            settlement_id: 13,
            route: route.clone(),
            status: SettlementStatus::Pending,
            at_height: 300,
            settlement_tx: None,
            revert_reason: None,
        };
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                301,
                Some("  0xtrimmed  ".to_string()),
                None,
            )
            .unwrap();
        assert_eq!(finalized.settlement_tx.as_deref(), Some("0xtrimmed"));
        assert_eq!(finalized.revert_reason, None);

        let mut reverted = SettlementRecord {
            settlement_id: 14,
            route,
            status: SettlementStatus::Pending,
            at_height: 400,
            settlement_tx: None,
            revert_reason: None,
        };
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                401,
                None,
                Some("  manual_compensation  ".to_string()),
            )
            .unwrap();
        assert_eq!(reverted.settlement_tx, None);
        assert_eq!(reverted.revert_reason.as_deref(), Some("manual_compensation"));
    }

    #[test]
    fn settlement_status_update_rejects_height_regression_without_side_effects() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 15,
            route,
            status: SettlementStatus::Pending,
            at_height: 500,
            settlement_tx: None,
            revert_reason: None,
        };

        let err = rec
            .apply_status(
                SettlementStatus::Finalized,
                499,
                Some("0xlate".to_string()),
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidSettlementHeightRegression {
                current_at: 500,
                next_at: 499
            }
        ));
        assert_eq!(rec.status, SettlementStatus::Pending);
        assert_eq!(rec.at_height, 500);
        assert_eq!(rec.settlement_tx, None);
        assert_eq!(rec.revert_reason, None);
    }

    #[test]
    fn register_did_rejects_duplicate_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-dup".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let err = reg
            .register_did(
                "did:trnm:agent-dup".to_string(),
                "org:lane2-backup".to_string(),
                20,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidAlreadyExists { did } if did == "did:trnm:agent-dup"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);

        let did = reg.did("did:trnm:agent-dup").unwrap();
        assert_eq!(did.controller, "org:lane2-admin");
        assert_eq!(did.created_at, 10);
        assert_eq!(did.revoked_at, None);
    }

    #[test]
    fn register_did_rejects_blank_or_noncanonical_identifiers_without_side_effects() {
        let mut reg = IdentityRegistry::default();

        let err = reg
            .register_did("   ".to_string(), "org:lane2-admin".to_string(), 10)
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));
        assert!(reg.audit_trail().is_empty());

        let err = reg
            .register_did(
                "did:trnm:agent-space ".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));
        assert!(reg.did("did:trnm:agent-space").is_none());

        let err = reg
            .register_did(
                "did:trnm:agent-ok".to_string(),
                " org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue {
                field: "controller",
                ..
            }
        ));
        assert!(reg.did("did:trnm:agent-ok").is_none());

        let err = reg
            .register_did(
                "did:trnm:agent-ok".to_string(),
                "org:lane2-admin ".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue {
                field: "controller",
                ..
            }
        ));
        assert!(reg.did("did:trnm:agent-ok").is_none());

        let err = reg
            .register_did("did:trnm:agent-ok".to_string(), "  ".to_string(), 10)
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue {
                field: "controller",
                ..
            }
        ));
        assert!(reg.did("did:trnm:agent-ok").is_none());
        assert!(reg.audit_trail().is_empty());
    }

    #[test]
    fn issue_capability_rejects_expiry_before_issue_height() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-1".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let err = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-1".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(19),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidCapabilityExpiry {
                issued_at: 20,
                expires_at: 19
            }
        ));
    }

    #[test]
    fn issue_capability_rejects_height_before_did_creation_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-1b".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-1b".to_string(),
                CapabilityScope::BridgeSettle,
                9,
                Some(90),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidCapabilityIssueHeight {
                did,
                created_at: 10,
                issued_at: 9,
            } if did == "did:trnm:agent-1b"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert!(reg.capability(1).is_none());
    }

    #[test]
    fn capability_is_not_active_before_issue_height() {
        let token = CapabilityToken {
            token_id: 1,
            subject_did: "did:trnm:agent-issue-window".to_string(),
            scope: CapabilityScope::BridgeSettle,
            issued_at: 50,
            expires_at: Some(60),
            revoked_at: None,
        };

        assert!(!token.is_active_at(49));
        assert!(token.is_active_at(50));
        assert!(token.is_active_at(60));
        assert!(!token.is_active_at(61));
    }

    #[test]
    fn capability_revocation_respects_historical_heights() {
        let token = CapabilityToken {
            token_id: 2,
            subject_did: "did:trnm:agent-revoke-window".to_string(),
            scope: CapabilityScope::AuditRead,
            issued_at: 10,
            expires_at: None,
            revoked_at: Some(20),
        };

        assert!(token.is_active_at(19));
        assert!(!token.is_active_at(20));
        assert!(!token.is_active_at(21));
    }

    #[test]
    fn did_capability_revocation_appends_audit_trail() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-1".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-1".to_string(),
                CapabilityScope::BridgeSettle,
                12,
                Some(120),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            20,
            Some("manual_revoke".to_string()),
        )
        .unwrap();
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(20));

        let token2 = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-1".to_string(),
                CapabilityScope::AuditRead,
                30,
                None,
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-1", 40)
            .unwrap();

        assert_eq!(reg.did("did:trnm:agent-1").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token2).unwrap().revoked_at, Some(40));

        let audit = reg.audit_trail();
        assert_eq!(audit.len(), 6);
        assert_eq!(audit[0].action, AuditAction::DidRegistered);
        assert_eq!(audit[1].action, AuditAction::CapabilityIssued);
        assert_eq!(audit[2].action, AuditAction::CapabilityRevoked);
        assert_eq!(audit[3].action, AuditAction::CapabilityIssued);
        assert_eq!(audit[4].action, AuditAction::DidRevoked);
        assert_eq!(audit[5].action, AuditAction::CapabilityRevoked);
        assert_eq!(audit[5].actor, "system:cascade");
        assert!(audit[5]
            .note
            .as_deref()
            .unwrap_or_default()
            .contains("cascade_on_did_revoke"));
    }

    #[test]
    fn revoke_did_rejects_height_before_creation_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let err = reg
            .revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 9)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidDidRevocationHeight {
                created_at: 10,
                revoked_at: 9
            }
        ));
        assert_eq!(reg.did("did:trnm:agent-2").unwrap().revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn revoke_did_rejects_noncanonical_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2x".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let err = reg
            .revoke_did("org:lane2-admin".to_string(), " did:trnm:agent-2x ", 12)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));
        assert_eq!(reg.did("did:trnm:agent-2x").unwrap().revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn revoke_did_is_idempotent_for_audit_and_timestamp() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-2".to_string(),
                CapabilityScope::BridgeSettle,
                12,
                Some(100),
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 40)
            .unwrap();
        let first_audit_len = reg.audit_trail().len();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2", 99)
            .unwrap();

        assert_eq!(reg.did("did:trnm:agent-2").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
        assert_eq!(reg.audit_trail().len(), first_audit_len);
    }

    #[test]
    fn revoke_capability_is_idempotent_for_audit_and_timestamp() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("security_rotate".to_string()),
        )
        .unwrap();
        let first_audit_len = reg.audit_trail().len();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            90,
            Some("late_duplicate".to_string()),
        )
        .unwrap();

        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
        assert_eq!(reg.audit_trail().len(), first_audit_len);
    }

    #[test]
    fn revoke_capability_rejects_height_before_issue_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3b".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3b".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability(
                "org:lane2-admin".to_string(),
                token_id,
                11,
                Some("time_travel_revoke".to_string()),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidCapabilityRevocationHeight {
                issued_at: 12,
                revoked_at: 11
            }
        ));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn revoke_did_does_not_override_previously_revoked_capability() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-4".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-4".to_string(),
                CapabilityScope::BridgeRevert,
                12,
                Some(88),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            20,
            Some("manual_revoke_before_did_revoke".to_string()),
        )
        .unwrap();
        let first_revoke_audit_len = reg.audit_trail().len();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-4", 40)
            .unwrap();

        assert_eq!(reg.did("did:trnm:agent-4").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(20));
        assert_eq!(reg.audit_trail().len(), first_revoke_audit_len + 1);
        assert_eq!(
            reg.audit_trail().last().map(|e| e.action),
            Some(AuditAction::DidRevoked)
        );
    }

    #[test]
    fn issue_capability_failure_does_not_consume_token_sequence() {
        let mut reg = IdentityRegistry::default();

        let err = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:missing".to_string(),
                CapabilityScope::AuditRead,
                11,
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidNotFound { did } if did == "did:trnm:missing"
        ));

        reg.register_did(
            "did:trnm:agent-5".to_string(),
            "org:lane2-admin".to_string(),
            12,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-5".to_string(),
                CapabilityScope::BridgeSettle,
                13,
                Some(200),
            )
            .unwrap();

        assert_eq!(token_id, 1);
    }

    #[test]
    fn issue_capability_rejects_revoked_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-5".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-5", 20)
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-5".to_string(),
                CapabilityScope::BridgeSettle,
                21,
                Some(100),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked {
                did
            } if did == "did:trnm:agent-5"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert!(reg.capability(1).is_none());
    }

    #[test]
    fn issue_capability_rejects_noncanonical_actor_identity_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-6".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .issue_capability(
                " org:lane2-admin".to_string(),
                "did:trnm:agent-6".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert!(reg.capability(1).is_none());
    }

    #[test]
    fn revoke_capability_rejects_blank_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("   ".to_string(), token_id, 30, Some("x".to_string()))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }
}
