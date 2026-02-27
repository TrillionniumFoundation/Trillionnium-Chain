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
        self.status = self.status.transition(to)?;
        self.at_height = at_height;

        match to {
            SettlementStatus::Finalized => {
                self.settlement_tx = settlement_tx;
                self.revert_reason = None;
            }
            SettlementStatus::Reverted => {
                self.revert_reason = revert_reason;
                self.settlement_tx = None;
            }
            SettlementStatus::Pending => {}
        }

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
        if self.revoked_at.is_some() {
            return false;
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
    pub fn register_did(
        &mut self,
        did: String,
        controller: String,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
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
        if let Some(exp) = expires_at {
            if exp < at_height {
                return Err(InteropIdentityError::InvalidCapabilityExpiry {
                    issued_at: at_height,
                    expires_at: exp,
                });
            }
        }

        match self.dids.get(&subject_did) {
            Some(did) if did.is_active() => {}
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
        let subject = {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if token.revoked_at.is_some() {
                return Ok(());
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
        let did_rec = self
            .dids
            .get_mut(did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: did.to_string(),
            })?;

        if did_rec.revoked_at.is_some() {
            return Ok(());
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
    DidAlreadyExists {
        did: String,
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
}

impl fmt::Display for InteropIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InteropIdentityError::InvalidSettlementTransition { from, to } => {
                write!(f, "illegal settlement transition: {:?} -> {:?}", from, to)
            }
            InteropIdentityError::DidAlreadyExists { did } => {
                write!(f, "did already exists: {}", did)
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
}
