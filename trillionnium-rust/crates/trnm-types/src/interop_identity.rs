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

pub const SETTLEMENT_TX_RECEIPT_SUCCESS: u8 = 1;

impl SettlementStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SettlementStatus::Pending => "pending",
            SettlementStatus::Finalized => "finalized",
            SettlementStatus::Reverted => "reverted",
        }
    }

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
        Err(InteropIdentityError::InvalidSettlementTransition { from: self, to })
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

fn normalize_revert_reason(reason: String) -> String {
    let mut canonical = String::with_capacity(reason.len());
    let mut prev_sep = false;

    for ch in reason.trim().chars() {
        let lowered = ch.to_ascii_lowercase();
        if lowered.is_ascii_alphanumeric() {
            canonical.push(lowered);
            prev_sep = false;
        } else if !prev_sep {
            canonical.push('-');
            prev_sep = true;
        }
    }

    while canonical.ends_with('-') {
        canonical.pop();
    }

    match canonical.as_str() {
        "fraud-proof" | "fraudproof" => "fraud-proof".to_string(),
        "tee-receipt" | "tee-attestation" => "tee-receipt".to_string(),
        "zk-receipt" | "zk-proof" => "zk-receipt".to_string(),
        _ => reason,
    }
}

fn is_disallowed_invisible_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{202A}'
            | '\u{202B}'
            | '\u{202C}'
            | '\u{202D}'
            | '\u{202E}'
            | '\u{2060}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}'
    )
}

fn canonical_path_segment(raw: &str) -> String {
    let sanitized: String = raw
        .trim()
        .chars()
        .map(|ch| match ch {
            '/' | '\\' | ':' | '<' | '"' | '|' | '?' | '*' => '_',
            c if c.is_whitespace() || c.is_control() || is_disallowed_invisible_char(c) => '_',
            c => c,
        })
        .collect();

    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return "_".to_string();
    }

    let canonical = sanitized.trim_end_matches(['.', ' ']);
    if canonical.is_empty() || canonical == "." || canonical == ".." {
        return "_".to_string();
    }

    let lowered = canonical.to_ascii_lowercase();
    let windows_basename = lowered.split('.').next().unwrap_or("");
    let is_windows_reserved = matches!(
        windows_basename,
        "con"
            | "prn"
            | "aux"
            | "nul"
            | "com1"
            | "com2"
            | "com3"
            | "com4"
            | "com5"
            | "com6"
            | "com7"
            | "com8"
            | "com9"
            | "lpt1"
            | "lpt2"
            | "lpt3"
            | "lpt4"
            | "lpt5"
            | "lpt6"
            | "lpt7"
            | "lpt8"
            | "lpt9"
    );

    if is_windows_reserved {
        format!("{canonical}_")
    } else {
        canonical.to_string()
    }
}

impl SettlementRecord {
    /// Stable PoC scaffold path for dual-chain settlement state-machine evidence.
    ///
    /// Format:
    /// `settlements/<route_id>/<source_chain>/<target_chain>/<settlement_id>/<status>@<height>`
    pub fn evidence_path(&self) -> String {
        format!(
            "settlements/{}/{}/{}/{}/{}@{}",
            canonical_path_segment(&self.route.route_id),
            canonical_path_segment(&self.route.source_chain),
            canonical_path_segment(&self.route.target_chain),
            self.settlement_id,
            self.status.as_str(),
            self.at_height
        )
    }

    pub fn apply_status(
        &mut self,
        to: SettlementStatus,
        at_height: u64,
        settlement_tx: Option<String>,
        revert_reason: Option<String>,
    ) -> Result<(), InteropIdentityError> {
        self.apply_status_with_receipt_status(to, at_height, settlement_tx, None, revert_reason)
    }

    pub fn apply_status_with_receipt_status(
        &mut self,
        to: SettlementStatus,
        at_height: u64,
        settlement_tx: Option<String>,
        tx_receipt_status: Option<u8>,
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
                let expected = SETTLEMENT_TX_RECEIPT_SUCCESS;
                let got = tx_receipt_status.unwrap_or(expected);
                if got != expected {
                    return Err(InteropIdentityError::InvalidSettlementReceiptStatus {
                        expected,
                        got,
                    });
                }

                let provided_tx = settlement_tx
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string);
                if self.status == SettlementStatus::Finalized {
                    if let (Some(existing), Some(provided)) =
                        (self.settlement_tx.as_deref(), provided_tx.as_deref())
                    {
                        if existing != provided {
                            return Err(InteropIdentityError::SettlementTerminalPayloadConflict {
                                status: SettlementStatus::Finalized,
                                existing: existing.to_string(),
                                provided: provided.to_string(),
                            });
                        }
                    }
                }
                let tx = provided_tx
                    .or_else(|| self.settlement_tx.clone())
                    .ok_or(InteropIdentityError::MissingSettlementTx)?;
                (Some(tx), None)
            }
            SettlementStatus::Reverted => {
                let provided_reason = revert_reason
                    .as_deref()
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_string)
                    .map(normalize_revert_reason);
                if self.status == SettlementStatus::Reverted {
                    if let (Some(existing), Some(provided)) =
                        (self.revert_reason.as_deref(), provided_reason.as_deref())
                    {
                        let existing_normalized = normalize_revert_reason(existing.to_string());
                        if existing_normalized != *provided {
                            return Err(InteropIdentityError::SettlementTerminalPayloadConflict {
                                status: SettlementStatus::Reverted,
                                existing: existing.to_string(),
                                provided: provided.to_string(),
                            });
                        }
                    }
                }
                let reason = provided_reason
                    .or_else(|| self.revert_reason.clone().map(normalize_revert_reason))
                    .ok_or(InteropIdentityError::MissingRevertReason)?;
                (None, Some(reason))
            }
            // Pending is a non-terminal in-flight state; terminal payloads must not persist here.
            // If legacy/corrupt snapshots carry terminal fields while pending, scrub them on write.
            SettlementStatus::Pending => (None, None),
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
    MarketPublish,
    MarketExecute,
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

    pub fn is_active_at(&self, at_height: u64) -> bool {
        if at_height < self.created_at {
            return false;
        }

        match self.revoked_at {
            Some(revoked_at) => at_height < revoked_at,
            None => true,
        }
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
    CapabilityRenewed,
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
    const DID_MIN_LEN: usize = 7;
    const DID_MAX_LEN: usize = 128;

    fn contains_disallowed_invisible_chars(value: &str) -> bool {
        value.chars().any(is_disallowed_invisible_char)
    }

    pub fn is_canonical_did(value: &str) -> bool {
        if value.len() < Self::DID_MIN_LEN || value.len() > Self::DID_MAX_LEN {
            return false;
        }
        if !value.starts_with("did:") {
            return false;
        }

        let mut parts = value.splitn(3, ':');
        let _did = parts.next();
        let method = parts.next().unwrap_or("");
        let method_specific = parts.next().unwrap_or("");

        if method.is_empty() || method_specific.is_empty() {
            return false;
        }

        if !method
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        {
            return false;
        }

        method_specific.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, ':' | '.' | '_' | '-')
        })
    }

    fn validate_identity_field(
        field: &'static str,
        value: &str,
    ) -> Result<(), InteropIdentityError> {
        let did_field = matches!(field, "did" | "subject_did");

        if value.trim().is_empty()
            || value.trim() != value
            || value.chars().any(char::is_control)
            || Self::contains_disallowed_invisible_chars(value)
            || (did_field && !Self::is_canonical_did(value))
        {
            return Err(InteropIdentityError::InvalidIdentityValue {
                field,
                value: value.to_string(),
            });
        }
        Ok(())
    }

    fn ensure_actor_controls_did(actor: &str, did: &DidRecord) -> Result<(), InteropIdentityError> {
        if did.controller != actor {
            return Err(InteropIdentityError::UnauthorizedActor {
                actor: actor.to_string(),
                did: did.did.clone(),
                controller: did.controller.clone(),
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
        self.push_audit(AuditAction::DidRegistered, controller, did, at_height, None);
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
                Self::ensure_actor_controls_did(&actor, did)?;
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

        let subject_did = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?
            .subject_did
            .clone();
        let did = self
            .dids
            .get(&subject_did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: subject_did.clone(),
            })?;
        Self::ensure_actor_controls_did(&actor, did)?;

        let subject = {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if let Some(first_revoked_at) = token.revoked_at {
                if at_height < first_revoked_at {
                    return Err(InteropIdentityError::InvalidCapabilityRevocationHeight {
                        issued_at: first_revoked_at,
                        revoked_at: at_height,
                    });
                }
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

    pub fn renew_capability(
        &mut self,
        actor: String,
        token_id: u64,
        at_height: u64,
        expires_at: Option<u64>,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", &actor)?;

        if let Some(exp) = expires_at {
            if exp < at_height {
                return Err(InteropIdentityError::InvalidCapabilityExpiry {
                    issued_at: at_height,
                    expires_at: exp,
                });
            }
        }

        let subject_did = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?
            .subject_did
            .clone();
        let did = self
            .dids
            .get(&subject_did)
            .ok_or_else(|| InteropIdentityError::DidNotFound {
                did: subject_did.clone(),
            })?;
        if !did.is_active() {
            return Err(InteropIdentityError::DidRevoked {
                did: did.did.clone(),
            });
        }
        Self::ensure_actor_controls_did(&actor, did)?;

        {
            let token = self
                .capabilities
                .get_mut(&token_id)
                .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;
            if !token.is_active_at(at_height) {
                return Err(InteropIdentityError::CapabilityInactive {
                    token_id,
                    at_height,
                    issued_at: token.issued_at,
                    expires_at: token.expires_at,
                    revoked_at: token.revoked_at,
                });
            }
            if let Some(current_expiry) = token.expires_at {
                match expires_at {
                    Some(requested_expiry) if requested_expiry < current_expiry => {
                        return Err(InteropIdentityError::CapabilityRenewalRegression {
                            current_expires_at: current_expiry,
                            requested_expires_at: requested_expiry,
                        });
                    }
                    None => {
                        return Err(InteropIdentityError::CapabilityRenewalCannotClearExpiry {
                            current_expires_at: current_expiry,
                        });
                    }
                    _ => {}
                }
            }
            if token.expires_at == expires_at {
                return Ok(());
            }
            token.expires_at = expires_at;
        }

        self.push_audit(
            AuditAction::CapabilityRenewed,
            actor,
            subject_did,
            at_height,
            Some(format!("token_id={} expires_at={:?}", token_id, expires_at)),
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

        Self::ensure_actor_controls_did(&actor, did_rec)?;

        let (is_first_revoke, did_revoke_anchor) =
            if let Some(first_revoked_at) = did_rec.revoked_at {
                if at_height < first_revoked_at {
                    return Err(InteropIdentityError::InvalidDidRevocationHeight {
                        created_at: first_revoked_at,
                        revoked_at: at_height,
                    });
                }
                (false, first_revoked_at)
            } else {
                if at_height < did_rec.created_at {
                    return Err(InteropIdentityError::InvalidDidRevocationHeight {
                        created_at: did_rec.created_at,
                        revoked_at: at_height,
                    });
                }
                did_rec.revoked_at = Some(at_height);
                (true, at_height)
            };

        if is_first_revoke {
            self.push_audit(
                AuditAction::DidRevoked,
                actor,
                did.to_string(),
                did_revoke_anchor,
                None,
            );
        }

        let to_revoke: Vec<u64> = self
            .capabilities
            .iter()
            .filter_map(|(token_id, token)| {
                (token.subject_did == did && token.revoked_at.is_none()).then_some(*token_id)
            })
            .collect();

        for token_id in to_revoke {
            let (subject, cascade_revoke_height) = {
                let Some(token) = self.capabilities.get_mut(&token_id) else {
                    continue;
                };
                let cascade_revoke_height = did_revoke_anchor.max(token.issued_at);
                token.revoked_at = Some(cascade_revoke_height);
                (token.subject_did.clone(), cascade_revoke_height)
            };
            self.push_audit(
                AuditAction::CapabilityRevoked,
                "system:cascade".to_string(),
                subject,
                cascade_revoke_height,
                Some(format!("cascade_on_did_revoke token_id={}", token_id)),
            );
        }

        Ok(())
    }

    pub fn verify_capability(
        &self,
        actor: &str,
        token_id: u64,
        required_scope: CapabilityScope,
        at_height: u64,
    ) -> Result<(), InteropIdentityError> {
        Self::validate_identity_field("actor", actor)?;

        let token = self
            .capabilities
            .get(&token_id)
            .ok_or(InteropIdentityError::CapabilityNotFound { token_id })?;

        let did =
            self.dids
                .get(&token.subject_did)
                .ok_or_else(|| InteropIdentityError::DidNotFound {
                    did: token.subject_did.clone(),
                })?;

        if !did.is_active_at(at_height) {
            return Err(InteropIdentityError::DidRevoked {
                did: did.did.clone(),
            });
        }

        if !token.is_active_at(at_height) {
            return Err(InteropIdentityError::CapabilityInactive {
                token_id,
                at_height,
                issued_at: token.issued_at,
                expires_at: token.expires_at,
                revoked_at: token.revoked_at,
            });
        }

        if token.scope != required_scope {
            return Err(InteropIdentityError::CapabilityScopeMismatch {
                token_id,
                expected: required_scope,
                actual: token.scope,
            });
        }

        Self::ensure_actor_controls_did(actor, did)?;
        Ok(())
    }

    pub fn did(&self, did: &str) -> Option<&DidRecord> {
        self.dids.get(did)
    }

    pub fn capability(&self, token_id: u64) -> Option<&CapabilityToken> {
        self.capabilities.get(&token_id)
    }

    pub fn capability_ids_by_subject(&self, subject_did: &str) -> Vec<u64> {
        self.capabilities
            .values()
            .filter(|token| token.subject_did == subject_did)
            .map(|token| token.token_id)
            .collect()
    }

    pub fn audit_trail(&self) -> &[AuditEvent] {
        &self.audit_trail
    }

    pub fn content_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"dids");
        for (k, v) in &self.dids {
            hasher.update(k.as_bytes());
            hasher.update(v.did.as_bytes());
            hasher.update(v.controller.as_bytes());
            hasher.update(v.created_at.to_le_bytes());
            if let Some(r) = v.revoked_at {
                hasher.update([1]);
                hasher.update(r.to_le_bytes());
            } else {
                hasher.update([0]);
            }
        }
        hasher.update(b"caps");
        for (k, v) in &self.capabilities {
            hasher.update(k.to_le_bytes());
            hasher.update(v.token_id.to_le_bytes());
            hasher.update(v.subject_did.as_bytes());
            // Scope is an enum, serialize it simple
            let scope_byte = match v.scope {
                CapabilityScope::BridgeSettle => 1,
                CapabilityScope::BridgeRevert => 2,
                CapabilityScope::AuditRead => 3,
                CapabilityScope::MarketPublish => 4,
                CapabilityScope::MarketExecute => 5,
            };
            hasher.update([scope_byte]);
            hasher.update(v.issued_at.to_le_bytes());
            if let Some(exp) = v.expires_at {
                hasher.update([1]);
                hasher.update(exp.to_le_bytes());
            } else {
                hasher.update([0]);
            }
            if let Some(rev) = v.revoked_at {
                hasher.update([1]);
                hasher.update(rev.to_le_bytes());
            } else {
                hasher.update([0]);
            }
        }
        // Audit trail not hashed for state root?
        // Usually audit trails are history, state root should capture current state.
        // But for "Verifiable Execution", history might be important.
        // Let's hash it for completeness of the registry state.
        hasher.update(b"audit");
        hasher.update(self.audit_trail.len().to_le_bytes());
        for ev in &self.audit_trail {
            hasher.update(ev.seq.to_le_bytes());
            let action_tag = match ev.action {
                AuditAction::DidRegistered => 1u8,
                AuditAction::DidRevoked => 2u8,
                AuditAction::CapabilityIssued => 3u8,
                AuditAction::CapabilityRenewed => 4u8,
                AuditAction::CapabilityRevoked => 5u8,
            };
            hasher.update([action_tag]);
            hasher.update(ev.actor.as_bytes());
            hasher.update(ev.subject.as_bytes());
            hasher.update(ev.at_height.to_le_bytes());
            if let Some(note) = ev.note.as_deref() {
                hasher.update([1]);
                hasher.update(note.as_bytes());
            } else {
                hasher.update([0]);
            }
        }
        hasher.update(self.next_capability_id.to_le_bytes());
        hasher.finalize().into()
    }

    fn normalize_note(note: Option<String>) -> Option<String> {
        note.and_then(|v| {
            let sanitized: String = v
                .trim()
                .chars()
                .map(|ch| {
                    if ch.is_control() || is_disallowed_invisible_char(ch) {
                        ' '
                    } else {
                        ch
                    }
                })
                .collect();

            let collapsed = sanitized.split_whitespace().collect::<Vec<_>>().join(" ");
            (!collapsed.is_empty()).then_some(collapsed)
        })
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
            note: Self::normalize_note(note),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settlement_state_machine_enforces_receipt_success_for_finalization() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 6,
            route,
            status: SettlementStatus::Pending,
            at_height: 100,
            settlement_tx: None,
            revert_reason: None,
        };

        let err = rec
            .apply_status_with_receipt_status(
                SettlementStatus::Finalized,
                105,
                Some("0xfailed".to_string()),
                Some(0),
                None,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidSettlementReceiptStatus {
                expected: 1,
                got: 0
            }
        ));

        rec.apply_status_with_receipt_status(
            SettlementStatus::Finalized,
            105,
            Some("0xok".to_string()),
            Some(SETTLEMENT_TX_RECEIPT_SUCCESS),
            None,
        )
        .unwrap();
        assert_eq!(rec.settlement_tx.as_deref(), Some("0xok"));
    }

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
    fn settlement_terminal_idempotent_reapply_ignores_blank_payload_overrides() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut finalized = SettlementRecord {
            settlement_id: 81,
            route: route.clone(),
            status: SettlementStatus::Pending,
            at_height: 1_000,
            settlement_tx: None,
            revert_reason: None,
        };
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                1_001,
                Some("0xpersist".to_string()),
                None,
            )
            .unwrap();
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                1_002,
                Some("   \t".to_string()),
                None,
            )
            .unwrap();
        assert_eq!(finalized.status, SettlementStatus::Finalized);
        assert_eq!(finalized.settlement_tx.as_deref(), Some("0xpersist"));
        assert_eq!(finalized.revert_reason, None);

        let mut reverted = SettlementRecord {
            settlement_id: 82,
            route,
            status: SettlementStatus::Pending,
            at_height: 2_000,
            settlement_tx: None,
            revert_reason: None,
        };
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                2_001,
                None,
                Some("keep-this-reason".to_string()),
            )
            .unwrap();
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                2_002,
                None,
                Some("   \n".to_string()),
            )
            .unwrap();
        assert_eq!(reverted.status, SettlementStatus::Reverted);
        assert_eq!(reverted.settlement_tx, None);
        assert_eq!(reverted.revert_reason.as_deref(), Some("keep-this-reason"));
    }

    #[test]
    fn settlement_terminal_idempotent_reapply_rejects_conflicting_payload_override() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut finalized = SettlementRecord {
            settlement_id: 83,
            route: route.clone(),
            status: SettlementStatus::Pending,
            at_height: 3_000,
            settlement_tx: None,
            revert_reason: None,
        };
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                3_001,
                Some("0xfinal-a".to_string()),
                None,
            )
            .unwrap();
        let err = finalized
            .apply_status(
                SettlementStatus::Finalized,
                3_002,
                Some("0xfinal-b".to_string()),
                None,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::SettlementTerminalPayloadConflict {
                status: SettlementStatus::Finalized,
                ..
            }
        ));
        assert_eq!(finalized.settlement_tx.as_deref(), Some("0xfinal-a"));

        let mut reverted = SettlementRecord {
            settlement_id: 84,
            route,
            status: SettlementStatus::Pending,
            at_height: 4_000,
            settlement_tx: None,
            revert_reason: None,
        };
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                4_001,
                None,
                Some("reason-a".to_string()),
            )
            .unwrap();
        let err = reverted
            .apply_status(
                SettlementStatus::Reverted,
                4_002,
                None,
                Some("reason-b".to_string()),
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::SettlementTerminalPayloadConflict {
                status: SettlementStatus::Reverted,
                ..
            }
        ));
        assert_eq!(reverted.revert_reason.as_deref(), Some("reason-a"));
    }

    #[test]
    fn settlement_terminal_idempotent_reapply_accepts_whitespace_equivalent_payload() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut finalized = SettlementRecord {
            settlement_id: 85,
            route: route.clone(),
            status: SettlementStatus::Pending,
            at_height: 5_000,
            settlement_tx: None,
            revert_reason: None,
        };
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                5_001,
                Some("0xstable".to_string()),
                None,
            )
            .unwrap();
        finalized
            .apply_status(
                SettlementStatus::Finalized,
                5_002,
                Some("  0xstable\n".to_string()),
                None,
            )
            .unwrap();
        assert_eq!(finalized.status, SettlementStatus::Finalized);
        assert_eq!(finalized.settlement_tx.as_deref(), Some("0xstable"));

        let mut reverted = SettlementRecord {
            settlement_id: 86,
            route,
            status: SettlementStatus::Pending,
            at_height: 6_000,
            settlement_tx: None,
            revert_reason: None,
        };
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                6_001,
                None,
                Some("timeout across relayers".to_string()),
            )
            .unwrap();
        reverted
            .apply_status(
                SettlementStatus::Reverted,
                6_002,
                None,
                Some("  timeout across relayers\t".to_string()),
            )
            .unwrap();
        assert_eq!(reverted.status, SettlementStatus::Reverted);
        assert_eq!(
            reverted.revert_reason.as_deref(),
            Some("timeout across relayers")
        );
    }

    #[test]
    fn settlement_terminal_idempotent_reapply_accepts_legacy_revert_reason_alias() {
        let mut reverted = SettlementRecord {
            settlement_id: 860,
            route: BridgeRoute {
                route_id: "eth->trnm".to_string(),
                source_chain: "ethereum".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Reverted,
            at_height: 6_100,
            settlement_tx: None,
            revert_reason: Some("tee_attestation".to_string()),
        };

        reverted
            .apply_status(
                SettlementStatus::Reverted,
                6_101,
                None,
                Some("tee-receipt".to_string()),
            )
            .unwrap();

        assert_eq!(reverted.status, SettlementStatus::Reverted);
        assert_eq!(reverted.revert_reason.as_deref(), Some("tee-receipt"));
    }

    #[test]
    fn settlement_terminal_idempotent_reapply_still_rejects_height_regression() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };

        let mut rec = SettlementRecord {
            settlement_id: 10,
            route,
            status: SettlementStatus::Pending,
            at_height: 300,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Finalized,
            305,
            Some("0xdone".to_string()),
            None,
        )
        .unwrap();

        let err = rec
            .apply_status(SettlementStatus::Finalized, 304, None, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidSettlementHeightRegression {
                current_at: 305,
                next_at: 304
            }
        ));
        assert_eq!(rec.status, SettlementStatus::Finalized);
        assert_eq!(rec.at_height, 305);
        assert_eq!(rec.settlement_tx.as_deref(), Some("0xdone"));
        assert_eq!(rec.revert_reason, None);
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
            .apply_status(
                SettlementStatus::Finalized,
                101,
                Some("   ".to_string()),
                None,
            )
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
        assert_eq!(
            reverted.revert_reason.as_deref(),
            Some("manual_compensation")
        );
    }

    #[test]
    fn settlement_revert_reason_normalizes_proof_adapter_aliases() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 140,
            route,
            status: SettlementStatus::Pending,
            at_height: 500,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            501,
            None,
            Some("TEE_ATTESTATION".to_string()),
        )
        .unwrap();
        assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));

        rec.apply_status(
            SettlementStatus::Reverted,
            502,
            None,
            Some("zk_proof".to_string()),
        )
        .unwrap_err();
        assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));
    }

    #[test]
    fn settlement_revert_reason_normalization_keeps_non_proof_reason() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 141,
            route,
            status: SettlementStatus::Pending,
            at_height: 600,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            601,
            None,
            Some("executor_sla_timeout".to_string()),
        )
        .unwrap();
        assert_eq!(rec.revert_reason.as_deref(), Some("executor_sla_timeout"));
    }

    #[test]
    fn settlement_revert_reason_reapply_accepts_equivalent_canonical_alias() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 142,
            route,
            status: SettlementStatus::Pending,
            at_height: 610,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            611,
            None,
            Some("fraud-proof".to_string()),
        )
        .unwrap();

        // Re-applying same terminal state with an equivalent alias should stay idempotent.
        rec.apply_status(
            SettlementStatus::Reverted,
            612,
            None,
            Some("FRAUD_PROOF".to_string()),
        )
        .unwrap();

        assert_eq!(rec.revert_reason.as_deref(), Some("fraud-proof"));
    }

    #[test]
    fn settlement_revert_reason_reapply_accepts_delimiter_variant_alias() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 143,
            route,
            status: SettlementStatus::Pending,
            at_height: 620,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            621,
            None,
            Some("tee-receipt".to_string()),
        )
        .unwrap();

        rec.apply_status(
            SettlementStatus::Reverted,
            622,
            None,
            Some(" TEE / ATTESTATION ".to_string()),
        )
        .unwrap();

        assert_eq!(rec.revert_reason.as_deref(), Some("tee-receipt"));
    }

    #[test]
    fn settlement_revert_reason_reapply_accepts_compact_legacy_alias() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 144,
            route,
            status: SettlementStatus::Pending,
            at_height: 623,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Reverted,
            624,
            None,
            Some("fraud-proof".to_string()),
        )
        .unwrap();

        rec.apply_status(
            SettlementStatus::Reverted,
            625,
            None,
            Some("FRAUDPROOF".to_string()),
        )
        .unwrap();

        assert_eq!(rec.revert_reason.as_deref(), Some("fraud-proof"));
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
    fn settlement_pending_reapply_scrubs_terminal_payload_fields() {
        let route = BridgeRoute {
            route_id: "eth->trnm".to_string(),
            source_chain: "ethereum".to_string(),
            target_chain: "trillionnium".to_string(),
        };
        let mut rec = SettlementRecord {
            settlement_id: 16,
            route,
            status: SettlementStatus::Pending,
            at_height: 600,
            // simulate legacy/corrupt snapshot carrying terminal payloads while pending
            settlement_tx: Some("0xstale".to_string()),
            revert_reason: Some("stale-reason".to_string()),
        };

        rec.apply_status(
            SettlementStatus::Pending,
            601,
            Some("0xignored".to_string()),
            Some("ignored".to_string()),
        )
        .unwrap();

        assert_eq!(rec.status, SettlementStatus::Pending);
        assert_eq!(rec.at_height, 601);
        assert_eq!(rec.settlement_tx, None);
        assert_eq!(rec.revert_reason, None);
    }

    #[test]
    fn settlement_evidence_path_encodes_dual_chain_route_and_state() {
        let rec = SettlementRecord {
            settlement_id: 42,
            route: BridgeRoute {
                route_id: "eth->trnm".to_string(),
                source_chain: "ethereum".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 900,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth->trnm/ethereum/trillionnium/42/pending@900"
        );
    }

    #[test]
    fn settlement_evidence_path_tracks_terminal_state_machine_outcome() {
        let mut rec = SettlementRecord {
            settlement_id: 43,
            route: BridgeRoute {
                route_id: "eth->trnm".to_string(),
                source_chain: "ethereum".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 1_000,
            settlement_tx: None,
            revert_reason: None,
        };

        rec.apply_status(
            SettlementStatus::Finalized,
            1_001,
            Some("0xsettled".to_string()),
            None,
        )
        .unwrap();
        assert_eq!(
            rec.evidence_path(),
            "settlements/eth->trnm/ethereum/trillionnium/43/finalized@1001"
        );

        let mut rec_reverted = SettlementRecord {
            settlement_id: 44,
            route: BridgeRoute {
                route_id: "eth->trnm".to_string(),
                source_chain: "ethereum".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_000,
            settlement_tx: None,
            revert_reason: None,
        };

        rec_reverted
            .apply_status(
                SettlementStatus::Reverted,
                2_001,
                None,
                Some("proof_mismatch".to_string()),
            )
            .unwrap();
        assert_eq!(
            rec_reverted.evidence_path(),
            "settlements/eth->trnm/ethereum/trillionnium/44/reverted@2001"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_route_segments_for_filesystem_safety() {
        let rec = SettlementRecord {
            settlement_id: 45,
            route: BridgeRoute {
                route_id: "eth/mainnet -> trnm".to_string(),
                source_chain: "ethereum/mainnet".to_string(),
                target_chain: "trillionnium\nalpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_222,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet_->_trnm/ethereum_mainnet/trillionnium_alpha/45/pending@2222"
        );
    }

    #[test]
    fn settlement_evidence_path_replaces_empty_route_segments_with_placeholder() {
        let rec = SettlementRecord {
            settlement_id: 46,
            route: BridgeRoute {
                route_id: "   ".to_string(),
                source_chain: "\n\t".to_string(),
                target_chain: "".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_223,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(rec.evidence_path(), "settlements/_/_/_/46/pending@2223");
    }

    #[test]
    fn settlement_evidence_path_rewrites_dot_segments_to_placeholder() {
        let rec = SettlementRecord {
            settlement_id: 47,
            route: BridgeRoute {
                route_id: "..".to_string(),
                source_chain: ".".to_string(),
                target_chain: "trillionnium".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_224,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/_/_/trillionnium/47/pending@2224"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_windows_separators_and_control_whitespace() {
        let rec = SettlementRecord {
            settlement_id: 48,
            route: BridgeRoute {
                route_id: "eth\\mainnet\t->\ttrnm".to_string(),
                source_chain: "ethereum\\mainnet".to_string(),
                target_chain: "trillionnium\ralpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_225,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet_->_trnm/ethereum_mainnet/trillionnium_alpha/48/pending@2225"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_unicode_whitespace_segments() {
        let rec = SettlementRecord {
            settlement_id: 480,
            route: BridgeRoute {
                route_id: "eth\u{2003}mainnet->trnm".to_string(),
                source_chain: "ethereum\u{00A0}mainnet".to_string(),
                target_chain: "trillionnium\u{3000}alpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_225,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/480/pending@2225"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_bidi_and_zero_width_format_controls() {
        let rec = SettlementRecord {
            settlement_id: 481,
            route: BridgeRoute {
                route_id: "eth\u{202E}mainnet->trnm\u{200B}".to_string(),
                source_chain: "ethereum\u{2066}mainnet\u{2069}".to_string(),
                target_chain: "trillionnium\u{FEFF}alpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_225,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet->trnm_/ethereum_mainnet_/trillionnium_alpha/481/pending@2225"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_colon_for_cross_platform_filesystem_safety() {
        let rec = SettlementRecord {
            settlement_id: 49,
            route: BridgeRoute {
                route_id: "eth:mainnet->trnm".to_string(),
                source_chain: "ethereum:mainnet".to_string(),
                target_chain: "trillionnium:alpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_226,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/49/pending@2226"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_arabic_letter_mark_controls() {
        let rec = SettlementRecord {
            settlement_id: 49_1,
            route: BridgeRoute {
                route_id: "eth\u{061C}mainnet->trnm".to_string(),
                source_chain: "ethereum\u{061C}mainnet".to_string(),
                target_chain: "trillionnium\u{061C}alpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_226,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/491/pending@2226"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_word_joiner_controls() {
        let rec = SettlementRecord {
            settlement_id: 49_2,
            route: BridgeRoute {
                route_id: "eth\u{2060}mainnet->trnm".to_string(),
                source_chain: "ethereum\u{2060}mainnet".to_string(),
                target_chain: "trillionnium\u{2060}alpha".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_226,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet->trnm/ethereum_mainnet/trillionnium_alpha/492/pending@2226"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_windows_reserved_punctuation() {
        let rec = SettlementRecord {
            settlement_id: 50,
            route: BridgeRoute {
                route_id: "eth<mainnet>|trnm".to_string(),
                source_chain: "ethereum?mainnet".to_string(),
                target_chain: "trillionnium\"alpha*".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_227,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_mainnet>_trnm/ethereum_mainnet/trillionnium_alpha_/50/pending@2227"
        );
    }

    #[test]
    fn settlement_evidence_path_avoids_windows_reserved_device_names() {
        let rec = SettlementRecord {
            settlement_id: 51,
            route: BridgeRoute {
                route_id: "CON".to_string(),
                source_chain: "nul".to_string(),
                target_chain: "Com1".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_228,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/CON_/nul_/Com1_/51/pending@2228"
        );
    }

    #[test]
    fn settlement_evidence_path_avoids_windows_reserved_device_names_with_extension_alias() {
        let rec = SettlementRecord {
            settlement_id: 52,
            route: BridgeRoute {
                route_id: "con.txt".to_string(),
                source_chain: "LPT1.log".to_string(),
                target_chain: "aux.backup".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_229,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/con.txt_/LPT1.log_/aux.backup_/52/pending@2229"
        );
    }

    #[test]
    fn settlement_evidence_path_avoids_windows_reserved_device_names_with_trailing_dot_or_space() {
        let rec = SettlementRecord {
            settlement_id: 53,
            route: BridgeRoute {
                route_id: "CON. ".to_string(),
                source_chain: "lpt1...".to_string(),
                target_chain: "aux ".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_230,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/CON_/lpt1_/aux_/53/pending@2230"
        );
    }

    #[test]
    fn settlement_evidence_path_avoids_windows_reserved_device_names_with_unicode_space_padding() {
        let rec = SettlementRecord {
            settlement_id: 53_0,
            route: BridgeRoute {
                route_id: "\u{2003}CON\u{2002}".to_string(),
                source_chain: "\u{00A0}nul\u{00A0}".to_string(),
                target_chain: "\u{2009}LPT9\u{2009}".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_229,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/CON_/nul_/LPT9_/530/pending@2229"
        );
    }

    #[test]
    fn settlement_evidence_path_trims_trailing_dot_or_space_for_non_reserved_segments() {
        let rec = SettlementRecord {
            settlement_id: 53_1,
            route: BridgeRoute {
                route_id: "eth-mainnet. ".to_string(),
                source_chain: "ethereum.. ".to_string(),
                target_chain: "trillionnium-alpha ".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_230,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth-mainnet/ethereum/trillionnium-alpha/531/pending@2230"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_nested_path_aliases_without_false_reserved_suffixes() {
        let rec = SettlementRecord {
            settlement_id: 54,
            route: BridgeRoute {
                route_id: "eth/CON/log".to_string(),
                source_chain: "bridge\\aux.txt".to_string(),
                target_chain: "mainnet/Com9.trace".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_231,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_CON_log/bridge_aux.txt/mainnet_Com9.trace/54/pending@2231"
        );
    }

    #[test]
    fn settlement_evidence_path_sanitizes_nested_reserved_device_aliases_with_trailing_dot_or_space(
    ) {
        let rec = SettlementRecord {
            settlement_id: 55,
            route: BridgeRoute {
                route_id: "eth/CON. /log".to_string(),
                source_chain: "bridge\\aux...\\proof".to_string(),
                target_chain: "mainnet/LPT1 .trace".to_string(),
            },
            status: SettlementStatus::Pending,
            at_height: 2_232,
            settlement_tx: None,
            revert_reason: None,
        };

        assert_eq!(
            rec.evidence_path(),
            "settlements/eth_CON.__log/bridge_aux..._proof/mainnet_LPT1_.trace/55/pending@2232"
        );
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

        let err = reg
            .register_did(
                "did:trnm:agent\nnewline".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));

        let err = reg
            .register_did(
                "did:trnm:agent-ok".to_string(),
                "org:lane2\nadmin".to_string(),
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

        assert!(reg.audit_trail().is_empty());
    }

    #[test]
    fn register_did_rejects_did_case_and_length_boundary_violations_without_side_effects() {
        let mut reg = IdentityRegistry::default();

        let err = reg
            .register_did(
                "did:Org:lane-xi".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));

        let err = reg
            .register_did(
                "did:org:Lane-Xi".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));

        let max_suffix = "a".repeat(120);
        let ok_boundary = format!("did:org:{max_suffix}");
        assert_eq!(ok_boundary.len(), 128);
        reg.register_did(ok_boundary.clone(), "org:lane2-admin".to_string(), 11)
            .expect("128-char DID boundary should be accepted");
        assert!(reg.did(&ok_boundary).is_some());

        let too_long = format!("did:org:{}", "a".repeat(121));
        assert_eq!(too_long.len(), 129);
        let err = reg
            .register_did(too_long, "org:lane2-admin".to_string(), 12)
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));
    }

    #[test]
    fn register_did_rejects_bidi_or_invisible_format_controls_without_side_effects() {
        let mut reg = IdentityRegistry::default();

        let err = reg
            .register_did(
                "did:trnm:agent\u{202E}spoof".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));

        let err = reg
            .register_did(
                "did:trnm:agent-safe".to_string(),
                "org:lane2\u{2066}admin\u{2069}".to_string(),
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

        let err = reg
            .register_did(
                "did:trnm:agent\u{2060}joiner".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "did", .. }
        ));

        let err = reg
            .register_did(
                "did:trnm:agent-bom-controller".to_string(),
                "org:lane2\u{FEFF}admin".to_string(),
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

        assert!(reg.did("did:trnm:agent-safe").is_none());
        assert!(reg.did("did:trnm:agent-bom-controller").is_none());
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
    fn revoke_did_rejects_actor_that_is_not_did_controller_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2u".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-2u".to_string(),
                CapabilityScope::AuditRead,
                12,
                Some(100),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_did("org:lane2-backup".to_string(), "did:trnm:agent-2u", 40)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-backup"
                && did == "did:trnm:agent-2u"
                && controller == "org:lane2-admin"
        ));
        assert_eq!(reg.did("did:trnm:agent-2u").unwrap().revoked_at, None);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
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
    fn revoke_did_replay_repairs_legacy_uncascaded_capability_without_rewriting_did_timestamp() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2fix".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-2fix".to_string(),
                CapabilityScope::BridgeSettle,
                12,
                Some(100),
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2fix", 40)
            .unwrap();

        // Simulate legacy/corrupt snapshot drift: DID already revoked but cascade revoke was lost.
        reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;
        let audit_len_before = reg.audit_trail().len();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2fix", 99)
            .unwrap();

        assert_eq!(reg.did("did:trnm:agent-2fix").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
        assert_eq!(reg.audit_trail().len(), audit_len_before + 1);
        assert_eq!(
            reg.audit_trail().last().map(|ev| ev.action),
            Some(AuditAction::CapabilityRevoked)
        );
        assert_eq!(
            reg.audit_trail().last().map(|ev| ev.actor.as_str()),
            Some("system:cascade")
        );
        assert_eq!(reg.audit_trail().last().map(|ev| ev.at_height), Some(40));
    }

    #[test]
    fn revoke_did_replay_preserves_issue_height_floor_when_repairing_legacy_token() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2rfloor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-2rfloor".to_string(),
                CapabilityScope::BridgeSettle,
                60,
                Some(120),
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2rfloor", 40)
            .unwrap();

        // Simulate legacy/corrupt snapshot drift: replay should re-apply the cascade
        // but keep the issue-height floor instead of backdating to DID revoke anchor.
        reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;
        let audit_len_before = reg.audit_trail().len();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2rfloor", 99)
            .unwrap();

        assert_eq!(
            reg.did("did:trnm:agent-2rfloor").unwrap().revoked_at,
            Some(40)
        );
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(60));
        assert_eq!(reg.audit_trail().len(), audit_len_before + 1);
    }

    #[test]
    fn revoke_did_replay_with_older_height_is_rejected_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-2r".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-2r".to_string(),
                CapabilityScope::BridgeSettle,
                12,
                Some(100),
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2r", 40)
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-2r", 39)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidDidRevocationHeight {
                created_at: 40,
                revoked_at: 39,
            }
        ));
        assert_eq!(reg.did("did:trnm:agent-2r").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(40));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
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
    fn revoke_capability_replay_with_same_height_is_idempotent_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3eq".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3eq".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("initial_revoke".to_string()),
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("same_height_replay".to_string()),
        )
        .unwrap();

        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn revoke_capability_makes_token_inactive_at_same_height_fail_closed() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3eq-boundary".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3eq-boundary".to_string(),
                CapabilityScope::AuditRead,
                12,
                Some(80),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("boundary_revoke".to_string()),
        )
        .unwrap();

        let err = reg
            .verify_capability("org:lane2-admin", token_id, CapabilityScope::AuditRead, 30)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: err_token_id,
                at_height: 30,
                issued_at: 12,
                expires_at: Some(80),
                revoked_at: Some(30),
            } if err_token_id == token_id
        ));
    }

    #[test]
    fn revoke_capability_replay_with_older_height_is_rejected_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3r".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3r".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("initial_revoke".to_string()),
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability(
                "org:lane2-admin".to_string(),
                token_id,
                29,
                Some("stale_replay".to_string()),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidCapabilityRevocationHeight {
                issued_at: 30,
                revoked_at: 29,
            }
        ));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn revoke_capability_trims_audit_note_for_compliance_provenance() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3a".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3a".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("  evidence:case-42  ".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note.as_deref(), Some("evidence:case-42"));
    }

    #[test]
    fn revoke_capability_blank_audit_note_is_normalized_to_none() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3aa".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3aa".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("   ".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note, None);
    }

    #[test]
    fn revoke_capability_zero_width_audit_note_is_normalized_to_none() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3ab".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3ab".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("\u{200B}\u{200C}\u{2060}".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note, None);
    }

    #[test]
    fn revoke_capability_bidi_controls_only_audit_note_is_normalized_to_none() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3ab-bidi".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3ab-bidi".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("\u{202E}\u{202C}\u{2067}\u{2069}".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note, None);
    }

    #[test]
    fn revoke_capability_audit_note_strips_invisibles_and_collapses_whitespace() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3ab-note-sanitize".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3ab-note-sanitize".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("  proof\u{200B}\n case\u{202E}\t42  ".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note.as_deref(), Some("proof case 42"));
    }

    #[test]
    fn revoke_capability_audit_note_with_only_controls_after_trim_is_none() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-3ab-note-empty".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-3ab-note-empty".to_string(),
                CapabilityScope::AuditRead,
                12,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("\n\t\u{200B}\u{202E}\r".to_string()),
        )
        .unwrap();

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.note, None);
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
    fn revoke_did_cascade_does_not_backdate_capability_before_issue_height() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-4b".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-4b".to_string(),
                CapabilityScope::BridgeSettle,
                60,
                Some(200),
            )
            .unwrap();

        reg.revoke_did("org:lane2-admin".to_string(), "did:trnm:agent-4b", 40)
            .unwrap();

        assert_eq!(reg.did("did:trnm:agent-4b").unwrap().revoked_at, Some(40));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(60));

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRevoked);
        assert_eq!(last.actor, "system:cascade");
        assert_eq!(last.at_height, 60);
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
    fn renew_capability_extends_expiry_and_appends_audit() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(30),
            )
            .unwrap();

        reg.renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(45))
            .unwrap();

        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(45));

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRenewed);
        assert_eq!(last.actor, "org:lane2-admin");
        assert_eq!(last.subject, "did:trnm:agent-renew");
        assert_eq!(last.at_height, 25);
        assert_eq!(last.note.as_deref(), Some("token_id=1 expires_at=Some(45)"));
    }

    #[test]
    fn renew_capability_with_same_expiry_is_idempotent_without_new_audit() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-same-expiry".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-same-expiry".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(40),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        reg.renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(40))
            .unwrap();

        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(40));
        assert_eq!(token.revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityIssued);
        assert_eq!(last.at_height, 20);
    }

    #[test]
    fn renew_capability_at_expiry_boundary_keeps_token_active_and_audited() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-boundary".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-boundary".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(30),
            )
            .unwrap();

        reg.renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(40))
            .unwrap();

        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(40));
        assert!(token.is_active_at(40));

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityRenewed);
        assert_eq!(last.actor, "org:lane2-admin");
        assert_eq!(last.subject, "did:trnm:agent-renew-boundary");
        assert_eq!(last.at_height, 30);
        assert_eq!(last.note.as_deref(), Some("token_id=1 expires_at=Some(40)"));
    }

    #[test]
    fn renew_capability_rejects_at_revocation_boundary_fail_closed() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-revoke-boundary".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-revoke-boundary".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("manual_boundary_revoke".to_string()),
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: 1,
                at_height: 30,
                issued_at: 20,
                expires_at: Some(60),
                revoked_at: Some(30),
            }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_with_non_expiring_token_is_idempotent_without_new_audit() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-no-expiry".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-no-expiry".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();

        reg.renew_capability("org:lane2-admin".to_string(), token_id, 25, None)
            .unwrap();

        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, None);
        assert_eq!(token.revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);

        let last = reg.audit_trail().last().unwrap();
        assert_eq!(last.action, AuditAction::CapabilityIssued);
        assert_eq!(last.actor, "org:lane2-admin");
        assert_eq!(last.subject, "did:trnm:agent-renew-no-expiry");
        assert_eq!(last.at_height, 20);
    }

    #[test]
    fn renew_capability_rejects_expiry_before_renew_height_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-invalid-expiry".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-invalid-expiry".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(24))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidCapabilityExpiry {
                issued_at: 25,
                expires_at: 24,
            }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_expiry_regression_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 25, Some(45))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityRenewalRegression {
                current_expires_at: 60,
                requested_expires_at: 45,
            }
        ));
        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(60));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_clearing_existing_expiry_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-clear-expiry".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-clear-expiry".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 25, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityRenewalCannotClearExpiry {
                current_expires_at: 60,
            }
        ));
        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(60));
        assert_eq!(token.revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_height_before_issue_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-preissue".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-preissue".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 19, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: err_token_id,
                at_height: 19,
                issued_at: 20,
                expires_at: Some(60),
                revoked_at: None,
            } if err_token_id == token_id
        ));
        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(60));
        assert_eq!(token.revoked_at, None);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-auth".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-auth".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(50),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .renew_capability("org:lane2-observer".to_string(), token_id, 25, Some(60))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-observer"
                && did == "did:trnm:agent-renew-auth"
                && controller == "org:lane2-admin"
        ));
        let token = reg.capability(token_id).unwrap();
        assert_eq!(token.expires_at, Some(50));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_noncanonical_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-actorfmt".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-actorfmt".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(" org:lane2-admin ".to_string(), token_id, 25, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_blank_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-blank-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-blank-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("   ".to_string(), token_id, 25, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_control_character_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-control-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-control-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin\n".to_string(), token_id, 25, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_zero_width_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-zero-width-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-zero-width-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(
                "org:lane2-admin\u{200b}".to_string(),
                token_id,
                25,
                Some(80),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-zwnj-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-zwnj-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(
                "org:lane2-admin\u{200c}".to_string(),
                token_id,
                25,
                Some(80),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_word_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-word-joiner-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-word-joiner-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(
                "org:lane2-admin\u{2060}".to_string(),
                token_id,
                25,
                Some(80),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-alm-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-alm-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(
                "org:lane2-admin\u{061C}".to_string(),
                token_id,
                25,
                Some(80),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_bom_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-bom-actor".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-bom-actor".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability(
                "org:lane2-admin\u{FEFF}".to_string(),
                token_id,
                25,
                Some(80),
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_unknown_token_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-missing".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let err = reg
            .renew_capability("org:lane2-admin".to_string(), 42, 25, Some(60))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityNotFound { token_id } if token_id == 42
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_missing_subject_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-missing-subject".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-missing-subject".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        // Simulate legacy/corrupt snapshot drift: token row exists but DID row is gone.
        let removed = reg.dids.remove("did:trnm:agent-renew-missing-subject");
        assert!(removed.is_some());

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidNotFound { did }
                if did == "did:trnm:agent-renew-missing-subject"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn renew_capability_rejects_revoked_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-revoked".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-revoked".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        reg.revoke_did(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-revoked",
            30,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 35, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-renew-revoked"
        ));
        let token_after = reg.capability(token_id).unwrap();
        assert_eq!(token_after.expires_at, token_before.expires_at);
        assert_eq!(token_after.revoked_at, token_before.revoked_at);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_previously_revoked_token_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-token-revoked".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-token-revoked".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("manual_revoke_before_renew".to_string()),
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 35, Some(80))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: err_token_id,
                at_height: 35,
                issued_at: 20,
                expires_at: Some(60),
                revoked_at: Some(30),
            } if err_token_id == token_id
        ));

        let token_after = reg.capability(token_id).unwrap();
        assert_eq!(token_after.expires_at, token_before.expires_at);
        assert_eq!(token_after.revoked_at, token_before.revoked_at);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_when_renew_height_equals_revocation_height() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-revoke-race".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-revoke-race".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("race_revoke".to_string()),
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: err_token_id,
                at_height: 30,
                issued_at: 20,
                expires_at: Some(60),
                revoked_at: Some(30),
            } if err_token_id == token_id
        ));

        let token_after = reg.capability(token_id).unwrap();
        assert_eq!(token_after.expires_at, token_before.expires_at);
        assert_eq!(token_after.revoked_at, token_before.revoked_at);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn renew_capability_rejects_when_renew_height_equals_did_revocation_boundary() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-renew-did-race".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-renew-did-race".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(60),
            )
            .unwrap();

        reg.revoke_did(
            "org:lane2-admin".to_string(),
            "did:trnm:agent-renew-did-race",
            30,
        )
        .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).unwrap().clone();

        let err = reg
            .renew_capability("org:lane2-admin".to_string(), token_id, 30, Some(90))
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked { did } if did == "did:trnm:agent-renew-did-race"
        ));
        let token_after = reg.capability(token_id).unwrap();
        assert_eq!(token_after.expires_at, token_before.expires_at);
        assert_eq!(token_after.revoked_at, token_before.revoked_at);
        assert_eq!(reg.audit_trail().len(), audit_len_before);
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
    fn issue_capability_rejects_noncanonical_subject_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-6b".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                " did:trnm:agent-6b ".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue {
                field: "subject_did",
                ..
            }
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

    #[test]
    fn revoke_capability_rejects_control_character_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-control".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-control".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2-admin\n".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_rejects_zero_width_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-zero-width".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-zero-width".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2\u{200b}-admin".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-zwnj".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-zwnj".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2\u{200c}-admin".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_rejects_word_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-word-joiner".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-word-joiner".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2\u{2060}-admin".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-alm".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-alm".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2\u{061C}-admin".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_rejects_bom_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-7-bom".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-7-bom".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2\u{FEFF}-admin".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field: "actor", .. }
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn issue_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-8".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .issue_capability(
                "org:lane2-backup".to_string(),
                "did:trnm:agent-8".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-backup"
                && did == "did:trnm:agent-8"
                && controller == "org:lane2-admin"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert!(reg.capability(1).is_none());
    }

    #[test]
    fn revoke_capability_rejects_actor_that_is_not_did_controller_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-9".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-9".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2-backup".to_string(), token_id, 30, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-backup"
                && did == "did:trnm:agent-9"
                && controller == "org:lane2-admin"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn revoke_capability_keeps_controller_check_even_after_token_is_revoked() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-10".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-10".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap();

        reg.revoke_capability(
            "org:lane2-admin".to_string(),
            token_id,
            30,
            Some("first_revoke".to_string()),
        )
        .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .revoke_capability("org:lane2-backup".to_string(), token_id, 40, None)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-backup"
                && did == "did:trnm:agent-10"
                && controller == "org:lane2-admin"
        ));
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, Some(30));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
    }

    #[test]
    fn capability_expiry_is_inclusive_at_expiry_height() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:agent-11".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:agent-11".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(25),
            )
            .unwrap();

        let token = reg.capability(token_id).unwrap();
        assert!(token.is_active_at(20));
        assert!(token.is_active_at(25));
        assert!(!token.is_active_at(26));
    }

    #[test]
    fn verify_capability_accepts_active_controller_and_matching_scope() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-1".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-1".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        reg.verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            50,
        )
        .unwrap();
    }

    #[test]
    fn verify_capability_rejects_scope_mismatch_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-2".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-2".to_string(),
                CapabilityScope::AuditRead,
                20,
                Some(200),
            )
            .unwrap();
        let audit_len_before = reg.audit_trail().len();

        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityScopeMismatch {
                token_id: id,
                expected: CapabilityScope::BridgeSettle,
                actual: CapabilityScope::AuditRead,
            } if id == token_id
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap().revoked_at, None);
    }

    #[test]
    fn verify_capability_rejects_revoked_did_even_if_token_looks_active() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-legacy".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-legacy".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        // simulate a legacy/corrupt snapshot: DID revoked but token still not revoked.
        reg.dids
            .get_mut("did:trnm:settler-legacy")
            .unwrap()
            .revoked_at = Some(25);
        reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                30,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked { did } if did == "did:trnm:settler-legacy"
        ));
    }

    #[test]
    fn verify_capability_allows_historical_height_before_did_revocation() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-legacy-historical".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-legacy-historical".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        // Legacy/corrupt snapshot: DID was revoked, but token revocation was never cascaded.
        reg.dids
            .get_mut("did:trnm:settler-legacy-historical")
            .unwrap()
            .revoked_at = Some(80);
        reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

        let out = reg.verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeSettle,
            79,
        );

        assert!(out.is_ok());
    }

    #[test]
    fn verify_capability_rejects_height_equal_to_did_revocation_boundary() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-legacy-boundary".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-legacy-boundary".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        // Legacy/corrupt snapshot: DID revocation exists but token revoke cascade is absent.
        reg.dids
            .get_mut("did:trnm:settler-legacy-boundary")
            .unwrap()
            .revoked_at = Some(80);
        reg.capabilities.get_mut(&token_id).unwrap().revoked_at = None;

        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                80,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidRevoked { did } if did == "did:trnm:settler-legacy-boundary"
        ));
    }

    #[test]
    fn verify_capability_rejects_noncanonical_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actorfmt".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actorfmt".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                " org:lane2-admin ",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_blank_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-blank".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-blank".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability("", token_id, CapabilityScope::BridgeSettle, 50)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_control_character_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-control".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-control".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin\n",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_zero_width_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-zwsp".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-zwsp".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin\u{200B}",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_zero_width_non_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-zwnj".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-zwnj".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin\u{200C}",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_word_joiner_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-word-joiner".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-word-joiner".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin\u{2060}",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_arabic_letter_mark_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-alm".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-alm".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin\u{061C}",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_bom_actor_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-actor-bom".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-actor-bom".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(200),
            )
            .unwrap();

        let audit_len_before = reg.audit_trail().len();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "\u{FEFF}org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                50,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::InvalidIdentityValue { field, .. } if field == "actor"
        ));
        assert_eq!(reg.audit_trail().len(), audit_len_before);
        assert_eq!(reg.capability(token_id).unwrap(), &token_before);
    }

    #[test]
    fn verify_capability_rejects_missing_subject_did_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-missing-subject".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-missing-subject".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(120),
            )
            .unwrap();

        // Simulate legacy/corrupt snapshot drift: capability exists but DID row was lost.
        let removed = reg.dids.remove("did:trnm:settler-missing-subject");
        assert!(removed.is_some());

        let audit_before = reg.audit_trail().to_vec();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                30,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::DidNotFound { did }
                if did == "did:trnm:settler-missing-subject"
        ));
        assert_eq!(reg.audit_trail(), audit_before.as_slice());
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn verify_capability_rejects_unknown_token_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-missing-token".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();

        let baseline = reg.audit_trail().to_vec();
        let err = reg
            .verify_capability("org:lane2-admin", 42, CapabilityScope::BridgeSettle, 50)
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityNotFound { token_id } if token_id == 42
        ));
        assert_eq!(reg.audit_trail(), baseline.as_slice());
    }

    #[test]
    fn verify_capability_rejects_expired_token_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-expired".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-expired".to_string(),
                CapabilityScope::BridgeRevert,
                20,
                Some(30),
            )
            .unwrap();

        let baseline_audit = reg.audit_trail().to_vec();
        let baseline_token = reg.capability(token_id).cloned().unwrap();
        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeRevert,
                31,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: id,
                at_height: 31,
                issued_at: 20,
                expires_at: Some(30),
                revoked_at: None,
            } if id == token_id
        ));
        assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
        assert_eq!(reg.capability(token_id), Some(&baseline_token));
    }

    #[test]
    fn verify_capability_rejects_height_before_issue_without_side_effects() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-before-issue".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-before-issue".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                None,
            )
            .unwrap();

        let baseline_audit = reg.audit_trail().to_vec();
        let baseline_token = reg.capability(token_id).cloned().unwrap();
        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeSettle,
                19,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: id,
                at_height: 19,
                issued_at: 20,
                expires_at: None,
                revoked_at: None,
            } if id == token_id
        ));
        assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
        assert_eq!(reg.capability(token_id), Some(&baseline_token));
    }

    #[test]
    fn verify_capability_accepts_height_equal_to_expiry_boundary() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-expiry-boundary".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-expiry-boundary".to_string(),
                CapabilityScope::BridgeRevert,
                20,
                Some(30),
            )
            .unwrap();

        let baseline_audit = reg.audit_trail().to_vec();
        let baseline_token = reg.capability(token_id).cloned().unwrap();
        reg.verify_capability(
            "org:lane2-admin",
            token_id,
            CapabilityScope::BridgeRevert,
            30,
        )
        .unwrap();

        assert_eq!(reg.audit_trail(), baseline_audit.as_slice());
        assert_eq!(reg.capability(token_id), Some(&baseline_token));
    }

    #[test]
    fn verify_capability_rejects_inactive_or_unauthorized_actor() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-3".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-3".to_string(),
                CapabilityScope::BridgeRevert,
                20,
                Some(30),
            )
            .unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-admin",
                token_id,
                CapabilityScope::BridgeRevert,
                31,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive {
                token_id: id,
                at_height: 31,
                issued_at: 20,
                expires_at: Some(30),
                revoked_at: None,
            } if id == token_id
        ));

        let token2 = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-3".to_string(),
                CapabilityScope::BridgeRevert,
                40,
                None,
            )
            .unwrap();
        let err = reg
            .verify_capability(
                "org:lane2-backup",
                token2,
                CapabilityScope::BridgeRevert,
                45,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-backup"
                && did == "did:trnm:settler-3"
                && controller == "org:lane2-admin"
        ));
    }

    #[test]
    fn verify_capability_unauthorized_actor_does_not_mutate_registry() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:settler-authz-no-side-effect".to_string(),
            "org:lane2-admin".to_string(),
            10,
        )
        .unwrap();
        let token_id = reg
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:settler-authz-no-side-effect".to_string(),
                CapabilityScope::BridgeSettle,
                20,
                Some(120),
            )
            .unwrap();

        let audit_before = reg.audit_trail().to_vec();
        let token_before = reg.capability(token_id).cloned().unwrap();

        let err = reg
            .verify_capability(
                "org:lane2-unauthorized",
                token_id,
                CapabilityScope::BridgeSettle,
                30,
            )
            .unwrap_err();

        assert!(matches!(
            err,
            InteropIdentityError::UnauthorizedActor {
                actor,
                did,
                controller,
            } if actor == "org:lane2-unauthorized"
                && did == "did:trnm:settler-authz-no-side-effect"
                && controller == "org:lane2-admin"
        ));
        assert_eq!(reg.audit_trail(), audit_before.as_slice());
        assert_eq!(reg.capability(token_id), Some(&token_before));
    }

    #[test]
    fn market_capability_scopes_work_as_expected() {
        let mut reg = IdentityRegistry::default();
        reg.register_did(
            "did:trnm:market-agent".to_string(),
            "org:market-maker".to_string(),
            100,
        )
        .unwrap();

        let pub_token = reg
            .issue_capability(
                "org:market-maker".to_string(),
                "did:trnm:market-agent".to_string(),
                CapabilityScope::MarketPublish,
                110,
                None,
            )
            .unwrap();

        let exec_token = reg
            .issue_capability(
                "org:market-maker".to_string(),
                "did:trnm:market-agent".to_string(),
                CapabilityScope::MarketExecute,
                120,
                None,
            )
            .unwrap();

        // 1. Verify MarketPublish scope works
        reg.verify_capability(
            "org:market-maker",
            pub_token,
            CapabilityScope::MarketPublish,
            115,
        )
        .unwrap();

        // 2. Verify MarketExecute scope works
        reg.verify_capability(
            "org:market-maker",
            exec_token,
            CapabilityScope::MarketExecute,
            125,
        )
        .unwrap();

        // 3. Verify scope mismatch is rejected
        let err = reg
            .verify_capability(
                "org:market-maker",
                pub_token,
                CapabilityScope::MarketExecute,
                115,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::CapabilityScopeMismatch {
                expected: CapabilityScope::MarketExecute,
                actual: CapabilityScope::MarketPublish,
                ..
            }
        ));

        // 4. Verify revocation works for market scopes
        reg.revoke_capability(
            "org:market-maker".to_string(),
            pub_token,
            130,
            Some("market_ban".to_string()),
        )
        .unwrap();

        let err = reg
            .verify_capability(
                "org:market-maker",
                pub_token,
                CapabilityScope::MarketPublish,
                131,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            InteropIdentityError::CapabilityInactive { .. }
        ));
    }

    #[test]
    fn content_hash_changes_when_audit_note_differs() {
        let mut reg_a = IdentityRegistry::default();
        reg_a
            .register_did(
                "did:trnm:hash-audit-note".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap();
        let token_id = reg_a
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:hash-audit-note".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap();
        reg_a
            .revoke_capability(
                "org:lane2-admin".to_string(),
                token_id,
                30,
                Some("reason:a".to_string()),
            )
            .unwrap();

        let mut reg_b = IdentityRegistry::default();
        reg_b
            .register_did(
                "did:trnm:hash-audit-note".to_string(),
                "org:lane2-admin".to_string(),
                10,
            )
            .unwrap();
        let token_id = reg_b
            .issue_capability(
                "org:lane2-admin".to_string(),
                "did:trnm:hash-audit-note".to_string(),
                CapabilityScope::AuditRead,
                20,
                None,
            )
            .unwrap();
        reg_b
            .revoke_capability(
                "org:lane2-admin".to_string(),
                token_id,
                30,
                Some("reason:b".to_string()),
            )
            .unwrap();

        assert_ne!(reg_a.content_hash(), reg_b.content_hash());
    }
}
