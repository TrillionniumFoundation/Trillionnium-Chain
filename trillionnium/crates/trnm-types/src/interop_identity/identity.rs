use super::normalize::is_disallowed_invisible_char;
use super::{BTreeMap, Deserialize, InteropIdentityError, Serialize};

#[path = "identity/audit.rs"]
mod audit;
#[path = "identity/capability.rs"]
mod capability;
#[path = "identity/did_validation.rs"]
mod did_validation;

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
    pub(super) dids: BTreeMap<String, DidRecord>,
    pub(super) capabilities: BTreeMap<u64, CapabilityToken>,
    pub(super) audit_trail: Vec<AuditEvent>,
    pub(super) next_capability_id: u64,
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
}
