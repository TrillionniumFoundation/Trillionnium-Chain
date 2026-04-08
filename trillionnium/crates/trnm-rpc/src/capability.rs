use std::{cmp::Ordering, fs, path::Path};

use trnm_rpc::RpcErrorResponse;
use trnm_types::{AuditAction, AuditEvent, CapabilityToken, IdentityRegistry};

use crate::envpaths::normalize_wrapped_env_value;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct CapabilityAuditQueryResponse {
    pub(crate) token: CapabilityToken,
    pub(crate) owner_history: Vec<AuditEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CapabilityAuditQueryError {
    TokenNotFound(u64),
    InvalidRegistryState { field: &'static str, value: String },
}

impl CapabilityAuditQueryError {
    pub(crate) fn to_rpc_error(&self) -> RpcErrorResponse {
        match self {
            Self::TokenNotFound(token_id) => RpcErrorResponse {
                code: "CAPABILITY_NOT_FOUND",
                message: format!("capability token not found: {}", token_id),
            },
            Self::InvalidRegistryState { field, value } => RpcErrorResponse {
                code: "INVALID_REGISTRY_STATE",
                message: format!(
                    "non-canonical {} in identity registry snapshot: {}",
                    field, value
                ),
            },
        }
    }

    pub(crate) fn http_status(&self) -> &'static str {
        match self {
            Self::TokenNotFound(_) => "404 Not Found",
            Self::InvalidRegistryState { .. } => "422 Unprocessable Entity",
        }
    }
}

pub(crate) fn load_identity_registry(path: &Path) -> IdentityRegistry {
    let Ok(raw) = fs::read_to_string(path) else {
        return IdentityRegistry::default();
    };
    serde_json::from_str::<IdentityRegistry>(&raw).unwrap_or_default()
}

fn audit_action_rank(action: &AuditAction) -> u8 {
    match action {
        AuditAction::DidRegistered => 0,
        AuditAction::DidRevoked => 1,
        AuditAction::CapabilityIssued => 2,
        AuditAction::CapabilityRenewed => 3,
        AuditAction::CapabilityRevoked => 4,
    }
}

pub(crate) fn query_capability_audit(
    registry: &IdentityRegistry,
    token_id: u64,
) -> Result<CapabilityAuditQueryResponse, CapabilityAuditQueryError> {
    let Some(token) = registry.capability(token_id).cloned() else {
        return Err(CapabilityAuditQueryError::TokenNotFound(token_id));
    };

    if !IdentityRegistry::is_canonical_did(&token.subject_did) {
        return Err(CapabilityAuditQueryError::InvalidRegistryState {
            field: "subject_did",
            value: token.subject_did.clone(),
        });
    }

    if let Some(invalid_subject) = registry
        .audit_trail()
        .iter()
        .map(|event| event.subject.as_str())
        .find(|subject: &&str| !IdentityRegistry::is_canonical_did(subject))
    {
        return Err(CapabilityAuditQueryError::InvalidRegistryState {
            field: "owner_history.subject",
            value: invalid_subject.to_string(),
        });
    }

    let mut owner_history: Vec<_> = registry
        .audit_trail()
        .iter()
        .filter(|event| event.subject == token.subject_did)
        .cloned()
        .collect();

    // Keep audit query output deterministic even when registry snapshots are
    // merged/imported with non-canonical ordering.
    owner_history.sort_by(|left, right| {
        left.at_height
            .cmp(&right.at_height)
            .then_with(|| left.seq.cmp(&right.seq))
            .then_with(|| audit_action_rank(&left.action).cmp(&audit_action_rank(&right.action)))
            .then_with(|| left.actor.cmp(&right.actor))
            .then_with(|| left.subject.cmp(&right.subject))
            .then_with(|| left.note.cmp(&right.note))
            .then(Ordering::Equal)
    });

    Ok(CapabilityAuditQueryResponse {
        token,
        owner_history,
    })
}

pub(crate) fn normalize_capability_subject_lookup(raw: &str) -> Option<String> {
    let normalized = normalize_wrapped_env_value(raw)
        .chars()
        .filter_map(|ch| match ch {
            '\u{061C}'
            | '\u{200B}'
            | '\u{200C}'
            | '\u{200D}'
            | '\u{200E}'
            | '\u{200F}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{FEFF}' => None,
            _ if ch.is_control() => None,
            _ => Some(ch),
        })
        .collect::<String>();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

pub(crate) fn resolve_capability_token_subject_or_token(
    registry: &IdentityRegistry,
    subject_or_token: &str,
) -> Option<u64> {
    let normalized = normalize_capability_subject_lookup(subject_or_token)?;
    if let Ok(token_id) = normalized.parse::<u64>() {
        return Some(token_id);
    }

    if !IdentityRegistry::is_canonical_did(&normalized) {
        return None;
    }

    let mut subject_tokens = registry
        .capability_ids_by_subject(&normalized)
        .into_iter()
        .filter(|token_id| {
            registry
                .capability(*token_id)
                .map(|token| token.subject_did == normalized)
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    subject_tokens.sort_unstable();
    subject_tokens.last().copied()
}
