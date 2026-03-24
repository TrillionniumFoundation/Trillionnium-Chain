use anyhow::Result;
use trnm_types::IdentityRegistry;

use super::*;

#[path = "audit_query/capability_subject.rs"]
mod capability_subject;
#[path = "audit_query/event_listing.rs"]
mod event_listing;
#[path = "audit_query/query_parsing.rs"]
mod query_parsing;

pub(crate) use capability_subject::resolve_capability_token_subject_or_token;
pub(crate) use event_listing::query_normalized_audit_events;
pub(crate) use query_parsing::{
    parse_query_events_limit_from_path, parse_query_normalized_audit_events_query_from_path,
};

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

    let mut owner_history: Vec<_> = registry
        .audit_trail()
        .iter()
        .filter(|event| event.subject == token.subject_did)
        .cloned()
        .collect();

    if let Some(invalid_subject) = owner_history
        .iter()
        .map(|event| event.subject.as_str())
        .find(|subject| !IdentityRegistry::is_canonical_did(subject))
    {
        return Err(CapabilityAuditQueryError::InvalidRegistryState {
            field: "owner_history.subject",
            value: invalid_subject.to_string(),
        });
    }

    owner_history.sort_by_key(|event| (event.at_height, event.seq));

    Ok(CapabilityAuditQueryResponse {
        token,
        owner_history,
    })
}
