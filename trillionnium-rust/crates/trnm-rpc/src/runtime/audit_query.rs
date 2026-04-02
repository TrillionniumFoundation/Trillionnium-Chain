use std::cmp::Ordering;

use anyhow::Result;
use trnm_types::{AuditAction, IdentityRegistry};

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
        .find(|subject| !IdentityRegistry::is_canonical_did(subject))
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
