use crate::adapter_parse::context_matches_token;
use crate::state::MessageIngressRecord;
use crate::{RC_DUPLICATE, RC_NONCE_REJECTED, RC_SLO_VIOLATION};

use super::{AdapterError, AdapterErrorKind, ReputationSignal};

pub(crate) fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(rc, RC_DUPLICATE | RC_NONCE_REJECTED | RC_SLO_VIOLATION)
}

pub(crate) fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == RC_DUPLICATE
}

pub(crate) fn classify_adapter_error(err: &AdapterError) -> (&'static str, &'static str) {
    if context_matches_token(&err.context, "proof-missing")
        || context_matches_token(&err.context, "missing-provider-request-id")
    {
        return ("ERR_M2V2_PROOF_MISSING", "proof_missing");
    }
    if context_matches_token(&err.context, "proof-invalid")
        || context_matches_token(&err.context, "missing-adapter-label")
        || context_matches_token(&err.context, "no-json-line")
        || context_matches_token(&err.context, "invalid-json")
    {
        return ("ERR_M2V2_PROOF_INVALID", "proof_invalid");
    }
    if context_matches_token(&err.context, "settlement-degraded") {
        return ("ERR_M2V2_SETTLEMENT_DEGRADED", "settlement_degraded");
    }
    if context_matches_token(&err.context, "proof-late")
        || context_matches_token(&err.context, "timeout")
    {
        return ("ERR_M2V2_PROOF_LATE", "proof_late");
    }

    match err.kind {
        AdapterErrorKind::Retriable => ("adapter_error", "retry_exhausted"),
        AdapterErrorKind::NonRetriable => ("adapter_error", "non_retriable"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReputationImpact {
    pub(crate) label: &'static str,
    pub(crate) delta: i32,
    pub(crate) tier: u8,
}

pub(crate) fn reputation_impact(signal: ReputationSignal) -> ReputationImpact {
    match signal {
        ReputationSignal::Accepted => ReputationImpact {
            label: "accepted",
            delta: 3,
            tier: 3,
        },
        ReputationSignal::AdapterRetryExhausted => ReputationImpact {
            label: "adapter_retry_exhausted",
            delta: -1,
            tier: 2,
        },
        ReputationSignal::VerifierRejected => ReputationImpact {
            label: "verifier_rejected",
            delta: -2,
            tier: 1,
        },
        ReputationSignal::AdapterNonRetriable => ReputationImpact {
            label: "adapter_non_retriable",
            delta: -3,
            tier: 0,
        },
    }
}

pub(crate) fn reputation_score_impact(signal: ReputationSignal) -> (&'static str, i32) {
    let impact = reputation_impact(signal);
    (impact.label, impact.delta)
}

pub(crate) fn reputation_delta(signal: ReputationSignal) -> i32 {
    reputation_impact(signal).delta
}

pub(crate) fn reputation_tier(signal: ReputationSignal) -> u8 {
    reputation_impact(signal).tier
}

pub(crate) fn apply_reputation_signal(
    rec: &mut MessageIngressRecord,
    signal: ReputationSignal,
) -> ReputationImpact {
    let impact = reputation_impact(signal);
    rec.reputation_delta = Some(impact.delta);
    impact
}

pub(crate) fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}
