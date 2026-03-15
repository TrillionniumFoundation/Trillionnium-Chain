use crate::adapter_parse::context_matches_token;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdapterErrorKind {
    Retriable,
    NonRetriable,
}

#[derive(Debug, Clone)]
pub(crate) struct AdapterError {
    pub(crate) kind: AdapterErrorKind,
    pub(crate) context: String,
}

pub(crate) fn is_deterministic_rejection(rc: i32) -> bool {
    matches!(
        rc,
        super::RC_DUPLICATE | super::RC_NONCE_REJECTED | super::RC_SLO_VIOLATION
    )
}

pub(crate) fn is_idempotent_duplicate_ok(rc: i32) -> bool {
    rc == super::RC_DUPLICATE
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
pub(crate) enum ReputationSignal {
    Accepted,
    VerifierRejected,
    AdapterRetryExhausted,
    AdapterNonRetriable,
}

pub(crate) fn reputation_delta(signal: ReputationSignal) -> i32 {
    match signal {
        ReputationSignal::Accepted => 3,
        ReputationSignal::VerifierRejected => -2,
        ReputationSignal::AdapterRetryExhausted => -1,
        ReputationSignal::AdapterNonRetriable => -3,
    }
}

pub(crate) fn adapter_error_signal(kind: AdapterErrorKind) -> ReputationSignal {
    match kind {
        AdapterErrorKind::Retriable => ReputationSignal::AdapterRetryExhausted,
        AdapterErrorKind::NonRetriable => ReputationSignal::AdapterNonRetriable,
    }
}
