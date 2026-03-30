use anyhow::{anyhow, Result};
use std::hash::Hash;
use std::time::{SystemTime, UNIX_EPOCH};

#[path = "state/relay_session.rs"]
mod relay_session;
#[path = "state/risk.rs"]
mod risk;

pub use relay_session::RelayService;
pub(crate) use relay_session::{
    hash_bytes, hash_envelope, hash_pair, merkle_root_and_proofs, RelaySessionState,
    MAX_PROOF_QUERY_SPAN, MAX_RELAY_QUERY_LIMIT,
};
pub use risk::RiskQuotaConfig;
pub(crate) use risk::{
    canonicalize_risk_source, elide_risk_error_key, RiskQuotaState,
    MAX_RISK_BUCKET_KEYS_PER_DOMAIN, RISK_ERROR_KEY_MAX_CHARS, RISK_SOURCE_MAX_CHARS,
};

pub(crate) fn bad_request(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("bad_request/{code}: {}", detail.into())
}

pub(crate) fn not_found(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("not_found/{code}: {}", detail.into())
}

pub(crate) fn too_many_requests(code: &str, detail: impl Into<String>) -> anyhow::Error {
    anyhow!("too_many_requests/{code}: {}", detail.into())
}

pub(crate) fn validate_session_id(session_id: &str, field: &str) -> Result<()> {
    if session_id.trim().is_empty() {
        return Err(bad_request(
            "empty_session",
            format!("{field} must be non-empty"),
        ));
    }
    if session_id.trim() != session_id
        || !session_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        return Err(bad_request(
            "invalid_session",
            format!("{field} must be canonical"),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_session_id;

    #[test]
    fn validate_session_id_rejects_zero_width_space() {
        let err = validate_session_id("sp\u{200B}canonical", "session_id").unwrap_err();
        assert!(err.to_string().contains("bad_request/invalid_session"));
    }

    #[test]
    fn validate_session_id_accepts_canonical_ascii_tokens() {
        validate_session_id("sp-canonical_01.v2", "session_id").unwrap();
    }
}

pub(crate) fn validate_proof_query_range(from_seq: u64, to_seq: u64) -> Result<()> {
    if from_seq == 0 {
        return Err(bad_request("invalid_range", "from_seq must be >= 1"));
    }
    if to_seq < from_seq {
        return Err(bad_request(
            "invalid_range",
            format!("from_seq({from_seq}) must be <= to_seq({to_seq})"),
        ));
    }
    let span = to_seq.saturating_sub(from_seq).saturating_add(1);
    if span > MAX_PROOF_QUERY_SPAN {
        return Err(bad_request(
            "range_out_of_bounds",
            format!("requested span {span} exceeds max {MAX_PROOF_QUERY_SPAN}"),
        ));
    }
    Ok(())
}

pub(crate) fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RiskDomain {
    Relay,
    Proof,
    Challenge,
}

impl RiskDomain {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RiskDomain::Relay => "relay",
            RiskDomain::Proof => "proof",
            RiskDomain::Challenge => "challenge",
        }
    }
}
