use crate::verification::backend::{
    backend_token_family_hint, backend_token_zk_system_hints,
    contains_forbidden_opaque_token_chars, normalize_backend_token, BackendExecutionError,
    VerificationBackendError, VerificationBackendFamily,
};
use crate::verification::VerificationResult;

pub(super) fn validate_selected_backend_token(raw: &str) -> Result<(), VerificationBackendError> {
    if raw != raw.trim() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' must not contain surrounding whitespace",
                raw
            ),
        }
        .into());
    }

    if raw.is_empty() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: "invalid zk payload: backend must not be empty".to_string(),
        }
        .into());
    }

    if raw.eq_ignore_ascii_case("noop") {
        if raw != "noop" {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: "invalid zk payload: legacy no-backend selector must use canonical lowercase token 'noop'".to_string(),
            }
            .into());
        }
    } else if normalize_backend_token(raw).is_none() {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' must contain at least one canonical token segment",
                raw
            ),
        }
        .into());
    }

    if contains_forbidden_opaque_token_chars(raw) {
        return Err(BackendExecutionError::MalformedProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' must be a single opaque token without embedded whitespace or control characters",
                raw
            ),
        }
        .into());
    }

    match backend_token_family_hint(raw) {
        Some(VerificationBackendFamily::Tee) => {
            return Err(BackendExecutionError::InvalidProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' declares tee family and does not match zk router semantics",
                    raw
                ),
            }
            .into())
        }
        Some(VerificationBackendFamily::Zk) if backend_token_zk_system_hints(raw).is_empty() => {
            return Err(BackendExecutionError::MalformedProof {
                backend: "zk:payload".to_string(),
                reason: format!(
                    "invalid zk payload: backend '{}' must not be a family-only zk router token without a canonical zk_system hint",
                    raw
                ),
            }
            .into())
        }
        _ => {}
    }

    if backend_token_zk_system_hints(raw).len() > 1 {
        return Err(BackendExecutionError::InvalidProof {
            backend: "zk:payload".to_string(),
            reason: format!(
                "invalid zk payload: backend '{}' carries multiple zk_system hints and does not match fail-closed zk router semantics",
                raw
            ),
        }
        .into());
    }

    Ok(())
}

pub(super) fn has_json_envelope(proof_data: &[u8]) -> bool {
    proof_data
        .iter()
        .position(|b| *b == b':')
        .and_then(|idx| proof_data.get(idx + 1..))
        .and_then(|body| std::str::from_utf8(body).ok())
        .map(|body| body.trim_start().starts_with('{'))
        .unwrap_or(false)
}

pub(super) fn classify_backend_err(err: VerificationBackendError) -> VerificationResult {
    match err {
        VerificationBackendError::Selection(selection) => {
            VerificationResult::Indeterminate(format!("unavailable: {selection}"))
        }
        VerificationBackendError::Execution(BackendExecutionError::InvalidProof { reason, .. }) => {
            VerificationResult::Invalid(reason)
        }
        VerificationBackendError::Execution(BackendExecutionError::MalformedProof { reason, .. }) => {
            VerificationResult::Invalid(format!("malformed: {reason}"))
        }
        VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. }) => {
            VerificationResult::Indeterminate(
                "unavailable: ZK proof cryptographic verification backend not configured"
                    .to_string(),
            )
        }
        VerificationBackendError::Execution(BackendExecutionError::Unavailable { backend, reason }) => {
            VerificationResult::Indeterminate(format!(
                "unavailable: verification backend '{backend}' cannot currently verify proof: {reason}"
            ))
        }
        VerificationBackendError::Execution(BackendExecutionError::Internal { backend, reason }) => {
            VerificationResult::Indeterminate(format!(
                "backend_error: verification backend '{backend}' failed: {reason}"
            ))
        }
    }
}
