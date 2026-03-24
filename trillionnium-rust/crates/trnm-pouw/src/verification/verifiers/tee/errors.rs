use crate::verification::backend::{BackendExecutionError, VerificationBackendError};
use crate::verification::VerificationResult;

pub(super) fn classify_backend_err(err: VerificationBackendError) -> VerificationResult {
    match err {
        VerificationBackendError::Selection(selection) => {
            VerificationResult::Indeterminate(format!("unavailable: {selection}"))
        }
        VerificationBackendError::Execution(BackendExecutionError::InvalidProof {
            reason, ..
        }) => VerificationResult::Invalid(reason),
        VerificationBackendError::Execution(BackendExecutionError::MalformedProof {
            reason, ..
        }) => VerificationResult::Invalid(format!("malformed: {reason}")),
        VerificationBackendError::Execution(BackendExecutionError::NotConfigured { .. }) => {
            VerificationResult::Indeterminate(
                "unavailable: TEE receipt cryptographic verification backend not configured"
                    .to_string(),
            )
        }
        VerificationBackendError::Execution(BackendExecutionError::Unavailable {
            backend,
            reason,
        }) => VerificationResult::Indeterminate(format!(
            "unavailable: verification backend '{backend}' cannot currently verify receipt: {reason}"
        )),
        VerificationBackendError::Execution(BackendExecutionError::Internal {
            backend,
            reason,
        }) => VerificationResult::Indeterminate(format!(
            "backend_error: verification backend '{backend}' failed: {reason}"
        )),
    }
}
