pub(super) use super::*;

pub(super) const TEST_URL: &str = "https://intel-verifier.invalid/v1/quote/sgx-dcap";
pub(super) const TEST_PROFILE: &str = "intel-dcap-external-default";
pub(super) const TEST_TIMEOUT_MS: u64 = 5_000;

pub(super) fn test_retry_policy() -> RetryBackoffPolicy {
    RetryBackoffPolicy {
        max_attempts: 3,
        backoff_ms: 250,
        strategy: RetryBackoffStrategy::Exponential,
    }
}

pub(super) fn mock_tee_backend_request<'a>(task: &'a TaskObject) -> BackendVerificationRequest<'a> {
    BackendVerificationRequest {
        family: VerificationBackendFamily::Tee,
        task,
        proof_data: b"TEE:...",
        tee_payload: None,
        zk_payload: None,
        resolved_vk_ref: None,
    }
}
