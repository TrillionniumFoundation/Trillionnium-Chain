use super::*;

#[allow(dead_code)]
struct Utf8HttpResponseBodyReader;

impl VerifierHttpResponseBodyReader for Utf8HttpResponseBodyReader {
    fn read_body(
        &self,
        raw_response: RawHttpVerifierResponse,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        let body = String::from_utf8(raw_response.body).map_err(|err| {
            BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!("http transport returned non-utf8 body: {err}"),
            }
        })?;
        Ok(HttpVerifierResponse {
            status_code: raw_response.status_code,
            body,
        })
    }
}

#[allow(dead_code)]
struct NoopVerifierHttpTimeoutHook;

impl VerifierHttpTimeoutHook for NoopVerifierHttpTimeoutHook {
    fn before_execute(
        &self,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        Ok(())
    }

    fn after_response(
        &self,
        _http_request: &HttpVerifierRequest,
        _raw_response: &RawHttpVerifierResponse,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        Ok(())
    }
}

#[allow(dead_code)]
struct RealVerifierHttpTransport {
    request_executor: Arc<dyn VerifierHttpRequestExecutor>,
    body_reader: Arc<dyn VerifierHttpResponseBodyReader>,
    timeout_hook: Arc<dyn VerifierHttpTimeoutHook>,
}

#[allow(dead_code)]
impl RealVerifierHttpTransport {
    fn new() -> Self {
        Self {
            request_executor: Arc::new(AdapterBackedVerifierHttpRequestExecutor::new()),
            body_reader: Arc::new(Utf8HttpResponseBodyReader),
            timeout_hook: Arc::new(NoopVerifierHttpTimeoutHook),
        }
    }

    #[cfg(test)]
    fn with_components(
        request_executor: Arc<dyn VerifierHttpRequestExecutor>,
        body_reader: Arc<dyn VerifierHttpResponseBodyReader>,
        timeout_hook: Arc<dyn VerifierHttpTimeoutHook>,
    ) -> Self {
        Self {
            request_executor,
            body_reader,
            timeout_hook,
        }
    }
}

impl VerifierHttpTransport for RealVerifierHttpTransport {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        self.timeout_hook.before_execute(http_request, request)?;
        let raw_response = self
            .request_executor
            .execute_request(http_request, request)?;
        self.timeout_hook
            .after_response(http_request, &raw_response, request)?;
        self.body_reader
            .read_body(raw_response, http_request, request)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRetryExecution {
    attempts: u32,
    response: HttpVerifierResponse,
}

#[allow(dead_code)]
trait VerifierHttpRetryExecutor: Send + Sync {
    fn execute(
        &self,
        transport: &dyn VerifierHttpTransport,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpRetryExecution, BackendExecutionError>;
}

#[allow(dead_code)]
struct PolicyAwareHttpRetryExecutor;

impl VerifierHttpRetryExecutor for PolicyAwareHttpRetryExecutor {
    fn execute(
        &self,
        transport: &dyn VerifierHttpTransport,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpRetryExecution, BackendExecutionError> {
        let max_attempts = http_request.retry_policy.max_attempts.max(1);
        let mut last_retryable_error: Option<BackendExecutionError> = None;
        for attempt in 1..=max_attempts {
            let mut attempt_request = http_request.clone();
            attempt_request
                .headers
                .insert("x-attempt".to_string(), attempt.to_string());
            match transport.send(&attempt_request, request) {
                Ok(response) if response.status_code >= 500 && attempt < max_attempts => continue,
                Ok(response) => {
                    return Ok(HttpRetryExecution {
                        attempts: attempt,
                        response,
                    })
                }
                Err(err @ BackendExecutionError::Unavailable { .. })
                | Err(err @ BackendExecutionError::Internal { .. })
                    if attempt < max_attempts =>
                {
                    last_retryable_error = Some(err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Err(
            last_retryable_error.unwrap_or_else(|| BackendExecutionError::Unavailable {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "http retry executor exhausted all attempts".to_string(),
            }),
        )
    }
}

