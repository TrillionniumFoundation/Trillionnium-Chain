pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionRequestExecutor {
    requests: Mutex<Vec<VerifierHttpClientSessionRequest>>,
}

impl VerifierHttpClientSessionRequestExecutor for RecordingHttpClientSessionRequestExecutor {
    fn execute_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(session_request.clone());
        assert_eq!(session_request.profile, session_config.profile);
        assert_eq!(
            session_request.transport_mode,
            session_config.transport_mode
        );
        assert_eq!(session_request.timeout_ms, session_config.timeout_ms);
        Ok(VerifierHttpClientSessionResponse {
            status_code: 210,
            headers: BTreeMap::from([("x-session-executor".to_string(), "ok".to_string())]),
            body: b"session-executor-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionResponseReader {
    responses: Mutex<Vec<VerifierHttpClientSessionResponse>>,
}

impl VerifierHttpClientSessionResponseReader for RecordingHttpClientSessionResponseReader {
    fn read_response(
        &self,
        session_response: VerifierHttpClientSessionResponse,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        self.responses
            .lock()
            .unwrap()
            .push(session_response.clone());
        Ok(VerifierHttpClientRuntimeResponse {
            status_code: session_response.status_code,
            headers: session_response.headers,
            body: session_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionRequestExecutor;

impl VerifierHttpClientSessionRequestExecutor for RejectingHttpClientSessionRequestExecutor {
    fn execute_request(
        &self,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session request executor rejected session".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionResponseReader;

impl VerifierHttpClientSessionResponseReader for PanicHttpClientSessionResponseReader {
    fn read_response(
        &self,
        _session_response: VerifierHttpClientSessionResponse,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        panic!("session response reader should not be called when request executor fails")
    }
}

pub(super) struct PanicHttpClientRuntimeResponseAdapter;

impl VerifierHttpClientRuntimeResponseAdapter for PanicHttpClientRuntimeResponseAdapter {
    fn adapt_response(
        &self,
        _runtime_response: VerifierHttpClientRuntimeResponse,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        panic!("response adapter should not be called when runtime fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpBodyReader {
    bodies: Mutex<Vec<Vec<u8>>>,
}

impl VerifierHttpResponseBodyReader for RecordingHttpBodyReader {
    fn read_body(
        &self,
        raw_response: RawHttpVerifierResponse,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        self.bodies.lock().unwrap().push(raw_response.body.clone());
        Ok(HttpVerifierResponse {
            status_code: raw_response.status_code,
            body: String::from_utf8(raw_response.body).unwrap(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpTimeoutHook {
    calls: Mutex<Vec<String>>,
}

impl VerifierHttpTimeoutHook for RecordingHttpTimeoutHook {
    fn before_execute(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        self.calls.lock().unwrap().push(format!(
            "before:{}:{}",
            http_request.profile, http_request.timeout_ms
        ));
        Ok(())
    }

    fn after_response(
        &self,
        http_request: &HttpVerifierRequest,
        raw_response: &RawHttpVerifierResponse,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        self.calls.lock().unwrap().push(format!(
            "after:{}:{}",
            http_request.profile, raw_response.status_code
        ));
        Ok(())
    }
}

pub(super) struct RejectingHttpTimeoutHook;

impl VerifierHttpTimeoutHook for RejectingHttpTimeoutHook {
    fn before_execute(
        &self,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "timeout hook rejected transport execution".into(),
        })
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

pub(super) struct PanicHttpRequestExecutor;

impl VerifierHttpRequestExecutor for PanicHttpRequestExecutor {
    fn execute_request(
        &self,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        panic!("request executor should not be called when timeout hook fails")
    }
}
