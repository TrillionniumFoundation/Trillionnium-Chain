pub(super) use super::*;


#[derive(Default)]
pub(super) struct RecordingHttpClientSessionFactory {
    opened: Mutex<Vec<ResolvedVerifierHttpClientSessionConfig>>,
    executed: Arc<
        Mutex<
            Vec<(
                ResolvedVerifierHttpClientSessionConfig,
                VerifierHttpClientRuntimeRequest,
            )>,
        >,
    >,
}

pub(super) struct RecordingHttpClientSession {
    executed: Arc<
        Mutex<
            Vec<(
                ResolvedVerifierHttpClientSessionConfig,
                VerifierHttpClientRuntimeRequest,
            )>,
        >,
    >,
}

impl VerifierHttpClientSessionFactory for RecordingHttpClientSessionFactory {
    fn open_session(
        &self,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSession>, BackendExecutionError> {
        self.opened.lock().unwrap().push(session_config.clone());
        Ok(Box::new(RecordingHttpClientSession {
            executed: self.executed.clone(),
        }))
    }
}

impl VerifierHttpClientSession for RecordingHttpClientSession {
    fn execute_session(
        &self,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        self.executed
            .lock()
            .unwrap()
            .push((session_config.clone(), runtime_request.clone()));
        Ok(VerifierHttpClientRuntimeResponse {
            status_code: 208,
            headers: BTreeMap::from([("x-session".to_string(), "ok".to_string())]),
            body: b"session-ok".to_vec(),
        })
    }
}

pub(super) struct RejectingHttpClientSessionFactory;

impl VerifierHttpClientSessionFactory for RejectingHttpClientSessionFactory {
    fn open_session(
        &self,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSession>, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session factory rejected runtime".into(),
        })
    }
}

#[allow(dead_code)]
pub(super) struct PanicHttpClientSession;

impl VerifierHttpClientSession for PanicHttpClientSession {
    fn execute_session(
        &self,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        panic!("client session should not be called when session factory fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolBytesEncoder {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolBytesRequest>>,
}
