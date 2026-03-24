use super::*;

pub(super) struct Http503IntelTransport;

impl VerifierHttpTransport for Http503IntelTransport {
    fn send(
        &self,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        Ok(HttpVerifierResponse {
            status_code: 503,
            body: "upstream unavailable".into(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpRequestExecutor {
    urls: Mutex<Vec<String>>,
}

impl VerifierHttpRequestExecutor for RecordingHttpRequestExecutor {
    fn execute_request(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        self.urls.lock().unwrap().push(http_request.url.clone());
        assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
        assert_eq!(http_request.profile, "intel-dcap-external-default");
        assert_eq!(
            http_request
                .headers
                .get("authorization")
                .map(String::as_str),
            Some("bearer tee.intel.external-token.sgx-dcap")
        );
        Ok(RawHttpVerifierResponse {
            status_code: 200,
            headers: BTreeMap::new(),
            body: b"{\"transport\":\"ok\"}".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpRequestPlanner {
    requests: Mutex<Vec<VerifierHttpClientRequest>>,
}

impl VerifierHttpRequestPlanner for RecordingHttpRequestPlanner {
    fn plan_request(
        &self,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRequest, BackendExecutionError> {
        let planned = VerifierHttpClientRequest {
            method: http_request.method,
            url: http_request.url.clone(),
            headers: http_request.headers.clone(),
            body: http_request.body.as_bytes().to_vec(),
            timeout_ms: http_request.timeout_ms,
        };
        self.requests.lock().unwrap().push(planned.clone());
        Ok(planned)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientAdapter {
    requests: Mutex<Vec<VerifierHttpClientRequest>>,
}

impl VerifierHttpClientAdapter for RecordingHttpClientAdapter {
    fn execute(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(client_request.clone());
        assert_eq!(client_request.method, HttpMethod::Post);
        assert_eq!(client_request.url, http_request.url);
        assert_eq!(client_request.timeout_ms, http_request.timeout_ms);
        assert_eq!(client_request.headers, http_request.headers);
        assert_eq!(client_request.body, http_request.body.as_bytes());
        Ok(RawHttpVerifierResponse {
            status_code: 202,
            headers: BTreeMap::from([("x-source".to_string(), "adapter".to_string())]),
            body: b"adapter-ok".to_vec(),
        })
    }
}

pub(super) struct RejectingHttpRequestPlanner;

impl VerifierHttpRequestPlanner for RejectingHttpRequestPlanner {
    fn plan_request(
        &self,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRequest, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "request planner rejected http request".into(),
        })
    }
}

pub(super) struct PanicHttpClientAdapter;

impl VerifierHttpClientAdapter for PanicHttpClientAdapter {
    fn execute(
        &self,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        panic!("client adapter should not be called when planner fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientConfigResolver {
    configs: Mutex<Vec<ResolvedVerifierHttpClientConfig>>,
}

impl VerifierHttpClientConfigResolver for RecordingHttpClientConfigResolver {
    fn resolve_config(
        &self,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierHttpClientConfig, BackendExecutionError> {
        let config = ResolvedVerifierHttpClientConfig {
            profile: http_request.profile.clone(),
            transport_mode: http_request.transport_mode.clone(),
            timeout_ms: client_request.timeout_ms,
        };
        self.configs.lock().unwrap().push(config.clone());
        Ok(config)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientHandle {
    calls: Mutex<Vec<(ResolvedVerifierHttpClientConfig, VerifierHttpClientRequest)>>,
}

impl VerifierHttpClientHandle for RecordingHttpClientHandle {
    fn execute(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        self.calls
            .lock()
            .unwrap()
            .push((config.clone(), client_request.clone()));
        assert_eq!(config.profile, http_request.profile);
        assert_eq!(config.transport_mode, http_request.transport_mode);
        assert_eq!(config.timeout_ms, client_request.timeout_ms);
        Ok(RawHttpVerifierResponse {
            status_code: 204,
            headers: BTreeMap::from([("x-client".to_string(), "handle".to_string())]),
            body: b"handle-ok".to_vec(),
        })
    }
}

pub(super) struct RejectingHttpClientConfigResolver;

impl VerifierHttpClientConfigResolver for RejectingHttpClientConfigResolver {
    fn resolve_config(
        &self,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierHttpClientConfig, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client config resolver rejected http adapter".into(),
        })
    }
}

pub(super) struct PanicHttpClientHandle;

impl VerifierHttpClientHandle for PanicHttpClientHandle {
    fn execute(
        &self,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        panic!("client handle should not be called when config resolver fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientRuntimeRequestBuilder {
    requests: Mutex<Vec<VerifierHttpClientRuntimeRequest>>,
}

impl VerifierHttpClientRuntimeRequestBuilder for RecordingHttpClientRuntimeRequestBuilder {
    fn build_request(
        &self,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeRequest, BackendExecutionError> {
        let runtime_request = VerifierHttpClientRuntimeRequest {
            method: client_request.method,
            url: client_request.url.clone(),
            headers: client_request.headers.clone(),
            body: client_request.body.clone(),
            timeout_ms: config.timeout_ms,
            profile: config.profile.clone(),
            transport_mode: config.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(runtime_request.clone());
        Ok(runtime_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientRuntime {
    requests: Mutex<Vec<VerifierHttpClientRuntimeRequest>>,
}

impl VerifierHttpClientRuntime for RecordingHttpClientRuntime {
    fn execute_runtime(
        &self,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(runtime_request.clone());
        assert_eq!(runtime_request.profile, config.profile);
        assert_eq!(runtime_request.transport_mode, config.transport_mode);
        assert_eq!(runtime_request.timeout_ms, config.timeout_ms);
        Ok(VerifierHttpClientRuntimeResponse {
            status_code: 206,
            headers: BTreeMap::from([("x-runtime".to_string(), "ok".to_string())]),
            body: b"runtime-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientRuntimeResponseAdapter {
    responses: Mutex<Vec<VerifierHttpClientRuntimeResponse>>,
}

impl VerifierHttpClientRuntimeResponseAdapter for RecordingHttpClientRuntimeResponseAdapter {
    fn adapt_response(
        &self,
        runtime_response: VerifierHttpClientRuntimeResponse,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        self.responses
            .lock()
            .unwrap()
            .push(runtime_response.clone());
        Ok(RawHttpVerifierResponse {
            status_code: runtime_response.status_code,
            headers: runtime_response.headers,
            body: runtime_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientRuntime;

impl VerifierHttpClientRuntime for RejectingHttpClientRuntime {
    fn execute_runtime(
        &self,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientRuntimeResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client runtime rejected http handle".into(),
        })
    }
}
