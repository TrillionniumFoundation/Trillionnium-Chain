pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionTransportRequestBuilder {
    requests: Mutex<Vec<VerifierHttpClientSessionTransportRequest>>,
}

impl VerifierHttpClientSessionTransportRequestBuilder
    for RecordingHttpClientSessionTransportRequestBuilder
{
    fn build_transport_request(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRequest, BackendExecutionError> {
        let transport_request = VerifierHttpClientSessionTransportRequest {
            method: call_request.method,
            url: call_request.url.clone(),
            headers: call_request.headers.clone(),
            body: call_request.body.clone(),
            timeout_ms: call_request.timeout_ms,
            profile: call_request.profile.clone(),
            transport_mode: call_request.transport_mode.clone(),
        };
        self.requests
            .lock()
            .unwrap()
            .push(transport_request.clone());
        Ok(transport_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionTransportAdapter {
    requests: Mutex<Vec<VerifierHttpClientSessionTransportRequest>>,
}

impl VerifierHttpClientSessionTransportAdapter for RecordingHttpClientSessionTransportAdapter {
    fn send_transport(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError> {
        self.requests
            .lock()
            .unwrap()
            .push(transport_request.clone());
        assert_eq!(transport_request.profile, session_config.profile);
        assert_eq!(
            transport_request.transport_mode,
            session_config.transport_mode
        );
        assert_eq!(transport_request.timeout_ms, session_config.timeout_ms);
        Ok(VerifierHttpClientSessionTransportRawResponse {
            status_code: 213,
            headers: BTreeMap::from([("x-transport".to_string(), "ok".to_string())]),
            body: b"transport-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionRawIoResponseParser {
    responses: Mutex<Vec<VerifierHttpClientSessionTransportRawResponse>>,
}

impl VerifierHttpClientSessionRawIoResponseParser
    for RecordingHttpClientSessionRawIoResponseParser
{
    fn parse_raw_response(
        &self,
        raw_response: VerifierHttpClientSessionTransportRawResponse,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(raw_response.clone());
        Ok(VerifierHttpClientSessionCallResponse {
            status_code: raw_response.status_code,
            headers: raw_response.headers,
            body: raw_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionTransportAdapter;

impl VerifierHttpClientSessionTransportAdapter for RejectingHttpClientSessionTransportAdapter {
    fn send_transport(
        &self,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session transport adapter rejected call request".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionRawIoResponseParser;

impl VerifierHttpClientSessionRawIoResponseParser for PanicHttpClientSessionRawIoResponseParser {
    fn parse_raw_response(
        &self,
        _raw_response: VerifierHttpClientSessionTransportRawResponse,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError> {
        panic!("raw io response parser should not be called when transport adapter fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionCallBuilder {
    requests: Mutex<Vec<VerifierHttpClientSessionCallRequest>>,
}

impl VerifierHttpClientSessionCallBuilder for RecordingHttpClientSessionCallBuilder {
    fn build_call(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallRequest, BackendExecutionError> {
        let call_request = VerifierHttpClientSessionCallRequest {
            method: wire_request.method,
            url: wire_request.url.clone(),
            headers: wire_request.headers.clone(),
            body: wire_request.body.clone(),
            timeout_ms: wire_request.timeout_ms,
            profile: wire_request.profile.clone(),
            transport_mode: wire_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(call_request.clone());
        Ok(call_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionCallExecutor {
    requests: Mutex<Vec<VerifierHttpClientSessionCallRequest>>,
}

impl VerifierHttpClientSessionCallExecutor for RecordingHttpClientSessionCallExecutor {
    fn execute_call(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(call_request.clone());
        assert_eq!(call_request.profile, session_config.profile);
        assert_eq!(call_request.transport_mode, session_config.transport_mode);
        assert_eq!(call_request.timeout_ms, session_config.timeout_ms);
        Ok(VerifierHttpClientSessionCallResponse {
            status_code: 212,
            headers: BTreeMap::from([("x-call".to_string(), "ok".to_string())]),
            body: b"call-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionCallResponseParser {
    responses: Mutex<Vec<VerifierHttpClientSessionCallResponse>>,
}

impl VerifierHttpClientSessionCallResponseParser for RecordingHttpClientSessionCallResponseParser {
    fn parse_call_response(
        &self,
        call_response: VerifierHttpClientSessionCallResponse,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(call_response.clone());
        Ok(VerifierHttpClientSessionWireResponse {
            status_code: call_response.status_code,
            headers: call_response.headers,
            body: call_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionCallExecutor;

impl VerifierHttpClientSessionCallExecutor for RejectingHttpClientSessionCallExecutor {
    fn execute_call(
        &self,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session call executor rejected wire request".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionCallResponseParser;

impl VerifierHttpClientSessionCallResponseParser for PanicHttpClientSessionCallResponseParser {
    fn parse_call_response(
        &self,
        _call_response: VerifierHttpClientSessionCallResponse,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError> {
        panic!("call response parser should not be called when call executor fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionWireRequestBuilder {
    requests: Mutex<Vec<VerifierHttpClientSessionWireRequest>>,
}

impl VerifierHttpClientSessionWireRequestBuilder for RecordingHttpClientSessionWireRequestBuilder {
    fn build_wire_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireRequest, BackendExecutionError> {
        let wire_request = VerifierHttpClientSessionWireRequest {
            method: session_request.method,
            url: session_request.url.clone(),
            headers: session_request.headers.clone(),
            body: session_request.body.clone(),
            timeout_ms: session_config.timeout_ms,
            profile: session_config.profile.clone(),
            transport_mode: session_config.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(wire_request.clone());
        Ok(wire_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionWireExecutor {
    requests: Mutex<Vec<VerifierHttpClientSessionWireRequest>>,
}

impl VerifierHttpClientSessionWireExecutor for RecordingHttpClientSessionWireExecutor {
    fn execute_wire(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(wire_request.clone());
        assert_eq!(wire_request.profile, session_config.profile);
        assert_eq!(wire_request.transport_mode, session_config.transport_mode);
        assert_eq!(wire_request.timeout_ms, session_config.timeout_ms);
        Ok(VerifierHttpClientSessionWireResponse {
            status_code: 211,
            headers: BTreeMap::from([("x-wire".to_string(), "ok".to_string())]),
            body: b"wire-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionWireResponseParser {
    responses: Mutex<Vec<VerifierHttpClientSessionWireResponse>>,
}

impl VerifierHttpClientSessionWireResponseParser for RecordingHttpClientSessionWireResponseParser {
    fn parse_wire_response(
        &self,
        wire_response: VerifierHttpClientSessionWireResponse,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(wire_response.clone());
        Ok(VerifierHttpClientSessionResponse {
            status_code: wire_response.status_code,
            headers: wire_response.headers,
            body: wire_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionWireExecutor;

impl VerifierHttpClientSessionWireExecutor for RejectingHttpClientSessionWireExecutor {
    fn execute_wire(
        &self,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session wire executor rejected session".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionWireResponseParser;

impl VerifierHttpClientSessionWireResponseParser for PanicHttpClientSessionWireResponseParser {
    fn parse_wire_response(
        &self,
        _wire_response: VerifierHttpClientSessionWireResponse,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError> {
        panic!("wire response parser should not be called when wire executor fails")
    }
}
