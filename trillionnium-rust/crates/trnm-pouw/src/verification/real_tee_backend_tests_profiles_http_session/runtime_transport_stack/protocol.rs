pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolRequestCodec {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolRequest>>,
}

impl VerifierHttpClientSessionProtocolRequestCodec
    for RecordingHttpClientSessionProtocolRequestCodec
{
    fn encode_protocol_request(
        &self,
        frame_request: &VerifierHttpClientSessionFrameRequest,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolRequest, BackendExecutionError> {
        let protocol_request = VerifierHttpClientSessionProtocolRequest {
            method: frame_request.method,
            url: frame_request.url.clone(),
            headers: frame_request.headers.clone(),
            body: frame_request.body.clone(),
            timeout_ms: frame_request.timeout_ms,
            profile: frame_request.profile.clone(),
            transport_mode: frame_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(protocol_request.clone());
        Ok(protocol_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolTransportExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolRequest>>,
}

impl VerifierHttpClientSessionProtocolTransportExchange
    for RecordingHttpClientSessionProtocolTransportExchange
{
    fn exchange_protocol(
        &self,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
        _frame_request: &VerifierHttpClientSessionFrameRequest,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(protocol_request.clone());
        assert_eq!(protocol_request.profile, connection_config.profile);
        assert_eq!(
            protocol_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(protocol_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolResponse {
            status_code: 217,
            headers: BTreeMap::from([("x-protocol".to_string(), "ok".to_string())]),
            body: b"protocol-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolResponseCodec {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolResponse>>,
}

impl VerifierHttpClientSessionProtocolResponseCodec
    for RecordingHttpClientSessionProtocolResponseCodec
{
    fn decode_protocol_response(
        &self,
        protocol_response: VerifierHttpClientSessionProtocolResponse,
        _frame_request: &VerifierHttpClientSessionFrameRequest,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionFrameResponse, BackendExecutionError> {
        self.responses
            .lock()
            .unwrap()
            .push(protocol_response.clone());
        Ok(VerifierHttpClientSessionFrameResponse {
            status_code: protocol_response.status_code,
            headers: protocol_response.headers,
            body: protocol_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolTransportExchange;

impl VerifierHttpClientSessionProtocolTransportExchange
    for RejectingHttpClientSessionProtocolTransportExchange
{
    fn exchange_protocol(
        &self,
        _protocol_request: &VerifierHttpClientSessionProtocolRequest,
        _frame_request: &VerifierHttpClientSessionFrameRequest,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol transport exchange rejected frame request".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolResponseCodec;

impl VerifierHttpClientSessionProtocolResponseCodec
    for PanicHttpClientSessionProtocolResponseCodec
{
    fn decode_protocol_response(
        &self,
        _protocol_response: VerifierHttpClientSessionProtocolResponse,
        _frame_request: &VerifierHttpClientSessionFrameRequest,
        _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        _socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionFrameResponse, BackendExecutionError> {
        panic!("protocol response codec should not be called when transport exchange fails")
    }
}
