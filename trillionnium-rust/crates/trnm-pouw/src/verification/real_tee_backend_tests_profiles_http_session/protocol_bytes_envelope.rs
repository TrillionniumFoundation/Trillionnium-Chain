pub(super) use super::*;


impl VerifierHttpClientSessionProtocolBytesEncoder
    for RecordingHttpClientSessionProtocolBytesEncoder
{
    fn encode_bytes_request(
        &self,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolBytesRequest, BackendExecutionError> {
        let bytes_request = VerifierHttpClientSessionProtocolBytesRequest {
            method: protocol_request.method,
            url: protocol_request.url.clone(),
            headers: protocol_request.headers.clone(),
            encoded_body: protocol_request.body.clone(),
            timeout_ms: protocol_request.timeout_ms,
            profile: protocol_request.profile.clone(),
            transport_mode: protocol_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(bytes_request.clone());
        Ok(bytes_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolBytesTransportExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolBytesRequest>>,
}

impl VerifierHttpClientSessionProtocolBytesTransportExchange
    for RecordingHttpClientSessionProtocolBytesTransportExchange
{
    fn exchange_bytes(
        &self,
        bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
        _protocol_request: &VerifierHttpClientSessionProtocolRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolEnvelopeResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(bytes_request.clone());
        assert_eq!(bytes_request.profile, connection_config.profile);
        assert_eq!(
            bytes_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(bytes_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolEnvelopeResponse {
            status_code: 218,
            headers: BTreeMap::from([("x-envelope".to_string(), "ok".to_string())]),
            encoded_body: b"envelope-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolEnvelopeParser {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolEnvelopeResponse>>,
}

impl VerifierHttpClientSessionProtocolEnvelopeParser
    for RecordingHttpClientSessionProtocolEnvelopeParser
{
    fn parse_envelope_response(
        &self,
        envelope_response: VerifierHttpClientSessionProtocolEnvelopeResponse,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolResponse, BackendExecutionError> {
        self.responses
            .lock()
            .unwrap()
            .push(envelope_response.clone());
        Ok(VerifierHttpClientSessionProtocolResponse {
            status_code: envelope_response.status_code,
            headers: envelope_response.headers,
            body: envelope_response.encoded_body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolBytesTransportExchange;

impl VerifierHttpClientSessionProtocolBytesTransportExchange
    for RejectingHttpClientSessionProtocolBytesTransportExchange
{
    fn exchange_bytes(
        &self,
        _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolEnvelopeResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol bytes transport exchange rejected protocol bytes"
                .into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolEnvelopeParser;

impl VerifierHttpClientSessionProtocolEnvelopeParser
    for PanicHttpClientSessionProtocolEnvelopeParser
{
    fn parse_envelope_response(
        &self,
        _envelope_response: VerifierHttpClientSessionProtocolEnvelopeResponse,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolResponse, BackendExecutionError> {
        panic!("protocol envelope parser should not be called when bytes transport exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolByteStreamFramer {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolByteStreamFrameRequest>>,
}
