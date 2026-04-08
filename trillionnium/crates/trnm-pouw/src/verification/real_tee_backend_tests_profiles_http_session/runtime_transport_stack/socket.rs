pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionSocketConnectionOpener {
    opened: Mutex<Vec<ResolvedVerifierHttpClientSessionSocketConnectionConfig>>,
    exchanges: Arc<
        Mutex<
            Vec<(
                ResolvedVerifierHttpClientSessionSocketConnectionConfig,
                VerifierHttpClientSessionSocketRequest,
            )>,
        >,
    >,
}

pub(super) struct RecordingHttpClientSessionSocketByteChannel {
    exchanges: Arc<
        Mutex<
            Vec<(
                ResolvedVerifierHttpClientSessionSocketConnectionConfig,
                VerifierHttpClientSessionSocketRequest,
            )>,
        >,
    >,
}

impl VerifierHttpClientSessionSocketConnectionOpener
    for RecordingHttpClientSessionSocketConnectionOpener
{
    fn open_connection(
        &self,
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
    ) -> Result<Box<dyn VerifierHttpClientSessionSocketByteChannel>, BackendExecutionError> {
        self.opened.lock().unwrap().push(connection_config.clone());
        Ok(Box::new(RecordingHttpClientSessionSocketByteChannel {
            exchanges: self.exchanges.clone(),
        }))
    }
}

impl VerifierHttpClientSessionSocketByteChannel for RecordingHttpClientSessionSocketByteChannel {
    fn exchange_bytes(
        &self,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
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
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        self.exchanges
            .lock()
            .unwrap()
            .push((connection_config.clone(), socket_request.clone()));
        Ok(VerifierHttpClientSessionSocketByteStreamResponse {
            status_code: 215,
            headers: BTreeMap::from([("x-channel".to_string(), "ok".to_string())]),
            body: b"channel-ok".to_vec(),
        })
    }
}

pub(super) struct RejectingHttpClientSessionSocketConnectionOpener;

impl VerifierHttpClientSessionSocketConnectionOpener
    for RejectingHttpClientSessionSocketConnectionOpener
{
    fn open_connection(
        &self,
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
    ) -> Result<Box<dyn VerifierHttpClientSessionSocketByteChannel>, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session socket connection opener rejected socket request".into(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionSocketRequestBuilder {
    requests: Mutex<Vec<VerifierHttpClientSessionSocketRequest>>,
}

impl VerifierHttpClientSessionSocketRequestBuilder
    for RecordingHttpClientSessionSocketRequestBuilder
{
    fn build_socket_request(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        _session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketRequest, BackendExecutionError> {
        let socket_request = VerifierHttpClientSessionSocketRequest {
            method: transport_request.method,
            url: transport_request.url.clone(),
            headers: transport_request.headers.clone(),
            body: transport_request.body.clone(),
            timeout_ms: transport_request.timeout_ms,
            profile: transport_request.profile.clone(),
            transport_mode: transport_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(socket_request.clone());
        Ok(socket_request)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionSocketAdapter {
    requests: Mutex<Vec<VerifierHttpClientSessionSocketRequest>>,
}

impl VerifierHttpClientSessionSocketAdapter for RecordingHttpClientSessionSocketAdapter {
    fn execute_socket(
        &self,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        _transport_request: &VerifierHttpClientSessionTransportRequest,
        _call_request: &VerifierHttpClientSessionCallRequest,
        _wire_request: &VerifierHttpClientSessionWireRequest,
        _session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        _runtime_request: &VerifierHttpClientRuntimeRequest,
        _config: &ResolvedVerifierHttpClientConfig,
        _client_request: &VerifierHttpClientRequest,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(socket_request.clone());
        assert_eq!(socket_request.profile, session_config.profile);
        assert_eq!(socket_request.transport_mode, session_config.transport_mode);
        assert_eq!(socket_request.timeout_ms, session_config.timeout_ms);
        Ok(VerifierHttpClientSessionSocketByteStreamResponse {
            status_code: 214,
            headers: BTreeMap::from([("x-socket".to_string(), "ok".to_string())]),
            body: b"socket-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionByteStreamResponseParser {
    responses: Mutex<Vec<VerifierHttpClientSessionSocketByteStreamResponse>>,
}

impl VerifierHttpClientSessionByteStreamResponseParser
    for RecordingHttpClientSessionByteStreamResponseParser
{
    fn parse_byte_stream(
        &self,
        socket_response: VerifierHttpClientSessionSocketByteStreamResponse,
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
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(socket_response.clone());
        Ok(VerifierHttpClientSessionTransportRawResponse {
            status_code: socket_response.status_code,
            headers: socket_response.headers,
            body: socket_response.body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionSocketAdapter;

impl VerifierHttpClientSessionSocketAdapter for RejectingHttpClientSessionSocketAdapter {
    fn execute_socket(
        &self,
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
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session socket adapter rejected transport request".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionByteStreamResponseParser;

impl VerifierHttpClientSessionByteStreamResponseParser
    for PanicHttpClientSessionByteStreamResponseParser
{
    fn parse_byte_stream(
        &self,
        _socket_response: VerifierHttpClientSessionSocketByteStreamResponse,
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
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError> {
        panic!("byte stream parser should not be called when socket adapter fails")
    }
}
