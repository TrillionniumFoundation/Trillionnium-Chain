use super::*;

#[allow(dead_code)]
struct FailClosedVerifierHttpClientSessionSocketConnectionOpener;

impl VerifierHttpClientSessionSocketConnectionOpener
    for FailClosedVerifierHttpClientSessionSocketConnectionOpener
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
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSessionSocketByteChannel>, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "real http client session socket connection opener for profile '{}' is not wired",
                http_request.profile
            ),
        })
    }
}

#[allow(dead_code)]
struct StaticVerifierHttpClientSessionSocketConnectionOpener;

impl VerifierHttpClientSessionSocketConnectionOpener
    for StaticVerifierHttpClientSessionSocketConnectionOpener
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<Box<dyn VerifierHttpClientSessionSocketByteChannel>, BackendExecutionError> {
        Ok(Box::new(
            FrameBackedVerifierHttpClientSessionSocketByteChannel::new(),
        ))
    }
}

#[allow(dead_code)]
struct ConnectionBackedVerifierHttpClientSessionSocketAdapter {
    connection_opener: Arc<dyn VerifierHttpClientSessionSocketConnectionOpener>,
}

#[allow(dead_code)]
impl ConnectionBackedVerifierHttpClientSessionSocketAdapter {
    fn new() -> Self {
        Self {
            connection_opener: Arc::new(StaticVerifierHttpClientSessionSocketConnectionOpener),
        }
    }

    #[cfg(test)]
    fn with_connection_opener(
        connection_opener: Arc<dyn VerifierHttpClientSessionSocketConnectionOpener>,
    ) -> Self {
        Self { connection_opener }
    }
}

impl VerifierHttpClientSessionSocketAdapter
    for ConnectionBackedVerifierHttpClientSessionSocketAdapter
{
    fn execute_socket(
        &self,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        let connection_config = ResolvedVerifierHttpClientSessionSocketConnectionConfig {
            profile: socket_request.profile.clone(),
            transport_mode: socket_request.transport_mode.clone(),
            timeout_ms: socket_request.timeout_ms,
        };
        let channel = self.connection_opener.open_connection(
            &connection_config,
            socket_request,
            transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        channel.exchange_bytes(
            &connection_config,
            socket_request,
            transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionByteStreamResponseParser;

impl VerifierHttpClientSessionByteStreamResponseParser
    for PassthroughVerifierHttpClientSessionByteStreamResponseParser
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
        Ok(VerifierHttpClientSessionTransportRawResponse {
            status_code: socket_response.status_code,
            headers: socket_response.headers,
            body: socket_response.body,
        })
    }
}

#[allow(dead_code)]
struct SocketBackedVerifierHttpClientSessionTransportAdapter {
    socket_request_builder: Arc<dyn VerifierHttpClientSessionSocketRequestBuilder>,
    socket_adapter: Arc<dyn VerifierHttpClientSessionSocketAdapter>,
    byte_stream_parser: Arc<dyn VerifierHttpClientSessionByteStreamResponseParser>,
}

#[allow(dead_code)]
impl SocketBackedVerifierHttpClientSessionTransportAdapter {
    fn new() -> Self {
        Self {
            socket_request_builder: Arc::new(DirectVerifierHttpClientSessionSocketRequestBuilder),
            socket_adapter: Arc::new(ConnectionBackedVerifierHttpClientSessionSocketAdapter::new()),
            byte_stream_parser: Arc::new(
                PassthroughVerifierHttpClientSessionByteStreamResponseParser,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        socket_request_builder: Arc<dyn VerifierHttpClientSessionSocketRequestBuilder>,
        socket_adapter: Arc<dyn VerifierHttpClientSessionSocketAdapter>,
        byte_stream_parser: Arc<dyn VerifierHttpClientSessionByteStreamResponseParser>,
    ) -> Self {
        Self {
            socket_request_builder,
            socket_adapter,
            byte_stream_parser,
        }
    }
}

impl VerifierHttpClientSessionTransportAdapter
    for SocketBackedVerifierHttpClientSessionTransportAdapter
{
    fn send_transport(
        &self,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionTransportRawResponse, BackendExecutionError> {
        let socket_request = self.socket_request_builder.build_socket_request(
            transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        let socket_response = self.socket_adapter.execute_socket(
            &socket_request,
            transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.byte_stream_parser.parse_byte_stream(
            socket_response,
            transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionRawIoResponseParser;

impl VerifierHttpClientSessionRawIoResponseParser
    for PassthroughVerifierHttpClientSessionRawIoResponseParser
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
        Ok(VerifierHttpClientSessionCallResponse {
            status_code: raw_response.status_code,
            headers: raw_response.headers,
            body: raw_response.body,
        })
    }
}

#[allow(dead_code)]
struct TransportBackedVerifierHttpClientSessionCallExecutor {
    transport_request_builder: Arc<dyn VerifierHttpClientSessionTransportRequestBuilder>,
    transport_adapter: Arc<dyn VerifierHttpClientSessionTransportAdapter>,
    raw_response_parser: Arc<dyn VerifierHttpClientSessionRawIoResponseParser>,
}

#[allow(dead_code)]
impl TransportBackedVerifierHttpClientSessionCallExecutor {
    fn new() -> Self {
        Self {
            transport_request_builder: Arc::new(
                DirectVerifierHttpClientSessionTransportRequestBuilder,
            ),
            transport_adapter: Arc::new(
                SocketBackedVerifierHttpClientSessionTransportAdapter::new(),
            ),
            raw_response_parser: Arc::new(PassthroughVerifierHttpClientSessionRawIoResponseParser),
        }
    }

    #[cfg(test)]
    fn with_components(
        transport_request_builder: Arc<dyn VerifierHttpClientSessionTransportRequestBuilder>,
        transport_adapter: Arc<dyn VerifierHttpClientSessionTransportAdapter>,
        raw_response_parser: Arc<dyn VerifierHttpClientSessionRawIoResponseParser>,
    ) -> Self {
        Self {
            transport_request_builder,
            transport_adapter,
            raw_response_parser,
        }
    }
}

impl VerifierHttpClientSessionCallExecutor
    for TransportBackedVerifierHttpClientSessionCallExecutor
{
    fn execute_call(
        &self,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionCallResponse, BackendExecutionError> {
        let transport_request = self.transport_request_builder.build_transport_request(
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        let raw_response = self.transport_adapter.send_transport(
            &transport_request,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.raw_response_parser.parse_raw_response(
            raw_response,
            call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionCallResponseParser;

impl VerifierHttpClientSessionCallResponseParser
    for PassthroughVerifierHttpClientSessionCallResponseParser
{
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
        Ok(VerifierHttpClientSessionWireResponse {
            status_code: call_response.status_code,
            headers: call_response.headers,
            body: call_response.body,
        })
    }
}

#[allow(dead_code)]
struct CallBackedVerifierHttpClientSessionWireExecutor {
    call_builder: Arc<dyn VerifierHttpClientSessionCallBuilder>,
    call_executor: Arc<dyn VerifierHttpClientSessionCallExecutor>,
    response_parser: Arc<dyn VerifierHttpClientSessionCallResponseParser>,
}

#[allow(dead_code)]
impl CallBackedVerifierHttpClientSessionWireExecutor {
    fn new() -> Self {
        Self {
            call_builder: Arc::new(DirectVerifierHttpClientSessionCallBuilder),
            call_executor: Arc::new(TransportBackedVerifierHttpClientSessionCallExecutor::new()),
            response_parser: Arc::new(PassthroughVerifierHttpClientSessionCallResponseParser),
        }
    }

    #[cfg(test)]
    fn with_components(
        call_builder: Arc<dyn VerifierHttpClientSessionCallBuilder>,
        call_executor: Arc<dyn VerifierHttpClientSessionCallExecutor>,
        response_parser: Arc<dyn VerifierHttpClientSessionCallResponseParser>,
    ) -> Self {
        Self {
            call_builder,
            call_executor,
            response_parser,
        }
    }
}

impl VerifierHttpClientSessionWireExecutor for CallBackedVerifierHttpClientSessionWireExecutor {
    fn execute_wire(
        &self,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionWireResponse, BackendExecutionError> {
        let call_request = self.call_builder.build_call(
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        let call_response = self.call_executor.execute_call(
            &call_request,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.response_parser.parse_call_response(
            call_response,
            wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionWireResponseParser;

impl VerifierHttpClientSessionWireResponseParser
    for PassthroughVerifierHttpClientSessionWireResponseParser
{
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
        Ok(VerifierHttpClientSessionResponse {
            status_code: wire_response.status_code,
            headers: wire_response.headers,
            body: wire_response.body,
        })
    }
}

#[allow(dead_code)]
pub(super) struct WireBackedVerifierHttpClientSessionRequestExecutor {
    request_builder: Arc<dyn VerifierHttpClientSessionWireRequestBuilder>,
    wire_executor: Arc<dyn VerifierHttpClientSessionWireExecutor>,
    response_parser: Arc<dyn VerifierHttpClientSessionWireResponseParser>,
}

#[allow(dead_code)]
impl WireBackedVerifierHttpClientSessionRequestExecutor {
    pub(super) fn new() -> Self {
        Self {
            request_builder: Arc::new(DirectVerifierHttpClientSessionWireRequestBuilder),
            wire_executor: Arc::new(CallBackedVerifierHttpClientSessionWireExecutor::new()),
            response_parser: Arc::new(PassthroughVerifierHttpClientSessionWireResponseParser),
        }
    }

    #[cfg(test)]
    fn with_components(
        request_builder: Arc<dyn VerifierHttpClientSessionWireRequestBuilder>,
        wire_executor: Arc<dyn VerifierHttpClientSessionWireExecutor>,
        response_parser: Arc<dyn VerifierHttpClientSessionWireResponseParser>,
    ) -> Self {
        Self {
            request_builder,
            wire_executor,
            response_parser,
        }
    }
}

impl VerifierHttpClientSessionRequestExecutor
    for WireBackedVerifierHttpClientSessionRequestExecutor
{
    fn execute_request(
        &self,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionResponse, BackendExecutionError> {
        let wire_request = self.request_builder.build_wire_request(
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        let wire_response = self.wire_executor.execute_wire(
            &wire_request,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )?;
        self.response_parser.parse_wire_response(
            wire_response,
            session_request,
            session_config,
            runtime_request,
            config,
            client_request,
            http_request,
            request,
        )
    }
}
