use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolResponseCodec;

impl VerifierHttpClientSessionProtocolResponseCodec
    for PassthroughVerifierHttpClientSessionProtocolResponseCodec
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
        Ok(VerifierHttpClientSessionFrameResponse {
            status_code: protocol_response.status_code,
            headers: protocol_response.headers,
            body: protocol_response.body,
        })
    }
}

#[allow(dead_code)]
struct CodecBackedVerifierHttpClientSessionFrameIoAdapter {
    protocol_request_codec: Arc<dyn VerifierHttpClientSessionProtocolRequestCodec>,
    protocol_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolTransportExchange>,
    protocol_response_codec: Arc<dyn VerifierHttpClientSessionProtocolResponseCodec>,
}

#[allow(dead_code)]
impl CodecBackedVerifierHttpClientSessionFrameIoAdapter {
    fn new() -> Self {
        Self {
            protocol_request_codec: Arc::new(DirectVerifierHttpClientSessionProtocolRequestCodec),
            protocol_transport_exchange: Arc::new(
                BytesBackedVerifierHttpClientSessionProtocolTransportExchange::new(),
            ),
            protocol_response_codec: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolResponseCodec,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        protocol_request_codec: Arc<dyn VerifierHttpClientSessionProtocolRequestCodec>,
        protocol_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolTransportExchange>,
        protocol_response_codec: Arc<dyn VerifierHttpClientSessionProtocolResponseCodec>,
    ) -> Self {
        Self {
            protocol_request_codec,
            protocol_transport_exchange,
            protocol_response_codec,
        }
    }
}

impl VerifierHttpClientSessionFrameIoAdapter
    for CodecBackedVerifierHttpClientSessionFrameIoAdapter
{
    fn exchange_frame(
        &self,
        frame_request: &VerifierHttpClientSessionFrameRequest,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
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
    ) -> Result<VerifierHttpClientSessionFrameResponse, BackendExecutionError> {
        let protocol_request = self.protocol_request_codec.encode_protocol_request(
            frame_request,
            connection_config,
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
        let protocol_response = self.protocol_transport_exchange.exchange_protocol(
            &protocol_request,
            frame_request,
            connection_config,
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
        self.protocol_response_codec.decode_protocol_response(
            protocol_response,
            frame_request,
            connection_config,
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
struct PassthroughVerifierHttpClientSessionFrameDecoder;

impl VerifierHttpClientSessionFrameDecoder for PassthroughVerifierHttpClientSessionFrameDecoder {
    fn decode_frame(
        &self,
        frame_response: VerifierHttpClientSessionFrameResponse,
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
    ) -> Result<VerifierHttpClientSessionSocketByteStreamResponse, BackendExecutionError> {
        Ok(VerifierHttpClientSessionSocketByteStreamResponse {
            status_code: frame_response.status_code,
            headers: frame_response.headers,
            body: frame_response.body,
        })
    }
}

#[allow(dead_code)]
pub(super) struct FrameBackedVerifierHttpClientSessionSocketByteChannel {
    frame_encoder: Arc<dyn VerifierHttpClientSessionFrameEncoder>,
    frame_io_adapter: Arc<dyn VerifierHttpClientSessionFrameIoAdapter>,
    frame_decoder: Arc<dyn VerifierHttpClientSessionFrameDecoder>,
}

#[allow(dead_code)]
impl FrameBackedVerifierHttpClientSessionSocketByteChannel {
    pub(super) fn new() -> Self {
        Self {
            frame_encoder: Arc::new(DirectVerifierHttpClientSessionFrameEncoder),
            frame_io_adapter: Arc::new(CodecBackedVerifierHttpClientSessionFrameIoAdapter::new()),
            frame_decoder: Arc::new(PassthroughVerifierHttpClientSessionFrameDecoder),
        }
    }

    #[cfg(test)]
    fn with_components(
        frame_encoder: Arc<dyn VerifierHttpClientSessionFrameEncoder>,
        frame_io_adapter: Arc<dyn VerifierHttpClientSessionFrameIoAdapter>,
        frame_decoder: Arc<dyn VerifierHttpClientSessionFrameDecoder>,
    ) -> Self {
        Self {
            frame_encoder,
            frame_io_adapter,
            frame_decoder,
        }
    }
}

impl VerifierHttpClientSessionSocketByteChannel
    for FrameBackedVerifierHttpClientSessionSocketByteChannel
{
    fn exchange_bytes(
        &self,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
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
        let frame_request = self.frame_encoder.encode_frame(
            connection_config,
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
        let frame_response = self.frame_io_adapter.exchange_frame(
            &frame_request,
            connection_config,
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
        self.frame_decoder.decode_frame(
            frame_response,
            connection_config,
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
