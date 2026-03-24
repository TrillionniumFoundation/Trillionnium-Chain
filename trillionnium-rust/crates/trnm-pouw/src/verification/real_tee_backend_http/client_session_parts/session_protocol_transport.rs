use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolEnvelopeNormalizer;

impl VerifierHttpClientSessionProtocolEnvelopeNormalizer
    for PassthroughVerifierHttpClientSessionProtocolEnvelopeNormalizer
{
    fn normalize_envelope(
        &self,
        framed_response: VerifierHttpClientSessionProtocolByteStreamFrameResponse,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolEnvelopeResponse, BackendExecutionError> {
        Ok(VerifierHttpClientSessionProtocolEnvelopeResponse {
            status_code: framed_response.status_code,
            headers: framed_response.headers,
            encoded_body: framed_response.encoded_body,
        })
    }
}

#[allow(dead_code)]
struct FramedBytesBackedVerifierHttpClientSessionProtocolBytesTransportExchange {
    byte_stream_framer: Arc<dyn VerifierHttpClientSessionProtocolByteStreamFramer>,
    byte_stream_exchange: Arc<dyn VerifierHttpClientSessionProtocolByteStreamExchange>,
    envelope_normalizer: Arc<dyn VerifierHttpClientSessionProtocolEnvelopeNormalizer>,
}

#[allow(dead_code)]
impl FramedBytesBackedVerifierHttpClientSessionProtocolBytesTransportExchange {
    fn new() -> Self {
        Self {
            byte_stream_framer: Arc::new(DirectVerifierHttpClientSessionProtocolByteStreamFramer),
            byte_stream_exchange: Arc::new(
                ChunkedByteStreamBackedVerifierHttpClientSessionProtocolByteStreamExchange::new(),
            ),
            envelope_normalizer: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolEnvelopeNormalizer,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        byte_stream_framer: Arc<dyn VerifierHttpClientSessionProtocolByteStreamFramer>,
        byte_stream_exchange: Arc<dyn VerifierHttpClientSessionProtocolByteStreamExchange>,
        envelope_normalizer: Arc<dyn VerifierHttpClientSessionProtocolEnvelopeNormalizer>,
    ) -> Self {
        Self {
            byte_stream_framer,
            byte_stream_exchange,
            envelope_normalizer,
        }
    }
}

impl VerifierHttpClientSessionProtocolBytesTransportExchange
    for FramedBytesBackedVerifierHttpClientSessionProtocolBytesTransportExchange
{
    fn exchange_bytes(
        &self,
        bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolEnvelopeResponse, BackendExecutionError> {
        let framed_request = self.byte_stream_framer.frame_bytes_request(
            bytes_request,
            protocol_request,
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
        let framed_response = self.byte_stream_exchange.exchange_framed_bytes(
            &framed_request,
            bytes_request,
            protocol_request,
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
        self.envelope_normalizer.normalize_envelope(
            framed_response,
            bytes_request,
            protocol_request,
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
struct PassthroughVerifierHttpClientSessionProtocolEnvelopeParser;

impl VerifierHttpClientSessionProtocolEnvelopeParser
    for PassthroughVerifierHttpClientSessionProtocolEnvelopeParser
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
        Ok(VerifierHttpClientSessionProtocolResponse {
            status_code: envelope_response.status_code,
            headers: envelope_response.headers,
            body: envelope_response.encoded_body,
        })
    }
}

#[allow(dead_code)]
struct BytesBackedVerifierHttpClientSessionProtocolTransportExchange {
    bytes_encoder: Arc<dyn VerifierHttpClientSessionProtocolBytesEncoder>,
    bytes_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolBytesTransportExchange>,
    envelope_parser: Arc<dyn VerifierHttpClientSessionProtocolEnvelopeParser>,
}

#[allow(dead_code)]
impl BytesBackedVerifierHttpClientSessionProtocolTransportExchange {
    fn new() -> Self {
        Self {
            bytes_encoder: Arc::new(DirectVerifierHttpClientSessionProtocolBytesEncoder),
            bytes_transport_exchange: Arc::new(
                FramedBytesBackedVerifierHttpClientSessionProtocolBytesTransportExchange::new(),
            ),
            envelope_parser: Arc::new(PassthroughVerifierHttpClientSessionProtocolEnvelopeParser),
        }
    }

    #[cfg(test)]
    fn with_components(
        bytes_encoder: Arc<dyn VerifierHttpClientSessionProtocolBytesEncoder>,
        bytes_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolBytesTransportExchange>,
        envelope_parser: Arc<dyn VerifierHttpClientSessionProtocolEnvelopeParser>,
    ) -> Self {
        Self {
            bytes_encoder,
            bytes_transport_exchange,
            envelope_parser,
        }
    }
}

impl VerifierHttpClientSessionProtocolTransportExchange
    for BytesBackedVerifierHttpClientSessionProtocolTransportExchange
{
    fn exchange_protocol(
        &self,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolResponse, BackendExecutionError> {
        let bytes_request = self.bytes_encoder.encode_bytes_request(
            protocol_request,
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
        let envelope_response = self.bytes_transport_exchange.exchange_bytes(
            &bytes_request,
            protocol_request,
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
        self.envelope_parser.parse_envelope_response(
            envelope_response,
            protocol_request,
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
