use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolStreamReassemblyValidator;

impl VerifierHttpClientSessionProtocolStreamReassemblyValidator
    for PassthroughVerifierHttpClientSessionProtocolStreamReassemblyValidator
{
    fn validate_and_reassemble(
        &self,
        frames_response: VerifierHttpClientSessionProtocolChunkFramesResponse,
        _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteChunksResponse, BackendExecutionError> {
        Ok(VerifierHttpClientSessionProtocolByteChunksResponse {
            status_code: frames_response.status_code,
            headers: frames_response.headers,
            chunks: frames_response.frames,
        })
    }
}

#[allow(dead_code)]
struct FramedChunkBackedVerifierHttpClientSessionProtocolChunkTransportExchange {
    framing_policy: Arc<dyn VerifierHttpClientSessionProtocolChunkFramingPolicy>,
    chunk_frame_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkFrameExchange>,
    reassembly_validator: Arc<dyn VerifierHttpClientSessionProtocolStreamReassemblyValidator>,
}

#[allow(dead_code)]
impl FramedChunkBackedVerifierHttpClientSessionProtocolChunkTransportExchange {
    fn new() -> Self {
        Self {
            framing_policy: Arc::new(DirectVerifierHttpClientSessionProtocolChunkFramingPolicy),
            chunk_frame_exchange: Arc::new(
                WindowedChunkBackedVerifierHttpClientSessionProtocolChunkFrameExchange::new(),
            ),
            reassembly_validator: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolStreamReassemblyValidator,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        framing_policy: Arc<dyn VerifierHttpClientSessionProtocolChunkFramingPolicy>,
        chunk_frame_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkFrameExchange>,
        reassembly_validator: Arc<dyn VerifierHttpClientSessionProtocolStreamReassemblyValidator>,
    ) -> Self {
        Self {
            framing_policy,
            chunk_frame_exchange,
            reassembly_validator,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTransportExchange
    for FramedChunkBackedVerifierHttpClientSessionProtocolChunkTransportExchange
{
    fn exchange_chunks(
        &self,
        chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteChunksResponse, BackendExecutionError> {
        let frames_request = self.framing_policy.frame_chunks(
            chunked_request,
            framed_request,
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
        let frames_response = self.chunk_frame_exchange.exchange_chunk_frames(
            &frames_request,
            chunked_request,
            framed_request,
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
        self.reassembly_validator.validate_and_reassemble(
            frames_response,
            chunked_request,
            framed_request,
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
struct PassthroughVerifierHttpClientSessionProtocolByteStreamAssembler;

impl VerifierHttpClientSessionProtocolByteStreamAssembler
    for PassthroughVerifierHttpClientSessionProtocolByteStreamAssembler
{
    fn assemble_response(
        &self,
        chunked_response: VerifierHttpClientSessionProtocolByteChunksResponse,
        _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteStreamFrameResponse, BackendExecutionError>
    {
        Ok(VerifierHttpClientSessionProtocolByteStreamFrameResponse {
            status_code: chunked_response.status_code,
            headers: chunked_response.headers,
            encoded_body: chunked_response.chunks.into_iter().flatten().collect(),
        })
    }
}

#[allow(dead_code)]
struct ChunkedByteStreamBackedVerifierHttpClientSessionProtocolByteStreamExchange {
    chunker: Arc<dyn VerifierHttpClientSessionProtocolByteStreamChunker>,
    chunk_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkTransportExchange>,
    assembler: Arc<dyn VerifierHttpClientSessionProtocolByteStreamAssembler>,
}

#[allow(dead_code)]
impl ChunkedByteStreamBackedVerifierHttpClientSessionProtocolByteStreamExchange {
    fn new() -> Self {
        Self {
            chunker: Arc::new(DirectVerifierHttpClientSessionProtocolByteStreamChunker),
            chunk_transport_exchange: Arc::new(
                FramedChunkBackedVerifierHttpClientSessionProtocolChunkTransportExchange::new(),
            ),
            assembler: Arc::new(PassthroughVerifierHttpClientSessionProtocolByteStreamAssembler),
        }
    }

    #[cfg(test)]
    fn with_components(
        chunker: Arc<dyn VerifierHttpClientSessionProtocolByteStreamChunker>,
        chunk_transport_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkTransportExchange>,
        assembler: Arc<dyn VerifierHttpClientSessionProtocolByteStreamAssembler>,
    ) -> Self {
        Self {
            chunker,
            chunk_transport_exchange,
            assembler,
        }
    }
}

impl VerifierHttpClientSessionProtocolByteStreamExchange
    for ChunkedByteStreamBackedVerifierHttpClientSessionProtocolByteStreamExchange
{
    fn exchange_framed_bytes(
        &self,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteStreamFrameResponse, BackendExecutionError>
    {
        let chunked_request = self.chunker.chunk_request(
            framed_request,
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
        let chunked_response = self.chunk_transport_exchange.exchange_chunks(
            &chunked_request,
            framed_request,
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
        self.assembler.assemble_response(
            chunked_response,
            framed_request,
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
