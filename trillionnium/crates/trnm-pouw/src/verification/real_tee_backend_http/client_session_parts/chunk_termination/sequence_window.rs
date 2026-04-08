use super::*;

pub(super) struct VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    frames: Vec<Vec<u8>>,
    window_start_sequence: u64,
    window_frame_count: usize,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionProtocolChunkSequenceWindowResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    frames: Vec<Vec<u8>>,
    window_start_sequence: u64,
    window_frame_count: usize,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkSequenceWindowPlanner: Send + Sync {
    fn plan_sequence_window(
        &self,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkSequenceWindowExchange: Send + Sync {
    fn exchange_sequence_window(
        &self,
        window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkIntegrityValidator: Send + Sync {
    fn validate_chunk_integrity(
        &self,
        window_response: VerifierHttpClientSessionProtocolChunkSequenceWindowResponse,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionProtocolChunkSequenceWindowPlanner;

impl VerifierHttpClientSessionProtocolChunkSequenceWindowPlanner
    for DirectVerifierHttpClientSessionProtocolChunkSequenceWindowPlanner
{
    fn plan_sequence_window(
        &self,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, BackendExecutionError>
    {
        Ok(
            VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: frames_request.method,
                url: frames_request.url.clone(),
                headers: frames_request.headers.clone(),
                frames: frames_request.frames.clone(),
                window_start_sequence: 0,
                window_frame_count: frames_request.frames.len(),
                timeout_ms: frames_request.timeout_ms,
                profile: frames_request.profile.clone(),
                transport_mode: frames_request.transport_mode.clone(),
            },
        )
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
