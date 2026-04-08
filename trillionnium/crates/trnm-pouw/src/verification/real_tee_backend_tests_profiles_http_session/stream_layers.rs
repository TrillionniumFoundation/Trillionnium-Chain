pub(super) use super::*;


impl VerifierHttpClientSessionProtocolByteStreamFramer
    for RecordingHttpClientSessionProtocolByteStreamFramer
{
    fn frame_bytes_request(
        &self,
        bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteStreamFrameRequest, BackendExecutionError>
    {
        let framed = VerifierHttpClientSessionProtocolByteStreamFrameRequest {
            method: bytes_request.method,
            url: bytes_request.url.clone(),
            headers: bytes_request.headers.clone(),
            encoded_body: bytes_request.encoded_body.clone(),
            timeout_ms: bytes_request.timeout_ms,
            profile: bytes_request.profile.clone(),
            transport_mode: bytes_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(framed.clone());
        Ok(framed)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolByteStreamExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolByteStreamFrameRequest>>,
}

impl VerifierHttpClientSessionProtocolByteStreamExchange
    for RecordingHttpClientSessionProtocolByteStreamExchange
{
    fn exchange_framed_bytes(
        &self,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
        _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteStreamFrameResponse, BackendExecutionError>
    {
        self.requests.lock().unwrap().push(framed_request.clone());
        assert_eq!(framed_request.profile, connection_config.profile);
        assert_eq!(
            framed_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(framed_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolByteStreamFrameResponse {
            status_code: 219,
            headers: BTreeMap::from([("x-proto-frame".to_string(), "ok".to_string())]),
            encoded_body: b"proto-frame-ok".to_vec(),
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolEnvelopeNormalizer {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolByteStreamFrameResponse>>,
}

impl VerifierHttpClientSessionProtocolEnvelopeNormalizer
    for RecordingHttpClientSessionProtocolEnvelopeNormalizer
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
        self.responses.lock().unwrap().push(framed_response.clone());
        Ok(VerifierHttpClientSessionProtocolEnvelopeResponse {
            status_code: framed_response.status_code,
            headers: framed_response.headers,
            encoded_body: framed_response.encoded_body,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolByteStreamExchange;

impl VerifierHttpClientSessionProtocolByteStreamExchange
    for RejectingHttpClientSessionProtocolByteStreamExchange
{
    fn exchange_framed_bytes(
        &self,
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
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolByteStreamFrameResponse, BackendExecutionError>
    {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol byte stream exchange rejected framed bytes".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolEnvelopeNormalizer;

impl VerifierHttpClientSessionProtocolEnvelopeNormalizer
    for PanicHttpClientSessionProtocolEnvelopeNormalizer
{
    fn normalize_envelope(
        &self,
        _framed_response: VerifierHttpClientSessionProtocolByteStreamFrameResponse,
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
        panic!("protocol envelope normalizer should not be called when byte stream exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolByteStreamChunker {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolByteChunksRequest>>,
}

impl VerifierHttpClientSessionProtocolByteStreamChunker
    for RecordingHttpClientSessionProtocolByteStreamChunker
{
    fn chunk_request(
        &self,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteChunksRequest, BackendExecutionError> {
        let chunked = VerifierHttpClientSessionProtocolByteChunksRequest {
            method: framed_request.method,
            url: framed_request.url.clone(),
            headers: framed_request.headers.clone(),
            chunks: vec![framed_request.encoded_body.clone()],
            timeout_ms: framed_request.timeout_ms,
            profile: framed_request.profile.clone(),
            transport_mode: framed_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(chunked.clone());
        Ok(chunked)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTransportExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolByteChunksRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTransportExchange
    for RecordingHttpClientSessionProtocolChunkTransportExchange
{
    fn exchange_chunks(
        &self,
        chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
        _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolByteChunksResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(chunked_request.clone());
        assert_eq!(chunked_request.profile, connection_config.profile);
        assert_eq!(
            chunked_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(chunked_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolByteChunksResponse {
            status_code: 220,
            headers: BTreeMap::from([("x-chunks".to_string(), "ok".to_string())]),
            chunks: vec![b"chunked-".to_vec(), b"stream-ok".to_vec()],
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolByteStreamAssembler {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolByteChunksResponse>>,
}

impl VerifierHttpClientSessionProtocolByteStreamAssembler
    for RecordingHttpClientSessionProtocolByteStreamAssembler
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
        self.responses
            .lock()
            .unwrap()
            .push(chunked_response.clone());
        Ok(VerifierHttpClientSessionProtocolByteStreamFrameResponse {
            status_code: chunked_response.status_code,
            headers: chunked_response.headers,
            encoded_body: chunked_response.chunks.into_iter().flatten().collect(),
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkTransportExchange;

impl VerifierHttpClientSessionProtocolChunkTransportExchange
    for RejectingHttpClientSessionProtocolChunkTransportExchange
{
    fn exchange_chunks(
        &self,
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
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolByteChunksResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk transport exchange rejected chunked request"
                .into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolByteStreamAssembler;

impl VerifierHttpClientSessionProtocolByteStreamAssembler
    for PanicHttpClientSessionProtocolByteStreamAssembler
{
    fn assemble_response(
        &self,
        _chunked_response: VerifierHttpClientSessionProtocolByteChunksResponse,
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
        panic!("byte stream assembler should not be called when chunk transport exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkFramingPolicy {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkFramesRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkFramingPolicy
    for RecordingHttpClientSessionProtocolChunkFramingPolicy
{
    fn frame_chunks(
        &self,
        chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesRequest, BackendExecutionError> {
        let framed = VerifierHttpClientSessionProtocolChunkFramesRequest {
            method: chunked_request.method,
            url: chunked_request.url.clone(),
            headers: chunked_request.headers.clone(),
            frames: chunked_request.chunks.clone(),
            timeout_ms: chunked_request.timeout_ms,
            profile: chunked_request.profile.clone(),
            transport_mode: chunked_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(framed.clone());
        Ok(framed)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkFrameExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkFramesRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkFrameExchange
    for RecordingHttpClientSessionProtocolChunkFrameExchange
{
    fn exchange_chunk_frames(
        &self,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
        _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
        _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(frames_request.clone());
        assert_eq!(frames_request.profile, connection_config.profile);
        assert_eq!(
            frames_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(frames_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolChunkFramesResponse {
            status_code: 221,
            headers: BTreeMap::from([("x-frame-policy".to_string(), "ok".to_string())]),
            frames: vec![b"validated-".to_vec(), b"frames-ok".to_vec()],
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolStreamReassemblyValidator {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkFramesResponse>>,
}

impl VerifierHttpClientSessionProtocolStreamReassemblyValidator
    for RecordingHttpClientSessionProtocolStreamReassemblyValidator
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
        self.responses.lock().unwrap().push(frames_response.clone());
        Ok(VerifierHttpClientSessionProtocolByteChunksResponse {
            status_code: frames_response.status_code,
            headers: frames_response.headers,
            chunks: frames_response.frames,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkFrameExchange;

impl VerifierHttpClientSessionProtocolChunkFrameExchange
    for RejectingHttpClientSessionProtocolChunkFrameExchange
{
    fn exchange_chunk_frames(
        &self,
        _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk frame exchange rejected framed chunks".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolStreamReassemblyValidator;

impl VerifierHttpClientSessionProtocolStreamReassemblyValidator
    for PanicHttpClientSessionProtocolStreamReassemblyValidator
{
    fn validate_and_reassemble(
        &self,
        _frames_response: VerifierHttpClientSessionProtocolChunkFramesResponse,
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
        panic!("stream reassembly validator should not be called when chunk frame exchange fails")
    }
}

