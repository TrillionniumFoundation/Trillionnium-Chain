pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkSequenceWindowPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkSequenceWindowRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkSequenceWindowPlanner
    for RecordingHttpClientSessionProtocolChunkSequenceWindowPlanner
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
        let windowed = VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
            method: frames_request.method,
            url: frames_request.url.clone(),
            headers: frames_request.headers.clone(),
            frames: frames_request.frames.clone(),
            window_start_sequence: 41,
            window_frame_count: frames_request.frames.len(),
            timeout_ms: frames_request.timeout_ms,
            profile: frames_request.profile.clone(),
            transport_mode: frames_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(windowed.clone());
        Ok(windowed)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkSequenceWindowExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkSequenceWindowRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkSequenceWindowExchange
    for RecordingHttpClientSessionProtocolChunkSequenceWindowExchange
{
    fn exchange_sequence_window(
        &self,
        window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        self.requests.lock().unwrap().push(window_request.clone());
        assert_eq!(window_request.profile, connection_config.profile);
        assert_eq!(
            window_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(window_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkSequenceWindowResponse {
                status_code: 222,
                headers: BTreeMap::from([("x-window".to_string(), "ok".to_string())]),
                frames: vec![b"windowed-".to_vec(), b"frames-ok".to_vec()],
                window_start_sequence: window_request.window_start_sequence,
                window_frame_count: window_request.window_frame_count,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkIntegrityValidator {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkIntegrityValidator
    for RecordingHttpClientSessionProtocolChunkIntegrityValidator
{
    fn validate_chunk_integrity(
        &self,
        window_response: VerifierHttpClientSessionProtocolChunkSequenceWindowResponse,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(window_response.clone());
        Ok(VerifierHttpClientSessionProtocolChunkFramesResponse {
            status_code: window_response.status_code,
            headers: window_response.headers,
            frames: window_response.frames,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkSequenceWindowExchange;

impl VerifierHttpClientSessionProtocolChunkSequenceWindowExchange
    for RejectingHttpClientSessionProtocolChunkSequenceWindowExchange
{
    fn exchange_sequence_window(
        &self,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason:
                "client session protocol chunk sequence window exchange rejected windowed frames"
                    .into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkIntegrityValidator;

impl VerifierHttpClientSessionProtocolChunkIntegrityValidator
    for PanicHttpClientSessionProtocolChunkIntegrityValidator
{
    fn validate_chunk_integrity(
        &self,
        _window_response: VerifierHttpClientSessionProtocolChunkSequenceWindowResponse,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        panic!("chunk integrity validator should not be called when sequence window exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkAckPolicy {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkAckPolicy
    for RecordingHttpClientSessionProtocolChunkAckPolicy
{
    fn plan_ack_request(
        &self,
        window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckRequest, BackendExecutionError> {
        let ack = VerifierHttpClientSessionProtocolChunkAckRequest {
            method: window_request.method,
            url: window_request.url.clone(),
            headers: window_request.headers.clone(),
            frames: window_request.frames.clone(),
            window_start_sequence: window_request.window_start_sequence,
            window_frame_count: window_request.window_frame_count,
            expected_ack_sequence: 52,
            retransmit_budget: 1,
            timeout_ms: window_request.timeout_ms,
            profile: window_request.profile.clone(),
            transport_mode: window_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(ack.clone());
        Ok(ack)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkRetransmitExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkRetransmitExchange
    for RecordingHttpClientSessionProtocolChunkRetransmitExchange
{
    fn exchange_retransmit(
        &self,
        ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(ack_request.clone());
        assert_eq!(ack_request.profile, connection_config.profile);
        assert_eq!(ack_request.transport_mode, connection_config.transport_mode);
        assert_eq!(ack_request.timeout_ms, connection_config.timeout_ms);
        Ok(VerifierHttpClientSessionProtocolChunkAckResponse {
            status_code: 223,
            headers: BTreeMap::from([("x-ack".to_string(), "ok".to_string())]),
            frames: vec![b"acked-".to_vec(), b"frames-ok".to_vec()],
            window_start_sequence: ack_request.window_start_sequence,
            window_frame_count: ack_request.window_frame_count,
            acked_through_sequence: ack_request.expected_ack_sequence,
            retransmit_count: 0,
        })
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkAckValidator {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkAckValidator
    for RecordingHttpClientSessionProtocolChunkAckValidator
{
    fn validate_ack_response(
        &self,
        ack_response: VerifierHttpClientSessionProtocolChunkAckResponse,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        self.responses.lock().unwrap().push(ack_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkSequenceWindowResponse {
                status_code: ack_response.status_code,
                headers: ack_response.headers,
                frames: ack_response.frames,
                window_start_sequence: ack_response.window_start_sequence,
                window_frame_count: ack_response.window_frame_count,
            },
        )
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkRetransmitExchange;

impl VerifierHttpClientSessionProtocolChunkRetransmitExchange
    for RejectingHttpClientSessionProtocolChunkRetransmitExchange
{
    fn exchange_retransmit(
        &self,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk retransmit exchange rejected acked window"
                .into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkAckValidator;

impl VerifierHttpClientSessionProtocolChunkAckValidator
    for PanicHttpClientSessionProtocolChunkAckValidator
{
    fn validate_ack_response(
        &self,
        _ack_response: VerifierHttpClientSessionProtocolChunkAckResponse,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        panic!("chunk ack validator should not be called when retransmit exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkRetransmitBudgetPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkRetransmitBudgetPlanner
    for RecordingHttpClientSessionProtocolChunkRetransmitBudgetPlanner
{
    fn plan_retransmit_budget(
        &self,
        ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, BackendExecutionError>
    {
        let budget = VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
            method: ack_request.method,
            url: ack_request.url.clone(),
            headers: ack_request.headers.clone(),
            frames: ack_request.frames.clone(),
            window_start_sequence: ack_request.window_start_sequence,
            window_frame_count: ack_request.window_frame_count,
            expected_ack_sequence: ack_request.expected_ack_sequence,
            retransmit_budget: ack_request.retransmit_budget,
            timeout_ms: ack_request.timeout_ms,
            profile: ack_request.profile.clone(),
            transport_mode: ack_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(budget.clone());
        Ok(budget)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkRetransmitBudgetExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange
    for RecordingHttpClientSessionProtocolChunkRetransmitBudgetExchange
{
    fn exchange_retransmit_budget(
        &self,
        budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        self.requests.lock().unwrap().push(budget_request.clone());
        assert_eq!(budget_request.profile, connection_config.profile);
        assert_eq!(
            budget_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(budget_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse {
                status_code: 224,
                headers: BTreeMap::from([("x-budget".to_string(), "ok".to_string())]),
                frames: vec![b"settled-".to_vec(), b"ack-ok".to_vec()],
                window_start_sequence: budget_request.window_start_sequence,
                window_frame_count: budget_request.window_frame_count,
                acked_through_sequence: budget_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: budget_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkAckSettlementValidator {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkAckSettlementValidator
    for RecordingHttpClientSessionProtocolChunkAckSettlementValidator
{
    fn validate_ack_settlement(
        &self,
        budget_response: VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse,
        _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        self.responses.lock().unwrap().push(budget_response.clone());
        Ok(VerifierHttpClientSessionProtocolChunkAckResponse {
            status_code: budget_response.status_code,
            headers: budget_response.headers,
            frames: budget_response.frames,
            window_start_sequence: budget_response.window_start_sequence,
            window_frame_count: budget_response.window_frame_count,
            acked_through_sequence: budget_response.acked_through_sequence,
            retransmit_count: budget_response.retransmit_count,
        })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkRetransmitBudgetExchange;

impl VerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange
    for RejectingHttpClientSessionProtocolChunkRetransmitBudgetExchange
{
    fn exchange_retransmit_budget(
        &self,
        _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk retransmit budget exchange rejected retransmit budget".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkAckSettlementValidator;

impl VerifierHttpClientSessionProtocolChunkAckSettlementValidator
    for PanicHttpClientSessionProtocolChunkAckSettlementValidator
{
    fn validate_ack_settlement(
        &self,
        _budget_response: VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse,
        _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
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
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        panic!("chunk ack settlement validator should not be called when retransmit budget exchange fails")
    }
}

#[derive(Default)]
