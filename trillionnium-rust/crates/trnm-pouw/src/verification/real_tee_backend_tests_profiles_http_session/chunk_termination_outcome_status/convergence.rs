pub(super) use super::*;

pub(super) struct RecordingHttpClientSessionProtocolChunkAckConvergencePlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckConvergenceRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkAckConvergencePlanner
    for RecordingHttpClientSessionProtocolChunkAckConvergencePlanner
{
    fn plan_ack_convergence(
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, BackendExecutionError>
    {
        let convergence = VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
            method: budget_request.method,
            url: budget_request.url.clone(),
            headers: budget_request.headers.clone(),
            frames: budget_request.frames.clone(),
            window_start_sequence: budget_request.window_start_sequence,
            window_frame_count: budget_request.window_frame_count,
            expected_ack_sequence: budget_request.expected_ack_sequence,
            retransmit_budget: budget_request.retransmit_budget,
            timeout_ms: budget_request.timeout_ms,
            profile: budget_request.profile.clone(),
            transport_mode: budget_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(convergence.clone());
        Ok(convergence)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkRetransmitTerminationExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckConvergenceRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange
    for RecordingHttpClientSessionProtocolChunkRetransmitTerminationExchange
{
    fn exchange_retransmit_termination(
        &self,
        convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
        _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        self.requests
            .lock()
            .unwrap()
            .push(convergence_request.clone());
        assert_eq!(convergence_request.profile, connection_config.profile);
        assert_eq!(
            convergence_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(convergence_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkAckConvergenceResponse {
                status_code: 225,
                headers: BTreeMap::from([("x-convergence".to_string(), "ok".to_string())]),
                frames: vec![b"terminated-".to_vec(), b"acks-ok".to_vec()],
                window_start_sequence: convergence_request.window_start_sequence,
                window_frame_count: convergence_request.window_frame_count,
                acked_through_sequence: convergence_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: convergence_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationValidator {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationValidator
    for RecordingHttpClientSessionProtocolChunkTerminationValidator
{
    fn validate_termination(
        &self,
        convergence_response: VerifierHttpClientSessionProtocolChunkAckConvergenceResponse,
        _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        self.responses
            .lock()
            .unwrap()
            .push(convergence_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse {
                status_code: convergence_response.status_code,
                headers: convergence_response.headers,
                frames: convergence_response.frames,
                window_start_sequence: convergence_response.window_start_sequence,
                window_frame_count: convergence_response.window_frame_count,
                acked_through_sequence: convergence_response.acked_through_sequence,
                retransmit_count: convergence_response.retransmit_count,
                budget_remaining: convergence_response.budget_remaining,
            },
        )
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkRetransmitTerminationExchange;

impl VerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange
    for RejectingHttpClientSessionProtocolChunkRetransmitTerminationExchange
{
    fn exchange_retransmit_termination(
        &self,
        _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk retransmit termination exchange rejected converged ack budget".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkTerminationValidator;

impl VerifierHttpClientSessionProtocolChunkTerminationValidator
    for PanicHttpClientSessionProtocolChunkTerminationValidator
{
    fn validate_termination(
        &self,
        _convergence_response: VerifierHttpClientSessionProtocolChunkAckConvergenceResponse,
        _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        panic!("chunk termination validator should not be called when retransmit termination exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationOutcomePlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationOutcomePlanner
