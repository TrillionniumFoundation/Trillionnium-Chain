    for RecordingHttpClientSessionProtocolChunkTerminationOutcomePlanner
{
    fn plan_termination_outcome(
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
        BackendExecutionError,
    > {
        let outcome = VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
            method: convergence_request.method,
            url: convergence_request.url.clone(),
            headers: convergence_request.headers.clone(),
            frames: convergence_request.frames.clone(),
            window_start_sequence: convergence_request.window_start_sequence,
            window_frame_count: convergence_request.window_frame_count,
            expected_ack_sequence: convergence_request.expected_ack_sequence,
            retransmit_budget: convergence_request.retransmit_budget,
            timeout_ms: convergence_request.timeout_ms,
            profile: convergence_request.profile.clone(),
            transport_mode: convergence_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(outcome.clone());
        Ok(outcome)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationOutcomeExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange
    for RecordingHttpClientSessionProtocolChunkTerminationOutcomeExchange
{
    fn exchange_termination_outcome(
        &self,
        outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        BackendExecutionError,
    > {
        self.requests.lock().unwrap().push(outcome_request.clone());
        assert_eq!(outcome_request.profile, connection_config.profile);
        assert_eq!(
            outcome_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(outcome_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse {
                status_code: 226,
                headers: BTreeMap::from([("x-termination".to_string(), "ok".to_string())]),
                frames: vec![b"projected-".to_vec(), b"settlement-ok".to_vec()],
                window_start_sequence: outcome_request.window_start_sequence,
                window_frame_count: outcome_request.window_frame_count,
                acked_through_sequence: outcome_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: outcome_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkSettlementProjection {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkSettlementProjection
    for RecordingHttpClientSessionProtocolChunkSettlementProjection
{
    fn project_settlement(
        &self,
        outcome_response: VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        self.responses
            .lock()
            .unwrap()
            .push(outcome_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkAckConvergenceResponse {
                status_code: outcome_response.status_code,
                headers: outcome_response.headers,
                frames: outcome_response.frames,
                window_start_sequence: outcome_response.window_start_sequence,
                window_frame_count: outcome_response.window_frame_count,
                acked_through_sequence: outcome_response.acked_through_sequence,
                retransmit_count: outcome_response.retransmit_count,
                budget_remaining: outcome_response.budget_remaining,
            },
        )
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkTerminationOutcomeExchange;

impl VerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange
    for RejectingHttpClientSessionProtocolChunkTerminationOutcomeExchange
{
    fn exchange_termination_outcome(
        &self,
        _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        BackendExecutionError,
    > {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk termination outcome exchange rejected termination outcome".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkSettlementProjection;

impl VerifierHttpClientSessionProtocolChunkSettlementProjection
    for PanicHttpClientSessionProtocolChunkSettlementProjection
{
    fn project_settlement(
        &self,
        _outcome_response: VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        panic!("settlement projection should not be called when termination outcome exchange fails")
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationVerdictPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest>>,
}

