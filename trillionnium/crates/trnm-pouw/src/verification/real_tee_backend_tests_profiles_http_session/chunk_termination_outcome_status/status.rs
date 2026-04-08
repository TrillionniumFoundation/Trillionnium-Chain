impl VerifierHttpClientSessionProtocolChunkTerminationStatusPlanner
    for RecordingHttpClientSessionProtocolChunkTerminationStatusPlanner
{
    fn plan_termination_status(
        &self,
        verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, BackendExecutionError>
    {
        let status = VerifierHttpClientSessionProtocolChunkTerminationStatusRequest {
            method: verdict_request.method,
            url: verdict_request.url.clone(),
            headers: verdict_request.headers.clone(),
            frames: verdict_request.frames.clone(),
            window_start_sequence: verdict_request.window_start_sequence,
            window_frame_count: verdict_request.window_frame_count,
            expected_ack_sequence: verdict_request.expected_ack_sequence,
            retransmit_budget: verdict_request.retransmit_budget,
            timeout_ms: verdict_request.timeout_ms,
            profile: verdict_request.profile.clone(),
            transport_mode: verdict_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(status.clone());
        Ok(status)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationStatusExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationStatusRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationStatusExchange
    for RecordingHttpClientSessionProtocolChunkTerminationStatusExchange
{
    fn exchange_termination_status(
        &self,
        status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
        BackendExecutionError,
    > {
        self.requests.lock().unwrap().push(status_request.clone());
        assert_eq!(status_request.profile, connection_config.profile);
        assert_eq!(
            status_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(status_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationStatusResponse {
                status_code: 228,
                headers: BTreeMap::from([("x-status".to_string(), "ok".to_string())]),
                frames: vec![b"status-".to_vec(), b"normalized-ok".to_vec()],
                window_start_sequence: status_request.window_start_sequence,
                window_frame_count: status_request.window_frame_count,
                acked_through_sequence: status_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: status_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkVerdictNormalizer {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationStatusResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkVerdictNormalizer
    for RecordingHttpClientSessionProtocolChunkVerdictNormalizer
{
    fn normalize_verdict(
        &self,
        status_response: VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
        _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse,
        BackendExecutionError,
    > {
        self.responses.lock().unwrap().push(status_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse {
                status_code: status_response.status_code,
                headers: status_response.headers,
                frames: status_response.frames,
                window_start_sequence: status_response.window_start_sequence,
                window_frame_count: status_response.window_frame_count,
                acked_through_sequence: status_response.acked_through_sequence,
                retransmit_count: status_response.retransmit_count,
                budget_remaining: status_response.budget_remaining,
            },
        )
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkTerminationStatusExchange;

impl VerifierHttpClientSessionProtocolChunkTerminationStatusExchange
    for RejectingHttpClientSessionProtocolChunkTerminationStatusExchange
{
    fn exchange_termination_status(
        &self,
        _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
        BackendExecutionError,
    > {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "client session protocol chunk termination status exchange rejected termination status".into(),
        })
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkVerdictNormalizer;

impl VerifierHttpClientSessionProtocolChunkVerdictNormalizer
    for PanicHttpClientSessionProtocolChunkVerdictNormalizer
{
    fn normalize_verdict(
        &self,
        _status_response: VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
        _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse,
        BackendExecutionError,
    > {
        panic!("verdict normalizer should not be called when termination status exchange fails")
    }
}

