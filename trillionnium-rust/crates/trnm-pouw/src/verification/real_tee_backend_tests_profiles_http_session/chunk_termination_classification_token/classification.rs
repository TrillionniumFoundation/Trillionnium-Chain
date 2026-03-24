pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationClassificationPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationClassificationPlanner
    for RecordingHttpClientSessionProtocolChunkTerminationClassificationPlanner
{
    fn plan_termination_classification(
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
        VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
        BackendExecutionError,
    > {
        let classification =
            VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest {
                method: status_request.method,
                url: status_request.url.clone(),
                headers: status_request.headers.clone(),
                frames: status_request.frames.clone(),
                window_start_sequence: status_request.window_start_sequence,
                window_frame_count: status_request.window_frame_count,
                expected_ack_sequence: status_request.expected_ack_sequence,
                retransmit_budget: status_request.retransmit_budget,
                timeout_ms: status_request.timeout_ms,
                profile: status_request.profile.clone(),
                transport_mode: status_request.transport_mode.clone(),
            };
        self.requests.lock().unwrap().push(classification.clone());
        Ok(classification)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationClassificationExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationClassificationExchange
    for RecordingHttpClientSessionProtocolChunkTerminationClassificationExchange
{
    fn exchange_termination_classification(
        &self,
        classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse,
        BackendExecutionError,
    > {
        self.requests
            .lock()
            .unwrap()
            .push(classification_request.clone());
        assert_eq!(classification_request.profile, connection_config.profile);
        assert_eq!(
            classification_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(
            classification_request.timeout_ms,
            connection_config.timeout_ms
        );
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse {
                status_code: 229,
                headers: BTreeMap::from([("x-classification".to_string(), "ok".to_string())]),
                frames: vec![b"classified-".to_vec(), b"outcome-ok".to_vec()],
                window_start_sequence: classification_request.window_start_sequence,
                window_frame_count: classification_request.window_frame_count,
                acked_through_sequence: classification_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: classification_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkNormalizedOutcomeMapper {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper
    for RecordingHttpClientSessionProtocolChunkNormalizedOutcomeMapper
{
    fn map_normalized_outcome(
        &self,
        classification_response: VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse,
        _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
        BackendExecutionError,
    > {
        self.responses
            .lock()
            .unwrap()
            .push(classification_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationStatusResponse {
                status_code: classification_response.status_code,
                headers: classification_response.headers,
                frames: classification_response.frames,
                window_start_sequence: classification_response.window_start_sequence,
                window_frame_count: classification_response.window_frame_count,
                acked_through_sequence: classification_response.acked_through_sequence,
                retransmit_count: classification_response.retransmit_count,
                budget_remaining: classification_response.budget_remaining,
            },
        )
    }
}
