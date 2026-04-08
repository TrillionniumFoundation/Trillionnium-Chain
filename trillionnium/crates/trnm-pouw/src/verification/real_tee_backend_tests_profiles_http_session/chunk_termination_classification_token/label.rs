pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationLabelPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationLabelRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationLabelPlanner
    for RecordingHttpClientSessionProtocolChunkTerminationLabelPlanner
{
    fn plan_termination_label(
        &self,
        category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, BackendExecutionError>
    {
        let label = VerifierHttpClientSessionProtocolChunkTerminationLabelRequest {
            method: category_request.method,
            url: category_request.url.clone(),
            headers: category_request.headers.clone(),
            frames: category_request.frames.clone(),
            window_start_sequence: category_request.window_start_sequence,
            window_frame_count: category_request.window_frame_count,
            expected_ack_sequence: category_request.expected_ack_sequence,
            retransmit_budget: category_request.retransmit_budget,
            timeout_ms: category_request.timeout_ms,
            profile: category_request.profile.clone(),
            transport_mode: category_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(label.clone());
        Ok(label)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationLabelExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationLabelRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationLabelExchange
    for RecordingHttpClientSessionProtocolChunkTerminationLabelExchange
{
    fn exchange_termination_label(
        &self,
        label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest,
        _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationLabelResponse, BackendExecutionError>
    {
        self.requests.lock().unwrap().push(label_request.clone());
        assert_eq!(label_request.profile, connection_config.profile);
        assert_eq!(
            label_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(label_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationLabelResponse {
                status_code: 231,
                headers: BTreeMap::from([("x-label".to_string(), "ok".to_string())]),
                frames: vec![b"labeled-".to_vec(), b"projection-ok".to_vec()],
                window_start_sequence: label_request.window_start_sequence,
                window_frame_count: label_request.window_frame_count,
                acked_through_sequence: label_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: label_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkVerdictProjectionResolver {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationLabelResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolver
    for RecordingHttpClientSessionProtocolChunkVerdictProjectionResolver
{
    fn resolve_verdict_projection(
        &self,
        label_response: VerifierHttpClientSessionProtocolChunkTerminationLabelResponse,
        _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest,
        _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationCategoryResponse,
        BackendExecutionError,
    > {
        self.responses.lock().unwrap().push(label_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationCategoryResponse {
                status_code: label_response.status_code,
                headers: label_response.headers,
                frames: label_response.frames,
                window_start_sequence: label_response.window_start_sequence,
                window_frame_count: label_response.window_frame_count,
                acked_through_sequence: label_response.acked_through_sequence,
                retransmit_count: label_response.retransmit_count,
                budget_remaining: label_response.budget_remaining,
            },
        )
    }
}
