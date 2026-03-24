pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenPlanner
    for RecordingHttpClientSessionProtocolChunkTerminationTokenPlanner
{
    fn plan_termination_token(
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, BackendExecutionError>
    {
        let token = VerifierHttpClientSessionProtocolChunkTerminationTokenRequest {
            method: label_request.method,
            url: label_request.url.clone(),
            headers: label_request.headers.clone(),
            frames: label_request.frames.clone(),
            window_start_sequence: label_request.window_start_sequence,
            window_frame_count: label_request.window_frame_count,
            expected_ack_sequence: label_request.expected_ack_sequence,
            retransmit_budget: label_request.retransmit_budget,
            timeout_ms: label_request.timeout_ms,
            profile: label_request.profile.clone(),
            transport_mode: label_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(token.clone());
        Ok(token)
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenExchange
    for RecordingHttpClientSessionProtocolChunkTerminationTokenExchange
{
    fn exchange_termination_token(
        &self,
        token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenResponse, BackendExecutionError>
    {
        self.requests.lock().unwrap().push(token_request.clone());
        assert_eq!(token_request.profile, connection_config.profile);
        assert_eq!(
            token_request.transport_mode,
            connection_config.transport_mode
        );
        assert_eq!(token_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationTokenResponse {
                status_code: 233,
                headers: BTreeMap::from([("x-token".to_string(), "ok".to_string())]),
                frames: vec![b"token-".to_vec(), b"normalized-ok".to_vec()],
                window_start_sequence: token_request.window_start_sequence,
                window_frame_count: token_request.window_frame_count,
                acked_through_sequence: token_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: token_request.retransmit_budget,
            },
        )
    }
}

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkVerdictProjectionNormalizer {
    responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenResponse>>,
}

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer
    for RecordingHttpClientSessionProtocolChunkVerdictProjectionNormalizer
{
    fn normalize_verdict_projection(
        &self,
        token_response: VerifierHttpClientSessionProtocolChunkTerminationTokenResponse,
        _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationLabelResponse, BackendExecutionError>
    {
        self.responses.lock().unwrap().push(token_response.clone());
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationLabelResponse {
                status_code: token_response.status_code,
                headers: token_response.headers,
                frames: token_response.frames,
                window_start_sequence: token_response.window_start_sequence,
                window_frame_count: token_response.window_frame_count,
                acked_through_sequence: token_response.acked_through_sequence,
                retransmit_count: token_response.retransmit_count,
                budget_remaining: token_response.budget_remaining,
            },
        )
    }
}
