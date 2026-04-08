pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner
    for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner
{
    fn plan_termination_token_fragment(
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
        BackendExecutionError,
    > {
        let fragment = VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest {
            method: token_request.method,
            url: token_request.url.clone(),
            headers: token_request.headers.clone(),
            frames: token_request.frames.clone(),
            window_start_sequence: token_request.window_start_sequence,
            window_frame_count: token_request.window_frame_count,
            expected_ack_sequence: token_request.expected_ack_sequence,
            retransmit_budget: token_request.retransmit_budget,
            timeout_ms: token_request.timeout_ms,
            profile: token_request.profile.clone(),
            transport_mode: token_request.transport_mode.clone(),
        };
        self.requests.lock().unwrap().push(fragment.clone());
        Ok(fragment)
    }
}
