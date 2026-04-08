pub(super) use super::*;

#[derive(Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentExchange {
    requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest>>,
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange
    for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentExchange
{
    fn exchange_termination_token_fragment(
        &self,
        fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse,
        BackendExecutionError,
    > {
        self.requests.lock().unwrap().push(fragment_request.clone());
        assert_eq!(fragment_request.profile, connection_config.profile);
        assert_eq!(fragment_request.transport_mode, connection_config.transport_mode);
        assert_eq!(fragment_request.timeout_ms, connection_config.timeout_ms);
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse {
                status_code: 235,
                headers: BTreeMap::from([("x-fragment".to_string(), "ok".to_string())]),
                frames: vec![b"fragment-".to_vec(), b"adapted-ok".to_vec()],
                window_start_sequence: fragment_request.window_start_sequence,
                window_frame_count: fragment_request.window_frame_count,
                acked_through_sequence: fragment_request.expected_ack_sequence,
                retransmit_count: 0,
                budget_remaining: fragment_request.retransmit_budget,
            },
        )
    }
}
