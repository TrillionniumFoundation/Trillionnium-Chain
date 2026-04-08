use super::*;

#[derive(Clone)]
pub(super) struct TerminationUnitShardFixture {
    pub(super) task: BackendTask,
    pub(super) shard_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest,
    pub(super) slice_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest,
    pub(super) fragment_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
    pub(super) token_request: VerifierHttpClientSessionProtocolChunkTerminationTokenRequest,
    pub(super) label_request: VerifierHttpClientSessionProtocolChunkTerminationLabelRequest,
    pub(super) category_request: VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
    pub(super) classification_request: VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
    pub(super) status_request: VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
    pub(super) verdict_request: VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
    pub(super) outcome_request: VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
    pub(super) convergence_request: VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
    pub(super) budget_request: VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
    pub(super) ack_request: VerifierHttpClientSessionProtocolChunkAckRequest,
    pub(super) window_request: VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
    pub(super) frames_request: VerifierHttpClientSessionProtocolChunkFramesRequest,
    pub(super) chunked_request: VerifierHttpClientSessionProtocolByteChunksRequest,
    pub(super) framed_request: VerifierHttpClientSessionProtocolByteStreamFrameRequest,
    pub(super) bytes_request: VerifierHttpClientSessionProtocolBytesRequest,
    pub(super) protocol_request: VerifierHttpClientSessionProtocolRequest,
    pub(super) frame_request: VerifierHttpClientSessionFrameRequest,
    pub(super) connection_config: ResolvedVerifierHttpClientSessionSocketConnectionConfig,
    pub(super) socket_request: VerifierHttpClientSessionSocketRequest,
    pub(super) transport_request: VerifierHttpClientSessionTransportRequest,
    pub(super) call_request: VerifierHttpClientSessionCallRequest,
    pub(super) wire_request: VerifierHttpClientSessionWireRequest,
    pub(super) session_request: VerifierHttpClientSessionRequest,
    pub(super) session_config: ResolvedVerifierHttpClientSessionConfig,
    pub(super) runtime_request: VerifierHttpClientRuntimeRequest,
    pub(super) config: ResolvedVerifierHttpClientConfig,
    pub(super) client_request: VerifierHttpClientRequest,
    pub(super) http_request: HttpVerifierRequest,
}

impl TerminationUnitShardFixture {
    pub(super) fn adapted() -> Self {
        Self::new(b"unit-adapted".to_vec(), vec![b"unit-".to_vec(), b"adapted".to_vec()], 631, 632, 1)
    }

    pub(super) fn empty() -> Self {
        Self::new(Vec::new(), vec![], 0, 0, 0)
    }

    fn new(body: Vec<u8>, frames: Vec<Vec<u8>>, window_start_sequence: u64, expected_ack_sequence: u64, retransmit_budget: usize) -> Self {
        let task = mock_task();
        let method = HttpMethod::Post;
        let url = "https://intel-verifier.invalid/v1/quote/sgx-dcap".to_string();
        let headers = BTreeMap::new();
        let timeout_ms = 5_000;
        let profile = "intel-dcap-external-default".to_string();
        let transport_mode = VerifierTransportMode::External;
        let window_frame_count = frames.len();
        let body_string = String::from_utf8(body.clone()).unwrap();
        Self {
            task,
            shard_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            slice_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            fragment_request: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            token_request: VerifierHttpClientSessionProtocolChunkTerminationTokenRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            label_request: VerifierHttpClientSessionProtocolChunkTerminationLabelRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            category_request: VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            classification_request: VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            status_request: VerifierHttpClientSessionProtocolChunkTerminationStatusRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            verdict_request: VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            outcome_request: VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            convergence_request: VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            budget_request: VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            ack_request: VerifierHttpClientSessionProtocolChunkAckRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, expected_ack_sequence, retransmit_budget,
                timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            window_request: VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(),
                window_start_sequence, window_frame_count, timeout_ms, profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            frames_request: VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), frames: frames.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            chunked_request: VerifierHttpClientSessionProtocolByteChunksRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), chunks: frames.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            framed_request: VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), encoded_body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            bytes_request: VerifierHttpClientSessionProtocolBytesRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), encoded_body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            protocol_request: VerifierHttpClientSessionProtocolRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            frame_request: VerifierHttpClientSessionFrameRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            connection_config: ResolvedVerifierHttpClientSessionSocketConnectionConfig {
                profile: profile.clone(), transport_mode: transport_mode.clone(), timeout_ms,
            },
            socket_request: VerifierHttpClientSessionSocketRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            transport_request: VerifierHttpClientSessionTransportRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            call_request: VerifierHttpClientSessionCallRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            wire_request: VerifierHttpClientSessionWireRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            session_request: VerifierHttpClientSessionRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            session_config: ResolvedVerifierHttpClientSessionConfig {
                profile: profile.clone(), transport_mode: transport_mode.clone(), timeout_ms,
            },
            runtime_request: VerifierHttpClientRuntimeRequest {
                method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms,
                profile: profile.clone(), transport_mode: transport_mode.clone(),
            },
            config: ResolvedVerifierHttpClientConfig {
                profile: profile.clone(), transport_mode: transport_mode.clone(), timeout_ms,
            },
            client_request: VerifierHttpClientRequest { method: method.clone(), url: url.clone(), headers: headers.clone(), body: body.clone(), timeout_ms },
            http_request: HttpVerifierRequest {
                method, transport_mode, profile, url, headers, body: body_string, timeout_ms,
                retry_policy: RetryBackoffPolicy { max_attempts: 3, backoff_ms: 250, strategy: RetryBackoffStrategy::Exponential },
            },
        }
    }

    pub(super) fn backend_request(&self) -> BackendVerificationRequest<'_> {
        BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &self.task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner {
    pub(super) requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest>>,
}
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner {
    fn plan_termination_token_fragment_slice_shard_unit(&self, shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest, BackendExecutionError> {
        let planned = VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest { method: shard_request.method.clone(), url: shard_request.url.clone(), headers: shard_request.headers.clone(), frames: shard_request.frames.clone(), window_start_sequence: shard_request.window_start_sequence, window_frame_count: shard_request.window_frame_count, expected_ack_sequence: shard_request.expected_ack_sequence, retransmit_budget: shard_request.retransmit_budget, timeout_ms: shard_request.timeout_ms, profile: shard_request.profile.clone(), transport_mode: shard_request.transport_mode.clone() };
        self.requests.lock().unwrap().push(planned.clone());
        Ok(planned)
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange {
    pub(super) requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest>>,
}
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange {
    fn exchange_termination_token_fragment_slice_shard_unit(&self, unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(unit_request.clone());
        Ok(VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitResponse { status_code: 241, headers: BTreeMap::new(), frames: vec![b"unit-".to_vec(), b"normalization-shard-adapted-ok".to_vec()], window_start_sequence: unit_request.window_start_sequence, window_frame_count: unit_request.window_frame_count, acked_through_sequence: unit_request.expected_ack_sequence, retransmit_count: 0, budget_remaining: unit_request.retransmit_budget })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange;
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange for RejectingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange {
    fn exchange_termination_token_fragment_slice_shard_unit(&self, _unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable { service: "client session protocol chunk termination token fragment slice shard unit exchange".into(), reason: "client session protocol chunk termination token fragment slice shard unit exchange rejected termination token fragment slice shard unit".into() })
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter {
    pub(super) responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse>>,
}
impl VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter for RecordingHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter {
    fn adapt_projection_normalization_shard(&self, unit_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitResponse, _unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, BackendExecutionError> {
        let adapted = VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse { status_code: unit_response.status_code, headers: unit_response.headers, frames: unit_response.frames, window_start_sequence: unit_response.window_start_sequence, window_frame_count: unit_response.window_frame_count, acked_through_sequence: unit_response.acked_through_sequence, retransmit_count: unit_response.retransmit_count, budget_remaining: unit_response.budget_remaining };
        self.responses.lock().unwrap().push(adapted.clone());
        Ok(adapted)
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter;
impl VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter for PanicHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter {
    fn adapt_projection_normalization_shard(&self, _unit_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitResponse, _unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, BackendExecutionError> {
        panic!("projection normalization shard adapter should not run")
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner {
    pub(super) requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest>>,
}
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner {
    fn plan_termination_token_fragment_slice_shard(&self, slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, BackendExecutionError> {
        let planned = VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest { method: slice_request.method.clone(), url: slice_request.url.clone(), headers: slice_request.headers.clone(), frames: slice_request.frames.clone(), window_start_sequence: slice_request.window_start_sequence, window_frame_count: slice_request.window_frame_count, expected_ack_sequence: slice_request.expected_ack_sequence, retransmit_budget: slice_request.retransmit_budget, timeout_ms: slice_request.timeout_ms, profile: slice_request.profile.clone(), transport_mode: slice_request.transport_mode.clone() };
        self.requests.lock().unwrap().push(planned.clone());
        Ok(planned)
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange {
    pub(super) requests: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest>>,
}
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange for RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange {
    fn exchange_termination_token_fragment_slice_shard(&self, shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, BackendExecutionError> {
        self.requests.lock().unwrap().push(shard_request.clone());
        Ok(VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse { status_code: 239, headers: BTreeMap::new(), frames: vec![b"shard-".to_vec(), b"resolution-shard-adapted-ok".to_vec()], window_start_sequence: shard_request.window_start_sequence, window_frame_count: shard_request.window_frame_count, acked_through_sequence: shard_request.expected_ack_sequence, retransmit_count: 0, budget_remaining: shard_request.retransmit_budget })
    }
}

pub(super) struct RejectingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange;
impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange for RejectingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange {
    fn exchange_termination_token_fragment_slice_shard(&self, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable { service: "client session protocol chunk termination token fragment slice shard exchange".into(), reason: "client session protocol chunk termination token fragment slice shard exchange rejected termination token fragment slice shard".into() })
    }
}

#[derive(Debug, Default)]
pub(super) struct RecordingHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter {
    pub(super) responses: Mutex<Vec<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse>>,
}
impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter for RecordingHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter {
    fn adapt_projection_resolution_shard(&self, shard_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse, BackendExecutionError> {
        let adapted = VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse { status_code: shard_response.status_code, headers: shard_response.headers, frames: shard_response.frames, window_start_sequence: shard_response.window_start_sequence, window_frame_count: shard_response.window_frame_count, acked_through_sequence: shard_response.acked_through_sequence, retransmit_count: shard_response.retransmit_count, budget_remaining: shard_response.budget_remaining };
        self.responses.lock().unwrap().push(adapted.clone());
        Ok(adapted)
    }
}

pub(super) struct PanicHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter;
impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter for PanicHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter {
    fn adapt_projection_resolution_shard(&self, _shard_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse, _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest, _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest, _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest, _token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest, _label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest, _category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest, _classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest, _status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest, _verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest, _outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest, _convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest, _budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest, _ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest, _window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest, _frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest, _chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest, _framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest, _bytes_request: &VerifierHttpClientSessionProtocolBytesRequest, _protocol_request: &VerifierHttpClientSessionProtocolRequest, _frame_request: &VerifierHttpClientSessionFrameRequest, _connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig, _socket_request: &VerifierHttpClientSessionSocketRequest, _transport_request: &VerifierHttpClientSessionTransportRequest, _call_request: &VerifierHttpClientSessionCallRequest, _wire_request: &VerifierHttpClientSessionWireRequest, _session_request: &VerifierHttpClientSessionRequest, _session_config: &ResolvedVerifierHttpClientSessionConfig, _runtime_request: &VerifierHttpClientRuntimeRequest, _config: &ResolvedVerifierHttpClientConfig, _client_request: &VerifierHttpClientRequest, _http_request: &HttpVerifierRequest, _request: &BackendVerificationRequest<'_>) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse, BackendExecutionError> {
        panic!("projection resolution shard adapter should not run")
    }
}
