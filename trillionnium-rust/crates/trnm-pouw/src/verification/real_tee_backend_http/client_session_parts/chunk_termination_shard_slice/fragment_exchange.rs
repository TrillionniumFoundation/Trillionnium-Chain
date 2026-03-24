use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter;

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter
{
    fn adapt_projection_normalization(
        &self,
        slice_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse,
        _slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest,
        _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
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
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse,
        BackendExecutionError,
    > {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse {
                status_code: slice_response.status_code,
                headers: slice_response.headers,
                frames: slice_response.frames,
                window_start_sequence: slice_response.window_start_sequence,
                window_frame_count: slice_response.window_frame_count,
                acked_through_sequence: slice_response.acked_through_sequence,
                retransmit_count: slice_response.retransmit_count,
                budget_remaining: slice_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct SliceAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange {
    termination_token_fragment_slice_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSlicePlanner>,
    termination_token_fragment_slice_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange>,
    verdict_projection_normalization_adapter:
        Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter>,
}

#[allow(dead_code)]
impl SliceAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange {
    fn new() -> Self {
        Self {
            termination_token_fragment_slice_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSlicePlanner,
            ),
            termination_token_fragment_slice_exchange: Arc::new(
                ShardAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange::new(),
            ),
            verdict_projection_normalization_adapter: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        termination_token_fragment_slice_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSlicePlanner,
        >,
        termination_token_fragment_slice_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange,
        >,
        verdict_projection_normalization_adapter: Arc<
            dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationAdapter,
        >,
    ) -> Self {
        Self {
            termination_token_fragment_slice_planner,
            termination_token_fragment_slice_exchange,
            verdict_projection_normalization_adapter,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange
    for SliceAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange
{
    fn exchange_termination_token_fragment(
        &self,
        fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
        token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest,
        label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest,
        category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
        classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
        status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
        outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
        convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
        budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
        chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
        bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
        frame_request: &VerifierHttpClientSessionFrameRequest,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse,
        BackendExecutionError,
    > {
        let slice_request = self
            .termination_token_fragment_slice_planner
            .plan_termination_token_fragment_slice(
                fragment_request,
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )?;
        let slice_response = self
            .termination_token_fragment_slice_exchange
            .exchange_termination_token_fragment_slice(
                &slice_request,
                fragment_request,
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )?;
        self.verdict_projection_normalization_adapter
            .adapt_projection_normalization(
                slice_response,
                &slice_request,
                fragment_request,
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )
    }
}

#[allow(dead_code)]
pub(super) struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter;

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter
{
    fn adapt_projection_resolution(
        &self,
        fragment_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentResponse,
        _fragment_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenResponse, BackendExecutionError>
    {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationTokenResponse {
                status_code: fragment_response.status_code,
                headers: fragment_response.headers,
                frames: fragment_response.frames,
                window_start_sequence: fragment_response.window_start_sequence,
                window_frame_count: fragment_response.window_frame_count,
                acked_through_sequence: fragment_response.acked_through_sequence,
                retransmit_count: fragment_response.retransmit_count,
                budget_remaining: fragment_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct FragmentAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenExchange {
    termination_token_fragment_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner>,
    termination_token_fragment_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange>,
    verdict_projection_resolution_adapter:
        Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter>,
}

#[allow(dead_code)]
impl FragmentAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenExchange {
    fn new() -> Self {
        Self {
            termination_token_fragment_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner,
            ),
            termination_token_fragment_exchange: Arc::new(
                SliceAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange::new(),
            ),
            verdict_projection_resolution_adapter: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        termination_token_fragment_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentPlanner,
        >,
        termination_token_fragment_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentExchange,
        >,
        verdict_projection_resolution_adapter: Arc<
            dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionAdapter,
        >,
    ) -> Self {
        Self {
            termination_token_fragment_planner,
            termination_token_fragment_exchange,
            verdict_projection_resolution_adapter,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenExchange
    for FragmentAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenExchange
{
    fn exchange_termination_token(
        &self,
        token_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenRequest,
        label_request: &VerifierHttpClientSessionProtocolChunkTerminationLabelRequest,
        category_request: &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest,
        classification_request: &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest,
        status_request: &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest,
        verdict_request: &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest,
        outcome_request: &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest,
        convergence_request: &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest,
        budget_request: &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest,
        ack_request: &VerifierHttpClientSessionProtocolChunkAckRequest,
        window_request: &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest,
        frames_request: &VerifierHttpClientSessionProtocolChunkFramesRequest,
        chunked_request: &VerifierHttpClientSessionProtocolByteChunksRequest,
        framed_request: &VerifierHttpClientSessionProtocolByteStreamFrameRequest,
        bytes_request: &VerifierHttpClientSessionProtocolBytesRequest,
        protocol_request: &VerifierHttpClientSessionProtocolRequest,
        frame_request: &VerifierHttpClientSessionFrameRequest,
        connection_config: &ResolvedVerifierHttpClientSessionSocketConnectionConfig,
        socket_request: &VerifierHttpClientSessionSocketRequest,
        transport_request: &VerifierHttpClientSessionTransportRequest,
        call_request: &VerifierHttpClientSessionCallRequest,
        wire_request: &VerifierHttpClientSessionWireRequest,
        session_request: &VerifierHttpClientSessionRequest,
        session_config: &ResolvedVerifierHttpClientSessionConfig,
        runtime_request: &VerifierHttpClientRuntimeRequest,
        config: &ResolvedVerifierHttpClientConfig,
        client_request: &VerifierHttpClientRequest,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenResponse, BackendExecutionError>
    {
        let fragment_request = self
            .termination_token_fragment_planner
            .plan_termination_token_fragment(
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )?;
        let fragment_response = self
            .termination_token_fragment_exchange
            .exchange_termination_token_fragment(
                &fragment_request,
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )?;
        self.verdict_projection_resolution_adapter
            .adapt_projection_resolution(
                fragment_response,
                &fragment_request,
                token_request,
                label_request,
                category_request,
                classification_request,
                status_request,
                verdict_request,
                outcome_request,
                convergence_request,
                budget_request,
                ack_request,
                window_request,
                frames_request,
                chunked_request,
                framed_request,
                bytes_request,
                protocol_request,
                frame_request,
                connection_config,
                socket_request,
                transport_request,
                call_request,
                wire_request,
                session_request,
                session_config,
                runtime_request,
                config,
                client_request,
                http_request,
                request,
            )
    }
}
