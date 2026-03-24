use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter;

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter
{
    fn adapt_projection_resolution_shard(
        &self,
        shard_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardResponse,
        _shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse,
        BackendExecutionError,
    > {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse {
                status_code: shard_response.status_code,
                headers: shard_response.headers,
                frames: shard_response.frames,
                window_start_sequence: shard_response.window_start_sequence,
                window_frame_count: shard_response.window_frame_count,
                acked_through_sequence: shard_response.acked_through_sequence,
                retransmit_count: shard_response.retransmit_count,
                budget_remaining: shard_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct ShardAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange {
    termination_token_fragment_slice_shard_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner>,
    termination_token_fragment_slice_shard_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange>,
    verdict_projection_resolution_shard_adapter:
        Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter>,
}

#[allow(dead_code)]
impl ShardAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange {
    fn new() -> Self {
        Self {
            termination_token_fragment_slice_shard_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner,
            ),
            termination_token_fragment_slice_shard_exchange: Arc::new(
                UnitAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange::new(),
            ),
            verdict_projection_resolution_shard_adapter: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        termination_token_fragment_slice_shard_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardPlanner,
        >,
        termination_token_fragment_slice_shard_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange,
        >,
        verdict_projection_resolution_shard_adapter: Arc<
            dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolutionShardAdapter,
        >,
    ) -> Self {
        Self {
            termination_token_fragment_slice_shard_planner,
            termination_token_fragment_slice_shard_exchange,
            verdict_projection_resolution_shard_adapter,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange
    for ShardAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceExchange
{
    fn exchange_termination_token_fragment_slice(
        &self,
        slice_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceResponse,
        BackendExecutionError,
    > {
        let shard_request = self
            .termination_token_fragment_slice_shard_planner
            .plan_termination_token_fragment_slice_shard(
                slice_request,
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
        let shard_response = self
            .termination_token_fragment_slice_shard_exchange
            .exchange_termination_token_fragment_slice_shard(
                &shard_request,
                slice_request,
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
        self.verdict_projection_resolution_shard_adapter
            .adapt_projection_resolution_shard(
                shard_response,
                &shard_request,
                slice_request,
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
