use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolver;

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionResolver
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolver
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

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection;

impl VerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection
    for PassthroughVerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection
{
    fn project_normalized_verdict(
        &self,
        category_response: VerifierHttpClientSessionProtocolChunkTerminationCategoryResponse,
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
        VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse,
        BackendExecutionError,
    > {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse {
                status_code: category_response.status_code,
                headers: category_response.headers,
                frames: category_response.frames,
                window_start_sequence: category_response.window_start_sequence,
                window_frame_count: category_response.window_frame_count,
                acked_through_sequence: category_response.acked_through_sequence,
                retransmit_count: category_response.retransmit_count,
                budget_remaining: category_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange
{
    termination_label_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationLabelPlanner>,
    termination_label_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationLabelExchange>,
    verdict_projection_resolver:
        Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolver>,
}

#[allow(dead_code)]
impl
    LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange
{
    pub(super) fn new() -> Self {
        Self {
            termination_label_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationLabelPlanner,
            ),
            termination_label_exchange: Arc::new(
                TokenNormalizedVerifierHttpClientSessionProtocolChunkTerminationLabelExchange::new(
                ),
            ),
            verdict_projection_resolver: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionResolver,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_label_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationLabelPlanner,
        >,
        termination_label_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationLabelExchange,
        >,
        verdict_projection_resolver: Arc<
            dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionResolver,
        >,
    ) -> Self {
        Self {
            termination_label_planner,
            termination_label_exchange,
            verdict_projection_resolver,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationCategoryExchange
    for LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange
{
    fn exchange_termination_category(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationCategoryResponse, BackendExecutionError> {
        let label_request = self.termination_label_planner.plan_termination_label(
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
        let label_response = self.termination_label_exchange.exchange_termination_label(
            &label_request,
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
        self.verdict_projection_resolver.resolve_verdict_projection(
            label_response,
            &label_request,
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
