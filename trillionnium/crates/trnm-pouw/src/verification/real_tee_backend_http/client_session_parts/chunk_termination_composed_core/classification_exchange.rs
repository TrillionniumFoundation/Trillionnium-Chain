use super::*;

pub(super) struct CategorizedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationClassificationExchange
{
    termination_category_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationCategoryPlanner>,
    termination_category_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationCategoryExchange>,
    normalized_verdict_projection:
        Arc<dyn VerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection>,
}

#[allow(dead_code)]
impl CategorizedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationClassificationExchange {
    pub(super) fn new() -> Self {
        Self {
            termination_category_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationCategoryPlanner,
            ),
            termination_category_exchange: Arc::new(
                LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange::new(),
            ),
            normalized_verdict_projection: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_category_planner: Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationCategoryPlanner>,
        termination_category_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationCategoryExchange>,
        normalized_verdict_projection: Arc<dyn VerifierHttpClientSessionProtocolChunkNormalizedVerdictProjection>,
    ) -> Self {
        Self {
            termination_category_planner,
            termination_category_exchange,
            normalized_verdict_projection,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationClassificationExchange
    for CategorizedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationClassificationExchange
{
    fn exchange_termination_classification(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationClassificationResponse, BackendExecutionError> {
        let category_request = self.termination_category_planner.plan_termination_category(
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
        let category_response = self.termination_category_exchange.exchange_termination_category(
            &category_request,
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
        self.normalized_verdict_projection.project_normalized_verdict(
            category_response,
            &category_request,
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
struct PassthroughVerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper;

impl VerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper
    for PassthroughVerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper
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

#[allow(dead_code)]
pub(super) struct ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange
{
    termination_classification_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationClassificationPlanner>,
    termination_classification_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationClassificationExchange>,
    normalized_outcome_mapper:
        Arc<dyn VerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper>,
}

#[allow(dead_code)]
impl
    ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange
{
    pub(super) fn new() -> Self {
        Self {
            termination_classification_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationClassificationPlanner,
            ),
            termination_classification_exchange: Arc::new(
                CategorizedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationClassificationExchange::new(),
            ),
            normalized_outcome_mapper: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_classification_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationClassificationPlanner,
        >,
        termination_classification_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationClassificationExchange,
        >,
        normalized_outcome_mapper: Arc<
            dyn VerifierHttpClientSessionProtocolChunkNormalizedOutcomeMapper,
        >,
    ) -> Self {
        Self {
            termination_classification_planner,
            termination_classification_exchange,
            normalized_outcome_mapper,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationStatusExchange
    for ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange
{
    fn exchange_termination_status(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationStatusResponse, BackendExecutionError> {
        let classification_request = self.termination_classification_planner.plan_termination_classification(
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
        let classification_response = self.termination_classification_exchange.exchange_termination_classification(
            &classification_request,
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
        self.normalized_outcome_mapper.map_normalized_outcome(
            classification_response,
            &classification_request,
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
