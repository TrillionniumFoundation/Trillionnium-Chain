use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer;

impl VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer
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

#[allow(dead_code)]
pub(super) struct TokenNormalizedVerifierHttpClientSessionProtocolChunkTerminationLabelExchange {
    termination_token_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenPlanner>,
    termination_token_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationTokenExchange>,
    verdict_projection_normalizer:
        Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer>,
}

#[allow(dead_code)]
impl TokenNormalizedVerifierHttpClientSessionProtocolChunkTerminationLabelExchange {
    pub(super) fn new() -> Self {
        Self {
            termination_token_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationTokenPlanner,
            ),
            termination_token_exchange: Arc::new(
                FragmentAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenExchange::new(
                ),
            ),
            verdict_projection_normalizer: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_token_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenPlanner,
        >,
        termination_token_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationTokenExchange,
        >,
        verdict_projection_normalizer: Arc<
            dyn VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizer,
        >,
    ) -> Self {
        Self {
            termination_token_planner,
            termination_token_exchange,
            verdict_projection_normalizer,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationLabelExchange
    for TokenNormalizedVerifierHttpClientSessionProtocolChunkTerminationLabelExchange
{
    fn exchange_termination_label(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationLabelResponse, BackendExecutionError>
    {
        let token_request = self.termination_token_planner.plan_termination_token(
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
        let token_response = self.termination_token_exchange.exchange_termination_token(
            &token_request,
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
        self.verdict_projection_normalizer
            .normalize_verdict_projection(
                token_response,
                &token_request,
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
