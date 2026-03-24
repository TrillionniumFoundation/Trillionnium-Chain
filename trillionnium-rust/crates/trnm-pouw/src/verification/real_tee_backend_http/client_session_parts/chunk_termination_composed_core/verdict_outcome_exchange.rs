use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkOutcomeMaterializer;

impl VerifierHttpClientSessionProtocolChunkOutcomeMaterializer
    for PassthroughVerifierHttpClientSessionProtocolChunkOutcomeMaterializer
{
    fn materialize_outcome(
        &self,
        verdict_response: VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse,
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
        VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        BackendExecutionError,
    > {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse {
                status_code: verdict_response.status_code,
                headers: verdict_response.headers,
                frames: verdict_response.frames,
                window_start_sequence: verdict_response.window_start_sequence,
                window_frame_count: verdict_response.window_frame_count,
                acked_through_sequence: verdict_response.acked_through_sequence,
                retransmit_count: verdict_response.retransmit_count,
                budget_remaining: verdict_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange {
    termination_verdict_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationVerdictPlanner>,
    termination_verdict_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationVerdictExchange>,
    outcome_materializer: Arc<dyn VerifierHttpClientSessionProtocolChunkOutcomeMaterializer>,
}

#[allow(dead_code)]
impl VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange {
    pub(super) fn new() -> Self {
        Self {
            termination_verdict_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationVerdictPlanner,
            ),
            termination_verdict_exchange: Arc::new(
                StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange::new(),
            ),
            outcome_materializer: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkOutcomeMaterializer,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_verdict_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationVerdictPlanner,
        >,
        termination_verdict_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationVerdictExchange,
        >,
        outcome_materializer: Arc<dyn VerifierHttpClientSessionProtocolChunkOutcomeMaterializer>,
    ) -> Self {
        Self {
            termination_verdict_planner,
            termination_verdict_exchange,
            outcome_materializer,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange
    for VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange
{
    fn exchange_termination_outcome(
        &self,
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
        VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
        BackendExecutionError,
    > {
        let verdict_request = self.termination_verdict_planner.plan_termination_verdict(
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
        let verdict_response = self
            .termination_verdict_exchange
            .exchange_termination_verdict(
                &verdict_request,
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
        self.outcome_materializer.materialize_outcome(
            verdict_response,
            &verdict_request,
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
