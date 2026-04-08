use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkSettlementProjection;

impl VerifierHttpClientSessionProtocolChunkSettlementProjection
    for PassthroughVerifierHttpClientSessionProtocolChunkSettlementProjection
{
    fn project_settlement(
        &self,
        outcome_response: VerifierHttpClientSessionProtocolChunkTerminationOutcomeResponse,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        Ok(
            VerifierHttpClientSessionProtocolChunkAckConvergenceResponse {
                status_code: outcome_response.status_code,
                headers: outcome_response.headers,
                frames: outcome_response.frames,
                window_start_sequence: outcome_response.window_start_sequence,
                window_frame_count: outcome_response.window_frame_count,
                acked_through_sequence: outcome_response.acked_through_sequence,
                retransmit_count: outcome_response.retransmit_count,
                budget_remaining: outcome_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct OutcomeProjectedVerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange {
    termination_outcome_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationOutcomePlanner>,
    termination_outcome_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange>,
    settlement_projection: Arc<dyn VerifierHttpClientSessionProtocolChunkSettlementProjection>,
}

#[allow(dead_code)]
impl OutcomeProjectedVerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange {
    pub(super) fn new() -> Self {
        Self {
            termination_outcome_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationOutcomePlanner,
            ),
            termination_outcome_exchange: Arc::new(
                VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange::new(
                ),
            ),
            settlement_projection: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkSettlementProjection,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_outcome_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationOutcomePlanner,
        >,
        termination_outcome_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange,
        >,
        settlement_projection: Arc<dyn VerifierHttpClientSessionProtocolChunkSettlementProjection>,
    ) -> Self {
        Self {
            termination_outcome_planner,
            termination_outcome_exchange,
            settlement_projection,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange
    for OutcomeProjectedVerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange
{
    fn exchange_retransmit_termination(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckConvergenceResponse, BackendExecutionError>
    {
        let outcome_request = self.termination_outcome_planner.plan_termination_outcome(
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
        let outcome_response = self
            .termination_outcome_exchange
            .exchange_termination_outcome(
                &outcome_request,
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
        self.settlement_projection.project_settlement(
            outcome_response,
            &outcome_request,
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
