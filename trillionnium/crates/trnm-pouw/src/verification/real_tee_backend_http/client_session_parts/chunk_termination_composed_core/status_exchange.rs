use super::*;

struct PassthroughVerifierHttpClientSessionProtocolChunkVerdictNormalizer;

impl VerifierHttpClientSessionProtocolChunkVerdictNormalizer
    for PassthroughVerifierHttpClientSessionProtocolChunkVerdictNormalizer
{
    fn normalize_verdict(
        &self,
        status_response: VerifierHttpClientSessionProtocolChunkTerminationStatusResponse,
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
        VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse,
        BackendExecutionError,
    > {
        Ok(
            VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse {
                status_code: status_response.status_code,
                headers: status_response.headers,
                frames: status_response.frames,
                window_start_sequence: status_response.window_start_sequence,
                window_frame_count: status_response.window_frame_count,
                acked_through_sequence: status_response.acked_through_sequence,
                retransmit_count: status_response.retransmit_count,
                budget_remaining: status_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
pub(super) struct StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange {
    termination_status_planner:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationStatusPlanner>,
    termination_status_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationStatusExchange>,
    verdict_normalizer: Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictNormalizer>,
}

#[allow(dead_code)]
impl StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange {
    pub(super) fn new() -> Self {
        Self {
            termination_status_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkTerminationStatusPlanner,
            ),
            termination_status_exchange: Arc::new(
                ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange::new(),
            ),
            verdict_normalizer: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkVerdictNormalizer,
            ),
        }
    }

    #[cfg(test)]
    pub(super) fn with_components(
        termination_status_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationStatusPlanner,
        >,
        termination_status_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkTerminationStatusExchange,
        >,
        verdict_normalizer: Arc<dyn VerifierHttpClientSessionProtocolChunkVerdictNormalizer>,
    ) -> Self {
        Self {
            termination_status_planner,
            termination_status_exchange,
            verdict_normalizer,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkTerminationVerdictExchange
    for StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange
{
    fn exchange_termination_verdict(
        &self,
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
        VerifierHttpClientSessionProtocolChunkTerminationVerdictResponse,
        BackendExecutionError,
    > {
        let status_request = self.termination_status_planner.plan_termination_status(
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
        let status_response = self
            .termination_status_exchange
            .exchange_termination_status(
                &status_request,
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
        self.verdict_normalizer.normalize_verdict(
            status_response,
            &status_request,
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
