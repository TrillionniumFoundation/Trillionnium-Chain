use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolChunkTerminationValidator;

impl VerifierHttpClientSessionProtocolChunkTerminationValidator
    for PassthroughVerifierHttpClientSessionProtocolChunkTerminationValidator
{
    fn validate_termination(
        &self,
        convergence_response: VerifierHttpClientSessionProtocolChunkAckConvergenceResponse,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        Ok(
            VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse {
                status_code: convergence_response.status_code,
                headers: convergence_response.headers,
                frames: convergence_response.frames,
                window_start_sequence: convergence_response.window_start_sequence,
                window_frame_count: convergence_response.window_frame_count,
                acked_through_sequence: convergence_response.acked_through_sequence,
                retransmit_count: convergence_response.retransmit_count,
                budget_remaining: convergence_response.budget_remaining,
            },
        )
    }
}

#[allow(dead_code)]
struct ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange {
    ack_convergence_planner: Arc<dyn VerifierHttpClientSessionProtocolChunkAckConvergencePlanner>,
    retransmit_termination_exchange:
        Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange>,
    termination_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationValidator>,
}

#[allow(dead_code)]
impl ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange {
    fn new() -> Self {
        Self {
            ack_convergence_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkAckConvergencePlanner,
            ),
            retransmit_termination_exchange: Arc::new(
                OutcomeProjectedVerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange::new(),
            ),
            termination_validator: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkTerminationValidator,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        ack_convergence_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkAckConvergencePlanner,
        >,
        retransmit_termination_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkRetransmitTerminationExchange,
        >,
        termination_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkTerminationValidator>,
    ) -> Self {
        Self {
            ack_convergence_planner,
            retransmit_termination_exchange,
            termination_validator,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange
    for ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange
{
    fn exchange_retransmit_budget(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse, BackendExecutionError>
    {
        let convergence_request = self.ack_convergence_planner.plan_ack_convergence(
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
        let convergence_response = self
            .retransmit_termination_exchange
            .exchange_retransmit_termination(
                &convergence_request,
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
        self.termination_validator.validate_termination(
            convergence_response,
            &convergence_request,
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
struct PassthroughVerifierHttpClientSessionProtocolChunkAckSettlementValidator;

impl VerifierHttpClientSessionProtocolChunkAckSettlementValidator
    for PassthroughVerifierHttpClientSessionProtocolChunkAckSettlementValidator
{
    fn validate_ack_settlement(
        &self,
        budget_response: VerifierHttpClientSessionProtocolChunkRetransmitBudgetResponse,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        Ok(VerifierHttpClientSessionProtocolChunkAckResponse {
            status_code: budget_response.status_code,
            headers: budget_response.headers,
            frames: budget_response.frames,
            window_start_sequence: budget_response.window_start_sequence,
            window_frame_count: budget_response.window_frame_count,
            acked_through_sequence: budget_response.acked_through_sequence,
            retransmit_count: budget_response.retransmit_count,
        })
    }
}

#[allow(dead_code)]
struct BudgetedRetransmitBackedVerifierHttpClientSessionProtocolChunkRetransmitExchange {
    budget_planner: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitBudgetPlanner>,
    budget_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange>,
    ack_settlement_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkAckSettlementValidator>,
}

#[allow(dead_code)]
impl BudgetedRetransmitBackedVerifierHttpClientSessionProtocolChunkRetransmitExchange {
    fn new() -> Self {
        Self {
            budget_planner: Arc::new(DirectVerifierHttpClientSessionProtocolChunkRetransmitBudgetPlanner),
            budget_exchange: Arc::new(
                ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange::new(),
            ),
            ack_settlement_validator: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkAckSettlementValidator,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        budget_planner: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitBudgetPlanner>,
        budget_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange>,
        ack_settlement_validator: Arc<
            dyn VerifierHttpClientSessionProtocolChunkAckSettlementValidator,
        >,
    ) -> Self {
        Self {
            budget_planner,
            budget_exchange,
            ack_settlement_validator,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkRetransmitExchange
    for BudgetedRetransmitBackedVerifierHttpClientSessionProtocolChunkRetransmitExchange
{
    fn exchange_retransmit(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkAckResponse, BackendExecutionError> {
        let budget_request = self.budget_planner.plan_retransmit_budget(
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
        let budget_response = self.budget_exchange.exchange_retransmit_budget(
            &budget_request,
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
        self.ack_settlement_validator.validate_ack_settlement(
            budget_response,
            &budget_request,
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
