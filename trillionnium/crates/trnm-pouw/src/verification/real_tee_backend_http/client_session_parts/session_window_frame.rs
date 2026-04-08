use super::*;

#[allow(dead_code)]
struct PassthroughVerifierHttpClientSessionProtocolChunkAckValidator;

impl VerifierHttpClientSessionProtocolChunkAckValidator
    for PassthroughVerifierHttpClientSessionProtocolChunkAckValidator
{
    fn validate_ack_response(
        &self,
        ack_response: VerifierHttpClientSessionProtocolChunkAckResponse,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        Ok(
            VerifierHttpClientSessionProtocolChunkSequenceWindowResponse {
                status_code: ack_response.status_code,
                headers: ack_response.headers,
                frames: ack_response.frames,
                window_start_sequence: ack_response.window_start_sequence,
                window_frame_count: ack_response.window_frame_count,
            },
        )
    }
}

#[allow(dead_code)]
struct AckedWindowBackedVerifierHttpClientSessionProtocolChunkSequenceWindowExchange {
    ack_policy: Arc<dyn VerifierHttpClientSessionProtocolChunkAckPolicy>,
    retransmit_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitExchange>,
    ack_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkAckValidator>,
}

#[allow(dead_code)]
impl AckedWindowBackedVerifierHttpClientSessionProtocolChunkSequenceWindowExchange {
    fn new() -> Self {
        Self {
            ack_policy: Arc::new(DirectVerifierHttpClientSessionProtocolChunkAckPolicy),
            retransmit_exchange: Arc::new(
                BudgetedRetransmitBackedVerifierHttpClientSessionProtocolChunkRetransmitExchange::new(),
            ),
            ack_validator: Arc::new(PassthroughVerifierHttpClientSessionProtocolChunkAckValidator),
        }
    }

    #[cfg(test)]
    fn with_components(
        ack_policy: Arc<dyn VerifierHttpClientSessionProtocolChunkAckPolicy>,
        retransmit_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkRetransmitExchange>,
        ack_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkAckValidator>,
    ) -> Self {
        Self {
            ack_policy,
            retransmit_exchange,
            ack_validator,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkSequenceWindowExchange
    for AckedWindowBackedVerifierHttpClientSessionProtocolChunkSequenceWindowExchange
{
    fn exchange_sequence_window(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkSequenceWindowResponse, BackendExecutionError>
    {
        let ack_request = self.ack_policy.plan_ack_request(
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
        let ack_response = self.retransmit_exchange.exchange_retransmit(
            &ack_request,
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
        self.ack_validator.validate_ack_response(
            ack_response,
            &ack_request,
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
struct PassthroughVerifierHttpClientSessionProtocolChunkIntegrityValidator;

impl VerifierHttpClientSessionProtocolChunkIntegrityValidator
    for PassthroughVerifierHttpClientSessionProtocolChunkIntegrityValidator
{
    fn validate_chunk_integrity(
        &self,
        window_response: VerifierHttpClientSessionProtocolChunkSequenceWindowResponse,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        Ok(VerifierHttpClientSessionProtocolChunkFramesResponse {
            status_code: window_response.status_code,
            headers: window_response.headers,
            frames: window_response.frames,
        })
    }
}

#[allow(dead_code)]
struct WindowedChunkBackedVerifierHttpClientSessionProtocolChunkFrameExchange {
    sequence_window_planner: Arc<dyn VerifierHttpClientSessionProtocolChunkSequenceWindowPlanner>,
    sequence_window_exchange: Arc<dyn VerifierHttpClientSessionProtocolChunkSequenceWindowExchange>,
    integrity_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkIntegrityValidator>,
}

#[allow(dead_code)]
impl WindowedChunkBackedVerifierHttpClientSessionProtocolChunkFrameExchange {
    fn new() -> Self {
        Self {
            sequence_window_planner: Arc::new(
                DirectVerifierHttpClientSessionProtocolChunkSequenceWindowPlanner,
            ),
            sequence_window_exchange: Arc::new(
                AckedWindowBackedVerifierHttpClientSessionProtocolChunkSequenceWindowExchange::new(
                ),
            ),
            integrity_validator: Arc::new(
                PassthroughVerifierHttpClientSessionProtocolChunkIntegrityValidator,
            ),
        }
    }

    #[cfg(test)]
    fn with_components(
        sequence_window_planner: Arc<
            dyn VerifierHttpClientSessionProtocolChunkSequenceWindowPlanner,
        >,
        sequence_window_exchange: Arc<
            dyn VerifierHttpClientSessionProtocolChunkSequenceWindowExchange,
        >,
        integrity_validator: Arc<dyn VerifierHttpClientSessionProtocolChunkIntegrityValidator>,
    ) -> Self {
        Self {
            sequence_window_planner,
            sequence_window_exchange,
            integrity_validator,
        }
    }
}

impl VerifierHttpClientSessionProtocolChunkFrameExchange
    for WindowedChunkBackedVerifierHttpClientSessionProtocolChunkFrameExchange
{
    fn exchange_chunk_frames(
        &self,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkFramesResponse, BackendExecutionError> {
        let window_request = self.sequence_window_planner.plan_sequence_window(
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
        let window_response = self.sequence_window_exchange.exchange_sequence_window(
            &window_request,
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
        self.integrity_validator.validate_chunk_integrity(
            window_response,
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
