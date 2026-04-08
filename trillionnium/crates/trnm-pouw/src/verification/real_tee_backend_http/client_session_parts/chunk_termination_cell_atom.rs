use super::*;

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest {
    method: HttpMethod,
    url: String,
    headers: BTreeMap<String, String>,
    frames: Vec<Vec<u8>>,
    window_start_sequence: u64,
    window_frame_count: usize,
    expected_ack_sequence: u64,
    retransmit_budget: usize,
    timeout_ms: u64,
    profile: String,
    transport_mode: VerifierTransportMode,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomResponse
{
    status_code: u16,
    headers: BTreeMap<String, String>,
    frames: Vec<Vec<u8>>,
    window_start_sequence: u64,
    window_frame_count: usize,
    acked_through_sequence: u64,
    retransmit_count: usize,
    budget_remaining: usize,
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomPlanner:
    Send + Sync
{
    fn plan_termination_token_fragment_slice_shard_unit_cell_atom(
        &self,
        cell_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellRequest,
        unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest,
        shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest,
        BackendExecutionError,
    >;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomExchange:
    Send + Sync
{
    fn exchange_termination_token_fragment_slice_shard_unit_cell_atom(
        &self,
        atom_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest,
        cell_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellRequest,
        unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest,
        shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomResponse, BackendExecutionError>;
}

#[allow(dead_code)]
pub(super) trait VerifierHttpClientSessionProtocolChunkVerdictProjectionNormalizationUnitAdapter:
    Send + Sync
{
    fn adapt_projection_normalization_unit(
        &self,
        atom_response: VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomResponse,
        atom_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest,
        cell_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellRequest,
        unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest,
        shard_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardRequest,
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
        VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellResponse,
        BackendExecutionError,
    >;
}

#[allow(dead_code)]
pub(super) struct DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomPlanner;

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomPlanner
    for DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomPlanner
{
    fn plan_termination_token_fragment_slice_shard_unit_cell_atom(
        &self,
        cell_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellRequest,
        _unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest,
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
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest, BackendExecutionError> {
        Ok(VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest {
            method: cell_request.method,
            url: cell_request.url.clone(),
            headers: cell_request.headers.clone(),
            frames: cell_request.frames.clone(),
            window_start_sequence: cell_request.window_start_sequence,
            window_frame_count: cell_request.window_frame_count,
            expected_ack_sequence: cell_request.expected_ack_sequence,
            retransmit_budget: cell_request.retransmit_budget,
            timeout_ms: cell_request.timeout_ms,
            profile: cell_request.profile.clone(),
            transport_mode: cell_request.transport_mode.clone(),
        })
    }
}

#[allow(dead_code)]
pub(super) struct FailClosedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomExchange;

impl VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomExchange
    for FailClosedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomExchange
{
    fn exchange_termination_token_fragment_slice_shard_unit_cell_atom(
        &self,
        _atom_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomRequest,
        _cell_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellRequest,
        _unit_request: &VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitRequest,
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
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<VerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitCellAtomResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "real http client session protocol chunk termination token fragment slice shard unit cell atom exchange for profile '{}' is not wired",
                http_request.profile
            ),
        })
    }
}
