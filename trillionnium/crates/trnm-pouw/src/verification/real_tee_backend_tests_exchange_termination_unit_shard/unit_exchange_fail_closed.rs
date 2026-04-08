use super::{support::*, *};

#[test]
fn unit_adapted_termination_token_fragment_slice_shard_exchange_fails_closed_when_slice_shard_unit_exchange_rejects(
) {
    let fixture = TerminationUnitShardFixture::empty();
    let exchange = UnitAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange::with_components(
        Arc::new(DirectVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner),
        Arc::new(RejectingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange),
        Arc::new(PanicHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter),
    );
    let request = fixture.backend_request();
    let err = exchange.exchange_termination_token_fragment_slice_shard(
        &fixture.shard_request,
        &fixture.slice_request,
        &fixture.fragment_request,
        &fixture.token_request,
        &fixture.label_request,
        &fixture.category_request,
        &fixture.classification_request,
        &fixture.status_request,
        &fixture.verdict_request,
        &fixture.outcome_request,
        &fixture.convergence_request,
        &fixture.budget_request,
        &fixture.ack_request,
        &fixture.window_request,
        &fixture.frames_request,
        &fixture.chunked_request,
        &fixture.framed_request,
        &fixture.bytes_request,
        &fixture.protocol_request,
        &fixture.frame_request,
        &fixture.connection_config,
        &fixture.socket_request,
        &fixture.transport_request,
        &fixture.call_request,
        &fixture.wire_request,
        &fixture.session_request,
        &fixture.session_config,
        &fixture.runtime_request,
        &fixture.config,
        &fixture.client_request,
        &fixture.http_request,
        &request,
    ).unwrap_err();
    assert!(matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("client session protocol chunk termination token fragment slice shard unit exchange rejected termination token fragment slice shard unit")));
}
