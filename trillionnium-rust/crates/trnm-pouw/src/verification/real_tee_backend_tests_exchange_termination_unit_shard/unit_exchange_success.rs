use super::{support::*, *};

#[test]
fn unit_adapted_termination_token_fragment_slice_shard_exchange_plans_slice_shard_unit_exchanges_and_adapts_projection_normalization(
) {
    let fixture = TerminationUnitShardFixture::adapted();
    let termination_token_fragment_slice_shard_unit_planner = Arc::new(
        RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitPlanner::default(),
    );
    let termination_token_fragment_slice_shard_unit_exchange = Arc::new(
        RecordingHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardUnitExchange::default(),
    );
    let verdict_projection_normalization_shard_adapter = Arc::new(
        RecordingHttpClientSessionProtocolChunkVerdictProjectionNormalizationShardAdapter::default(),
    );
    let exchange = UnitAdaptedVerifierHttpClientSessionProtocolChunkTerminationTokenFragmentSliceShardExchange::with_components(
        termination_token_fragment_slice_shard_unit_planner.clone(),
        termination_token_fragment_slice_shard_unit_exchange.clone(),
        verdict_projection_normalization_shard_adapter.clone(),
    );
    let request = fixture.backend_request();
    let response = exchange.exchange_termination_token_fragment_slice_shard(
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
    ).unwrap();
    assert_eq!(response.status_code, 241);
    assert_eq!(response.frames, vec![b"unit-".to_vec(), b"normalization-shard-adapted-ok".to_vec()]);
    let planned = termination_token_fragment_slice_shard_unit_planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 632);
    let exchanged = termination_token_fragment_slice_shard_unit_exchange.requests.lock().unwrap().clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let adapted = verdict_projection_normalization_shard_adapter.responses.lock().unwrap().clone();
    assert_eq!(adapted.len(), 1);
    assert_eq!(adapted[0].status_code, 241);
    assert_eq!(adapted[0].acked_through_sequence, 632);
    assert_eq!(adapted[0].budget_remaining, 1);
}
