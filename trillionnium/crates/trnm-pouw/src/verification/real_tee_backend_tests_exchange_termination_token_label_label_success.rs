use super::support::*;

#[test]
fn label_projected_termination_classification_exchange_plans_labels_exchanges_and_resolves_verdict_projection(
) {
    let task = mock_task();
    let termination_label_planner =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationLabelPlanner::default());
    let termination_label_exchange =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationLabelExchange::default());
    let verdict_projection_resolver =
        Arc::new(RecordingHttpClientSessionProtocolChunkVerdictProjectionResolver::default());
    let exchange = LabelProjectedTerminationBackedVerifierHttpClientSessionProtocolChunkTerminationCategoryExchange::with_components(
        termination_label_planner.clone(),
        termination_label_exchange.clone(),
        verdict_projection_resolver.clone(),
    );
    let response = exchange
        .exchange_termination_category(
            &VerifierHttpClientSessionProtocolChunkTerminationCategoryRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationClassificationRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                expected_ack_sequence: 132,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                window_start_sequence: 131,
                window_frame_count: 2,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteChunksRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                chunks: vec![b"labeled-".to_vec(), b"projection".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolBytesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &ResolvedVerifierHttpClientSessionSocketConnectionConfig {
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
                timeout_ms: 5_000,
            },
            &VerifierHttpClientSessionSocketRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionTransportRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionCallRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionWireRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &ResolvedVerifierHttpClientSessionConfig {
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
                timeout_ms: 5_000,
            },
            &VerifierHttpClientRuntimeRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &ResolvedVerifierHttpClientConfig {
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
                timeout_ms: 5_000,
            },
            &VerifierHttpClientRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"labeled-projection".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "labeled-projection".into(),
                timeout_ms: 5_000,
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
            &BackendVerificationRequest {
                family: VerificationBackendFamily::Tee,
                task: &task,
                proof_data: b"TEE:...",
                tee_payload: None,
                zk_payload: None,
                resolved_vk_ref: None,
            },
        )
        .unwrap();
    assert_eq!(response.status_code, 231);
    assert_eq!(
        response.frames,
        vec![b"labeled-".to_vec(), b"projection-ok".to_vec()]
    );
    let planned = termination_label_planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 132);
    let exchanged = termination_label_exchange.requests.lock().unwrap().clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let resolved = verdict_projection_resolver
        .responses
        .lock()
        .unwrap()
        .clone();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].status_code, 231);
    assert_eq!(resolved[0].acked_through_sequence, 132);
    assert_eq!(resolved[0].budget_remaining, 1);
}
