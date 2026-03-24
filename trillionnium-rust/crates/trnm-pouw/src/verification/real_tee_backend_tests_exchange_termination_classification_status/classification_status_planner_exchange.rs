pub(super) use super::support::*;

#[test]
fn classified_termination_status_exchange_plans_classifies_and_maps_normalized_outcome() {
    let task = mock_task();
    let termination_classification_planner = Arc::new(
        RecordingHttpClientSessionProtocolChunkTerminationClassificationPlanner::default(),
    );
    let termination_classification_exchange = Arc::new(
        RecordingHttpClientSessionProtocolChunkTerminationClassificationExchange::default(),
    );
    let normalized_outcome_mapper =
        Arc::new(RecordingHttpClientSessionProtocolChunkNormalizedOutcomeMapper::default());
    let exchange = ClassifiedTerminationStatusBackedVerifierHttpClientSessionProtocolChunkTerminationStatusExchange::with_components(
        termination_classification_planner.clone(),
        termination_classification_exchange.clone(),
        normalized_outcome_mapper.clone(),
    );
    let response = exchange
        .exchange_termination_status(
            &VerifierHttpClientSessionProtocolChunkTerminationStatusRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                expected_ack_sequence: 112,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                window_start_sequence: 111,
                window_frame_count: 2,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"classified-".to_vec(), b"status".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteChunksRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                chunks: vec![b"classified-".to_vec(), b"status".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolBytesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
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
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionTransportRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionCallRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionWireRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"classified-status".to_vec(),
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
                body: b"classified-status".to_vec(),
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
                body: b"classified-status".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "classified-status".into(),
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
    assert_eq!(response.status_code, 229);
    assert_eq!(
        response.frames,
        vec![b"classified-".to_vec(), b"outcome-ok".to_vec()]
    );
    let planned = termination_classification_planner
        .requests
        .lock()
        .unwrap()
        .clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 112);
    let exchanged = termination_classification_exchange
        .requests
        .lock()
        .unwrap()
        .clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let mapped = normalized_outcome_mapper.responses.lock().unwrap().clone();
    assert_eq!(mapped.len(), 1);
    assert_eq!(mapped[0].status_code, 229);
    assert_eq!(mapped[0].acked_through_sequence, 112);
    assert_eq!(mapped[0].budget_remaining, 1);
}
