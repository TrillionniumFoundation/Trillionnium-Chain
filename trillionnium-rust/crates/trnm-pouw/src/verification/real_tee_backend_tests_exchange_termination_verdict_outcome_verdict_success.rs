use super::*;

#[test]
fn verdict_backed_termination_outcome_exchange_plans_verdict_exchanges_and_materializes_outcome() {
    let task = mock_task();
    let termination_verdict_planner =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationVerdictPlanner::default());
    let termination_verdict_exchange =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationVerdictExchange::default());
    let outcome_materializer =
        Arc::new(RecordingHttpClientSessionProtocolChunkOutcomeMaterializer::default());
    let exchange = VerdictBackedVerifierHttpClientSessionProtocolChunkTerminationOutcomeExchange::with_components(
        termination_verdict_planner.clone(),
        termination_verdict_exchange.clone(),
        outcome_materializer.clone(),
    );
    let response = exchange
        .exchange_termination_outcome(
            &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                window_start_sequence: 91,
                window_frame_count: 2,
                expected_ack_sequence: 92,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                window_start_sequence: 91,
                window_frame_count: 2,
                expected_ack_sequence: 92,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                window_start_sequence: 91,
                window_frame_count: 2,
                expected_ack_sequence: 92,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                window_start_sequence: 91,
                window_frame_count: 2,
                expected_ack_sequence: 92,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                window_start_sequence: 91,
                window_frame_count: 2,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteChunksRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                chunks: vec![b"verdict-".to_vec(), b"outcome".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolBytesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
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
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionTransportRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionCallRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionWireRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"verdict-outcome".to_vec(),
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
                body: b"verdict-outcome".to_vec(),
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
                body: b"verdict-outcome".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "verdict-outcome".into(),
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
    assert_eq!(response.status_code, 227);
    assert_eq!(
        response.frames,
        vec![b"verdict-".to_vec(), b"materialized-ok".to_vec()]
    );
    let planned = termination_verdict_planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 92);
    let exchanged = termination_verdict_exchange
        .requests
        .lock()
        .unwrap()
        .clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let materialized = outcome_materializer.responses.lock().unwrap().clone();
    assert_eq!(materialized.len(), 1);
    assert_eq!(materialized[0].status_code, 227);
    assert_eq!(materialized[0].acked_through_sequence, 92);
    assert_eq!(materialized[0].budget_remaining, 1);
}
