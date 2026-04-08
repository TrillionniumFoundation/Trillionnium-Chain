pub(super) use super::support::*;

#[test]
fn status_normalized_termination_verdict_exchange_plans_status_exchanges_and_normalizes_verdict() {
    let task = mock_task();
    let termination_status_planner =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationStatusPlanner::default());
    let termination_status_exchange =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationStatusExchange::default());
    let verdict_normalizer =
        Arc::new(RecordingHttpClientSessionProtocolChunkVerdictNormalizer::default());
    let exchange = StatusNormalizedVerifierHttpClientSessionProtocolChunkTerminationVerdictExchange::with_components(
        termination_status_planner.clone(),
        termination_status_exchange.clone(),
        verdict_normalizer.clone(),
    );
    let response = exchange
        .exchange_termination_verdict(
            &VerifierHttpClientSessionProtocolChunkTerminationVerdictRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                expected_ack_sequence: 102,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkTerminationOutcomeRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                expected_ack_sequence: 102,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckConvergenceRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                expected_ack_sequence: 102,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                expected_ack_sequence: 102,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                expected_ack_sequence: 102,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                window_start_sequence: 101,
                window_frame_count: 2,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"status-".to_vec(), b"verdict".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteChunksRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                chunks: vec![b"status-".to_vec(), b"verdict".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolBytesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
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
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionTransportRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionCallRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionWireRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"status-verdict".to_vec(),
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
                body: b"status-verdict".to_vec(),
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
                body: b"status-verdict".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "status-verdict".into(),
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
    assert_eq!(response.status_code, 228);
    assert_eq!(
        response.frames,
        vec![b"status-".to_vec(), b"normalized-ok".to_vec()]
    );
    let planned = termination_status_planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 102);
    let exchanged = termination_status_exchange.requests.lock().unwrap().clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let normalized = verdict_normalizer.responses.lock().unwrap().clone();
    assert_eq!(normalized.len(), 1);
    assert_eq!(normalized[0].status_code, 228);
    assert_eq!(normalized[0].acked_through_sequence, 102);
    assert_eq!(normalized[0].budget_remaining, 1);
}
