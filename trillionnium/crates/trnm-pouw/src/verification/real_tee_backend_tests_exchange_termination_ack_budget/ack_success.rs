pub(super) use super::support::*;

#[test]
fn converging_ack_budget_exchange_plans_termination_and_validates_budget_response() {
    let task = mock_task();
    let ack_convergence_planner =
        Arc::new(RecordingHttpClientSessionProtocolChunkAckConvergencePlanner::default());
    let retransmit_termination_exchange =
        Arc::new(RecordingHttpClientSessionProtocolChunkRetransmitTerminationExchange::default());
    let termination_validator =
        Arc::new(RecordingHttpClientSessionProtocolChunkTerminationValidator::default());
    let exchange = ConvergingAckBackedVerifierHttpClientSessionProtocolChunkRetransmitBudgetExchange::with_components(
        ack_convergence_planner.clone(),
        retransmit_termination_exchange.clone(),
        termination_validator.clone(),
    );
    let response = exchange
        .exchange_retransmit_budget(
            &VerifierHttpClientSessionProtocolChunkRetransmitBudgetRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"terminated-".to_vec(), b"budget".to_vec()],
                window_start_sequence: 71,
                window_frame_count: 2,
                expected_ack_sequence: 72,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkAckRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"terminated-".to_vec(), b"budget".to_vec()],
                window_start_sequence: 71,
                window_frame_count: 2,
                expected_ack_sequence: 72,
                retransmit_budget: 1,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkSequenceWindowRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"terminated-".to_vec(), b"budget".to_vec()],
                window_start_sequence: 71,
                window_frame_count: 2,
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolChunkFramesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                frames: vec![b"terminated-".to_vec(), b"budget".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteChunksRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                chunks: vec![b"terminated-".to_vec(), b"budget".to_vec()],
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolByteStreamFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolBytesRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                encoded_body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionProtocolRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionFrameRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
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
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionTransportRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionCallRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionWireRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
                profile: "intel-dcap-external-default".into(),
                transport_mode: VerifierTransportMode::External,
            },
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"terminated-budget".to_vec(),
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
                body: b"terminated-budget".to_vec(),
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
                body: b"terminated-budget".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "terminated-budget".into(),
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
    assert_eq!(response.status_code, 225);
    assert_eq!(
        response.frames,
        vec![b"terminated-".to_vec(), b"acks-ok".to_vec()]
    );
    let planned = ack_convergence_planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(planned[0].expected_ack_sequence, 72);
    assert_eq!(planned[0].retransmit_budget, 1);
    let exchanged = retransmit_termination_exchange
        .requests
        .lock()
        .unwrap()
        .clone();
    assert_eq!(exchanged.len(), 1);
    assert_eq!(exchanged[0], planned[0]);
    let validated = termination_validator.responses.lock().unwrap().clone();
    assert_eq!(validated.len(), 1);
    assert_eq!(validated[0].status_code, 225);
    assert_eq!(validated[0].acked_through_sequence, 72);
    assert_eq!(validated[0].budget_remaining, 1);
}
