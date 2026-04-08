use super::*;

#[test]
fn wire_backed_session_request_executor_builds_executes_and_parses_wire_response() {
    let task = mock_task();
    let request_builder = Arc::new(RecordingHttpClientSessionWireRequestBuilder::default());
    let wire_executor = Arc::new(RecordingHttpClientSessionWireExecutor::default());
    let response_parser = Arc::new(RecordingHttpClientSessionWireResponseParser::default());
    let executor = WireBackedVerifierHttpClientSessionRequestExecutor::with_components(
        request_builder.clone(),
        wire_executor.clone(),
        response_parser.clone(),
    );
    let response = executor
        .execute_request(
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: b"wire-body".to_vec(),
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
                body: b"wire-body".to_vec(),
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
                body: b"wire-body".to_vec(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "wire-body".into(),
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
    assert_eq!(response.status_code, 211);
    assert_eq!(response.body, b"wire-ok".to_vec());
    let built = request_builder.requests.lock().unwrap().clone();
    assert_eq!(built.len(), 1);
    assert_eq!(built[0].profile, "intel-dcap-external-default");
    let executed = wire_executor.requests.lock().unwrap().clone();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0], built[0]);
    let parsed = response_parser.responses.lock().unwrap().clone();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].status_code, 211);
    assert_eq!(parsed[0].body, b"wire-ok".to_vec());
}

#[test]
fn wire_backed_session_request_executor_fails_closed_when_wire_executor_rejects() {
    let task = mock_task();
    let executor = WireBackedVerifierHttpClientSessionRequestExecutor::with_components(
        Arc::new(DirectVerifierHttpClientSessionWireRequestBuilder),
        Arc::new(RejectingHttpClientSessionWireExecutor),
        Arc::new(PanicHttpClientSessionWireResponseParser),
    );
    let err = executor
        .execute_request(
            &VerifierHttpClientSessionRequest {
                method: HttpMethod::Post,
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: Vec::new(),
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
                body: Vec::new(),
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
                body: Vec::new(),
                timeout_ms: 5_000,
            },
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: String::new(),
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
        .unwrap_err();
    assert!(
        matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("client session wire executor rejected session"))
    );
}
