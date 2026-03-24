use super::*;

#[test]
fn adapter_backed_request_executor_plans_and_delegates_to_client_adapter() {
    let task = mock_task();
    let planner = Arc::new(RecordingHttpRequestPlanner::default());
    let client_adapter = Arc::new(RecordingHttpClientAdapter::default());
    let executor = AdapterBackedVerifierHttpRequestExecutor::with_components(
        planner.clone(),
        client_adapter.clone(),
    );
    let response = executor
        .execute_request(
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::from([(
                    "content-type".to_string(),
                    "application/json".to_string(),
                )]),
                body: "{\"hello\":\"world\"}".into(),
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
    assert_eq!(response.status_code, 202);
    assert_eq!(response.body, b"adapter-ok".to_vec());
    let planned = planner.requests.lock().unwrap().clone();
    assert_eq!(planned.len(), 1);
    assert_eq!(
        planned[0].url,
        "https://intel-verifier.invalid/v1/quote/sgx-dcap"
    );
    assert_eq!(planned[0].body, b"{\"hello\":\"world\"}".to_vec());
    let executed = client_adapter.requests.lock().unwrap().clone();
    assert_eq!(executed.len(), 1);
    assert_eq!(executed[0], planned[0]);
}

#[test]
fn adapter_backed_request_executor_fails_closed_when_planner_rejects() {
    let task = mock_task();
    let executor = AdapterBackedVerifierHttpRequestExecutor::with_components(
        Arc::new(RejectingHttpRequestPlanner),
        Arc::new(PanicHttpClientAdapter),
    );
    let err = executor
        .execute_request(
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::new(),
                body: "{}".into(),
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
    match err {
        BackendExecutionError::Unavailable { reason, .. } => {
            assert!(reason.contains("request planner rejected http request"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn real_http_transport_execution_skeleton_delegates_to_components() {
    let task = mock_task();
    let request_executor = Arc::new(RecordingHttpRequestExecutor::default());
    let body_reader = Arc::new(RecordingHttpBodyReader::default());
    let timeout_hook = Arc::new(RecordingHttpTimeoutHook::default());
    let transport = RealVerifierHttpTransport::with_components(
        request_executor.clone(),
        body_reader.clone(),
        timeout_hook.clone(),
    );
    let response = transport
        .send(
            &HttpVerifierRequest {
                method: HttpMethod::Post,
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                url: "https://intel-verifier.invalid/v1/quote/sgx-dcap".into(),
                headers: BTreeMap::from([(
                    "authorization".to_string(),
                    "bearer tee.intel.external-token.sgx-dcap".to_string(),
                )]),
                body: "{\"transport\":\"ok\"}".into(),
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
    assert_eq!(response.status_code, 200);
    assert_eq!(response.body, "{\"transport\":\"ok\"}");
    let executed_urls = request_executor.urls.lock().unwrap().clone();
    assert_eq!(executed_urls.len(), 1);
    assert_eq!(
        executed_urls[0],
        "https://intel-verifier.invalid/v1/quote/sgx-dcap"
    );
    let read_bodies = body_reader.bodies.lock().unwrap().clone();
    assert_eq!(read_bodies, vec![b"{\"transport\":\"ok\"}".to_vec()]);
    let timeout_calls = timeout_hook.calls.lock().unwrap().clone();
    assert_eq!(
        timeout_calls,
        vec![
            "before:intel-dcap-external-default:5000".to_string(),
            "after:intel-dcap-external-default:200".to_string(),
        ]
    );
}

