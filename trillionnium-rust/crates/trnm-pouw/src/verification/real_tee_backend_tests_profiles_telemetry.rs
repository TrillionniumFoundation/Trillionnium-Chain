use super::*;

#[test]
fn http_retry_executor_retries_503_then_succeeds() {
    let task = mock_task();
    let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let client = HttpBackedIntelQuoteVerifierClient::with_retry_executor(
        Arc::new(FlakyIntelHttpTransport {
            calls: calls.clone(),
        }),
        Arc::new(PolicyAwareHttpRetryExecutor),
    );
    let result = client.verify_intel_quote_request(
        &IntelQuoteVerifierClientRequest {
            transport: StaticVerifierTransportConfigSource::external_defaults()
                .intel_quote_transport_config("sgx-dcap"),
            call_metadata: ExternalCallMetadata {
                request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                attempt: 1,
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
            request_event: VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::RequestPrepared,
                request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                transport_mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".into(),
                backend_id: None,
                status: None,
                detail: None,
            },
            attestation_target: "sgx-dcap".into(),
            measurement_field: "mrenclave".into(),
            measurement: "mrenclave:demo-sgx-v1".into(),
            report_data_hash: hex::encode(task.result_hash.unwrap()),
            quote: "quote-sgx-dcap-demo-v1".into(),
            intel_collateral: IntelQuoteCollateralBundle {
                collateral: "intel-dcap-collateral-demo-v1".into(),
                cert_chain: "intel-dcap-cert-chain-demo-v1".into(),
                issuer: "intel".into(),
            },
        },
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        },
    );
    assert!(
        matches!(result, Ok(MockVerifierResponse { backend_id, .. }) if backend_id == "intel-http-retry")
    );
    assert_eq!(&*calls.lock().unwrap(), &["1".to_string(), "2".to_string()]);
}

#[test]
fn json_encoding_telemetry_sink_records_serialized_events() {
    let recorder = Arc::new(BufferingTelemetryRecorder::default());
    let sink = JsonEncodingTelemetrySink::new(recorder.clone());
    let event = VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::ResponseMapped,
        request_id: "req-1".into(),
        telemetry_scope: "trnm.test.scope".into(),
        transport_mode: VerifierTransportMode::External,
        profile: "intel-dcap-external-default".into(),
        backend_id: Some("intel-http".into()),
        status: Some(MockVerifierResponseStatus::Verified),
        detail: Some("ok".into()),
    };
    sink.emit(event.clone());
    let records = recorder.records.lock().unwrap().clone();
    assert_eq!(records.len(), 1);
    let decoded: VerifierTelemetryEvent = serde_json::from_str(&records[0]).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn jsonl_telemetry_recorder_writes_newline_delimited_records() {
    let writer = Arc::new(BufferingTelemetryLineWriter::default());
    let recorder = JsonlTelemetryRecorder::new(writer.clone());
    recorder.record("{\"event\":1}".to_string());
    let records = writer.records.lock().unwrap().clone();
    assert_eq!(records, vec!["{\"event\":1}\n".to_string()]);
}

#[test]
fn telemetry_sink_records_request_response_and_mapped_events() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
    let input = match SGX_DCAP_ADAPTER
        .build_verifier_input(&handoff, None)
        .unwrap()
    {
        TeeVerifierInput::Quote(input) => input,
        TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
    };
    let sink = Arc::new(RecordingTelemetrySink::default());
    let provider = ClientBackedIntelQuoteVerifierProvider::with_telemetry_sink(
        Arc::new(AssertingExternalIntelQuoteClient),
        Arc::new(StaticVerifierTransportConfigSource::external_defaults()),
        sink.clone(),
    );
    let result = provider.verify_intel_quote_bundle(
        &input,
        &BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data,
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        },
    );
    assert!(
        matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-external-mock-client")
    );
    let events = sink.events.lock().unwrap().clone();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0].kind, VerifierTelemetryEventKind::RequestPrepared);
    assert_eq!(events[1].kind, VerifierTelemetryEventKind::ResponseReceived);
    assert_eq!(events[2].kind, VerifierTelemetryEventKind::ResponseMapped);
    assert_eq!(events[0].request_id, events[1].request_id);
    assert_eq!(events[1].request_id, events[2].request_id);
}
