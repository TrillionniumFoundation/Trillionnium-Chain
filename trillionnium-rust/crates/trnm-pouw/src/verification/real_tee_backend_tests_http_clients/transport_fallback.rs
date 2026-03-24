use super::*;

#[test]
fn real_http_transport_timeout_hook_fails_closed_before_execute() {
    let task = mock_task();
    let transport = RealVerifierHttpTransport::with_components(
        Arc::new(PanicHttpRequestExecutor),
        Arc::new(Utf8HttpResponseBodyReader),
        Arc::new(RejectingHttpTimeoutHook),
    );
    let err = transport
        .send(
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
    assert!(
        matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("timeout hook rejected transport execution"))
    );
}

#[test]
fn real_http_transport_stub_fails_closed_unavailable() {
    let task = mock_task();
    let err = RealVerifierHttpTransport::new()
        .send(
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
    assert!(
        matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("intel-dcap-external-default") && reason.contains("client session protocol chunk termination token fragment slice shard unit cell atom exchange"))
    );
}

#[test]
fn http_backed_intel_client_skeleton_encodes_request_and_decodes_response() {
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
    let provider = ClientBackedIntelQuoteVerifierProvider::new(
        Arc::new(HttpBackedIntelQuoteVerifierClient::new(Arc::new(
            AssertingIntelHttpTransport,
        ))),
        Arc::new(StaticVerifierTransportConfigSource::external_defaults()),
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
        matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-http-transport")
    );
}

#[test]
fn http_backed_amd_client_skeleton_encodes_request_and_decodes_response() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
    let input = match SEV_SNP_ADAPTER
        .build_verifier_input(&handoff, None)
        .unwrap()
    {
        TeeVerifierInput::Report(input) => input,
        TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
    };
    let provider = ClientBackedAmdReportVerifierProvider::new(
        Arc::new(HttpBackedAmdReportVerifierClient::new(Arc::new(
            AssertingAmdHttpTransport,
        ))),
        Arc::new(StaticVerifierTransportConfigSource::external_defaults()),
    );
    let result = provider.verify_amd_report_bundle(
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
        matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-http-transport")
    );
}

#[test]
fn http_backed_intel_client_maps_http_503_to_unavailable() {
    let task = mock_task();
    let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
    let client = HttpBackedIntelQuoteVerifierClient::new(Arc::new(Http503IntelTransport));
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
        matches!(result, Err(BackendExecutionError::Unavailable { reason, .. }) if reason.contains("status 503"))
    );
}

#[test]
fn client_backed_intel_provider_uses_external_transport_profile_when_injected() {
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
    let provider = ClientBackedIntelQuoteVerifierProvider::new(
        Arc::new(AssertingExternalIntelQuoteClient),
        Arc::new(StaticVerifierTransportConfigSource::external_defaults()),
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
}

#[test]
fn client_backed_amd_provider_uses_external_transport_profile_when_injected() {
    let task = mock_task();
    let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
    let payload = parse_tee_attestation_payload(proof_data).unwrap();
    let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
    let input = match SEV_SNP_ADAPTER
        .build_verifier_input(&handoff, None)
        .unwrap()
    {
        TeeVerifierInput::Report(input) => input,
        TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
    };
    let provider = ClientBackedAmdReportVerifierProvider::new(
        Arc::new(AssertingExternalAmdReportClient),
        Arc::new(StaticVerifierTransportConfigSource::external_defaults()),
    );
    let result = provider.verify_amd_report_bundle(
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
        matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-external-mock-client")
    );
}
