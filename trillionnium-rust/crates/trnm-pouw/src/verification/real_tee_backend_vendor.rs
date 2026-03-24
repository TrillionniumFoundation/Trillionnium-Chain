use super::*;

trait VendorVerifierExecutor: Send + Sync {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;

    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

fn verify_fixture_intel_client_request(
    input: &IntelQuoteVerifierClientRequest,
    fixture: &TeeFixture,
    request: &BackendVerificationRequest<'_>,
) -> Result<(), BackendExecutionError> {
    match &fixture.verifier_input {
        TeeVerifierInput::Quote(expected) => {
            if input.measurement_field != expected.measurement_field {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation target '{}' requires measurement field '{}'",
                        input.attestation_target, expected.measurement_field
                    ),
                });
            }
            if input.measurement != expected.measurement {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation {} '{}' does not match target '{}' fixture",
                        input.measurement_field, input.measurement, input.attestation_target
                    ),
                });
            }
            if input.quote != expected.quote {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation quote does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.intel_collateral.collateral != expected.intel_collateral.collateral {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation collateral does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.intel_collateral.cert_chain != expected.intel_collateral.cert_chain {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation cert_chain does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.intel_collateral.issuer != expected.intel_collateral.issuer {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation issuer does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.report_data_hash != expected.report_data_hash {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation report_data_hash does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            Ok(())
        }
        TeeVerifierInput::Report(expected) => Err(BackendExecutionError::InvalidProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "tee attestation target '{}' requires {} handoff",
                input.attestation_target, expected.verifier_kind
            ),
        }),
    }
}

fn verify_fixture_amd_client_request(
    input: &AmdReportVerifierClientRequest,
    fixture: &TeeFixture,
    request: &BackendVerificationRequest<'_>,
) -> Result<(), BackendExecutionError> {
    match &fixture.verifier_input {
        TeeVerifierInput::Report(expected) => {
            if input.measurement_field != expected.measurement_field {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation target '{}' requires measurement field '{}'",
                        input.attestation_target, expected.measurement_field
                    ),
                });
            }
            if input.measurement != expected.measurement {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation {} '{}' does not match target '{}' fixture",
                        input.measurement_field, input.measurement, input.attestation_target
                    ),
                });
            }
            if input.report != expected.report {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation report does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.amd_signer.vcek != expected.amd_signer.vcek {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation vcek does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.amd_signer.cert_chain != expected.amd_signer.cert_chain {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation cert_chain does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.amd_signer.report_signer != expected.amd_signer.report_signer {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation report_signer does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            if input.report_data_hash != expected.report_data_hash {
                return Err(BackendExecutionError::InvalidProof {
                    backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    reason: format!(
                        "tee attestation report_data_hash does not match target '{}' fixture",
                        input.attestation_target
                    ),
                });
            }
            Ok(())
        }
        TeeVerifierInput::Quote(expected) => Err(BackendExecutionError::InvalidProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "tee attestation target '{}' requires {} handoff",
                input.attestation_target, expected.verifier_kind
            ),
        }),
    }
}

#[allow(dead_code)]
struct HttpBackedIntelQuoteVerifierClient {
    transport: Arc<dyn VerifierHttpTransport>,
    retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
    profile_resolver: Arc<dyn VerifierProfileResolver>,
    auth_injector: Arc<dyn VerifierAuthInjector>,
}

impl HttpBackedIntelQuoteVerifierClient {
    #[allow(dead_code)]
    fn new(transport: Arc<dyn VerifierHttpTransport>) -> Self {
        Self::with_retry_executor(transport, Arc::new(PolicyAwareHttpRetryExecutor))
    }

    #[allow(dead_code)]
    fn with_retry_executor(
        transport: Arc<dyn VerifierHttpTransport>,
        retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
    ) -> Self {
        Self {
            transport,
            retry_executor,
            profile_resolver: Arc::new(
                RegistryBackedVerifierProfileResolver::with_builtin_defaults(),
            ),
            auth_injector: Arc::new(HeaderVerifierAuthInjector),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_components(
        transport: Arc<dyn VerifierHttpTransport>,
        retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
        profile_resolver: Arc<dyn VerifierProfileResolver>,
        auth_injector: Arc<dyn VerifierAuthInjector>,
    ) -> Self {
        Self {
            transport,
            retry_executor,
            profile_resolver,
            auth_injector,
        }
    }
}

impl IntelQuoteVerifierClient for HttpBackedIntelQuoteVerifierClient {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        let profile = self
            .profile_resolver
            .resolve(&request_input.transport, request)?;
        let mut headers = build_http_headers(&profile, &request_input.call_metadata);
        self.auth_injector
            .inject(&request_input.transport, &mut headers, request)?;
        let http_request = build_intel_quote_http_request(request_input, &profile, headers)?;
        let execution =
            self.retry_executor
                .execute(self.transport.as_ref(), &http_request, request)?;
        decode_http_verifier_response(&execution.response, request)
    }
}

#[allow(dead_code)]
struct HttpBackedAmdReportVerifierClient {
    transport: Arc<dyn VerifierHttpTransport>,
    retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
    profile_resolver: Arc<dyn VerifierProfileResolver>,
    auth_injector: Arc<dyn VerifierAuthInjector>,
}

impl HttpBackedAmdReportVerifierClient {
    #[allow(dead_code)]
    fn new(transport: Arc<dyn VerifierHttpTransport>) -> Self {
        Self::with_retry_executor(transport, Arc::new(PolicyAwareHttpRetryExecutor))
    }

    #[allow(dead_code)]
    fn with_retry_executor(
        transport: Arc<dyn VerifierHttpTransport>,
        retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
    ) -> Self {
        Self {
            transport,
            retry_executor,
            profile_resolver: Arc::new(
                RegistryBackedVerifierProfileResolver::with_builtin_defaults(),
            ),
            auth_injector: Arc::new(HeaderVerifierAuthInjector),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_components(
        transport: Arc<dyn VerifierHttpTransport>,
        retry_executor: Arc<dyn VerifierHttpRetryExecutor>,
        profile_resolver: Arc<dyn VerifierProfileResolver>,
        auth_injector: Arc<dyn VerifierAuthInjector>,
    ) -> Self {
        Self {
            transport,
            retry_executor,
            profile_resolver,
            auth_injector,
        }
    }
}

impl AmdReportVerifierClient for HttpBackedAmdReportVerifierClient {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        let profile = self
            .profile_resolver
            .resolve(&request_input.transport, request)?;
        let mut headers = build_http_headers(&profile, &request_input.call_metadata);
        self.auth_injector
            .inject(&request_input.transport, &mut headers, request)?;
        let http_request = build_amd_report_http_request(request_input, &profile, headers)?;
        let execution =
            self.retry_executor
                .execute(self.transport.as_ref(), &http_request, request)?;
        decode_http_verifier_response(&execution.response, request)
    }
}

struct FixtureBackedIntelQuoteVerifierClient {
    fixtures: Vec<TeeFixture>,
}

impl FixtureBackedIntelQuoteVerifierClient {
    fn new(fixtures: Vec<TeeFixture>) -> Self {
        Self { fixtures }
    }

    fn fixture_for_target<'a>(
        &'a self,
        attestation_target: &str,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<&'a TeeFixture, BackendExecutionError> {
        self.fixtures
            .iter()
            .find(|fixture| fixture.verifier_input.attestation_target() == attestation_target)
            .ok_or_else(|| BackendExecutionError::Unavailable {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "no embedded attestation vector registered for target '{}'",
                    attestation_target
                ),
            })
    }
}

impl IntelQuoteVerifierClient for FixtureBackedIntelQuoteVerifierClient {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        let fixture = self.fixture_for_target(&request_input.attestation_target, request)?;
        let mut response = mock_response_from_fixture_result(
            verify_fixture_intel_client_request(request_input, fixture, request),
            fixture.backend_id.clone(),
        );
        response.telemetry_event = Some(build_response_telemetry_event(
            &request_input.call_metadata,
            &request_input.transport,
            &response,
        ));
        let raw = encode_mock_verifier_response_json(&response)?;
        decode_mock_verifier_response_json(&raw, request)
    }
}

struct FixtureBackedAmdReportVerifierClient {
    fixtures: Vec<TeeFixture>,
}

impl FixtureBackedAmdReportVerifierClient {
    fn new(fixtures: Vec<TeeFixture>) -> Self {
        Self { fixtures }
    }

    fn fixture_for_target<'a>(
        &'a self,
        attestation_target: &str,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<&'a TeeFixture, BackendExecutionError> {
        self.fixtures
            .iter()
            .find(|fixture| fixture.verifier_input.attestation_target() == attestation_target)
            .ok_or_else(|| BackendExecutionError::Unavailable {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "no embedded attestation vector registered for target '{}'",
                    attestation_target
                ),
            })
    }
}

impl AmdReportVerifierClient for FixtureBackedAmdReportVerifierClient {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError> {
        let fixture = self.fixture_for_target(&request_input.attestation_target, request)?;
        let mut response = mock_response_from_fixture_result(
            verify_fixture_amd_client_request(request_input, fixture, request),
            fixture.backend_id.clone(),
        );
        response.telemetry_event = Some(build_response_telemetry_event(
            &request_input.call_metadata,
            &request_input.transport,
            &response,
        ));
        let raw = encode_mock_verifier_response_json(&response)?;
        decode_mock_verifier_response_json(&raw, request)
    }
}

struct ClientBackedIntelQuoteVerifierProvider {
    client: Arc<dyn IntelQuoteVerifierClient>,
    config_source: Arc<dyn VerifierTransportConfigSource>,
    telemetry_sink: Arc<dyn VerifierTelemetrySink>,
}

impl ClientBackedIntelQuoteVerifierProvider {
    fn new(
        client: Arc<dyn IntelQuoteVerifierClient>,
        config_source: Arc<dyn VerifierTransportConfigSource>,
    ) -> Self {
        Self::with_telemetry_sink(client, config_source, Arc::new(NoopVerifierTelemetrySink))
    }

    fn with_telemetry_sink(
        client: Arc<dyn IntelQuoteVerifierClient>,
        config_source: Arc<dyn VerifierTransportConfigSource>,
        telemetry_sink: Arc<dyn VerifierTelemetrySink>,
    ) -> Self {
        Self {
            client,
            config_source,
            telemetry_sink,
        }
    }
}

impl IntelQuoteVerifierProvider for ClientBackedIntelQuoteVerifierProvider {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let transport = self
            .config_source
            .intel_quote_transport_config(&input.attestation_target);
        validate_transport_auth_and_profile(
            &transport,
            request,
            &input.verifier_kind,
            &input.attestation_target,
        )?;
        let call_metadata = build_external_call_metadata(
            request,
            &input.verifier_kind,
            &input.attestation_target,
            &transport,
        );
        let request_event = build_request_telemetry_event(&call_metadata, &transport);
        self.telemetry_sink.emit(request_event.clone());
        let client_request = IntelQuoteVerifierClientRequest {
            request_event,
            call_metadata,
            transport,
            attestation_target: input.attestation_target.clone(),
            measurement_field: input.measurement_field.clone(),
            measurement: input.measurement.clone(),
            report_data_hash: input.report_data_hash.clone(),
            quote: input.quote.clone(),
            intel_collateral: input.intel_collateral.clone(),
        };
        let response = self
            .client
            .verify_intel_quote_request(&client_request, request)?;
        validate_response_telemetry_event(&response, &client_request.call_metadata, request)?;
        if let Some(event) = response.telemetry_event.clone() {
            self.telemetry_sink.emit(event);
        }
        let mapped_event = build_mapped_telemetry_event(
            &client_request.call_metadata,
            &client_request.transport,
            &response,
        );
        self.telemetry_sink.emit(mapped_event);
        map_mock_verifier_response(response, request)
    }
}

struct ClientBackedAmdReportVerifierProvider {
    client: Arc<dyn AmdReportVerifierClient>,
    config_source: Arc<dyn VerifierTransportConfigSource>,
    telemetry_sink: Arc<dyn VerifierTelemetrySink>,
}

impl ClientBackedAmdReportVerifierProvider {
    fn new(
        client: Arc<dyn AmdReportVerifierClient>,
        config_source: Arc<dyn VerifierTransportConfigSource>,
    ) -> Self {
        Self::with_telemetry_sink(client, config_source, Arc::new(NoopVerifierTelemetrySink))
    }

    fn with_telemetry_sink(
        client: Arc<dyn AmdReportVerifierClient>,
        config_source: Arc<dyn VerifierTransportConfigSource>,
        telemetry_sink: Arc<dyn VerifierTelemetrySink>,
    ) -> Self {
        Self {
            client,
            config_source,
            telemetry_sink,
        }
    }
}

impl AmdReportVerifierProvider for ClientBackedAmdReportVerifierProvider {
    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let transport = self
            .config_source
            .amd_report_transport_config(&input.attestation_target);
        validate_transport_auth_and_profile(
            &transport,
            request,
            &input.verifier_kind,
            &input.attestation_target,
        )?;
        let call_metadata = build_external_call_metadata(
            request,
            &input.verifier_kind,
            &input.attestation_target,
            &transport,
        );
        let request_event = build_request_telemetry_event(&call_metadata, &transport);
        self.telemetry_sink.emit(request_event.clone());
        let client_request = AmdReportVerifierClientRequest {
            request_event,
            call_metadata,
            transport,
            attestation_target: input.attestation_target.clone(),
            measurement_field: input.measurement_field.clone(),
            measurement: input.measurement.clone(),
            report_data_hash: input.report_data_hash.clone(),
            report: input.report.clone(),
            amd_signer: input.amd_signer.clone(),
        };
        let response = self
            .client
            .verify_amd_report_request(&client_request, request)?;
        validate_response_telemetry_event(&response, &client_request.call_metadata, request)?;
        if let Some(event) = response.telemetry_event.clone() {
            self.telemetry_sink.emit(event);
        }
        let mapped_event = build_mapped_telemetry_event(
            &client_request.call_metadata,
            &client_request.transport,
            &response,
        );
        self.telemetry_sink.emit(mapped_event);
        map_mock_verifier_response(response, request)
    }
}

struct ProviderBackedVendorVerifierExecutor {
    intel_quote_provider: Arc<dyn IntelQuoteVerifierProvider>,
    amd_report_provider: Arc<dyn AmdReportVerifierProvider>,
}

impl ProviderBackedVendorVerifierExecutor {
    fn new(
        intel_quote_provider: Arc<dyn IntelQuoteVerifierProvider>,
        amd_report_provider: Arc<dyn AmdReportVerifierProvider>,
    ) -> Self {
        Self {
            intel_quote_provider,
            amd_report_provider,
        }
    }

    fn fixture_backed() -> Self {
        let fixtures = load_embedded_fixtures();
        let config_source = Arc::new(EnvVerifierTransportConfigSource::from_env(
            StaticVerifierTransportConfigSource::mock_defaults(),
        ));
        Self::new(
            Arc::new(ClientBackedIntelQuoteVerifierProvider::new(
                Arc::new(FixtureBackedIntelQuoteVerifierClient::new(fixtures.clone())),
                config_source.clone(),
            )),
            Arc::new(ClientBackedAmdReportVerifierProvider::new(
                Arc::new(FixtureBackedAmdReportVerifierClient::new(fixtures)),
                config_source,
            )),
        )
    }
}

impl VendorVerifierExecutor for ProviderBackedVendorVerifierExecutor {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        self.intel_quote_provider
            .verify_intel_quote_bundle(input, request)
    }

    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        self.amd_report_provider
            .verify_amd_report_bundle(input, request)
    }
}

pub struct RealTeeBackend {
    executor: Arc<dyn VendorVerifierExecutor>,
}
