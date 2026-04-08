use super::*;

impl TeeVerifierInput {
    fn attestation_target(&self) -> &str {
        match self {
            Self::Quote(input) => &input.attestation_target,
            Self::Report(input) => &input.attestation_target,
        }
    }
}

#[derive(Debug, Clone)]
struct TeeFixture {
    backend_id: String,
    verifier_input: TeeVerifierInput,
}

impl TeeFixture {
    fn from_embedded_json(raw: &str) -> Self {
        let manifest: TeeFixtureManifest =
            serde_json::from_str(raw).expect("embedded tee fixture manifest must be valid json");
        let receipt = synthetic_receipt_for_manifest(&manifest);
        let payload = parse_tee_attestation_payload(receipt.as_bytes())
            .expect("embedded tee fixture must satisfy TEE payload contract");
        let handoff = TeeVerifierHandoff::from_payload(&payload, None)
            .expect("embedded tee fixture payload must build handoff");
        let adapter = resolve_target_adapter(&handoff.attestation_target)
            .expect("embedded tee fixture target must resolve to adapter");
        let verifier_input = adapter
            .build_verifier_input(&handoff, None)
            .expect("embedded tee fixture handoff must build verifier input");
        Self {
            backend_id: manifest.backend_id,
            verifier_input,
        }
    }
}

impl TeeVerifierHandoff {
    fn from_payload(
        payload: &ParsedTeeProofPayload,
        request: Option<&BackendVerificationRequest<'_>>,
    ) -> Result<Self, BackendExecutionError> {
        let evidence = payload.evidence().ok_or_else(|| {
            malformed_payload_err(
                request,
                format!(
                    "invalid tee receipt: target '{}' requires {} evidence",
                    payload.attestation_target,
                    payload.evidence_kind.as_str()
                ),
            )
        })?;

        Ok(Self {
            attestation_target: payload.attestation_target.clone(),
            verifier_kind: payload.verifier_kind.clone(),
            measurement_field: payload.measurement_field.clone(),
            measurement: payload.measurement.clone(),
            report_data_hash: payload.report_data_hash.clone(),
            evidence_kind: payload.evidence_kind,
            evidence: evidence.to_string(),
            verifier_metadata: payload.verifier_metadata.clone(),
        })
    }
}

trait TeeTargetAdapter: Send + Sync {
    fn attestation_target(&self) -> &'static str;
    fn verifier_kind(&self) -> &'static str;
    fn evidence_kind(&self) -> TeeEvidenceKind;
    fn measurement_field(&self) -> &'static str;

    fn build_verifier_input(
        &self,
        handoff: &TeeVerifierHandoff,
        request: Option<&BackendVerificationRequest<'_>>,
    ) -> Result<TeeVerifierInput, BackendExecutionError>;
}

struct SgxDcapAdapter;
struct TdxQgsAdapter;
struct SevSnpAdapter;

static SGX_DCAP_ADAPTER: SgxDcapAdapter = SgxDcapAdapter;
static TDX_QGS_ADAPTER: TdxQgsAdapter = TdxQgsAdapter;
static SEV_SNP_ADAPTER: SevSnpAdapter = SevSnpAdapter;

impl TeeTargetAdapter for SgxDcapAdapter {
    fn attestation_target(&self) -> &'static str {
        "sgx-dcap"
    }

    fn verifier_kind(&self) -> &'static str {
        "quote-verifier"
    }

    fn evidence_kind(&self) -> TeeEvidenceKind {
        TeeEvidenceKind::Quote
    }

    fn measurement_field(&self) -> &'static str {
        "mrenclave"
    }

    fn build_verifier_input(
        &self,
        handoff: &TeeVerifierHandoff,
        request: Option<&BackendVerificationRequest<'_>>,
    ) -> Result<TeeVerifierInput, BackendExecutionError> {
        ensure_handoff_contract(self, handoff, request)?;
        Ok(TeeVerifierInput::Quote(QuoteVerifierInput {
            attestation_target: handoff.attestation_target.clone(),
            verifier_kind: handoff.verifier_kind.clone(),
            measurement_field: handoff.measurement_field.clone(),
            measurement: handoff.measurement.clone(),
            report_data_hash: handoff.report_data_hash.clone(),
            quote: handoff.evidence.clone(),
            intel_collateral: IntelQuoteCollateralBundle {
                collateral: required_metadata(
                    handoff.verifier_metadata.collateral.as_deref(),
                    "collateral",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                cert_chain: required_metadata(
                    handoff.verifier_metadata.cert_chain.as_deref(),
                    "cert_chain",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                issuer: required_metadata(
                    handoff.verifier_metadata.issuer.as_deref(),
                    "issuer",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
            },
        }))
    }
}

impl TeeTargetAdapter for TdxQgsAdapter {
    fn attestation_target(&self) -> &'static str {
        "tdx-qgs"
    }

    fn verifier_kind(&self) -> &'static str {
        "quote-verifier"
    }

    fn evidence_kind(&self) -> TeeEvidenceKind {
        TeeEvidenceKind::Quote
    }

    fn measurement_field(&self) -> &'static str {
        "mrtd"
    }

    fn build_verifier_input(
        &self,
        handoff: &TeeVerifierHandoff,
        request: Option<&BackendVerificationRequest<'_>>,
    ) -> Result<TeeVerifierInput, BackendExecutionError> {
        ensure_handoff_contract(self, handoff, request)?;
        Ok(TeeVerifierInput::Quote(QuoteVerifierInput {
            attestation_target: handoff.attestation_target.clone(),
            verifier_kind: handoff.verifier_kind.clone(),
            measurement_field: handoff.measurement_field.clone(),
            measurement: handoff.measurement.clone(),
            report_data_hash: handoff.report_data_hash.clone(),
            quote: handoff.evidence.clone(),
            intel_collateral: IntelQuoteCollateralBundle {
                collateral: required_metadata(
                    handoff.verifier_metadata.collateral.as_deref(),
                    "collateral",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                cert_chain: required_metadata(
                    handoff.verifier_metadata.cert_chain.as_deref(),
                    "cert_chain",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                issuer: required_metadata(
                    handoff.verifier_metadata.issuer.as_deref(),
                    "issuer",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
            },
        }))
    }
}

impl TeeTargetAdapter for SevSnpAdapter {
    fn attestation_target(&self) -> &'static str {
        "sev-snp"
    }

    fn verifier_kind(&self) -> &'static str {
        "report-verifier"
    }

    fn evidence_kind(&self) -> TeeEvidenceKind {
        TeeEvidenceKind::Report
    }

    fn measurement_field(&self) -> &'static str {
        "measurement"
    }

    fn build_verifier_input(
        &self,
        handoff: &TeeVerifierHandoff,
        request: Option<&BackendVerificationRequest<'_>>,
    ) -> Result<TeeVerifierInput, BackendExecutionError> {
        ensure_handoff_contract(self, handoff, request)?;
        Ok(TeeVerifierInput::Report(ReportVerifierInput {
            attestation_target: handoff.attestation_target.clone(),
            verifier_kind: handoff.verifier_kind.clone(),
            measurement_field: handoff.measurement_field.clone(),
            measurement: handoff.measurement.clone(),
            report_data_hash: handoff.report_data_hash.clone(),
            report: handoff.evidence.clone(),
            amd_signer: AmdSnpSignerBundle {
                vcek: required_metadata(
                    handoff.verifier_metadata.vcek.as_deref(),
                    "vcek",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                cert_chain: required_metadata(
                    handoff.verifier_metadata.cert_chain.as_deref(),
                    "cert_chain",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
                report_signer: required_metadata(
                    handoff.verifier_metadata.report_signer.as_deref(),
                    "report_signer",
                    handoff.attestation_target.as_str(),
                    request,
                )?,
            },
        }))
    }
}

fn resolve_target_adapter(attestation_target: &str) -> Option<&'static dyn TeeTargetAdapter> {
    match attestation_target {
        "sgx-dcap" => Some(&SGX_DCAP_ADAPTER),
        "tdx-qgs" => Some(&TDX_QGS_ADAPTER),
        "sev-snp" => Some(&SEV_SNP_ADAPTER),
        _ => None,
    }
}

fn ensure_handoff_contract(
    adapter: &dyn TeeTargetAdapter,
    handoff: &TeeVerifierHandoff,
    request: Option<&BackendVerificationRequest<'_>>,
) -> Result<(), BackendExecutionError> {
    if handoff.attestation_target != adapter.attestation_target() {
        return Err(invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' does not match adapter '{}'",
                handoff.attestation_target,
                adapter.attestation_target()
            ),
        ));
    }

    if handoff.verifier_kind != adapter.verifier_kind() {
        return Err(invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' requires {} handoff",
                handoff.attestation_target,
                adapter.verifier_kind()
            ),
        ));
    }

    if handoff.evidence_kind != adapter.evidence_kind() {
        return Err(invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' requires {} evidence",
                handoff.attestation_target,
                adapter.evidence_kind().as_str()
            ),
        ));
    }

    if handoff.measurement_field != adapter.measurement_field() {
        return Err(invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' requires measurement field '{}'",
                handoff.attestation_target,
                adapter.measurement_field()
            ),
        ));
    }

    match adapter.evidence_kind() {
        TeeEvidenceKind::Quote => {
            if handoff.verifier_metadata.vcek.is_some()
                || handoff.verifier_metadata.report_signer.is_some()
            {
                return Err(invalid_backend_input_err(
                    request,
                    format!(
                        "tee attestation target '{}' does not accept report verifier metadata",
                        handoff.attestation_target
                    ),
                ));
            }
        }
        TeeEvidenceKind::Report => {
            if handoff.verifier_metadata.collateral.is_some()
                || handoff.verifier_metadata.issuer.is_some()
            {
                return Err(invalid_backend_input_err(
                    request,
                    format!(
                        "tee attestation target '{}' does not accept quote verifier metadata",
                        handoff.attestation_target
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn malformed_payload_err(
    request: Option<&BackendVerificationRequest<'_>>,
    reason: String,
) -> BackendExecutionError {
    BackendExecutionError::MalformedProof {
        backend: request
            .map(|request| request.backend_label(RealTeeBackend::backend_id_static()))
            .unwrap_or_else(|| "tee:payload".to_string()),
        reason,
    }
}

fn invalid_backend_input_err(
    request: Option<&BackendVerificationRequest<'_>>,
    reason: String,
) -> BackendExecutionError {
    BackendExecutionError::InvalidProof {
        backend: request
            .map(|request| request.backend_label(RealTeeBackend::backend_id_static()))
            .unwrap_or_else(|| "tee:payload".to_string()),
        reason,
    }
}

fn required_metadata(
    value: Option<&str>,
    field: &str,
    attestation_target: &str,
    request: Option<&BackendVerificationRequest<'_>>,
) -> Result<String, BackendExecutionError> {
    value.map(str::to_string).ok_or_else(|| {
        invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' requires {} metadata",
                attestation_target, field
            ),
        )
    })
}
