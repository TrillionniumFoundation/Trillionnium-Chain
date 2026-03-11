use std::sync::Arc;

use serde::Deserialize;

use crate::verification::backend::{
    parse_tee_attestation_payload, BackendExecutionError, BackendVerificationRequest,
    BackendVerificationSuccess, ParsedTeeProofPayload, TeeEvidenceKind, TeeVerifierMetadata,
    VerificationBackend, VerificationBackendFamily, ZkBackendRegistry,
};
#[cfg(test)]
use crate::verification::backend::{VerificationBackendConfig, VerificationBackendKind};
#[cfg(test)]
use crate::verification::{registry::VerifierRegistry, VerificationResult};
#[cfg(test)]
use trnm_types::{ProofType, TaskObject, TaskStatus};

#[derive(Debug, Clone, Deserialize)]
struct TeeFixtureManifest {
    backend_id: String,
    attestation_target: String,
    measurement: String,
    report_data_hash: String,
    #[serde(default)]
    quote: Option<String>,
    #[serde(default)]
    report: Option<String>,
    #[serde(default)]
    collateral: Option<String>,
    #[serde(default)]
    cert_chain: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    vcek: Option<String>,
    #[serde(default)]
    report_signer: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TeeVerifierHandoff {
    attestation_target: String,
    verifier_kind: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    evidence_kind: TeeEvidenceKind,
    evidence: String,
    verifier_metadata: TeeVerifierMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntelQuoteCollateralBundle {
    collateral: String,
    cert_chain: String,
    issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmdSnpSignerBundle {
    vcek: String,
    cert_chain: String,
    report_signer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QuoteVerifierInput {
    attestation_target: String,
    verifier_kind: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    quote: String,
    intel_collateral: IntelQuoteCollateralBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportVerifierInput {
    attestation_target: String,
    verifier_kind: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    report: String,
    amd_signer: AmdSnpSignerBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TeeVerifierInput {
    Quote(QuoteVerifierInput),
    Report(ReportVerifierInput),
}

impl TeeVerifierInput {
    fn attestation_target(&self) -> &str {
        match self {
            Self::Quote(input) => &input.attestation_target,
            Self::Report(input) => &input.attestation_target,
        }
    }

    fn verifier_kind(&self) -> &str {
        match self {
            Self::Quote(input) => &input.verifier_kind,
            Self::Report(input) => &input.verifier_kind,
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
        let evidence = payload.evidence().ok_or_else(|| malformed_payload_err(
            request,
            format!(
                "invalid tee receipt: target '{}' requires {} evidence",
                payload.attestation_target,
                payload.evidence_kind.as_str()
            ),
        ))?;

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
    value
        .map(str::to_string)
        .ok_or_else(|| invalid_backend_input_err(
            request,
            format!(
                "tee attestation target '{}' requires {} metadata",
                attestation_target, field
            ),
        ))
}

fn verify_fixture_input(
    input: &TeeVerifierInput,
    fixture: &TeeFixture,
    request: &BackendVerificationRequest<'_>,
) -> Result<(), BackendExecutionError> {
    match (input, &fixture.verifier_input) {
        (TeeVerifierInput::Quote(input), TeeVerifierInput::Quote(expected)) => {
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
        (TeeVerifierInput::Report(input), TeeVerifierInput::Report(expected)) => {
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
        (input, expected) => Err(BackendExecutionError::InvalidProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "tee attestation target '{}' requires {} handoff",
                input.attestation_target(),
                expected.verifier_kind()
            ),
        }),
    }
}

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

struct FixtureBackedVendorVerifierExecutor {
    fixtures: Vec<TeeFixture>,
}

impl FixtureBackedVendorVerifierExecutor {
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

impl VendorVerifierExecutor for FixtureBackedVendorVerifierExecutor {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let fixture = self.fixture_for_target(&input.attestation_target, request)?;
        verify_fixture_input(&TeeVerifierInput::Quote(input.clone()), fixture, request)?;
        Ok(BackendVerificationSuccess {
            backend_id: fixture.backend_id.clone(),
        })
    }

    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        let fixture = self.fixture_for_target(&input.attestation_target, request)?;
        verify_fixture_input(&TeeVerifierInput::Report(input.clone()), fixture, request)?;
        Ok(BackendVerificationSuccess {
            backend_id: fixture.backend_id.clone(),
        })
    }
}

pub struct RealTeeBackend {
    executor: Arc<dyn VendorVerifierExecutor>,
}

impl Default for RealTeeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RealTeeBackend {
    pub fn new() -> Self {
        Self::with_executor(Arc::new(FixtureBackedVendorVerifierExecutor::new(
            load_embedded_fixtures(),
        )))
    }

    fn with_executor(executor: Arc<dyn VendorVerifierExecutor>) -> Self {
        Self { executor }
    }

    const fn backend_id_static() -> &'static str {
        "real-tee-backend"
    }
}

impl VerificationBackend for RealTeeBackend {
    fn backend_id(&self) -> &str {
        Self::backend_id_static()
    }

    fn verify(
        &self,
        request: BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
        if request.family != VerificationBackendFamily::Tee {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "real tee backend only supports tee verification family".to_string(),
            });
        }

        let parsed = if let Some(payload) = request.tee_payload {
            payload.clone()
        } else {
            parse_tee_attestation_payload(request.proof_data)?
        };
        let expected_hash = request.task.result_hash.map(hex::encode).ok_or_else(|| {
            BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: "missing task result_hash binding context".to_string(),
            }
        })?;

        if parsed.report_data_hash != expected_hash {
            return Err(BackendExecutionError::InvalidProof {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "attestation report_data_hash '{}' does not match task result hash",
                    parsed.report_data_hash
                ),
            });
        }

        let handoff = TeeVerifierHandoff::from_payload(&parsed, Some(&request))?;
        let adapter = resolve_target_adapter(&handoff.attestation_target).ok_or_else(|| {
            BackendExecutionError::Unavailable {
                backend: request.backend_label(self.backend_id()),
                reason: format!(
                    "no target adapter registered for attestation target '{}'",
                    handoff.attestation_target
                ),
            }
        })?;
        let verifier_input = adapter.build_verifier_input(&handoff, Some(&request))?;

        match &verifier_input {
            TeeVerifierInput::Quote(input) => {
                self.executor.verify_intel_quote_bundle(input, &request)
            }
            TeeVerifierInput::Report(input) => {
                self.executor.verify_amd_report_bundle(input, &request)
            }
        }
    }
}

fn synthetic_receipt_for_manifest(manifest: &TeeFixtureManifest) -> String {
    let mut receipt = format!(
        "TEE:task_id=0,worker=fixture,proof_type=tee,result_hash={hash},attestation_target={target},measurement={measurement},report_data_hash={hash}",
        hash = manifest.report_data_hash.trim().to_ascii_lowercase(),
        target = manifest.attestation_target,
        measurement = manifest.measurement,
    );
    if let Some(quote) = manifest.quote.as_deref() {
        receipt.push_str(",quote=");
        receipt.push_str(quote);
    }
    if let Some(report) = manifest.report.as_deref() {
        receipt.push_str(",report=");
        receipt.push_str(report);
    }
    if let Some(collateral) = manifest.collateral.as_deref() {
        receipt.push_str(",collateral=");
        receipt.push_str(collateral);
    }
    if let Some(cert_chain) = manifest.cert_chain.as_deref() {
        receipt.push_str(",cert_chain=");
        receipt.push_str(cert_chain);
    }
    if let Some(issuer) = manifest.issuer.as_deref() {
        receipt.push_str(",issuer=");
        receipt.push_str(issuer);
    }
    if let Some(vcek) = manifest.vcek.as_deref() {
        receipt.push_str(",vcek=");
        receipt.push_str(vcek);
    }
    if let Some(report_signer) = manifest.report_signer.as_deref() {
        receipt.push_str(",report_signer=");
        receipt.push_str(report_signer);
    }
    receipt
}

fn load_embedded_fixtures() -> Vec<TeeFixture> {
    [
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/tee/sgx_dcap_valid.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/tee/tdx_qgs_valid.json"
        )),
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/tee/sev_snp_valid.json"
        )),
    ]
    .into_iter()
    .map(TeeFixture::from_embedded_json)
    .collect()
}

pub fn register_optional_backends(registry: &mut ZkBackendRegistry) {
    registry.register(Arc::new(RealTeeBackend::new()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_task() -> TaskObject {
        TaskObject {
            task_id: 42,
            creator: "alice".into(),
            bounty: 1,
            status: TaskStatus::Committed,
            proof_type: ProofType::Tee,
            metadata: None,
            worker: Some("worker1".into()),
            committed_hash: None,
            result_hash: Some([0x11; 32]),
            reveal_salt: None,
            committed_at_height: None,
            reveal_deadline_height: None,
            challenge_deadline_height: None,
            challenge_window_blocks_snapshot: None,
            challenged_at_height: None,
            resolve_deadline_height: None,
            challenge_bond: None,
            challenger: None,
            challenge_bond_forfeited: None,
            version: 1,
        }
    }

    fn tee_config() -> VerificationBackendConfig {
        VerificationBackendConfig {
            tee_backend: VerificationBackendKind::Custom("real-tee-backend".into()),
            ..VerificationBackendConfig::default()
        }
    }

    fn sgx_handoff() -> TeeVerifierHandoff {
        let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
        TeeVerifierHandoff::from_payload(&payload, None).unwrap()
    }

    fn snp_handoff() -> TeeVerifierHandoff {
        let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd").unwrap();
        TeeVerifierHandoff::from_payload(&payload, None).unwrap()
    }

    #[test]
    fn sgx_adapter_builds_quote_verifier_input() {
        let input = SGX_DCAP_ADAPTER
            .build_verifier_input(&sgx_handoff(), None)
            .unwrap();
        assert!(matches!(
            input,
            TeeVerifierInput::Quote(QuoteVerifierInput {
                attestation_target,
                verifier_kind,
                measurement_field,
                quote,
                intel_collateral,
                ..
            }) if attestation_target == "sgx-dcap"
                && verifier_kind == "quote-verifier"
                && measurement_field == "mrenclave"
                && quote == "quote-sgx-dcap-demo-v1"
                && intel_collateral.collateral == "intel-dcap-collateral-demo-v1"
                && intel_collateral.cert_chain == "intel-dcap-cert-chain-demo-v1"
                && intel_collateral.issuer == "intel"
        ));
    }

    #[test]
    fn snp_adapter_builds_report_verifier_input() {
        let input = SEV_SNP_ADAPTER
            .build_verifier_input(&snp_handoff(), None)
            .unwrap();
        assert!(matches!(
            input,
            TeeVerifierInput::Report(ReportVerifierInput {
                attestation_target,
                verifier_kind,
                measurement_field,
                report,
                amd_signer,
                ..
            }) if attestation_target == "sev-snp"
                && verifier_kind == "report-verifier"
                && measurement_field == "measurement"
                && report == "report-sev-snp-demo-v1"
                && amd_signer.vcek == "amd-vcek-demo-v1"
                && amd_signer.cert_chain == "amd-cert-chain-demo-v1"
                && amd_signer.report_signer == "amd"
        ));
    }

    struct AssertingIntelQuoteExecutor;

    impl VendorVerifierExecutor for AssertingIntelQuoteExecutor {
        fn verify_intel_quote_bundle(
            &self,
            input: &QuoteVerifierInput,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(input.attestation_target, "sgx-dcap");
            assert_eq!(input.verifier_kind, "quote-verifier");
            assert_eq!(input.measurement_field, "mrenclave");
            assert_eq!(input.quote, "quote-sgx-dcap-demo-v1");
            assert_eq!(input.intel_collateral.collateral, "intel-dcap-collateral-demo-v1");
            assert_eq!(input.intel_collateral.cert_chain, "intel-dcap-cert-chain-demo-v1");
            assert_eq!(input.intel_collateral.issuer, "intel");
            Ok(BackendVerificationSuccess {
                backend_id: "intel-mock-executor".into(),
            })
        }

        fn verify_amd_report_bundle(
            &self,
            _input: &ReportVerifierInput,
            request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "unexpected amd report path in intel executor test".to_string(),
            })
        }
    }

    struct AssertingAmdReportExecutor;

    impl VendorVerifierExecutor for AssertingAmdReportExecutor {
        fn verify_intel_quote_bundle(
            &self,
            _input: &QuoteVerifierInput,
            request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "unexpected intel quote path in amd executor test".to_string(),
            })
        }

        fn verify_amd_report_bundle(
            &self,
            input: &ReportVerifierInput,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            assert_eq!(input.attestation_target, "sev-snp");
            assert_eq!(input.verifier_kind, "report-verifier");
            assert_eq!(input.measurement_field, "measurement");
            assert_eq!(input.report, "report-sev-snp-demo-v1");
            assert_eq!(input.amd_signer.vcek, "amd-vcek-demo-v1");
            assert_eq!(input.amd_signer.cert_chain, "amd-cert-chain-demo-v1");
            assert_eq!(input.amd_signer.report_signer, "amd");
            Ok(BackendVerificationSuccess {
                backend_id: "amd-mock-executor".into(),
            })
        }
    }

    #[test]
    fn real_tee_backend_delegates_intel_quote_bundle_to_executor() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let backend = RealTeeBackend::with_executor(Arc::new(AssertingIntelQuoteExecutor));

        let result = backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data,
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        });

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-executor"
        ));
    }

    #[test]
    fn real_tee_backend_delegates_amd_report_bundle_to_executor() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let backend = RealTeeBackend::with_executor(Arc::new(AssertingAmdReportExecutor));

        let result = backend.verify(BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data,
            tee_payload: Some(&payload),
            zk_payload: None,
            resolved_vk_ref: None,
        });

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-executor"
        ));
    }

    #[test]
    fn real_tee_backend_accepts_valid_sgx_vector() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";

        assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
    }

    #[test]
    fn real_tee_backend_accepts_valid_tdx_vector() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-tdx-qgs-demo-v1,collateral=intel-tdx-qgs-collateral-demo-v1,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel";

        assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
    }

    #[test]
    fn real_tee_backend_accepts_valid_sev_snp_vector() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";

        assert_eq!(registry.verify(&task, receipt), VerificationResult::Valid);
    }

    #[test]
    fn real_tee_backend_rejects_unsupported_attestation_target_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=nitro-enclave,measurement=enclave:demo,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-demo";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("unsupported attestation_target 'nitro-enclave'")
        ));
    }

    #[test]
    fn real_tee_backend_rejects_missing_report_for_report_verifier_target_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("requires report evidence")
        ));
    }

    #[test]
    fn real_tee_backend_rejects_report_data_hash_mismatch_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=2222222222222222222222222222222222222222222222222222222222222222,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("report_data_hash") && msg.contains("does not match task result hash")
        ));
    }

    #[test]
    fn real_tee_backend_rejects_quote_metadata_mismatch_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=tdx-qgs,measurement=mrtd:demo-tdx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-tdx-qgs-demo-v1,collateral=wrong-collateral,cert_chain=intel-tdx-qgs-cert-chain-demo-v1,issuer=intel";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("collateral") && msg.contains("tdx-qgs")
        ));
    }

    #[test]
    fn real_tee_backend_rejects_report_signer_mismatch_fail_closed() {
        let registry = VerifierRegistry::with_backend_config(tee_config());
        let task = mock_task();
        let receipt = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=wrong-signer";

        assert!(matches!(
            registry.verify(&task, receipt),
            VerificationResult::Invalid(msg)
                if msg.contains("report_signer") && msg.contains("sev-snp")
        ));
    }
}
