use std::collections::BTreeMap;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntelQuoteCollateralBundle {
    collateral: String,
    cert_chain: String,
    issuer: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerifierTransportMode {
    Mock,
    External,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RetryBackoffStrategy {
    Fixed,
    Exponential,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RetryBackoffPolicy {
    max_attempts: u32,
    backoff_ms: u64,
    strategy: RetryBackoffStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifierTransportConfig {
    mode: VerifierTransportMode,
    profile: String,
    endpoint: String,
    timeout_ms: u64,
    auth_scheme: Option<String>,
    auth_ref: Option<String>,
    retry_policy: RetryBackoffPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ExternalCallMetadata {
    request_id: String,
    telemetry_scope: String,
    attempt: u32,
    retry_policy: RetryBackoffPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum VerifierTelemetryEventKind {
    RequestPrepared,
    ResponseReceived,
    ResponseMapped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifierTelemetryEvent {
    kind: VerifierTelemetryEventKind,
    request_id: String,
    telemetry_scope: String,
    transport_mode: VerifierTransportMode,
    profile: String,
    backend_id: Option<String>,
    status: Option<MockVerifierResponseStatus>,
    detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MockVerifierResponseStatus {
    Verified,
    Invalid,
    Unavailable,
    Malformed,
    Internal,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum HttpMethod {
    Post,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpVerifierRequest {
    method: HttpMethod,
    transport_mode: VerifierTransportMode,
    profile: String,
    url: String,
    headers: BTreeMap<String, String>,
    body: String,
    timeout_ms: u64,
    retry_policy: RetryBackoffPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedVerifierProfile {
    mode: VerifierTransportMode,
    profile: String,
    endpoint: String,
    timeout_ms: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpVerifierResponse {
    status_code: u16,
    body: String,
}

#[allow(dead_code)]
trait VerifierHttpTransport: Send + Sync {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError>;
}

trait VerifierProfileResolver: Send + Sync {
    fn resolve(
        &self,
        transport: &VerifierTransportConfig,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierProfile, BackendExecutionError>;
}

#[allow(dead_code)]
struct StaticVerifierProfileResolver;

impl VerifierProfileResolver for StaticVerifierProfileResolver {
    fn resolve(
        &self,
        transport: &VerifierTransportConfig,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierProfile, BackendExecutionError> {
        Ok(ResolvedVerifierProfile {
            mode: transport.mode.clone(),
            profile: transport.profile.clone(),
            endpoint: transport.endpoint.clone(),
            timeout_ms: transport.timeout_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct VerifierProfileRegistryEntry {
    profile: String,
    mode: VerifierTransportMode,
    endpoint_prefix: String,
    auth_required: bool,
}

#[derive(Debug, Clone, Default)]
struct RuntimeVerifierProfileRegistry {
    entries: BTreeMap<String, VerifierProfileRegistryEntry>,
}

impl RuntimeVerifierProfileRegistry {
    fn with_builtin_defaults() -> Self {
        let mut entries = BTreeMap::new();
        for entry in [
            VerifierProfileRegistryEntry {
                profile: "intel-dcap-mock-default".into(),
                mode: VerifierTransportMode::Mock,
                endpoint_prefix: "mock://intel-quote-verifier/".into(),
                auth_required: false,
            },
            VerifierProfileRegistryEntry {
                profile: "intel-dcap-external-default".into(),
                mode: VerifierTransportMode::External,
                endpoint_prefix: "https://intel-verifier.invalid/v1/quote/".into(),
                auth_required: true,
            },
            VerifierProfileRegistryEntry {
                profile: "amd-sev-snp-mock-default".into(),
                mode: VerifierTransportMode::Mock,
                endpoint_prefix: "mock://amd-report-verifier/".into(),
                auth_required: false,
            },
            VerifierProfileRegistryEntry {
                profile: "amd-sev-snp-external-default".into(),
                mode: VerifierTransportMode::External,
                endpoint_prefix: "https://amd-verifier.invalid/v1/report/".into(),
                auth_required: true,
            },
        ] {
            entries.insert(entry.profile.clone(), entry);
        }
        Self { entries }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn from_entries(entries: Vec<VerifierProfileRegistryEntry>) -> Self {
        let mut map = BTreeMap::new();
        for entry in entries {
            map.insert(entry.profile.clone(), entry);
        }
        Self { entries: map }
    }

    fn resolve(&self, profile: &str) -> Option<&VerifierProfileRegistryEntry> {
        self.entries.get(profile)
    }
}

trait VerifierProfileRegistrySource: Send + Sync {
    fn load(
        &self,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RuntimeVerifierProfileRegistry, BackendExecutionError>;
}

struct StaticVerifierProfileRegistrySource {
    registry: RuntimeVerifierProfileRegistry,
}

impl StaticVerifierProfileRegistrySource {
    fn with_builtin_defaults() -> Self {
        Self {
            registry: RuntimeVerifierProfileRegistry::with_builtin_defaults(),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn from_registry(registry: RuntimeVerifierProfileRegistry) -> Self {
        Self { registry }
    }
}

impl VerifierProfileRegistrySource for StaticVerifierProfileRegistrySource {
    fn load(
        &self,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<RuntimeVerifierProfileRegistry, BackendExecutionError> {
        Ok(self.registry.clone())
    }
}

struct EnvJsonVerifierProfileRegistrySource {
    defaults: RuntimeVerifierProfileRegistry,
    vars: BTreeMap<String, String>,
}

impl EnvJsonVerifierProfileRegistrySource {
    #[allow(dead_code)]
    fn from_env(defaults: RuntimeVerifierProfileRegistry) -> Self {
        Self {
            defaults,
            vars: std::env::vars().collect(),
        }
    }

    #[cfg(test)]
    fn from_vars(defaults: RuntimeVerifierProfileRegistry, vars: BTreeMap<String, String>) -> Self {
        Self { defaults, vars }
    }
}

impl VerifierProfileRegistrySource for EnvJsonVerifierProfileRegistrySource {
    fn load(
        &self,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RuntimeVerifierProfileRegistry, BackendExecutionError> {
        let mut registry = self.defaults.clone();
        let Some(raw) = self.vars.get("TRNM_TEE_PROFILE_REGISTRY_JSON") else {
            return Ok(registry);
        };
        let entries: Vec<VerifierProfileRegistryEntry> = serde_json::from_str(raw).map_err(|err| {
            BackendExecutionError::Internal {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!("failed to decode TRNM_TEE_PROFILE_REGISTRY_JSON: {err}"),
            }
        })?;
        for entry in entries {
            registry.entries.insert(entry.profile.clone(), entry);
        }
        Ok(registry)
    }
}

struct RegistryBackedVerifierProfileResolver {
    source: Arc<dyn VerifierProfileRegistrySource>,
}

impl RegistryBackedVerifierProfileResolver {
    fn with_builtin_defaults() -> Self {
        Self {
            source: Arc::new(StaticVerifierProfileRegistrySource::with_builtin_defaults()),
        }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    fn with_registry(registry: RuntimeVerifierProfileRegistry) -> Self {
        Self {
            source: Arc::new(StaticVerifierProfileRegistrySource::from_registry(registry)),
        }
    }
}

impl VerifierProfileResolver for RegistryBackedVerifierProfileResolver {
    fn resolve(
        &self,
        transport: &VerifierTransportConfig,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<ResolvedVerifierProfile, BackendExecutionError> {
        let registry = self.source.load(request)?;
        let Some(entry) = registry.resolve(&transport.profile) else {
            return Err(BackendExecutionError::NotConfigured {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
            });
        };
        if entry.mode != transport.mode {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "verifier profile '{}' does not match transport mode",
                    transport.profile
                ),
            });
        }
        if !transport.endpoint.starts_with(&entry.endpoint_prefix) {
            return Err(BackendExecutionError::MalformedProof {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: format!(
                    "verifier profile '{}' does not match endpoint prefix",
                    transport.profile
                ),
            });
        }
        if entry.auth_required && transport.auth_ref.as_deref().unwrap_or("").trim().is_empty() {
            return Err(BackendExecutionError::NotConfigured {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
            });
        }
        Ok(ResolvedVerifierProfile {
            mode: transport.mode.clone(),
            profile: transport.profile.clone(),
            endpoint: transport.endpoint.clone(),
            timeout_ms: transport.timeout_ms,
        })
    }
}

trait VerifierAuthInjector: Send + Sync {
    fn inject(
        &self,
        transport: &VerifierTransportConfig,
        headers: &mut BTreeMap<String, String>,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;
}

struct HeaderVerifierAuthInjector;

impl VerifierAuthInjector for HeaderVerifierAuthInjector {
    fn inject(
        &self,
        transport: &VerifierTransportConfig,
        headers: &mut BTreeMap<String, String>,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        match transport.mode {
            VerifierTransportMode::Mock => Ok(()),
            VerifierTransportMode::External => {
                let auth_scheme = transport
                    .auth_scheme
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| BackendExecutionError::NotConfigured {
                        backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    })?;
                let auth_ref = transport
                    .auth_ref
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| BackendExecutionError::NotConfigured {
                        backend: request.backend_label(RealTeeBackend::backend_id_static()),
                    })?;
                headers.insert(
                    "authorization".to_string(),
                    format!("{} {}", auth_scheme, auth_ref),
                );
                Ok(())
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawHttpVerifierResponse {
    status_code: u16,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[allow(dead_code)]
trait VerifierHttpRequestExecutor: Send + Sync {
    fn execute_request(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
trait VerifierHttpResponseBodyReader: Send + Sync {
    fn read_body(
        &self,
        raw_response: RawHttpVerifierResponse,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError>;
}

#[allow(dead_code)]
trait VerifierHttpTimeoutHook: Send + Sync {
    fn before_execute(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;

    fn after_response(
        &self,
        http_request: &HttpVerifierRequest,
        raw_response: &RawHttpVerifierResponse,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError>;
}

#[allow(dead_code)]
struct FailClosedVerifierHttpRequestExecutor;

impl VerifierHttpRequestExecutor for FailClosedVerifierHttpRequestExecutor {
    fn execute_request(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
        Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "real http request executor for profile '{}' is not wired",
                http_request.profile
            ),
        })
    }
}

#[allow(dead_code)]
struct Utf8HttpResponseBodyReader;

impl VerifierHttpResponseBodyReader for Utf8HttpResponseBodyReader {
    fn read_body(
        &self,
        raw_response: RawHttpVerifierResponse,
        _http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        let body = String::from_utf8(raw_response.body).map_err(|err| BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!("http transport returned non-utf8 body: {err}"),
        })?;
        Ok(HttpVerifierResponse {
            status_code: raw_response.status_code,
            body,
        })
    }
}

#[allow(dead_code)]
struct NoopVerifierHttpTimeoutHook;

impl VerifierHttpTimeoutHook for NoopVerifierHttpTimeoutHook {
    fn before_execute(
        &self,
        _http_request: &HttpVerifierRequest,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        Ok(())
    }

    fn after_response(
        &self,
        _http_request: &HttpVerifierRequest,
        _raw_response: &RawHttpVerifierResponse,
        _request: &BackendVerificationRequest<'_>,
    ) -> Result<(), BackendExecutionError> {
        Ok(())
    }
}

#[allow(dead_code)]
struct RealVerifierHttpTransport {
    request_executor: Arc<dyn VerifierHttpRequestExecutor>,
    body_reader: Arc<dyn VerifierHttpResponseBodyReader>,
    timeout_hook: Arc<dyn VerifierHttpTimeoutHook>,
}

#[allow(dead_code)]
impl RealVerifierHttpTransport {
    fn new() -> Self {
        Self {
            request_executor: Arc::new(FailClosedVerifierHttpRequestExecutor),
            body_reader: Arc::new(Utf8HttpResponseBodyReader),
            timeout_hook: Arc::new(NoopVerifierHttpTimeoutHook),
        }
    }

    #[cfg(test)]
    fn with_components(
        request_executor: Arc<dyn VerifierHttpRequestExecutor>,
        body_reader: Arc<dyn VerifierHttpResponseBodyReader>,
        timeout_hook: Arc<dyn VerifierHttpTimeoutHook>,
    ) -> Self {
        Self {
            request_executor,
            body_reader,
            timeout_hook,
        }
    }
}

impl VerifierHttpTransport for RealVerifierHttpTransport {
    fn send(
        &self,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpVerifierResponse, BackendExecutionError> {
        self.timeout_hook.before_execute(http_request, request)?;
        let raw_response = self
            .request_executor
            .execute_request(http_request, request)?;
        self.timeout_hook
            .after_response(http_request, &raw_response, request)?;
        self.body_reader.read_body(raw_response, http_request, request)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct HttpRetryExecution {
    attempts: u32,
    response: HttpVerifierResponse,
}

#[allow(dead_code)]
trait VerifierHttpRetryExecutor: Send + Sync {
    fn execute(
        &self,
        transport: &dyn VerifierHttpTransport,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpRetryExecution, BackendExecutionError>;
}

#[allow(dead_code)]
struct PolicyAwareHttpRetryExecutor;

impl VerifierHttpRetryExecutor for PolicyAwareHttpRetryExecutor {
    fn execute(
        &self,
        transport: &dyn VerifierHttpTransport,
        http_request: &HttpVerifierRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<HttpRetryExecution, BackendExecutionError> {
        let max_attempts = http_request.retry_policy.max_attempts.max(1);
        let mut last_retryable_error: Option<BackendExecutionError> = None;
        for attempt in 1..=max_attempts {
            let mut attempt_request = http_request.clone();
            attempt_request
                .headers
                .insert("x-attempt".to_string(), attempt.to_string());
            match transport.send(&attempt_request, request) {
                Ok(response) if response.status_code >= 500 && attempt < max_attempts => continue,
                Ok(response) => {
                    return Ok(HttpRetryExecution {
                        attempts: attempt,
                        response,
                    })
                }
                Err(err @ BackendExecutionError::Unavailable { .. })
                | Err(err @ BackendExecutionError::Internal { .. }) if attempt < max_attempts => {
                    last_retryable_error = Some(err);
                    continue;
                }
                Err(err) => return Err(err),
            }
        }
        Err(last_retryable_error.unwrap_or_else(|| BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "http retry executor exhausted all attempts".to_string(),
        }))
    }
}

trait VerifierTelemetrySink: Send + Sync {
    fn emit(&self, event: VerifierTelemetryEvent);
}

struct NoopVerifierTelemetrySink;

impl VerifierTelemetrySink for NoopVerifierTelemetrySink {
    fn emit(&self, _event: VerifierTelemetryEvent) {}
}

#[allow(dead_code)]
trait VerifierTelemetryRecorder: Send + Sync {
    fn record(&self, encoded_event: String);
}

#[allow(dead_code)]
trait VerifierTelemetryRecordWriter: Send + Sync {
    fn write_record(&self, encoded_event: &str);
}

#[allow(dead_code)]
struct NoopTelemetryRecordWriter;

impl VerifierTelemetryRecordWriter for NoopTelemetryRecordWriter {
    fn write_record(&self, _encoded_event: &str) {}
}

#[allow(dead_code)]
struct JsonEncodingTelemetrySink {
    recorder: Arc<dyn VerifierTelemetryRecorder>,
}

impl JsonEncodingTelemetrySink {
    #[allow(dead_code)]
    fn new(recorder: Arc<dyn VerifierTelemetryRecorder>) -> Self {
        Self { recorder }
    }
}

impl VerifierTelemetrySink for JsonEncodingTelemetrySink {
    fn emit(&self, event: VerifierTelemetryEvent) {
        if let Ok(encoded) = serde_json::to_string(&event) {
            self.recorder.record(encoded);
        }
    }
}

#[allow(dead_code)]
struct JsonlTelemetryRecorder {
    writer: Arc<dyn VerifierTelemetryRecordWriter>,
}

#[allow(dead_code)]
impl JsonlTelemetryRecorder {
    fn new(writer: Arc<dyn VerifierTelemetryRecordWriter>) -> Self {
        Self { writer }
    }
}

impl VerifierTelemetryRecorder for JsonlTelemetryRecorder {
    fn record(&self, encoded_event: String) {
        self.writer.write_record(&(encoded_event + "
"));
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct IntelQuoteVerifierHttpPayload {
    request_id: String,
    telemetry_scope: String,
    attestation_target: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    quote: String,
    intel_collateral: IntelQuoteCollateralBundle,
    retry_policy: RetryBackoffPolicy,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct AmdReportVerifierHttpPayload {
    request_id: String,
    telemetry_scope: String,
    attestation_target: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    report: String,
    amd_signer: AmdSnpSignerBundle,
    retry_policy: RetryBackoffPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MockVerifierResponse {
    status: MockVerifierResponseStatus,
    backend_id: String,
    detail: Option<String>,
    telemetry_event: Option<VerifierTelemetryEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IntelQuoteVerifierClientRequest {
    transport: VerifierTransportConfig,
    call_metadata: ExternalCallMetadata,
    request_event: VerifierTelemetryEvent,
    attestation_target: String,
    measurement_field: String,
    measurement: String,
    report_data_hash: String,
    quote: String,
    intel_collateral: IntelQuoteCollateralBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmdReportVerifierClientRequest {
    transport: VerifierTransportConfig,
    call_metadata: ExternalCallMetadata,
    request_event: VerifierTelemetryEvent,
    attestation_target: String,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct VerifierTransportTemplate {
    mode: VerifierTransportMode,
    profile: String,
    endpoint_base: String,
    timeout_ms: u64,
    auth_scheme: Option<String>,
    auth_ref_prefix: Option<String>,
    retry_policy: RetryBackoffPolicy,
}

impl VerifierTransportTemplate {
    fn render(&self, attestation_target: &str) -> VerifierTransportConfig {
        VerifierTransportConfig {
            mode: self.mode.clone(),
            profile: self.profile.clone(),
            endpoint: format!("{}/{}", self.endpoint_base.trim_end_matches('/'), attestation_target),
            timeout_ms: self.timeout_ms,
            auth_scheme: self.auth_scheme.clone(),
            auth_ref: self
                .auth_ref_prefix
                .as_ref()
                .map(|prefix| format!("{prefix}.{attestation_target}")),
            retry_policy: self.retry_policy.clone(),
        }
    }
}

trait VerifierTransportConfigSource: Send + Sync {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig;
    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig;
}

#[derive(Debug, Clone)]
struct StaticVerifierTransportConfigSource {
    intel_quote: VerifierTransportTemplate,
    amd_report: VerifierTransportTemplate,
}

impl StaticVerifierTransportConfigSource {
    fn mock_defaults() -> Self {
        Self {
            intel_quote: VerifierTransportTemplate {
                mode: VerifierTransportMode::Mock,
                profile: "intel-dcap-mock-default".to_string(),
                endpoint_base: "mock://intel-quote-verifier".to_string(),
                timeout_ms: 1_500,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.intel.mock-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 1,
                    backoff_ms: 0,
                    strategy: RetryBackoffStrategy::Fixed,
                },
            },
            amd_report: VerifierTransportTemplate {
                mode: VerifierTransportMode::Mock,
                profile: "amd-sev-snp-mock-default".to_string(),
                endpoint_base: "mock://amd-report-verifier".to_string(),
                timeout_ms: 1_500,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.amd.mock-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 1,
                    backoff_ms: 0,
                    strategy: RetryBackoffStrategy::Fixed,
                },
            },
        }
    }

    #[allow(dead_code)]
    fn external_defaults() -> Self {
        Self {
            intel_quote: VerifierTransportTemplate {
                mode: VerifierTransportMode::External,
                profile: "intel-dcap-external-default".to_string(),
                endpoint_base: "https://intel-verifier.invalid/v1/quote".to_string(),
                timeout_ms: 5_000,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.intel.external-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
            amd_report: VerifierTransportTemplate {
                mode: VerifierTransportMode::External,
                profile: "amd-sev-snp-external-default".to_string(),
                endpoint_base: "https://amd-verifier.invalid/v1/report".to_string(),
                timeout_ms: 5_000,
                auth_scheme: Some("bearer".to_string()),
                auth_ref_prefix: Some("tee.amd.external-token".to_string()),
                retry_policy: RetryBackoffPolicy {
                    max_attempts: 3,
                    backoff_ms: 250,
                    strategy: RetryBackoffStrategy::Exponential,
                },
            },
        }
    }
}

impl VerifierTransportConfigSource for StaticVerifierTransportConfigSource {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.intel_quote.render(attestation_target)
    }

    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.amd_report.render(attestation_target)
    }
}

#[derive(Debug, Clone)]
struct EnvVerifierTransportConfigSource {
    defaults: StaticVerifierTransportConfigSource,
    vars: BTreeMap<String, String>,
}

impl EnvVerifierTransportConfigSource {
    fn from_env(defaults: StaticVerifierTransportConfigSource) -> Self {
        Self {
            defaults,
            vars: std::env::vars().collect(),
        }
    }

    #[cfg(test)]
    fn from_vars(defaults: StaticVerifierTransportConfigSource, vars: BTreeMap<String, String>) -> Self {
        Self { defaults, vars }
    }

    fn render_profile(
        &self,
        profile_prefix: &str,
        fallback: &VerifierTransportTemplate,
        attestation_target: &str,
    ) -> VerifierTransportConfig {
        let key = |suffix: &str| format!("TRNM_TEE_{}_{}", profile_prefix, suffix);
        let mode = self
            .vars
            .get(&key("MODE"))
            .and_then(|value| parse_transport_mode(value))
            .unwrap_or_else(|| fallback.mode.clone());
        let profile = self
            .vars
            .get(&key("PROFILE"))
            .cloned()
            .unwrap_or_else(|| fallback.profile.clone());
        let endpoint_base = self
            .vars
            .get(&key("ENDPOINT_BASE"))
            .cloned()
            .unwrap_or_else(|| fallback.endpoint_base.clone());
        let timeout_ms = self
            .vars
            .get(&key("TIMEOUT_MS"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback.timeout_ms);
        let retry_max_attempts = self
            .vars
            .get(&key("RETRY_MAX_ATTEMPTS"))
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(fallback.retry_policy.max_attempts);
        let retry_backoff_ms = self
            .vars
            .get(&key("RETRY_BACKOFF_MS"))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(fallback.retry_policy.backoff_ms);
        let retry_strategy = self
            .vars
            .get(&key("RETRY_STRATEGY"))
            .and_then(|value| parse_retry_backoff_strategy(value))
            .unwrap_or(fallback.retry_policy.strategy);
        let auth_scheme = self
            .vars
            .get(&key("AUTH_SCHEME"))
            .cloned()
            .or_else(|| fallback.auth_scheme.clone());
        let auth_ref_prefix = self
            .vars
            .get(&key("AUTH_REF_PREFIX"))
            .cloned()
            .or_else(|| fallback.auth_ref_prefix.clone());
        VerifierTransportTemplate {
            mode,
            profile,
            endpoint_base,
            timeout_ms,
            auth_scheme,
            auth_ref_prefix,
            retry_policy: RetryBackoffPolicy {
                max_attempts: retry_max_attempts,
                backoff_ms: retry_backoff_ms,
                strategy: retry_strategy,
            },
        }
        .render(attestation_target)
    }
}

impl VerifierTransportConfigSource for EnvVerifierTransportConfigSource {
    fn intel_quote_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.render_profile("INTEL_QUOTE", &self.defaults.intel_quote, attestation_target)
    }

    fn amd_report_transport_config(&self, attestation_target: &str) -> VerifierTransportConfig {
        self.render_profile("AMD_REPORT", &self.defaults.amd_report, attestation_target)
    }
}

fn parse_transport_mode(raw: &str) -> Option<VerifierTransportMode> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "mock" => Some(VerifierTransportMode::Mock),
        "external" => Some(VerifierTransportMode::External),
        _ => None,
    }
}

fn parse_retry_backoff_strategy(raw: &str) -> Option<RetryBackoffStrategy> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "fixed" => Some(RetryBackoffStrategy::Fixed),
        "exponential" => Some(RetryBackoffStrategy::Exponential),
        _ => None,
    }
}

fn validate_transport_auth_and_profile(
    transport: &VerifierTransportConfig,
    request: &BackendVerificationRequest<'_>,
    verifier_kind: &str,
    attestation_target: &str,
) -> Result<(), BackendExecutionError> {
    let backend = request.backend_label(&format!(
        "{}-{}-client",
        attestation_target,
        verifier_kind.replace(':', "-")
    ));
    if transport.profile.trim().is_empty() {
        return Err(BackendExecutionError::NotConfigured { backend });
    }
    if transport.endpoint.trim().is_empty() {
        return Err(BackendExecutionError::NotConfigured { backend });
    }
    match transport.mode {
        VerifierTransportMode::Mock => {
            if !transport.endpoint.starts_with("mock://") {
                return Err(BackendExecutionError::MalformedProof {
                    backend,
                    reason: format!(
                        "mock verifier transport for '{}' must use mock:// endpoint",
                        attestation_target
                    ),
                });
            }
        }
        VerifierTransportMode::External => {
            let auth_scheme = transport.auth_scheme.as_deref().unwrap_or("").trim();
            let auth_ref = transport.auth_ref.as_deref().unwrap_or("").trim();
            if auth_scheme.is_empty() || auth_ref.is_empty() {
                return Err(BackendExecutionError::NotConfigured { backend });
            }
            if !transport.endpoint.starts_with("https://") {
                return Err(BackendExecutionError::MalformedProof {
                    backend,
                    reason: format!(
                        "external verifier transport for '{}' must use https:// endpoint",
                        attestation_target
                    ),
                });
            }
        }
    }
    if transport.retry_policy.max_attempts == 0 {
        return Err(BackendExecutionError::MalformedProof {
            backend,
            reason: format!(
                "verifier transport for '{}' must set retry max_attempts >= 1",
                attestation_target
            ),
        });
    }
    Ok(())
}

fn build_request_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::RequestPrepared,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: None,
        status: None,
        detail: None,
    }
}

fn build_response_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
    response: &MockVerifierResponse,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::ResponseReceived,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: Some(response.backend_id.clone()),
        status: Some(response.status),
        detail: response.detail.clone(),
    }
}

fn build_mapped_telemetry_event(
    metadata: &ExternalCallMetadata,
    transport: &VerifierTransportConfig,
    response: &MockVerifierResponse,
) -> VerifierTelemetryEvent {
    VerifierTelemetryEvent {
        kind: VerifierTelemetryEventKind::ResponseMapped,
        request_id: metadata.request_id.clone(),
        telemetry_scope: metadata.telemetry_scope.clone(),
        transport_mode: transport.mode.clone(),
        profile: transport.profile.clone(),
        backend_id: Some(response.backend_id.clone()),
        status: Some(response.status),
        detail: response.detail.clone(),
    }
}

fn validate_response_telemetry_event(
    response: &MockVerifierResponse,
    metadata: &ExternalCallMetadata,
    request: &BackendVerificationRequest<'_>,
) -> Result<(), BackendExecutionError> {
    let Some(event) = response.telemetry_event.as_ref() else {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response missing telemetry event".to_string(),
        });
    };
    if event.request_id != metadata.request_id || event.telemetry_scope != metadata.telemetry_scope {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response telemetry does not match request metadata".to_string(),
        });
    }
    if event.kind != VerifierTelemetryEventKind::ResponseReceived {
        return Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: "verifier response telemetry kind is invalid".to_string(),
        });
    }
    Ok(())
}

fn build_external_call_metadata(
    request: &BackendVerificationRequest<'_>,
    verifier_kind: &str,
    attestation_target: &str,
    transport: &VerifierTransportConfig,
) -> ExternalCallMetadata {
    ExternalCallMetadata {
        request_id: format!(
            "tee:{}:{}:task-{}:attempt-1",
            verifier_kind,
            attestation_target,
            request.task.task_id
        ),
        telemetry_scope: format!(
            "trnm.pouw.tee.{}.{}",
            verifier_kind.replace('-', "_"),
            attestation_target.replace('-', "_")
        ),
        attempt: 1,
        retry_policy: transport.retry_policy.clone(),
    }
}

fn encode_mock_verifier_response_json(
    response: &MockVerifierResponse,
) -> Result<String, BackendExecutionError> {
    serde_json::to_string(response).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode mock verifier response json: {err}"),
    })
}

fn decode_mock_verifier_response_json(
    raw: &str,
    request: &BackendVerificationRequest<'_>,
) -> Result<MockVerifierResponse, BackendExecutionError> {
    serde_json::from_str(raw).map_err(|err| BackendExecutionError::MalformedProof {
        backend: request.backend_label(RealTeeBackend::backend_id_static()),
        reason: format!("invalid verifier response payload: {err}"),
    })
}

fn backend_label_from_response(
    response: &MockVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> String {
    let backend_id = if response.backend_id.trim().is_empty() {
        RealTeeBackend::backend_id_static().to_string()
    } else {
        response.backend_id.clone()
    };
    request.backend_label(&backend_id)
}

fn response_detail_or_default(response: &MockVerifierResponse, default: &str) -> String {
    response
        .detail
        .clone()
        .unwrap_or_else(|| default.to_string())
}

fn map_mock_verifier_response(
    response: MockVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> Result<BackendVerificationSuccess, BackendExecutionError> {
    match response.status {
        MockVerifierResponseStatus::Verified => Ok(BackendVerificationSuccess {
            backend_id: response.backend_id,
        }),
        MockVerifierResponseStatus::Invalid => Err(BackendExecutionError::InvalidProof {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier rejected attestation evidence",
            ),
        }),
        MockVerifierResponseStatus::Unavailable => Err(BackendExecutionError::Unavailable {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier transport is unavailable",
            ),
        }),
        MockVerifierResponseStatus::Malformed => Err(BackendExecutionError::MalformedProof {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier reported malformed request or evidence",
            ),
        }),
        MockVerifierResponseStatus::Internal => Err(BackendExecutionError::Internal {
            backend: backend_label_from_response(&response, request),
            reason: response_detail_or_default(
                &response,
                "external verifier failed internally",
            ),
        }),
    }
}

fn mock_response_from_fixture_result(
    result: Result<(), BackendExecutionError>,
    backend_id: String,
) -> MockVerifierResponse {
    match result {
        Ok(()) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id,
            detail: None,
            telemetry_event: None,
        },
        Err(BackendExecutionError::InvalidProof { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Invalid,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::Unavailable { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Unavailable,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::NotConfigured { .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Unavailable,
            backend_id,
            detail: Some("external verifier backend not configured".to_string()),
            telemetry_event: None,
        },
        Err(BackendExecutionError::MalformedProof { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Malformed,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
        Err(BackendExecutionError::Internal { reason, .. }) => MockVerifierResponse {
            status: MockVerifierResponseStatus::Internal,
            backend_id,
            detail: Some(reason),
            telemetry_event: None,
        },
    }
}

#[allow(dead_code)]
fn build_http_headers(
    profile: &ResolvedVerifierProfile,
    metadata: &ExternalCallMetadata,
) -> BTreeMap<String, String> {
    let mut headers = BTreeMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("x-request-id".to_string(), metadata.request_id.clone());
    headers.insert(
        "x-telemetry-scope".to_string(),
        metadata.telemetry_scope.clone(),
    );
    headers.insert("x-transport-profile".to_string(), profile.profile.clone());
    headers
}

#[allow(dead_code)]
fn build_intel_quote_http_request(
    request_input: &IntelQuoteVerifierClientRequest,
    profile: &ResolvedVerifierProfile,
    headers: BTreeMap<String, String>,
) -> Result<HttpVerifierRequest, BackendExecutionError> {
    let payload = IntelQuoteVerifierHttpPayload {
        request_id: request_input.call_metadata.request_id.clone(),
        telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
        attestation_target: request_input.attestation_target.clone(),
        measurement_field: request_input.measurement_field.clone(),
        measurement: request_input.measurement.clone(),
        report_data_hash: request_input.report_data_hash.clone(),
        quote: request_input.quote.clone(),
        intel_collateral: request_input.intel_collateral.clone(),
        retry_policy: request_input.call_metadata.retry_policy.clone(),
    };
    let body = serde_json::to_string(&payload).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode intel verifier http payload: {err}"),
    })?;
    Ok(HttpVerifierRequest {
        method: HttpMethod::Post,
        transport_mode: profile.mode.clone(),
        profile: profile.profile.clone(),
        url: profile.endpoint.clone(),
        headers,
        body,
        timeout_ms: profile.timeout_ms,
        retry_policy: request_input.transport.retry_policy.clone(),
    })
}

#[allow(dead_code)]
fn build_amd_report_http_request(
    request_input: &AmdReportVerifierClientRequest,
    profile: &ResolvedVerifierProfile,
    headers: BTreeMap<String, String>,
) -> Result<HttpVerifierRequest, BackendExecutionError> {
    let payload = AmdReportVerifierHttpPayload {
        request_id: request_input.call_metadata.request_id.clone(),
        telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
        attestation_target: request_input.attestation_target.clone(),
        measurement_field: request_input.measurement_field.clone(),
        measurement: request_input.measurement.clone(),
        report_data_hash: request_input.report_data_hash.clone(),
        report: request_input.report.clone(),
        amd_signer: request_input.amd_signer.clone(),
        retry_policy: request_input.call_metadata.retry_policy.clone(),
    };
    let body = serde_json::to_string(&payload).map_err(|err| BackendExecutionError::Internal {
        backend: RealTeeBackend::backend_id_static().to_string(),
        reason: format!("failed to encode amd verifier http payload: {err}"),
    })?;
    Ok(HttpVerifierRequest {
        method: HttpMethod::Post,
        transport_mode: profile.mode.clone(),
        profile: profile.profile.clone(),
        url: profile.endpoint.clone(),
        headers,
        body,
        timeout_ms: profile.timeout_ms,
        retry_policy: request_input.transport.retry_policy.clone(),
    })
}

#[allow(dead_code)]
fn decode_http_verifier_response(
    http_response: &HttpVerifierResponse,
    request: &BackendVerificationRequest<'_>,
) -> Result<MockVerifierResponse, BackendExecutionError> {
    match http_response.status_code {
        200..=299 => decode_mock_verifier_response_json(&http_response.body, request),
        400..=499 => Err(BackendExecutionError::MalformedProof {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "http verifier request rejected with status {}",
                http_response.status_code
            ),
        }),
        _ => Err(BackendExecutionError::Unavailable {
            backend: request.backend_label(RealTeeBackend::backend_id_static()),
            reason: format!(
                "http verifier transport returned status {}",
                http_response.status_code
            ),
        }),
    }
}

trait IntelQuoteVerifierClient: Send + Sync {
    fn verify_intel_quote_request(
        &self,
        request_input: &IntelQuoteVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError>;
}

trait AmdReportVerifierClient: Send + Sync {
    fn verify_amd_report_request(
        &self,
        request_input: &AmdReportVerifierClientRequest,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<MockVerifierResponse, BackendExecutionError>;
}

trait IntelQuoteVerifierProvider: Send + Sync {
    fn verify_intel_quote_bundle(
        &self,
        input: &QuoteVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
}

trait AmdReportVerifierProvider: Send + Sync {
    fn verify_amd_report_bundle(
        &self,
        input: &ReportVerifierInput,
        request: &BackendVerificationRequest<'_>,
    ) -> Result<BackendVerificationSuccess, BackendExecutionError>;
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
                input.attestation_target,
                expected.verifier_kind
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
                input.attestation_target,
                expected.verifier_kind
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
            profile_resolver: Arc::new(RegistryBackedVerifierProfileResolver::with_builtin_defaults()),
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
        let profile = self.profile_resolver.resolve(&request_input.transport, request)?;
        let mut headers = build_http_headers(&profile, &request_input.call_metadata);
        self.auth_injector
            .inject(&request_input.transport, &mut headers, request)?;
        let http_request = build_intel_quote_http_request(request_input, &profile, headers)?;
        let execution = self
            .retry_executor
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
            profile_resolver: Arc::new(RegistryBackedVerifierProfileResolver::with_builtin_defaults()),
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
        let profile = self.profile_resolver.resolve(&request_input.transport, request)?;
        let mut headers = build_http_headers(&profile, &request_input.call_metadata);
        self.auth_injector
            .inject(&request_input.transport, &mut headers, request)?;
        let http_request = build_amd_report_http_request(request_input, &profile, headers)?;
        let execution = self
            .retry_executor
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
        let response = self.client.verify_intel_quote_request(&client_request, request)?;
        validate_response_telemetry_event(&response, &client_request.call_metadata, request)?;
        if let Some(event) = response.telemetry_event.clone() {
            self.telemetry_sink.emit(event);
        }
        let mapped_event = build_mapped_telemetry_event(&client_request.call_metadata, &client_request.transport, &response);
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
        let response = self.client.verify_amd_report_request(&client_request, request)?;
        validate_response_telemetry_event(&response, &client_request.call_metadata, request)?;
        if let Some(event) = response.telemetry_event.clone() {
            self.telemetry_sink.emit(event);
        }
        let mapped_event = build_mapped_telemetry_event(&client_request.call_metadata, &client_request.transport, &response);
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

impl Default for RealTeeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl RealTeeBackend {
    pub fn new() -> Self {
        Self::with_executor(Arc::new(ProviderBackedVendorVerifierExecutor::fixture_backed()))
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

    #[test]
    fn env_transport_config_source_overrides_mock_defaults() {
        let mut vars = BTreeMap::new();
        vars.insert("TRNM_TEE_INTEL_QUOTE_MODE".to_string(), "external".to_string());
        vars.insert(
            "TRNM_TEE_INTEL_QUOTE_ENDPOINT_BASE".to_string(),
            "https://override.intel.example/v2/quote".to_string(),
        );
        vars.insert("TRNM_TEE_INTEL_QUOTE_TIMEOUT_MS".to_string(), "7000".to_string());
        vars.insert(
            "TRNM_TEE_INTEL_QUOTE_PROFILE".to_string(),
            "intel-dcap-override-profile".to_string(),
        );
        vars.insert(
            "TRNM_TEE_INTEL_QUOTE_AUTH_REF_PREFIX".to_string(),
            "tee.intel.override-token".to_string(),
        );
        vars.insert(
            "TRNM_TEE_INTEL_QUOTE_RETRY_MAX_ATTEMPTS".to_string(),
            "4".to_string(),
        );
        vars.insert(
            "TRNM_TEE_INTEL_QUOTE_RETRY_BACKOFF_MS".to_string(),
            "900".to_string(),
        );
        let source = EnvVerifierTransportConfigSource::from_vars(
            StaticVerifierTransportConfigSource::mock_defaults(),
            vars,
        );
        let intel = source.intel_quote_transport_config("sgx-dcap");
        assert_eq!(intel.mode, VerifierTransportMode::External);
        assert_eq!(intel.endpoint, "https://override.intel.example/v2/quote/sgx-dcap");
        assert_eq!(intel.timeout_ms, 7_000);
        assert_eq!(intel.profile, "intel-dcap-override-profile");
        assert_eq!(intel.auth_ref.as_deref(), Some("tee.intel.override-token.sgx-dcap"));
        assert_eq!(intel.retry_policy.max_attempts, 4);
        assert_eq!(intel.retry_policy.backoff_ms, 900);
        assert_eq!(intel.retry_policy.strategy, RetryBackoffStrategy::Fixed);
    }

    #[test]
    fn static_transport_config_source_renders_external_profiles() {
        let source = StaticVerifierTransportConfigSource::external_defaults();
        let intel = source.intel_quote_transport_config("sgx-dcap");
        assert_eq!(intel.mode, VerifierTransportMode::External);
        assert_eq!(intel.endpoint, "https://intel-verifier.invalid/v1/quote/sgx-dcap");
        assert_eq!(intel.timeout_ms, 5_000);
        assert_eq!(intel.profile, "intel-dcap-external-default");
        assert_eq!(intel.auth_scheme.as_deref(), Some("bearer"));
        assert_eq!(intel.auth_ref.as_deref(), Some("tee.intel.external-token.sgx-dcap"));
        assert_eq!(intel.retry_policy.max_attempts, 3);
        assert_eq!(intel.retry_policy.backoff_ms, 250);
        assert_eq!(intel.retry_policy.strategy, RetryBackoffStrategy::Exponential);

        let amd = source.amd_report_transport_config("sev-snp");
        assert_eq!(amd.mode, VerifierTransportMode::External);
        assert_eq!(amd.endpoint, "https://amd-verifier.invalid/v1/report/sev-snp");
        assert_eq!(amd.timeout_ms, 5_000);
        assert_eq!(amd.profile, "amd-sev-snp-external-default");
        assert_eq!(amd.auth_scheme.as_deref(), Some("bearer"));
        assert_eq!(amd.auth_ref.as_deref(), Some("tee.amd.external-token.sev-snp"));
        assert_eq!(amd.retry_policy.max_attempts, 3);
        assert_eq!(amd.retry_policy.backoff_ms, 250);
        assert_eq!(amd.retry_policy.strategy, RetryBackoffStrategy::Exponential);
    }

    #[test]
    fn env_json_profile_registry_source_overrides_builtin_entry() {
        let mut vars = BTreeMap::new();
        vars.insert(
            "TRNM_TEE_PROFILE_REGISTRY_JSON".to_string(),
            serde_json::to_string(&vec![VerifierProfileRegistryEntry {
                profile: "intel-dcap-external-default".into(),
                mode: VerifierTransportMode::External,
                endpoint_prefix: "https://override.intel.example/v9/quote/".into(),
                auth_required: true,
            }])
            .unwrap(),
        );
        let source = EnvJsonVerifierProfileRegistrySource::from_vars(
            RuntimeVerifierProfileRegistry::with_builtin_defaults(),
            vars,
        );
        let task = mock_task();
        let registry = source
            .load(&BackendVerificationRequest {
                family: VerificationBackendFamily::Tee,
                task: &task,
                proof_data: b"TEE:...",
                tee_payload: None,
                zk_payload: None,
                resolved_vk_ref: None,
            })
            .unwrap();
        let entry = registry.resolve("intel-dcap-external-default").unwrap();
        assert_eq!(entry.endpoint_prefix, "https://override.intel.example/v9/quote/");
        assert!(entry.auth_required);
    }

    #[test]
    fn registry_backed_profile_resolver_rejects_unknown_profile_fail_closed() {
        let task = mock_task();
        let request = BackendVerificationRequest {
            family: VerificationBackendFamily::Tee,
            task: &task,
            proof_data: b"TEE:...",
            tee_payload: None,
            zk_payload: None,
            resolved_vk_ref: None,
        };
        let mut transport = StaticVerifierTransportConfigSource::external_defaults()
            .intel_quote_transport_config("sgx-dcap");
        transport.profile = "unknown-profile".into();
        let resolver = RegistryBackedVerifierProfileResolver::with_builtin_defaults();
        let err = resolver.resolve(&transport, &request).unwrap_err();
        assert!(matches!(err, BackendExecutionError::NotConfigured { .. }));
    }

    #[test]
    fn mock_verifier_response_json_codec_roundtrip() {
        let response = MockVerifierResponse {
            status: MockVerifierResponseStatus::Verified,
            backend_id: "intel-dcap-quote-verifier".into(),
            detail: Some("ok".into()),
            telemetry_event: Some(VerifierTelemetryEvent {
                kind: VerifierTelemetryEventKind::ResponseReceived,
                request_id: "req-1".into(),
                telemetry_scope: "trnm.test".into(),
                transport_mode: VerifierTransportMode::Mock,
                profile: "test-profile".into(),
                backend_id: Some("intel-dcap-quote-verifier".into()),
                status: Some(MockVerifierResponseStatus::Verified),
                detail: Some("ok".into()),
            }),
        };
        let raw = encode_mock_verifier_response_json(&response).unwrap();
        let task = mock_task();
        let decoded = decode_mock_verifier_response_json(
            &raw,
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
        assert_eq!(decoded, response);
    }

    #[test]
    fn mock_verifier_response_json_codec_rejects_invalid_json() {
        let task = mock_task();
        let err = decode_mock_verifier_response_json(
            "{not-json",
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
        assert!(matches!(err, BackendExecutionError::MalformedProof { reason, .. } if reason.contains("invalid verifier response payload")));
    }

    struct PanicIntelQuoteClient;

    impl IntelQuoteVerifierClient for PanicIntelQuoteClient {
        fn verify_intel_quote_request(
            &self,
            _request_input: &IntelQuoteVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            panic!("intel quote client should not be called when config validation fails")
        }
    }

    struct PanicAmdReportClient;

    impl AmdReportVerifierClient for PanicAmdReportClient {
        fn verify_amd_report_request(
            &self,
            _request_input: &AmdReportVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            panic!("amd report client should not be called when config validation fails")
        }
    }

    struct MismatchedTelemetryIntelQuoteClient;

    impl IntelQuoteVerifierClient for MismatchedTelemetryIntelQuoteClient {
        fn verify_intel_quote_request(
            &self,
            request_input: &IntelQuoteVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "intel-dcap-quote-verifier".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: format!("{}-other", request_input.call_metadata.request_id),
                    telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                    transport_mode: request_input.transport.mode.clone(),
                    profile: request_input.transport.profile.clone(),
                    backend_id: Some("intel-dcap-quote-verifier".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            })
        }
    }

    struct AssertingIntelHttpTransport;

    impl VerifierHttpTransport for AssertingIntelHttpTransport {
        fn send(
            &self,
            http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<HttpVerifierResponse, BackendExecutionError> {
            assert_eq!(http_request.method, HttpMethod::Post);
            assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
            assert_eq!(http_request.profile, "intel-dcap-external-default");
            assert_eq!(http_request.url, "https://intel-verifier.invalid/v1/quote/sgx-dcap");
            assert_eq!(http_request.timeout_ms, 5_000);
            assert_eq!(http_request.headers.get("content-type").map(String::as_str), Some("application/json"));
            assert_eq!(http_request.headers.get("x-request-id").map(String::as_str), Some("tee:quote-verifier:sgx-dcap:task-42:attempt-1"));
            assert_eq!(http_request.headers.get("x-transport-profile").map(String::as_str), Some("intel-dcap-external-default"));
            assert_eq!(http_request.headers.get("authorization").map(String::as_str), Some("bearer tee.intel.external-token.sgx-dcap"));
            let payload: IntelQuoteVerifierHttpPayload = serde_json::from_str(&http_request.body).unwrap();
            assert_eq!(payload.attestation_target, "sgx-dcap");
            assert_eq!(payload.measurement_field, "mrenclave");
            assert_eq!(payload.measurement, "mrenclave:demo-sgx-v1");
            assert_eq!(payload.quote, "quote-sgx-dcap-demo-v1");
            assert_eq!(payload.retry_policy.max_attempts, 3);
            let response = MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "intel-http-transport".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: payload.request_id.clone(),
                    telemetry_scope: payload.telemetry_scope.clone(),
                    transport_mode: VerifierTransportMode::External,
                    profile: "intel-dcap-external-default".into(),
                    backend_id: Some("intel-http-transport".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            };
            Ok(HttpVerifierResponse {
                status_code: 200,
                body: encode_mock_verifier_response_json(&response).unwrap(),
            })
        }
    }

    struct AssertingAmdHttpTransport;

    impl VerifierHttpTransport for AssertingAmdHttpTransport {
        fn send(
            &self,
            http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<HttpVerifierResponse, BackendExecutionError> {
            assert_eq!(http_request.method, HttpMethod::Post);
            assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
            assert_eq!(http_request.profile, "amd-sev-snp-external-default");
            assert_eq!(http_request.url, "https://amd-verifier.invalid/v1/report/sev-snp");
            assert_eq!(http_request.timeout_ms, 5_000);
            assert_eq!(http_request.headers.get("content-type").map(String::as_str), Some("application/json"));
            assert_eq!(http_request.headers.get("x-request-id").map(String::as_str), Some("tee:report-verifier:sev-snp:task-42:attempt-1"));
            assert_eq!(http_request.headers.get("x-transport-profile").map(String::as_str), Some("amd-sev-snp-external-default"));
            assert_eq!(http_request.headers.get("authorization").map(String::as_str), Some("bearer tee.amd.external-token.sev-snp"));
            let payload: AmdReportVerifierHttpPayload = serde_json::from_str(&http_request.body).unwrap();
            assert_eq!(payload.attestation_target, "sev-snp");
            assert_eq!(payload.measurement_field, "measurement");
            assert_eq!(payload.measurement, "measurement:demo-snp-v1");
            assert_eq!(payload.report, "report-sev-snp-demo-v1");
            assert_eq!(payload.retry_policy.max_attempts, 3);
            let response = MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "amd-http-transport".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: payload.request_id.clone(),
                    telemetry_scope: payload.telemetry_scope.clone(),
                    transport_mode: VerifierTransportMode::External,
                    profile: "amd-sev-snp-external-default".into(),
                    backend_id: Some("amd-http-transport".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            };
            Ok(HttpVerifierResponse {
                status_code: 200,
                body: encode_mock_verifier_response_json(&response).unwrap(),
            })
        }
    }

    struct FlakyIntelHttpTransport {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl VerifierHttpTransport for FlakyIntelHttpTransport {
        fn send(
            &self,
            http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<HttpVerifierResponse, BackendExecutionError> {
            let attempt = http_request
                .headers
                .get("x-attempt")
                .cloned()
                .unwrap_or_else(|| "?".to_string());
            self.calls.lock().unwrap().push(attempt.clone());
            if attempt == "1" {
                Ok(HttpVerifierResponse {
                    status_code: 503,
                    body: "upstream unavailable".into(),
                })
            } else {
                let response = MockVerifierResponse {
                    status: MockVerifierResponseStatus::Verified,
                    backend_id: "intel-http-retry".into(),
                    detail: None,
                    telemetry_event: Some(VerifierTelemetryEvent {
                        kind: VerifierTelemetryEventKind::ResponseReceived,
                        request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                        telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                        transport_mode: VerifierTransportMode::External,
                        profile: "intel-dcap-external-default".into(),
                        backend_id: Some("intel-http-retry".into()),
                        status: Some(MockVerifierResponseStatus::Verified),
                        detail: None,
                    }),
                };
                Ok(HttpVerifierResponse {
                    status_code: 200,
                    body: encode_mock_verifier_response_json(&response).unwrap(),
                })
            }
        }
    }

    #[derive(Default)]
    struct RecordingTelemetrySink {
        events: Mutex<Vec<VerifierTelemetryEvent>>,
    }

    impl VerifierTelemetrySink for RecordingTelemetrySink {
        fn emit(&self, event: VerifierTelemetryEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    #[derive(Default)]
    struct BufferingTelemetryRecorder {
        records: Mutex<Vec<String>>,
    }

    impl VerifierTelemetryRecorder for BufferingTelemetryRecorder {
        fn record(&self, encoded_event: String) {
            self.records.lock().unwrap().push(encoded_event);
        }
    }

    #[derive(Default)]
    struct BufferingTelemetryLineWriter {
        records: Mutex<Vec<String>>,
    }

    impl VerifierTelemetryRecordWriter for BufferingTelemetryLineWriter {
        fn write_record(&self, encoded_event: &str) {
            self.records.lock().unwrap().push(encoded_event.to_string());
        }
    }

    struct Http503IntelTransport;

    impl VerifierHttpTransport for Http503IntelTransport {
        fn send(
            &self,
            _http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<HttpVerifierResponse, BackendExecutionError> {
            Ok(HttpVerifierResponse {
                status_code: 503,
                body: "upstream unavailable".into(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingHttpRequestExecutor {
        urls: Mutex<Vec<String>>,
    }

    impl VerifierHttpRequestExecutor for RecordingHttpRequestExecutor {
        fn execute_request(
            &self,
            http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
            self.urls.lock().unwrap().push(http_request.url.clone());
            assert_eq!(http_request.transport_mode, VerifierTransportMode::External);
            assert_eq!(http_request.profile, "intel-dcap-external-default");
            assert_eq!(http_request.headers.get("authorization").map(String::as_str), Some("bearer tee.intel.external-token.sgx-dcap"));
            Ok(RawHttpVerifierResponse {
                status_code: 200,
                headers: BTreeMap::new(),
                body: b"{\"transport\":\"ok\"}".to_vec(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingHttpBodyReader {
        bodies: Mutex<Vec<Vec<u8>>>,
    }

    impl VerifierHttpResponseBodyReader for RecordingHttpBodyReader {
        fn read_body(
            &self,
            raw_response: RawHttpVerifierResponse,
            _http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<HttpVerifierResponse, BackendExecutionError> {
            self.bodies.lock().unwrap().push(raw_response.body.clone());
            Ok(HttpVerifierResponse {
                status_code: raw_response.status_code,
                body: String::from_utf8(raw_response.body).unwrap(),
            })
        }
    }

    #[derive(Default)]
    struct RecordingHttpTimeoutHook {
        calls: Mutex<Vec<String>>,
    }

    impl VerifierHttpTimeoutHook for RecordingHttpTimeoutHook {
        fn before_execute(
            &self,
            http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<(), BackendExecutionError> {
            self.calls.lock().unwrap().push(format!(
                "before:{}:{}",
                http_request.profile, http_request.timeout_ms
            ));
            Ok(())
        }

        fn after_response(
            &self,
            http_request: &HttpVerifierRequest,
            raw_response: &RawHttpVerifierResponse,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<(), BackendExecutionError> {
            self.calls.lock().unwrap().push(format!(
                "after:{}:{}",
                http_request.profile, raw_response.status_code
            ));
            Ok(())
        }
    }

    struct RejectingHttpTimeoutHook;

    impl VerifierHttpTimeoutHook for RejectingHttpTimeoutHook {
        fn before_execute(
            &self,
            _http_request: &HttpVerifierRequest,
            request: &BackendVerificationRequest<'_>,
        ) -> Result<(), BackendExecutionError> {
            Err(BackendExecutionError::Unavailable {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "timeout hook rejected transport execution".into(),
            })
        }

        fn after_response(
            &self,
            _http_request: &HttpVerifierRequest,
            _raw_response: &RawHttpVerifierResponse,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<(), BackendExecutionError> {
            Ok(())
        }
    }

    struct PanicHttpRequestExecutor;

    impl VerifierHttpRequestExecutor for PanicHttpRequestExecutor {
        fn execute_request(
            &self,
            _http_request: &HttpVerifierRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<RawHttpVerifierResponse, BackendExecutionError> {
            panic!("request executor should not be called when timeout hook fails")
        }
    }

    struct AssertingExternalIntelQuoteClient;

    impl IntelQuoteVerifierClient for AssertingExternalIntelQuoteClient {
        fn verify_intel_quote_request(
            &self,
            request_input: &IntelQuoteVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            assert_eq!(request_input.transport.mode, VerifierTransportMode::External);
            assert_eq!(request_input.transport.endpoint, "https://intel-verifier.invalid/v1/quote/sgx-dcap");
            assert_eq!(request_input.transport.profile, "intel-dcap-external-default");
            assert_eq!(request_input.transport.timeout_ms, 5_000);
            assert_eq!(request_input.transport.retry_policy.max_attempts, 3);
            assert_eq!(request_input.transport.retry_policy.backoff_ms, 250);
            assert_eq!(request_input.transport.retry_policy.strategy, RetryBackoffStrategy::Exponential);
            assert_eq!(request_input.transport.auth_ref.as_deref(), Some("tee.intel.external-token.sgx-dcap"));
            assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 3);
            assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 250);
            assert_eq!(request_input.request_event.kind, VerifierTelemetryEventKind::RequestPrepared);
            assert_eq!(request_input.request_event.profile, "intel-dcap-external-default");
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "intel-external-mock-client".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: request_input.call_metadata.request_id.clone(),
                    telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                    transport_mode: request_input.transport.mode.clone(),
                    profile: request_input.transport.profile.clone(),
                    backend_id: Some("intel-external-mock-client".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            })
        }
    }

    struct AssertingExternalAmdReportClient;

    impl AmdReportVerifierClient for AssertingExternalAmdReportClient {
        fn verify_amd_report_request(
            &self,
            request_input: &AmdReportVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            assert_eq!(request_input.transport.mode, VerifierTransportMode::External);
            assert_eq!(request_input.transport.endpoint, "https://amd-verifier.invalid/v1/report/sev-snp");
            assert_eq!(request_input.transport.profile, "amd-sev-snp-external-default");
            assert_eq!(request_input.transport.timeout_ms, 5_000);
            assert_eq!(request_input.transport.retry_policy.max_attempts, 3);
            assert_eq!(request_input.transport.retry_policy.backoff_ms, 250);
            assert_eq!(request_input.transport.retry_policy.strategy, RetryBackoffStrategy::Exponential);
            assert_eq!(request_input.transport.auth_ref.as_deref(), Some("tee.amd.external-token.sev-snp"));
            assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 3);
            assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 250);
            assert_eq!(request_input.request_event.kind, VerifierTelemetryEventKind::RequestPrepared);
            assert_eq!(request_input.request_event.profile, "amd-sev-snp-external-default");
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "amd-external-mock-client".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: request_input.call_metadata.request_id.clone(),
                    telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                    transport_mode: request_input.transport.mode.clone(),
                    profile: request_input.transport.profile.clone(),
                    backend_id: Some("amd-external-mock-client".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            })
        }
    }

    struct AssertingIntelQuoteClient;

    impl IntelQuoteVerifierClient for AssertingIntelQuoteClient {
        fn verify_intel_quote_request(
            &self,
            request_input: &IntelQuoteVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            assert_eq!(request_input.transport.mode, VerifierTransportMode::Mock);
            assert_eq!(request_input.transport.endpoint, "mock://intel-quote-verifier/sgx-dcap");
            assert_eq!(request_input.transport.profile, "intel-dcap-mock-default");
            assert_eq!(request_input.transport.timeout_ms, 1_500);
            assert_eq!(request_input.transport.retry_policy.max_attempts, 1);
            assert_eq!(request_input.transport.retry_policy.backoff_ms, 0);
            assert_eq!(request_input.transport.retry_policy.strategy, RetryBackoffStrategy::Fixed);
            assert_eq!(request_input.transport.auth_scheme.as_deref(), Some("bearer"));
            assert_eq!(request_input.transport.auth_ref.as_deref(), Some("tee.intel.mock-token.sgx-dcap"));
            assert_eq!(request_input.call_metadata.request_id, "tee:quote-verifier:sgx-dcap:task-42:attempt-1");
            assert_eq!(request_input.call_metadata.telemetry_scope, "trnm.pouw.tee.quote_verifier.sgx_dcap");
            assert_eq!(request_input.call_metadata.attempt, 1);
            assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 1);
            assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 0);
            assert_eq!(request_input.request_event.kind, VerifierTelemetryEventKind::RequestPrepared);
            assert_eq!(request_input.request_event.profile, "intel-dcap-mock-default");
            assert_eq!(request_input.attestation_target, "sgx-dcap");
            assert_eq!(request_input.measurement_field, "mrenclave");
            assert_eq!(request_input.measurement, "mrenclave:demo-sgx-v1");
            assert_eq!(request_input.quote, "quote-sgx-dcap-demo-v1");
            assert_eq!(request_input.intel_collateral.collateral, "intel-dcap-collateral-demo-v1");
            assert_eq!(request_input.intel_collateral.cert_chain, "intel-dcap-cert-chain-demo-v1");
            assert_eq!(request_input.intel_collateral.issuer, "intel");
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "intel-mock-client".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: request_input.call_metadata.request_id.clone(),
                    telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                    transport_mode: request_input.transport.mode.clone(),
                    profile: request_input.transport.profile.clone(),
                    backend_id: Some("intel-mock-client".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            })
        }
    }

    struct AssertingAmdReportClient;

    impl AmdReportVerifierClient for AssertingAmdReportClient {
        fn verify_amd_report_request(
            &self,
            request_input: &AmdReportVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            assert_eq!(request_input.transport.mode, VerifierTransportMode::Mock);
            assert_eq!(request_input.transport.endpoint, "mock://amd-report-verifier/sev-snp");
            assert_eq!(request_input.transport.profile, "amd-sev-snp-mock-default");
            assert_eq!(request_input.transport.timeout_ms, 1_500);
            assert_eq!(request_input.transport.retry_policy.max_attempts, 1);
            assert_eq!(request_input.transport.retry_policy.backoff_ms, 0);
            assert_eq!(request_input.transport.retry_policy.strategy, RetryBackoffStrategy::Fixed);
            assert_eq!(request_input.transport.auth_scheme.as_deref(), Some("bearer"));
            assert_eq!(request_input.transport.auth_ref.as_deref(), Some("tee.amd.mock-token.sev-snp"));
            assert_eq!(request_input.call_metadata.request_id, "tee:report-verifier:sev-snp:task-42:attempt-1");
            assert_eq!(request_input.call_metadata.telemetry_scope, "trnm.pouw.tee.report_verifier.sev_snp");
            assert_eq!(request_input.call_metadata.attempt, 1);
            assert_eq!(request_input.call_metadata.retry_policy.max_attempts, 1);
            assert_eq!(request_input.call_metadata.retry_policy.backoff_ms, 0);
            assert_eq!(request_input.request_event.kind, VerifierTelemetryEventKind::RequestPrepared);
            assert_eq!(request_input.request_event.profile, "amd-sev-snp-mock-default");
            assert_eq!(request_input.attestation_target, "sev-snp");
            assert_eq!(request_input.measurement_field, "measurement");
            assert_eq!(request_input.measurement, "measurement:demo-snp-v1");
            assert_eq!(request_input.report, "report-sev-snp-demo-v1");
            assert_eq!(request_input.amd_signer.vcek, "amd-vcek-demo-v1");
            assert_eq!(request_input.amd_signer.cert_chain, "amd-cert-chain-demo-v1");
            assert_eq!(request_input.amd_signer.report_signer, "amd");
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Verified,
                backend_id: "amd-mock-client".into(),
                detail: None,
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: request_input.call_metadata.request_id.clone(),
                    telemetry_scope: request_input.call_metadata.telemetry_scope.clone(),
                    transport_mode: request_input.transport.mode.clone(),
                    profile: request_input.transport.profile.clone(),
                    backend_id: Some("amd-mock-client".into()),
                    status: Some(MockVerifierResponseStatus::Verified),
                    detail: None,
                }),
            })
        }
    }

    #[test]
    fn client_backed_intel_provider_delegates_request_to_client() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let provider = ClientBackedIntelQuoteVerifierProvider::new(
            Arc::new(AssertingIntelQuoteClient),
            Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
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

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-client"
        ));
    }

    #[test]
    fn client_backed_amd_provider_delegates_request_to_client() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Report(input) => input,
            TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
        };
        let provider = ClientBackedAmdReportVerifierProvider::new(
            Arc::new(AssertingAmdReportClient),
            Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
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

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-client"
        ));
    }

    #[test]
    fn client_backed_intel_provider_fails_closed_when_external_auth_missing() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let mut vars = BTreeMap::new();
        vars.insert("TRNM_TEE_INTEL_QUOTE_MODE".to_string(), "external".to_string());
        vars.insert("TRNM_TEE_INTEL_QUOTE_PROFILE".to_string(), "intel-dcap-external-override".to_string());
        vars.insert("TRNM_TEE_INTEL_QUOTE_ENDPOINT_BASE".to_string(), "https://override.intel.example/v2/quote".to_string());
        vars.insert("TRNM_TEE_INTEL_QUOTE_AUTH_SCHEME".to_string(), "".to_string());
        vars.insert("TRNM_TEE_INTEL_QUOTE_AUTH_REF_PREFIX".to_string(), "".to_string());
        let provider = ClientBackedIntelQuoteVerifierProvider::new(
            Arc::new(PanicIntelQuoteClient),
            Arc::new(EnvVerifierTransportConfigSource::from_vars(
                StaticVerifierTransportConfigSource::mock_defaults(),
                vars,
            )),
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
        assert!(matches!(result, Err(BackendExecutionError::NotConfigured { backend }) if backend.contains("sgx-dcap") && backend.contains("quote-verifier")));
    }

    #[test]
    fn client_backed_amd_provider_fails_closed_when_profile_missing() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Report(input) => input,
            TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
        };
        let mut vars = BTreeMap::new();
        vars.insert("TRNM_TEE_AMD_REPORT_MODE".to_string(), "external".to_string());
        vars.insert("TRNM_TEE_AMD_REPORT_PROFILE".to_string(), "".to_string());
        vars.insert("TRNM_TEE_AMD_REPORT_ENDPOINT_BASE".to_string(), "https://override.amd.example/v2/report".to_string());
        vars.insert("TRNM_TEE_AMD_REPORT_AUTH_REF_PREFIX".to_string(), "tee.amd.override-token".to_string());
        vars.insert("TRNM_TEE_AMD_REPORT_AUTH_SCHEME".to_string(), "bearer".to_string());
        let provider = ClientBackedAmdReportVerifierProvider::new(
            Arc::new(PanicAmdReportClient),
            Arc::new(EnvVerifierTransportConfigSource::from_vars(
                StaticVerifierTransportConfigSource::mock_defaults(),
                vars,
            )),
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
        assert!(matches!(result, Err(BackendExecutionError::NotConfigured { backend }) if backend.contains("sev-snp") && backend.contains("report-verifier")));
    }

    #[test]
    fn client_backed_intel_provider_rejects_mismatched_response_telemetry_fail_closed() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let provider = ClientBackedIntelQuoteVerifierProvider::new(
            Arc::new(MismatchedTelemetryIntelQuoteClient),
            Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
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
        assert!(matches!(result, Err(BackendExecutionError::MalformedProof { reason, .. }) if reason.contains("telemetry does not match request metadata")));
    }

    #[test]
    fn http_retry_executor_retries_503_then_succeeds() {
        let task = mock_task();
        let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let client = HttpBackedIntelQuoteVerifierClient::with_retry_executor(
            Arc::new(FlakyIntelHttpTransport { calls: calls.clone() }),
            Arc::new(PolicyAwareHttpRetryExecutor),
        );
        let result = client.verify_intel_quote_request(
            &IntelQuoteVerifierClientRequest {
                transport: StaticVerifierTransportConfigSource::external_defaults().intel_quote_transport_config("sgx-dcap"),
                call_metadata: ExternalCallMetadata {
                    request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                    telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                    attempt: 1,
                    retry_policy: RetryBackoffPolicy { max_attempts: 3, backoff_ms: 250, strategy: RetryBackoffStrategy::Exponential },
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
        assert!(matches!(result, Ok(MockVerifierResponse { backend_id, .. }) if backend_id == "intel-http-retry"));
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
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
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
        assert!(matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-external-mock-client"));
        let events = sink.events.lock().unwrap().clone();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].kind, VerifierTelemetryEventKind::RequestPrepared);
        assert_eq!(events[1].kind, VerifierTelemetryEventKind::ResponseReceived);
        assert_eq!(events[2].kind, VerifierTelemetryEventKind::ResponseMapped);
        assert_eq!(events[0].request_id, events[1].request_id);
        assert_eq!(events[1].request_id, events[2].request_id);
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
            .unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "{\"transport\":\"ok\"}");
        assert_eq!(request_executor.urls.lock().unwrap().clone(), vec!["https://intel-verifier.invalid/v1/quote/sgx-dcap".to_string()]);
        assert_eq!(body_reader.bodies.lock().unwrap().clone(), vec![b"{\"transport\":\"ok\"}".to_vec()]);
        assert_eq!(timeout_hook.calls.lock().unwrap().clone(), vec![
            "before:intel-dcap-external-default:5000".to_string(),
            "after:intel-dcap-external-default:200".to_string(),
        ]);
    }

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
        assert!(matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("timeout hook rejected transport execution")));
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
        assert!(matches!(err, BackendExecutionError::Unavailable { reason, .. } if reason.contains("intel-dcap-external-default")));
    }

    #[test]
    fn http_backed_intel_client_skeleton_encodes_request_and_decodes_response() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let provider = ClientBackedIntelQuoteVerifierProvider::new(
            Arc::new(HttpBackedIntelQuoteVerifierClient::new(Arc::new(AssertingIntelHttpTransport))),
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
        assert!(matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-http-transport"));
    }

    #[test]
    fn http_backed_amd_client_skeleton_encodes_request_and_decodes_response() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Report(input) => input,
            TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
        };
        let provider = ClientBackedAmdReportVerifierProvider::new(
            Arc::new(HttpBackedAmdReportVerifierClient::new(Arc::new(AssertingAmdHttpTransport))),
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
        assert!(matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-http-transport"));
    }

    #[test]
    fn http_backed_intel_client_maps_http_503_to_unavailable() {
        let task = mock_task();
        let payload = parse_tee_attestation_payload(b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel").unwrap();
        let client = HttpBackedIntelQuoteVerifierClient::new(Arc::new(Http503IntelTransport));
        let result = client.verify_intel_quote_request(
            &IntelQuoteVerifierClientRequest {
                transport: StaticVerifierTransportConfigSource::external_defaults().intel_quote_transport_config("sgx-dcap"),
                call_metadata: ExternalCallMetadata {
                    request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                    telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                    attempt: 1,
                    retry_policy: RetryBackoffPolicy { max_attempts: 3, backoff_ms: 250, strategy: RetryBackoffStrategy::Exponential },
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
        assert!(matches!(result, Err(BackendExecutionError::Unavailable { reason, .. }) if reason.contains("status 503")));
    }

    #[test]
    fn client_backed_intel_provider_uses_external_transport_profile_when_injected() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
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
        assert!(matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-external-mock-client"));
    }

    #[test]
    fn client_backed_amd_provider_uses_external_transport_profile_when_injected() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
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
        assert!(matches!(result, Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-external-mock-client"));
    }

    struct InvalidIntelQuoteClientResponse;

    impl IntelQuoteVerifierClient for InvalidIntelQuoteClientResponse {
        fn verify_intel_quote_request(
            &self,
            _request_input: &IntelQuoteVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Invalid,
                backend_id: "intel-dcap-quote-verifier".into(),
                detail: Some("quote digest mismatch".into()),
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: "tee:quote-verifier:sgx-dcap:task-42:attempt-1".into(),
                    telemetry_scope: "trnm.pouw.tee.quote_verifier.sgx_dcap".into(),
                    transport_mode: VerifierTransportMode::Mock,
                    profile: "intel-dcap-mock-default".into(),
                    backend_id: Some("intel-dcap-quote-verifier".into()),
                    status: Some(MockVerifierResponseStatus::Invalid),
                    detail: Some("quote digest mismatch".into()),
                }),
            })
        }
    }

    struct UnavailableAmdReportClientResponse;

    impl AmdReportVerifierClient for UnavailableAmdReportClientResponse {
        fn verify_amd_report_request(
            &self,
            _request_input: &AmdReportVerifierClientRequest,
            _request: &BackendVerificationRequest<'_>,
        ) -> Result<MockVerifierResponse, BackendExecutionError> {
            Ok(MockVerifierResponse {
                status: MockVerifierResponseStatus::Unavailable,
                backend_id: "amd-sev-snp-report-verifier".into(),
                detail: Some("transport timeout contacting SNP verifier".into()),
                telemetry_event: Some(VerifierTelemetryEvent {
                    kind: VerifierTelemetryEventKind::ResponseReceived,
                    request_id: "tee:report-verifier:sev-snp:task-42:attempt-1".into(),
                    telemetry_scope: "trnm.pouw.tee.report_verifier.sev_snp".into(),
                    transport_mode: VerifierTransportMode::Mock,
                    profile: "amd-sev-snp-mock-default".into(),
                    backend_id: Some("amd-sev-snp-report-verifier".into()),
                    status: Some(MockVerifierResponseStatus::Unavailable),
                    detail: Some("transport timeout contacting SNP verifier".into()),
                }),
            })
        }
    }

    struct AssertingIntelQuoteProvider;

    impl IntelQuoteVerifierProvider for AssertingIntelQuoteProvider {
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
                backend_id: "intel-mock-provider".into(),
            })
        }
    }

    struct AssertingAmdReportProvider;

    impl AmdReportVerifierProvider for AssertingAmdReportProvider {
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
                backend_id: "amd-mock-provider".into(),
            })
        }
    }

    struct RejectingIntelQuoteProvider;

    impl IntelQuoteVerifierProvider for RejectingIntelQuoteProvider {
        fn verify_intel_quote_bundle(
            &self,
            _input: &QuoteVerifierInput,
            request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "unexpected intel quote path in amd provider test".to_string(),
            })
        }
    }

    struct RejectingAmdReportProvider;

    impl AmdReportVerifierProvider for RejectingAmdReportProvider {
        fn verify_amd_report_bundle(
            &self,
            _input: &ReportVerifierInput,
            request: &BackendVerificationRequest<'_>,
        ) -> Result<BackendVerificationSuccess, BackendExecutionError> {
            Err(BackendExecutionError::Internal {
                backend: request.backend_label(RealTeeBackend::backend_id_static()),
                reason: "unexpected amd report path in intel provider test".to_string(),
            })
        }
    }

    #[test]
    fn client_backed_intel_provider_maps_invalid_response_fail_closed() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let provider = ClientBackedIntelQuoteVerifierProvider::new(
            Arc::new(InvalidIntelQuoteClientResponse),
            Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
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

        assert!(matches!(
            result,
            Err(BackendExecutionError::InvalidProof { backend, reason })
                if backend == "tee:intel-dcap-quote-verifier" && reason.contains("quote digest mismatch")
        ));
    }

    #[test]
    fn client_backed_amd_provider_maps_unavailable_response_to_backend_unavailable() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Report(input) => input,
            TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
        };
        let provider = ClientBackedAmdReportVerifierProvider::new(
            Arc::new(UnavailableAmdReportClientResponse),
            Arc::new(StaticVerifierTransportConfigSource::mock_defaults()),
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

        assert!(matches!(
            result,
            Err(BackendExecutionError::Unavailable { backend, reason })
                if backend == "tee:amd-sev-snp-report-verifier" && reason.contains("transport timeout")
        ));
    }

    #[test]
    fn provider_backed_executor_delegates_intel_quote_bundle_to_provider() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sgx-dcap,measurement=mrenclave:demo-sgx-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,quote=quote-sgx-dcap-demo-v1,collateral=intel-dcap-collateral-demo-v1,cert_chain=intel-dcap-cert-chain-demo-v1,issuer=intel";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SGX_DCAP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Quote(input) => input,
            TeeVerifierInput::Report(_) => panic!("expected intel quote verifier input"),
        };
        let executor = ProviderBackedVendorVerifierExecutor::new(
            Arc::new(AssertingIntelQuoteProvider),
            Arc::new(RejectingAmdReportProvider),
        );

        let result = executor.verify_intel_quote_bundle(
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

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "intel-mock-provider"
        ));
    }

    #[test]
    fn provider_backed_executor_delegates_amd_report_bundle_to_provider() {
        let task = mock_task();
        let proof_data = b"TEE:task_id=42,worker=worker1,proof_type=tee,result_hash=1111111111111111111111111111111111111111111111111111111111111111,attestation_target=sev-snp,measurement=measurement:demo-snp-v1,report_data_hash=1111111111111111111111111111111111111111111111111111111111111111,report=report-sev-snp-demo-v1,vcek=amd-vcek-demo-v1,cert_chain=amd-cert-chain-demo-v1,report_signer=amd";
        let payload = parse_tee_attestation_payload(proof_data).unwrap();
        let handoff = TeeVerifierHandoff::from_payload(&payload, None).unwrap();
        let input = match SEV_SNP_ADAPTER.build_verifier_input(&handoff, None).unwrap() {
            TeeVerifierInput::Report(input) => input,
            TeeVerifierInput::Quote(_) => panic!("expected amd report verifier input"),
        };
        let executor = ProviderBackedVendorVerifierExecutor::new(
            Arc::new(RejectingIntelQuoteProvider),
            Arc::new(AssertingAmdReportProvider),
        );

        let result = executor.verify_amd_report_bundle(
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

        assert!(matches!(
            result,
            Ok(BackendVerificationSuccess { backend_id }) if backend_id == "amd-mock-provider"
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
