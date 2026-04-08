use super::*;

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
        self.writer.write_record(
            &(encoded_event
                + "
"),
        );
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

