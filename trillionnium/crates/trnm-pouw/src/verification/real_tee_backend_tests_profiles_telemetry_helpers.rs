use super::*;

#[derive(Default)]
pub(super) struct RecordingTelemetrySink {
    events: Mutex<Vec<VerifierTelemetryEvent>>,
}

impl VerifierTelemetrySink for RecordingTelemetrySink {
    fn emit(&self, event: VerifierTelemetryEvent) {
        self.events.lock().unwrap().push(event);
    }
}

#[derive(Default)]
pub(super) struct BufferingTelemetryRecorder {
    records: Mutex<Vec<String>>,
}

impl VerifierTelemetryRecorder for BufferingTelemetryRecorder {
    fn record(&self, encoded_event: String) {
        self.records.lock().unwrap().push(encoded_event);
    }
}

#[derive(Default)]
pub(super) struct BufferingTelemetryLineWriter {
    records: Mutex<Vec<String>>,
}

impl VerifierTelemetryRecordWriter for BufferingTelemetryLineWriter {
    fn write_record(&self, encoded_event: &str) {
        self.records.lock().unwrap().push(encoded_event.to_string());
    }
}
