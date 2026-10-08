#![no_main]

use libfuzzer_sys::fuzz_target;
use trnm_protocol::pon_wire::{Envelope, Header};
use trnm_protocol::qualified_work_task::{QualifiedWorkTask, SignedQualifiedWorkTask};

fuzz_target!(|bytes: &[u8]| {
    // Actual decoders see the complete untrusted input, including trailing bytes.
    // A decoder accepting a noncanonical wire is a crash, not an ignored case.
    if let Ok(header) = Header::decode(bytes) {
        assert_eq!(header.encode(), bytes);
    }
    if let Ok(envelope) = Envelope::decode(bytes) {
        assert_eq!(envelope.encode().expect("accepted envelope encodes"), bytes);
    }
    if let Ok(task) = QualifiedWorkTask::decode(bytes) {
        assert_eq!(task.encode().expect("accepted task encodes"), bytes);
    }
    if let Ok(task) = SignedQualifiedWorkTask::decode(bytes) {
        assert_eq!(task.encode().expect("accepted signed task encodes"), bytes);
    }
});
