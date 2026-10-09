#![no_main]

use libfuzzer_sys::fuzz_target;

#[path = "support/work_certificate.rs"]
mod checks;

fuzz_target!(|bytes: &[u8]| {
    // Preserve raw parser mutations; the separate four-byte semantic selector
    // exercises ticket boundaries, late rejection and cancellation every run.
    checks::check_raw(bytes);
    checks::check_structured(&bytes[..bytes.len().min(4)]);
});
