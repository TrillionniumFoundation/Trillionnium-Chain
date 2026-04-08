use crate::proof_adapter::proof_adapter_core::ProofAdapter;
use crate::proof_adapter::StandardProofAdapter;

#[test]
fn standard_proof_adapter_reports_verifier_decision_and_reason_code() {
    let adapter = StandardProofAdapter;

    let (ok, code) = adapter.verify("hello", 8);
    assert!(ok);
    assert_eq!(code, "ok");

    let (ok, code) = adapter.verify("\u{200B}\u{200C}", 8);
    assert!(!ok);
    assert_eq!(code, "empty_output");

    let (ok, code) = adapter.verify("helloabc", 4);
    assert!(!ok);
    assert_eq!(code, "output_too_long");
}
