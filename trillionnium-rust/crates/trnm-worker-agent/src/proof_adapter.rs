use crate::LlmAdapterResponse;

pub trait ProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String);
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String>;
}

pub struct StandardProofAdapter;

impl ProofAdapter for StandardProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        let (status, code) = crate::verify_model_output(output, max_chars);
        (status == "accepted", code.to_string())
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        serde_json::from_str(stdout).map_err(|e| e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{ProofAdapter, StandardProofAdapter};

    #[test]
    fn standard_proof_adapter_reports_verifier_decision_and_reason_code() {
        let adapter = StandardProofAdapter;

        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let (ok, code) = adapter.verify("\u{200B}\u{200C}", 8);
        assert!(!ok);
        assert_eq!(code, "empty_output");

        let (ok, code) = adapter.verify("你好abc", 4);
        assert!(!ok);
        assert_eq!(code, "output_too_long");
    }
}
