use std::time::Duration;
use crate::LlmAdapterResponse;

pub trait ProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String);
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String>;
}

pub struct StandardProofAdapter;

impl ProofAdapter for StandardProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        crate::verify_model_output(output, max_chars)
            .map(|(status, code)| (status == "accepted", code.to_string()))
    }
    
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        serde_json::from_str(stdout).map_err(|e| e.to_string())
    }
}
