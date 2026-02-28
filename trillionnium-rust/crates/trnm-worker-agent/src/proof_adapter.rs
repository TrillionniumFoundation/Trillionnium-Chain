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
        if let Ok(parsed) = serde_json::from_str(stdout) {
            return Ok(parsed);
        }

        let lines: Vec<&str> = stdout.lines().collect();
        for start in (0..lines.len()).rev() {
            let head = lines[start].trim_start();
            if !head.starts_with('{') {
                continue;
            }
            let candidate = lines[start..].join("\n");
            if let Ok(parsed) = serde_json::from_str::<LlmAdapterResponse>(candidate.trim()) {
                return Ok(parsed);
            }
        }

        Err("no-json-line".to_string())
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

    #[test]
    fn standard_proof_adapter_parse_response_accepts_last_json_line_after_noise() {
        let adapter = StandardProofAdapter;
        let stdout = "debug:warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r1\"}\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse trailing json line");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r1"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_trailing_pretty_json_block() {
        let adapter = StandardProofAdapter;
        let stdout = "debug:warmup\n{\n  \"output_text\": \"ok\",\n  \"provider_request_id\": \"r2\"\n}\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse trailing pretty json block");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r2"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_rejects_without_json_line() {
        let adapter = StandardProofAdapter;
        let err = adapter
            .parse_response("debug:warmup\nstatus=ok\n")
            .expect_err("missing json should be rejected");
        assert_eq!(err, "no-json-line");
    }
}
