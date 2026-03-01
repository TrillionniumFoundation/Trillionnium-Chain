use crate::LlmAdapterResponse;

pub trait ProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String);
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String>;
}

pub struct StandardProofAdapter;

fn last_balanced_json_object(input: &str) -> Option<String> {
    let mut depth = 0usize;
    let mut start: Option<usize> = None;
    let mut in_string = false;
    let mut escaped = false;
    let mut last: Option<String> = None;

    for (idx, ch) in input.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
                continue;
            }
            match ch {
                '\\' => escaped = true,
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }

        match ch {
            '"' => in_string = true,
            '{' => {
                if depth == 0 {
                    start = Some(idx);
                }
                depth += 1;
            }
            '}' => {
                if depth == 0 {
                    continue;
                }
                depth -= 1;
                if depth == 0 {
                    if let Some(s) = start {
                        last = Some(input[s..=idx].to_string());
                    }
                    start = None;
                }
            }
            _ => {}
        }
    }

    last
}

impl ProofAdapter for StandardProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        let (status, code) = crate::verify_model_output(output, max_chars);
        (status == "accepted", code.to_string())
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        let normalized = stdout.trim_start_matches('\u{feff}');

        if let Ok(parsed) = serde_json::from_str(normalized) {
            return Ok(parsed);
        }

        for line in normalized.lines().rev().map(str::trim) {
            let line = line.trim_start_matches('\u{feff}');

            if line.starts_with('{') && line.ends_with('}') {
                if let Ok(parsed) = serde_json::from_str(line) {
                    return Ok(parsed);
                }
            }

            if let (Some(start), Some(end)) = (line.find('{'), line.rfind('}')) {
                if start < end {
                    let candidate = line[start..=end].trim_start_matches('\u{feff}');
                    if let Ok(parsed) = serde_json::from_str(candidate) {
                        return Ok(parsed);
                    }
                }
            }
        }

        if let Some(candidate) = last_balanced_json_object(normalized) {
            if let Ok(parsed) = serde_json::from_str::<LlmAdapterResponse>(&candidate) {
                return Ok(parsed);
            }
        }

        Err("no-json-line".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{last_balanced_json_object, ProofAdapter, StandardProofAdapter};

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
    fn standard_proof_adapter_parse_response_accepts_json_embedded_in_log_line() {
        let adapter = StandardProofAdapter;
        let stdout = "info:adapter payload={\"output_text\":\"ok\",\"provider_request_id\":\"r2\"}\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json embedded in log line");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r2"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_multiline_json_payload() {
        let adapter = StandardProofAdapter;
        let stdout = "info: warmup\n```json\n{\n  \"output_text\": \"ok\",\n  \"provider_request_id\": \"r3\"\n}\n```\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse multiline json payload");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3"));
    }

    #[test]
    fn last_balanced_json_object_ignores_braces_inside_strings() {
        let payload = "log {\"message\":\"brace } kept\"}\nlog {\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}";
        let candidate = last_balanced_json_object(payload).expect("expected a balanced json object");
        assert_eq!(
            candidate,
            "{\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}"
        );
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_with_utf8_bom_prefix() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{feff}{\"output_text\":\"ok\",\"provider_request_id\":\"r5\"}";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with leading utf-8 bom");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r5"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_line_with_bom_after_log_prefix() {
        let adapter = StandardProofAdapter;
        let stdout = "debug:warmup\n\u{feff}{\"output_text\":\"ok\",\"provider_request_id\":\"r6\"}\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json line with bom after noise");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r6"));
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
