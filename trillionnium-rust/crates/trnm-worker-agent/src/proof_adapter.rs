use crate::LlmAdapterResponse;

pub trait ProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String);
    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String>;
}

pub const DEFAULT_PROOF_ADAPTER: &str = "standard";

pub struct StandardProofAdapter;
pub struct TeeReceiptProofAdapter;
pub struct ZkReceiptProofAdapter;

pub fn build_proof_adapter(name: &str) -> Result<Box<dyn ProofAdapter>, String> {
    let normalized = name
        .trim_start_matches('\u{feff}')
        .trim()
        .to_ascii_lowercase();
    match normalized.as_str() {
        "" | DEFAULT_PROOF_ADAPTER | "fraud-proof" | "fraud_proof" => {
            Ok(Box::new(StandardProofAdapter))
        }
        "tee-receipt" | "tee_receipt" => Ok(Box::new(TeeReceiptProofAdapter)),
        "zk-receipt" | "zk_receipt" => Ok(Box::new(ZkReceiptProofAdapter)),
        other => Err(format!("unsupported-proof-adapter:{other}")),
    }
}

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

fn parse_response_with_standard_rules(stdout: &str) -> Result<LlmAdapterResponse, String> {
    let normalized = stdout.trim_start().trim_start_matches('\u{feff}');

    if let Ok(parsed) = serde_json::from_str(normalized) {
        return Ok(parsed);
    }

    for line in normalized.lines().rev().map(str::trim) {
        if line.starts_with('{') && line.ends_with('}') {
            if let Ok(parsed) = serde_json::from_str(line) {
                return Ok(parsed);
            }
        }

        if let (Some(start), Some(end)) = (line.find('{'), line.rfind('}')) {
            if start < end {
                let candidate = &line[start..=end];
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

impl ProofAdapter for StandardProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        let (status, code) = crate::verify_model_output(output, max_chars);
        (status == "accepted", code.to_string())
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        parse_response_with_standard_rules(stdout)
    }
}

impl ProofAdapter for TeeReceiptProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        let (ok, code) = StandardProofAdapter.verify(output, max_chars);
        if !ok {
            return (false, code);
        }
        (true, "tee_receipt_ok".to_string())
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        let parsed = parse_response_with_standard_rules(stdout)?;

        let request_id_ok = parsed
            .provider_request_id
            .as_deref()
            .map(str::trim)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if !request_id_ok {
            return Err("tee-receipt-missing-provider-request-id".to_string());
        }

        let adapter_ok = parsed
            .adapter
            .as_deref()
            .map(str::trim)
            .map(|v| {
                let normalized = v.to_ascii_lowercase();
                normalized == "tee-receipt"
                    || normalized == "tee_receipt"
                    || normalized == "tee-attestation"
            })
            .unwrap_or(false);
        if !adapter_ok {
            return Err("tee-receipt-missing-adapter-label".to_string());
        }

        Ok(parsed)
    }
}

impl ProofAdapter for ZkReceiptProofAdapter {
    fn verify(&self, output: &str, max_chars: usize) -> (bool, String) {
        let (ok, code) = StandardProofAdapter.verify(output, max_chars);
        if !ok {
            return (false, code);
        }
        (true, "zk_receipt_ok".to_string())
    }

    fn parse_response(&self, stdout: &str) -> Result<LlmAdapterResponse, String> {
        let parsed = parse_response_with_standard_rules(stdout)?;

        let request_id_ok = parsed
            .provider_request_id
            .as_deref()
            .map(str::trim)
            .map(|v| !v.is_empty())
            .unwrap_or(false);
        if !request_id_ok {
            return Err("zk-receipt-missing-provider-request-id".to_string());
        }

        let adapter_ok = parsed
            .adapter
            .as_deref()
            .map(str::trim)
            .map(|v| {
                let normalized = v.to_ascii_lowercase();
                normalized == "zk-receipt" || normalized == "zk_receipt" || normalized == "zk-proof"
            })
            .unwrap_or(false);
        if !adapter_ok {
            return Err("zk-receipt-missing-adapter-label".to_string());
        }

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        build_proof_adapter, last_balanced_json_object, ProofAdapter, StandardProofAdapter,
        TeeReceiptProofAdapter, ZkReceiptProofAdapter, DEFAULT_PROOF_ADAPTER,
    };

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
        let stdout =
            "info:adapter payload={\"output_text\":\"ok\",\"provider_request_id\":\"r2\"}\n";

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
    fn tee_receipt_adapter_parse_response_requires_auditable_fields() {
        let adapter = TeeReceiptProofAdapter;

        let ok = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\",\"adapter\":\"tee-receipt\"}",
            )
            .expect("tee receipt payload should parse");
        assert_eq!(ok.provider_request_id.as_deref(), Some("pr-1"));

        let tee_attestation = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2\",\"adapter\":\"tee-attestation\"}",
            )
            .expect("tee attestation alias should parse");
        assert_eq!(tee_attestation.provider_request_id.as_deref(), Some("pr-2"));

        let missing_request_id = adapter
            .parse_response("{\"output_text\":\"ok\",\"adapter\":\"tee-receipt\"}")
            .expect_err("provider_request_id is required");
        assert_eq!(
            missing_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let missing_adapter = adapter
            .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\"}")
            .expect_err("adapter label is required");
        assert_eq!(missing_adapter, "tee-receipt-missing-adapter-label");
    }

    #[test]
    fn zk_receipt_adapter_parse_response_requires_auditable_fields() {
        let adapter = ZkReceiptProofAdapter;

        let ok = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-1\",\"adapter\":\"zk-receipt\"}",
            )
            .expect("zk receipt payload should parse");
        assert_eq!(ok.provider_request_id.as_deref(), Some("pr-zk-1"));

        let zk_proof_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2\",\"adapter\":\"zk-proof\"}",
            )
            .expect("zk proof alias should parse");
        assert_eq!(zk_proof_alias.provider_request_id.as_deref(), Some("pr-zk-2"));

        let missing_request_id = adapter
            .parse_response("{\"output_text\":\"ok\",\"adapter\":\"zk-receipt\"}")
            .expect_err("provider_request_id is required");
        assert_eq!(missing_request_id, "zk-receipt-missing-provider-request-id");

        let missing_adapter = adapter
            .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-3\"}")
            .expect_err("adapter label is required");
        assert_eq!(missing_adapter, "zk-receipt-missing-adapter-label");
    }

    #[test]
    fn last_balanced_json_object_ignores_braces_inside_strings() {
        let payload = "log {\"message\":\"brace } kept\"}\nlog {\"output_text\":\"ok\",\"provider_request_id\":\"r4\"}";
        let candidate =
            last_balanced_json_object(payload).expect("expected a balanced json object");
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
    fn standard_proof_adapter_parse_response_accepts_json_with_whitespace_then_bom_prefix() {
        let adapter = StandardProofAdapter;
        let stdout = "\n  \u{feff}{\"output_text\":\"ok\",\"provider_request_id\":\"r6\"}";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with whitespace before utf-8 bom");
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

    #[test]
    fn build_proof_adapter_accepts_default_and_fraud_and_tee_receipt_and_zk_aliases() {
        let adapter = build_proof_adapter(DEFAULT_PROOF_ADAPTER).expect("default adapter");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("\u{feff} STANDARD ").expect("bom+whitespace default");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("fraud-proof").expect("fraud proof alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("FRAUD_PROOF").expect("fraud proof underscore alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("tee-receipt").expect("tee receipt alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE_RECEIPT").expect("tee receipt underscore alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("zk-receipt").expect("zk receipt alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK_RECEIPT").expect("zk receipt underscore alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let err = match build_proof_adapter("tee-attestation") {
            Ok(_) => panic!("unknown plugin must fail closed"),
            Err(err) => err,
        };
        assert_eq!(err, "unsupported-proof-adapter:tee-attestation");
    }
}
