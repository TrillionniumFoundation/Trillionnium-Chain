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
    let normalized = normalize_adapter_label(name);
    match normalized.as_str() {
        ""
        | DEFAULT_PROOF_ADAPTER
        | "fraud-proof"
        | "fraud_proof"
        | "fraud-proof-v1"
        | "fraud_proof_v1"
        | "fraudproof"
        | "fraudproofv1" => Ok(Box::new(StandardProofAdapter)),
        "tee-receipt" | "tee_receipt" | "tee-receipt-v1" | "tee_receipt_v1" | "tee-attestation"
        | "tee_attestation" | "tee-attestation-v1" | "tee_attestation_v1" | "teereceipt"
        | "teeattestation" | "teereceiptv1" | "teeattestationv1" => {
            Ok(Box::new(TeeReceiptProofAdapter))
        }
        "zk-receipt" | "zk_receipt" | "zk-receipt-v1" | "zk_receipt_v1" | "zk-proof"
        | "zk_proof" | "zk-proof-v1" | "zk_proof_v1" | "zkreceipt" | "zkproof" | "zkproofv1"
        | "zkreceiptv1" => Ok(Box::new(ZkReceiptProofAdapter)),
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

fn is_invisible_receipt_filler(ch: char) -> bool {
    matches!(
        ch,
        '\u{061c}'
            | '\u{00ad}'
            | '\u{034f}'
            | '\u{180e}'
            | '\u{200b}'
            | '\u{200c}'
            | '\u{200d}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{2060}'
            | '\u{2061}'
            | '\u{2062}'
            | '\u{2063}'
            | '\u{2064}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
            | '\u{fe0e}'
            | '\u{fe0f}'
            | '\u{feff}'
    )
}

fn collapse_adapter_delimiters(raw: &str) -> String {
    let mut collapsed = String::with_capacity(raw.len());
    let mut last_was_delimiter = false;

    for ch in raw.chars() {
        let mapped = match ch {
            other if is_invisible_receipt_filler(other) => None,
            '‐' | '‑' | '‒' | '–' | '—' | '―' | '−' | '－' => Some('-'),
            '_' | '/' | '\\' | ':' | '.' => Some('-'),
            other if other.is_whitespace() => Some('-'),
            other => Some(other),
        };

        match mapped {
            Some('-') => {
                if !last_was_delimiter {
                    collapsed.push('-');
                    last_was_delimiter = true;
                }
            }
            Some(other) => {
                collapsed.push(other);
                last_was_delimiter = false;
            }
            None => {}
        }
    }

    collapsed
}

fn peel_outer_quote_wrappers(value: &str) -> &str {
    const QUOTE_WRAPPERS: [(&str, &str); 12] = [
        ("'", "'"),
        ("\"", "\""),
        ("`", "`"),
        ("“", "”"),
        ("‘", "’"),
        ("«", "»"),
        ("‹", "›"),
        ("「", "」"),
        ("『", "』"),
        ("〈", "〉"),
        ("《", "》"),
        ("⟨", "⟩"),
    ];
    const ESCAPED_QUOTE_WRAPPERS: [(&str, &str); 12] = [
        (r#"\'"#, r#"\'"#),
        (r#"\""#, r#"\""#),
        (r#"\`"#, r#"\`"#),
        ("\\“", "\\”"),
        ("\\‘", "\\’"),
        ("\\«", "\\»"),
        ("\\‹", "\\›"),
        ("\\「", "\\」"),
        ("\\『", "\\』"),
        ("\\〈", "\\〉"),
        ("\\《", "\\》"),
        ("\\⟨", "\\⟩"),
    ];

    let mut current = value.trim().trim_start_matches('\u{feff}').trim();

    for _ in 0..16 {
        let mut changed = false;

        for (prefix, suffix) in QUOTE_WRAPPERS {
            if let Some(stripped) = current
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            {
                current = stripped.trim().trim_start_matches('\u{feff}').trim();
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        for (prefix, suffix) in ESCAPED_QUOTE_WRAPPERS {
            if let Some(stripped) = current
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
            {
                current = stripped.trim().trim_start_matches('\u{feff}').trim();
                changed = true;
                break;
            }
        }
        if changed {
            continue;
        }

        break;
    }

    current
}

fn normalize_adapter_label(label: &str) -> String {
    collapse_adapter_delimiters(peel_outer_quote_wrappers(label))
        .trim_matches('-')
        .to_ascii_lowercase()
}

fn normalize_adapter_value(value: &str) -> String {
    collapse_adapter_delimiters(peel_outer_quote_wrappers(value))
        .trim_matches('-')
        .to_ascii_lowercase()
}

fn has_non_empty_auditable_value(value: Option<&str>) -> bool {
    value
        .map(strip_terminal_control_sequences)
        .map(|v| {
            v.chars()
                .filter(|c| !is_invisible_receipt_filler(*c))
                .collect::<String>()
        })
        .map(|v| peel_outer_quote_wrappers(v.as_str()).to_string())
        .map(|v| {
            v.chars()
                .filter(|c| !is_invisible_receipt_filler(*c))
                .collect::<String>()
        })
        .map(|v| v.chars().any(|c| !c.is_whitespace() && !c.is_control()))
        .unwrap_or(false)
}

fn strip_terminal_control_sequences(input: &str) -> String {
    let mut sanitized = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            if ch.is_control() && !matches!(ch, '\n' | '\r' | '\t') {
                continue;
            }
            sanitized.push(ch);
            continue;
        }

        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                while let Some(next) = chars.next() {
                    if ('@'..='~').contains(&next) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                let mut saw_esc = false;
                while let Some(next) = chars.next() {
                    if saw_esc && next == '\\' {
                        break;
                    }
                    saw_esc = next == '\u{1b}';
                    if !saw_esc && next == '\u{7}' {
                        break;
                    }
                }
            }
            Some('P' | '^' | '_') => {
                chars.next();
                let mut saw_esc = false;
                while let Some(next) = chars.next() {
                    if saw_esc && next == '\\' {
                        break;
                    }
                    saw_esc = next == '\u{1b}';
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }

    sanitized
}

fn parse_response_with_standard_rules(stdout: &str) -> Result<LlmAdapterResponse, String> {
    let sanitized = strip_terminal_control_sequences(stdout);
    let normalized = sanitized
        .trim_start()
        .trim_start_matches(is_invisible_receipt_filler);
    let starts_with_json_object = normalized.starts_with('{');

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

    if starts_with_json_object {
        return Err("invalid-json".to_string());
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

        let request_id_ok = has_non_empty_auditable_value(parsed.provider_request_id.as_deref());
        if !request_id_ok {
            return Err("tee-receipt-missing-provider-request-id".to_string());
        }

        let adapter_ok = parsed
            .adapter
            .as_deref()
            .map(normalize_adapter_value)
            .map(|normalized| {
                normalized == "tee-receipt"
                    || normalized == "tee_receipt"
                    || normalized == "tee-receipt-v1"
                    || normalized == "tee_receipt_v1"
                    || normalized == "tee-attestation"
                    || normalized == "tee_attestation"
                    || normalized == "tee-attestation-v1"
                    || normalized == "tee_attestation_v1"
                    || normalized == "teereceipt"
                    || normalized == "teereceiptv1"
                    || normalized == "teeattestation"
                    || normalized == "teeattestationv1"
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

        let request_id_ok = has_non_empty_auditable_value(parsed.provider_request_id.as_deref());
        if !request_id_ok {
            return Err("zk-receipt-missing-provider-request-id".to_string());
        }

        let adapter_ok = parsed
            .adapter
            .as_deref()
            .map(normalize_adapter_value)
            .map(|normalized| {
                normalized == "zk-receipt"
                    || normalized == "zk_receipt"
                    || normalized == "zk-receipt-v1"
                    || normalized == "zk_receipt_v1"
                    || normalized == "zk-proof"
                    || normalized == "zk_proof"
                    || normalized == "zk-proof-v1"
                    || normalized == "zk_proof_v1"
                    || normalized == "zkreceipt"
                    || normalized == "zkreceiptv1"
                    || normalized == "zkproof"
                    || normalized == "zkproofv1"
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
        build_proof_adapter, last_balanced_json_object, normalize_adapter_label,
        normalize_adapter_value, ProofAdapter, StandardProofAdapter, TeeReceiptProofAdapter,
        ZkReceiptProofAdapter, DEFAULT_PROOF_ADAPTER,
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

        let (ok, code) = adapter.verify("helloabc", 4);
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
    fn standard_proof_adapter_parse_response_accepts_json_prefix_before_trailing_logs() {
        let adapter = StandardProofAdapter;
        let stdout =
            "{\"output_text\":\"ok\",\"provider_request_id\":\"r2-prefix\"}\ninfo: cleanup complete\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse leading json object before trailing logs");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r2-prefix"));
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
    fn standard_proof_adapter_parse_response_accepts_crlf_fenced_multiline_json_payload() {
        let adapter = StandardProofAdapter;
        let stdout = "info: warmup\r\n```json\r\n{\r\n  \"output_text\": \"ok\",\r\n  \"provider_request_id\": \"r3-crlf\"\r\n}\r\n```\r\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse CRLF multiline json payload");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-crlf"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_ansi_csi_logs() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{1b}[2K\u{1b}[32minfo\u{1b}[0m warmup\n\u{1b}[33m{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-csi\"}\u{1b}[0m\n";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json wrapped in ansi csi sequences");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-csi"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_ansi_osc_logs() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{1b}]0;worker-agent\u{7}info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-osc\"}\n\u{1b}]133;C\u{1b}\\";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with ansi osc noise around it");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-osc"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_ansi_dcs_logs() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{1b}Ptmux;warmup=1\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-dcs\"}\n\u{1b}Ptmux;cleanup=1\u{1b}\\";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with ansi dcs noise around it");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-dcs"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_ansi_apc_logs() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{1b}_apc warmup\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-apc\"}\n\u{1b}_apc cleanup\u{1b}\\";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with ansi apc noise around it");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-apc"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_ansi_pm_logs() {
        let adapter = StandardProofAdapter;
        let stdout = "\u{1b}^pm warmup\u{1b}\\info: warmup\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-ansi-pm\"}\n\u{1b}^pm cleanup\u{1b}\\";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with ansi pm noise around it");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r3-ansi-pm"));
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_after_raw_control_byte_noise() {
        let adapter = StandardProofAdapter;
        let stdout = "\0\u{2}info: warmup\u{1f}\n{\"output_text\":\"ok\",\"provider_request_id\":\"r3-control-noise\"}\0\u{3}";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with raw control-byte noise around it");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(
            parsed.provider_request_id.as_deref(),
            Some("r3-control-noise")
        );
    }

    #[test]
    fn standard_proof_adapter_parse_response_accepts_json_with_raw_control_byte_prefix() {
        let adapter = StandardProofAdapter;
        let stdout =
            "\0\u{2}{\"output_text\":\"ok\",\"provider_request_id\":\"r3-control-prefix\"}";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with raw control-byte prefix");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(
            parsed.provider_request_id.as_deref(),
            Some("r3-control-prefix")
        );
    }

    #[test]
    fn adapter_label_normalization_peels_nested_and_shell_escaped_quote_wrappers() {
        assert_eq!(
            normalize_adapter_label(" '\"TEE_RECEIPT\"' "),
            "tee-receipt"
        );
        assert_eq!(normalize_adapter_value(" '\"ZK_PROOF\"' "), "zk-proof");
        assert_eq!(
            normalize_adapter_label(r#"\"TEE-ATTESTATION\""#),
            "tee-attestation"
        );
        assert_eq!(normalize_adapter_value(r#"\"ZK-RECEIPT\""#), "zk-receipt");
    }

    #[test]
    fn adapter_label_normalization_peels_smart_and_localized_quote_wrappers() {
        assert_eq!(normalize_adapter_label("“TEE_RECEIPT”"), "tee-receipt");
        assert_eq!(normalize_adapter_value("‘ZK_PROOF’"), "zk-proof");
        assert_eq!(
            normalize_adapter_label("«TEE-ATTESTATION»"),
            "tee-attestation"
        );
        assert_eq!(normalize_adapter_value("‹zk receipt›"), "zk-receipt");
        assert_eq!(normalize_adapter_label("「TEE_RECEIPT」"), "tee-receipt");
        assert_eq!(normalize_adapter_value("『ZK_PROOF』"), "zk-proof");
        assert_eq!(
            normalize_adapter_label("〈TEE-ATTESTATION〉"),
            "tee-attestation"
        );
        assert_eq!(normalize_adapter_value("《ZK_RECEIPT》"), "zk-receipt");
        assert_eq!(normalize_adapter_label("⟨TEE_RECEIPT⟩"), "tee-receipt");
        assert_eq!(normalize_adapter_value("⟨ZK_PROOF⟩"), "zk-proof");
        assert_eq!(normalize_adapter_label(r#"\“TEE_RECEIPT\”"#), "tee-receipt");
        assert_eq!(normalize_adapter_value(r#"\‘ZK_PROOF\’"#), "zk-proof");
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

        let tee_attestation_underscore = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2b\",\"adapter\":\"TEE_ATTESTATION\"}",
            )
            .expect("tee attestation underscore alias should parse");
        assert_eq!(
            tee_attestation_underscore.provider_request_id.as_deref(),
            Some("pr-2b")
        );

        let tee_compact_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2bb\",\"adapter\":\"teeattestation\"}",
            )
            .expect("tee compact alias should parse");
        assert_eq!(
            tee_compact_alias.provider_request_id.as_deref(),
            Some("pr-2bb")
        );

        let tee_attestation_v1 = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2bc\",\"adapter\":\"TEE_ATTESTATION_V1\"}",
            )
            .expect("tee attestation v1 alias should parse");
        assert_eq!(
            tee_attestation_v1.provider_request_id.as_deref(),
            Some("pr-2bc")
        );

        let tee_with_bom_and_whitespace = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2c\",\"adapter\":\"  \\uFEFFTEE_RECEIPT  \"}",
            )
            .expect("tee receipt label with bom+whitespace should parse");
        assert_eq!(
            tee_with_bom_and_whitespace.provider_request_id.as_deref(),
            Some("pr-2c")
        );

        let tee_with_non_breaking_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2d\",\"adapter\":\"TEE‑RECEIPT\"}",
            )
            .expect("tee receipt label with non-breaking hyphen should parse");
        assert_eq!(
            tee_with_non_breaking_hyphen.provider_request_id.as_deref(),
            Some("pr-2d")
        );

        let tee_with_soft_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2d0\",\"adapter\":\"TEE\u{00AD}_RECEIPT\"}",
            )
            .expect("tee receipt label with soft hyphen should parse");
        assert_eq!(
            tee_with_soft_hyphen.provider_request_id.as_deref(),
            Some("pr-2d0")
        );

        let tee_with_zero_width_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2e\",\"adapter\":\"TEE\u{200d}_RECEIPT\"}",
            )
            .expect("tee receipt label with zero-width joiner should parse");
        assert_eq!(
            tee_with_zero_width_joiner.provider_request_id.as_deref(),
            Some("pr-2e")
        );

        let tee_with_directional_isolates = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2e0\",\"adapter\":\"TEE\u{2066}_RECEIPT\u{2069}\"}",
            )
            .expect("tee receipt label with directional isolates should parse");
        assert_eq!(
            tee_with_directional_isolates.provider_request_id.as_deref(),
            Some("pr-2e0")
        );

        let tee_with_left_to_right_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eaa\",\"adapter\":\"TEE\u{200E}_RECEIPT\"}",
            )
            .expect("tee receipt label with left-to-right mark should parse");
        assert_eq!(
            tee_with_left_to_right_mark.provider_request_id.as_deref(),
            Some("pr-2eaa")
        );

        let tee_with_bidi_override = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eab\",\"adapter\":\"TEE\u{202E}_RECEIPT\"}",
            )
            .expect("tee receipt label with bidi override should parse");
        assert_eq!(
            tee_with_bidi_override.provider_request_id.as_deref(),
            Some("pr-2eab")
        );

        let tee_with_word_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ea\",\"adapter\":\"TEE\u{2060}_RECEIPT\"}",
            )
            .expect("tee receipt label with word joiner should parse");
        assert_eq!(
            tee_with_word_joiner.provider_request_id.as_deref(),
            Some("pr-2ea")
        );

        let tee_with_invisible_times = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2eb\",\"adapter\":\"TEE\u{2062}_RECEIPT\"}",
            )
            .expect("tee receipt label with invisible times should parse");
        assert_eq!(
            tee_with_invisible_times.provider_request_id.as_deref(),
            Some("pr-2eb")
        );

        let tee_with_rtl_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ec\",\"adapter\":\"TEE\u{200F}_RECEIPT\"}",
            )
            .expect("tee receipt label with rtl mark should parse");
        assert_eq!(
            tee_with_rtl_mark.provider_request_id.as_deref(),
            Some("pr-2ec")
        );

        let tee_with_embedded_bom = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2f\",\"adapter\":\"TEE\u{feff}_RECEIPT\"}",
            )
            .expect("tee receipt label with embedded bom should parse");
        assert_eq!(
            tee_with_embedded_bom.provider_request_id.as_deref(),
            Some("pr-2f")
        );

        let tee_with_space_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2g\",\"adapter\":\"TEE RECEIPT\"}",
            )
            .expect("tee receipt label with space separator should parse");
        assert_eq!(
            tee_with_space_separator.provider_request_id.as_deref(),
            Some("pr-2g")
        );

        let tee_with_colon_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2h\",\"adapter\":\"TEE:RECEIPT\"}",
            )
            .expect("tee receipt label with colon separator should parse");
        assert_eq!(
            tee_with_colon_separator.provider_request_id.as_deref(),
            Some("pr-2h")
        );

        let tee_with_slash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2i\",\"adapter\":\"TEE/RECEIPT\"}",
            )
            .expect("tee receipt label with slash separator should parse");
        assert_eq!(
            tee_with_slash_separator.provider_request_id.as_deref(),
            Some("pr-2i")
        );

        let tee_with_backslash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2ib\",\"adapter\":\"TEE\\\\RECEIPT\"}",
            )
            .expect("tee receipt label with backslash separator should parse");
        assert_eq!(
            tee_with_backslash_separator.provider_request_id.as_deref(),
            Some("pr-2ib")
        );

        let tee_with_spaced_separators = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2j\",\"adapter\":\" TEE / RECEIPT \"}",
            )
            .expect("tee receipt label with spaced separators should parse");
        assert_eq!(
            tee_with_spaced_separators.provider_request_id.as_deref(),
            Some("pr-2j")
        );

        let tee_with_nested_quote_wrappers = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-2k\",\"adapter\":\" '\\\"TEE_RECEIPT\\\"' \"}",
            )
            .expect("tee receipt label with nested quote wrappers should parse");
        assert_eq!(
            tee_with_nested_quote_wrappers
                .provider_request_id
                .as_deref(),
            Some("pr-2k")
        );

        let missing_request_id = adapter
            .parse_response("{\"output_text\":\"ok\",\"adapter\":\"tee-receipt\"}")
            .expect_err("provider_request_id is required");
        assert_eq!(
            missing_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let bom_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\uFEFF\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("bom-only provider_request_id must fail closed");
        assert_eq!(
            bom_only_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let zero_width_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u200B\\u200D\\u2060\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("zero-width-only provider_request_id must fail closed");
        assert_eq!(
            zero_width_only_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let directional_isolate_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u2066\\u2069\\u180E\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("directional-isolate-only provider_request_id must fail closed");
        assert_eq!(
            directional_isolate_only_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let whitespace_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"   \\n\\t  \",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("whitespace-only provider_request_id must fail closed");
        assert_eq!(
            whitespace_only_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let quote_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\" '\\\"\\\"' \",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("quote-only provider_request_id must fail closed");
        assert_eq!(
            quote_only_request_id,
            "tee-receipt-missing-provider-request-id"
        );

        let missing_adapter = adapter
            .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\"}")
            .expect_err("adapter label is required");
        assert_eq!(missing_adapter, "tee-receipt-missing-adapter-label");

        let bom_only_adapter = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1x\",\"adapter\":\"\\uFEFF\"}",
            )
            .expect_err("bom-only adapter label must fail closed");
        assert_eq!(bom_only_adapter, "tee-receipt-missing-adapter-label");

        let mismatched_adapter = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-1\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("mismatched adapter label must fail closed");
        assert_eq!(mismatched_adapter, "tee-receipt-missing-adapter-label");
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
        assert_eq!(
            zk_proof_alias.provider_request_id.as_deref(),
            Some("pr-zk-2")
        );

        let zk_proof_underscore_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2b\",\"adapter\":\"ZK_PROOF\"}",
            )
            .expect("zk proof underscore alias should parse");
        assert_eq!(
            zk_proof_underscore_alias.provider_request_id.as_deref(),
            Some("pr-zk-2b")
        );

        let zk_proof_v1_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ba\",\"adapter\":\"ZK_PROOF_V1\"}",
            )
            .expect("zk proof v1 underscore alias should parse");
        assert_eq!(
            zk_proof_v1_alias.provider_request_id.as_deref(),
            Some("pr-zk-2ba")
        );

        let zk_compact_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2bb\",\"adapter\":\"zkproof\"}",
            )
            .expect("zk compact alias should parse");
        assert_eq!(
            zk_compact_alias.provider_request_id.as_deref(),
            Some("pr-zk-2bb")
        );

        let zk_compact_v1_alias = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2bc\",\"adapter\":\"zkproofv1\"}",
            )
            .expect("zk compact v1 alias should parse");
        assert_eq!(
            zk_compact_v1_alias.provider_request_id.as_deref(),
            Some("pr-zk-2bc")
        );

        let zk_with_bom_and_whitespace = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2c\",\"adapter\":\"  \\uFEFFZK_RECEIPT  \"}",
            )
            .expect("zk receipt label with bom+whitespace should parse");
        assert_eq!(
            zk_with_bom_and_whitespace.provider_request_id.as_deref(),
            Some("pr-zk-2c")
        );

        let zk_with_non_breaking_hyphen = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2d\",\"adapter\":\"ZK‑RECEIPT\"}",
            )
            .expect("zk receipt label with non-breaking hyphen should parse");
        assert_eq!(
            zk_with_non_breaking_hyphen.provider_request_id.as_deref(),
            Some("pr-zk-2d")
        );

        let zk_with_combining_grapheme_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2d0\",\"adapter\":\"ZK\u{034F}_RECEIPT\"}",
            )
            .expect("zk receipt label with combining grapheme joiner should parse");
        assert_eq!(
            zk_with_combining_grapheme_joiner
                .provider_request_id
                .as_deref(),
            Some("pr-zk-2d0")
        );

        let zk_with_zero_width_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2e\",\"adapter\":\"ZK\u{200d}_RECEIPT\"}",
            )
            .expect("zk receipt label with zero-width joiner should parse");
        assert_eq!(
            zk_with_zero_width_joiner.provider_request_id.as_deref(),
            Some("pr-zk-2e")
        );

        let zk_with_directional_isolates = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2e0\",\"adapter\":\"ZK\u{2066}_RECEIPT\u{2069}\"}",
            )
            .expect("zk receipt label with directional isolates should parse");
        assert_eq!(
            zk_with_directional_isolates.provider_request_id.as_deref(),
            Some("pr-zk-2e0")
        );

        let zk_with_invisible_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eaa\",\"adapter\":\"ZK\u{2063}_RECEIPT\"}",
            )
            .expect("zk receipt label with invisible separator should parse");
        assert_eq!(
            zk_with_invisible_separator.provider_request_id.as_deref(),
            Some("pr-zk-2eaa")
        );

        let zk_with_bidi_embedding = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eab\",\"adapter\":\"ZK\u{202A}_RECEIPT\"}",
            )
            .expect("zk receipt label with bidi embedding should parse");
        assert_eq!(
            zk_with_bidi_embedding.provider_request_id.as_deref(),
            Some("pr-zk-2eab")
        );

        let zk_with_word_joiner = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ea\",\"adapter\":\"ZK\u{2060}_RECEIPT\"}",
            )
            .expect("zk receipt label with word joiner should parse");
        assert_eq!(
            zk_with_word_joiner.provider_request_id.as_deref(),
            Some("pr-zk-2ea")
        );

        let zk_with_invisible_plus = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2eb\",\"adapter\":\"ZK\u{2064}_RECEIPT\"}",
            )
            .expect("zk receipt label with invisible plus should parse");
        assert_eq!(
            zk_with_invisible_plus.provider_request_id.as_deref(),
            Some("pr-zk-2eb")
        );

        let zk_with_arabic_letter_mark = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ec\",\"adapter\":\"ZK\u{061C}_RECEIPT\"}",
            )
            .expect("zk receipt label with arabic letter mark should parse");
        assert_eq!(
            zk_with_arabic_letter_mark.provider_request_id.as_deref(),
            Some("pr-zk-2ec")
        );

        let zk_with_embedded_bom = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2f\",\"adapter\":\"ZK\u{feff}_RECEIPT\"}",
            )
            .expect("zk receipt label with embedded bom should parse");
        assert_eq!(
            zk_with_embedded_bom.provider_request_id.as_deref(),
            Some("pr-zk-2f")
        );

        let zk_with_space_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2g\",\"adapter\":\"ZK RECEIPT\"}",
            )
            .expect("zk receipt label with space separator should parse");
        assert_eq!(
            zk_with_space_separator.provider_request_id.as_deref(),
            Some("pr-zk-2g")
        );

        let zk_with_slash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2h\",\"adapter\":\"ZK/RECEIPT\"}",
            )
            .expect("zk receipt label with slash separator should parse");
        assert_eq!(
            zk_with_slash_separator.provider_request_id.as_deref(),
            Some("pr-zk-2h")
        );

        let zk_with_colon_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2i\",\"adapter\":\"ZK:RECEIPT\"}",
            )
            .expect("zk receipt label with colon separator should parse");
        assert_eq!(
            zk_with_colon_separator.provider_request_id.as_deref(),
            Some("pr-zk-2i")
        );

        let zk_with_backslash_separator = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ib\",\"adapter\":\"ZK\\\\RECEIPT\"}",
            )
            .expect("zk receipt label with backslash separator should parse");
        assert_eq!(
            zk_with_backslash_separator.provider_request_id.as_deref(),
            Some("pr-zk-2ib")
        );

        let zk_with_spaced_separators = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2j\",\"adapter\":\" ZK - RECEIPT \"}",
            )
            .expect("zk receipt label with spaced separators should parse");
        assert_eq!(
            zk_with_spaced_separators.provider_request_id.as_deref(),
            Some("pr-zk-2j")
        );

        let zk_with_nested_quote_wrappers = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-2ic\",\"adapter\":\" '\\\"ZK_RECEIPT\\\"' \"}",
            )
            .expect("zk receipt label with nested quote wrappers should parse");
        assert_eq!(
            zk_with_nested_quote_wrappers.provider_request_id.as_deref(),
            Some("pr-zk-2ic")
        );

        let missing_request_id = adapter
            .parse_response("{\"output_text\":\"ok\",\"adapter\":\"zk-receipt\"}")
            .expect_err("provider_request_id is required");
        assert_eq!(missing_request_id, "zk-receipt-missing-provider-request-id");

        let bom_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\uFEFF\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("bom-only provider_request_id must fail closed");
        assert_eq!(
            bom_only_request_id,
            "zk-receipt-missing-provider-request-id"
        );

        let zero_width_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u200B\\u200D\\u2060\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("zero-width-only provider_request_id must fail closed");
        assert_eq!(
            zero_width_only_request_id,
            "zk-receipt-missing-provider-request-id"
        );

        let directional_isolate_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"\\u2066\\u2069\\u180E\",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("directional-isolate-only provider_request_id must fail closed");
        assert_eq!(
            directional_isolate_only_request_id,
            "zk-receipt-missing-provider-request-id"
        );

        let whitespace_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"   \\n\\t  \",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("whitespace-only provider_request_id must fail closed");
        assert_eq!(
            whitespace_only_request_id,
            "zk-receipt-missing-provider-request-id"
        );

        let quote_only_request_id = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\" '\\\"\\\"' \",\"adapter\":\"zk-receipt\"}",
            )
            .expect_err("quote-only provider_request_id must fail closed");
        assert_eq!(
            quote_only_request_id,
            "zk-receipt-missing-provider-request-id"
        );

        let missing_adapter = adapter
            .parse_response("{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-3\"}")
            .expect_err("adapter label is required");
        assert_eq!(missing_adapter, "zk-receipt-missing-adapter-label");

        let bom_only_adapter = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-3x\",\"adapter\":\"\\uFEFF\"}",
            )
            .expect_err("bom-only adapter label must fail closed");
        assert_eq!(bom_only_adapter, "zk-receipt-missing-adapter-label");

        let mismatched_adapter = adapter
            .parse_response(
                "{\"output_text\":\"ok\",\"provider_request_id\":\"pr-zk-4\",\"adapter\":\"tee-receipt\"}",
            )
            .expect_err("mismatched adapter label must fail closed");
        assert_eq!(mismatched_adapter, "zk-receipt-missing-adapter-label");
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
    fn standard_proof_adapter_parse_response_accepts_json_with_zero_width_filler_prefix() {
        let adapter = StandardProofAdapter;
        let stdout =
            "\u{200b}\u{200c}\u{2060}{\"output_text\":\"ok\",\"provider_request_id\":\"r6-zwsp\"}";

        let parsed = adapter
            .parse_response(stdout)
            .expect("should parse json with zero-width filler prefix");
        assert_eq!(parsed.output_text, "ok");
        assert_eq!(parsed.provider_request_id.as_deref(), Some("r6-zwsp"));
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

        let adapter = build_proof_adapter(" \n\t ").expect("whitespace-only defaults to standard");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter =
            build_proof_adapter("\u{feff} \n\t").expect("bom+whitespace defaults to standard");
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

        let adapter = build_proof_adapter("FRAUD\u{200d}_PROOF")
            .expect("fraud proof alias should strip zero-width joiner");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("fraud-proof-v1").expect("fraud proof v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter =
            build_proof_adapter("FRAUD_PROOF_V1").expect("fraud proof underscore v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("fraudproof").expect("fraud proof compact alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "ok");

        let adapter = build_proof_adapter("fraudproofv1").expect("fraud proof compact v1 alias");
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

        let adapter = build_proof_adapter("  \u{feff}TEE_RECEIPT  ")
            .expect("tee receipt alias should tolerate whitespace+bom");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE_RECEIPT_V1").expect("tee v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE‑RECEIPT").expect("tee non-breaking hyphen alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\u{200d}_RECEIPT")
            .expect("tee alias should strip zero-width joiner");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\u{2066}_RECEIPT\u{2069}")
            .expect("tee alias should strip directional isolates");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\u{202E}_RECEIPT")
            .expect("tee alias should strip bidi override controls");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\u{2062}_RECEIPT")
            .expect("tee alias should strip invisible times");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter =
            build_proof_adapter("TEE\u{200F}_RECEIPT").expect("tee alias should strip rtl mark");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\u{feff}_RECEIPT").expect("tee embedded bom alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE\\RECEIPT")
            .expect("tee backslash separator alias should normalize");
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

        let adapter = build_proof_adapter("ZK\\RECEIPT")
            .expect("zk backslash separator alias should normalize");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("zk_receipt_v1").expect("zk v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK‑RECEIPT").expect("zk non-breaking hyphen alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{200d}_RECEIPT")
            .expect("zk alias should strip zero-width joiner");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{2066}_RECEIPT\u{2069}")
            .expect("zk alias should strip directional isolates");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{202A}_RECEIPT")
            .expect("zk alias should strip bidi embedding controls");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{2064}_RECEIPT")
            .expect("zk alias should strip invisible plus");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{061C}_RECEIPT")
            .expect("zk alias should strip arabic letter mark");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK\u{feff}_RECEIPT").expect("zk embedded bom alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("tee-attestation").expect("tee attestation alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("teeattestation").expect("tee compact alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("TEE_ATTESTATION_V1").expect("tee attestation v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");

        let adapter = build_proof_adapter("zk-proof").expect("zk proof alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("zk-proof-v1").expect("zk proof v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("ZK_PROOF_V1").expect("zk proof underscore v1 alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("zkproof").expect("zk compact alias");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "zk_receipt_ok");

        let adapter = build_proof_adapter("tee attestation")
            .expect("tee attestation space-separated alias should parse");
        let (ok, code) = adapter.verify("hello", 8);
        assert!(ok);
        assert_eq!(code, "tee_receipt_ok");
    }

    #[test]
    fn build_proof_adapter_accepts_separator_aliases_for_receipt_modes() {
        for label in [
            "FRAUD PROOF",
            "FRAUD/PROOF",
            "FRAUD:PROOF",
            " FRAUD / PROOF ",
            "FRAUD - PROOF",
            "FRAUD PROOF V1",
            "FRAUD/PROOF/V1",
            "FRAUD:PROOF:V1",
        ] {
            let adapter = build_proof_adapter(label)
                .unwrap_or_else(|_| panic!("fraud separator alias should parse: {label}"));
            let (ok, code) = adapter.verify("hello", 8);
            assert!(ok, "fraud separator alias should verify: {label}");
            assert_eq!(code, "ok", "fraud alias code mismatch: {label}");
        }

        for label in [
            "TEE RECEIPT",
            "TEE/RECEIPT",
            "TEE:RECEIPT",
            " TEE / RECEIPT ",
            "TEE - RECEIPT",
        ] {
            let adapter = build_proof_adapter(label)
                .unwrap_or_else(|_| panic!("tee separator alias should parse: {label}"));
            let (ok, code) = adapter.verify("hello", 8);
            assert!(ok, "tee separator alias should verify: {label}");
            assert_eq!(code, "tee_receipt_ok", "tee alias code mismatch: {label}");
        }

        for label in [
            "ZK RECEIPT",
            "ZK/RECEIPT",
            "ZK:RECEIPT",
            " ZK / RECEIPT ",
            "ZK - RECEIPT",
        ] {
            let adapter = build_proof_adapter(label)
                .unwrap_or_else(|_| panic!("zk separator alias should parse: {label}"));
            let (ok, code) = adapter.verify("hello", 8);
            assert!(ok, "zk separator alias should verify: {label}");
            assert_eq!(code, "zk_receipt_ok", "zk alias code mismatch: {label}");
        }
    }
}
