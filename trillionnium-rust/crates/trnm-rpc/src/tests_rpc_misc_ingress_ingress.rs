use super::*;
use std::os::unix::fs::MetadataExt;

#[test]
fn quarantine_record_within_bounds_rejects_oversized_or_blank_fields() {
    let valid = IngressQuarantineRecord {
        source_path: "/tmp/ingress.jsonl".to_string(),
        line_number: 1,
        line_hash: 7,
        raw_line: "{\"broken\":1".to_string(),
        error: "EOF while parsing a value at line 1 column 12".to_string(),
        quarantined_at_unix_ms: 1,
    };
    assert!(
        quarantine_record_within_bounds(&valid),
        "well-formed quarantine entries should be retained"
    );

    let blank_error = IngressQuarantineRecord {
        error: "   ".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&blank_error),
        "blank parse context should be rejected fail-closed"
    );

    let zero_line_hash = IngressQuarantineRecord {
        line_hash: 0,
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&zero_line_hash),
        "zero hash quarantine identities should be rejected fail-closed"
    );

    let oversized_line_number = IngressQuarantineRecord {
        line_number: 1_048_577,
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&oversized_line_number),
        "implausibly large retained line numbers should be rejected fail-closed"
    );

    let oversized_raw_line = IngressQuarantineRecord {
        raw_line: "x".repeat(4097),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&oversized_raw_line),
        "raw ingress payload echoes should stay noise-bounded"
    );

    let oversized_source_path = IngressQuarantineRecord {
        source_path: "x".repeat(4097),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&oversized_source_path),
        "source path metadata should stay field-bounded"
    );

    let oversized_error = IngressQuarantineRecord {
        error: "x".repeat(4097),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&oversized_error),
        "error payloads should stay field-bounded"
    );

    let control_char_raw_line = IngressQuarantineRecord {
        raw_line: "{\"broken\":\u0000}".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&control_char_raw_line),
        "control characters in quarantined payload echoes should fail closed"
    );

    let bidi_override_error = IngressQuarantineRecord {
        error: "parse failed \u{202e}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&bidi_override_error),
        "bidi override characters should be rejected to keep quarantine logs unambiguous"
    );

    let line_separator_source_path = IngressQuarantineRecord {
        source_path: "/tmp/ingress\u{2028}jsonl".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&line_separator_source_path),
        "unicode line separators should be rejected from quarantine metadata"
    );

    let zero_width_error = IngressQuarantineRecord {
        error: "parse failed\u{200b}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&zero_width_error),
        "zero-width quarantine characters should be rejected to keep retained logs unambiguous"
    );

    let left_to_right_mark_error = IngressQuarantineRecord {
        error: "parse failed\u{200e}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&left_to_right_mark_error),
        "invisible bidi marks should be rejected to keep retained logs unambiguous"
    );

    let right_to_left_mark_source_path = IngressQuarantineRecord {
        source_path: "/tmp/ingress\u{200f}jsonl".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&right_to_left_mark_source_path),
        "rtl marks should be rejected from quarantine metadata"
    );

    let arabic_letter_mark_raw_line = IngressQuarantineRecord {
        raw_line: "{\"broken\":\"\u{061c}tail\"}".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&arabic_letter_mark_raw_line),
        "arabic letter mark should be rejected to keep quarantine payload echoes unambiguous"
    );

    let tag_character_error = IngressQuarantineRecord {
        error: "parse failed\u{E0001}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&tag_character_error),
        "invisible unicode tag characters should be rejected to keep quarantine logs unambiguous"
    );

    let unicode_noncharacter_error = IngressQuarantineRecord {
        error: "parse failed\u{FDD0}json".to_string(),
        ..valid
    };
    assert!(
        !quarantine_record_within_bounds(&unicode_noncharacter_error),
        "unicode noncharacters should be rejected to keep retained quarantine logs unambiguous"
    );
}

#[test]
fn load_ingress_records_quarantines_control_char_utf8_lines_with_sanitized_raw_line() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-control-char", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, b"{\"broken\":\x00}\n").expect("write control-char ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "control-char malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "control-char malformed ingress row should be quarantined");
    assert_eq!(entries[0]["error"], "control character (\\u0000-\\u001F) found while parsing a value at line 1 column 11");
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert_eq!(raw_line, "{\"broken\":�}");
    assert!(
        !raw_line.chars().any(|ch| ch.is_control()),
        "quarantine raw_line should sanitize control characters before retention"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_sanitizes_quarantine_source_path_metadata() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-path-\u{202e}meta", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, b"{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "malformed ingress row should be quarantined");

    let source_path = entries[0]["source_path"]
        .as_str()
        .expect("quarantine source_path should be a string");
    assert!(
        source_path.contains('�'),
        "quarantine source_path should sanitize ambiguous bidi metadata"
    );
    assert!(
        !source_path.contains('\u{202e}'),
        "quarantine source_path should not retain bidi override characters"
    );
    assert_eq!(entries[0]["line_number"], 1);

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_sanitizes_quarantine_source_path_tag_metadata() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-path-\u{E0001}meta", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, b"{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "malformed ingress row should be quarantined");

    let source_path = entries[0]["source_path"]
        .as_str()
        .expect("quarantine source_path should be a string");
    assert!(
        source_path.contains('�'),
        "quarantine source_path should sanitize invisible tag metadata"
    );
    assert!(
        !source_path.contains('\u{E0001}'),
        "quarantine source_path should not retain invisible tag characters"
    );
    assert_eq!(entries[0]["line_number"], 1);

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_quarantines_oversized_malformed_lines_with_accounting() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_malformed = format!("{{\"broken\":\"{}", "x".repeat(70_000));
    fs::write(
        &path,
        format!(
            concat!(
                "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
                "{}\n"
            ),
            oversized_malformed
        ),
    )
    .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(
        records.len(),
        1,
        "valid ingress rows should survive salvage"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "oversized malformed ingress row should be quarantined"
    );
    assert_eq!(entries[0]["line_number"], 2);
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert_eq!(raw_line.len(), 4096, "quarantine raw_line should be bounded");
    assert!(
        oversized_malformed.starts_with(raw_line),
        "quarantine raw_line should preserve the malformed prefix"
    );
    assert_eq!(
        entries[0]["error"],
        "ingress line exceeds 65536 bytes parse bound (got 70010)"
    );
    assert_eq!(entries[0]["source_path"], path.display().to_string());

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_oversized_quarantine_hash_distinguishes_different_tails() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-hash-bounds", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let shared_prefix = format!("{{\"broken\":\"{}", "x".repeat(69_000));
    let malformed_a = format!("{}tail-a", shared_prefix);
    let malformed_b = format!("{}tail-b", shared_prefix);
    fs::write(&path, format!("{}\n{}\n", malformed_a, malformed_b)).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed oversized rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 2, "both malformed oversized rows should be quarantined");
    assert_eq!(
        entries[0]["raw_line"].as_str(),
        entries[1]["raw_line"].as_str(),
        "quarantine raw_line truncation may match when only distant tails differ"
    );
    assert_ne!(
        entries[0]["line_hash"],
        entries[1]["line_hash"],
        "bounded line hashing should still distinguish different oversized malformed tails"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_oversized_quarantine_hash_distinguishes_different_middles() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-hash-middle-bounds", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let prefix = format!("{{\"broken\":\"{}", "x".repeat(35_000));
    let suffix = format!("{}\"", "z".repeat(35_000));
    let malformed_a = format!("{}MID-A{}", prefix, suffix);
    let malformed_b = format!("{}MID-B{}", prefix, suffix);
    fs::write(&path, format!("{}\n{}\n", malformed_a, malformed_b)).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed oversized rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 2, "bounded hashing should not dedupe oversized malformed rows that differ only mid-body");
    assert_eq!(
        entries[0]["raw_line"].as_str(),
        entries[1]["raw_line"].as_str(),
        "quarantine raw_line truncation may match when only distant middles differ"
    );
    assert_ne!(
        entries[0]["line_hash"],
        entries[1]["line_hash"],
        "bounded line hashing should sample the oversized middle to distinguish same-edge malformed rows"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_oversized_invalid_utf8_quarantines_with_parse_bound_error() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-oversized-invalid-utf8", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut fixture = Vec::new();
    fixture.extend_from_slice(b"{\"broken\":\"");
    fixture.extend_from_slice(&vec![b'x'; 70_000]);
    fixture.extend_from_slice(&[0xF0, 0x28, 0x8C, 0x28]);
    fixture.extend_from_slice(b"\n");
    fs::write(&path, fixture).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "oversized invalid utf-8 ingress rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "oversized invalid utf-8 row should be quarantined");
    assert_eq!(
        entries[0]["error"],
        "ingress line exceeds 65536 bytes parse bound (got 70016)"
    );
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert_eq!(raw_line.len(), 4096, "quarantine raw_line should stay byte-bounded");
    assert!(
        !raw_line.contains('�'),
        "quarantine truncation should avoid lossy decoding of distant oversized invalid tails"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_invalid_utf8_quarantine_hash_distinguishes_different_tails() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-invalid-utf8-hash-bounds", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let shared_prefix = vec![b'x'; 69_000];
    let mut fixture = Vec::new();
    fixture.extend_from_slice(b"{\"broken\":\"");
    fixture.extend_from_slice(&shared_prefix);
    fixture.extend_from_slice(b"tail-a");
    fixture.extend_from_slice(&[0xF0, 0x28, 0x8C, 0x28]);
    fixture.extend_from_slice(b"\n");
    fixture.extend_from_slice(b"{\"broken\":\"");
    fixture.extend_from_slice(&shared_prefix);
    fixture.extend_from_slice(b"tail-b");
    fixture.extend_from_slice(&[0xF0, 0x28, 0x8C, 0x28]);
    fixture.extend_from_slice(b"\n");
    fs::write(&path, fixture).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "invalid utf-8 ingress rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 2, "both invalid utf-8 rows should be quarantined");
    assert_eq!(
        entries[0]["raw_line"].as_str(),
        entries[1]["raw_line"].as_str(),
        "quarantine raw_line truncation may match when only distant tails differ"
    );
    assert_ne!(
        entries[0]["line_hash"],
        entries[1]["line_hash"],
        "bounded hashing should distinguish different invalid utf-8 tails beyond quarantine truncation"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_bounds_invalid_utf8_quarantine_raw_line_after_lossy_decode() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-invalid-utf8-lossy-bounds", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut fixture = vec![0xFF; 5_000];
    fixture.push(b'\n');
    fs::write(&path, fixture).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "invalid utf-8 ingress rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "invalid utf-8 ingress row should be quarantined");
    assert_eq!(entries[0]["error"], "ingress line is not valid utf-8");
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert!(
        raw_line.contains('�'),
        "lossy quarantine output should preserve invalid utf-8 markers for debugging"
    );
    assert!(
        raw_line.as_bytes().len() <= 4096,
        "quarantine raw_line should stay byte-bounded after lossy utf-8 decoding"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_keeps_clean_trailing_newline_files_stable() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-clean-trailing-newline-stable", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let valid = concat!(
        "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n"
    );
    fs::write(&path, valid).expect("write clean ingress fixture");
    let before_ino = fs::metadata(&path).expect("metadata before load").ino();

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "clean ingress row should load normally");
    assert!(
        !quarantine.exists(),
        "clean ingress rows with a trailing newline should not create quarantine noise"
    );

    let after_ino = fs::metadata(&path).expect("metadata after load").ino();
    assert_eq!(
        after_ino, before_ino,
        "clean ingress files ending with a newline should not be atomically rewritten just for a phantom trailing empty line"
    );
    let raw = fs::read_to_string(&path).expect("read clean ingress fixture");
    assert_eq!(raw, valid, "clean trailing-newline ingress content should remain untouched");

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_compacts_whitespace_only_noise_without_quarantine() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-whitespace-noise-compact", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let whitespace_noise = format!("{}\r\n", " ".repeat(70_000));
    fs::write(
        &path,
        format!(
            concat!(
                "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
                "{}"
            ),
            whitespace_noise
        ),
    )
    .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid ingress rows should survive whitespace-noise compaction");
    assert!(
        !quarantine.exists(),
        "whitespace-only ingress noise should be compacted instead of quarantined"
    );

    let salvaged_raw = fs::read_to_string(&path).expect("read compacted ingress file");
    let salvaged_lines: Vec<&str> = salvaged_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(salvaged_lines.len(), 1, "compaction should drop whitespace-only noise lines");
    assert!(
        salvaged_lines[0].contains("\"request_id\":\"req-1\""),
        "compaction should retain the valid ingress record"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_compacts_unicode_whitespace_only_noise_without_quarantine() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-unicode-whitespace-noise-compact", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let unicode_whitespace_noise = format!("{}\n", "\u{3000}".repeat(3_000));
    fs::write(
        &path,
        format!(
            concat!(
                "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
                "{}"
            ),
            unicode_whitespace_noise
        ),
    )
    .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid ingress rows should survive unicode-whitespace compaction");
    assert!(
        !quarantine.exists(),
        "unicode whitespace-only ingress noise should be compacted instead of quarantined"
    );

    let salvaged_raw = fs::read_to_string(&path).expect("read compacted ingress file");
    let salvaged_lines: Vec<&str> = salvaged_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(salvaged_lines.len(), 1, "compaction should drop unicode-whitespace noise lines");
    assert!(
        salvaged_lines[0].contains("\"request_id\":\"req-1\""),
        "compaction should retain the valid ingress record"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_quarantines_crlf_line_that_only_exceeds_parse_bound_on_disk() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-crlf-parse-bound-on-disk", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_json = format!("{{\"payload\":\"{}\"}}\r\n", "x".repeat(65_522));
    fs::write(&path, oversized_json).expect("write crlf oversized ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "crlf ingress row beyond the on-disk parse bound should fail closed");
    assert!(quarantine.exists(), "oversized crlf ingress row should be quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "one oversized crlf ingress row should be quarantined");
    assert_eq!(
        entries[0]["error"],
        "ingress line exceeds 65536 bytes parse bound (got 65537)",
        "parse-bound accounting should use the on-disk line length before CR trimming"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_quarantines_oversized_ascii_whitespace_only_noise() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-oversized-ascii-whitespace-noise-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let ascii_whitespace_noise = format!("{}\n", " ".repeat(70_000));
    fs::write(
        &path,
        format!(
            concat!(
                "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
                "{}"
            ),
            ascii_whitespace_noise
        ),
    )
    .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid ingress rows should survive oversized ascii-whitespace quarantine");
    assert!(
        quarantine.exists(),
        "oversized ascii whitespace-only ingress noise should be quarantined"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        1,
        "one oversized ascii-whitespace line should be quarantined"
    );
    assert!(
        quarantine_lines[0].contains("whitespace-only line omitted"),
        "quarantine entry should replace blank raw payload with an explicit marker"
    );
    assert!(
        quarantine_lines[0].contains("exceeds 65536 bytes parse bound (got 70000)"),
        "quarantine entry should preserve the parse-bound error"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_quarantines_oversized_unicode_whitespace_only_noise() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-oversized-unicode-whitespace-noise-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let unicode_whitespace_noise = format!("{}\n", "\u{3000}".repeat(30_000));
    fs::write(
        &path,
        format!(
            concat!(
                "{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n",
                "{}"
            ),
            unicode_whitespace_noise
        ),
    )
    .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid ingress rows should survive oversized unicode-whitespace quarantine");
    assert!(
        quarantine.exists(),
        "oversized unicode whitespace-only ingress noise should be quarantined"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        1,
        "one oversized unicode-whitespace line should be quarantined"
    );
    assert!(
        quarantine_lines[0].contains("whitespace-only line omitted"),
        "quarantine entry should replace blank raw payload with an explicit marker"
    );
    assert!(
        quarantine_lines[0].contains("exceeds 65536 bytes parse bound"),
        "quarantine entry should preserve the parse-bound error"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_quarantines_invalid_utf8_line_without_dropping_valid_rows() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-invalid-utf8", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut fixture = Vec::new();
    fixture.extend_from_slice(b"{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n");
    fixture.extend_from_slice(b"{\"broken\":\"");
    fixture.extend_from_slice(&[0xF0, 0x28, 0x8C, 0x28]);
    fixture.extend_from_slice(b"\"}\n");
    fs::write(&path, fixture).expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid utf-8 ingress rows should survive salvage");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "invalid utf-8 ingress row should be quarantined");
    assert_eq!(entries[0]["line_number"], 2);
    assert_eq!(entries[0]["error"], "ingress line is not valid utf-8");
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert!(
        raw_line.contains('�'),
        "invalid utf-8 should be lossily preserved in quarantine for debugging"
    );

    let salvaged_raw = fs::read_to_string(&path).expect("read salvaged ingress file");
    let salvaged_lines: Vec<&str> = salvaged_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(salvaged_lines.len(), 1, "salvage should retain only valid ingress rows");

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_deduplicates_repeated_quarantine_noise_per_scan() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-bounded", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut fixture = String::new();
    fixture.push_str("{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n");
    for _ in 0..130 {
        fixture.push_str("{\"broken\":1\n");
    }
    fs::write(&path, fixture).expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(records.len(), 1, "valid ingress rows should survive salvage");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "quarantine append should deduplicate repeated malformed-ingress noise within a scan"
    );
    assert_eq!(entries[0]["line_number"], 2);
    assert!(
        entries[0]["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "repeated malformed rows should stay fail-closed in quarantine"
    );

    let salvaged_raw = fs::read_to_string(&path).expect("read salvaged ingress file");
    let salvaged_lines: Vec<&str> = salvaged_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        salvaged_lines.len(),
        1,
        "salvage should retain only valid ingress rows after quarantine succeeds"
    );

    let records_second = load_ingress_records();
    assert_eq!(
        records_second.len(),
        1,
        "subsequent scans should keep the salvaged valid row"
    );
    let quarantine_second_raw = fs::read_to_string(&quarantine).expect("read quarantine file again");
    let entries_second: Vec<serde_json::Value> = quarantine_second_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries_second.len(),
        1,
        "subsequent scans should not append duplicate quarantine noise once salvage rewrites ingress"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_skips_invalid_utf8_preexisting_quarantine_noise_without_dropping_valid_rows() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-invalid-utf8-retained-noise", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let retained = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 7,
        "line_hash": 77,
        "raw_line": "{\"broken\":77",
        "error": "EOF while parsing a value at line 1 column 13",
        "quarantined_at_unix_ms": 123,
    });
    let mut quarantine_fixture = serde_json::to_vec(&retained).expect("serialize retained quarantine entry");
    quarantine_fixture.extend_from_slice(b"\n");
    quarantine_fixture.extend_from_slice(&[0xF0, 0x28, 0x8C, 0x28]);
    quarantine_fixture.extend_from_slice(b"\n");
    fs::write(&quarantine, quarantine_fixture).expect("write invalid utf-8 quarantine noise");
    fs::write(&path, "{\"broken\":99\n").expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 2, "invalid utf-8 retained noise should be skipped, not wipe valid retained entries");
    assert_eq!(entries[0]["line_hash"], 77);
    assert_eq!(entries[1]["line_number"], 1);
    assert!(
        entries[1]["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after skipping invalid utf-8 retained noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_malformed_quarantine_noise() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-corrupt-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&quarantine, "not-json\n{\"broken\":true}\n").expect("seed malformed quarantine file");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "preexisting malformed quarantine noise should be discarded");
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_deduplicates_preexisting_quarantine_noise_on_rewrite() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-dedupe-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let retained = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 7,
        "line_hash": 77,
        "raw_line": "{\"broken\":77",
        "error": "EOF while parsing a value at line 1 column 13",
        "quarantined_at_unix_ms": 123,
    });
    let retained_line = serde_json::to_string(&retained).expect("serialize retained quarantine entry");
    fs::write(&quarantine, format!("{0}\n{0}\n", retained_line))
        .expect("seed duplicate quarantine noise");
    fs::write(&path, "{\"broken\":99\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "rewrite should collapse duplicate retained quarantine noise before appending new entries"
    );
    assert_eq!(entries[0]["line_number"], 7);
    assert_eq!(entries[1]["line_number"], 1);

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_oversized_preexisting_quarantine_noise() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-oversized-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_noise = format!("{}\n", "x".repeat(1_048_577));
    fs::write(&quarantine, oversized_noise).expect("seed oversized quarantine noise");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(lines.len(), 1, "oversized preexisting quarantine noise should be discarded");
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after oversized noise reset"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_wrong_field_types() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-schema-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let malformed_retained_entry = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": "not-a-number",
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "seeded quarantine entry with wrong field types",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&malformed_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed malformed-schema quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries with invalid schema should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should replace malformed-schema retained noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_oversized_raw_line() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-oversized-raw-line-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_retained_entry = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "x".repeat(4097),
        "error": "seeded oversized quarantine entry",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&oversized_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed oversized raw_line quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries beyond raw_line bounds should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        entry["raw_line"].as_str().expect("raw_line string").len() < 4097,
        "new quarantined ingress row should replace oversized retained noise"
    );
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after dropping oversized retained noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_oversized_source_path() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-oversized-source-path-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_retained_entry = serde_json::json!({
        "source_path": "x".repeat(4097),
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "seeded oversized source_path quarantine entry",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&oversized_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed oversized source_path quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries beyond source_path bounds should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert_eq!(
        entry["source_path"],
        path.display().to_string(),
        "new quarantined ingress row should replace oversized retained source_path noise"
    );
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after dropping oversized retained source_path noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_blank_error() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-blank-error-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let blank_error_retained_entry = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "   ",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&blank_error_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed blank-error quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries with blank error should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        !entry["error"].as_str().expect("error string").trim().is_empty(),
        "new quarantined ingress row should replace retained entries missing parse context"
    );
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after dropping blank-error retained noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_missing_source_path() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-empty-source-path-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let missing_source_path_retained_entry = serde_json::json!({
        "source_path": "",
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "seeded quarantine entry with missing source path",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&missing_source_path_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed missing-source-path quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries with missing source path should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert_eq!(entry["source_path"], path.display().to_string());
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should replace retained entries missing source path"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_drops_preexisting_quarantine_entries_with_oversized_serialized_line() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-oversized-serialized-line-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized_retained_entry = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "x".repeat(20_000),
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&oversized_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed oversized serialized quarantine entry");
    fs::write(&path, "{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines.len(),
        1,
        "preexisting quarantine entries beyond serialized line bounds should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        lines[0].as_bytes().len() < 16_384,
        "new quarantined ingress row should replace oversized retained serialized noise"
    );
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after dropping oversized retained serialized noise"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_bounds_total_quarantine_file_growth() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-retention-bounds", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    for batch in 0..9 {
        let mut fixture = String::new();
        for idx in 0..128 {
            fixture.push_str(&format!("{{\"broken\":{}\n", batch * 128 + idx));
        }
        fs::write(&path, fixture).expect("write ingress fixture");
        let records = load_ingress_records();
        assert!(records.is_empty(), "malformed ingress rows should remain quarantined");
    }

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1024,
        "total quarantine retention should stay bounded across repeated malformed scans"
    );
    assert_eq!(entries.first().expect("first entry")["line_number"], 1);
    assert_eq!(entries.last().expect("last entry")["line_number"], 128);
    assert!(
        entries.first().expect("first entry")["raw_line"]
            .as_str()
            .expect("raw_line string")
            .contains("128"),
        "oldest retained entry should come from the retained tail after earlier batches roll off"
    );
    assert!(
        entries.last().expect("last entry")["raw_line"]
            .as_str()
            .expect("raw_line string")
            .contains("1151"),
        "newest retained entry should come from the most recent malformed batch"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn append_quarantine_records_keeps_same_hash_error_with_distinct_raw_lines() {
    let path = unique_tmp_path("ingress-quarantine-dedupe-raw-line", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);

    let shared_hash = 42;
    let shared_error = "ingress line is not valid utf-8".to_string();
    append_quarantine_records(
        &path,
        &[
            IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: 1,
                line_hash: shared_hash,
                raw_line: "{\"broken\":\"prefix-a\"}".to_string(),
                error: shared_error.clone(),
                quarantined_at_unix_ms: 1,
            },
            IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: 2,
                line_hash: shared_hash,
                raw_line: "{\"broken\":\"prefix-b\"}".to_string(),
                error: shared_error,
                quarantined_at_unix_ms: 2,
            },
        ],
    )
    .expect("append quarantine records");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        2,
        "distinct bounded raw_line echoes should survive quarantine dedupe even when hash and error match"
    );
    assert_ne!(entries[0]["raw_line"], entries[1]["raw_line"]);

    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}
