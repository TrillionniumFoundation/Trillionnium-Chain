use super::*;
use std::os::unix::fs::MetadataExt;

fn expected_stable_line_hash(raw: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x00000100000001B3;

    let mut hash = FNV_OFFSET_BASIS;
    for byte in raw.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

#[test]
fn append_quarantine_records_reports_only_new_entries() {
    let path = unique_tmp_path("ingress-quarantine-count", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);

    let entry = IngressQuarantineRecord {
        source_path: path.display().to_string(),
        line_number: 2,
        line_hash: 7,
        raw_line: "not-json".to_string(),
        error: "expected value".to_string(),
        quarantined_at_unix_ms: 1,
    };

    let appended = append_quarantine_records(&path, &[entry.clone()]).expect("append first");
    assert_eq!(appended, 1, "first malformed ingress row should be counted once");

    let duplicated = append_quarantine_records(&path, &[entry]).expect("append duplicate");
    assert_eq!(
        duplicated, 0,
        "reloading the same malformed ingress row must not inflate quarantine accounting"
    );

    let raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    assert_eq!(raw.lines().filter(|line| !line.trim().is_empty()).count(), 1);

    let _ = fs::remove_file(&quarantine);
}


#[test]
fn append_quarantine_records_deduplicates_same_batch_entries() {
    let path = unique_tmp_path("ingress-quarantine-batch", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);

    let appended = append_quarantine_records(
        &path,
        &[
            IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: 2,
                line_hash: 7,
                raw_line: "not-json".to_string(),
                error: "expected value".to_string(),
                quarantined_at_unix_ms: 1,
            },
            IngressQuarantineRecord {
                source_path: path.display().to_string(),
                line_number: 2,
                line_hash: 7,
                raw_line: "not-json".to_string(),
                error: "expected value".to_string(),
                quarantined_at_unix_ms: 1,
            },
        ],
    )
    .expect("append duplicated batch");
    assert_eq!(
        appended, 1,
        "duplicate malformed rows in the same batch must not inflate quarantine accounting"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "batch dedup should persist exactly one entry");

    let _ = fs::remove_file(&quarantine);
}

#[test]
fn append_quarantine_records_deduplicates_legacy_rows_missing_line_hash() {
    let path = unique_tmp_path("ingress-quarantine-legacy", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);

    fs::write(
        &quarantine,
        format!(
            concat!(
                "{{",
                "\"source_path\":\"{}\",",
                "\"line_number\":2,",
                "\"raw_line\":\"not-json\",",
                "\"error\":\"expected value\",",
                "\"quarantined_at_unix_ms\":1",
                "}}\n"
            ),
            path.display()
        ),
    )
    .expect("seed legacy quarantine row");

    let appended = append_quarantine_records(
        &path,
        &[IngressQuarantineRecord {
            source_path: path.display().to_string(),
            line_number: 2,
            line_hash: stable_line_hash("not-json"),
            raw_line: "not-json".to_string(),
            error: "expected value".to_string(),
            quarantined_at_unix_ms: 2,
        }],
    )
    .expect("append duplicate legacy row");
    assert_eq!(
        appended, 0,
        "legacy quarantine rows without line_hash must still suppress duplicate accounting"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "legacy dedup should not append a second row");

    let _ = fs::remove_file(&quarantine);
}

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

    let padded_error = IngressQuarantineRecord {
        error: " parse failed ".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&padded_error),
        "padded quarantine fields should be rejected so retention stays canonical and dedupe-friendly"
    );

    let zero_line_hash = IngressQuarantineRecord {
        line_hash: 0,
        ..valid.clone()
    };
    assert!(
        quarantine_record_within_bounds(&zero_line_hash),
        "zero hash values are allowed when all other bounds hold, preserving quarantine retention"
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

    let word_joiner_error = IngressQuarantineRecord {
        error: "parse failed\u{2060}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&word_joiner_error),
        "word joiner characters should be rejected to keep quarantine logs unambiguous"
    );

    let invisible_separator_error = IngressQuarantineRecord {
        error: "parse failed\u{2063}json".to_string(),
        ..valid.clone()
    };
    assert!(
        !quarantine_record_within_bounds(&invisible_separator_error),
        "invisible separator characters should be rejected to keep quarantine logs unambiguous"
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
fn load_ingress_records_trims_quarantine_source_path_metadata_for_retention_bounds() {
    let _guard = lock_env();
    let dir = unique_tmp_path(" ingress-quarantine-path-padding ", "dir");
    fs::create_dir_all(&dir).expect("create padded ingress fixture dir");
    let path = dir.join("requests.jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, b"{\"broken\":1\n").expect("write malformed ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should remain quarantined");
    assert!(quarantine.exists(), "trimmed source_path metadata should still retain the quarantine entry");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "one malformed ingress row should be retained after source path trimming");

    let source_path = entries[0]["source_path"]
        .as_str()
        .expect("quarantine source_path should be a string");
    assert_eq!(source_path, source_path.trim(), "quarantine source_path metadata should be canonicalized before bounded retention");
    assert!(
        source_path.ends_with("requests.jsonl"),
        "quarantine source_path should still identify the ingress file after trimming"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    let _ = fs::remove_dir_all(&dir);
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
            r#"  {"request_id":"req-1","task_id":10001,"channel":"telegram","user_id":"u1","session_id":"s1","text":"ok","idempotency_key":"k1","status":"open","created_at_unix_ms":1,"assigned_worker":null,"assigned_at_unix_ms":null,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}  
not-json
"#,
        )
        .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(
        records.len(),
        1,
        "whitespace-wrapped valid ingress rows should survive salvage"
    );
    assert_eq!(records[0].request_id, "req-1");

    let first_quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let first_entries: Vec<serde_json::Value> = first_quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        first_entries.len(),
        1,
        "malformed ingress row should be quarantined"
    );
    assert_eq!(first_entries[0]["line_number"], 2);
    assert_eq!(first_entries[0]["raw_line"], "not-json");
    assert_eq!(first_entries[0]["source_path"], path.display().to_string());

    let second_records = load_ingress_records();
    assert_eq!(second_records.len(), 1, "salvage should stay stable on reload");

    let second_quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let second_entries: Vec<serde_json::Value> = second_quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        second_entries.len(),
        1,
        "reloading the same malformed ingress line must not duplicate quarantine accounting"
    );

    fs::write(&path, fixture).expect("rewrite ingress fixture with same malformed row");
    let records_second = load_ingress_records();
    assert_eq!(records_second.len(), 1, "salvage should remain stable on replay");

    let quarantine_raw_second = fs::read_to_string(&quarantine).expect("read quarantine file again");
    let entries_second: Vec<serde_json::Value> = quarantine_raw_second
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries_second.len(),
        1,
        "reintroduced malformed row should not amplify quarantine noise"
    );

    fs::write(
        &path,
        r#"not-json
{"request_id":"req-2","task_id":10002,"channel":"telegram","user_id":"u2","session_id":"s2","text":"ok-2","idempotency_key":"k2","status":"open","created_at_unix_ms":2,"assigned_worker":null,"assigned_at_unix_ms":null,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}
not-json
"#,
    )
    .expect("rewrite ingress fixture with shifted malformed row");
    let records_third = load_ingress_records();
    assert_eq!(
        records_third.len(),
        1,
        "salvage should keep valid rows even when malformed replay shifts lines"
    );

    let quarantine_raw_third = fs::read_to_string(&quarantine).expect("read quarantine file third time");
    let entries_third: Vec<serde_json::Value> = quarantine_raw_third
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries_third.len(),
        1,
        "identical malformed row should stay deduped even if its line number shifts after rewrite"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_truncates_oversized_quarantine_raw_lines() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-raw-line-bound", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let oversized = "é".repeat(400);
    fs::write(&path, format!("{oversized}\n")).expect("write oversized malformed ingress line");

    let records = load_ingress_records();
    assert!(records.is_empty(), "oversized malformed row should be quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "single malformed row should produce one quarantine entry");

    let stored_raw = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw line string");
    assert!(
        stored_raw.len() <= 512,
        "quarantine raw line should be truncated to the configured byte ceiling"
    );
    assert!(
        oversized.starts_with(stored_raw),
        "quarantine raw line should preserve the original prefix after truncation"
    );
    assert!(
        std::str::from_utf8(stored_raw.as_bytes()).is_ok(),
        "quarantine truncation must preserve utf-8 boundaries"
    );
    assert_eq!(entries[0]["line_hash"].as_u64(), Some(expected_stable_line_hash(&oversized)));

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_dedupes_duplicate_noise_before_quarantine_cap() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-dedup-noise-bound", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let unique_prefix = (0..255)
        .map(|idx| format!("uniq-bad-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    let duplicate_storm = std::iter::repeat_n("storm-dup".to_string(), 100).collect::<Vec<_>>().join("\n");
    let fixture = format!("{unique_prefix}\n{duplicate_storm}\nuniq-tail\n");
    fs::write(&path, fixture).expect("write duplicate-noise ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "all malformed rows should be quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read deduped quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 256, "duplicate malformed noise should not crowd out distinct quarantine evidence");
    assert_eq!(entries.first().and_then(|v| v["raw_line"].as_str()), Some("uniq-bad-0"));
    assert_eq!(entries.get(254).and_then(|v| v["raw_line"].as_str()), Some("uniq-bad-254"));
    assert_eq!(entries.last().and_then(|v| v["raw_line"].as_str()), Some("uniq-tail"));
    assert_eq!(
        entries.iter().filter(|v| v["raw_line"].as_str() == Some("storm-dup")).count(),
        1,
        "duplicate malformed rows should collapse to one quarantine record per salvage cycle"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_prefers_latest_duplicate_after_bounded_eviction() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-latest-duplicate-after-eviction", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut rows = (0..256)
        .map(|idx| format!("noise-{idx}"))
        .collect::<Vec<_>>();
    rows.push("noise-0".to_string());
    let fixture = rows.join("\n");
    fs::write(&path, format!("{fixture}\n")).expect("write eviction fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "all malformed rows should be quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read bounded quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 256, "quarantine journal should stay capped");
    assert_eq!(entries.first().and_then(|v| v["raw_line"].as_str()), Some("noise-1"));
    assert_eq!(entries.last().and_then(|v| v["raw_line"].as_str()), Some("noise-0"));
    assert_eq!(entries.last().and_then(|v| v["line_number"].as_u64()), Some(257));

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_bounds_quarantine_journal_growth() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-bounded", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let fixture = (0..300)
        .map(|idx| format!("not-json-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, format!("{fixture}\n")).expect("write oversized ingress quarantine fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "all malformed rows should be quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read bounded quarantine file");
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
fn load_ingress_records_quarantines_trimmed_malformed_raw_line_suffix() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-trailing-space", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let malformed = format!("{{"broken":"{} ", "x".repeat(4095));
    fs::write(&path, format!("{}
", malformed)).expect("write ingress fixture");

    let records = load_ingress_records();
    assert!(records.is_empty(), "malformed ingress rows should stay quarantined");

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(entries.len(), 1, "trailing-space malformed row should still be quarantined");
    let raw_line = entries[0]["raw_line"]
        .as_str()
        .expect("quarantine raw_line should be a string");
    assert_eq!(raw_line.len(), 4095, "quarantine raw_line should trim the trailing space instead of dropping the record");
    assert!(raw_line.starts_with("{"broken":""));
    assert!(!raw_line.ends_with(' '), "quarantine raw_line should be canonicalized for retention");

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
fn load_ingress_records_quarantines_oversized_crlf_ascii_whitespace_only_noise() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-oversized-crlf-ascii-whitespace-noise-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let ascii_whitespace_noise = format!("{}\r\n", " ".repeat(65_535));
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
    assert_eq!(records.len(), 1, "valid ingress rows should survive oversized crlf ascii-whitespace quarantine");
    assert!(
        quarantine.exists(),
        "oversized crlf ascii whitespace-only ingress noise should be quarantined"
    );

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let quarantine_lines: Vec<&str> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        quarantine_lines.len(),
        1,
        "one oversized crlf ascii-whitespace line should be quarantined"
    );
    assert!(
        quarantine_lines[0].contains("whitespace-only line omitted"),
        "quarantine entry should replace oversized crlf blank payloads with an explicit marker"
    );
    assert!(
        quarantine_lines[0].contains("exceeds 65536 bytes parse bound (got 65537)"),
        "quarantine entry should preserve on-disk crlf parse-bound accounting"
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
        "only malformed ingress rows should be quarantined"
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
fn load_ingress_records_does_not_duplicate_existing_quarantine_accounting() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-dedupe", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, "not-json\n").expect("write malformed ingress fixture");

    let first = load_ingress_records();
    let second = load_ingress_records();
    assert!(first.is_empty());
    assert!(second.is_empty());

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "reloading identical malformed ingress rows should not duplicate quarantine accounting"
    );
    assert_eq!(entries[0]["line_number"], 1);
    assert_eq!(entries[0]["raw_line"], "not-json");

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_dedupes_quarantine_accounting_for_whitespace_only_malformed_replays() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-whitespace-dedupe", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
    let first = load_ingress_records();
    assert!(first.is_empty());

    fs::write(&path, "  not-json  \n").expect("rewrite malformed ingress fixture with padding");
    let second = load_ingress_records();
    assert!(second.is_empty());

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "whitespace-only malformed replays should not duplicate quarantine accounting"
    );
    assert_eq!(entries[0]["line_number"], 1);
    assert_eq!(entries[0]["raw_line"], "not-json");

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_dedupes_quarantine_accounting_when_existing_hash_is_stale() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-stale-hash", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
    fs::write(
        &quarantine,
        format!(
            concat!(
                r#"{{"source_path":"{}","line_number":1,"line_hash":0,"raw_line":"not-json","error":"legacy","quarantined_at_unix_ms":1}}"#,
                "\n"
            ),
            path.display()
        ),
    )
    .expect("seed stale quarantine fixture");

    let records = load_ingress_records();
    assert!(records.is_empty());

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "replays should not duplicate quarantine accounting when legacy hashes drift"
    );
    assert_eq!(entries[0]["line_hash"], 0);
    assert_eq!(entries[0]["raw_line"], "not-json");

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn load_ingress_records_dedupes_quarantine_accounting_when_legacy_hash_is_stringified() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-string-hash", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(&path, "not-json\n").expect("write malformed ingress fixture");
    fs::write(
        &quarantine,
        format!(
            concat!(
                r#"{{"source_path":"{}","line_number":" 1 ","line_hash":"{}","error":"legacy","quarantined_at_unix_ms":1}}"#,
                "\n"
            ),
            path.display(),
            super::ingress::stable_line_hash("not-json")
        ),
    )
    .expect("seed stringified legacy quarantine fixture");

    let records = load_ingress_records();
    assert!(records.is_empty());

    let quarantine_raw = fs::read_to_string(&quarantine).expect("read quarantine file");
    let entries: Vec<serde_json::Value> = quarantine_raw
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries.len(),
        1,
        "stringified legacy quarantine hashes should still dedupe malformed ingress replays"
    );
    assert_eq!(entries[0]["line_hash"], super::ingress::stable_line_hash("not-json"));

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}
