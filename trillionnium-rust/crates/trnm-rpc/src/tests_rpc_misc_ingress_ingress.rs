use super::*;

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
fn load_ingress_records_drops_preexisting_quarantine_entries_with_empty_error() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-empty-error-retention", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let empty_error_retained_entry = serde_json::json!({
        "source_path": path.display().to_string(),
        "line_number": 99,
        "line_hash": 123_u64,
        "raw_line": "seed",
        "error": "",
        "quarantined_at_unix_ms": 1_u128,
    });
    fs::write(
        &quarantine,
        format!("{}\n", serde_json::to_string(&empty_error_retained_entry).expect("serialize seed entry")),
    )
    .expect("seed empty-error quarantine entry");
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
        "preexisting quarantine entries with empty error should be discarded"
    );
    let entry: serde_json::Value = serde_json::from_str(lines[0]).expect("valid quarantine jsonl");
    assert_eq!(entry["line_number"], 1);
    assert!(
        !entry["error"].as_str().expect("error string").is_empty(),
        "new quarantined ingress row should replace retained entries missing parse context"
    );
    assert!(
        entry["error"]
            .as_str()
            .expect("error string")
            .contains("EOF while parsing"),
        "new malformed ingress record should still be quarantined after dropping empty-error retained noise"
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
