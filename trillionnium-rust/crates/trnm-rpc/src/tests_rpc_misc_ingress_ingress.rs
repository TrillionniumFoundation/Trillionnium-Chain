use super::*;

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
fn load_ingress_records_quarantines_malformed_lines_with_accounting() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let fixture = r#"{"request_id":"req-1","task_id":10001,"channel":"telegram","user_id":"u1","session_id":"s1","text":"ok","idempotency_key":"k1","status":"open","created_at_unix_ms":1,"assigned_worker":null,"assigned_at_unix_ms":null,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}
not-json
"#;

    fs::write(&path, fixture).expect("write ingress fixture");

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
        "malformed ingress row should be quarantined"
    );
    assert_eq!(entries[0]["line_number"], 2);
    assert_eq!(entries[0]["raw_line"], "not-json");
    assert_eq!(entries[0]["source_path"], path.display().to_string());

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
        256,
        "quarantine journal should stay capped under malformed ingress bursts"
    );
    assert_eq!(entries.first().and_then(|v| v["raw_line"].as_str()), Some("not-json-44"));
    assert_eq!(entries.last().and_then(|v| v["raw_line"].as_str()), Some("not-json-299"));

    let second_fixture = (300..310)
        .map(|idx| format!("not-json-{idx}"))
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&path, format!("{second_fixture}\n")).expect("write second malformed ingress burst");

    let records_second = load_ingress_records();
    assert!(
        records_second.is_empty(),
        "follow-up malformed burst should also quarantine cleanly"
    );

    let quarantine_raw_second =
        fs::read_to_string(&quarantine).expect("read bounded quarantine file after replay");
    let entries_second: Vec<serde_json::Value> = quarantine_raw_second
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("valid quarantine jsonl"))
        .collect();
    assert_eq!(
        entries_second.len(),
        256,
        "quarantine journal should remain capped across repeated malformed bursts"
    );
    assert_eq!(entries_second.first().and_then(|v| v["raw_line"].as_str()), Some("not-json-54"));
    assert_eq!(entries_second.last().and_then(|v| v["raw_line"].as_str()), Some("not-json-309"));

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}
