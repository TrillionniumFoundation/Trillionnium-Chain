use super::*;

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
