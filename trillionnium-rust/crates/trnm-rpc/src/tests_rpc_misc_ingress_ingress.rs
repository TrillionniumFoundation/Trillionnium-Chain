use super::*;

#[test]
fn load_ingress_records_quarantines_malformed_lines_with_accounting() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

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
    assert_eq!(entries[0]["raw_line"], "not-json");
    assert_eq!(entries[0]["source_path"], path.display().to_string());

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
