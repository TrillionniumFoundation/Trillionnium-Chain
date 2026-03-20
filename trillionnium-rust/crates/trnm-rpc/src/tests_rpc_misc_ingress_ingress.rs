use super::*;

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
fn load_ingress_records_quarantines_malformed_lines_with_accounting() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    fs::write(
            &path,
            r#"{"request_id":"req-1","task_id":10001,"channel":"telegram","user_id":"u1","session_id":"s1","text":"ok","idempotency_key":"k1","status":"open","created_at_unix_ms":1,"assigned_worker":null,"assigned_at_unix_ms":null,"model_output":null,"result_hash":null,"verifier_status":null,"resolution_code":null,"commit_tx_hash":null,"reveal_tx_hash":null}
not-json
"#,
        )
        .expect("write ingress fixture");

    let records = load_ingress_records();
    assert_eq!(
        records.len(),
        1,
        "valid ingress rows should survive salvage"
    );

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

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}
