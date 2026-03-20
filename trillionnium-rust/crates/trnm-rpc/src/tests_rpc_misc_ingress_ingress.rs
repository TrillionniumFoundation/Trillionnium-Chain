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
fn load_ingress_records_bounds_quarantine_append_noise_per_scan() {
    let _guard = lock_env();
    let path = unique_tmp_path("ingress-quarantine-bounded", "jsonl");
    let quarantine = ingress_quarantine_file_for(&path);
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
    std::env::set_var("TRNM_RPC_INGRESS_FILE", path.to_string_lossy().to_string());

    let mut fixture = String::new();
    fixture.push_str("{\"request_id\":\"req-1\",\"task_id\":10001,\"channel\":\"telegram\",\"user_id\":\"u1\",\"session_id\":\"s1\",\"text\":\"ok\",\"idempotency_key\":\"k1\",\"status\":\"open\",\"created_at_unix_ms\":1,\"assigned_worker\":null,\"assigned_at_unix_ms\":null,\"model_output\":null,\"result_hash\":null,\"verifier_status\":null,\"resolution_code\":null,\"commit_tx_hash\":null,\"reveal_tx_hash\":null}\n");
    for idx in 0..130 {
        fixture.push_str(&format!("{{\"broken\":{idx}\n"));
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
        128,
        "quarantine append should be bounded per load to limit repeated malformed-ingress noise"
    );
    assert_eq!(entries.first().expect("first entry")["line_number"], 4);
    assert_eq!(entries.last().expect("last entry")["line_number"], 131);
    assert!(
        entries.iter().all(|entry| {
            entry["error"]
                .as_str()
                .expect("error string")
                .contains("EOF while parsing")
        }),
        "all malformed rows should stay fail-closed in quarantine"
    );

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}
