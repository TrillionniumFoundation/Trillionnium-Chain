use super::*;

fn faucet_env_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn clear_faucet_env() {
    std::env::remove_var("TRNM_RPC_FAUCET_WINDOW_SECONDS");
    std::env::remove_var("TRNM_RPC_FAUCET_MAX_REQUESTS");
}

#[test]
fn faucet_env_parsing_enforces_minimums() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "0");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "0");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, FAUCET_WINDOW_SECONDS_MIN);
    assert_eq!(max_requests, FAUCET_MAX_REQUESTS_MIN);

    clear_faucet_env();
}

#[test]
fn faucet_env_parsing_uses_defaults_for_invalid_values() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "bad");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "bad");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, FAUCET_WINDOW_SECONDS_DEFAULT);
    assert_eq!(max_requests, FAUCET_MAX_REQUESTS_DEFAULT);

    clear_faucet_env();
}

#[test]
fn faucet_env_parsing_accepts_surrounding_whitespace() {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    clear_faucet_env();

    std::env::set_var("TRNM_RPC_FAUCET_WINDOW_SECONDS", "  120  ");
    std::env::set_var("TRNM_RPC_FAUCET_MAX_REQUESTS", "\t9\n");

    let window = env_u64_with_min(
        "TRNM_RPC_FAUCET_WINDOW_SECONDS",
        FAUCET_WINDOW_SECONDS_DEFAULT,
        FAUCET_WINDOW_SECONDS_MIN,
    );
    let max_requests = env_u32_with_min(
        "TRNM_RPC_FAUCET_MAX_REQUESTS",
        FAUCET_MAX_REQUESTS_DEFAULT,
        FAUCET_MAX_REQUESTS_MIN,
    );

    assert_eq!(window, 120);
    assert_eq!(max_requests, 9);

    clear_faucet_env();
}

#[test]
fn read_log_tail_returns_recent_lines() {
    let tmp = unique_tmp_path("trnm-rpc-tail-test", "log");
    fs::write(
        &tmp,
        "line1
line2
[event] event_type=commit task_id=1 tx_id=1 block_height=1
",
    )
    .expect("write temp log");
    let tail = read_log_tail(&tmp, 80).expect("tail text");
    assert!(tail.contains("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_keeps_first_line_when_tail_starts_on_newline_boundary() {
    let tmp = unique_tmp_path("trnm-rpc-tail-boundary", "log");
    let content = "line1\n[event] event_type=commit task_id=7 tx_id=11 block_height=3\n";
    fs::write(&tmp, content).expect("write temp log");

    let start = "line1\n".len() as u64;
    let tail_bytes = content.len() as u64 - start;
    let tail = read_log_tail(&tmp, tail_bytes).expect("tail text");

    assert!(tail.starts_with("[event] event_type=commit"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn read_log_tail_tolerates_non_utf8_bytes() {
    let tmp = unique_tmp_path("trnm-rpc-tail-binary", "log");
    let mut bytes = vec![0xff, 0xfe, b'\n'];
    bytes.extend_from_slice(b"[event] event_type=commit task_id=9 tx_id=1 block_height=1\n");
    fs::write(&tmp, bytes).expect("write temp binary log");

    let tail = read_log_tail(&tmp, 1024).expect("tail text");
    assert!(tail.contains("[event] event_type=commit task_id=9"));
    let _ = fs::remove_file(tmp);
}

#[test]
fn discover_default_node_event_log_sources_includes_dynamic_node4_and_nightly_logs() {
    let root = unique_tmp_path("trnm-rpc-log-root", "dir");
    let run_dir = root.join("run");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::write(run_dir.join("node1.log"), "").expect("write node1");
    fs::write(run_dir.join("node4.log"), "").expect("write node4");
    fs::write(run_dir.join("nightly-bft.log"), "").expect("write nightly");
    fs::write(run_dir.join("notes.txt"), "").expect("write txt");

    let got = discover_default_node_event_log_sources(&root);

    assert!(got.contains(&run_dir.join("node1.log")));
    assert!(got.contains(&run_dir.join("node4.log")));
    assert!(got.contains(&run_dir.join("nightly-bft.log")));
    assert!(!got.contains(&run_dir.join("notes.txt")));

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_node_event_log_sources_prefers_manifest_and_env_over_fixed_defaults() {
    let _guard = lock_env();
    let root = unique_tmp_path("trnm-rpc-log-sources", "dir");
    let run_dir = root.join("run");
    let manifest_dir = root.join("cfg");
    fs::create_dir_all(&run_dir).expect("create run dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");

    let env_log = root.join("env-node4.log");
    let manifest_log = manifest_dir.join("nightly.log");
    let manifest = manifest_dir.join("sources.txt");
    fs::write(&env_log, "").expect("write env log");
    fs::write(&manifest_log, "").expect("write manifest log");
    fs::write(&manifest, "# comment\nnightly.log\n").expect("write manifest");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            env_log.to_string_lossy().to_string(),
        );
        std::env::set_var(
            NODE_EVENT_LOG_MANIFEST_ENV,
            manifest.to_string_lossy().to_string(),
        );
    }

    let got = load_node_event_log_sources(&root);

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert!(got.contains(&env_log));
    assert!(got.contains(&manifest_log));
    assert_eq!(got.len(), 2, "custom sources should replace defaults");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn load_latest_node_events_reads_events_from_configured_node4_source() {
    let _guard = lock_env();
    let path = unique_tmp_path("trnm-rpc-node4", "log");
    fs::write(
            &path,
            "[event] event_type=commit task_id=44 tx_id=7 block_height=9 actor=node4 from_status=ASSIGNED to_status=COMPLETED state_root=abc signer=node4\n",
        )
        .expect("write node4 log");

    let prev_sources = std::env::var(NODE_EVENT_LOG_SOURCES_ENV).ok();
    let prev_manifest = std::env::var(NODE_EVENT_LOG_MANIFEST_ENV).ok();
    unsafe {
        std::env::set_var(
            NODE_EVENT_LOG_SOURCES_ENV,
            path.to_string_lossy().to_string(),
        );
        std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV);
    }

    let got = load_latest_node_events();

    match prev_sources {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_SOURCES_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_SOURCES_ENV) },
    }
    match prev_manifest {
        Some(v) => unsafe { std::env::set_var(NODE_EVENT_LOG_MANIFEST_ENV, v) },
        None => unsafe { std::env::remove_var(NODE_EVENT_LOG_MANIFEST_ENV) },
    }

    assert!(got.iter().any(|evt| {
        evt.task_id == 44
            && evt.tx_id == 7
            && evt.block_height == 9
            && evt.actor == "node4"
            && evt.signer.as_deref() == Some("node4")
    }));

    let _ = fs::remove_file(path);
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

    std::env::remove_var("TRNM_RPC_INGRESS_FILE");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_file(&quarantine);
}

#[test]
fn atomic_write_text_file_replaces_without_leaving_temp_files() {
    let path = unique_tmp_path("rpc-atomic-write", "json");
    let parent = path.parent().expect("temp parent").to_path_buf();
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap()
        .to_string();
    let _ = fs::remove_file(&path);

    atomic_write_text_file(&path, "{\"ok\":true}\n").expect("atomic write succeeds");
    let raw = fs::read_to_string(&path).expect("read atomic target");
    assert_eq!(raw, "{\"ok\":true}\n");

    let leftovers: Vec<_> = fs::read_dir(&parent)
        .expect("read temp dir")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().to_string())
        .filter(|name| name.starts_with(&format!(".{}.tmp-", file_name)))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporary atomic-write files should be cleaned"
    );

    let _ = fs::remove_file(&path);
}

#[test]
fn load_latest_adapter_records_skips_invalid_jsonl_rows() {
    let dir = run_root().join("run/worker-agent");
    fs::create_dir_all(&dir).expect("create worker-agent dir");

    let mut backup: Vec<(PathBuf, Vec<u8>)> = vec![];
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_adapter = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                .unwrap_or(false);
            if !is_adapter {
                continue;
            }
            if let Ok(bytes) = fs::read(&path) {
                backup.push((path.clone(), bytes));
            }
            let _ = fs::remove_file(&path);
        }
    }

    let fixture = dir.join(format!("tx-adapter-99991231-{}.jsonl", std::process::id()));
    fs::write(
            &fixture,
            "not-json\n{\"ts\":1772074584,\"mode\":\"mock\",\"kind\":\"commit\",\"task_id\":101001,\"worker\":\"worker1\",\"commit_hash\":\"764c7baf3e1d3d325511cdc3d7836fbc1fa71a289bd669edcc4b55d6baaee9d7\",\"nonce\":101001,\"tx_hash\":\"7336b90d593ebe324cb4b3e41e7e9d86d1e2418f230cca0162ca1d539f32c2b9\",\"status\":\"accepted\",\"rc\":0}\n",
        )
        .expect("write adapter fixture");

    let records = load_latest_adapter_records();
    assert_eq!(records.len(), 1, "only valid JSONL rows should be loaded");
    assert_eq!(records[0].task_id, 101001);

    let _ = fs::remove_file(&fixture);
    for (path, bytes) in backup {
        let _ = fs::write(path, bytes);
    }
}
