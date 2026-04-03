pub(crate) use super::*;

fn with_isolated_adapter_dir(test: impl FnOnce(&PathBuf)) {
    let _guard = faucet_env_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
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

    test(&dir);

    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let is_adapter = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|s| s.starts_with("tx-adapter-") && s.ends_with(".jsonl"))
                .unwrap_or(false);
            if is_adapter {
                let _ = fs::remove_file(&path);
            }
        }
    }
    for (path, bytes) in backup {
        let _ = fs::write(path, bytes);
    }
}

#[test]
fn load_latest_adapter_records_skips_invalid_jsonl_rows() {
    with_isolated_adapter_dir(|dir| {
        let fixture = dir.join(format!("tx-adapter-99991231-{}.jsonl", std::process::id()));
        fs::write(
            &fixture,
            "not-json\n{\"ts\":1772074584,\"mode\":\"mock\",\"kind\":\"commit\",\"task_id\":101001,\"worker\":\"worker1\",\"commit_hash\":\"764c7baf3e1d3d325511cdc3d7836fbc1fa71a289bd669edcc4b55d6baaee9d7\",\"nonce\":101001,\"tx_hash\":\"7336b90d593ebe324cb4b3e41e7e9d86d1e2418f230cca0162ca1d539f32c2b9\",\"status\":\"accepted\",\"rc\":0}\n",
        )
        .expect("write adapter fixture");

        let records = load_latest_adapter_records();
        assert_eq!(records.len(), 1, "only valid JSONL rows should be loaded");
        assert_eq!(records[0].task_id, 101001);
    });
}

#[test]
fn load_latest_adapter_records_falls_back_to_previous_nonempty_snapshot_when_latest_is_corrupt() {
    with_isolated_adapter_dir(|dir| {
        let previous = dir.join(format!("tx-adapter-20260403-{}-a.jsonl", std::process::id()));
        let latest = dir.join(format!("tx-adapter-20260404-{}-z.jsonl", std::process::id()));
        fs::write(
            &previous,
            "{\"ts\":1772074584,\"mode\":\"mock\",\"kind\":\"commit\",\"task_id\":4242,\"worker\":\"worker1\",\"commit_hash\":\"764c7baf3e1d3d325511cdc3d7836fbc1fa71a289bd669edcc4b55d6baaee9d7\",\"nonce\":101001,\"tx_hash\":\"7336b90d593ebe324cb4b3e41e7e9d86d1e2418f230cca0162ca1d539f32c2b9\",\"status\":\"accepted\",\"rc\":0}\n",
        )
        .expect("write previous adapter snapshot");
        fs::write(&latest, "not-json\n").expect("write corrupt latest adapter snapshot");

        let records = load_latest_adapter_records();
        assert_eq!(records.len(), 1, "corrupt newest snapshot should not erase the last durable read-model snapshot");
        assert_eq!(records[0].task_id, 4242);
    });
}

#[test]
fn load_latest_adapter_records_falls_back_to_previous_nonempty_snapshot_when_latest_is_empty() {
    with_isolated_adapter_dir(|dir| {
        let previous = dir.join(format!("tx-adapter-20260403-{}-a.jsonl", std::process::id()));
        let latest = dir.join(format!("tx-adapter-20260404-{}-z.jsonl", std::process::id()));
        fs::write(
            &previous,
            "{\"ts\":1772074584,\"mode\":\"mock\",\"kind\":\"commit\",\"task_id\":5252,\"worker\":\"worker1\",\"commit_hash\":\"764c7baf3e1d3d325511cdc3d7836fbc1fa71a289bd669edcc4b55d6baaee9d7\",\"nonce\":101001,\"tx_hash\":\"7336b90d593ebe324cb4b3e41e7e9d86d1e2418f230cca0162ca1d539f32c2b9\",\"status\":\"accepted\",\"rc\":0}\n",
        )
        .expect("write previous adapter snapshot");
        fs::write(&latest, "\n  \n").expect("write empty latest adapter snapshot");

        let records = load_latest_adapter_records();
        assert_eq!(
            records.len(),
            1,
            "empty newest snapshot should not erase the last durable read-model snapshot"
        );
        assert_eq!(records[0].task_id, 5252);
    });
}
