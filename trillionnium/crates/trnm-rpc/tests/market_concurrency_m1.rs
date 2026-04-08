use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

fn unique_market_fixture_path(name: &str, ext: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!("trnm_rpc_{}_{}.{}", name, ts, ext))
}

#[test]
fn market_create_task_concurrent_writes_do_not_drop_records() {
    let tasks = unique_market_fixture_path("market_tasks_concurrency", "jsonl");
    let bids = unique_market_fixture_path("market_bids_concurrency", "jsonl");
    let _ = fs::remove_file(&tasks);
    let _ = fs::remove_file(&bids);

    let workers = 8usize;
    let mut joins = Vec::with_capacity(workers);
    for i in 0..workers {
        let tasks_env = tasks.clone();
        let bids_env = bids.clone();
        joins.push(thread::spawn(move || {
            Command::new("cargo")
                .args(["run", "-p", "trnm-rpc", "--"])
                .args([
                    "market.create_task",
                    "--creator",
                    &format!("creator-{i}"),
                    "--bounty",
                    "100",
                    "--description",
                    "concurrency-regression",
                ])
                .env("TRNM_RPC_MARKET_TASKS_FILE", tasks_env)
                .env("TRNM_RPC_MARKET_BIDS_FILE", bids_env)
                .output()
                .expect("failed to execute trnm-rpc")
        }));
    }

    for out in joins {
        let output = out.join().expect("join thread");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let raw = fs::read_to_string(&tasks).expect("read tasks file");
    let records: Vec<&str> = raw.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(
        records.len(),
        workers,
        "expected one record per concurrent create_task invocation"
    );

    let mut ids = HashSet::new();
    for line in records {
        let v: Value = serde_json::from_str(line).expect("valid task json line");
        let id = v["task_id"].as_u64().expect("task_id");
        ids.insert(id);
    }
    assert_eq!(
        ids.len(),
        workers,
        "task_id must stay unique under contention"
    );

    let tasks_lock = tasks.with_file_name(format!(
        "{}.lock",
        tasks
            .file_name()
            .and_then(|v| v.to_str())
            .expect("tasks file name")
    ));
    assert!(
        !tasks_lock.exists(),
        "lock file should be cleaned after concurrent writers exit"
    );
}
