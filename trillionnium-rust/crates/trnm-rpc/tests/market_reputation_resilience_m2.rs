use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn unique_market_path(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "trnm_rpc_{}_{}_{}.{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix epoch")
            .as_millis(),
        ext
    ));
    path
}

fn run_ok_with_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new("cargo");
    command.args(["run", "-p", "trnm-rpc", "--"]).args(args);
    for (k, v) in envs {
        command.env(k, v);
    }
    let output = command.output().expect("failed to execute trnm-rpc");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn market_match_falls_back_to_zero_reputation_when_reputation_file_is_malformed_json() {
    let tasks = unique_market_path("market_tasks", "jsonl");
    let bids = unique_market_path("market_bids", "jsonl");
    let reputation = unique_market_path("market_reputation", "json");
    fs::write(&reputation, "{not valid json").expect("write malformed reputation fixture");

    let tasks_env = tasks.to_string_lossy().into_owned();
    let bids_env = bids.to_string_lossy().into_owned();
    let reputation_env = reputation.to_string_lossy().into_owned();
    let envs = [
        ("TRNM_RPC_MARKET_TASKS_FILE", tasks_env.as_str()),
        ("TRNM_RPC_MARKET_BIDS_FILE", bids_env.as_str()),
        ("TRNM_RPC_MARKET_REPUTATION_FILE", reputation_env.as_str()),
    ];

    let create_out = run_ok_with_env(
        &[
            "market.create_task",
            "--creator",
            "alice",
            "--bounty",
            "101",
            "--description",
            "m2 malformed reputation fallback",
        ],
        &envs,
    );
    let created: Value = serde_json::from_str(&create_out).expect("create task JSON");
    let task_id = created["task_id"].as_u64().expect("task_id").to_string();

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-low",
            "--price",
            "100",
        ],
        &envs,
    );

    run_ok_with_env(
        &[
            "market.submit_bid",
            "--task-id",
            &task_id,
            "--worker",
            "worker-high",
            "--price",
            "101",
        ],
        &envs,
    );

    let match_out = run_ok_with_env(&["market.match_task", "--task-id", &task_id], &envs);
    let matched: Value = serde_json::from_str(match_out.trim()).expect("match JSON");

    assert_eq!(matched["winner"], "worker-low");
    assert_eq!(matched["winner_reputation"], 0);
    assert_eq!(matched["match_policy"], "price_reputation_weighted");

    let _ = fs::remove_file(tasks);
    let _ = fs::remove_file(bids);
    let _ = fs::remove_file(reputation);
}
