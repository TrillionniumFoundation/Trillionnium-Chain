use super::*;

#[test]
fn test_market_match_non_existent_task() {
    let env = test_env("no_task");
    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "99999"]);
    assert!(stderr.contains("\"code\": \"task-not-found\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_match_no_bids() {
    let env = test_env("no_bids");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "no bids task",
        ],
    );

    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(stderr.contains("\"code\": \"no-bids\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_match_task_not_open_prefers_code_field() {
    let env = test_env("task_not_open");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "task not open",
        ],
    );
    run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker1",
            "--price",
            "90",
        ],
    );
    run_rpc(&env, &["market-match-task", "--task-id", "20001"]);

    let stderr = run_rpc_fail(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(stderr.contains("\"code\": \"task-not-open\""));

    let _ = fs::remove_dir_all(&env.root);
}

#[test]
fn test_market_submit_bid_task_not_open_prefers_code_field() {
    let env = test_env("submit_bid_task_not_open");
    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "submit bid task not open",
        ],
    );
    run_rpc(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker1",
            "--price",
            "90",
        ],
    );
    run_rpc(&env, &["market-match-task", "--task-id", "20001"]);

    let stderr = run_rpc_fail(
        &env,
        &[
            "market-submit-bid",
            "--task-id",
            "20001",
            "--worker",
            "worker2",
            "--price",
            "80",
        ],
    );
    assert!(stderr.contains("\"code\": \"task-not-open\""));

    let _ = fs::remove_dir_all(&env.root);
}
