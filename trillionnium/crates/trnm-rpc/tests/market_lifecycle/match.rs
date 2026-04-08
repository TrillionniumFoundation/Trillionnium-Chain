use super::*;

#[test]
fn test_market_match_task_success() {
    let env = test_env("match_success");

    run_rpc(
        &env,
        &[
            "market-create-task",
            "--creator",
            "alice",
            "--bounty",
            "100",
            "--description",
            "test task",
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
    run_rpc(
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

    let out = run_rpc(&env, &["market-match-task", "--task-id", "20001"]);
    assert!(out.contains("\"winner\":\"worker2\""));
    assert!(out.contains("\"price\":80"));
    assert!(out.contains("\"status\":\"matched\""));

    let tasks_json = fs::read_to_string(&env.market_tasks_file).unwrap();
    assert!(tasks_json.contains("\"status\":\"matched\""));

    let _ = fs::remove_dir_all(&env.root);
}
