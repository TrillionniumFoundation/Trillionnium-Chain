use super::*;

#[test]
fn test_market_submit_bid_selects_lower_price() {
    let env = test_env("submit_bid");

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
    let out = run_rpc(
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

    assert!(out.contains("\"worker\": \"worker2\""));
    assert!(out.contains("\"price\": 80"));

    let _ = fs::remove_dir_all(&env.root);
}
