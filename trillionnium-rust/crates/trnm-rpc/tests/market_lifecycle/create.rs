use super::*;

#[test]
fn test_market_create_task() {
    let env = test_env("create_task");

    let out = run_rpc(
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
    assert!(out.contains("\"creator\": \"alice\""));
    assert!(out.contains("\"bounty\": 100"));
    assert!(out.contains("\"status\": \"open\""));

    let _ = fs::remove_dir_all(&env.root);
}
