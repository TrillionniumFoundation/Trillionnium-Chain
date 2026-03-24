use super::*;

#[path = "tests_rollback_snapshot_pending.rs"]
mod tests_rollback_snapshot_pending;
#[path = "tests_rollback_snapshot_paused_retry/mod.rs"]
mod tests_rollback_snapshot_paused_retry;
#[path = "tests_rollback_snapshot_invalid.rs"]
mod tests_rollback_snapshot_invalid;
#[path = "tests_rollback_snapshot_terminal.rs"]
mod tests_rollback_snapshot_terminal;

fn challenged_task_fixture(
    st: &mut StateStore,
    task_id: u64,
) -> (ObjectRef, [u8; 32], [u8; 32]) {
    st.set_balance("challenger", 1_000_000);
    st.set_balance(&format!("worker{}", task_id), 1_000);
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(
        task_id,
        &result_hash,
        &reveal_salt,
        &format!("worker{}", task_id),
    );
    let r1 = apply_create_task(st, task_id, "alice".into(), 100).unwrap();
    let r2 = apply_accept_task(st, r1, format!("worker{}", task_id)).unwrap();
    let r3 = trnm_pouw::apply_commit_result_at_height(
        st,
        r2,
        format!("worker{}", task_id),
        committed,
        100,
    )
    .unwrap();
    let r4 =
        trnm_pouw::apply_reveal_result_at_height(st, r3, result_hash, reveal_salt, None, 110)
            .unwrap();
    let r5 = trnm_pouw::apply_challenge_at_height(
        st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        120,
    )
    .unwrap();
    (r5, result_hash, reveal_salt)
}
