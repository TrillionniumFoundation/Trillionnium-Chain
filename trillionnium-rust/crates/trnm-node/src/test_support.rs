pub(super) use crate::{
    apply_accept_task, apply_accept_task_at_height, apply_challenge, apply_challenge_at_height,
    apply_commit_result, apply_commit_result_at_height, apply_create_task, apply_one,
    apply_resolve, apply_resolve_at_height, apply_reveal_result, apply_timeout, average_or_zero,
    balance_deltas_for_transition, challenger_of, classify_apply_error, compute_commitment,
    decide_order_for_commit, diff_u128_to_i128, event_delta_from_balances,
    event_type_for_apply_outcome, finality_budget_share_ppm, gap_percent_bps,
    hot_object_tail_share_ppm, hot_object_top_label_share_ppm, is_rejected_by_emergency_pause,
    missed_proposals_added_since, now_unix_ms, pick_txs_with_critical_guard,
    pre_execute_group_parallel, ratio_milli_u64, ratio_percent_bps, ratio_ppm, ratio_ppm_u64,
    requeue_uncommitted_txs, resolve_wal_dir, scan_and_apply_timeouts, summarize_hot_objects,
    task_id_of, treasury_total, verified_signer_of, wal_file, wal_meta_file, wall_time_share_ppm,
    Args, EventDelta, HotObjectSummary, MockTx, ObjectRef, PreExecPool, ShadowOnlyRlAdvisor,
    StateStore, TaskStatus, WalDirMode, CHALLENGE_ESCROW_ACCOUNT,
    CHALLENGE_FORFEIT_TREASURY_ACCOUNT, DEFAULT_BFT_WAL_DIR, RESOLVE_AUTHORITY_HOT_LABEL,
    RESOLVE_PENDING_APPROVAL_HOT_LABEL, WORKER_SLASH_TREASURY_ACCOUNT,
};
pub(super) use crate::{RlAdviceContext, RlAdvisor};
pub(super) use std::collections::{HashSet, VecDeque};
pub(super) use std::fs;
pub(super) use std::path::PathBuf;
pub(super) use std::sync::Arc;
pub(super) use trnm_pouw;
pub(super) use trnm_state::{GovParamUpdateOutcome, PendingResolveApprovalSnapshot};

pub(super) fn challenged_task_fixture(
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
    let r4 = trnm_pouw::apply_reveal_result_at_height(st, r3, result_hash, reveal_salt, None, 110)
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

pub(super) fn temp_wal_dir(name: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("trnm-node-{}-{}", name, now_unix_ms()));
    p
}
