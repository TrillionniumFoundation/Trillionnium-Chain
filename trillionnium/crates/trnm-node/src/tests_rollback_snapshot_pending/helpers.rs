use super::*;

pub(super) fn assert_pending_snapshot(
    st: &StateStore,
    task_id: u64,
    before_task: Task,
    before_escrow: u64,
    expected: PendingResolveApprovalSnapshot,
) {
    assert_eq!(st.get_task(task_id).unwrap(), before_task);
    assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
    assert_eq!(st.pending_resolve_approval(task_id), Some((true, 1)));
    assert_eq!(
        st.pending_resolve_first_approver(task_id).as_deref(),
        Some(expected.first_approver.as_str())
    );
    assert_eq!(st.pending_resolve_approval_snapshot(task_id), Some(expected));
}
