use super::*;

#[derive(Debug, Clone)]
pub(crate) struct TxRollbackSnapshot {
    pub(crate) task_id: u64,
    pub(crate) task: Option<trnm_types::TaskObject>,
    pub(crate) balances: Vec<(String, Option<u128>)>,
    pub(crate) pending_resolve_approval: Option<PendingResolveApprovalSnapshot>,
}

pub(crate) fn balance_snapshot(st: &StateStore, address: &str) -> Option<u128> {
    let balance = st.balance_of(address);
    if balance == 0 {
        None
    } else {
        Some(balance)
    }
}

pub(crate) fn capture_rollback_snapshot(st: &StateStore, tx: &MockTx) -> TxRollbackSnapshot {
    let task_id = task_id_of(tx);
    let task = st.get_task(task_id);
    let pending_resolve_approval = st.pending_resolve_approval_snapshot(task_id);
    let mut balances: Vec<(String, Option<u128>)> = Vec::new();
    let mut push_balance = |address: &str| {
        if balances.iter().any(|(existing, _)| existing == address) {
            return;
        }
        balances.push((address.to_string(), balance_snapshot(st, address)));
    };

    match tx {
        MockTx::CreateTask { creator, .. } => {
            push_balance(creator);
        }
        MockTx::Challenge { challenger, .. } => {
            push_balance(challenger);
            push_balance("treasury.challenge_escrow");
        }
        MockTx::Resolve { .. } => {
            push_balance("treasury.challenge_escrow");
            push_balance("treasury.challenge_forfeits");
            push_balance("treasury.worker_slashes");
            if let Some(task) = task.as_ref() {
                if let Some(worker) = task.worker.as_deref() {
                    push_balance(worker);
                }
                if let Some(challenger) = task.challenger.as_deref() {
                    push_balance(challenger);
                }
            }
        }
        MockTx::AcceptTask { .. } | MockTx::Commit { .. } | MockTx::Reveal { .. } => {}
    }

    TxRollbackSnapshot {
        task_id,
        task,
        balances,
        pending_resolve_approval,
    }
}

pub(crate) fn canonicalize_resolve_authority_snapshot(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed != raw {
        return None;
    }

    let has_forbidden_separator = |token: &str| {
        token.contains(';')
            || token.contains('|')
            || token.contains('；')
            || token.contains('，')
            || token.contains('、')
    };

    let mut seen = std::collections::BTreeSet::new();
    let mut canonical_members = Vec::new();
    for member in trimmed.split(',') {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty()
            || member_trimmed != member
            || member_trimmed.chars().any(|c| c.is_whitespace())
            || has_forbidden_separator(member_trimmed)
            || !member_trimmed.is_ascii()
            || member_trimmed.eq_ignore_ascii_case("governance.resolve_authority")
            || member_trimmed.eq_ignore_ascii_case("governance.emergency_pause")
            || member_trimmed.eq_ignore_ascii_case("system")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
            || member_trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
        {
            return None;
        }
        let lowered = member_trimmed.to_ascii_lowercase();
        if !seen.insert(lowered.clone()) {
            return None;
        }
        canonical_members.push(lowered);
    }

    if canonical_members.len() < 2 {
        return None;
    }
    canonical_members.sort();
    Some(canonical_members.join(","))
}

pub(crate) fn is_canonical_resolve_approver_snapshot(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && trimmed == raw
        && !trimmed.chars().any(|c| c.is_whitespace())
        && !trimmed.contains(',')
        && !trimmed.contains(';')
        && !trimmed.contains('|')
        && trimmed.is_ascii()
        && !trimmed.eq_ignore_ascii_case("governance.resolve_authority")
        && !trimmed.eq_ignore_ascii_case("governance.emergency_pause")
        && !trimmed.eq_ignore_ascii_case("system")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
        && !trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
}

pub(crate) fn restore_pending_resolve_approval_from_snapshot(
    st: &mut StateStore,
    task_id: u64,
    snapshot: Option<PendingResolveApprovalSnapshot>,
) {
    st.clear_pending_resolve_approval(task_id);

    let Some(snapshot) = snapshot else {
        return;
    };

    let Some(task) = st.get_task(task_id) else {
        return;
    };
    if snapshot.task_version != task.version {
        return;
    }
    if snapshot.confirmations != 1 {
        return;
    }
    if !is_canonical_resolve_approver_snapshot(&snapshot.first_approver) {
        return;
    }
    let snapshot_first_approver = snapshot.first_approver.to_ascii_lowercase();

    let Some(snapshot_authority_set) =
        canonicalize_resolve_authority_snapshot(&snapshot.authority_set)
    else {
        return;
    };
    let expected_authority_set = st
        .pending_gov_update("resolve_authority")
        .map(|pending| pending.value)
        .or_else(|| st.gov_param_string("resolve_authority"));
    let Some(expected_authority_set) = expected_authority_set
        .as_deref()
        .and_then(canonicalize_resolve_authority_snapshot)
    else {
        return;
    };
    if snapshot_authority_set != expected_authority_set {
        return;
    }

    st.restore_pending_resolve_approval_from_rollback(
        task_id,
        Some(PendingResolveApprovalSnapshot {
            first_approver: snapshot_first_approver,
            authority_set: snapshot_authority_set,
            ..snapshot
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let r4 = trnm_pouw::apply_reveal_result_at_height(
            st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
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

    #[test]
    fn restore_pending_resolve_approval_normalizes_case_and_order_equivalent_replacement_authority() {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_283,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_303,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_304,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(replacement, GovParamUpdateOutcome::Scheduled { .. }));

        let _ = challenged_task_fixture(&mut st, 8_115);
        st.set_gov_param(98_305, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_115).unwrap();

        restore_pending_resolve_approval_from_snapshot(
            &mut st,
            8_115,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "Authority-D".into(),
                authority_set: "Authority-D,Authority-C".into(),
                task_version: before_task.version,
            }),
        );

        assert_eq!(st.pending_resolve_approval(8_115), Some((false, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(8_115).as_deref(),
            Some("authority-d")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_115),
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "authority-d".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            })
        );
    }

    #[test]
    fn canonicalize_resolve_authority_snapshot_rejects_reserved_or_alias_members_fail_closed() {
        for raw in [
            "authority-a,governance.resolve_authority",
            "authority-a,governance.emergency_pause",
            "authority-a,system",
            "authority-a,treasury.challenge_escrow",
            "authority-a,treasury.challenge_forfeits",
            "authority-a,treasury.worker_slashes",
            "authority-a,Authority-A",
        ] {
            assert_eq!(
                canonicalize_resolve_authority_snapshot(raw),
                None,
                "reserved or aliased authority member must fail closed: {raw}"
            );
        }
    }

    #[test]
    fn restore_pending_resolve_approval_from_snapshot_rejects_reserved_first_approver_alias() {
        let mut st = StateStore::default();
        st.set_gov_param(
            98_300,
            7_998,
            "resolve_authority".into(),
            "authority-c,authority-d".into(),
        )
        .expect("resolve authority set should install");

        let _ = challenged_task_fixture(&mut st, 8_116);
        st.set_gov_param(98_306, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_116).unwrap();

        restore_pending_resolve_approval_from_snapshot(
            &mut st,
            8_116,
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "governance.resolve_authority".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        );

        assert_eq!(
            st.pending_resolve_approval(8_116),
            None,
            "rollback restore must fail closed when first approver reuses a reserved canonical alias"
        );
        assert_eq!(
            st.pending_resolve_first_approver(8_116),
            None,
            "reserved first approver aliases must not materialize a staged approver during paused restore"
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_116),
            None,
            "reserved first approver aliases must not persist paused rollback metadata"
        );
    }
}

pub(crate) fn rollback_tx_snapshot(st: &mut StateStore, snapshot: TxRollbackSnapshot) {
    st.restore_task(snapshot.task_id, snapshot.task);
    for (address, balance) in snapshot.balances {
        st.restore_balance(&address, balance);
    }
    restore_pending_resolve_approval_from_snapshot(
        st,
        snapshot.task_id,
        snapshot.pending_resolve_approval,
    );
}

pub(crate) fn balance_deltas_from_snapshot(
    before: &TxRollbackSnapshot,
    after: &StateStore,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_before: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(_, balance)| balance.unwrap_or(0))
        .sum();
    let treasury_after: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(address, _)| after.balance_of(address))
        .sum();
    let treasury_delta = event_delta_from_balances(treasury_after, treasury_before);
    let challenger_delta = challenger.and_then(|acct| {
        before
            .balances
            .iter()
            .find(|(address, _)| address == acct)
            .map(|(_, balance)| {
                event_delta_from_balances(after.balance_of(acct), balance.unwrap_or(0))
            })
    });
    (treasury_delta, challenger_delta)
}

pub(crate) fn scan_and_apply_timeouts(
    st: &mut StateStore,
    known_task_ids: &HashSet<u64>,
    current_height: u64,
    tx_id_seed: u64,
) -> u64 {
    let mut migrated = 0u64;
    for task_id in known_task_ids.iter().copied() {
        let Some(task) = st.get_task(task_id) else {
            continue;
        };
        if !matches!(
            task.status,
            TaskStatus::Assigned
                | TaskStatus::Committed
                | TaskStatus::Revealed
                | TaskStatus::Challenged
        ) {
            continue;
        }
        if st.is_emergency_paused() && matches!(task.status, TaskStatus::Challenged) {
            continue;
        }
        let from_status = format!("{:?}", task.status);
        let challenger = task.challenger.clone();
        let Some(task_ref) = st.get_ref(task_id) else {
            continue;
        };
        let before = st.clone();
        if apply_timeout(st, task_ref, current_height).is_ok() {
            migrated += 1;
            let to_status = status_name(st, task_id);
            let root = hex::encode(st.state_root());
            let (treasury_delta, challenger_delta) =
                balance_deltas_for_transition(&before, st, task_id, challenger.as_deref());
            let bond_disposition = if from_status == "Challenged" {
                st.get_task(task_id).and_then(|t| {
                    t.challenge_bond_forfeited
                        .map(|forfeited| if forfeited { "forfeited" } else { "refunded" })
                })
            } else {
                None
            };
            emit_timeout_event(
                st,
                task_id,
                tx_id_seed.saturating_add(migrated),
                migrated,
                false,
                false,
                current_height,
                &from_status,
                &to_status,
                &root,
                &treasury_delta,
                challenger_delta.as_ref(),
                challenger.as_deref(),
                bond_disposition,
            );
            println!(
                "[timeout] height={} task_id={} from_status={} to_status={} source=auto_scan",
                current_height, task_id, from_status, to_status
            );
        }
    }
    migrated
}
