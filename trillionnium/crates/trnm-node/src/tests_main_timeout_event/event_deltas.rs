use super::*;

#[test]
fn event_deltas_match_balance_movements_on_revealed_timeout_complete() {
    let mut st = StateStore::new();
    st.set_balance("worker8100", 1_000);

    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let r1 = apply_create_task(&mut st, 8100, "alice".into(), 100).unwrap();
    let committed = compute_commitment(8100, &result_hash, &reveal_salt, "worker8100");
    let r2 = apply_accept_task(&mut st, r1, "worker8100".into()).unwrap();
    let r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker8100".into(), committed, 1)
            .unwrap();
    let revealed =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 2)
            .unwrap();

    let before = st.clone();
    let _ = apply_timeout(&mut st, revealed, 1_000).unwrap();

    let (treasury_delta, challenger_delta) =
        balance_deltas_for_transition(&before, &st, 8100, None);

    assert_eq!(st.get_task(8100).unwrap().status, TaskStatus::Completed);
    assert_eq!(
        treasury_delta.numeric,
        diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
    );
    assert_eq!(challenger_delta, None);
    assert_eq!(treasury_delta.numeric, Some(0));
}

#[test]
fn event_deltas_match_balance_movements_on_resolve_slashed() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 100);
    st.set_balance("worker8101", 1_000);

    let r1 = apply_create_task(&mut st, 8101, "alice".into(), 100).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(8101, &result_hash, &reveal_salt, "worker8101");

    let r2 = apply_accept_task(&mut st, r1, "worker8101".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker8101".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let challenger = before
        .get_task(8101)
        .and_then(|t| t.challenger)
        .expect("challenger must exist");
    let resolve_authority = "authority8101,authority8101b".to_string();
    st.set_gov_param_bootstrap_unchecked(
        18_101,
        "resolve_authority".into(),
        resolve_authority.clone(),
    )
    .unwrap();
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        true,
        "authority8101".into(),
        "authority8101".into(),
    )
    .expect_err("first multisig approver should stage only");
    assert!(matches!(
        staged,
        trnm_pouw::PouwError::ResolveApprovalStaged
    ));
    let _r7 = apply_resolve(
        &mut st,
        r5,
        true,
        "authority8101b".into(),
        "authority8101b".into(),
    )
    .unwrap();

    let (treasury_delta, challenger_delta) =
        balance_deltas_for_transition(&before, &st, 8101, Some(challenger.as_str()));

    assert_eq!(
        treasury_delta.numeric,
        diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
    );
    assert_eq!(
        challenger_delta.as_ref().and_then(|d| d.numeric),
        diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
    );
    assert!(
        challenger_delta
            .as_ref()
            .and_then(|d| d.numeric)
            .unwrap_or(0)
            > 0
    );
}

#[test]
fn event_deltas_match_balance_movements_on_resolve_forfeited() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 100);
    st.set_balance("worker8102", 1_000);

    let r1 = apply_create_task(&mut st, 8102, "alice".into(), 100).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(8102, &result_hash, &reveal_salt, "worker8102");

    let r2 = apply_accept_task(&mut st, r1, "worker8102".into()).unwrap();
    let r3 = apply_commit_result(&mut st, r2, "worker8102".into(), committed).unwrap();
    let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
    let r5 = apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

    let before = st.clone();
    let challenger = before
        .get_task(8102)
        .and_then(|t| t.challenger)
        .expect("challenger must exist");
    let resolve_authority = "authority8102,authority8102b".to_string();
    st.set_gov_param_bootstrap_unchecked(
        18_102,
        "resolve_authority".into(),
        resolve_authority.clone(),
    )
    .unwrap();
    let staged = apply_resolve(
        &mut st,
        r5.clone(),
        false,
        "authority8102".into(),
        "authority8102".into(),
    )
    .expect_err("first multisig approver should stage only");
    assert!(matches!(
        staged,
        trnm_pouw::PouwError::ResolveApprovalStaged
    ));
    let _r7 = apply_resolve(
        &mut st,
        r5,
        false,
        "authority8102b".into(),
        "authority8102b".into(),
    )
    .unwrap();

    let (treasury_delta, challenger_delta) =
        balance_deltas_for_transition(&before, &st, 8102, Some(challenger.as_str()));

    assert_eq!(
        treasury_delta.numeric,
        diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
    );
    assert_eq!(
        challenger_delta.as_ref().and_then(|d| d.numeric),
        diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
    );
    assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(0));
}

#[test]
fn event_deltas_match_balance_movements_on_challenged_timeout_refund() {
    let mut st = StateStore::new();
    st.set_balance("challenger", 100);
    st.set_balance("worker8103", 1_000);

    let r1 = apply_create_task(&mut st, 8103, "alice".into(), 100).unwrap();
    let result_hash = [7u8; 32];
    let reveal_salt = [9u8; 32];
    let committed = compute_commitment(8103, &result_hash, &reveal_salt, "worker8103");

    let r2 = apply_accept_task(&mut st, r1, "worker8103".into()).unwrap();
    let r3 =
        trnm_pouw::apply_commit_result_at_height(&mut st, r2, "worker8103".into(), committed, 1)
            .unwrap();
    let r4 =
        trnm_pouw::apply_reveal_result_at_height(&mut st, r3, result_hash, reveal_salt, None, 2)
            .unwrap();
    let challenged = trnm_pouw::apply_challenge_at_height(
        &mut st,
        r4,
        "challenger".into(),
        10,
        "challenger".into(),
        3,
    )
    .unwrap();

    let before = st.clone();
    let challenger = before
        .get_task(8103)
        .and_then(|t| t.challenger)
        .expect("challenger must exist");
    let _ = apply_timeout(&mut st, challenged, 1_000).unwrap();

    let (treasury_delta, challenger_delta) =
        balance_deltas_for_transition(&before, &st, 8103, Some(challenger.as_str()));

    assert_eq!(
        treasury_delta.numeric,
        diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
    );
    assert_eq!(
        challenger_delta.as_ref().and_then(|d| d.numeric),
        diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
    );
    assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(10));
    assert_eq!(
        st.get_task(8103).and_then(|t| t.challenge_bond_forfeited),
        Some(false)
    );
}

#[test]
fn format_task_metering_event_fields_includes_normalized_work_units_and_policy_summary() {
    let snapshot = TaskMeteringSnapshot {
        workload_class: "llm_inference".into(),
        metering_schema: "llm_token_meter_v1".into(),
        policy_snapshot_version: 1,
        receipt_hash: "deadbeef".into(),
        prompt_tokens: 128,
        generated_tokens: 32,
        decode_steps: 32,
        kv_bytes_moved: 4096,
        normalized_work_units: 192,
        prompt_token_weight: 1,
        generated_token_weight: 1,
        decode_step_weight: 1,
        kv_byte_weight: 0,
        min_accept_work_units: 100,
        challenge_success_bounty_base: 1,
        challenge_success_bounty_per_work_unit_num: 1,
        challenge_success_bounty_per_work_unit_den: 192,
        worker_completion_bonus_per_work_unit_num: 1,
        worker_completion_bonus_per_work_unit_den: 256,
        worker_slash_rebate_per_work_unit_num: 1,
        worker_slash_rebate_per_work_unit_den: 384,
    };
    let line = format_task_metering_event_fields(&snapshot);
    assert!(line.contains("metering_schema=llm_token_meter_v1"));
    assert!(line.contains("metering_normalized_work_units=192"));
    assert!(line.contains("metering_policy_snapshot_version=1"));
    assert!(line.contains("metering_min_accept_work_units=100"));
    assert!(line.contains("metering_worker_slash_rebate_per_work_unit_den=384"));
}

#[test]
fn event_delta_fallback_is_deterministic_for_large_balances() {
    let before = i128::MAX as u128 + 10;
    let after = before + 25;

    let delta = event_delta_from_balances(after, before);
    assert_eq!(delta.numeric, None);
    assert_eq!(delta.text, "u128:+25");
    assert_ne!(delta.text, "-");

    let reverse = event_delta_from_balances(before, after);
    assert_eq!(reverse.numeric, None);
    assert_eq!(reverse.text, "u128:-25");
}

#[test]
fn event_delta_normal_range_text_matches_previous_numeric_output() {
    let before = 100u128;
    let after = 82u128;

    let delta = event_delta_from_balances(after, before);
    assert_eq!(delta.numeric, Some(-18));
    assert_eq!(delta.text, "-18");
}
