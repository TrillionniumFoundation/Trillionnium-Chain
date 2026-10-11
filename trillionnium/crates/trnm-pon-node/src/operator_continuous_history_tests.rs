//! Actual signature/filesystem/accounting definitions. No fixture is Native authority.
use super::*;
use crate::operator_continuous_test_support::{claim, delegation, identity, usage as high_usage};
use std::os::unix::fs::PermissionsExt;
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
fn signed(j: &Journal, sequence: u64, previous: Option<String>, revoked: bool) -> VerifiedBump {
    let body = BudgetIncrease {
        schema: "restricted-continuous-budget-increase-v2".into(),
        identity: identity(),
        sequence,
        previous_digest: previous,
        exact_prior_journal: j.anchor(),
        exact_usage_digest: j.usage_digest().unwrap(),
        ceilings: Ceilings {
            global: high_usage(),
            tasks: BTreeMap::from([("10".repeat(32), high_usage())]),
            classes: BTreeMap::from([("structured".into(), high_usage())]),
        },
        issued_ns: 1,
        expires_ns: 2,
        revoked,
        delegation: delegation(sequence),
    };
    let r = signing_key_from_hex(&"11".repeat(32)).unwrap();
    let t = signing_key_from_hex(&"22".repeat(32)).unwrap();
    let registry_signature = sign_hex(&r, &bump_message(&body, 1).unwrap());
    let task_signature = sign_hex(&t, &bump_message(&body, 2).unwrap());
    let h = digest(&bump_message(&body, 0).unwrap());
    let raw = serde_json::to_vec(&BumpEnvelope {
        body: body.clone(),
        registry_signature,
        task_signature,
    })
    .unwrap();
    authenticate_bump(
        &raw,
        &BumpAuthority {
            identity: identity(),
            expected: body,
            envelope_sha256: digest(&raw),
            latest_sequence: sequence,
            latest_digest: h,
        },
        1,
    )
    .unwrap()
}
pub(crate) fn journal() -> (tempfile::TempDir, Journal) {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let uid = rustix::process::geteuid().as_raw();
    let mut j = Journal::open(dir.path(), uid, &identity(), &Anchor::empty()).unwrap();
    let b = signed(&j, 1, None, false);
    j.increase(&b).unwrap();
    (dir, j)
}
#[test]
fn retained_history_crosses_256_without_reset_and_cold_scan_matches_indexes() {
    let (dir, mut j) = journal();
    for n in 1..=300 {
        j.record_authenticated_claim(claim(n)).unwrap();
    }
    let head = j.anchor();
    let usage = j.usage_digest().unwrap();
    assert_eq!(j.index.global.as_ref().unwrap().operations, 300);
    assert_eq!(j.index.tasks[&"10".repeat(32)].operations, 300);
    drop(j);
    let mut reopened = Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head,
    )
    .unwrap();
    assert_eq!(reopened.usage_digest().unwrap(), usage);
    assert_eq!(
        reopened.record_authenticated_claim(claim(1)),
        Err(PolicyError::Replay)
    );
}
#[test]
fn task_class_and_global_totals_are_incremental_and_replay_does_not_spend() {
    let (_dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    let before = j.usage_digest().unwrap();
    assert_eq!(
        j.record_authenticated_claim(claim(1)),
        Err(PolicyError::Replay)
    );
    assert_eq!(j.usage_digest().unwrap(), before);
    let old = j
        .index
        .claims
        .values()
        .fold(Usage::zero(), |n, c| n.claim(&c.allocation).unwrap());
    assert_eq!(j.index.global.as_ref().unwrap(), &old);
}
#[test]
fn budget_bump_keeps_same_identity_and_exact_usage_and_prior_head() {
    let (_dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    let previous = j.index.budget_digest.clone();
    let mut b = signed(&j, 2, previous, false);
    b.body.exact_usage_digest = "ff".repeat(32);
    assert_eq!(j.increase(&b), Err(PolicyError::ExternalContext));
    let b = signed(&j, 2, j.index.budget_digest.clone(), false);
    j.increase(&b).unwrap();
    assert_eq!(j.index.global.as_ref().unwrap().operations, 1);
    assert_eq!(
        j.record_authenticated_claim(claim(1)),
        Err(PolicyError::Replay)
    );
}
#[test]
fn lower_ceiling_and_revoke_never_refund_existing_claims() {
    let (_dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    let mut b = signed(&j, 2, j.index.budget_digest.clone(), false);
    b.body.ceilings.global.operations -= 1;
    assert_eq!(j.increase(&b), Err(PolicyError::Budget));
    let b = signed(&j, 2, j.index.budget_digest.clone(), true);
    j.increase(&b).unwrap();
    assert_eq!(
        j.record_authenticated_claim(claim(2)),
        Err(PolicyError::Revoked)
    );
    assert_eq!(j.index.claims.len(), 1);
}
#[test]
fn actual_owner_cpu_scope_links_startup_two_claims_and_settles_once() {
    let (_dir, mut j) = journal();
    let mut a = claim(1);
    a.purpose = "startup-catalog".into();
    a.operation = crate::operator_continuous_recipient::operation_id(&identity(), &a).unwrap();
    let aid = a.operation.clone();
    let mut b = claim(2);
    b.purpose = "parent-reconcile".into();
    b.operation = crate::operator_continuous_recipient::operation_id(&identity(), &b).unwrap();
    let bid = b.operation.clone();
    j.record_authenticated_claim(a).unwrap();
    j.record_authenticated_claim(b).unwrap();
    let cpu = crate::ingress::public_v3::ServiceMutationCpuDomain::standalone();
    let op = cpu.begin().unwrap();
    let scope = "aa".repeat(32);
    j.start_cpu(scope.clone(), aid, "10".repeat(32), "structured".into())
        .unwrap();
    j.link_startup_claim(scope.clone(), bid).unwrap();
    let actual = op.finish();
    assert!(!actual.accounting_unavailable);
    j.settle_cpu(scope.clone(), &actual).unwrap();
    assert_eq!(
        j.index.global.as_ref().unwrap().actual_cpu_ns,
        actual.total_cpu_ns.unwrap()
    );
    assert_eq!(j.index.pending_scopes, 0);
    assert!(j.settle_cpu(scope, &actual).is_err());
}
#[test]
fn unknown_and_unfinished_actual_scopes_hold_on_restart_and_bump() {
    let (dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    j.start_cpu(
        "aa".repeat(32),
        claim(1).operation,
        "10".repeat(32),
        "structured".into(),
    )
    .unwrap();
    let head = j.anchor();
    drop(j);
    assert!(Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head
    )
    .is_err());
    let (dir, mut j) = journal();
    let sink = j.fault_sink().unwrap();
    sink.persist_unknown().unwrap();
    let b = signed(&j, 2, j.index.budget_digest.clone(), false);
    assert_eq!(j.increase(&b), Err(PolicyError::CpuUnknown));
    let head = j.anchor();
    drop(j);
    assert!(Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head
    )
    .is_err());
}
#[test]
fn torn_deleted_row_and_wrong_outside_latest_never_cold_accept() {
    let (dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    let head = j.anchor();
    drop(j);
    let path = dir.path().join("entry-00000000000000000002.json");
    fs::write(&path, b"{").unwrap();
    assert!(Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head
    )
    .is_err());
    let (dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    let head = j.anchor();
    drop(j);
    fs::remove_file(dir.path().join("entry-00000000000000000001.json")).unwrap();
    assert!(Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head
    )
    .is_err());
}
#[test]
fn row_and_total_byte_caps_hold_without_dropping_history() {
    let (_dir, mut j) = journal();
    let before = j.anchor();
    j.bytes = MAX_JOURNAL_BYTES;
    assert_eq!(
        j.record_authenticated_claim(claim(1)),
        Err(PolicyError::Capacity)
    );
    assert_eq!(j.anchor(), before);
    assert_eq!(j.index.claims.len(), 0);
}
#[test]
fn clean_checkpoint_token_is_single_use_and_preserves_every_spent_counter() {
    let (_dir, mut j) = journal();
    j.record_authenticated_claim(claim(1)).unwrap();
    j.close_clean("12".repeat(32), 0).unwrap();
    let before = j.usage_digest().unwrap();
    let _token = j.issue_clean_restart().unwrap();
    assert!(j.issue_clean_restart().is_err());
    assert_eq!(j.usage_digest().unwrap(), before);
}

#[test]
fn original_registry_scope_package_and_uncapped_sequence_are_exact() {
    let (_dir, j) = journal();
    let valid = signed(&j, 2, j.index.budget_digest.clone(), false);
    assert_eq!(valid.body.delegation.registry2_view_sequence, 1000);
    let mut body = valid.body.clone();
    body.delegation.context.scope = "same-operator-restricted-testnet".into();
    assert!(body.delegation.validate(&body.identity, &body).is_err());
    body = valid.body.clone();
    body.delegation.context.consumer_source_package = "ee".repeat(32);
    assert!(body.delegation.validate(&body.identity, &body).is_err());
}
#[test]
fn cold_claim_full_task_binding_and_cumulative_class_are_not_hash_presence() {
    let (_dir, mut j) = journal();
    let mut changed = claim(1);
    changed.task_binding = "ee".repeat(32);
    changed.operation =
        crate::operator_continuous_recipient::operation_id(&identity(), &changed).unwrap();
    assert!(j.record_authenticated_claim(changed).is_err());
    assert_eq!(
        j.index
            .global
            .clone()
            .unwrap_or_else(Usage::zero)
            .operations,
        0
    );
}
#[test]
fn active_scope_snapshot_has_actual_settled_head_without_clean_close() {
    let (_dir, mut j) = journal();
    let c = claim(1);
    let op_id = c.operation.clone();
    j.record_authenticated_claim(c).unwrap();
    let cpu = crate::ingress::public_v3::ServiceMutationCpuDomain::standalone();
    let actual = cpu.begin().unwrap();
    let scope = "aa".repeat(32);
    j.start_cpu(scope.clone(), op_id, "10".repeat(32), "structured".into())
        .unwrap();
    j.settle_cpu(scope.clone(), &actual.finish()).unwrap();
    let snapshot = j.scope_receipt(&scope).unwrap();
    assert_eq!(snapshot.journal_head, j.anchor());
    assert_eq!(
        snapshot.owner_cpu_ns + snapshot.scoped_worker_cpu_ns,
        snapshot.total_cpu_ns
    );
    assert_eq!(
        snapshot.live_paid_cpu_ns + snapshot.residual_cpu_ns,
        snapshot.total_cpu_ns
    );
    assert!(!j.index.last_clean);
}
#[test]
fn control_frame_counters_remain_retained_and_extra_capacity_cannot_reset() {
    let (_dir, mut j) = journal();
    j.control_frame(b"{\"purpose\":\"read-status\"}").unwrap();
    assert_eq!(j.index.control_frames, 1);
    j.index.control_frames = 65536;
    assert_eq!(j.control_frame_capacity(), Err(PolicyError::Capacity));
    assert_eq!(j.control_frame(b"{}"), Err(PolicyError::Capacity));
}

pub(crate) fn claimed_journal() -> (tempfile::TempDir, Journal, Claim) {
    let (dir, mut j) = journal();
    let mut c = claim(1);
    c.allocation.cpu_ns = 100_000_000;
    j.record_authenticated_claim(c.clone()).unwrap();
    (dir, j, c)
}

fn mode5_claim_for(purpose: &str, n: u64) -> Claim {
    let mut c = claim(n);
    c.purpose = purpose.into();
    c.operation = crate::operator_continuous_recipient::operation_id(&identity(), &c).unwrap();
    c
}
fn mode5_start(
    j: &mut Journal,
    c: Claim,
    scope: &str,
) -> crate::ingress::public_v3::ServiceMutationCpuOperation {
    let operation = c.operation.clone();
    j.record_authenticated_claim(c).unwrap();
    let domain = crate::ingress::public_v3::ServiceMutationCpuDomain::standalone();
    let cpu = domain.begin().unwrap();
    j.start_cpu(
        scope.to_owned(),
        operation,
        "10".repeat(32),
        "structured".into(),
    )
    .unwrap();
    cpu
}
#[test]
fn mode5_pool_admission_retains_original_operation_and_exact_ordered_digest_after_cold_open() {
    let (dir, mut j) = journal();
    let c = mode5_claim_for("pool-submit-bundle", 1);
    let op = c.operation.clone();
    let scope = "a1".repeat(32);
    let cpu = mode5_start(&mut j, c, &scope);
    let group = "a2".repeat(32);
    let raw = "a3".repeat(32);
    j.record_pool_admission(&op, group.clone(), raw.clone())
        .unwrap();
    assert_eq!(j.pool_admission(&group).unwrap().operation, op);
    j.settle_cpu(scope, &cpu.finish()).unwrap();
    let head = j.anchor();
    let usage = j.usage_digest().unwrap();
    drop(j);
    let mut reopened = Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head,
    )
    .unwrap();
    assert_eq!(
        reopened.pool_admission(&group).unwrap().transactions_sha256,
        raw
    );
    assert_eq!(reopened.usage_digest().unwrap(), usage);
    assert!(reopened
        .record_pool_admission(&op, group, "a4".repeat(32))
        .is_err());
}
#[test]
fn mode5_pool_validation_requires_known_settlement_and_exact_task_parent_group_order_for_search() {
    let (_dir, mut j) = journal();
    let c = mode5_claim_for("pool-validate-batch", 1);
    let operation = c.operation.clone();
    let scope = "b1".repeat(32);
    let cpu = mode5_start(&mut j, c.clone(), &scope);
    let binding = crate::operator_continuous_test_support::binding();
    let groups = vec!["b2".repeat(32), "b3".repeat(32)];
    let raw = "b4".repeat(32);
    j.record_pool_validation(PoolValidation {
        operation: operation.clone(),
        parent: c.parent.clone(),
        generation: c.generation,
        native_task: c.native_task,
        instance_class: c.instance_class,
        task_binding: c.task_binding,
        pool_context: "b5".repeat(32),
        transactions_sha256: raw.clone(),
        groups: groups.clone(),
    })
    .unwrap();
    assert!(j
        .check_pool_search(&operation, &c.parent, 0, &binding, &raw, &groups)
        .is_err());
    j.settle_cpu(scope, &cpu.finish()).unwrap();
    assert!(j
        .check_pool_search(&operation, &c.parent, 0, &binding, &raw, &groups)
        .is_ok());
    assert!(j
        .check_pool_search(&operation, &c.parent, 1, &binding, &raw, &groups)
        .is_err());
    assert!(j
        .check_pool_search(&operation, &"b6".repeat(32), 0, &binding, &raw, &groups)
        .is_err());
    let mut wrong = binding.clone();
    wrong.instance_class = "zero".into();
    assert!(j
        .check_pool_search(&operation, &c.parent, 0, &wrong, &raw, &groups)
        .is_err());
    let reverse = vec![groups[1].clone(), groups[0].clone()];
    assert!(j
        .check_pool_search(&operation, &c.parent, 0, &binding, &raw, &reverse)
        .is_err());
}
#[test]
fn mode5_lease_reconcile_witness_must_settle_before_a_new_budget_can_bind_its_actual_head() {
    let (_dir, mut j) = journal();
    let mut c = mode5_claim_for("lease-reconcile", 1);
    let (_, _, mut edge) = crate::operator_continuous_lease::tests::fixture();
    // Journal unit projection only: the separate original Node lease checker
    // is mandatory before production can emit this witness.
    edge.old_task_binding = c.task_binding.clone();
    edge.actual_generation = c.generation;
    c.payload = edge.payload().unwrap();
    c.operation = crate::operator_continuous_recipient::operation_id(&identity(), &c).unwrap();
    let operation = c.operation.clone();
    let scope = "c1".repeat(32);
    let before = signed(&j, 2, j.index.budget_digest.clone(), false);
    let cpu = mode5_start(&mut j, c, &scope);
    j.record_lease_witness(operation.clone(), edge.clone())
        .unwrap();
    assert!(j.check_lease_witness(&operation, &edge).is_err());
    j.settle_cpu(scope, &cpu.finish()).unwrap();
    assert!(j.check_lease_witness(&operation, &edge).is_ok());
    let mut wrong = edge.clone();
    wrong.actual_generation += 1;
    assert!(j.check_lease_witness(&operation, &wrong).is_err());
    assert_eq!(j.increase(&before), Err(PolicyError::ExternalContext));
    let actual = signed(&j, 2, j.index.budget_digest.clone(), false);
    j.increase(&actual).unwrap();
    assert!(j.check_lease_witness(&operation, &edge).is_ok());
}
fn mode5_known_process(j: &mut Journal) -> crate::operator_continuous_recovery::Verified {
    let scope = "d1".repeat(32);
    let cpu = mode5_start(j, mode5_claim_for("startup-catalog", 1), &scope);
    let actual = cpu.finish();
    j.settle_cpu(scope.clone(), &actual).unwrap();
    let mut v =
        crate::operator_continuous_recovery::tests::verified(j.anchor(), j.usage_digest().unwrap());
    v.body.process_start_scope = scope;
    v.body.known_scope_total_cpu_ns = actual.total_cpu_ns.unwrap();
    // A declared extra 7ns tests accounting arithmetic only. It is not real
    // outside wait4 evidence and never grants production Native qualification.
    v.body.residual_cpu_ns = 7;
    v.body.closed_process_total_cpu_ns = v.body.known_scope_total_cpu_ns + 7;
    v.digest = crate::operator_continuous_recovery::body_digest(&v.body).unwrap();
    v
}
#[test]
fn mode5_known_unclean_residual_is_once_durable_without_refund_or_a_clean_close() {
    let (dir, mut j) = journal();
    let v = mode5_known_process(&mut j);
    let known = j.index.global.as_ref().unwrap().actual_cpu_ns;
    assert!(j.issue_known_unclean_restart(&v).is_err());
    j.record_known_unclean_process(&v).unwrap();
    assert_eq!(j.index.global.as_ref().unwrap().actual_cpu_ns, known + 7);
    assert_eq!(j.index.tasks[&"10".repeat(32)].actual_cpu_ns, known + 7);
    assert_eq!(j.index.classes["structured"].actual_cpu_ns, known + 7);
    assert!(!j.index.last_clean);
    assert!(j.record_known_unclean_process(&v).is_err());
    let head = j.anchor();
    let usage = j.usage_digest().unwrap();
    drop(j);
    let mut j = Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &identity(),
        &head,
    )
    .unwrap();
    assert_eq!(j.usage_digest().unwrap(), usage);
    let token = j.issue_known_unclean_restart(&v).unwrap();
    assert!(j.issue_known_unclean_restart(&v).is_err());
    let cpu =
        crate::ingress::public_v3::ServiceMutationCpuDomain::from_known_unclean_continuous_restart(
            token,
        );
    let receiver = cpu.clone();
    assert!(receiver.shares_domain_with(&cpu));
    assert!(cpu.begin().is_err());
    assert!(cpu
        .await_startup_credit(std::time::Instant::now() + std::time::Duration::from_millis(1))
        .is_err());
    cpu.await_startup_credit(std::time::Instant::now() + std::time::Duration::from_secs(9))
        .unwrap();
    assert!(!receiver.begin().unwrap().finish().accounting_unavailable);
    assert_eq!(j.usage_digest().unwrap(), usage);
}
#[test]
fn mode5_unclean_restart_wrong_prefix_unknown_pending_or_unstarted_claim_cannot_create_credit() {
    let (_dir, mut j) = journal();
    let v = mode5_known_process(&mut j);
    let mut wrong = v.clone();
    wrong.body.known_scope_total_cpu_ns += 1;
    wrong.body.closed_process_total_cpu_ns += 1;
    wrong.digest = crate::operator_continuous_recovery::body_digest(&wrong.body).unwrap();
    assert!(j.record_known_unclean_process(&wrong).is_err());
    assert!(j.issue_known_unclean_restart(&wrong).is_err());
    j.record_authenticated_claim(claim(2)).unwrap();
    let mut now = v.clone();
    now.body.prior_journal = j.anchor();
    now.body.exact_usage_digest = j.usage_digest().unwrap();
    now.digest = crate::operator_continuous_recovery::body_digest(&now.body).unwrap();
    assert!(j.record_known_unclean_process(&now).is_err());
    j.mark_unknown().unwrap();
    assert!(j.issue_known_unclean_restart(&now).is_err());
}
