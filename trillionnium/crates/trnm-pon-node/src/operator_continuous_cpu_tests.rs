use super::*;
use crate::operator_continuous_history::{self as history, tests::claimed_journal};
use std::panic::{catch_unwind, AssertUnwindSafe};
fn start(c: &history::Claim) -> Start {
    Start {
        scope: "aa".repeat(32),
        operation: c.operation.clone(),
        linked_startup: None,
        task: c.native_task.clone(),
        class: c.instance_class.clone(),
    }
}
#[test]
fn mode4_durable_actual_interval_settles_original_owner_cpu_exactly_once() {
    let (_dir, j, c) = claimed_journal();
    let sink = Arc::new(j.fault_sink().unwrap());
    let j = Arc::new(Mutex::new(j));
    let cpu = ServiceMutationCpuDomain::standalone();
    let operation = DurableOperation::begin(j.clone(), &cpu, start(&c), sink).unwrap();
    operation.checkpoint_handle().unwrap().checkpoint().unwrap();
    let actual = operation.finish().unwrap();
    assert!(actual.accounting_record_persisted);
    assert!(!actual.actual.accounting_unavailable);
    let receipt = j.lock().unwrap().scope_receipt(&"aa".repeat(32)).unwrap();
    assert_eq!(receipt.total_cpu_ns, actual.actual.total_cpu_ns.unwrap());
    assert_eq!(
        receipt.owner_cpu_ns + receipt.scoped_worker_cpu_ns,
        receipt.total_cpu_ns
    );
    assert_eq!(
        receipt.live_paid_cpu_ns + receipt.residual_cpu_ns,
        receipt.total_cpu_ns
    );
    assert!(cpu.accounting_available());
}
#[test]
fn mode4_observed_public_interval_attaches_without_an_extra_begin_or_debit() {
    let (_dir, j, c) = claimed_journal();
    let sink = Arc::new(j.fault_sink().unwrap());
    let j = Arc::new(Mutex::new(j));
    let cpu = ServiceMutationCpuDomain::standalone();
    let original = cpu.begin().unwrap();
    let observed =
        ObservedOperation::begin(j.clone(), start(&c), original.checkpoint_handle(), sink).unwrap();
    observed.checkpoint_handle().checkpoint().unwrap();
    let actual = original.finish();
    assert!(observed.finish(&actual));
    let receipt = j.lock().unwrap().scope_receipt(&"aa".repeat(32)).unwrap();
    assert_eq!(receipt.total_cpu_ns, actual.total_cpu_ns.unwrap());
    assert_eq!(receipt.spawned, 0);
    assert!(cpu.accounting_available());
}
#[test]
fn mode4_poisoned_observed_initializer_persists_unknown_independent_of_journal_lock() {
    let (dir, j, c) = claimed_journal();
    let head = j.anchor();
    let sink = Arc::new(j.fault_sink().unwrap());
    let j = Arc::new(Mutex::new(j));
    let poisoned = j.clone();
    assert!(catch_unwind(AssertUnwindSafe(move || {
        let _held = poisoned.lock().unwrap();
        panic!("mechanism poison")
    }))
    .is_err());
    let cpu = ServiceMutationCpuDomain::standalone();
    let original = cpu.begin().unwrap();
    assert!(
        ObservedOperation::begin(j.clone(), start(&c), original.checkpoint_handle(), sink).is_err()
    );
    let _actual = original.finish();
    drop(j);
    assert!(history::Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &crate::operator_continuous_test_support::identity(),
        &head
    )
    .is_err());
}
#[test]
fn mode4_unfinished_drop_retains_cpu_unknown_and_does_not_make_clean_restart() {
    let (dir, j, c) = claimed_journal();
    let sink = Arc::new(j.fault_sink().unwrap());
    let j = Arc::new(Mutex::new(j));
    let cpu = ServiceMutationCpuDomain::standalone();
    let operation = DurableOperation::begin(j.clone(), &cpu, start(&c), sink).unwrap();
    drop(operation);
    assert!(!cpu.accounting_available());
    let head = j.lock().unwrap().anchor();
    drop(j);
    assert!(history::Journal::open(
        dir.path(),
        rustix::process::geteuid().as_raw(),
        &crate::operator_continuous_test_support::identity(),
        &head
    )
    .is_err());
}
#[test]
fn mode4_clean_zero_credit_restart_waits_original_refill_in_the_same_domain() {
    let (_dir, mut j, _c) = claimed_journal();
    j.close_clean("12".repeat(32), 0).unwrap();
    let token = j.issue_clean_restart().unwrap();
    let cpu = ServiceMutationCpuDomain::from_clean_continuous_restart(token);
    let receiver = cpu.clone();
    assert!(cpu.shares_domain_with(&receiver));
    assert!(cpu.begin().is_err());
    assert!(cpu
        .await_startup_credit(std::time::Instant::now() + std::time::Duration::from_millis(1))
        .is_err());
    cpu.await_startup_credit(std::time::Instant::now() + std::time::Duration::from_secs(9))
        .unwrap();
    let original = receiver.begin().unwrap();
    let actual = original.finish();
    assert!(!actual.accounting_unavailable);
    assert!(cpu.shares_domain_with(&receiver));
}
