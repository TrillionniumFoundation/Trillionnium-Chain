use super::*;
use std::sync::atomic::AtomicUsize;

fn public_operation() -> (
    ServiceMutationCpuDomain,
    ServiceMutationCpuOperation,
    Arc<AtomicBool>,
) {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    operation
        .live
        .bind_public_request(
            Instant::now() + Duration::from_secs(5),
            Arc::new(AtomicBool::new(false)),
            cancelled.clone(),
        )
        .unwrap();
    // This tests local scheduler state, not Work validity or public acceptance.
    operation.live.promote_verified_identity([93; 32]).unwrap();
    (domain, operation, cancelled)
}
fn force_unspendable_credit(domain: &ServiceMutationCpuDomain) {
    let mut budget = domain.budget.lock().unwrap();
    budget.credit_ns = -1_000_000_000;
    budget.updated = Instant::now() + Duration::from_secs(30);
    budget.flow = None; // Controlled accounting state, not a cost measurement.
}

#[test]
fn node_owner_scopes_are_nested_and_restore_the_exact_enclosing_wait_policy() {
    for history in [false, true] {
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        if history {
            operation
                .bind_history_request(Instant::now() + Duration::from_secs(5))
                .unwrap();
        }
        let handle = operation.checkpoint_handle();
        let first = handle.prevent_refill_wait_while_node_owned().unwrap();
        let second = handle.prevent_refill_wait_while_node_owned().unwrap();
        assert_eq!(operation.live.state.lock().unwrap().node_owner_scopes, 2);
        drop(first);
        assert_eq!(operation.live.state.lock().unwrap().node_owner_scopes, 1);
        drop(second);
        {
            let state = operation.live.state.lock().unwrap();
            assert_eq!(state.node_owner_scopes, 0);
            assert_eq!(state.wait_inside_checkpoint, !history);
        }
        assert!(!operation.finish().accounting_unavailable);
    }
}

#[test]
fn held_node_budget_refusal_never_sleeps_and_releases_the_real_head_reader() {
    let (domain, operation, _) = public_operation();
    let dir = tempfile::tempdir().unwrap();
    let settings = crate::Settings::development(Some(1)).unwrap();
    let node = Mutex::new(crate::Node::open(dir.path(), settings, 2).unwrap());
    let handle = operation.checkpoint_handle();
    let owner = crate::ingress::lock_mutation_owner(&node, &mut |_| Ok(()), Some(&handle)).unwrap();
    assert!(node.try_lock().is_err());
    force_unspendable_credit(&domain);
    let calls = AtomicUsize::new(0);
    let before = domain.budget.lock().unwrap().credit_ns;
    let error = operation
        .live
        .observe_with_control(false, true, true, &|| {
            calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_BUDGET");
    // Waiting would make a second resource callback before the first sleep.
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    assert!(domain.budget.lock().unwrap().credit_ns <= before);
    assert!(operation.live.state.lock().unwrap().refused);
    drop(owner);
    assert_eq!(operation.live.state.lock().unwrap().node_owner_scopes, 0);
    thread::scope(|scope| {
        scope
            .spawn(|| {
                let owner = crate::ingress::lock_owner(&node, &mut |_| Ok(())).unwrap();
                owner.public_head_metadata().unwrap()
            })
            .join()
            .unwrap()
    });
    let settlement = operation.finish();
    assert!(settlement.live_refused);
    assert!(!settlement.accounting_unavailable);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
}

#[test]
fn dropping_node_owner_restores_unlocked_continuation_without_new_reserve() {
    let (domain, operation, cancelled) = public_operation();
    let dir = tempfile::tempdir().unwrap();
    let settings = crate::Settings::development(Some(1)).unwrap();
    let node = Mutex::new(crate::Node::open(dir.path(), settings, 2).unwrap());
    let handle = operation.checkpoint_handle();
    let owner = crate::ingress::lock_mutation_owner(&node, &mut |_| Ok(()), Some(&handle)).unwrap();
    drop(owner);
    assert!(node.try_lock().is_ok());
    force_unspendable_credit(&domain);
    let calls = AtomicUsize::new(0);
    let error = operation
        .live
        .observe_with_control(false, true, true, &|| {
            // Stop at the unlocked refill-wait boundary, before an actual sleep.
            if calls.fetch_add(1, Ordering::Relaxed) == 1 {
                cancelled.store(true, Ordering::Release);
            }
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_REQUEST_CANCELLED");
    assert_eq!(calls.load(Ordering::Relaxed), 2);
    assert!(!operation.live.state.lock().unwrap().refused);
    assert_eq!(domain.observe().unwrap().in_flight, 1);
    assert!(!operation.finish().accounting_unavailable);
    assert_eq!(domain.observe().unwrap().in_flight, 0);
}

#[test]
fn wrong_thread_and_depth_overflow_fence_the_same_account_without_refund() {
    for overflow in [false, true] {
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        let handle = operation.checkpoint_handle();
        let error = if overflow {
            operation.live.state.lock().unwrap().node_owner_scopes = u32::MAX;
            handle.prevent_refill_wait_while_node_owned().err().unwrap()
        } else {
            thread::spawn(move || handle.prevent_refill_wait_while_node_owned().map(|_| ()))
                .join()
                .unwrap()
                .unwrap_err()
        };
        assert_eq!(error.to_string(), "PUBLIC_MUTATION_CPU_UNAVAILABLE");
        let observed = domain.observe().unwrap();
        assert!(observed.accounting_unavailable);
        assert_eq!(observed.in_flight, 1);
        assert!(operation.finish().accounting_unavailable);
        assert!(domain.begin().is_err());
    }
}

#[test]
fn guard_unwind_restores_nesting_but_cannot_forgive_a_lost_scope() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    let handle = operation.checkpoint_handle();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = handle.prevent_refill_wait_while_node_owned().unwrap();
        panic!("injected owner-scope unwind");
    }));
    assert!(result.is_err());
    assert_eq!(operation.live.state.lock().unwrap().node_owner_scopes, 0);
    assert!(domain.accounting_available());
    let held = handle.prevent_refill_wait_while_node_owned().unwrap();
    operation.live.state.lock().unwrap().node_owner_scopes = 0;
    drop(held);
    assert!(!domain.accounting_available());
    assert!(operation.finish().accounting_unavailable);
}

#[test]
fn settlement_cannot_certify_an_owner_scope_that_has_not_closed() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    let held = operation
        .checkpoint_handle()
        .prevent_refill_wait_while_node_owned()
        .unwrap();
    assert!(operation.finish().accounting_unavailable);
    drop(held);
    assert!(!domain.accounting_available());
}
