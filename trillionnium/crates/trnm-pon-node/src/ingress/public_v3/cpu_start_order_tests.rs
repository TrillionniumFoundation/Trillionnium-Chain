use super::super::{MUTATION_CPU_BURST_NS, MUTATION_CPU_START_RESERVE_NS};
use super::*;

fn account() -> Arc<Mutex<PaidMutationCpuBudget>> {
    let mut budget = PaidMutationCpuBudget::new();
    budget.updated = Instant::now() + std::time::Duration::from_secs(60);
    Arc::new(Mutex::new(budget))
}
fn flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}
fn register(account: &Arc<Mutex<PaidMutationCpuBudget>>) -> PendingCpuStart {
    PendingCpuStart::register(
        account.clone(),
        Instant::now() + std::time::Duration::from_secs(30),
        flag(),
        flag(),
    )
    .unwrap()
}

#[test]
fn shared_start_order_refuses_overtaking_and_unqueued_owner_without_new_credit() {
    let shared = account();
    let mut first = register(&shared);
    let mut second = register(&shared);
    let now = Instant::now();
    let mut budget = shared.lock().unwrap();
    for _ in 0..32 {
        assert!(!second.is_head(&mut budget, now).unwrap());
        assert!(first.is_head(&mut budget, now).unwrap());
    }
    let before = (budget.credit_ns, budget.in_flight, budget.updated);
    assert_eq!(
        second.reserve(&mut budget, now).unwrap_err().to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    assert_eq!(
        budget.reserve(now).unwrap_err().to_string(),
        "PUBLIC_MUTATION_CPU_BUDGET"
    );
    assert_eq!((budget.credit_ns, budget.in_flight, budget.updated), before);
    first.reserve(&mut budget, now).unwrap();
    assert!(second.is_head(&mut budget, now).unwrap());
    assert_eq!(budget.in_flight, 1);
    second.reserve(&mut budget, now).unwrap();
    assert_eq!(budget.in_flight, 2);
    assert_eq!(
        budget.credit_ns,
        i128::from(MUTATION_CPU_BURST_NS - 2 * MUTATION_CPU_START_RESERVE_NS)
    );
    assert!(budget.cpu_starts.slots.iter().all(Option::is_none));
    assert_eq!(
        first.reserve(&mut budget, now).unwrap_err().to_string(),
        "PUBLIC_PENDING_ORDER"
    );
    assert_eq!(budget.in_flight, 2);
}

#[test]
fn pending_start_drop_releases_only_metadata_and_does_not_reorder_survivors() {
    let shared = account();
    let first = register(&shared);
    let second = register(&shared);
    let third = register(&shared);
    let before = {
        let budget = shared.lock().unwrap();
        (budget.credit_ns, budget.in_flight, budget.updated)
    };
    drop(second);
    let fourth = register(&shared);
    assert!(fourth.sequence > third.sequence);
    {
        let mut budget = shared.lock().unwrap();
        assert!(first.is_head(&mut budget, Instant::now()).unwrap());
        assert!(!third.is_head(&mut budget, Instant::now()).unwrap());
        assert!(!fourth.is_head(&mut budget, Instant::now()).unwrap());
        assert_eq!((budget.credit_ns, budget.in_flight, budget.updated), before);
    }
    drop(first);
    let mut budget = shared.lock().unwrap();
    assert!(third.is_head(&mut budget, Instant::now()).unwrap());
    assert_eq!((budget.credit_ns, budget.in_flight, budget.updated), before);
}

#[test]
fn other_waiter_retires_cancel_stop_or_deadline_without_reviving_old_order() {
    for reason in 0..3 {
        let shared = account();
        let stop = flag();
        let cancelled = flag();
        let now = Instant::now();
        let old = PendingCpuStart::register(
            shared.clone(),
            now + std::time::Duration::from_secs(10),
            stop.clone(),
            cancelled.clone(),
        )
        .unwrap();
        let next = PendingCpuStart::register(
            shared.clone(),
            now + std::time::Duration::from_secs(60),
            flag(),
            flag(),
        )
        .unwrap();
        if reason == 0 {
            cancelled.store(true, Ordering::Release);
        } else if reason == 1 {
            stop.store(true, Ordering::Release);
        }
        let observed = if reason == 2 {
            now + std::time::Duration::from_secs(11)
        } else {
            now
        };
        let mut budget = shared.lock().unwrap();
        let before = (budget.credit_ns, budget.in_flight, budget.updated);
        assert!(next.is_head(&mut budget, observed).unwrap());
        stop.store(false, Ordering::Release);
        cancelled.store(false, Ordering::Release);
        assert_eq!(
            old.is_head(&mut budget, now).unwrap_err().to_string(),
            "PUBLIC_PENDING_ORDER"
        );
        assert_eq!((budget.credit_ns, budget.in_flight, budget.updated), before);
    }
}

#[test]
fn shared_start_slots_and_sequence_are_finite_and_never_reset() {
    let shared = account();
    let held: Vec<_> = (0..CAPACITY).map(|_| register(&shared)).collect();
    assert_eq!(CAPACITY, super::super::super::MAX_MUTATING_GRANTS);
    let failure = PendingCpuStart::register(
        shared.clone(),
        Instant::now() + std::time::Duration::from_secs(30),
        flag(),
        flag(),
    )
    .err()
    .unwrap();
    assert_eq!(failure.to_string(), "PUBLIC_QUEUE_BUSY");
    let last = held.last().unwrap().sequence;
    drop(held);
    let later = register(&shared);
    assert!(later.sequence > last);
    drop(later);
    {
        let mut budget = shared.lock().unwrap();
        budget.cpu_starts.next = u64::MAX;
    }
    let failure = PendingCpuStart::register(
        shared.clone(),
        Instant::now() + std::time::Duration::from_secs(30),
        flag(),
        flag(),
    )
    .err()
    .unwrap();
    assert_eq!(failure.to_string(), "PUBLIC_PENDING_ORDER");
    let budget = shared.lock().unwrap();
    assert_eq!(budget.cpu_starts.next, u64::MAX);
    assert!(budget.cpu_starts.slots.iter().all(Option::is_none));
    assert_eq!(budget.in_flight, 0);
    assert_eq!(budget.credit_ns, i128::from(MUTATION_CPU_BURST_NS));
    assert!(!budget.unavailable);
}

#[test]
fn same_sequence_from_another_account_cannot_claim_or_release_a_turn() {
    let first = account();
    let other = account();
    let mut a = register(&first);
    let b = register(&other);
    assert_eq!(a.sequence, b.sequence);
    {
        let mut foreign = other.lock().unwrap();
        let before = (foreign.credit_ns, foreign.in_flight);
        assert_eq!(
            a.is_head(&mut foreign, Instant::now())
                .unwrap_err()
                .to_string(),
            "PUBLIC_PENDING_ORDER"
        );
        assert_eq!(
            a.reserve(&mut foreign, Instant::now())
                .unwrap_err()
                .to_string(),
            "PUBLIC_PENDING_ORDER"
        );
        assert_eq!((foreign.credit_ns, foreign.in_flight), before);
    }
    drop(a);
    let mut foreign = other.lock().unwrap();
    assert!(b.is_head(&mut foreign, Instant::now()).unwrap());
}
