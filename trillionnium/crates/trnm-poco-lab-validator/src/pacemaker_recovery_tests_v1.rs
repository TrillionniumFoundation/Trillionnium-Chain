#[test]
fn reconstructed_timer_cannot_consume_another_owners_expiry() {
    let now = Instant::now();
    let mut old = GenerationAwarePacemakerV0::new(Duration::from_millis(100), MAX_TIMEOUT).unwrap();
    let mut new = GenerationAwarePacemakerV0::new(Duration::from_millis(100), MAX_TIMEOUT).unwrap();
    let a = old.arm(Epoch::new(0), View::new(5), now).unwrap();
    let b = new.arm(Epoch::new(0), View::new(5), now).unwrap();
    assert_eq!(
        a.get(),
        b.get(),
        "same diagnostic sequence is not same owner"
    );
    assert_ne!(a, b);
    let stale = old.poll(now + Duration::from_millis(100)).unwrap();
    let fresh = new.poll(now + Duration::from_millis(100)).unwrap();
    assert!(!new.validate_generation(stale.epoch(), stale.view(), stale.generation()));
    assert!(new.confirm_timeout_emitted(stale).is_err());
    assert_eq!(new.consecutive_timeouts(), 0);
    new.confirm_timeout_emitted(fresh).unwrap();
    assert_eq!(new.consecutive_timeouts(), 1);
}

#[test]
fn rejected_generation_exhaustion_preserves_active_timer() {
    let now = Instant::now();
    let mut timer =
        GenerationAwarePacemakerV0::new(Duration::from_millis(100), MAX_TIMEOUT).unwrap();
    let original = timer.arm(Epoch::new(0), View::new(1), now).unwrap();
    timer.next_generation = MAX_GENERATION;
    assert!(timer.arm(Epoch::new(0), View::new(2), now).is_err());
    assert_eq!(timer.next_generation, MAX_GENERATION);
    assert!(timer.validate_generation(Epoch::new(0), View::new(1), original));
    assert_eq!(
        timer
            .poll(now + Duration::from_millis(100))
            .unwrap()
            .generation(),
        original
    );
}

#[test]
fn equal_sequences_are_distinct_across_concurrent_timer_owners() {
    let handles: Vec<_> = (0..32)
        .map(|_| {
            std::thread::spawn(|| {
                let mut timer =
                    GenerationAwarePacemakerV0::new(Duration::from_millis(100), MAX_TIMEOUT)
                        .unwrap();
                timer
                    .arm(Epoch::new(0), View::new(1), Instant::now())
                    .unwrap()
            })
        })
        .collect();
    let values: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    for (index, value) in values.iter().enumerate() {
        assert_eq!(value.get(), 1);
        assert!(values[..index].iter().all(|prior| prior != value));
    }
}

#[test]
fn rejected_deadline_overflow_does_not_burn_generation_or_replace_timer() {
    let now = Instant::now();
    let mut timer = GenerationAwarePacemakerV0::new(Duration::from_secs(10), MAX_TIMEOUT).unwrap();
    let original = timer.arm(Epoch::new(0), View::new(1), now).unwrap();
    let next = timer.next_generation;
    // Find the actual platform's representable upper Instant, without sleeping
    // or relying on wall-clock timestamps. This crate's target is Unix.
    let (mut low, mut high) = (0u64, u64::MAX);
    assert!(now.checked_add(Duration::from_secs(high)).is_none());
    while high - low > 1 {
        let middle = low + (high - low) / 2;
        if now.checked_add(Duration::from_secs(middle)).is_some() {
            low = middle;
        } else {
            high = middle;
        }
    }
    let boundary = now.checked_add(Duration::from_secs(low)).unwrap();
    assert!(timer.arm(Epoch::new(0), View::new(2), boundary).is_err());
    assert_eq!(timer.next_generation, next);
    assert!(timer.validate_generation(Epoch::new(0), View::new(1), original));
    assert_eq!(
        timer
            .poll(now + Duration::from_secs(10))
            .unwrap()
            .generation(),
        original
    );
}
