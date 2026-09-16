#[test]
fn continuously_nonempty_ingress_yields_after_exact_budget() {
    let mut calls = 0;
    let total = MAX_INGRESS_EVENTS_PER_TURN_V1 * 3;
    let progressed = drain_ingress_turn_v1(|| {
        calls += 1;
        if calls > total {
            Ok(None)
        } else {
            Ok(Some(true))
        }
    })
    .unwrap();
    assert!(progressed);
    assert_eq!(calls, MAX_INGRESS_EVENTS_PER_TURN_V1);
}

#[test]
fn no_op_ingress_cannot_starve_timers_by_avoiding_progress_counts() {
    let mut calls = 0;
    assert!(!drain_ingress_turn_v1(|| {
        calls += 1;
        Ok(Some(false))
    })
    .unwrap());
    assert_eq!(calls, MAX_INGRESS_EVENTS_PER_TURN_V1);
}

#[test]
fn bounded_ingress_preserves_tail_and_canonical_order() {
    let mut queue: VecDeque<_> = (0..(MAX_INGRESS_EVENTS_PER_TURN_V1 * 2 + 1)).collect();
    let mut consumed = Vec::new();
    drain_ingress_turn_v1(|| {
        Ok(queue.pop_front().map(|index| {
            consumed.push(index);
            true
        }))
    })
    .unwrap();
    assert_eq!(
        consumed,
        (0..MAX_INGRESS_EVENTS_PER_TURN_V1).collect::<Vec<_>>()
    );
    assert_eq!(queue.front(), Some(&MAX_INGRESS_EVENTS_PER_TURN_V1));
    drain_ingress_turn_v1(|| {
        Ok(queue.pop_front().map(|index| {
            consumed.push(index);
            false
        }))
    })
    .unwrap();
    assert_eq!(
        consumed,
        (0..(MAX_INGRESS_EVENTS_PER_TURN_V1 * 2)).collect::<Vec<_>>()
    );
    assert_eq!(queue.len(), 1);
}

#[test]
fn ingress_error_preserves_unread_tail_and_does_not_report_success() {
    let mut queue = VecDeque::from([0, 1, 2, 3]);
    let result = drain_ingress_turn_v1(|| {
        let index = queue.pop_front().unwrap();
        if index == 1 {
            bail!("retained handler failure")
        }
        Ok(Some(true))
    });
    assert!(result.is_err());
    assert_eq!(queue, VecDeque::from([2, 3]));
}

#[test]
fn empty_ingress_is_read_once_without_manufacturing_progress() {
    let mut reads = 0;
    assert!(!drain_ingress_turn_v1(|| {
        reads += 1;
        Ok(None)
    })
    .unwrap());
    assert_eq!(reads, 1);
}
