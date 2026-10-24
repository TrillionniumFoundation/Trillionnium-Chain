use super::*;
use std::sync::{mpsc, Arc, Barrier};
use std::thread;
use std::time::Instant;
fn fixture(seed: u8) -> (Hash, Hash, Vec<u8>) {
    let a: Vec<u32> = (0..CELLS).map(|i| (i % 31) as u32).collect();
    let b: Vec<u32> = (0..CELLS).map(|i| (i % 23) as u32).collect();
    let c = [seed; 32];
    (c, task_id(&a, &b).unwrap(), prove(c, &a, &b).unwrap())
}
fn changed_product(bytes: &[u8], i: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let at = 4 + 8 * CELLS + i * 4;
    let old = u32::from_le_bytes(out[at..at + 4].try_into().unwrap());
    out[at..at + 4].copy_from_slice(&(((u64::from(old) + 1) % Q as u64) as u32).to_le_bytes());
    out
}
#[test]
fn one_success_avoids_three_full_product_replays() {
    let (c, t, p) = fixture(43);
    let cache = WorkFactCache::new(4).unwrap();
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    for i in [0, CELLS / 2, CELLS - 1] {
        assert!(matches!(
            cache.verify(c, t, [255; 32], &changed_product(&p, i)),
            Err(FactError::Relation(WorkError::Product))
        ));
    }
    let observed = cache.counters();
    println!(
        "W1_FACT_OBSERVATION proofs=4 invalid_accepted=0 full_replays={} hits={}",
        observed.full_replays, observed.hits
    );
    assert_eq!(observed.full_replays, 1);
    assert_eq!(observed.hits, 3);
}
#[test]
fn invalid_first_never_poisoned_the_later_valid_statement() {
    let (c, t, p) = fixture(44);
    let cache = WorkFactCache::new(1).unwrap();
    assert!(matches!(
        cache.verify(c, t, [255; 32], &changed_product(&p, 0)),
        Err(FactError::Relation(WorkError::Product))
    ));
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    assert_eq!(cache.counters().full_replays, 2);
}
#[test]
fn warm_fact_rechecks_current_target_task_and_canonical_fields() {
    let (c, t, p) = fixture(45);
    let cache = WorkFactCache::new(1).unwrap();
    let work = cache.verify(c, t, [255; 32], &p).unwrap();
    assert!(cache.verify(c, t, work.ticket(), &p).is_ok());
    let mut lower = work.ticket();
    for i in (0..32).rev() {
        if lower[i] > 0 {
            lower[i] -= 1;
            break;
        }
        lower[i] = 255;
    }
    assert!(matches!(
        cache.verify(c, t, lower, &p),
        Err(FactError::Relation(WorkError::Target))
    ));
    assert!(matches!(
        cache.verify(c, [0; 32], [255; 32], &p),
        Err(FactError::Relation(WorkError::Task))
    ));
    let mut bad = p.clone();
    bad[4 + 8 * CELLS..8 + 8 * CELLS].copy_from_slice(&(Q as u32).to_le_bytes());
    assert!(matches!(
        cache.verify(c, [0; 32], [255; 32], &bad),
        Err(FactError::Relation(WorkError::Field))
    ));
    assert!(matches!(
        cache.verify(c, t, [0; 32], &bad),
        Err(FactError::Relation(WorkError::Target))
    ));
    assert!(matches!(
        cache.verify(c, t, [255; 32], &p[..p.len() - 1]),
        Err(FactError::Relation(WorkError::Length))
    ));
    assert_eq!(cache.counters().full_replays, 1);
}
#[test]
fn differential_dense_zero_identity_rank_one_and_mutations() {
    let mut cases = 0;
    for shape in 0..4 {
        let a: Vec<u32> = (0..CELLS)
            .map(|i| match shape {
                0 => (i % 31) as u32,
                1 => 0,
                2 => u32::from(i / N == i % N),
                _ => ((i / N + 1) * (i % N + 1)) as u32,
            })
            .collect();
        let b: Vec<u32> = (0..CELLS)
            .map(|i| if shape == 1 { 0 } else { (i % 23) as u32 })
            .collect();
        let task = task_id(&a, &b).unwrap();
        for seed in [51, 52] {
            let c = [seed; 32];
            let p = prove(c, &a, &b).unwrap();
            let cache = WorkFactCache::new(2).unwrap();
            let mut variants = vec![
                p.clone(),
                changed_product(&p, 0),
                changed_product(&p, CELLS / 2),
                changed_product(&p, CELLS - 1),
            ];
            let mut trace = p.clone();
            *trace.last_mut().unwrap() ^= 1;
            variants.push(trace);
            let mut field = p.clone();
            field[4..8].copy_from_slice(&(Q as u32).to_le_bytes());
            variants.push(field);
            let mut magic = p.clone();
            magic[0] = 0;
            variants.push(magic);
            variants.push(p[..p.len() - 1].to_vec());
            for v in variants {
                let reference = verify_reference(c, task, [255; 32], &v)
                    .map(|w| (w.challenge, w.task, w.ticket, w.product));
                let reused = cache
                    .verify(c, task, [255; 32], &v)
                    .map(|w| (w.challenge, w.task, w.ticket, w.product));
                match (reference, reused) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b),
                    (Err(a), Err(FactError::Relation(b))) => assert_eq!(a, b),
                    other => panic!("differential mismatch {other:?}"),
                }
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 64);
    println!("W1_FACT_DIFFERENTIAL cases={cases} mismatches=0");
}
#[test]
fn no_negative_cache_and_no_cross_challenge_reuse() {
    let (c, t, p) = fixture(46);
    let cache = WorkFactCache::new(1).unwrap();
    let mut fake = p.clone();
    *fake.last_mut().unwrap() ^= 1;
    for _ in 0..2 {
        assert!(matches!(
            cache.verify(c, t, [255; 32], &fake),
            Err(FactError::Relation(WorkError::Transcript))
        ));
    }
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    assert!(matches!(
        cache.verify([77; 32], t, [255; 32], &p),
        Err(FactError::Relation(WorkError::Transcript))
    ));
    assert_eq!(cache.counters().full_replays, 4);
}
#[test]
fn capacity_eviction_and_new_owner_are_explicit() {
    assert!(WorkFactCache::new(0).is_err());
    assert!(WorkFactCache::new(MAX_FACT_SLOTS + 1).is_err());
    let cache = WorkFactCache::new(1).unwrap();
    let (c, t, p) = fixture(47);
    cache.verify(c, t, [255; 32], &p).unwrap();
    let (c2, t2, p2) = fixture(48);
    cache.verify(c2, t2, [255; 32], &p2).unwrap();
    cache.verify(c, t, [255; 32], &p).unwrap();
    assert_eq!(cache.capacity(), 1);
    assert_eq!(cache.counters().full_replays, 3);
    assert_eq!(cache.counters().evictions, 2);
    let reopened = WorkFactCache::new(1).unwrap();
    reopened.verify(c, t, [255; 32], &p).unwrap();
    assert_eq!(reopened.counters().full_replays, 1);
}
#[test]
fn returned_product_does_not_mutate_retained_fact() {
    let (c, t, p) = fixture(49);
    let cache = WorkFactCache::new(1).unwrap();
    let mut first = cache.verify(c, t, [255; 32], &p).unwrap();
    let original = first.product.clone();
    first.product[0] ^= 1;
    assert_eq!(cache.verify(c, t, [255; 32], &p).unwrap().product, original);
}
#[test]
fn concurrent_identical_statements_have_one_leader() {
    let (c, t, p) = fixture(60);
    let cache = Arc::new(WorkFactCache::new(1).unwrap());
    let barrier = Arc::new(Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let cache = cache.clone();
            let barrier = barrier.clone();
            let p = p.clone();
            thread::spawn(move || {
                barrier.wait();
                cache
                    .verify_with_progress(c, t, [255; 32], &p, &mut |point| {
                        if matches!(
                            point,
                            VerificationProgress::Noise {
                                label: 0,
                                counter: 0
                            }
                        ) {
                            thread::sleep(Duration::from_millis(25));
                        }
                        Ok::<_, ()>(())
                    })
                    .unwrap()
                    .product
            })
        })
        .collect();
    let products: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(products.iter().all(|p| p == &products[0]));
    assert_eq!(cache.counters().full_replays, 1);
    assert_eq!(cache.counters().hits, 7);
    assert!(cache.counters().wait_polls > 0);
}
#[test]
fn waiter_cancels_without_cancelling_the_leader() {
    let (c, t, p) = fixture(61);
    let cache = Arc::new(WorkFactCache::new(1).unwrap());
    let (started_tx, started_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let leader_cache = cache.clone();
    let leader_p = p.clone();
    let leader = thread::spawn(move || {
        leader_cache.verify_with_progress(c, t, [255; 32], &leader_p, &mut |point| {
            if matches!(
                point,
                VerificationProgress::Noise {
                    label: 0,
                    counter: 0
                }
            ) {
                started_tx.send(()).unwrap();
                go_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            Ok::<_, &str>(())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let mut calls = 0;
    let result = cache.verify_with_progress(c, t, [255; 32], &p, &mut |_| {
        calls += 1;
        if calls >= 2 {
            Err("waiter-cancel")
        } else {
            Ok(())
        }
    });
    go_tx.send(()).unwrap();
    assert!(leader.join().unwrap().is_ok());
    assert!(matches!(result, Err(FactError::Cancelled("waiter-cancel"))));
    assert_eq!(cache.counters().full_replays, 1);
}
#[test]
fn cancelled_leader_wakes_waiter_for_its_own_complete_verification() {
    let (c, t, p) = fixture(62);
    let cache = Arc::new(WorkFactCache::new(1).unwrap());
    let (started_tx, started_rx) = mpsc::channel();
    let (go_tx, go_rx) = mpsc::channel();
    let x = cache.clone();
    let bytes = p.clone();
    let leader = thread::spawn(move || {
        x.verify_with_progress(c, t, [255; 32], &bytes, &mut |point| {
            if matches!(
                point,
                VerificationProgress::Noise {
                    label: 0,
                    counter: 0
                }
            ) {
                started_tx.send(()).unwrap();
                go_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                return Err("leader-cancel");
            }
            Ok(())
        })
    });
    started_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let x = cache.clone();
    let waiter = thread::spawn(move || x.verify(c, t, [255; 32], &p));
    let until = Instant::now() + Duration::from_secs(2);
    while cache.counters().wait_polls == 0 && Instant::now() < until {
        thread::yield_now();
    }
    go_tx.send(()).unwrap();
    assert!(matches!(
        leader.join().unwrap(),
        Err(FactError::Cancelled("leader-cancel"))
    ));
    assert!(waiter.join().unwrap().is_ok());
    assert_eq!(cache.counters().full_replays, 2);
}
#[test]
fn unwind_does_not_leave_a_computing_slot() {
    let (c, t, p) = fixture(63);
    let cache = WorkFactCache::new(1).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = cache.verify_with_progress(c, t, [255; 32], &p, &mut |point| {
            if point == VerificationProgress::BeforeProduct {
                panic!("injected producer unwind");
            }
            Ok::<_, ()>(())
        });
    }));
    assert!(result.is_err());
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    assert_eq!(cache.counters().full_replays, 2);
}
#[test]
fn warm_final_cancel_does_not_return_authority_or_destroy_math() {
    let (c, t, p) = fixture(64);
    let cache = WorkFactCache::new(1).unwrap();
    cache.verify(c, t, [255; 32], &p).unwrap();
    assert!(matches!(
        cache.verify_with_progress(c, t, [255; 32], &p, &mut |point| if point
            == VerificationProgress::BeforeVerifiedWork
        {
            Err("cancel-final")
        } else {
            Ok(())
        }),
        Err(FactError::Cancelled("cancel-final"))
    ));
    assert!(cache.verify(c, t, [255; 32], &p).is_ok());
    assert_eq!(cache.counters().full_replays, 1);
}
#[test]
fn poisoned_local_slot_is_unavailable_not_invalid_work_or_fallback() {
    let cache = Arc::new(WorkFactCache::new(1).unwrap());
    let x = cache.clone();
    assert!(thread::spawn(move || {
        let _guard = x.slots[0].state.lock().unwrap();
        panic!("injected lock poison");
    })
    .join()
    .is_err());
    let (c, t, p) = fixture(65);
    assert!(matches!(
        cache.verify(c, t, [255; 32], &p),
        Err(FactError::Unavailable)
    ));
    assert_eq!(cache.counters().full_replays, 0);
}
