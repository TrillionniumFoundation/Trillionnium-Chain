//! Retain the original request control through pre-persistence materialization.
//! These are real signed native admission controls, not public SLO acceptance.
use super::*;
use std::sync::Arc;

fn is_materialization(point: GrowthProgress) -> bool {
    matches!(
        point,
        GrowthProgress::WorkingCopy { .. }
            | GrowthProgress::WitnessAccount { .. }
            | GrowthProgress::DeltaComparison { .. }
            | GrowthProgress::BeforeDeltaEncoding
            | GrowthProgress::AfterDeltaEncoding
    )
}

#[test]
fn native_growth_v2_materialization_controls_preserve_state_and_original_errors() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(86), 1_000)],
    );
    let before = rows(&node.db);
    let active = node.active().unwrap();
    let changes = node.db.total_changes();
    let parent = node.growth_parent(settings.genesis()).unwrap();
    let observed = Mutex::new(Vec::new());
    let executed = execute(&settings, &parent, &packet, &|point| {
        if is_materialization(point) {
            observed.lock().unwrap().push(point);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(executed.state.commitment.id, packet.header.ledger.state);
    assert_eq!(
        sequence_root("receipts", &executed.receipts),
        packet.header.ledger.receipts
    );
    let points = observed.into_inner().unwrap();
    let working_len = parent.source.stored.working.len();
    let proof_len = packet.accounts.accounts.len();
    assert!(working_len > 1);
    assert!(proof_len > 1);
    assert!(points.contains(&GrowthProgress::WorkingCopy { index: working_len }));
    assert!(points.contains(&GrowthProgress::WitnessAccount { index: proof_len }));
    assert!(points.contains(&GrowthProgress::DeltaComparison { index: 1 }));
    let last_delta = points
        .iter()
        .rev()
        .find(|point| matches!(point, GrowthProgress::DeltaComparison { .. }))
        .copied()
        .unwrap();
    let cuts = [
        GrowthProgress::WorkingCopy { index: 0 },
        GrowthProgress::WorkingCopy { index: 1 },
        GrowthProgress::WorkingCopy { index: working_len },
        GrowthProgress::WitnessAccount { index: 0 },
        GrowthProgress::WitnessAccount { index: proof_len },
        GrowthProgress::DeltaComparison { index: 0 },
        GrowthProgress::DeltaComparison { index: 1 },
        last_delta,
        GrowthProgress::BeforeDeltaEncoding,
        GrowthProgress::AfterDeltaEncoding,
    ];
    for cut in cuts {
        assert!(points.contains(&cut), "unreached control {cut:?}");
        for failure in 0..3 {
            let hit = AtomicBool::new(false);
            let identity = Arc::new(());
            let error = node
                .admit_growth_with_progress(&packet, 100_000, &|point| {
                    assert!(!hit.load(Ordering::Relaxed), "continued after {cut:?}");
                    if point != cut {
                        return Ok(());
                    }
                    hit.store(true, Ordering::Relaxed);
                    match failure {
                        0 => Err(Error::new(ErrorCode::PublicRequestCancelled)),
                        1 => Err(Error::new(ErrorCode::PublicMutationCpuBudget)),
                        _ => Err(Error::from(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            ProofControlSource(identity.clone()),
                        ))),
                    }
                })
                .expect_err("cancelled materialization reached admission");
            assert!(hit.load(Ordering::Relaxed), "missed {cut:?}");
            match failure {
                0 => assert!(error.is(ErrorCode::PublicRequestCancelled)),
                1 => assert!(error.is(ErrorCode::PublicMutationCpuBudget)),
                _ => {
                    let source = std::error::Error::source(&error)
                        .unwrap()
                        .downcast_ref::<std::io::Error>()
                        .unwrap()
                        .get_ref()
                        .unwrap()
                        .downcast_ref::<ProofControlSource>()
                        .unwrap();
                    assert!(Arc::ptr_eq(&identity, &source.0));
                }
            }
            assert!(node.db.is_autocommit());
            assert_eq!(node.db.total_changes(), changes);
            assert_eq!(node.active().unwrap(), active);
            assert_eq!(rows(&node.db), before);
            assert!(node.growth_packet(packet.id().unwrap()).is_err());
        }
    }
    let id = admit(&mut node, &packet);
    let expected = rows(&node.db);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 2);
    assert_eq!(
        node.growth_account(id, public(86))
            .unwrap()
            .unwrap()
            .balance,
        1_000
    );
    drop(node);
    let node = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(node.active().unwrap().0, id);
    assert_eq!(node.next_nonce(public(0)).unwrap(), 2);
    assert_eq!(rows(&node.db), expected);
}
