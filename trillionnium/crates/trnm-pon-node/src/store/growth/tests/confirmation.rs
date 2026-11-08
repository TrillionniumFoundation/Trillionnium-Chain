//! Actual PNP2 admission into an independent native receiver, then confirmation.
use super::*;

#[test]
fn growth_confirmation_reaches_independent_native_receiver_and_cold_reopen() {
    let producer_dir = tempfile::tempdir().unwrap();
    let receiver_dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut producer =
        Node::open_with_permanent_account_growth_v2(producer_dir.path(), settings.clone()).unwrap();
    let transaction = transfer(&settings, 0, 1, public(100), 1000);
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut tip = settings.genesis();
    let mut packets = Vec::new();
    for height in 1..=7 {
        let packet = make(
            &producer,
            tip,
            if height == 1 {
                vec![transaction.clone()]
            } else {
                vec![]
            },
        );
        tip = producer.admit_growth(&packet, 100_000).unwrap();
        packets.push(packet);
    }
    let mut receiver =
        Node::open_with_permanent_account_growth_v2(receiver_dir.path(), settings.clone()).unwrap();
    for packet in &packets {
        let id = receiver.admit_growth(packet, 100_000).unwrap();
        receiver.activate(id).unwrap();
    }
    let included = packets[0].id().unwrap();
    let before = rows(&receiver.db);
    let result = receiver
        .confirmation(transaction_id, included, 100_000)
        .unwrap();
    assert!(result.confirmed);
    assert_eq!(result.depth, Some(6));
    assert!(!result.reorged && !result.finalized && !result.execution_authority);
    assert_eq!(rows(&receiver.db), before);
    drop(receiver);
    let reopened =
        Node::open_with_permanent_account_growth_v2(receiver_dir.path(), settings).unwrap();
    let after = reopened
        .confirmation(transaction_id, included, 100_000)
        .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(after).unwrap()
    );
    assert_eq!(rows(&reopened.db), before);
}

fn confirmed_growth_fixture(
    two_transactions: bool,
) -> (tempfile::TempDir, Settings, Node, Hash, Vec<Hash>) {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let mut transactions = vec![transfer(&settings, 0, 1, public(100), 1000)];
    if two_transactions {
        transactions.push(transfer(&settings, 1, 1, public(101), 1000));
    }
    let ids = transactions
        .iter()
        .map(|raw| hash(b"tx-id", &[raw]))
        .collect();
    let packet = make(&node, settings.genesis(), transactions);
    let included = admit(&mut node, &packet);
    let mut tip = included;
    for _ in 0..6 {
        let packet = make(&node, tip, vec![]);
        tip = admit(&mut node, &packet);
    }
    (dir, settings, node, included, ids)
}

#[test]
fn growth_confirmation_batch_shares_body_and_rejects_missing_or_duplicate_membership() {
    let (_dir, settings, node, included, ids) = confirmed_growth_fixture(true);
    let before = rows(&node.db);
    let queries = [(ids[0], included), (ids[1], included)];
    let bodies = AtomicUsize::new(0);
    let batch = node
        .growth_confirmations_with_progress(&queries, 100_000, &|point| {
            if let GrowthProgress::ConfirmationBody { index } = point {
                assert_eq!(index, bodies.fetch_add(1, Ordering::SeqCst));
            }
            Ok(())
        })
        .unwrap();
    assert_eq!(bodies.load(Ordering::SeqCst), 1);
    assert_eq!(batch.distinct_bodies_checked, 1);
    assert_eq!(batch.ancestry_checked, 7);
    assert_eq!(batch.observations.len(), 2);
    assert!(batch.observations.iter().all(|result| result.confirmed
        && result.depth == Some(6)
        && !result.finalized
        && !result.execution_authority));
    assert_eq!(
        node.confirmations(&[], 100_000).unwrap_err().to_string(),
        "CONFIRMATION_LIMIT"
    );
    assert_eq!(
        node.confirmations(&[queries[0]; 257], 100_000)
            .unwrap_err()
            .to_string(),
        "CONFIRMATION_LIMIT"
    );
    assert_eq!(
        node.confirmations(&[queries[0], queries[0]], 100_000)
            .unwrap_err()
            .to_string(),
        "DUPLICATE_QUERY"
    );
    assert_eq!(
        node.confirmations(&[queries[0], ([99; 32], included)], 100_000)
            .unwrap_err()
            .to_string(),
        "MEMBERSHIP"
    );
    assert_eq!(
        node.confirmation(ids[0], settings.genesis(), 100_000)
            .unwrap_err()
            .to_string(),
        "GENESIS_HAS_NO_PACKET"
    );
    assert_eq!(
        node.confirmations_with_progress(&queries, 100_000, &mut |_| Ok(()))
            .unwrap_err()
            .to_string(),
        "GROWTH_USE_CONFIRMATION_PROGRESS"
    );
    assert_eq!(rows(&node.db), before);
    assert!(node.db.is_autocommit());
}

#[test]
fn growth_confirmation_cancellation_keeps_native_work_execution_and_snapshot_boundaries() {
    let (_dir, _settings, node, included, ids) = confirmed_growth_fixture(false);
    let before = rows(&node.db);
    for stage in ["entry", "work", "execution", "ancestry", "terminal"] {
        let reached = AtomicBool::new(false);
        let error = node
            .growth_confirmations_with_progress(&[(ids[0], included)], 100_000, &|point| {
                let stop = matches!(
                    (stage, point),
                    ("entry", GrowthProgress::BeforeObservation)
                        | ("work", GrowthProgress::Work(_))
                        | ("execution", GrowthProgress::Execution(_))
                        | (
                            "ancestry",
                            GrowthProgress::ConfirmationAncestor { index: 3 }
                        )
                        | ("terminal", GrowthProgress::ObservationReady)
                );
                if stop {
                    reached.store(true, Ordering::SeqCst);
                    Err("CONFIRMATION_CANCELLED".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(
            reached.load(Ordering::SeqCst),
            "missing real {stage} checkpoint"
        );
        assert_eq!(error.to_string(), "CONFIRMATION_CANCELLED", "{stage}");
        assert!(node.db.is_autocommit(), "{stage} retained its snapshot");
        assert_eq!(rows(&node.db), before, "{stage} wrote native state");
    }
    assert!(
        node.confirmation(ids[0], included, 100_000)
            .unwrap()
            .confirmed
    );
}

#[test]
fn growth_confirmation_rechecks_future_ancestor_even_when_tip_and_old_clock_pass() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let transaction = transfer(&settings, 0, 1, public(100), 1000);
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut tip = settings.genesis();
    let mut included = tip;
    for height in 1..=15 {
        let timestamp = match height {
            13 => 1000,
            14 => 122,
            15 => 123,
            _ => 1 + height * 10,
        };
        let packet = node
            .make_growth_consensus_maintenance(
                tip,
                if height == 1 {
                    vec![transaction.clone()]
                } else {
                    vec![]
                },
                public(3),
                timestamp,
                4096,
            )
            .unwrap();
        tip = node.admit_growth(&packet, 2000).unwrap();
        if height == 1 {
            included = tip;
        }
    }
    assert_eq!(
        node.growth_packet(tip).unwrap().header.ledger.timestamp,
        123
    );
    let before = rows(&node.db);
    assert_eq!(
        node.activate_observed(tip, 200).unwrap_err().to_string(),
        "TIME_DEFERRED"
    );
    assert_eq!(rows(&node.db), before);
    assert_eq!(node.activate_observed(tip, 2000).unwrap(), tip);
    assert!(
        node.confirmation(transaction_id, included, 2000)
            .unwrap()
            .confirmed
    );
    let before = rows(&node.db);
    for observed_now in [200, 879] {
        assert_eq!(
            node.check_observed_history(tip, observed_now)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        assert_eq!(
            node.activate_observed(tip, observed_now)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        assert_eq!(
            node.confirmation(transaction_id, included, observed_now)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
    }
    // Inclusive future-skew boundary, not merely a much later successful clock.
    assert!(
        node.confirmation(transaction_id, included, 880)
            .unwrap()
            .confirmed
    );
    assert_eq!(rows(&node.db), before);
    drop(node);
    let reopened = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(
        reopened
            .confirmation(transaction_id, included, 879)
            .unwrap_err()
            .to_string(),
        "TIME_DEFERRED"
    );
    assert!(
        reopened
            .confirmation(transaction_id, included, 880)
            .unwrap()
            .confirmed
    );
}

#[test]
fn growth_confirmation_uses_required_work_after_legal_difficulty_decrease() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let transaction = transfer(&settings, 0, 1, public(100), 1000);
    let transaction_id = hash(b"tx-id", &[&transaction]);
    let mut tip = settings.genesis();
    let mut included = tip;
    let mut included_work = None;
    for height in 1..=37 {
        let timestamp = if height <= 15 {
            1 + height
        } else if height <= 31 {
            161 + (height - 16) * 40
        } else {
            761 + (height - 31) * 10
        };
        let packet = node
            .make_growth_consensus_maintenance(
                tip,
                if height == 31 {
                    vec![transaction.clone()]
                } else {
                    vec![]
                },
                public(3),
                timestamp,
                4096,
            )
            .unwrap();
        tip = node.admit_growth(&packet, 100_000).unwrap();
        node.activate_observed(tip, 100_000).unwrap();
        if height == 31 {
            included = tip;
            included_work = Some(consensus::required_work(packet.header.ledger.target).unwrap());
        }
    }
    let result = node
        .confirmation(transaction_id, included, 100_000)
        .unwrap();
    assert_eq!(result.depth, Some(6));
    assert!(!result.confirmed && !result.reorged);
    assert_eq!(
        result.required_work_delta,
        hex::encode(included_work.unwrap().mul_small(6).unwrap().bytes())
    );
    let delta = node
        .record(tip)
        .unwrap()
        .work
        .checked_sub(node.record(included).unwrap().work)
        .unwrap();
    assert_eq!(result.work_delta, Some(hex::encode(delta.bytes())));
    assert!(delta < included_work.unwrap().mul_small(6).unwrap());
    assert!(!result.finalized && !result.execution_authority);
}

#[test]
fn growth_confirmation_tracks_actual_reorg_and_re_adoption_without_rewriting_history() {
    let (dir, settings, mut node, included, ids) = confirmed_growth_fixture(false);
    let original_tip = node.active().unwrap().0;
    let mut fork = settings.genesis();
    for _ in 0..8 {
        let height = node.record(fork).unwrap().height + 1;
        let packet = node
            .make_growth_consensus_maintenance(fork, vec![], public(4), 1 + height * 10, 4096)
            .unwrap();
        fork = node.admit_growth(&packet, 100_000).unwrap();
    }
    assert_eq!(node.activate_observed(fork, 100_000).unwrap(), fork);
    let before = rows(&node.db);
    let result = node.confirmation(ids[0], included, 100_000).unwrap();
    assert!(result.reorged && !result.confirmed);
    assert_eq!(result.depth, None);
    assert_eq!(result.work_delta, None);
    assert_eq!(rows(&node.db), before);
    let mut restored = original_tip;
    for _ in 0..2 {
        let packet = make(&node, restored, vec![]);
        restored = node.admit_growth(&packet, 100_000).unwrap();
    }
    assert_eq!(node.activate_observed(restored, 100_000).unwrap(), restored);
    let confirmed = node.confirmation(ids[0], included, 100_000).unwrap();
    assert!(confirmed.confirmed && !confirmed.reorged);
    assert_eq!(confirmed.depth, Some(8));
    let before = rows(&node.db);
    drop(node);
    let reopened = Node::open_with_permanent_account_growth_v2(dir.path(), settings).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.confirmation(ids[0], included, 100_000).unwrap()).unwrap(),
        serde_json::to_value(confirmed).unwrap()
    );
    assert_eq!(rows(&reopened.db), before);
}

#[test]
fn growth_confirmation_replays_included_work_even_with_unchanged_header_and_trace() {
    let (_dir, _settings, node, included, ids) = confirmed_growth_fixture(false);
    let original = node.growth_packet(included).unwrap();
    let raw = original.encode().unwrap();
    let mut changed = original.clone();
    let at = changed.proof.len() - 33;
    changed.proof[at] ^= 1;
    assert_eq!(changed.id().unwrap(), included);
    node.db
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![changed.encode().unwrap(), included.as_slice()],
        )
        .unwrap();
    let before = rows(&node.db);
    let error = node.confirmation(ids[0], included, 100_000).unwrap_err();
    assert!(error.to_string().starts_with("WORK:"), "{error}");
    assert_eq!(rows(&node.db), before);
    assert!(node.db.is_autocommit());
    node.db
        .execute(
            "UPDATE blocks SET packet=? WHERE id=?",
            params![raw, included.as_slice()],
        )
        .unwrap();
    assert!(
        node.confirmation(ids[0], included, 100_000)
            .unwrap()
            .confirmed
    );
}

#[test]
fn growth_confirmation_refuses_foreign_wal_commits_hidden_inside_the_read_snapshot() {
    let (dir, settings, mut node, included, ids) = confirmed_growth_fixture(false);
    for stage in ["entry", "ancestry", "terminal"] {
        let before = rows(&node.db);
        let fired = AtomicBool::new(false);
        let database = dir.path().join("native.sqlite");
        let error = node
            .growth_confirmations_with_progress(&[(ids[0], included)], 100_000, &|point| {
                let trigger = matches!(
                    (stage, point),
                    ("entry", GrowthProgress::BeforeObservation)
                        | (
                            "ancestry",
                            GrowthProgress::ConfirmationAncestor { index: 0 }
                        )
                        | ("terminal", GrowthProgress::ObservationReady)
                );
                if trigger && !fired.swap(true, Ordering::SeqCst) {
                    let foreign = Connection::open(&database).unwrap();
                    // Two actual foreign commits restore original row values.
                    // A stable snapshot cannot make their storage epoch current.
                    foreign
                        .execute(
                            "UPDATE blocks SET height=height+1 WHERE id=?",
                            [included.as_slice()],
                        )
                        .unwrap();
                    foreign
                        .execute(
                            "UPDATE blocks SET height=height-1 WHERE id=?",
                            [included.as_slice()],
                        )
                        .unwrap();
                }
                Ok(())
            })
            .unwrap_err();
        assert!(fired.load(Ordering::SeqCst), "missing {stage} callback");
        assert_eq!(error.to_string(), "GROWTH_STORAGE_EPOCH_CHANGED", "{stage}");
        assert!(error.requires_owner_stop());
        assert!(node.db.is_autocommit());
        assert_eq!(rows(&node.db), before);
        drop(node);
        node = Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
        assert!(
            node.confirmation(ids[0], included, 100_000)
                .unwrap()
                .confirmed
        );
    }
}
