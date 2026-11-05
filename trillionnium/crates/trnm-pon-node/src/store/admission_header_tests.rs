//! Actual public header preflight uses its caller's original resource owner.
//! No complete W1, State, activation or independent confirmation is skipped.
use super::*;
use crate::{ErrorCode, ErrorKind};

fn open(path: &Path, settings: &Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings.clone(), 1).unwrap()
    } else {
        Node::open(path, settings.clone(), 1).unwrap()
    }
}

fn make(node: &Node, parent: Hash, height: u64) -> Packet {
    node.make(
        parent,
        vec![],
        development_public(0).unwrap(),
        1 + 10 * height,
        4096,
    )
    .unwrap()
}

fn chain(node: &mut Node, count: u64) -> Vec<Hash> {
    let mut ids = vec![node.settings.genesis()];
    for height in 1..=count {
        let packet = make(node, *ids.last().unwrap(), height);
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate_observed(id, 100_000).unwrap();
        ids.push(id);
    }
    ids
}

#[test]
fn admission_header_public_precheck_honors_each_original_cancellation() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(dir.path(), &settings, authenticated);
        let ids = chain(&mut node, 3);
        let packet = make(&node, ids[3], 4);
        let before = node.stats().unwrap();
        let state = node.read_active().unwrap();
        let mut complete_calls = 0;
        assert!(node
            .precheck_public_admission_context_with_progress(&packet, 100_000, &mut |point| {
                assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                complete_calls += 1;
                Ok(())
            })
            .unwrap()
            .is_none());
        // Entry, batch start, each of three real rows, and the final fence.
        assert_eq!(complete_calls, 6);
        for code in [
            ErrorCode::PublicRequestCancelled,
            ErrorCode::PublicRequestDeadline,
            ErrorCode::PublicMutationCpuBudget,
        ] {
            for cut in 1..=complete_calls {
                let mut calls = 0;
                let error = node
                    .precheck_public_admission_context_with_progress(
                        &packet,
                        100_000,
                        &mut |point| {
                            assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                            calls += 1;
                            if calls == cut {
                                Err(Error::new(code))
                            } else {
                                Ok(())
                            }
                        },
                    )
                    .unwrap_err();
                assert!(error.is(code));
                assert_ne!(error.kind(), ErrorKind::ProtocolInvalid);
                assert!(!error.requires_owner_stop());
                assert_eq!(calls, cut);
                assert!(node.db.is_autocommit());
                assert_eq!(node.stats().unwrap(), before);
                assert_eq!(node.read_active().unwrap(), state);
            }
        }
        // Retrying starts a fresh context check and receives no prior verdict.
        let id = node.admit(&packet, 100_000).unwrap();
        node.activate_observed(id, 100_000).unwrap();
        let final_state = node.read_active().unwrap();
        drop(node);
        assert_eq!(
            open(dir.path(), &settings, authenticated)
                .read_active()
                .unwrap(),
            final_state
        );
    }
}

#[test]
fn admission_header_target_and_time_share_only_one_current_window() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(dir.path(), &settings, authenticated);
        let ids = chain(&mut node, 20);
        let packet = make(&node, ids[20], 21);
        let expected_target = node.expected_target(ids[20]).unwrap();
        let times: Vec<_> = node
            .recent(ids[20])
            .unwrap()
            .iter()
            .take(11)
            .map(|p| p.0)
            .collect();
        assert_eq!(packet.header.target, expected_target);
        for timestamp in [0, 1, 110, packet.header.timestamp, 200_001] {
            let mut changed = packet.clone();
            changed.header.timestamp = timestamp;
            // Check the original clock relation separately from proof binding.
            let expected = consensus::check_time(
                timestamp,
                &times,
                100_000,
                settings.limit("future_skew_seconds").unwrap(),
            );
            let result = node.precheck_public_admission_context_with_progress(
                &changed,
                100_000,
                &mut |_| Ok(()),
            );
            if let Err(error) = expected {
                assert_eq!(result.unwrap_err().to_string(), error.to_string());
            }
        }
        let before = node.history_read_counters();
        assert!(node
            .precheck_public_admission_context_with_progress(&packet, 100_000, &mut |_| Ok(()))
            .unwrap()
            .is_none());
        let after = node.history_read_counters();
        let bound = settings.limit("retarget_interval").unwrap().clamp(11, 20);
        assert_eq!(
            after.header_link_queries - before.header_link_queries,
            bound.div_ceil(HISTORY_HEADER_BATCH)
        );
        let expected_bytes = bound * (settings.packet_header_length() as u64 + 32);
        assert_eq!(
            after.header_trace_bytes - before.header_trace_bytes,
            expected_bytes
        );
        // A valid earlier call does not retain the caller's clock permission.
        let deferred = node
            .precheck_public_admission_context_with_progress(&packet, 0, &mut |_| Ok(()))
            .unwrap_err();
        assert!(deferred.is(ErrorCode::TimeDeferred));
    }
}

#[test]
fn admission_header_epoch_change_never_becomes_consensus_invalid_or_success() {
    for authenticated in [false, true] {
        for duplicate in [false, true] {
            for foreign in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let settings = Settings::development(Some(1)).unwrap();
                let mut node = open(dir.path(), &settings, authenticated);
                let ids = chain(&mut node, 3);
                let packet = if duplicate {
                    node.packet(ids[3]).unwrap()
                } else {
                    make(&node, ids[3], 4)
                };
                let expected = if duplicate { Some(ids[3]) } else { None };
                let mut total = 0;
                assert_eq!(
                    node.precheck_public_admission_context_with_progress(
                        &packet,
                        100_000,
                        &mut |point| {
                            assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                            total += 1;
                            Ok(())
                        }
                    )
                    .unwrap(),
                    expected
                );
                let before = node.stats().unwrap();
                let parent = packet.header.parent;
                let old_height = node.record(parent).unwrap().height;
                let writer = Connection::open(dir.path().join("native.sqlite")).unwrap();
                // Exercise entry, batch start, every real row and the final
                // fence. An entry write would otherwise return HEIGHT before
                // the successful-path fence; a late write could return success.
                for cut in 1..=total {
                    let mut calls = 0;
                    let changes = node.db.total_changes();
                    let error = node
                        .precheck_public_admission_context_with_progress(
                            &packet,
                            100_000,
                            &mut |point| {
                                assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                                calls += 1;
                                if calls == cut {
                                    let db = if foreign { &writer } else { &node.db };
                                    assert_eq!(
                                        db.execute(
                                            "UPDATE blocks SET height=height+1 WHERE id=?",
                                            [parent.as_slice()],
                                        )?,
                                        1
                                    );
                                }
                                Ok(())
                            },
                        )
                        .unwrap_err();
                    assert!(calls >= cut);
                    assert!(error.is(ErrorCode::AdmissionHeaderEpochChanged));
                    assert_eq!(error.kind(), ErrorKind::StaleContext);
                    assert!(!error.requires_owner_stop());
                    assert_eq!(node.db.total_changes() - changes, u64::from(!foreign));
                    assert_eq!(node.record(parent).unwrap().height, old_height + 1);
                    writer
                        .execute(
                            "UPDATE blocks SET height=? WHERE id=?",
                            params![old_height, parent.as_slice()],
                        )
                        .unwrap();
                    assert_eq!(node.stats().unwrap(), before);
                    assert!(node.db.is_autocommit());
                    assert_eq!(
                        node.precheck_public_admission_context_with_progress(
                            &packet,
                            100_000,
                            &mut |_| Ok(())
                        )
                        .unwrap(),
                        expected
                    );
                }
            }
        }
    }
}

#[test]
fn admission_header_epoch_change_keeps_original_resource_refusal() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(dir.path(), &settings, authenticated);
        let ids = chain(&mut node, 3);
        let packet = make(&node, ids[3], 4);
        let before = node.stats().unwrap();
        let writer = Connection::open(dir.path().join("native.sqlite")).unwrap();
        for foreign in [false, true] {
            for code in [
                ErrorCode::PublicRequestCancelled,
                ErrorCode::PublicRequestDeadline,
                ErrorCode::PublicMutationCpuBudget,
            ] {
                for cut in 1..=6 {
                    let mut calls = 0;
                    let error = node
                        .precheck_public_admission_context_with_progress(
                            &packet,
                            100_000,
                            &mut |point| {
                                assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                                calls += 1;
                                if calls == cut {
                                    let db = if foreign { &writer } else { &node.db };
                                    db.execute(
                                        "UPDATE blocks SET height=height+1 WHERE id=?",
                                        [ids[3].as_slice()],
                                    )?;
                                    return Err(Error::new(code));
                                }
                                Ok(())
                            },
                        )
                        .unwrap_err();
                    assert!(error.is(code));
                    assert_ne!(error.kind(), ErrorKind::ProtocolInvalid);
                    assert!(!error.requires_owner_stop());
                    assert_eq!(calls, cut);
                    writer
                        .execute("UPDATE blocks SET height=3 WHERE id=?", [ids[3].as_slice()])
                        .unwrap();
                    assert_eq!(node.stats().unwrap(), before);
                }
            }
        }
        assert!(node
            .precheck_public_admission_context_with_progress(&packet, 100_000, &mut |_| Ok(()))
            .unwrap()
            .is_none());
    }
}

#[test]
fn admission_header_checks_do_not_replace_or_close_callers_transaction() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(dir.path(), &settings, authenticated);
        let ids = chain(&mut node, 3);
        let packet = make(&node, ids[3], 4);
        let before = node.stats().unwrap();
        let tx = rusqlite::Transaction::new_unchecked(
            &node.db,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let epoch = node.admission_state_epoch().unwrap();
        let owner = trnm_sqlite_io_boundary::TransactionScope::capture(&tx).unwrap();
        let mut calls = 0;
        assert!(node
            .precheck_public_admission_context_with_progress(&packet, 100_000, &mut |point| {
                assert_eq!(point, ExecutionProgress::BeforeHeaderContext);
                assert!(!node.db.is_autocommit());
                calls += 1;
                Ok(())
            })
            .unwrap()
            .is_none());
        assert_eq!(calls, 6);
        let error = node
            .precheck_public_admission_context_with_progress(&packet, 100_000, &mut |_| {
                Err(Error::new(ErrorCode::PublicRequestCancelled))
            })
            .unwrap_err();
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert!(node.admission_state_epoch().unwrap() == epoch);
        assert!(owner.same_write_snapshot(&tx).unwrap());
        assert!(!node.db.is_autocommit());
        tx.rollback().unwrap();
        assert!(node.db.is_autocommit());
        assert_eq!(node.stats().unwrap(), before);
    }
}
