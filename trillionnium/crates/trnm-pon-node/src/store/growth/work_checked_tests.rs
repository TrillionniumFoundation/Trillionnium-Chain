//! Real W1, signed transitions and SQLite rejection fences for service adapters.
//! No listener, mock success, alternate owner or new wire profile is installed.
use super::*;

fn checked(packet: &GrowthPacket) -> GrowthWorkCheckedPacket {
    GrowthWorkCheckedPacket::verify_with_progress(packet.clone(), &|_| Ok(())).unwrap()
}

#[test]
fn native_growth_v2_checked_work_rebinds_after_releasing_the_original_owner() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let owner = Mutex::new(
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap(),
    );
    let packet = {
        let node = owner.lock().unwrap();
        let packet = make(
            &node,
            settings.genesis(),
            vec![transfer(&settings, 0, 1, public(81), 1000)],
        );
        assert_eq!(
            node.precheck_growth_admission_with_progress(&packet, 100_000, &|_| Ok(()))
                .unwrap(),
            None
        );
        packet
    };
    let before = rows(&owner.lock().unwrap().db);
    let replay_seen = AtomicBool::new(false);
    let work = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                GrowthWorkCheckedPacket::verify_with_progress(packet.clone(), &|point| {
                    if point == GrowthProgress::Work(pon_work::VerificationProgress::BeforeReplay) {
                        // Actual full W1 starts on another thread with no Node lock.
                        let node = owner
                            .try_lock()
                            .expect("work must release the original owner");
                        assert_eq!(node.active().unwrap(), (settings.genesis(), 0));
                        replay_seen.store(true, Ordering::Relaxed);
                    }
                    Ok(())
                })
            })
            .join()
            .unwrap()
            .unwrap()
    });
    assert!(replay_seen.load(Ordering::Relaxed));
    let mut node = owner.lock().unwrap();
    assert_eq!(rows(&node.db), before);
    // A heavier valid branch arrives while the verified packet has no owner.
    let first = make(&node, settings.genesis(), vec![]);
    let first_id = admit(&mut node, &first);
    let second = make(&node, first_id, vec![]);
    let fork = admit(&mut node, &second);
    let active = node.active().unwrap();
    let id = node
        .admit_growth_work_checked_with_progress(work, 100_000, &|point| {
            assert!(
                !matches!(point, GrowthProgress::Work(_)),
                "W1 replayed twice"
            );
            Ok(())
        })
        .unwrap();
    assert_eq!(id, packet.id().unwrap());
    assert_eq!(
        node.active().unwrap(),
        active,
        "admission must not activate"
    );
    assert_eq!(node.activate(id).unwrap(), fork);
    assert!(node.growth_account(fork, public(81)).unwrap().is_none());
    let observation = node.growth_exact_packet_observation(&packet).unwrap();
    assert_eq!(observation["stored_exact"], true);
    assert_eq!(observation["active_chain_member"], false);
    assert!(observation["accepted_task"].is_null());
}

#[test]
fn native_growth_v2_checked_work_cannot_reuse_clock_context_or_parent_state() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let mut packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(82), 1000)],
    );
    packet.header.ledger.timestamp = 5000;
    reseal(&mut packet);
    node.precheck_growth_admission_with_progress(&packet, 100_000, &|_| Ok(()))
        .unwrap();
    let before = rows(&node.db);
    let error = node
        .admit_growth_work_checked_with_progress(checked(&packet), 1, &|_| Ok(()))
        .unwrap_err();
    assert_eq!(error.to_string(), "TIME_DEFERRED");
    assert_eq!(rows(&node.db), before);

    let other_dir = tempfile::tempdir().unwrap();
    let other_settings = base_settings()
        .with_permanent_account_growth_v2("checked-work-wrong-context")
        .unwrap();
    let mut other =
        Node::open_with_permanent_account_growth_v2(other_dir.path(), other_settings).unwrap();
    let other_before = rows(&other.db);
    assert_eq!(
        other
            .admit_growth_work_checked_with_progress(checked(&packet), 100_000, &|_| Ok(()))
            .unwrap_err()
            .to_string(),
        "NETWORK"
    );
    assert_eq!(rows(&other.db), other_before);

    let work = checked(&packet);
    let parent_root = node.record(settings.genesis()).unwrap().root;
    // Same-connection fault deliberately does not change PRAGMA data_version.
    // The consumed token must still authenticate the actual original parent.
    node.db
        .execute(
            "UPDATE blocks SET state_root=zeroblob(32) WHERE id=?",
            [settings.genesis().as_slice()],
        )
        .unwrap();
    let expected = node
        .growth_observe(settings.genesis())
        .unwrap_err()
        .to_string();
    let corrupt = rows(&node.db);
    assert_eq!(
        node.admit_growth_work_checked_with_progress(work, 100_000, &|_| Ok(()))
            .unwrap_err()
            .to_string(),
        expected
    );
    assert_eq!(rows(&node.db), corrupt);
    assert!(node.growth_packet(packet.id().unwrap()).is_err());
    node.db
        .execute(
            "UPDATE blocks SET state_root=? WHERE id=?",
            params![parent_root.as_slice(), settings.genesis().as_slice()],
        )
        .unwrap();
    assert_eq!(rows(&node.db), before);
    let id = node
        .admit_growth_work_checked_with_progress(checked(&packet), 100_000, &|_| Ok(()))
        .unwrap();
    assert_eq!(id, packet.id().unwrap());
}

#[test]
fn native_growth_v2_checked_work_refuses_foreign_sql_epoch_before_admission() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(&node, settings.genesis(), vec![]);
    let work = checked(&packet);
    let foreign = Connection::open(dir.path().join("native.sqlite")).unwrap();
    foreign
        .execute("UPDATE active SET generation=generation+1", [])
        .unwrap();
    let corrupt = rows(&node.db);
    assert_eq!(
        node.admit_growth_work_checked_with_progress(work, 100_000, &|_| Ok(()))
            .unwrap_err()
            .to_string(),
        "GROWTH_STORAGE_EPOCH_CHANGED"
    );
    assert_eq!(rows(&node.db), corrupt);
    assert!(node.db.is_autocommit());
}

#[test]
fn native_growth_v2_checked_work_cancellation_never_commits_partial_state() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(83), 1000)],
    );
    let before = rows(&node.db);
    for cut in [
        GrowthProgress::BeforeContext,
        GrowthProgress::ParentProof(multiproof::MultiproofProgress::Account { index: 0 }),
        GrowthProgress::BeforeCommit,
    ] {
        let reached = AtomicBool::new(false);
        let error = node
            .admit_growth_work_checked_with_progress(checked(&packet), 100_000, &|point| {
                assert!(
                    !reached.load(Ordering::Relaxed),
                    "progress after cancellation"
                );
                if point == cut {
                    reached.store(true, Ordering::Relaxed);
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(reached.load(Ordering::Relaxed));
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert_eq!(rows(&node.db), before);
        assert!(node.db.is_autocommit());
    }
    admit(&mut node, &packet);
}

#[test]
fn native_growth_v2_controlled_exact_observation_cancels_without_sql_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let first = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(84), 1000)],
    );
    let first_id = admit(&mut node, &first);
    let packet = make(&node, first_id, vec![]);
    let id = admit(&mut node, &packet);
    let third = make(&node, id, vec![]);
    admit(&mut node, &third);
    let before = rows(&node.db);
    let changes = node.db.total_changes();
    let expected = node.growth_exact_packet_observation(&packet).unwrap();
    for cut in [
        GrowthProgress::BeforeObservation,
        GrowthProgress::BeforeContext,
        GrowthProgress::HeaderAncestor { index: 0 },
        GrowthProgress::Work(pon_work::VerificationProgress::BeforeVerifiedWork),
        GrowthProgress::ParentProof(multiproof::MultiproofProgress::Account { index: 0 }),
        GrowthProgress::CommitmentProof(multiproof::MultiproofProgress::BeforeOutput),
        GrowthProgress::FinalSuccessorProof(multiproof::MultiproofProgress::BeforeOutput),
        GrowthProgress::ObservationDelta,
        GrowthProgress::MembershipRead { index: 1 },
        GrowthProgress::BeforeObservationTask,
        GrowthProgress::ObservationReady,
    ] {
        let reached = AtomicBool::new(false);
        let error = node
            .growth_exact_packet_observation_with_progress(&packet, &|point| {
                assert!(
                    !reached.load(Ordering::Relaxed),
                    "progress after cancellation"
                );
                if point == cut {
                    reached.store(true, Ordering::Relaxed);
                    Err(Error::new(ErrorCode::PublicRequestCancelled))
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert!(reached.load(Ordering::Relaxed), "{cut:?}");
        assert!(error.is(ErrorCode::PublicRequestCancelled));
        assert!(node.db.is_autocommit());
        assert_eq!(node.db.total_changes(), changes);
        assert_eq!(rows(&node.db), before);
    }
    let error = node
        .growth_exact_packet_observation_with_progress(&packet, &|point| {
            if point == GrowthProgress::ObservationReady {
                Err(Error::new(ErrorCode::PublicMutationCpuBudget))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
    assert!(error.is(ErrorCode::PublicMutationCpuBudget));
    assert!(node.db.is_autocommit());
    assert_eq!(
        node.growth_exact_packet_observation(&packet).unwrap(),
        expected
    );
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(rows(&node.db), before);
}

#[cfg(target_os = "linux")]
#[test]
fn native_growth_v2_controlled_exact_observation_uses_original_service_cpu_domain() {
    use crate::ingress::public_v3::ServiceMutationCpuDomain;
    let dir = tempfile::tempdir().unwrap();
    let settings = settings();
    let mut node =
        Node::open_with_permanent_account_growth_v2(dir.path(), settings.clone()).unwrap();
    let packet = make(
        &node,
        settings.genesis(),
        vec![transfer(&settings, 0, 1, public(85), 1000)],
    );
    admit(&mut node, &packet);
    let cpu = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&cpu).unwrap();
    let original = node.public_service_cpu_domain().unwrap();
    assert!(cpu.shares_domain_with(&original));
    let operation = original.begin().unwrap();
    let before = rows(&node.db);
    let changes = node.db.total_changes();
    let result =
        node.growth_exact_packet_observation_with_progress(&packet, &|_| operation.checkpoint());
    let settled = operation.finish();
    assert_eq!(result.unwrap()["active_chain_member"], true);
    assert!(!settled.accounting_unavailable);
    assert!(settled.total_cpu_ns.is_some_and(|ns| ns > 0));
    assert_eq!(settled.total_cpu_ns, settled.owner_cpu_ns);
    assert_eq!(settled.scoped_worker_cpu_ns, Some(0));
    assert_eq!(settled.spawned_workers, 0);
    assert_eq!(
        settled.live_paid_cpu_ns.unwrap() + settled.residual_cpu_ns.unwrap(),
        settled.total_cpu_ns.unwrap()
    );
    assert_eq!(node.db.total_changes(), changes);
    assert_eq!(rows(&node.db), before);
    assert!(node.db.is_autocommit());
}
