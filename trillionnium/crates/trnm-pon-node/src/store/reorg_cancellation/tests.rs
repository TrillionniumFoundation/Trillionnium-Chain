use super::*;
use crate::ingress::public_v3::{
    scalar_cpu::REORG_TERMINATION_RESERVE_NS, ServiceMutationCpuDomain,
};
use std::{sync::Mutex, time::Instant};

fn fixture(path: &Path, authenticated: bool) -> (Node, Packet, Packet) {
    let settings = Settings::development(Some(1_700_000_000)).unwrap();
    let mut node = if authenticated {
        Node::open_with_authenticated_state(path, settings.clone(), 2).unwrap()
    } else {
        Node::open(path, settings.clone(), 2).unwrap()
    };
    let left = node
        .make(
            settings.genesis(),
            vec![],
            development_public(0).unwrap(),
            1_700_000_010,
            4096,
        )
        .unwrap();
    let left_id = node.admit(&left, 1_700_000_100).unwrap();
    node.activate(left_id).unwrap();
    let right = node
        .make(
            settings.genesis(),
            vec![],
            development_public(1).unwrap(),
            1_700_000_011,
            4096,
        )
        .unwrap();
    let right_id = node.admit(&right, 1_700_000_100).unwrap();
    let target = node
        .make(
            right_id,
            vec![],
            development_public(1).unwrap(),
            1_700_000_021,
            4096,
        )
        .unwrap();
    node.admit(&target, 1_700_000_100).unwrap();
    let honest = node
        .make(
            left_id,
            vec![],
            development_public(2).unwrap(),
            1_700_000_022,
            4096,
        )
        .unwrap();
    (node, target, honest)
}

fn row(node: &Node) -> (u64, u64, Option<u64>, String) {
    node.db.query_row(
        "SELECT reorg.done,reorg_lifecycle_v1.outcome,reorg_lifecycle_v1.cancelled_cursor,reorg_lifecycle_v1.reason FROM reorg,reorg_lifecycle_v1 ORDER BY operation DESC LIMIT 1",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
    ).unwrap()
}

fn lifecycle_bytes(node: &Node) -> Vec<u8> {
    lifecycle_db_bytes(&node.db)
}

fn lifecycle_db_bytes(db: &Connection) -> Vec<u8> {
    type Row = (
        i64,
        Vec<u8>,
        Vec<u8>,
        u64,
        u64,
        Vec<u8>,
        Vec<u8>,
        u64,
        Option<u64>,
        String,
    );
    let records: Vec<Row> = db.prepare(
        "SELECT operation,old_tip,new_tip,generation,old_slot,old_root,owner_context,outcome,cancelled_cursor,reason FROM reorg_lifecycle_v1 ORDER BY operation",
    ).unwrap().query_map([], |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?,r.get(9)?)))
        .unwrap().collect::<std::result::Result<_,_>>().unwrap();
    serde_json::to_vec(&records).unwrap()
}

#[test]
fn cancellation_terminates_only_staging_and_preserves_full_active_state() {
    for authenticated in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, target, honest) = fixture(dir.path(), authenticated);
        let before = node.read_active().unwrap();
        let blocks: u64 = node
            .db
            .query_row("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
            .unwrap();
        let error = node
            .activate_with_fault_and_progress(
                target.id().unwrap(),
                Some(&mut |point| {
                    if point == "intent" {
                        return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
                    }
                    Ok(())
                }),
                &mut || Ok(()),
                None,
            )
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::LegacyRequestDeadline), "{error}");
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(row(&node), (2, 2, Some(0), "REQUEST_DEADLINE".into()));
        let lifecycle = lifecycle_bytes(&node);
        assert_eq!(
            node.db
                .query_row::<u64, _, _>("SELECT COUNT(*) FROM blocks", [], |r| r.get(0))
                .unwrap(),
            blocks
        );
        let id = node.admit(&honest, 1_700_000_100).unwrap();
        assert_eq!(node.activate(id).unwrap(), id);
        assert_eq!(lifecycle_bytes(&node), lifecycle);
        assert!(node.ready().is_ok());
        assert_eq!(
            node.packet(target.id().unwrap()).unwrap().encode().unwrap(),
            target.encode().unwrap()
        );
    }
}

#[test]
fn late_staging_cancellation_and_postcommit_control_cannot_rewrite_active_facts() {
    for stage in ["detach:0", "attach:1", "before-publish", "published"] {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, target, _) = fixture(dir.path(), false);
        let before = node.read_active().unwrap();
        let error = node
            .activate_with_fault_and_progress(
                target.id().unwrap(),
                Some(&mut |point| {
                    if point == stage {
                        Err(Error::new(crate::ErrorCode::LegacyRequestDeadline))
                    } else {
                        Ok(())
                    }
                }),
                &mut || Ok(()),
                None,
            )
            .unwrap_err();
        assert!(
            error.is(crate::ErrorCode::LegacyRequestDeadline),
            "{stage}: {error}"
        );
        if stage == "published" {
            assert_eq!(node.read_active().unwrap().0, target.id().unwrap());
            assert_eq!(row(&node), (1, 1, None, String::new()));
        } else {
            assert_eq!(node.read_active().unwrap(), before);
            let retained = row(&node);
            assert_eq!((retained.0, retained.1), (2, 2));
            assert!(retained.2.unwrap() > 0);
            assert_eq!(retained.3, "REQUEST_DEADLINE");
        }
    }
}

#[test]
fn foreign_sqlite_commit_cannot_use_a_stale_termination_reservation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let before = node.read_active().unwrap();
    let error = node
        .activate_with_fault_and_progress(
            target.id().unwrap(),
            Some(&mut |point| {
                if point == "intent" {
                    let foreign = Connection::open(dir.path().join("native.sqlite")).unwrap();
                    foreign
                        .execute(
                            "INSERT INTO metadata VALUES('foreign-durable-write',X'01')",
                            [],
                        )
                        .unwrap();
                    return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
                }
                Ok(())
            }),
            &mut || Ok(()),
            None,
        )
        .unwrap_err();
    assert!(error.requires_owner_stop());
    assert!(error.is(crate::ErrorCode::StorageContext));
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(row(&node), (0, 0, None, String::new()));
    node.db
        .execute_batch("CREATE TEMP TABLE restored_authorizer(value INTEGER)")
        .unwrap();
}

#[test]
fn repeated_aborts_reclaim_old_staging_only_in_the_next_native_intent_transaction() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, mut target, honest) = fixture(dir.path(), false);
    for round in 0..2 {
        let before = node.read_active().unwrap();
        let error = node
            .activate_with_fault_and_progress(
                target.id().unwrap(),
                Some(&mut |point| {
                    if point == "intent" {
                        Err(Error::new(crate::ErrorCode::LegacyRequestDeadline))
                    } else {
                        Ok(())
                    }
                }),
                &mut || Ok(()),
                None,
            )
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::LegacyRequestDeadline));
        assert_eq!(node.read_active().unwrap(), before);
        let slots: u64 = node
            .db
            .query_row("SELECT COUNT(DISTINCT slot) FROM kv", [], |r| r.get(0))
            .unwrap();
        assert_eq!(slots, 2);
        assert_eq!(
            node.db
                .query_row::<u64, _, _>(
                    "SELECT COUNT(*) FROM reorg_lifecycle_v1 WHERE outcome=2",
                    [],
                    |r| r.get(0)
                )
                .unwrap(),
            round + 1
        );
        if round == 0 {
            let id = node.admit(&honest, 1_700_000_100).unwrap();
            node.activate(id).unwrap();
            target = node
                .make(
                    target.id().unwrap(),
                    vec![],
                    development_public(1).unwrap(),
                    1_700_000_031,
                    4096,
                )
                .unwrap();
            node.admit(&target, 1_700_000_100).unwrap();
        }
    }
}

#[test]
fn cancelled_lifecycle_survives_explicit_authenticated_migration_without_rewriting_source() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(&dir.path().join("source"), false);
    let before = node.read_active().unwrap();
    let error = node
        .activate_with_fault_and_progress(
            target.id().unwrap(),
            Some(&mut |point| {
                if point == "intent" {
                    Err(Error::new(crate::ErrorCode::LegacyRequestDeadline))
                } else {
                    Ok(())
                }
            }),
            &mut || Ok(()),
            None,
        )
        .unwrap_err();
    assert!(error.is(crate::ErrorCode::LegacyRequestDeadline));
    let original = lifecycle_bytes(&node);
    let destination = dir.path().join("authenticated");
    let receipt = node.migrate_to_authenticated_state(&destination).unwrap();
    assert!(!receipt.pending_reorganization);
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(lifecycle_bytes(&node), original);
    let copy = Connection::open_with_flags(
        destination.join("native.sqlite"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    assert_eq!(lifecycle_db_bytes(&copy), original);
    drop(copy);
    let reopened =
        Node::open_with_authenticated_state(&destination, node.settings.clone(), 2).unwrap();
    assert_eq!(reopened.read_active().unwrap().0, target.id().unwrap());
    let retained: (u64, String) = reopened
        .db
        .query_row(
            "SELECT outcome,reason FROM reorg_lifecycle_v1 ORDER BY operation LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(retained, (2, "REQUEST_DEADLINE".into()));
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(lifecycle_bytes(&node), original);
}

#[test]
fn separate_history_snapshot_rechecks_the_cancelled_owner_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let active = node.read_active().unwrap().0;
    let genesis = node.settings.genesis();
    node.activate_with_fault_and_progress(
        target.id().unwrap(),
        Some(&mut |point| {
            if point == "intent" {
                Err(Error::new(crate::ErrorCode::LegacyRequestDeadline))
            } else {
                Ok(())
            }
        }),
        &mut || Ok(()),
        None,
    )
    .unwrap_err();
    let snapshot = node
        .prepare_public_history_snapshot(
            active,
            genesis,
            crate::ancestry_index::READ_SQL_BUDGET,
            &mut |_| Ok(()),
        )
        .unwrap();
    let read = snapshot.read(&mut |_| Ok(())).unwrap();
    node.finish_public_history_snapshot(read, &mut |_| Ok(()))
        .unwrap();
    node.db
        .execute(
            "UPDATE reorg_lifecycle_v1 SET owner_context=zeroblob(32)",
            [],
        )
        .unwrap();
    let error = node
        .prepare_public_history_snapshot(
            active,
            genesis,
            crate::ancestry_index::READ_SQL_BUDGET,
            &mut |_| Ok(()),
        )
        .err()
        .unwrap();
    assert!(error.is(crate::ErrorCode::ReorgLifecycle));
    assert!(node
        .ready()
        .unwrap_err()
        .is(crate::ErrorCode::ReorgLifecycle));
}

#[test]
fn paid_cancellation_reserves_headroom_and_settles_the_original_account_once() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let before = node.read_active().unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    let operation = domain.begin().unwrap();
    let checkpoint = operation.checkpoint_handle();
    let mut reserved = None;
    let error = node
        .activate_with_fault_and_progress(
            target.id().unwrap(),
            Some(&mut |point| {
                if point == "intent" {
                    let actual = domain.observe_actual_flow().unwrap().unwrap();
                    assert_eq!(actual.termination_reserved_ns, REORG_TERMINATION_RESERVE_NS);
                    assert_eq!(actual.live_owners, 1);
                    assert!(actual.balance_identity_verified);
                    reserved = Some(actual);
                    return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
                }
                Ok(())
            }),
            &mut || checkpoint.checkpoint(),
            Some(&checkpoint),
        )
        .unwrap_err();
    assert!(error.is(crate::ErrorCode::LegacyRequestDeadline), "{error}");
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(
        domain
            .observe_actual_flow()
            .unwrap()
            .unwrap()
            .termination_reserved_ns,
        0
    );
    let settled = operation.finish();
    assert!(!settled.accounting_unavailable);
    assert!(settled.total_cpu_ns.unwrap() > 0);
    let after = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(after.live_owners, 0);
    assert_eq!(after.termination_reserved_ns, 0);
    assert!(after.balance_identity_verified);
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&domain));
    println!(
        "{}",
        serde_json::json!({"schema":"native-reorg-same-account-termination-v1","at_intent":reserved,"settlement":settled,"after":after,"new_accounts":0,"active_state_unchanged":true})
    );
}

#[test]
fn paid_intent_rejects_missing_or_foreign_original_cpu_before_persisting() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let original = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&original).unwrap();
    assert!(node
        .activate(target.id().unwrap())
        .unwrap_err()
        .is(crate::ErrorCode::OwnerReorgTerminationCpuRequired));
    let foreign = ServiceMutationCpuDomain::standalone();
    let operation = foreign.begin().unwrap();
    let checkpoint = operation.checkpoint_handle();
    assert!(node
        .activate_observed_with_termination(
            target.id().unwrap(),
            1_700_000_100,
            &mut || Ok(()),
            Some(&checkpoint)
        )
        .unwrap_err()
        .is(crate::ErrorCode::OwnerPublicServiceCpuDomain));
    assert_eq!(
        node.db
            .query_row::<u64, _, _>("SELECT COUNT(*) FROM reorg_lifecycle_v1", [], |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(original.observe().unwrap().in_flight, 0);
    assert!(!operation.finish().accounting_unavailable);
}

#[test]
fn forgotten_termination_principal_cannot_be_reported_as_a_clean_cpu_close() {
    let domain = ServiceMutationCpuDomain::standalone();
    let operation = domain.begin().unwrap();
    let reserved = operation
        .checkpoint_handle()
        .reserve_reorg_termination()
        .unwrap();
    std::mem::forget(reserved);
    assert!(operation.finish().accounting_unavailable);
    assert!(domain.observe().unwrap().accounting_unavailable);
    assert!(domain.begin().is_err());
}

#[test]
fn cleanup_authorizer_blocks_trigger_writes_and_restores_after_error() {
    for table in ["active", "peer_request_audit", "metadata"] {
        let dir = tempfile::tempdir().unwrap();
        let (mut node, target, _) = fixture(dir.path(), false);
        let before = node.read_active().unwrap();
        let action = match table {
            "active" => "UPDATE active SET generation=generation+1",
            "peer_request_audit" => "DELETE FROM peer_request_audit",
            _ => "DELETE FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
        };
        node.db.execute_batch(&format!("CREATE TEMP TRIGGER attack_cleanup BEFORE UPDATE OF outcome ON reorg_lifecycle_v1 WHEN NEW.outcome=2 BEGIN {action}; END;")).unwrap();
        let error = node
            .activate_with_fault_and_progress(
                target.id().unwrap(),
                Some(&mut |point| {
                    if point == "intent" {
                        return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
                    }
                    Ok(())
                }),
                &mut || Ok(()),
                None,
            )
            .unwrap_err();
        assert!(error.requires_owner_stop(), "{table}: {error}");
        assert_eq!(node.read_active().unwrap(), before);
        assert_eq!(row(&node), (0, 0, None, String::new()));
        // DDL is forbidden by the cleanup authorizer: success proves restore.
        node.db
            .execute_batch(
                "DROP TRIGGER attack_cleanup; CREATE TEMP TABLE after_cleanup(value INTEGER);",
            )
            .unwrap();
        assert_eq!(
            node.db
                .query_row::<u64, _, _>("PRAGMA busy_timeout", [], |r| r.get(0))
                .unwrap(),
            5000
        );
    }
}

#[test]
fn cleanup_panic_rolls_back_and_restores_sql_guards_without_refunding_unknown_cpu() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let before = node.read_active().unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    let operation = domain.begin().unwrap();
    let checkpoint = operation.checkpoint_handle();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.activate_with_fault_and_progress(
            target.id().unwrap(),
            Some(&mut |point| {
                if point == "intent" {
                    return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
                }
                assert_ne!(
                    point, "cancel-lifecycle-written",
                    "actual cleanup panic before COMMIT"
                );
                Ok(())
            }),
            &mut || checkpoint.checkpoint(),
            Some(&checkpoint),
        )
    }));
    assert!(outcome.is_err());
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(row(&node), (0, 0, None, String::new()));
    assert!(domain.observe().unwrap().accounting_unavailable);
    node.db
        .execute_batch("CREATE TEMP TABLE after_panic(value INTEGER);")
        .unwrap();
    assert_eq!(
        node.db
            .query_row::<u64, _, _>("PRAGMA busy_timeout", [], |r| r.get(0))
            .unwrap(),
        5000
    );
    assert!(operation.finish().accounting_unavailable);
}

#[test]
fn old_schema_or_old_namespace_is_refused_without_automatic_migration() {
    for remove_table in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1_700_000_000)).unwrap();
        let node = Node::open(dir.path(), settings.clone(), 2).unwrap();
        let old_base = BASE_DDL
            .lines()
            .filter(|line| !line.starts_with("CREATE TABLE reorg_lifecycle_v1("))
            .collect::<Vec<_>>()
            .join("\n");
        let old_ddl = format!("{}{}", old_base, crate::ancestry_index::DDL);
        let old_id = hash(b"native-branch-schema-v2", &[old_ddl.as_bytes()]);
        assert_ne!(old_id, node.state_backend.schema_id());
        drop(node);
        let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
        if remove_table {
            db.execute_batch("DROP TABLE reorg_lifecycle_v1;").unwrap();
        }
        db.execute(
            "UPDATE metadata SET value=? WHERE key='schema'",
            [old_id.as_slice()],
        )
        .unwrap();
        drop(db);
        let error = Node::open(dir.path(), settings, 2)
            .err()
            .expect("old schema cannot activate");
        assert_eq!(
            error.to_string(),
            if remove_table {
                "SCHEMA"
            } else {
                "STORAGE_CONTEXT"
            }
        );
        let db = Connection::open(dir.path().join("native.sqlite")).unwrap();
        assert_eq!(
            db.query_row::<Vec<u8>, _, _>(
                "SELECT value FROM metadata WHERE key='schema'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            old_id
        );
    }
}

#[test]
#[ignore = "actual full W1 depletion; preserves all attempts and original account"]
fn actual_full_w1_depletion_terminates_intent_and_admits_an_independent_honest_mutation() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, honest) = fixture(dir.path(), false);
    let before = node.read_active().unwrap();
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    node.begin_ordinary_public_service_epoch().unwrap();
    let operation = domain.begin().unwrap();
    let checkpoint = operation.checkpoint_handle();
    let mut invalid = target.clone();
    // Last C word: the ordinary verifier traverses the whole matrix product
    // before this actual invalid-product verdict. No arithmetic debit is
    // substituted for the native proof-verification entry point.
    invalid.proof[4 + 3 * pon_work::CELLS * 4 - 4] ^= 1;
    assert_eq!(
        WorkCheckedPacket::verify(invalid.clone())
            .err()
            .unwrap()
            .to_string(),
        "WORK:Product"
    );
    let mut attacks = 0_u64;
    let mut attack_observations = Vec::new();
    let mut depleted = None;
    let end = Instant::now() + Duration::from_secs(30);
    let error = node
        .activate_with_fault_and_progress(
            target.id().unwrap(),
            Some(&mut |point| {
                if point != "intent" {
                    return Ok(());
                }
                loop {
                    assert!(
                        Instant::now() < end,
                        "actual budget did not deplete within declared 30s attempt"
                    );
                    if let Err(error) = checkpoint.checkpoint() {
                        assert!(
                            error.is(crate::ErrorCode::PublicMutationCpuBudget),
                            "{error}"
                        );
                        depleted = Some(domain.observe_actual_flow().unwrap().unwrap());
                        return Err(error);
                    }
                    let attempt_started = Instant::now();
                    let error = WorkCheckedPacket::verify(invalid.clone()).err().unwrap();
                    attack_observations.push(serde_json::json!({"ordinal":attacks,"wall_ns":attempt_started.elapsed().as_nanos(),"error":error.to_string()}));
                    assert_eq!(error.to_string(), "WORK:Product");
                    attacks += 1;
                }
            }),
            &mut || checkpoint.checkpoint(),
            Some(&checkpoint),
        )
        .unwrap_err();
    assert!(
        error.is(crate::ErrorCode::PublicMutationCpuBudget),
        "{error}"
    );
    assert_eq!(node.read_active().unwrap(), before);
    assert_eq!(row(&node).0, 2);
    let cpu = operation.finish();
    assert!(!cpu.accounting_unavailable);
    assert!(cpu.live_refused);
    let owner = Mutex::new(node);
    let honest_start = Instant::now();
    let honest_deadline = honest_start + Duration::from_secs(5);
    let mut reservation_attempts = 0_u64;
    let mut honest_attempt_observations = Vec::new();
    let result = loop {
        reservation_attempts += 1;
        let attempt_started = Instant::now();
        let outcome = crate::ingress::dispatch_shared_with_metered_w1(
            &owner,
            crate::ingress::Request::Submit {
                packet: hex::encode(honest.encode().unwrap()),
            },
            &domain,
            &|| ensure(Instant::now() < honest_deadline, "PUBLIC_REQUEST_DEADLINE"),
        );
        let attempt_finished = Instant::now();
        let (phase, native_success, error) = match &outcome {
            Ok(outcome) => (
                "native_finished",
                outcome.native.is_ok(),
                outcome.native.as_ref().err().map(ToString::to_string),
            ),
            Err(error) => ("dispatch_refused", false, Some(error.to_string())),
        };
        honest_attempt_observations.push(serde_json::json!({
            "ordinal":reservation_attempts,
            "scheduled_from_logical_start_ns":attempt_started.duration_since(honest_start).as_nanos(),
            "completed_from_logical_start_ns":attempt_finished.duration_since(honest_start).as_nanos(),
            "wall_ns":attempt_finished.duration_since(attempt_started).as_nanos(),
            "phase":phase,"native_success":native_success,"error":error,
        }));
        match outcome {
            Ok(outcome) => break outcome,
            Err(error) if error.is(crate::ErrorCode::PublicMutationCpuBudget) => {
                assert!(
                    Instant::now() < honest_deadline,
                    "honest service did not recover within declared 5s; attempts={honest_attempt_observations:?}"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("{error}; attempts={honest_attempt_observations:?}"),
        }
    };
    let honest_complete_ns = honest_start.elapsed().as_nanos();
    let honest_deadline_ns = Duration::from_secs(5).as_nanos();
    assert!(
        honest_complete_ns <= honest_deadline_ns,
        "honest final return exceeded its original 5s deadline: {honest_complete_ns}ns; attempts={honest_attempt_observations:?}"
    );
    assert!(
        result.native.is_ok(),
        "{:?}; attempts={honest_attempt_observations:?}",
        result.native
    );
    assert!(!result.cpu.accounting_unavailable);
    let mut node = owner.into_inner().unwrap();
    assert_eq!(node.read_active().unwrap().0, honest.id().unwrap());
    let final_flow = domain.observe_actual_flow().unwrap().unwrap();
    assert!(final_flow.balance_identity_verified);
    assert_eq!(final_flow.live_owners, 0);
    assert_eq!(final_flow.termination_reserved_ns, 0);
    node.finish_remote_history_cpu_epoch(&domain).unwrap();
    println!(
        "{}",
        serde_json::json!({"schema":"native-full-w1-reorg-depletion-v2","invalid_full_w1_attempts":attacks,"attack_observations":attack_observations,"raw_invalid_packet_hex":hex::encode(invalid.encode().unwrap()),"raw_honest_packet_hex":hex::encode(honest.encode().unwrap()),"actual_budget_refusals":1,"depleted":depleted,"attack_cpu":cpu,"honest_logical_mutations":1,"honest_reservation_attempts":reservation_attempts,"honest_attempt_observations":honest_attempt_observations,"honest_successes":1,"honest_scheduled_to_complete_ns":honest_complete_ns,"honest_deadline_ns":honest_deadline_ns,"honest_cpu":result.cpu,"final_flow":final_flow,"new_accounts":0,"scope":"local original native full W1 and same original owner; not A03 or WAN"})
    );
}

#[test]
fn an_original_live_epoch_binds_once_and_unknown_owner_blocks_metered_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let (mut node, target, _) = fixture(dir.path(), false);
    let domain = ServiceMutationCpuDomain::standalone();
    // A live reference belongs to this Node, unlike a marker found on reopen.
    node.begin_ordinary_public_service_epoch().unwrap();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    let owner = Mutex::new(node);
    let request = crate::ingress::Request::Submit {
        packet: hex::encode(target.encode().unwrap()),
    };
    let accepted =
        crate::ingress::dispatch_shared_with_metered_w1(&owner, request.clone(), &domain, &|| {
            Ok(())
        })
        .unwrap();
    assert!(accepted.native.is_ok());
    assert!(!accepted.cpu.accounting_unavailable);
    let before = owner.lock().unwrap().read_active().unwrap();
    let paid_before = domain
        .observe_actual_flow()
        .unwrap()
        .unwrap()
        .paid_cpu_debit_ns;
    owner
        .lock()
        .unwrap()
        .mark_ordinary_public_service_epoch_unknown();
    // Scalar accounting can still be known when a listener's lifecycle is
    // uncertain. This is an owner-boundary control, not a depletion trial.
    assert!(domain.accounting_available());
    let facts = pon_work::facts::WorkFactCache::new(1).unwrap();
    let plain =
        crate::ingress::dispatch_shared_with_metered_w1(&owner, request.clone(), &domain, &|| {
            Ok(())
        })
        .err()
        .expect("unknown live epoch cannot reserve through the plain helper");
    let cached = crate::ingress::dispatch_shared_with_metered_work_facts(
        &owner,
        request,
        &facts,
        &domain,
        &|| Ok(()),
    )
    .err()
    .expect("unknown live epoch cannot reserve through the cached helper");
    for error in [plain, cached] {
        assert!(error.is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    }
    let after = domain.observe_actual_flow().unwrap().unwrap();
    assert_eq!(after.paid_cpu_debit_ns, paid_before);
    assert_eq!(after.live_owners, 0);
    assert_eq!(after.booked_reservation_ns, 0);
    assert_eq!(facts.counters().full_replays, 0);
    assert_eq!(owner.lock().unwrap().read_active().unwrap(), before);
}

fn retained_replay(db: &Connection) -> Vec<u8> {
    type ReplayRow = (Vec<u8>, u64, Option<u64>, Option<Vec<u8>>, Option<u64>);
    let replay: Vec<ReplayRow> = db
        .prepare("SELECT session_id,highest_ack,pending_nonce,pending_digest,pending_bytes FROM peer_replay ORDER BY session_id")
        .unwrap().query_map([], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))
        .unwrap().collect::<std::result::Result<_,_>>().unwrap();
    type AuditRow = (Vec<u8>, u64, Vec<u8>, Option<Vec<u8>>, u64);
    let audit: Vec<AuditRow> = db
        .prepare("SELECT session_id,nonce,payload_digest,payload,status FROM peer_request_audit ORDER BY session_id,nonce")
        .unwrap().query_map([], |row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))
        .unwrap().collect::<std::result::Result<_,_>>().unwrap();
    serde_json::to_vec(&(replay, audit)).unwrap()
}

fn active_sql_bytes(db: &Connection) -> Vec<u8> {
    let active: (Vec<u8>, u64, u64) = db
        .query_row(
            "SELECT tip,generation,state_slot FROM active WHERE singleton=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    let state: Vec<(String, Vec<u8>)> = db
        .prepare("SELECT key,value FROM kv WHERE slot=? ORDER BY key")
        .unwrap()
        .query_map([active.2], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<std::result::Result<_, _>>()
        .unwrap();
    serde_json::to_vec(&(active, state)).unwrap()
}

#[test]
#[ignore = "subprocess fixture: only parent chooses a real SIGKILL cut"]
fn reorg_cancellation_kill_child() {
    let root = PathBuf::from(std::env::var("TRNM_REORG_KILL_DIRECTORY").unwrap());
    let cut_name = std::env::var("TRNM_REORG_KILL_STAGE").unwrap();
    let (mut node, target, _) = fixture(&root.join("node"), false);
    // Persist the exact native replay frame through its original admission
    // owner. This is the native verified-frame test seam; actual signature
    // verification is separately exercised by the unchanged socket control.
    let payload = serde_json::to_vec(&crate::ingress::Request::Submit {
        packet: hex::encode(target.encode().unwrap()),
    })
    .unwrap();
    let session = PeerSessionIdentityV0::new(
        IoDigest32V0::new(node.settings.genesis()).unwrap(),
        IoDigest32V0::new(node.settings.parameters()).unwrap(),
        IoDigest32V0::new(development_public(0).unwrap()).unwrap(),
        IoDigest32V0::new(hash(b"reorg-kill-session-v1", &[&node.settings.genesis()])).unwrap(),
        IoDigest32V0::new(crate::authenticated_profile_digest()).unwrap(),
        1,
    )
    .unwrap();
    let frame = AuthenticatedPeerFrameV0::new(
        session,
        1,
        IoDigest32V0::new(crate::authenticated_payload_digest(&payload)).unwrap(),
        payload.len(),
    )
    .unwrap();
    assert!(matches!(
        node.begin_authenticated_request(frame, &payload).unwrap(),
        AuthenticatedReplayDecision::Execute
    ));
    let domain = ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&domain).unwrap();
    node.begin_ordinary_public_service_epoch().unwrap();
    fs::write(root.join("active-before.json"), active_sql_bytes(&node.db)).unwrap();
    fs::write(root.join("replay-before.json"), retained_replay(&node.db)).unwrap();
    let operation = domain.begin().unwrap();
    let checkpoint = operation.checkpoint_handle();
    let _ = node.activate_with_fault_and_progress(
        target.id().unwrap(),
        Some(&mut |point| {
            if point == cut_name {
                // The original parent kills this actual process at the cut.
                fs::write(root.join("cut-ready"), point).unwrap();
                loop {
                    std::thread::park_timeout(Duration::from_millis(5));
                }
            }
            if point == "intent" {
                return Err(Error::new(crate::ErrorCode::LegacyRequestDeadline));
            }
            Ok(())
        }),
        &mut || checkpoint.checkpoint(),
        Some(&checkpoint),
    );
    panic!("requested SIGKILL cut was not reached");
}

struct KillOnDrop(std::process::Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn three_actual_sigkill_cuts_keep_active_state_replay_and_unknown_cpu_fence() {
    use std::os::unix::process::ExitStatusExt;
    for stage in [
        "cancel-before-transaction",
        "cancel-lifecycle-written",
        "cancel-committed",
    ] {
        let root = tempfile::tempdir().unwrap();
        let mut child = KillOnDrop(
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("store::reorg_cancellation::tests::reorg_cancellation_kill_child")
                .args(["--ignored", "--exact", "--nocapture"])
                .env("TRNM_REORG_KILL_DIRECTORY", root.path())
                .env("TRNM_REORG_KILL_STAGE", stage)
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let end = Instant::now() + Duration::from_secs(30);
        while fs::read_to_string(root.path().join("cut-ready"))
            .ok()
            .as_deref()
            != Some(stage)
        {
            assert!(
                Instant::now() < end,
                "child did not reach {stage} within 30s"
            );
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited before {stage}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        let status = child.0.wait().unwrap();
        assert_eq!(status.signal(), Some(libc::SIGKILL));
        let db = Connection::open_with_flags(
            root.path().join("node/native.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        assert_eq!(
            active_sql_bytes(&db),
            fs::read(root.path().join("active-before.json")).unwrap()
        );
        let replay = fs::read(root.path().join("replay-before.json")).unwrap();
        assert_eq!(retained_replay(&db), replay);
        let done: u64 = db
            .query_row("SELECT done FROM reorg WHERE singleton=1", [], |r| r.get(0))
            .unwrap();
        let lifecycle: u64 = db
            .query_row(
                "SELECT outcome FROM reorg_lifecycle_v1 ORDER BY operation DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(done, if stage == "cancel-committed" { 2 } else { 0 });
        assert_eq!(lifecycle, done);
        let epoch: Vec<u8> = db
            .query_row(
                "SELECT value FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(epoch, b"active-v1");
        drop(db);
        let mut reopened = Node::open(
            &root.path().join("node"),
            Settings::development(Some(1_700_000_000)).unwrap(),
            2,
        )
        .unwrap();
        assert_eq!(retained_replay(&reopened.db), replay);
        assert!(reopened.public_service_cpu_domain().is_err());
        assert!(reopened
            .begin_ordinary_public_service_epoch()
            .unwrap_err()
            .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        assert!(reopened.public_service_cpu_domain().is_err());
        let target: Vec<u8> = reopened
            .db
            .query_row("SELECT new_tip FROM reorg WHERE singleton=1", [], |row| {
                row.get(0)
            })
            .unwrap();
        let packet = reopened.packet(bytes32(target).unwrap()).unwrap();
        let packet_hex = hex::encode(packet.encode().unwrap());
        let request = crate::ingress::Request::Submit {
            packet: packet_hex.clone(),
        };
        let fresh = ServiceMutationCpuDomain::standalone();
        let before_credit = fresh.observe().unwrap().stored_credit_ns;
        let bind_error = reopened.bind_public_service_cpu_domain(&fresh).unwrap_err();
        assert!(bind_error.is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        let owner = Mutex::new(reopened);
        let facts = pon_work::facts::WorkFactCache::new(1).unwrap();
        let plain_error = crate::ingress::dispatch_shared_with_metered_w1(
            &owner,
            request.clone(),
            &fresh,
            &|| Ok(()),
        )
        .err()
        .expect("marked crash cannot bind or reserve through the plain W1 helper");
        let fact_error = crate::ingress::dispatch_shared_with_metered_work_facts(
            &owner,
            request,
            &facts,
            &fresh,
            &|| Ok(()),
        )
        .err()
        .expect("marked crash cannot bind or reserve through the work-fact helper");
        for error in [&plain_error, &fact_error] {
            assert!(error.is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
        }
        let fresh_flow = fresh.observe_actual_flow().unwrap().unwrap();
        assert_eq!(fresh_flow.stored_credit_ns, before_credit);
        assert_eq!(fresh_flow.live_owners, 0);
        assert_eq!(fresh_flow.paid_cpu_debit_ns, 0);
        assert_eq!(fresh_flow.booked_reservation_ns, 0);
        assert_eq!(facts.counters().full_replays, 0);
        let reopened = owner.into_inner().unwrap();
        assert!(reopened.public_service_cpu_domain().is_err());
        assert_eq!(retained_replay(&reopened.db), replay);
        assert_eq!(
            reopened
                .db
                .query_row::<Vec<u8>, _, _>(
                    "SELECT value FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
                    [],
                    |row| row.get(0),
                )
                .unwrap(),
            epoch
        );
        let first_outcome: u64 = reopened
            .db
            .query_row(
                "SELECT outcome FROM reorg_lifecycle_v1 ORDER BY operation LIMIT 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            first_outcome,
            if stage == "cancel-committed" { 2 } else { 1 }
        );
        println!(
            "{}",
            serde_json::json!({"schema":"native-reorg-termination-sigkill-v2","cut":stage,"signal":status.signal(),"pre_reopen_active_state_unchanged":true,"pre_reopen_done":done,"pre_reopen_lifecycle":lifecycle,"native_replay_and_audit_bytes_unchanged":true,"cpu_epoch_retained":true,"new_cpu_account_available":false,"unknown_debt_refuses_public_restart":true,"cold_bind_error":bind_error.to_string(),"metered_plain_error":plain_error.to_string(),"metered_fact_error":fact_error.to_string(),"raw_helper_packet_hex":packet_hex,"fresh_unbound_domain_flow":fresh_flow,"original_cancelled_lifecycle_retained":stage=="cancel-committed","scope":"actual native SIGKILL; original cold recovery remains trusted-local; supplied diagnostic domain never attaches or reserves; no autonomous paid restart recovery claim"})
        );
    }
}
