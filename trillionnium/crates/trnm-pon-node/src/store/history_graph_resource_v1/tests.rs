//! Storage/ownership controls for the new atomic marker. Resource closures here
//! are explicit unit fixtures, not substitutes for the real fixed-parent gate.
use super::*;
use crate::ErrorCode;

fn fixture() -> (tempfile::TempDir, Settings, Node) {
    let dir = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(crate::ingress::now().unwrap() - 100)).unwrap();
    let node = Node::open(dir.path(), settings.clone(), 1).unwrap();
    (dir, settings, node)
}

fn begin(node: &mut Node) -> Epoch {
    node.remote_history_cpu_domain().unwrap();
    node.begin_history_graph_resource_v1(
        &serde_json::json!({"unit_fixture_only":true,"physical_kernel_qualified":false}),
        &|| Ok(()),
    )
    .unwrap()
}

fn both(db: &Connection) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
    (read(db, CPU_KEY).unwrap(), read(db, KEY).unwrap())
}

fn begin_actual_cold_operation(
    domain: &ServiceMutationCpuDomain,
) -> crate::ingress::public_v3::ServiceMutationCpuOperation {
    // The original History start needs its 100ms reserve, not the separate
    // continuous startup helper's full 2-CPU-second burst. Keep the same finite
    // two-second wall limit and earn every unit through the real original refill.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        match domain.begin() {
            Ok(operation) => return operation,
            Err(error)
                if error.is(ErrorCode::PublicMutationCpuBudget)
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(2))
            }
            Err(error) => panic!("actual original cold CPU begin failed: {error}"),
        }
    }
}

#[test]
fn graph_resource_v1_policy_and_original_cpu_epoch_publish_atomically() {
    let (_dir, _settings, mut node) = fixture();
    node.db.execute_batch("CREATE TEMP TRIGGER refuse_graph_policy BEFORE INSERT ON metadata WHEN NEW.key='ordinary-history-graph-resource-policy-v1' BEGIN SELECT RAISE(ABORT,'test graph policy write refusal'); END;").unwrap();
    assert!(node
        .begin_history_graph_resource_v1(&serde_json::json!({"unit_fixture_only":true}), &|| Ok(()))
        .is_err());
    assert_eq!(both(&node.db), (None, None));
    assert_eq!(node.public_service_epoch_listeners, 0);
    assert!(node.history_graph_resource_binding.is_none());
    node.db
        .execute_batch("DROP TRIGGER refuse_graph_policy;")
        .unwrap();
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    node.finish_ordinary_public_service_epoch(true).unwrap();
}

#[test]
fn graph_resource_v1_clean_settlement_preserves_credit_and_allows_old_strict_next() {
    let (dir, settings, mut node) = fixture();
    let original = node.stats().unwrap();
    let domain = node.remote_history_cpu_domain().unwrap();
    assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
    let epoch = begin(&mut node);
    epoch.verify().unwrap();
    node.check_history_graph_resource_before_commit().unwrap();
    assert_eq!(
        both(&node.db),
        (Some(CPU_ACTIVE.to_vec()), Some(epoch.expected.clone()))
    );
    let binding: Value = serde_json::from_slice(&epoch.expected).unwrap();
    assert_eq!(binding["profile"], profile::PROFILE);
    assert_eq!(binding["maximum_node_bodies_between_full_checks"], 8);
    assert_eq!(binding["policy_digest"], profile::policy_digest());
    assert_eq!(binding["new_cpu_credit_granted"], false);
    assert!(
        binding.get("source_commit").is_none() && binding.get("binary_sha256").is_none(),
        "source/binary observations are not a new authority or a future settlement lock"
    );
    node.finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
        .unwrap();
    assert_eq!(both(&node.db), (None, None));
    assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&domain));
    assert!(node.begin_ordinary_public_service_epoch().unwrap());
    node.finish_ordinary_public_service_epoch(true).unwrap();
    assert_eq!(node.stats().unwrap(), original);
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert!(reopened.begin_ordinary_public_service_epoch().unwrap());
    reopened.finish_ordinary_public_service_epoch(true).unwrap();
    let next = begin(&mut reopened);
    assert_ne!(
        next.expected, epoch.expected,
        "new epoch cannot reuse a prior cleanup token"
    );
    assert!(reopened
        .finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
        .is_err());
    assert_eq!(
        both(&reopened.db),
        (Some(CPU_ACTIVE.to_vec()), Some(next.expected))
    );
}

#[test]
fn graph_resource_v1_refuses_profile_switch_or_borrowed_listener_last_close() {
    let (_dir, _settings, mut strict) = fixture();
    strict.begin_ordinary_public_service_epoch().unwrap();
    let before = both(&strict.db);
    assert!(strict
        .begin_history_graph_resource_v1(&serde_json::json!({}), &|| Ok(()))
        .err()
        .unwrap()
        .is(ErrorCode::HistoryGraphResourceProfileV1));
    assert_eq!(both(&strict.db), before);
    strict.finish_ordinary_public_service_epoch(true).unwrap();
    let epoch = begin(&mut strict);
    for error in [
        strict.begin_remote_history_cpu_epoch().unwrap_err(),
        strict.begin_ordinary_public_service_epoch().unwrap_err(),
        strict
            .finish_ordinary_public_service_epoch(true)
            .unwrap_err(),
        strict.remote_history_cpu_domain().err().unwrap(),
    ] {
        assert!(error.is(ErrorCode::HistoryGraphResourceProfileV1));
    }
    assert!(strict
        .begin_history_graph_resource_v1(&serde_json::json!({}), &|| Ok(()))
        .is_err());
    assert_eq!(
        both(&strict.db),
        (Some(CPU_ACTIVE.to_vec()), Some(epoch.expected.clone()))
    );
    strict
        .finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
        .unwrap();
    strict.begin_ordinary_public_service_epoch().unwrap();
    strict.finish_ordinary_public_service_epoch(true).unwrap();
}

#[test]
fn graph_resource_v1_missing_changed_or_oversized_marker_never_reuses_a_verdict() {
    for mutation in [
        "DELETE FROM metadata WHERE key='ordinary-history-graph-resource-policy-v1'",
        "UPDATE metadata SET value=X'00' WHERE key='ordinary-history-graph-resource-policy-v1'",
        "UPDATE metadata SET value=zeroblob(16385) WHERE key='ordinary-history-graph-resource-policy-v1'",
        "UPDATE metadata SET value='wrong-type' WHERE key='ordinary-history-graph-resource-policy-v1'",
        "DELETE FROM metadata WHERE key='ordinary-public-v3-epoch-v1'",
        "UPDATE metadata SET value=X'00' WHERE key='ordinary-public-v3-epoch-v1'",
    ] {
        let (dir, settings, mut node) = fixture();
        let epoch = begin(&mut node);
        epoch.verify().unwrap();
        node.db.execute(mutation, []).unwrap();
        assert!(epoch.verify().is_err());
        assert!(node.check_history_graph_resource_before_commit().is_err());
        assert!(node.finish_history_graph_resource_v1(&epoch, true, &|| Ok(())).is_err());
        assert!(node.public_service_epoch_unknown);
        drop(node);
        let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
        assert!(reopened.remote_history_cpu_domain().is_err());
        assert!(reopened.begin_ordinary_public_service_epoch().is_err());
        assert!(reopened.begin_history_graph_resource_v1(&serde_json::json!({}), &|| Ok(())).is_err());
    }
}

#[test]
fn graph_resource_v1_uncommitted_same_connection_change_cannot_hide_from_commit_fence() {
    let (_dir, _settings, mut node) = fixture();
    let epoch = begin(&mut node);
    epoch.verify().unwrap();
    node.db.execute_batch("BEGIN IMMEDIATE; UPDATE metadata SET value=X'00' WHERE key='ordinary-history-graph-resource-policy-v1';").unwrap();
    epoch.verify().unwrap(); // A separate WAL reader sees the original committed row.
    assert!(node
        .check_history_graph_resource_before_commit()
        .unwrap_err()
        .is(ErrorCode::HistoryGraphResourceBindingV1));
    node.db.execute_batch("ROLLBACK;").unwrap();
    epoch.verify().unwrap();
    node.check_history_graph_resource_before_commit().unwrap();
    node.finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
        .unwrap();
}

#[test]
fn graph_resource_v1_reused_statement_rebinds_and_reads_after_failure_restore_and_eviction() {
    for capacity in [0, 1, 16] {
        let (dir, _settings, mut node) = fixture();
        let epoch = begin(&mut node);
        epoch
            .reader
            .lock()
            .unwrap()
            .set_prepared_statement_cache_capacity(capacity);
        node.db.set_prepared_statement_cache_capacity(capacity);
        let outside = Connection::open(dir.path().join("native.sqlite")).unwrap();
        epoch.verify().unwrap();
        node.check_history_graph_resource_before_commit().unwrap();
        for (key, original) in [(CPU_KEY, CPU_ACTIVE), (KEY, epoch.expected.as_slice())] {
            for sql_value in [
                rusqlite::types::Value::Integer(0),
                rusqlite::types::Value::Text("different".into()),
                rusqlite::types::Value::Blob(vec![0; 16_385]),
            ] {
                outside
                    .execute(
                        "UPDATE metadata SET value=?1 WHERE key=?2",
                        params![sql_value, key],
                    )
                    .unwrap();
                assert!(epoch.verify().is_err());
                assert!(node.check_history_graph_resource_before_commit().is_err());
                outside
                    .execute(
                        "UPDATE metadata SET value=?1 WHERE key=?2",
                        params![original, key],
                    )
                    .unwrap();
                epoch.verify().unwrap();
                node.check_history_graph_resource_before_commit().unwrap();
            }
            outside
                .execute("DELETE FROM metadata WHERE key=?1", [key])
                .unwrap();
            assert!(epoch.verify().is_err());
            outside
                .execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,?2)",
                    params![key, original],
                )
                .unwrap();
            epoch.verify().unwrap();
        }
        // Reusing the plan must not retain an expected-row comparison, even
        // after successful reads and explicit eviction of its compiled plan.
        assert!(matches_current(&node.db, b"a different epoch").is_err());
        matches_current(&node.db, &epoch.expected).unwrap();
        for db in [&node.db, &*epoch.reader.lock().unwrap()] {
            db.flush_prepared_statement_cache();
            matches_current(db, &epoch.expected).unwrap();
            assert!(db.is_autocommit());
        }
        node.db
            .execute_batch(
                "BEGIN IMMEDIATE; DELETE FROM metadata WHERE key='ordinary-public-v3-epoch-v1';",
            )
            .unwrap();
        epoch.verify().unwrap(); // Fresh independent WAL reader sees committed state.
        assert!(node.check_history_graph_resource_before_commit().is_err());
        node.db.execute_batch("ROLLBACK;").unwrap();
        node.check_history_graph_resource_before_commit().unwrap();
        epoch.verify().unwrap();
        node.finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
            .unwrap();
    }
}

#[test]
fn graph_resource_v1_finish_transaction_refusal_retains_both_original_markers() {
    let (dir, settings, mut node) = fixture();
    let epoch = begin(&mut node);
    let before = both(&node.db);
    node.db.execute_batch("CREATE TEMP TRIGGER refuse_graph_close BEFORE DELETE ON metadata WHEN OLD.key='ordinary-history-graph-resource-policy-v1' BEGIN SELECT RAISE(ABORT,'test graph policy close refusal'); END;").unwrap();
    assert!(node
        .finish_history_graph_resource_v1(&epoch, true, &|| Ok(()))
        .is_err());
    assert_eq!(
        both(&node.db),
        before,
        "first DELETE must roll back with the second"
    );
    assert!(node.public_service_epoch_unknown);
    drop(node);
    let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
    assert_eq!(both(&reopened.db), before);
    assert!(reopened.remote_history_cpu_domain().is_err());
}

#[test]
fn graph_resource_v1_unclean_and_resource_refused_closes_never_clear_original_debt() {
    for resource_refused in [false, true] {
        let (dir, settings, mut node) = fixture();
        let epoch = begin(&mut node);
        let before = both(&node.db);
        if resource_refused {
            assert!(node
                .finish_history_graph_resource_v1(&epoch, true, &|| Err(
                    "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
                ))
                .is_err());
        } else {
            node.finish_history_graph_resource_v1(&epoch, false, &|| Ok(()))
                .unwrap();
        }
        assert_eq!(both(&node.db), before);
        assert_eq!(node.public_service_epoch_unknown, !resource_refused);
        assert_eq!(
            node.history_graph_resource_pending.is_some(),
            resource_refused
        );
        drop(node);
        let mut reopened = Node::open(dir.path(), settings, 1).unwrap();
        assert_eq!(both(&reopened.db), before);
        assert!(reopened.remote_history_cpu_domain().is_err());
    }
}

#[test]
fn graph_resource_v1_live_known_close_retries_only_original_epoch_without_credit() {
    for changed in ["none", "marker", "parent", "unknown", "busy"] {
        let (dir, settings, mut node) = fixture();
        let epoch = begin(&mut node);
        let domain = node.public_service_cpu_domain().unwrap();
        let parent: Value = serde_json::from_slice::<Value>(&epoch.expected).unwrap()
            ["fixed_parent_observation"]
            .clone();
        let before = both(&node.db);
        assert!(node
            .finish_history_graph_resource_v1(&epoch, true, &|| Err(
                "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
            ))
            .is_err());
        assert!(node.history_graph_resource_pending.is_some());
        assert!(!node.public_service_epoch_unknown);
        assert_eq!(both(&node.db), before);
        assert!(node
            .resume_history_graph_resource_settlement_v1(&parent, &|| Err(
                "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
            ))
            .is_err());
        assert!(node.history_graph_resource_pending.is_some());
        assert!(!node.public_service_epoch_unknown);
        let mut observed_parent = parent.clone();
        let mut active = None;
        match changed {
            "marker" => {
                node.db
                    .execute("UPDATE metadata SET value=X'00' WHERE key=?1", [KEY])
                    .unwrap();
            }
            "parent" => observed_parent["replacement"] = serde_json::json!(true),
            "unknown" | "busy" => {
                let operation = begin_actual_cold_operation(&domain);
                if changed == "unknown" {
                    drop(operation);
                } else {
                    active = Some(operation);
                }
            }
            "none" => {}
            _ => unreachable!(),
        }
        let result = node.resume_history_graph_resource_settlement_v1(&observed_parent, &|| Ok(()));
        if changed == "busy" {
            assert!(result.unwrap_err().is(ErrorCode::PublicMutationCpuBudget));
            assert!(node.history_graph_resource_pending.is_some());
            assert!(!node.public_service_epoch_unknown);
            assert_eq!(both(&node.db), before);
            assert!(!active.take().unwrap().finish().accounting_unavailable);
            let credit = domain.observe().unwrap().stored_credit_ns;
            node.resume_history_graph_resource_settlement_v1(&parent, &|| Ok(()))
                .unwrap();
            assert_eq!(domain.observe().unwrap().stored_credit_ns, credit);
        } else if changed == "none" {
            result.unwrap();
            assert_eq!(domain.observe().unwrap().stored_credit_ns, 0);
        } else {
            assert!(result.is_err());
            assert!(node.public_service_epoch_unknown);
            assert!(node.history_graph_resource_pending.is_none());
            assert!(read(&node.db, CPU_KEY).unwrap().is_some());
            continue;
        }
        assert_eq!(both(&node.db), (None, None));
        assert!(node.history_graph_resource_pending.is_none());
        assert!(node
            .public_service_cpu_domain()
            .unwrap()
            .shares_domain_with(&domain));
        assert!(node
            .resume_history_graph_resource_settlement_v1(&parent, &|| Ok(()))
            .is_err());
        node.begin_ordinary_public_service_epoch().unwrap();
        node.finish_ordinary_public_service_epoch(true).unwrap();
        // The successful old close does not supply a new live capability.
        let next = begin(&mut node);
        assert!(node
            .finish_history_graph_resource_v1(&next, true, &|| Err(
                "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
            ))
            .is_err());
        drop(node);
        let mut cold = Node::open(dir.path(), settings, 1).unwrap();
        assert!(cold.history_graph_resource_pending.is_none());
        assert!(cold
            .resume_history_graph_resource_settlement_v1(&parent, &|| Ok(()))
            .is_err());
        assert!(cold.remote_history_cpu_domain().is_err());
    }
}

#[test]
fn graph_resource_v1_early_resume_keeps_original_limits_without_rebinding_parent() {
    let (_directory, _settings, mut node) = fixture();
    let domain = node.remote_history_cpu_domain().unwrap();
    let parent = serde_json::json!({
        "schema":"fixed-kernel-parent-identity-observation-v1", "path":"/sys/fs/cgroup/trnmponpublic.slice",
        "device":1,"inode":2,"boot_id":"unit-fixture-not-physical-host",
        "cpu_quota_us":25000,"cpu_period_us":100000,"cpu_burst_us":0,
        "memory_bytes":2147483648u64,"swap_bytes":0,"tasks":256,"observation_is_authority":false,
    });
    let epoch = node
        .begin_history_graph_resource_v1(&parent, &|| Ok(()))
        .unwrap();
    assert!(node
        .finish_history_graph_resource_v1(&epoch, true, &|| Err(
            "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
        ))
        .is_err());
    let original_rows = both(&node.db);
    let credit = domain.observe().unwrap();
    let mut still_restricted = parent.clone();
    still_restricted["cpu_quota_us"] = serde_json::json!(20000);
    let error = node
        .resume_history_graph_resource_settlement_v1(&still_restricted, &|| Ok(()))
        .unwrap_err();
    assert_eq!(error.to_string(), "PUBLIC_HOST_KERNEL_LIMITS_CHANGED");
    assert!(node.history_graph_resource_pending.is_some());
    assert!(!node.public_service_epoch_unknown);
    assert_eq!(both(&node.db), original_rows);
    assert_eq!(domain.observe().unwrap(), credit);
    node.resume_history_graph_resource_settlement_v1(&parent, &|| Ok(()))
        .unwrap();
    assert_eq!(both(&node.db), (None, None));
    assert_eq!(domain.observe().unwrap(), credit);
    let next = node
        .begin_history_graph_resource_v1(&parent, &|| Ok(()))
        .unwrap();
    assert!(node
        .finish_history_graph_resource_v1(&next, true, &|| Err(
            "PUBLIC_HOST_KERNEL_LIMITS_CHANGED".into()
        ))
        .is_err());
    let mut replacement = parent.clone();
    replacement["inode"] = serde_json::json!(3);
    assert!(node
        .resume_history_graph_resource_settlement_v1(&replacement, &|| Ok(()))
        .is_err());
    assert!(node.public_service_epoch_unknown);
    assert!(node.history_graph_resource_pending.is_none());
    assert!(both(&node.db).0.is_some() && both(&node.db).1.is_some());
}
