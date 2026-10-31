use super::*;
use std::{
    sync::{atomic::AtomicUsize, Mutex},
    time::Instant,
};
use trnm_crypto_primitives::{sign_hex, signing_key_from_hex};
use trnm_protocol::pon_wire::Envelope;

fn open(path: &Path, settings: &Settings, authenticated: bool) -> Node {
    if authenticated {
        Node::open_with_authenticated_state(path, settings.clone(), 2).unwrap()
    } else {
        Node::open(path, settings.clone(), 2).unwrap()
    }
}
fn transfer(settings: &Settings, nonce: u64) -> Vec<u8> {
    let key =
        signing_key_from_hex(&hex::encode(hash(b"DEV-ONLY-KEY", &[&0_u64.to_le_bytes()]))).unwrap();
    let mut payload = development_public(nonce + 10).unwrap().to_vec();
    payload.extend(1_u64.to_le_bytes());
    let mut envelope = Envelope {
        network: settings.network(),
        sender: development_public(0).unwrap(),
        nonce,
        expiry: 10_000,
        fee_limit: 1_000_000,
        tag: 1,
        payload,
        signature: [0; 64],
    };
    envelope.signature = hex::decode(sign_hex(&key, &envelope.signing_digest().unwrap()))
        .unwrap()
        .try_into()
        .unwrap();
    envelope.encode().unwrap()
}
fn packet(node: &Node, parent: Hash, first: u64, count: u64, timestamp: u64, miner: u64) -> Packet {
    node.make(
        parent,
        (first..first + count)
            .map(|n| transfer(node.settings(), n))
            .collect(),
        development_public(miner).unwrap(),
        timestamp,
        4096,
    )
    .unwrap()
}
fn prepared(node: &Node, packet: &Packet) -> Box<PreparedExecution> {
    let lease = node.reserve_detached_execution().unwrap();
    let checked = WorkCheckedPacket::verify(packet.clone()).unwrap();
    match node
        .prepare_shared_admission(
            checked,
            lease,
            1000,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
        .unwrap()
    {
        PreparedSharedAdmission::Execute(value) => value,
        PreparedSharedAdmission::Existing(_) => panic!("new candidate must execute"),
        PreparedSharedAdmission::HeldForSnapshotCapacity { .. } => {
            panic!("small fixture must detach")
        }
    }
}
fn executed(node: &Node, packet: &Packet) -> ExecutedSharedAdmission {
    prepared(node, packet)
        .execute(&ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap()
}
fn wrong_root(mut packet: Packet) -> Packet {
    packet.header.state[0] ^= 1;
    let (a, b) = maintenance();
    let prover = pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        packet.header.nonce = nonce;
        packet.proof = prover.prove(packet.header.challenge()).unwrap();
        if WorkCheckedPacket::verify(packet.clone()).is_ok() {
            return packet;
        }
    }
    panic!("real bounded W1 search exhausted");
}
fn bindings(node: &Node) -> u64 {
    let observed = node.native_history_arithmetic_observation();
    [
        "execution_parent_checked_apply",
        "execution_parent_rebuilt_tree",
        "execution_parent_full_root",
    ]
    .iter()
    .map(|key| observed["counters"][key].as_u64().unwrap())
    .sum()
}

#[test]
fn native_m06_runs_without_writer_and_matches_held_owner_on_both_backends() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let reference_directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 4, 1001, 0);
        let owner = Mutex::new(node);
        let before_bindings = bindings(&owner.lock().unwrap());
        let preparation = prepared(&owner.lock().unwrap(), &candidate);
        assert!(preparation.snapshot_payload_bytes > 0);
        assert!(preparation.snapshot_payload_bytes <= MAX_SNAPSHOT_PAYLOAD);
        let checked = AtomicUsize::new(0);
        let observer = Mutex::new(());
        let control = |point| {
            if matches!(
                point,
                ExecutionProgress::BeforeStateClone
                    | ExecutionProgress::BeforePrepare { .. }
                    | ExecutionProgress::BeforeCommitment
            ) {
                // Executor workers can call this concurrently. Serialize only
                // these observer probes so one observer is not mistaken for a
                // retained native writer by another observer's try_lock.
                let _probe = observer.lock().unwrap();
                owner
                    .try_lock()
                    .expect("M06 retained Node writer")
                    .public_head_metadata()
                    .unwrap();
                checked.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        };
        let outcome = preparation
            .execute(&ExecutionControl::new(&control, &()))
            .unwrap();
        assert!(checked.load(Ordering::Relaxed) >= 6);
        let mut node = owner.lock().unwrap();
        if authenticated {
            assert_eq!(bindings(&node), before_bindings + 1);
        }
        let id = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap();
        node.activate_observed(id, 1000).unwrap();
        let mut reference = open(reference_directory.path(), &settings, authenticated);
        reference.admit(&candidate, 1000).unwrap();
        reference.activate_observed(id, 1000).unwrap();
        assert_eq!(
            node.read_active().unwrap(),
            reference.read_active().unwrap()
        );
        assert_eq!(
            node.packet(id).unwrap().encode().unwrap(),
            candidate.encode().unwrap()
        );
        assert_eq!(
            node.record(id).unwrap().work.bytes(),
            reference.record(id).unwrap().work.bytes()
        );
        drop(node);
        drop(owner);
        assert_eq!(
            open(directory.path(), &settings, authenticated)
                .read_active()
                .unwrap(),
            reference.read_active().unwrap()
        );
    }
}

#[test]
fn one_original_snapshot_lease_is_bounded_and_cannot_move_to_another_node() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(a.path(), &settings, false);
    let other = open(b.path(), &settings, false);
    let lease = node.reserve_detached_execution().unwrap();
    assert!(node
        .reserve_detached_execution()
        .err()
        .unwrap()
        .is(crate::ErrorCode::PublicQueueBusy));
    let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
    let error = other
        .prepare_shared_admission(
            WorkCheckedPacket::verify(candidate).unwrap(),
            lease,
            1000,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
        .err()
        .unwrap();
    assert!(error.is(crate::ErrorCode::OwnerDetachedExecutionContext));
    drop(node.reserve_detached_execution().unwrap());
}

#[test]
fn completed_artifact_refuses_wrong_owner_reopen_and_late_owner_stop() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(a.path(), &settings, true);
    let mut other = open(b.path(), &settings, true);
    let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
    let outcome = executed(&node, &candidate);
    assert!(other
        .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap_err()
        .is(crate::ErrorCode::OwnerDetachedExecutionContext));
    let outcome = executed(&node, &candidate);
    drop(node);
    node = open(a.path(), &settings, true);
    assert!(node
        .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap_err()
        .is(crate::ErrorCode::OwnerDetachedExecutionContext));
    let outcome = executed(&node, &candidate);
    node.mark_ordinary_public_service_epoch_unknown();
    assert!(node
        .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap_err()
        .is(crate::ErrorCode::OwnerPublicServiceUncleanEpoch));
    assert!(node.packet(candidate.id().unwrap()).is_err());
    assert!(other.packet(candidate.id().unwrap()).is_err());
}

#[test]
fn current_clock_target_and_unsupported_owner_are_rechecked_after_m06() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), &settings, false);
    let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
    let outcome = executed(&node, &candidate);
    assert_eq!(
        node.commit_shared_admission(outcome, 0, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap_err()
            .to_string(),
        "TIME_DEFERRED"
    );
    // Deliberate internal corruption control; callers have no such field access.
    let mut outcome = executed(&node, &candidate);
    outcome.admission.packet.header.target[0] ^= 1;
    assert_eq!(
        node.commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap_err()
            .to_string(),
        "TARGET"
    );
    let outcome = executed(&node, &candidate);
    node.enable_local_root_rejection_cache().unwrap();
    assert!(node
        .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap_err()
        .is(crate::ErrorCode::OwnerDetachedExecutionUnsupported));
    assert!(node
        .reserve_detached_execution()
        .err()
        .unwrap()
        .is(crate::ErrorCode::OwnerDetachedExecutionUnsupported));
    assert!(node.packet(candidate.id().unwrap()).is_err());
}

#[test]
fn foreign_write_and_restore_cannot_reuse_original_database_epoch() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let outcome = executed(&node, &candidate);
        let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
        foreign
            .execute("INSERT INTO metadata VALUES('detached-fault',X'00')", [])
            .unwrap();
        foreign
            .execute("DELETE FROM metadata WHERE key='detached-fault'", [])
            .unwrap();
        let error = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap_err();
        assert!(error.is(crate::ErrorCode::StorageContext) && error.requires_owner_stop());
        assert!(node.packet(candidate.id().unwrap()).is_err());
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
    }
}

#[test]
fn final_sqlite_writer_fence_rejects_write_and_restore_after_last_context_check() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let outcome = executed(&node, &candidate);
        let foreign = Mutex::new(Connection::open(directory.path().join("native.sqlite")).unwrap());
        let seen = AtomicUsize::new(0);
        let control = |point| {
            if point == ExecutionProgress::BeforePersistence
                && seen.fetch_add(1, Ordering::Relaxed) == 1
            {
                // This is the final original control boundary immediately
                // before BEGIN IMMEDIATE, after fresh context checks finished.
                let foreign = foreign.lock().unwrap();
                foreign
                    .execute("INSERT INTO metadata VALUES('last-window',X'00')", [])
                    .unwrap();
                foreign
                    .execute("DELETE FROM metadata WHERE key='last-window'", [])
                    .unwrap();
            }
            Ok(())
        };
        let error = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&control, &()))
            .unwrap_err();
        assert_eq!(seen.load(Ordering::Relaxed), 2);
        assert!(error.is(crate::ErrorCode::StorageContext) && error.requires_owner_stop());
        assert!(node.packet(candidate.id().unwrap()).is_err());
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
    }
}

#[test]
fn legal_concurrent_append_revalidates_parent_and_preserves_competing_branch() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let competing = packet(&node, settings.genesis(), 1, 1, 1002, 1);
        let outcome = executed(&node, &candidate);
        let competing_id = node.admit(&competing, 1000).unwrap();
        node.activate_observed(competing_id, 1000).unwrap();
        let id = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap();
        assert_eq!(id, candidate.id().unwrap());
        assert_eq!(node.read_active().unwrap().0, competing_id);
        assert_eq!(
            node.packet(id).unwrap().encode().unwrap(),
            candidate.encode().unwrap()
        );
    }
}

#[test]
fn detached_result_cannot_bypass_real_pending_reorganization() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let competing = packet(&node, settings.genesis(), 1, 1, 1002, 1);
        let outcome = executed(&node, &candidate);
        let competing_id = node.admit(&competing, 1000).unwrap();
        let mut cut = |point: &str| {
            if point == "intent" {
                // A non-control fault retains a real unfinished intent. Typed
                // cancellation is now terminalized by its original owner and
                // is covered by the separate same-owner cancellation matrix.
                Err(Error::new(crate::ErrorCode::StoragePacket))
            } else {
                Ok(())
            }
        };
        assert!(node
            .activate_with_fault(competing_id, Some(&mut cut))
            .unwrap_err()
            .is(crate::ErrorCode::StoragePacket));
        let error = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap_err();
        assert_eq!(error.to_string(), "REORG_IN_PROGRESS");
        assert!(node.packet(candidate.id().unwrap()).is_err());
        // The original recovery, not this artifact, resolves that durable intent.
        node.activate_observed(competing_id, 1000).unwrap();
        assert_eq!(node.read_active().unwrap().0, competing_id);
    }
}

#[test]
fn real_w1_wrong_root_and_original_m06_cancellation_create_no_commit() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let node = open(directory.path(), &settings, true);
    let valid = packet(&node, settings.genesis(), 1, 4, 1001, 0);
    let invalid = wrong_root(valid.clone());
    let before_bindings = bindings(&node);
    assert_eq!(
        prepared(&node, &invalid)
            .execute(&ExecutionControl::new(&|_| Ok(()), &()))
            .err()
            .unwrap()
            .to_string(),
        "ROOT"
    );
    assert_eq!(bindings(&node), before_bindings + 1);
    let seen = AtomicUsize::new(0);
    let cancelled = prepared(&node, &valid).execute(&ExecutionControl::new(
        &|point| {
            if matches!(point, ExecutionProgress::BeforeApply { .. }) {
                seen.fetch_add(1, Ordering::Relaxed);
                Err(Error::new(crate::ErrorCode::PublicRequestDeadline))
            } else {
                Ok(())
            }
        },
        &(),
    ));
    assert!(cancelled
        .err()
        .unwrap()
        .is(crate::ErrorCode::PublicRequestDeadline));
    assert!(seen.load(Ordering::Relaxed) > 0);
    assert!(node.packet(valid.id().unwrap()).is_err());
    assert!(node.packet(invalid.id().unwrap()).is_err());
    assert_eq!(node.read_active().unwrap().0, settings.genesis());
    drop(node.reserve_detached_execution().unwrap());
}

#[test]
fn original_transaction_readback_rejects_trigger_corruption_and_rolls_back() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let outcome = executed(&node, &candidate);
        node.db.execute_batch("CREATE TRIGGER detached_skip BEFORE INSERT ON deltas BEGIN SELECT RAISE(IGNORE); END;").unwrap();
        let error = node
            .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
            .unwrap_err();
        assert!(error.requires_owner_stop());
        assert!(node.packet(candidate.id().unwrap()).is_err());
        assert_eq!(node.read_active().unwrap().0, settings.genesis());
    }
}

#[test]
fn snapshot_payload_capacity_is_a_private_schedule_hint_and_preserves_control_errors() {
    let control = ExecutionControl::new(&|_| Ok(()), &());
    let mut state = State::new();
    for index in 0..2048 {
        state.insert(format!("bounded-{index:05}"), json_value("x".repeat(4094)));
    }
    assert!(
        matches!(payload_bytes(&state, &control).unwrap(), SnapshotPayload::HeldRequired { observed_bytes } if observed_bytes > MAX_SNAPSHOT_PAYLOAD)
    );
    // An identical-looking caller resource error is NOT authority to continue
    // in another schedule. Only the private counter result selects held M06.
    let error = payload_bytes(
        &state,
        &ExecutionControl::new(
            &|_| {
                Err(Error::new(
                    crate::ErrorCode::PublicExecutionSnapshotCapacity,
                ))
            },
            &(),
        ),
    )
    .unwrap_err();
    assert!(error.is(crate::ErrorCode::PublicExecutionSnapshotCapacity));
    assert_eq!(error.kind(), crate::ErrorKind::Capacity);
    assert!(!error.requires_owner_stop());
}

#[test]
fn admitted_custom_genesis_over_eight_mib_keeps_original_held_schedule_and_cpu_owner() {
    for authenticated in [false, true] {
        assert_custom_genesis_held_schedule_and_cpu_owner(authenticated);
    }
}

#[test]
fn authenticated_large_parent_original_schedule_supplementary_denominator() {
    assert_custom_genesis_held_schedule_and_cpu_owner(true);
}

fn assert_custom_genesis_held_schedule_and_cpu_owner(authenticated: bool) {
    // Explicit independent test genesis, NOT a claimed history grown from the
    // installed default genesis. All original limits and assertions are shared.
    let directory = tempfile::tempdir().unwrap();
    let reference_directory = tempfile::tempdir().unwrap();
    let mut settings = Settings::development(Some(1)).unwrap();
    for index in 0..2100 {
        settings.initial.insert(
            format!("fixture-large-parent:{index:04}"),
            json_value("x".repeat(4080)),
        );
    }
    let initial_root = settings.state_root(&settings.initial).unwrap();
    settings.genesis = hash(
        b"genesis",
        &[
            &settings.network(),
            &settings.parameters(),
            &initial_root,
            &settings.genesis_time().to_le_bytes(),
        ],
    );
    let mut node = open(directory.path(), &settings, authenticated);
    let mut reference = open(reference_directory.path(), &settings, authenticated);
    let seed = packet(&node, settings.genesis(), 1, 1, 1001, 0);
    let parent = node.admit(&seed, 1000).unwrap();
    node.activate_observed(parent, 1000).unwrap();
    assert_eq!(reference.admit(&seed, 1000).unwrap(), parent);
    reference.activate_observed(parent, 1000).unwrap();
    let candidate = packet(&node, parent, 2, 4, 1002, 0);
    let before = node.read_active().unwrap();
    let actual_payload: usize = before
        .2
        .iter()
        .map(|(key, value)| key.len() + canonical(value).unwrap().len())
        .sum();
    assert!(actual_payload > MAX_SNAPSHOT_PAYLOAD);
    let lease = node.reserve_detached_execution().unwrap();
    let held = node
        .prepare_shared_admission(
            WorkCheckedPacket::verify(candidate.clone()).unwrap(),
            lease,
            1000,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
        .unwrap();
    let PreparedSharedAdmission::HeldForSnapshotCapacity {
        checked,
        observed_payload_bytes,
    } = held
    else {
        panic!("large native parent must select original held M06")
    };
    assert!(
        observed_payload_bytes > MAX_SNAPSHOT_PAYLOAD && observed_payload_bytes <= actual_payload
    );
    drop(checked);
    drop(node.reserve_detached_execution().unwrap());
    assert_eq!(node.read_active().unwrap(), before);
    let original = crate::ingress::public_v3::ServiceMutationCpuDomain::standalone();
    node.bind_public_service_cpu_domain(&original).unwrap();
    let arithmetic_before = node.authenticated_arithmetic.observation();
    let owner = Mutex::new(node);
    let end = Instant::now() + std::time::Duration::from_secs(10);
    // Inspect the exact shared scalar-CPU epoch without mutating credit.
    // Observations are optional diagnostics: a missing/unknown meter remains
    // unknown, and the original dispatch/unwrap still decides acceptance.
    let cpu_budget_before = original.observe().ok();
    let cpu_flow_before = original.observe_actual_flow().ok().flatten();
    let dispatch_start = Instant::now();
    let attempt = crate::ingress::dispatch_shared_with_metered_w1(
        &owner,
        crate::ingress::Request::Submit {
            packet: hex::encode(candidate.encode().unwrap()),
        },
        &original,
        &|| ensure(Instant::now() < end, "PUBLIC_REQUEST_DEADLINE"),
    );
    // Preserve the original acceptance assertion below, including its failure.
    // Previously the unwrap above panicked before the original arithmetic
    // evidence could be printed for >8 MiB parent state. Capture actual
    // post-dispatch accounting without retrying, increasing CPU credit, or
    // using an unmetered execution path.
    let elapsed_ns = dispatch_start.elapsed().as_nanos();
    let cpu_budget_after = original.observe().ok();
    let cpu_flow_after = original.observe_actual_flow().ok().flatten();
    let arithmetic_after = owner.lock().unwrap().authenticated_arithmetic.observation();
    let unchanged_on_refusal = if attempt.is_err() {
        // Even a damaged readback must not hide the original typed CPU
        // refusal. Unknown is null, never treated as a verified equality.
        owner
            .lock()
            .ok()
            .and_then(|node| node.read_active().ok())
            .map(|actual| actual == before)
    } else {
        None
    };
    println!(
        "{}",
        serde_json::json!({
            "schema": "native-large-parent-original-dispatch-diagnostic-v1",
            "authenticated_backend": authenticated,
            "complete_key_utf8_and_canonical_value_bytes": actual_payload,
            "observed_held_capacity_lower_bound_bytes": observed_payload_bytes,
            "dispatch_elapsed_ns": elapsed_ns.to_string(),
            "original_dispatch_result": attempt.as_ref().map(|_| "ok").map_err(ToString::to_string),
            "active_state_unchanged_on_refusal": unchanged_on_refusal,
            "cpu_budget_before": cpu_budget_before,
            "cpu_budget_after": cpu_budget_after,
            "actual_cpu_flow_before": cpu_flow_before,
            "actual_cpu_flow_after": cpu_flow_after,
            "arithmetic_before": &arithmetic_before,
            "arithmetic_after": &arithmetic_after,
            "measurement_scope": "actual original metered dispatch; observation after outcome, no alternative execution, refill or altered acceptance"
        })
    );
    // This remains the original strict business gate: a budget refusal is
    // still an actual failing native test, not a qualified success.
    let result = attempt.unwrap();
    println!(
        "{}",
        serde_json::json!({"schema":"native-large-parent-arithmetic-stages-v1", "authenticated_backend":authenticated, "before":arithmetic_before, "after":arithmetic_after, "measurement_scope":"existing stage counters sampled outside the original paid CPU operation; no budget or schedule changes"})
    );
    println!(
        "{}",
        serde_json::json!({"schema":"native-large-parent-schedule-parity-v1", "authenticated_backend":authenticated, "genesis_fixture":"2100 explicitly seeded 4080-byte string cells; original native validator and one signed admitted seed block; not default-genesis historical growth", "genesis":hex::encode(settings.genesis()), "genesis_state_root":hex::encode(initial_root), "admitted_parent":hex::encode(parent), "complete_key_utf8_and_canonical_value_bytes":actual_payload, "early_capacity_observed_lower_bound_bytes":observed_payload_bytes, "original_cpu_receipt":result.cpu, "native_result":result.native.as_ref().map(|_|"ok").map_err(ToString::to_string), "host_qualified":false, "budget_depletion_demonstrated":false, "all_honest_service_qualified":false})
    );
    assert!(!result.cpu.accounting_unavailable);
    assert_eq!(result.cpu.started_workers, result.cpu.finished_workers);
    assert_eq!(result.cpu.started_workers, result.cpu.known_workers);
    assert!(result.cpu.total_cpu_ns.unwrap() > 0);
    let reply = result.native.unwrap();
    let id = candidate.id().unwrap();
    assert_eq!(reply["block"], hex::encode(id));
    assert_eq!(reference.admit(&candidate, 1000).unwrap(), id);
    reference.activate_observed(id, 1000).unwrap();
    let node = owner.lock().unwrap();
    assert!(node
        .public_service_cpu_domain()
        .unwrap()
        .shares_domain_with(&original));
    assert_eq!(original.observe().unwrap().in_flight, 0);
    assert_eq!(
        node.read_active().unwrap(),
        reference.read_active().unwrap()
    );
    assert_eq!(
        node.packet(id).unwrap().encode().unwrap(),
        candidate.encode().unwrap()
    );
    drop(node);
    drop(owner);
    assert_eq!(
        open(directory.path(), &settings, authenticated)
            .read_active()
            .unwrap(),
        reference.read_active().unwrap()
    );
}

fn process_cpu_ns() -> u64 {
    let stamp = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    u64::try_from(stamp.tv_sec)
        .unwrap()
        .checked_mul(1_000_000_000)
        .unwrap()
        .checked_add(u64::try_from(stamp.tv_nsec).unwrap())
        .unwrap()
}
fn rss_kib() -> u64 {
    let raw = fs::read_to_string("/proc/self/status").unwrap();
    raw.lines()
        .find(|line| line.starts_with("VmRSS:"))
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
#[ignore = "explicit actual 1024-signed-transfer full-State snapshot/execution/commit cost; not a saturation campaign"]
fn detached_full_state_cost_uses_real_signed_history_and_reports_scope() {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(1)).unwrap();
    let mut node = open(directory.path(), &settings, true);
    let mut parent = settings.genesis();
    for block in 0..4 {
        let seed = packet(&node, parent, block * 256 + 1, 256, 1001 + block, 0);
        parent = node.admit(&seed, 1000).unwrap();
        node.activate_observed(parent, 1000).unwrap();
    }
    let candidate = packet(&node, parent, 1025, 1, 1010, 0);
    let checked = WorkCheckedPacket::verify(candidate.clone()).unwrap();
    let before_rss = rss_kib();
    let started = Instant::now();
    let cpu = process_cpu_ns();
    let lease = node.reserve_detached_execution().unwrap();
    let PreparedSharedAdmission::Execute(preparation) = node
        .prepare_shared_admission(
            checked,
            lease,
            1000,
            &ExecutionControl::new(&|_| Ok(()), &()),
        )
        .unwrap()
    else {
        panic!("new packet");
    };
    let prepare_cpu = process_cpu_ns() - cpu;
    let prepare_wall = started.elapsed().as_nanos();
    let keys = preparation.prior.len();
    let payload = preparation.snapshot_payload_bytes;
    let prepared_rss = rss_kib();
    let started = Instant::now();
    let cpu = process_cpu_ns();
    let outcome = preparation
        .execute(&ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap();
    let execution_cpu = process_cpu_ns() - cpu;
    let execution_wall = started.elapsed().as_nanos();
    let executed_rss = rss_kib();
    let started = Instant::now();
    let cpu = process_cpu_ns();
    let id = node
        .commit_shared_admission(outcome, 1000, &ExecutionControl::new(&|_| Ok(()), &()))
        .unwrap();
    let commit_cpu = process_cpu_ns() - cpu;
    let commit_wall = started.elapsed().as_nanos();
    assert_eq!(id, candidate.id().unwrap());
    assert!(keys >= 1024 && payload > 0);
    // A separate real deep-copy observation AFTER the measured pipeline, so
    // this extra allocation does not warm the pipeline's earlier State clone.
    let clone_source = node.state_at(parent).unwrap();
    let clone_started = Instant::now();
    let clone_cpu = process_cpu_ns();
    let cloned = clone_source.clone();
    let clone_cpu = process_cpu_ns() - clone_cpu;
    let clone_wall = clone_started.elapsed().as_nanos();
    assert_eq!(cloned, clone_source);
    println!(
        "{}",
        serde_json::json!({"schema":"native-detached-full-state-cost-v1","actual_seed_transfers":1024,
        "actual_seed_blocks":4,"state_keys":keys,"canonical_key_value_bytes":payload,
        "one_snapshot_slot":true,"snapshot_payload_cap_bytes":MAX_SNAPSHOT_PAYLOAD,
        "prepare_process_cpu_ns":prepare_cpu,"prepare_wall_ns":prepare_wall,
        "execution_process_cpu_ns":execution_cpu,"execution_wall_ns":execution_wall,
        "commit_process_cpu_ns":commit_cpu,"commit_wall_ns":commit_wall,
        "separate_actual_state_clone_process_cpu_ns":clone_cpu,"separate_actual_state_clone_wall_ns":clone_wall,
        "rss_kib_before":before_rss,"rss_kib_prepared":prepared_rss,"rss_kib_executed":executed_rss,
        "scope":"one actual authenticated native Node; full signed history; per-stage whole-process CPU includes joined M06 workers; RSS snapshots include allocator retention and are not allocation attribution; snapshot/SQL still hold writer; no A03 or WAN throughput claim",
        "budget_depletion_demonstrated":false,"resource_fairness_qualified":false,"production_activation":false})
    );
}

fn held_parent_fixture(node: &Node, candidate: &Packet) -> HeldPreparedAdmission {
    HeldPreparedAdmission {
        checked: WorkCheckedPacket::verify(candidate.clone()).unwrap(),
        parent: node
            .check_admission_parent(candidate, &mut || Ok(()))
            .unwrap(),
        owner: Arc::clone(&node.detached_execution),
    }
}

#[test]
fn held_parent_continuation_checks_original_owner_epoch_and_current_clock() {
    for authenticated in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let other_directory = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(1)).unwrap();
        let mut node = open(directory.path(), &settings, authenticated);
        let mut other = open(other_directory.path(), &settings, authenticated);
        let candidate = packet(&node, settings.genesis(), 1, 1, 1001, 0);
        let control = ExecutionControl::new(&|_| Ok(()), &());
        let prepared = held_parent_fixture(&node, &candidate);
        assert!(other
            .admit_held_prepared(prepared, 1000, &control)
            .unwrap_err()
            .is(crate::ErrorCode::OwnerDetachedExecutionContext));
        let prepared = held_parent_fixture(&node, &candidate);
        assert_eq!(
            node.admit_held_prepared(prepared, 0, &control)
                .unwrap_err()
                .to_string(),
            "TIME_DEFERRED"
        );
        let prepared = held_parent_fixture(&node, &candidate);
        let reads_before = node.native_history_arithmetic_observation();
        let foreign = Connection::open(directory.path().join("native.sqlite")).unwrap();
        foreign
            .execute(
                "INSERT INTO metadata VALUES('held-epoch-control',X'00')",
                [],
            )
            .unwrap();
        foreign
            .execute("DELETE FROM metadata WHERE key='held-epoch-control'", [])
            .unwrap();
        assert!(prepared.parent.epoch != Some(node.admission_state_epoch().unwrap()));
        let id = node.admit_held_prepared(prepared, 1000, &control).unwrap();
        assert_eq!(id, candidate.id().unwrap());
        if authenticated {
            let after = node.native_history_arithmetic_observation();
            let reads = |value: &serde_json::Value| {
                value["stages"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["stage"] == "state_at")
                    .unwrap()["totals"]["calls"]
                    .as_u64()
                    .unwrap()
            };
            assert!(
                reads(&after) > reads(&reads_before),
                "changed epoch must reconstruct the full current parent"
            );
        }
        assert!(other.packet(id).is_err());
        node.activate_observed(id, 1000).unwrap();
        assert_eq!(node.read_active().unwrap().0, id);
    }
}
