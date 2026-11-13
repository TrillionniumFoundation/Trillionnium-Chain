//! Tests of the real durable owner API, using private temporary directories.
//! Metadata-only fixtures do not certify native-chain or physical service work.
use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const NOW: u64 = 1_000;
const DEADLINE: u64 = 10_000;

fn profile() -> ResourceProfileV1 {
    ResourceProfileV1 {
        owner_id: [91; 32],
        grants: [ResourcesV1 {
            cpu_ns: 1_000,
            io_bytes: 2_000,
        }; 3],
        max_operations: [4; 3],
        max_inflight: [2; 3],
        overshoot: ResourcesV1 {
            cpu_ns: 50,
            io_bytes: 50,
        },
    }
}
fn request(id: u8, class: ClassV1) -> ResourceRequestV1 {
    ResourceRequestV1 {
        binding: OperationBindingV1 {
            operation_id: [id; 32],
            request_digest: [81; 32],
            parent_state: [71; 32],
            deadline_unix_ms: DEADLINE,
        },
        class,
        execution: ResourcesV1 {
            cpu_ns: 400,
            io_bytes: 400,
        },
        cleanup: ResourcesV1 {
            cpu_ns: 100,
            io_bytes: 100,
        },
        recovery_of: None,
    }
}
fn completion() -> CompletionV1 {
    CompletionV1 {
        worker_stopped: true,
        effect_readback: true,
        cleanup_complete: true,
        receipt_digest: [61; 32],
    }
}
fn node_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["native.sqlite", "owner.lock"] {
        let path = directory.path().join(name);
        File::create(&path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    directory
}
fn fixture_with(p: &ResourceProfileV1) -> (tempfile::TempDir, ResourceOwnerV1) {
    let directory = node_directory();
    let owner = ResourceOwnerV1::initialize(directory.path(), p).unwrap();
    (directory, owner)
}
fn fixture() -> (tempfile::TempDir, ResourceOwnerV1) {
    fixture_with(&profile())
}
fn error<T>(result: Result<T>) -> String {
    match result {
        Err(error) => error.to_string(),
        Ok(_) => panic!("unexpected success"),
    }
}
fn fresh(owner: &ResourceOwnerV1, request: &ResourceRequestV1) -> ResourceReservationV1 {
    match owner.reserve(request, NOW).unwrap() {
        AdmissionV1::Fresh(reservation) => reservation,
        AdmissionV1::Existing(_) => panic!("new operation already existed"),
    }
}
fn assert_held(owner: &ResourceOwnerV1, expected_state: OperationStateV1) {
    let snapshot = owner.snapshot().unwrap();
    let lane = &snapshot.lanes[0];
    assert_eq!(lane.charged, ResourcesV1::default());
    assert_eq!(
        lane.inflight_execution,
        ResourcesV1 {
            cpu_ns: 400,
            io_bytes: 400
        }
    );
    assert_eq!(
        lane.inflight_cleanup,
        ResourcesV1 {
            cpu_ns: 100,
            io_bytes: 100
        }
    );
    assert_eq!(
        lane.available,
        Some(ResourcesV1 {
            cpu_ns: 500,
            io_bytes: 1_500
        })
    );
    assert_eq!(lane.unresolved_operations, 1);
    let record = owner.observe([1; 32]).unwrap().unwrap();
    assert_eq!(record.state, expected_state);
    assert!(record.charge.is_none() && record.completion.is_none());
    assert!(!snapshot.physical_resource_bound_qualified);
    assert!(!snapshot.honest_service_bound_qualified);
}

#[test]
fn open_never_initializes_and_explicit_initialization_never_replaces() {
    let directory = node_directory();
    let journal = directory.path().join(JOURNAL_NAME);
    assert!(!ResourceOwnerV1::is_present(directory.path()).unwrap());
    assert!(ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).is_err());
    assert!(!journal.exists());
    fs::write(&journal, b"unknown partial prior initialization").unwrap();
    let original = fs::read(&journal).unwrap();
    assert!(ResourceOwnerV1::initialize(directory.path(), &profile()).is_err());
    assert_eq!(fs::read(&journal).unwrap(), original);
    let (initialized, owner) = fixture();
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    let original = fs::read(initialized.path().join(JOURNAL_NAME)).unwrap();
    assert!(ResourceOwnerV1::initialize(initialized.path(), &profile()).is_err());
    assert_eq!(
        fs::read(initialized.path().join(JOURNAL_NAME)).unwrap(),
        original
    );
    assert_held(&owner, OperationStateV1::Reserved);
}

#[test]
fn profile_changes_refuse_without_reinterpreting_existing_principal() {
    let (directory, owner) = fixture();
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    let before = fs::read(directory.path().join(JOURNAL_NAME)).unwrap();
    for field in 0..7 {
        let mut changed = profile();
        match field {
            0 => changed.owner_id[0] ^= 1,
            1 => changed.grants[0].cpu_ns += 1,
            2 => changed.grants[1].io_bytes += 1,
            3 => changed.max_operations[2] += 1,
            4 => changed.max_inflight[0] += 1,
            5 => changed.overshoot.cpu_ns += 1,
            6 => changed.overshoot.io_bytes += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            error(ResourceOwnerV1::open(
                directory.path(),
                changed.id().unwrap()
            )),
            "RESOURCE_OWNER_PROFILE"
        );
    }
    assert_eq!(
        fs::read(directory.path().join(JOURNAL_NAME)).unwrap(),
        before
    );
    assert_held(&owner, OperationStateV1::Reserved);
}

#[test]
fn same_id_retry_is_observation_and_changed_binding_members_refuse() {
    let (_directory, owner) = fixture();
    let original = request(1, ClassV1::Bootstrap);
    drop(fresh(&owner, &original));
    let before = owner.snapshot().unwrap();
    for field in 0..8 {
        let mut changed = original.clone();
        match field {
            0 => changed.binding.request_digest[0] ^= 1,
            1 => changed.binding.parent_state[0] ^= 1,
            2 => changed.binding.deadline_unix_ms += 1,
            3 => changed.class = ClassV1::Committed,
            4 => changed.execution.cpu_ns += 1,
            5 => changed.execution.io_bytes += 1,
            6 => changed.cleanup.cpu_ns += 1,
            7 => changed.cleanup.io_bytes += 1,
            _ => unreachable!(),
        }
        assert_eq!(
            error(owner.reserve(&changed, NOW)),
            "RESOURCE_OWNER_BINDING_CONFLICT"
        );
    }
    let mut changed = original.clone();
    changed.class = ClassV1::Recovery;
    changed.recovery_of = Some([2; 32]);
    assert_eq!(
        error(owner.reserve(&changed, NOW)),
        "RESOURCE_OWNER_BINDING_CONFLICT"
    );
    match owner.reserve(&original, DEADLINE + 1).unwrap() {
        AdmissionV1::Existing(record) => assert_eq!(record.request, original),
        AdmissionV1::Fresh(_) => panic!("retry minted dispatch permission"),
    }
    assert_eq!(owner.snapshot().unwrap().record_hash, before.record_hash);
    assert_held(&owner, OperationStateV1::Reserved);
}

#[test]
fn original_deadline_and_one_time_native_claim_survive_another_handle() {
    let (directory, owner) = fixture();
    let original = request(1, ClassV1::Bootstrap);
    let mut supervisor = fresh(&owner, &original);
    assert_eq!(
        error(supervisor.validate_running(directory.path(), NOW)),
        "RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED"
    );
    let other = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
    assert_eq!(
        error(other.claim_existing(&original, DEADLINE)),
        "RESOURCE_OWNER_DEADLINE"
    );
    let worker = other.claim_existing(&original, NOW).unwrap();
    worker.validate_running(directory.path(), NOW).unwrap();
    assert_eq!(
        error(supervisor.claim(NOW)),
        "RESOURCE_OWNER_ALREADY_CLAIMED"
    );
    assert_eq!(
        error(supervisor.validate_running(directory.path(), NOW)),
        "RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED"
    );
    assert_eq!(
        error(owner.claim_existing(&original, NOW)),
        "RESOURCE_OWNER_ALREADY_CLAIMED"
    );
    assert_eq!(
        error(worker.validate_running(directory.path(), DEADLINE)),
        "RESOURCE_OWNER_DEADLINE"
    );
    let wrong_node = node_directory();
    assert_eq!(
        error(worker.validate_running(wrong_node.path(), NOW)),
        "RESOURCE_OWNER_NATIVE_CLAIM_REQUIRED"
    );
    drop(worker);
    drop(supervisor);
    assert_held(&owner, OperationStateV1::Running);
    assert_eq!(
        error(owner.reserve(&request(2, ClassV1::Bootstrap), DEADLINE)),
        "RESOURCE_OWNER_DEADLINE"
    );
}

#[test]
fn admitted_clock_floor_is_durable_and_backwards_time_cannot_claim_or_start() {
    let (directory, owner) = fixture();
    let original = request(1, ClassV1::Bootstrap);
    drop(fresh(&owner, &original));
    drop(owner);
    let reopened = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
    assert_eq!(reopened.snapshot().unwrap().clock_floor_unix_ms, NOW);
    assert_eq!(
        error(reopened.claim_existing(&original, NOW - 1)),
        "RESOURCE_OWNER_CLOCK_ROLLBACK"
    );
    assert_eq!(
        error(reopened.reserve(&request(2, ClassV1::Committed), NOW - 1)),
        "RESOURCE_OWNER_CLOCK_ROLLBACK"
    );
    let worker = reopened.claim_existing(&original, NOW + 1).unwrap();
    assert_eq!(reopened.snapshot().unwrap().clock_floor_unix_ms, NOW + 1);
    assert_eq!(
        error(reopened.reserve(&request(2, ClassV1::Committed), NOW)),
        "RESOURCE_OWNER_CLOCK_ROLLBACK"
    );
    // Existing status and reconciliation do not mint new clock-based grants.
    assert!(matches!(
        reopened.reserve(&original, NOW - 1).unwrap(),
        AdmissionV1::Existing(_)
    ));
    drop(worker);
    reopened
        .reconcile_conservatively(&original, completion())
        .unwrap();
    assert_eq!(reopened.snapshot().unwrap().clock_floor_unix_ms, NOW + 1);
}

#[test]
fn drop_and_reopen_preserve_full_reserved_and_running_principal() {
    for running in [false, true] {
        let (directory, owner) = fixture();
        let mut reservation = fresh(&owner, &request(1, ClassV1::Bootstrap));
        if running {
            reservation.claim(NOW).unwrap();
        }
        drop(reservation);
        let before = owner.snapshot().unwrap();
        drop(owner);
        let reopened = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
        assert_held(
            &reopened,
            if running {
                OperationStateV1::Running
            } else {
                OperationStateV1::Reserved
            },
        );
        assert_eq!(reopened.snapshot().unwrap().record_hash, before.record_hash);
    }
}

#[test]
fn process_exit_without_destructors_preserves_the_original_hold() {
    const CHILD_NODE: &str = "TRNM_RESOURCE_OWNER_CRASH_TEST_NODE";
    const CHILD_RUNNING: &str = "TRNM_RESOURCE_OWNER_CRASH_TEST_RUNNING";
    if let Some(path) = std::env::var_os(CHILD_NODE) {
        let node = PathBuf::from(path);
        let owner = ResourceOwnerV1::open(&node, profile().id().unwrap()).unwrap();
        let mut reservation = fresh(&owner, &request(1, ClassV1::Bootstrap));
        if std::env::var(CHILD_RUNNING).unwrap() == "yes" {
            reservation.claim(NOW).unwrap();
        }
        // Deliberately skip Drop. The parent records the expected nonzero exit.
        std::process::exit(17);
    }
    for running in [false, true] {
        let (directory, owner) = fixture();
        let output = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("resource_owner_v1::tests::process_exit_without_destructors_preserves_the_original_hold")
            .arg("--nocapture")
            .env(CHILD_NODE, directory.path())
            .env(CHILD_RUNNING, if running { "yes" } else { "no" })
            .output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(17),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        drop(owner);
        let reopened = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
        assert_held(
            &reopened,
            if running {
                OperationStateV1::Running
            } else {
                OperationStateV1::Reserved
            },
        );
    }
}

#[test]
fn independent_processes_cannot_claim_the_same_operation_twice() {
    const CHILD_NODE: &str = "TRNM_RESOURCE_OWNER_CLAIM_TEST_NODE";
    const CHILD_INDEX: &str = "TRNM_RESOURCE_OWNER_CLAIM_TEST_INDEX";
    if let Some(path) = std::env::var_os(CHILD_NODE) {
        let node = PathBuf::from(path);
        let index = std::env::var(CHILD_INDEX).unwrap();
        fs::write(node.join(format!("ready-{index}")), b"ready").unwrap();
        let start = Instant::now();
        while !node.join("claim-go").exists() {
            assert!(
                start.elapsed() < Duration::from_secs(5),
                "claim start barrier timed out"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let outcome = ResourceOwnerV1::open(&node, profile().id().unwrap())
            .and_then(|owner| owner.claim_existing(&request(1, ClassV1::Bootstrap), NOW));
        let result = match outcome {
            Ok(reservation) => {
                drop(reservation);
                "claimed".to_owned()
            }
            Err(error) => error.to_string(),
        };
        fs::write(node.join(format!("result-{index}")), result).unwrap();
        return;
    }
    let (directory, owner) = fixture();
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    let mut children = Vec::new();
    for index in 0..4 {
        children.push(Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("resource_owner_v1::tests::independent_processes_cannot_claim_the_same_operation_twice")
            .arg("--nocapture")
            .env(CHILD_NODE, directory.path())
            .env(CHILD_INDEX, index.to_string())
            .stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap());
    }
    let start = Instant::now();
    while !(0..4).all(|index| directory.path().join(format!("ready-{index}")).exists()) {
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "claim readiness barrier timed out"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    fs::write(directory.path().join("claim-go"), b"go").unwrap();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let results: Vec<_> = (0..4)
        .map(|index| fs::read_to_string(directory.path().join(format!("result-{index}"))).unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|value| value.as_str() == "claimed")
            .count(),
        1,
        "{results:?}"
    );
    assert!(
        results.iter().all(|value| matches!(
            value.as_str(),
            "claimed" | "RESOURCE_OWNER_BUSY" | "RESOURCE_OWNER_ALREADY_CLAIMED"
        )),
        "{results:?}"
    );
    assert_held(&owner, OperationStateV1::Running);
    assert_eq!(owner.snapshot().unwrap().sequence, 3);
}

#[test]
fn incomplete_completion_facts_never_release_any_principal() {
    for field in 0..4 {
        let (_directory, owner) = fixture();
        let mut reservation = fresh(&owner, &request(1, ClassV1::Bootstrap));
        reservation.claim(NOW).unwrap();
        let mut incomplete = completion();
        match field {
            0 => incomplete.worker_stopped = false,
            1 => incomplete.effect_readback = false,
            2 => incomplete.cleanup_complete = false,
            3 => incomplete.receipt_digest = [0; 32],
            _ => unreachable!(),
        }
        assert_eq!(
            error(reservation.finish(
                incomplete,
                ChargeV1::Measured(ResourcesV1 {
                    cpu_ns: 250,
                    io_bytes: 300
                })
            )),
            "RESOURCE_OWNER_COMPLETION_REQUIRED"
        );
        assert_held(&owner, OperationStateV1::Running);
    }
}

#[test]
fn unclaimed_work_cannot_refund_a_fabricated_measurement() {
    let (_directory, owner) = fixture();
    let reservation = fresh(&owner, &request(1, ClassV1::Bootstrap));
    assert_eq!(
        error(reservation.finish(completion(), ChargeV1::Measured(ResourcesV1::default()))),
        "RESOURCE_OWNER_SETTLEMENT_STATE"
    );
    assert_held(&owner, OperationStateV1::Reserved);
}

#[test]
fn measured_terminal_refund_is_exact_and_terminal_retry_never_dispatches() {
    let (directory, owner) = fixture();
    let original = request(1, ClassV1::Bootstrap);
    let mut reservation = fresh(&owner, &original);
    reservation.claim(NOW).unwrap();
    let actual = ResourcesV1 {
        cpu_ns: 250,
        io_bytes: 300,
    };
    let record = reservation
        .finish(completion(), ChargeV1::Measured(actual))
        .unwrap();
    assert_eq!(record.state, OperationStateV1::Settled);
    let before = owner.snapshot().unwrap();
    let lane = &before.lanes[0];
    assert_eq!(lane.charged, actual);
    assert_eq!(
        lane.available,
        Some(ResourcesV1 {
            cpu_ns: 750,
            io_bytes: 1_700
        })
    );
    assert_eq!(lane.inflight_execution, ResourcesV1::default());
    assert_eq!(lane.inflight_cleanup, ResourcesV1::default());
    assert_eq!(lane.unresolved_operations, 0);
    let reopened = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
    match reopened.reserve(&original, NOW).unwrap() {
        AdmissionV1::Existing(existing) => assert_eq!(existing, record),
        AdmissionV1::Fresh(_) => panic!("terminal operation redispatched"),
    }
    assert_eq!(
        error(reopened.claim_existing(&original, NOW)),
        "RESOURCE_OWNER_ALREADY_CLAIMED"
    );
    assert_eq!(reopened.snapshot().unwrap().record_hash, before.record_hash);
}

#[test]
fn conservative_reconciliation_charges_full_hold_and_is_idempotent() {
    for running in [false, true] {
        let (_directory, owner) = fixture();
        let original = request(1, ClassV1::Bootstrap);
        let mut reservation = fresh(&owner, &original);
        if running {
            reservation.claim(NOW).unwrap();
        }
        drop(reservation);
        let record = owner
            .reconcile_conservatively(&original, completion())
            .unwrap();
        let first = owner.snapshot().unwrap();
        assert_eq!(record.charge, Some(ChargeV1::Conservative));
        assert_eq!(
            first.lanes[0].charged,
            ResourcesV1 {
                cpu_ns: 500,
                io_bytes: 500
            }
        );
        assert_eq!(
            first.lanes[0].available,
            Some(ResourcesV1 {
                cpu_ns: 500,
                io_bytes: 1_500
            })
        );
        assert_eq!(first.lanes[0].unresolved_operations, 0);
        assert_eq!(
            owner
                .reconcile_conservatively(&original, completion())
                .unwrap(),
            record
        );
        assert_eq!(owner.snapshot().unwrap().record_hash, first.record_hash);
        let mut changed = completion();
        changed.receipt_digest[0] ^= 1;
        assert_eq!(
            error(owner.reconcile_conservatively(&original, changed)),
            "RESOURCE_OWNER_SETTLEMENT_CONFLICT"
        );
        assert_eq!(owner.snapshot().unwrap().record_hash, first.record_hash);
    }
}

#[test]
fn actual_overrun_persists_as_debt_and_fences_even_a_different_class() {
    for actual_cpu in [501, 3_501] {
        let (directory, owner) = fixture();
        let mut reservation = fresh(&owner, &request(1, ClassV1::Bootstrap));
        reservation.claim(NOW).unwrap();
        let actual = ResourcesV1 {
            cpu_ns: actual_cpu,
            io_bytes: 500,
        };
        reservation
            .finish(completion(), ChargeV1::Measured(actual))
            .unwrap();
        drop(owner);
        let reopened = ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).unwrap();
        let snapshot = reopened.snapshot().unwrap();
        assert_eq!(snapshot.lanes[0].charged, actual);
        assert!(snapshot.admission_fenced);
        assert_eq!(snapshot.within_declared_accounting_bound, actual_cpu == 501);
        assert!(!snapshot.physical_resource_bound_qualified);
        assert!(!snapshot.honest_service_bound_qualified);
        assert_eq!(
            error(reopened.reserve(&request(2, ClassV1::Committed), NOW)),
            "RESOURCE_OWNER_FENCED"
        );
        assert_eq!(
            reopened.snapshot().unwrap().record_hash,
            snapshot.record_hash
        );
    }
}

#[test]
fn overshoot_is_not_spendable_and_cleanup_is_reserved_before_dispatch() {
    let mut p = profile();
    p.grants[0] = ResourcesV1 {
        cpu_ns: 400,
        io_bytes: 400,
    };
    p.overshoot = ResourcesV1 {
        cpu_ns: 1_000,
        io_bytes: 1_000,
    };
    let (_directory, owner) = fixture_with(&p);
    assert_eq!(
        error(owner.reserve(&request(1, ClassV1::Bootstrap), NOW)),
        "RESOURCE_OWNER_BUDGET"
    );
    let snapshot = owner.snapshot().unwrap();
    assert_eq!(snapshot.lanes[0].available, Some(p.grants[0]));
    assert_eq!(snapshot.lanes[0].retained_operations, 0);
}

#[test]
fn class_inflight_and_retained_slots_do_not_consume_other_lanes() {
    let mut p = profile();
    p.max_operations[0] = 1;
    p.max_inflight[0] = 1;
    let (_directory, owner) = fixture_with(&p);
    let first = request(1, ClassV1::Bootstrap);
    drop(fresh(&owner, &first));
    drop(fresh(&owner, &request(2, ClassV1::Committed)));
    let mut recovery = request(3, ClassV1::Recovery);
    recovery.recovery_of = Some(first.binding.operation_id);
    drop(fresh(&owner, &recovery));
    owner
        .reconcile_conservatively(&first, completion())
        .unwrap();
    assert_eq!(
        error(owner.reserve(&request(4, ClassV1::Bootstrap), NOW)),
        "RESOURCE_OWNER_RECORD_LIMIT"
    );
    let snapshot = owner.snapshot().unwrap();
    assert_eq!(snapshot.lanes[0].retained_operations, 1);
    assert_eq!(
        snapshot.lanes[1].available,
        Some(ResourcesV1 {
            cpu_ns: 500,
            io_bytes: 1_500
        })
    );
    assert_eq!(
        snapshot.lanes[2].available,
        Some(ResourcesV1 {
            cpu_ns: 500,
            io_bytes: 1_500
        })
    );
    let mut p = profile();
    p.max_inflight[0] = 1;
    let (_directory, owner) = fixture_with(&p);
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    assert_eq!(
        error(owner.reserve(&request(2, ClassV1::Bootstrap), NOW)),
        "RESOURCE_OWNER_INFLIGHT_LIMIT"
    );
    drop(fresh(&owner, &request(3, ClassV1::Committed)));
}

#[test]
fn depleted_bootstrap_and_novel_ids_preserve_original_recovery_capacity() {
    let mut p = profile();
    p.grants[0] = ResourcesV1 {
        cpu_ns: 500,
        io_bytes: 500,
    };
    let (_directory, owner) = fixture_with(&p);
    let original = request(1, ClassV1::Bootstrap);
    drop(fresh(&owner, &original));
    for id in 2..10 {
        assert_eq!(
            error(owner.reserve(&request(id, ClassV1::Bootstrap), NOW)),
            "RESOURCE_OWNER_BUDGET"
        );
    }
    let mut recovery = request(10, ClassV1::Recovery);
    assert_eq!(
        error(owner.reserve(&recovery, NOW)),
        "RESOURCE_OWNER_RECOVERY_LINK"
    );
    recovery.recovery_of = Some([99; 32]);
    assert_eq!(
        error(owner.reserve(&recovery, NOW)),
        "RESOURCE_OWNER_RECOVERY_LINK"
    );
    recovery.recovery_of = Some(original.binding.operation_id);
    drop(fresh(&owner, &recovery));
    let mut altered = recovery.clone();
    altered.recovery_of = Some([98; 32]);
    assert_eq!(
        error(owner.reserve(&altered, NOW)),
        "RESOURCE_OWNER_BINDING_CONFLICT"
    );
    owner
        .reconcile_conservatively(&original, completion())
        .unwrap();
    recovery.binding.operation_id = [11; 32];
    assert_eq!(
        error(owner.reserve(&recovery, NOW)),
        "RESOURCE_OWNER_RECOVERY_LINK"
    );
    assert_eq!(owner.snapshot().unwrap().lanes[2].unresolved_operations, 1);
}

#[test]
fn independent_file_lock_refuses_admission_without_partial_reservation() {
    let (directory, owner) = fixture();
    let before = owner.snapshot().unwrap();
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join(JOURNAL_NAME))
        .unwrap();
    held.try_lock_exclusive().unwrap();
    assert_eq!(
        error(owner.reserve(&request(1, ClassV1::Bootstrap), NOW)),
        "RESOURCE_OWNER_BUSY"
    );
    drop(held);
    assert_eq!(owner.snapshot().unwrap().record_hash, before.record_hash);
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    assert_held(&owner, OperationStateV1::Reserved);
}

#[test]
fn active_node_owner_prevents_adoption_before_any_journal_is_created() {
    let directory = node_directory();
    let held = OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("owner.lock"))
        .unwrap();
    held.try_lock_exclusive().unwrap();
    assert!(ResourceOwnerV1::initialize(directory.path(), &profile()).is_err());
    assert!(!directory.path().join(JOURNAL_NAME).exists());
    drop(held);
    ResourceOwnerV1::initialize(directory.path(), &profile()).unwrap();
}

#[test]
fn global_record_and_file_caps_refuse_without_creating_or_repairing_credit() {
    let directory = node_directory();
    let mut oversized = profile();
    oversized.max_operations = [400; 3];
    assert_eq!(
        error(ResourceOwnerV1::initialize(directory.path(), &oversized)),
        "RESOURCE_OWNER_SLOTS"
    );
    assert!(!directory.path().join(JOURNAL_NAME).exists());
    let mut missing_overshoot = profile();
    missing_overshoot.overshoot.cpu_ns = 0;
    assert_eq!(
        error(ResourceOwnerV1::initialize(
            directory.path(),
            &missing_overshoot
        )),
        "RESOURCE_OWNER_OVERSHOOT_REQUIRED"
    );
    assert!(!directory.path().join(JOURNAL_NAME).exists());
    let owner = ResourceOwnerV1::initialize(directory.path(), &profile()).unwrap();
    let journal = OpenOptions::new()
        .write(true)
        .open(directory.path().join(JOURNAL_NAME))
        .unwrap();
    journal.set_len(MAX_BYTES + 1).unwrap();
    assert_eq!(error(owner.snapshot()), "RESOURCE_OWNER_JOURNAL_SIZE");
    assert_eq!(
        fs::metadata(directory.path().join(JOURNAL_NAME))
            .unwrap()
            .len(),
        MAX_BYTES + 1
    );
}

fn last_frame_start(bytes: &[u8]) -> usize {
    let mut offset = 8;
    loop {
        let length = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        let next = offset + 4 + length + 32;
        if next == bytes.len() {
            return offset;
        }
        assert!(next < bytes.len());
        offset = next;
    }
}
fn replace_last_payload(bytes: &mut Vec<u8>, payload: &[u8]) {
    let start = last_frame_start(bytes);
    bytes.truncate(start);
    bytes.extend((payload.len() as u32).to_le_bytes());
    bytes.extend(payload);
    bytes.extend(digest(FRAME_DOMAIN, payload));
}

#[test]
fn malformed_torn_and_inconsistent_journals_are_never_auto_repaired() {
    for case in [
        "magic",
        "torn",
        "hash",
        "json",
        "chain",
        "sequence",
        "canonical",
        "length",
    ] {
        let (directory, owner) = fixture();
        drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
        let path = directory.path().join(JOURNAL_NAME);
        let mut bytes = fs::read(&path).unwrap();
        match case {
            "magic" => bytes[0] ^= 1,
            "torn" => {
                bytes.pop();
            }
            "hash" => {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
            }
            "json" => replace_last_payload(&mut bytes, b"{"),
            "chain" | "sequence" | "canonical" => {
                let start = last_frame_start(&bytes);
                let len = u32::from_le_bytes(bytes[start..start + 4].try_into().unwrap()) as usize;
                let mut frame: Frame =
                    serde_json::from_slice(&bytes[start + 4..start + 4 + len]).unwrap();
                if case == "chain" {
                    frame.previous[0] ^= 1;
                }
                if case == "sequence" {
                    frame.sequence += 1;
                }
                let mut payload = serde_json::to_vec(&frame).unwrap();
                if case == "canonical" {
                    payload.push(b' ');
                }
                replace_last_payload(&mut bytes, &payload);
            }
            "length" => bytes[8..12].copy_from_slice(&((MAX_FRAME + 1) as u32).to_le_bytes()),
            _ => unreachable!(),
        }
        fs::write(&path, &bytes).unwrap();
        assert!(owner.snapshot().is_err(), "{case}");
        assert!(
            ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).is_err(),
            "{case}"
        );
        assert!(
            ResourceOwnerV1::initialize(directory.path(), &profile()).is_err(),
            "{case}"
        );
        assert_eq!(fs::read(&path).unwrap(), bytes, "{case}");
    }
}

#[test]
fn journal_symlink_hardlink_permissions_and_replacement_node_are_refused() {
    for case in ["symlink", "hardlink", "mode"] {
        let (directory, owner) = fixture();
        let journal = directory.path().join(JOURNAL_NAME);
        let alternate = directory.path().join("journal-alternate");
        match case {
            "symlink" => {
                fs::rename(&journal, &alternate).unwrap();
                symlink(&alternate, &journal).unwrap();
            }
            "hardlink" => fs::hard_link(&journal, &alternate).unwrap(),
            "mode" => fs::set_permissions(&journal, fs::Permissions::from_mode(0o640)).unwrap(),
            _ => unreachable!(),
        }
        assert!(owner.snapshot().is_err(), "{case}");
        assert!(
            ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).is_err(),
            "{case}"
        );
    }
    let (original, owner) = fixture();
    let replacement = node_directory();
    fs::copy(
        original.path().join(JOURNAL_NAME),
        replacement.path().join(JOURNAL_NAME),
    )
    .unwrap();
    assert_eq!(
        error(ResourceOwnerV1::open(
            replacement.path(),
            profile().id().unwrap()
        )),
        "RESOURCE_OWNER_NODE_IDENTITY"
    );
    assert_eq!(
        owner.snapshot().unwrap().lanes[0].available,
        Some(profile().grants[0])
    );
}

#[test]
fn missing_insecure_or_aliased_native_files_never_become_original_node() {
    let missing = tempfile::tempdir().unwrap();
    assert!(ResourceOwnerV1::initialize(missing.path(), &profile()).is_err());
    assert!(!missing.path().join(JOURNAL_NAME).exists());
    for case in ["directory-mode", "native-symlink", "native-hardlink"] {
        let (directory, owner) = fixture();
        let native = directory.path().join("native.sqlite");
        let alternate = directory.path().join("native-alternate.sqlite");
        match case {
            "directory-mode" => {
                fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o770)).unwrap()
            }
            "native-symlink" => {
                fs::rename(&native, &alternate).unwrap();
                symlink(&alternate, &native).unwrap();
            }
            "native-hardlink" => fs::hard_link(&native, &alternate).unwrap(),
            _ => unreachable!(),
        }
        assert!(owner.snapshot().is_err(), "{case}");
        assert!(
            ResourceOwnerV1::open(directory.path(), profile().id().unwrap()).is_err(),
            "{case}"
        );
    }
}

#[test]
fn canonical_node_alias_cannot_create_a_second_resource_epoch() {
    let (directory, owner) = fixture();
    drop(fresh(&owner, &request(1, ClassV1::Bootstrap)));
    let aliases = tempfile::tempdir().unwrap();
    let alias = aliases.path().join("same-node");
    symlink(directory.path(), &alias).unwrap();
    let alias_owner = ResourceOwnerV1::open(&alias, profile().id().unwrap()).unwrap();
    assert_eq!(alias_owner.node_path(), owner.node_path());
    assert_eq!(
        alias_owner.snapshot().unwrap().record_hash,
        owner.snapshot().unwrap().record_hash
    );
    assert!(ResourceOwnerV1::initialize(&alias, &profile()).is_err());
    assert_held(&alias_owner, OperationStateV1::Reserved);
}
