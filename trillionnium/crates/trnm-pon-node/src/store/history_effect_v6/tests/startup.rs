//! Original paid Startup controls. These add no credit, signed allowance, retry
//! or timeout to the existing complete suite. Synthetic material remains a codec
//! fixture; the small seal unit controls below do not establish startup authority.
use super::*;
use crate::operator_checkpoint_tile::{
    CheckpointTileRuntimePaths, CurrentStartupMaterial, HistoryCheckpointInput, ReplayProgress,
};
use std::cell::{Cell, RefCell};
use std::os::unix::fs::PermissionsExt;
use trnm_mvcc_fee::checkpoint_tile_material_v1::MaterialPhase;

fn load(path: &Path, sha: &str) -> ProtectedHistoryV6Input {
    ProtectedHistoryV6Input::load(path, rustix::process::geteuid().as_raw(), sha).unwrap()
}
fn failed(result: Result<HistoryEffectV6>) -> Error {
    match result {
        Ok(_) => panic!("interrupted Startup unexpectedly returned an owner"),
        Err(error) => error,
    }
}
fn settlement(a: &TestAuthority, expected: &str) -> journal::CpuReceipt {
    let mut records: Vec<_> = fs::read_dir(&a.journal)
        .unwrap()
        .map(|row| row.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("000000000000000000")
        })
        .collect();
    records.sort();
    let raw = fs::read(records.last().unwrap()).unwrap();
    let frame: journal::Frame = serde_json::from_slice(&raw).unwrap();
    let outside = Anchor {
        sequence: frame.sequence,
        digest: policy::digest(&raw),
    };
    let journal::Event::Settlement {
        native_id,
        native_error,
        cpu,
        ..
    } = frame.event
    else {
        panic!("failed Startup must persist its actual settlement");
    };
    assert_eq!(native_id, None);
    assert_eq!(native_error.as_deref(), Some(expected));
    assert!(cpu.known() && cpu.total_cpu_ns.unwrap() > 0);
    assert_eq!(cpu.spawned_workers, 0);
    assert_eq!(cpu.scoped_worker_cpu_ns, Some(0));
    let cold = journal::Journal::open(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &outside,
    )
    .unwrap()
    .observation();
    assert!(cold["pending"].is_null());
    assert_eq!(cold["known_settlements"], 1);
    assert_eq!(cold["used_operations"], 1);
    assert_eq!(cold["spent"]["cpu_ns"], 4_000_000_000u64);
    // A failed Startup does not fabricate a clean-close or authorize a restart.
    assert!(!cold["epoch"].is_null());
    let evidence = json!({"error":expected,"cpu":cpu,"cold_journal":cold,
        "new_startup_authority_granted":false,"original_allowance_ns":4_000_000_000u64});
    write_value(
        &a.f.dir.path().join("startup-control-result.json"),
        &evidence,
    );
    eprintln!("HISTORY_V6_STARTUP_CONTROL {evidence}");
    cpu
}

#[test]
fn cancellation_reaches_material_second_hash_and_both_state_reads() {
    for target in 0..8 {
        let a = TestAuthority::new();
        let _retain = process::retain_fixture(a.f.dir.path(), &format!("startup-cancel-{target}"));
        let (path, sha) = a.launch("cancel", 1, 1, a.genesis(), a.installed.clone());
        let cancel = HistoryEffectV6StartupCancellation::for_operation(&a.id(1)).unwrap();
        let entered = RefCell::new(Vec::new());
        let state_count = Cell::new(0);
        let triggered = Cell::new(false);
        let result = HistoryEffectV6::open_with_startup_progress(
            &a.store,
            load(&path, &sha),
            2,
            deadline(),
            Some(&cancel),
            &|event| {
                assert!(
                    !triggered.get(),
                    "a later callback ran after owner cancellation"
                );
                entered.borrow_mut().push(event);
                let selected = match (target, event) {
                    (0..=3, StartupProgress::Material(ReplayProgress::Material(point))) => {
                        let phase = [
                            MaterialPhase::ActivationHex,
                            MaterialPhase::WeightQuantization,
                            MaterialPhase::TaskHash,
                            MaterialPhase::DescriptorEncoding,
                        ][target];
                        point.phase == phase && point.completed >= 256
                    }
                    (4, StartupProgress::Material(ReplayProgress::SecondCheckpointHash(at))) => {
                        at >= 65536
                    }
                    (5, StartupProgress::Material(ReplayProgress::SecondActivationHash(at))) => {
                        at > 0
                    }
                    (6, StartupProgress::FirstState) | (7, StartupProgress::SecondState) => {
                        state_count.set(state_count.get() + 1);
                        state_count.get() == 3 // inside the actual first SQL row
                    }
                    _ => false,
                };
                if selected {
                    triggered.set(true);
                    cancel.cancel();
                }
                Ok(())
            },
        );
        assert!(
            triggered.get(),
            "target {target} never reached; {entered:?}"
        );
        assert_eq!(failed(result).to_string(), "HISTORY_V6_CANCELLED");
        let cpu = settlement(&a, "HISTORY_V6_CANCELLED");
        assert!(!cpu.live_refused && !cpu.accounting_unavailable);
    }
}

fn thread_cpu_ns() -> u64 {
    let at = rustix::time::clock_gettime(rustix::time::ClockId::ThreadCPUTime);
    u64::try_from(at.tv_sec).unwrap() * 1_000_000_000 + u64::try_from(at.tv_nsec).unwrap()
}
#[test]
fn original_cpu_deadline_and_signed_expiry_interrupt_interior_material() {
    for mode in ["cpu", "deadline", "expiry", "budget-expiry"] {
        let a = if mode == "budget-expiry" {
            TestAuthority::with_budget_lifetime(12_000_000_000)
        } else {
            TestAuthority::new()
        };
        let _retain = process::retain_fixture(a.f.dir.path(), &format!("startup-{mode}"));
        let (path, sha) = a.launch(mode, 1, 1, a.genesis(), a.installed.clone());
        let expires = if mode == "budget-expiry" {
            serde_json::from_slice::<Value>(&a.budget).unwrap()["body"]["expires_ns"]
                .as_u64()
                .unwrap()
        } else {
            policy::now().unwrap() + 12_000_000_000
        };
        let (path, sha) = if mode == "expiry" {
            let mut value = read(&path);
            let raw: Vec<u8> = serde_json::from_value(value["signed_startup"].clone()).unwrap();
            let signed_value: Value = serde_json::from_slice(&raw).unwrap();
            let mut op: Operation = serde_json::from_value(signed_value["body"].clone()).unwrap();
            op.expires_ns = expires;
            value["signed_startup"] = json!(signed(b'O', &op));
            let path = a.f.dir.path().join("launch-fresh-expiry.json");
            let sha = write_value(&path, &value);
            (path, sha)
        } else {
            (path, sha)
        };
        let until = if mode == "deadline" {
            Instant::now() + Duration::from_secs(12)
        } else {
            deadline()
        };
        let triggered = Cell::new(false);
        let result = HistoryEffectV6::open_with_startup_progress(
            &a.store,
            load(&path, &sha),
            2,
            until,
            None,
            &|event| {
                assert!(
                    !triggered.get(),
                    "owner refusal did not stop the material callback"
                );
                if matches!(event, StartupProgress::Material(ReplayProgress::Material(point))
                    if point.phase == MaterialPhase::WeightQuantization && point.completed >= 256)
                {
                    triggered.set(true);
                    if mode == "cpu" {
                        let stop = thread_cpu_ns() + 2_100_000_000;
                        while thread_cpu_ns() < stop {
                            for value in 0..4096u64 {
                                std::hint::black_box(value.wrapping_mul(7919));
                            }
                        }
                    } else if mode == "deadline" {
                        while Instant::now() < until {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    } else {
                        while policy::now()? < expires {
                            std::thread::sleep(Duration::from_millis(2));
                        }
                    }
                }
                Ok(())
            },
        );
        assert!(
            triggered.get(),
            "actual interior boundary was not reached: {mode}"
        );
        let expected = match mode {
            "cpu" => "PUBLIC_MUTATION_CPU_BUDGET",
            "deadline" => "HISTORY_V6_DEADLINE",
            _ => "HISTORY_V6_OPERATION_EXPIRED",
        };
        assert_eq!(failed(result).to_string(), expected);
        let cpu = settlement(&a, expected);
        assert_eq!(cpu.live_refused, mode == "cpu");
        if mode == "cpu" {
            assert!(cpu.total_cpu_ns.unwrap() > 2_000_000_000);
        }
    }
}

fn role(f: &Fixture, name: &str) -> PathBuf {
    f.material_inputs()
        .into_iter()
        .find(|row| row.role == name)
        .unwrap()
        .path
}
#[test]
fn consumed_material_seal_rechecks_actual_handles_bytes_and_current_context() {
    // This unit control exercises seal ownership using real paid CPU handles.
    // Only the public-entry controls above exercise durable Startup authority.
    for variant in [
        "valid", "newline", "intent", "cpu", "cancel", "deadline", "budget", "settings", "spec",
        "replace", "bytes",
    ] {
        let f = Fixture::new();
        let _retain = process::retain_fixture(f.dir.path(), &format!("startup-seal-{variant}"));
        let domain = ServiceMutationCpuDomain::standalone();
        let operation = domain.begin().unwrap();
        let scope = StartupScope {
            intent_sha256: policy::digest(b"unit-scope-not-startup-authority"),
            checkpoint: operation.checkpoint_handle(),
            cancelled: Arc::new(AtomicBool::new(false)),
            deadline: deadline(),
            budget_expires_ns: policy::now().unwrap() + 60_000_000_000,
        };
        let mut spec_raw = fs::read(role(&f, "spec")).unwrap();
        let mut bundle_raw = fs::read(role(&f, "bootstrap")).unwrap();
        if variant == "newline" {
            spec_raw.push(b'\n');
            bundle_raw.push(b'\n');
        }
        let model = fs::read(role(&f, "model")).unwrap();
        let input = fs::read(role(&f, "input")).unwrap();
        let checkpoint = role(&f, "checkpoint");
        let activation = role(&f, "activation");
        let prepared = Settings::prepare_history_checkpoint(
            HistoryCheckpointInput {
                spec: &spec_raw,
                bundle: &bundle_raw,
                model: &model,
                input: &input,
            },
            CheckpointTileRuntimePaths::new(checkpoint.clone(), activation.clone()),
            scope.clone(),
            &|_| operation.checkpoint(),
        )
        .unwrap();
        let (mut settings, seal) = prepared.into_parts();
        assert_eq!(settings.genesis, f.settings.genesis);
        assert_eq!(settings.initial, f.settings.initial);
        let mut current = scope.clone();
        let mut other_operation = None;
        match variant {
            "intent" => current.intent_sha256 = policy::digest(b"different-intent"),
            "cpu" => {
                let other = domain.begin().unwrap();
                current.checkpoint = other.checkpoint_handle();
                other_operation = Some(other);
            }
            "cancel" => current.cancelled = Arc::new(AtomicBool::new(false)),
            "deadline" => current.deadline += Duration::from_secs(1),
            "budget" => current.budget_expires_ns += 1,
            "settings" => {
                settings.initial.insert("meta:issued".into(), json!(1));
            }
            "spec" => spec_raw[0] ^= 1,
            "replace" => {
                let replacement = f.dir.path().join("replacement.safetensors");
                fs::copy(&checkpoint, &replacement).unwrap();
                fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
                fs::rename(replacement, &checkpoint).unwrap();
            }
            "bytes" => {
                let mut bytes = fs::read(&checkpoint).unwrap();
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                fs::write(&checkpoint, bytes).unwrap();
            }
            _ => {}
        }
        let second_checkpoint = Cell::new(0);
        let second_activation = Cell::new(0);
        let result = seal.verify_and_consume(
            &settings,
            CurrentStartupMaterial {
                scope: current,
                spec: &spec_raw,
                bundle: &bundle_raw,
                model: &model,
                input: &input,
            },
            &|event| {
                operation.checkpoint()?;
                match event {
                    ReplayProgress::SecondCheckpointHash(at) => second_checkpoint.set(at),
                    ReplayProgress::SecondActivationHash(at) => second_activation.set(at),
                    _ => {}
                }
                Ok(())
            },
        );
        if matches!(variant, "valid" | "newline") {
            result.unwrap();
            assert_eq!(
                second_checkpoint.get(),
                fs::metadata(&checkpoint).unwrap().len()
            );
            assert_eq!(
                second_activation.get(),
                fs::metadata(&activation).unwrap().len()
            );
        } else {
            let expected = match variant {
                "settings" | "spec" => "HISTORY_V6_STARTUP_SEAL_CONTEXT",
                "replace" | "bytes" => "CHECKPOINT_FILE_CHANGED",
                _ => "HISTORY_V6_STARTUP_SEAL_SCOPE",
            };
            assert_eq!(result.unwrap_err().to_string(), expected, "{variant}");
        }
        if let Some(other) = other_operation {
            assert!(!other.finish().accounting_unavailable);
        }
        assert!(!operation.finish().accounting_unavailable);
    }
}

#[test]
fn startup_cancellation_handle_cannot_select_another_signed_operation() {
    let a = TestAuthority::new();
    let (path, sha) = a.launch("wrong-cancel", 1, 1, a.genesis(), a.installed.clone());
    let cancellation = HistoryEffectV6StartupCancellation::for_operation(&a.id(2)).unwrap();
    cancellation.cancel();
    assert_eq!(
        failed(HistoryEffectV6::open_with_cancellation(
            &a.store,
            load(&path, &sha),
            2,
            deadline(),
            &cancellation,
        ))
        .to_string(),
        "HISTORY_V6_STARTUP_CANCEL_BINDING"
    );
    let journal = journal::Journal::open(
        &a.journal,
        rustix::process::geteuid().as_raw(),
        &a.identity,
        &a.installed,
    )
    .unwrap();
    assert_eq!(journal.observation()["used_operations"], 0);
    assert_eq!(journal.observation()["spent"]["cpu_ns"], 0);
}
