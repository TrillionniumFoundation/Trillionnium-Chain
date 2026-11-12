//! SP27-02's separately selected native health gate. Historical pair semantics
//! and the original Host/permission/resource checks remain owned by the parent
//! harness. Every completed phase is saved before deciding whether to continue.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    any::Any,
    io::{Read, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
};

const HEALTH_REPEATS: usize = 3;
const WINDOW_NS: u64 = PRESSURE_MS * 1_000_000;

fn write_new_json(path: &Path, value: &Value) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    let bytes = serde_json::to_vec_pretty(value).map_err(std::io::Error::other)?;
    file.write_all(&bytes)?;
    file.write_all(b"\n")?;
    file.sync_all()
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let used = file.read(&mut buffer)?;
        if used == 0 {
            return Ok(hex::encode(digest.finalize()));
        }
        digest.update(&buffer[..used]);
    }
}

fn identity_record() -> Value {
    let executable = std::env::current_exe();
    let binary = executable
        .as_ref()
        .map_err(|error| error.to_string())
        .and_then(|path| sha256_file(path).map_err(|error| error.to_string()));
    let read = |path| fs::read_to_string(path).map(|value| value.trim().to_owned());
    json!({
        "schema": "sp27-receiver-run-identity-v1",
        "pid": std::process::id(),
        "hostname": read("/proc/sys/kernel/hostname").ok(),
        "boot_id": read("/proc/sys/kernel/random/boot_id").ok(),
        "process_cgroup": read("/proc/self/cgroup").ok(),
        "binary_path": executable.as_ref().ok(),
        "binary_sha256": binary.as_ref().ok(),
        "binary_identity_error": binary.as_ref().err(),
        "compiled_test_source_sha256": hex::encode(Sha256::digest(include_bytes!("../public_v3_from_zero.rs"))),
        "compiled_health_module_sha256": hex::encode(Sha256::digest(include_bytes!("sp27_receiver_controls.rs"))),
        "runner_declared_source_sha": std::env::var("TRNM_SP27_SOURCE_SHA").ok(),
        "runner_declared_run_id": std::env::var("TRNM_SP27_RUN_ID").ok(),
        "github_run_id": std::env::var("GITHUB_RUN_ID").ok(),
        "github_run_attempt": std::env::var("GITHUB_RUN_ATTEMPT").ok(),
        "identity_scope": "actual executable bytes, compiled source bytes and local process facts; declared runner/git identities require independent runner readback",
    })
}

fn host_record() -> Value {
    use trnm_pon_node::host_kernel_parent::{
        require_host_kernel_budget, FIXED_PUBLIC_KERNEL_PARENT,
    };
    // Read the SAME fixed parent through its existing native checker. This call
    // cannot provision, delegate, replace, widen, or migrate a resource group.
    // The address selects the check's public-service eligibility requirement;
    // this observation does not open an externally reachable listener.
    match require_host_kernel_budget(
        "0.0.0.0:0".parse().unwrap(),
        Some(FIXED_PUBLIC_KERNEL_PARENT),
    ) {
        Ok(Some(budget)) => match budget.verify().and_then(|()| budget.resource_sample()) {
            Ok(sample) => json!({"schema": "sp27-receiver-host-readback-v1",
                "fixed_parent": FIXED_PUBLIC_KERNEL_PARENT, "verified": true,
                "sample": sample, "error": null,
                "scope": "native bounded-parent eligibility; exact runner limits and exclusivity need runner receipts"}),
            Err(error) => json!({"schema": "sp27-receiver-host-readback-v1",
                "fixed_parent": FIXED_PUBLIC_KERNEL_PARENT, "verified": false,
                "sample": null, "error": error.to_string()}),
        },
        Ok(None) => json!({"schema": "sp27-receiver-host-readback-v1",
            "fixed_parent": FIXED_PUBLIC_KERNEL_PARENT, "verified": false,
            "sample": null, "error": "REQUIRED_NATIVE_PARENT_NOT_RETURNED"}),
        Err(error) => json!({"schema": "sp27-receiver-host-readback-v1",
            "fixed_parent": FIXED_PUBLIC_KERNEL_PARENT, "verified": false,
            "sample": null, "error": error.to_string()}),
    }
}

fn planned_controls() -> Value {
    json!([
        {"stratum": "transport", "status": "PLANNED_NOT_EXECUTED",
         "variable": "transport/admission load before W1",
         "legality": "must declare exact valid transport body and reached native stage",
         "arrival_load": "connections, bytes and arrival timestamps must be matched; a small Head is not an equal-byte control",
         "validation_stage": "transport only; not established by request label",
         "stop": "unhealthy no-pressure control, Host error, observation loss, state-integrity failure, or four-second end"},
        {"stratum": "early-reject", "status": "PLANNED_NOT_EXECUTED",
         "variable": "rejection before full W1 replay",
         "legality": "well-defined invalid input with native precheck rejection; not an accepted proof",
         "arrival_load": "same negotiated connection policy and recorded bytes/rate as late-reject",
         "validation_stage": "prove full_work_started=false with complete observer coverage",
         "stop": "unexpected acceptance, unhealthy no-pressure control, Host/coverage error, or four-second end"},
        {"stratum": "late-reject", "status": "PLANNED_NOT_EXECUTED",
         "variable": "full W1 replay before false-transcript rejection",
         "legality": "task/ticket prechecks pass; mathematical relation remains invalid",
         "arrival_load": "record realized offered/admitted load, failed calls and carried cache state",
         "validation_stage": "native full-work and rejection observations; label alone is insufficient",
         "stop": "unexpected acceptance, unhealthy no-pressure control, Host/coverage error, or four-second end"},
        {"stratum": "valid-expensive", "status": "PLANNED_NOT_EXECUTED",
         "variable": "valid expensive work and any resulting state/queue interaction",
         "legality": "native-valid proof; successful acceptance is an expected possible outcome",
         "arrival_load": "same total bounded offered load, with complete producer preparation and failure costs",
         "validation_stage": "full W1 plus actual admission; duplicate/parent/state effects must be separated",
         "stop": "business identity/state confound, unhealthy no-pressure control, Host/coverage error, or four-second end"}
    ])
}

fn healthy(phase: &Value) -> bool {
    // The final native gate is authoritative. A logged endpoint smaller than T
    // cannot convert a false/missing native final gate into confirmation.
    phase["requested_window_ns"].as_u64() == Some(WINDOW_NS)
        && phase["workers"].as_u64() == Some(0)
        && phase["invariant_target_met"].as_bool() == Some(true)
        && phase["finite_business_target_met"].as_bool() == Some(true)
        && phase["client_confirmed_before_original_window_end"].as_bool() == Some(true)
        && phase["client_confirmed_transactions"].as_u64() == Some(1)
        && phase["confirmation_ended_ns"]
            .as_u64()
            .is_some_and(|end| end < WINDOW_NS)
        && phase["verification_errors"]
            .as_array()
            .is_some_and(|errors| errors.is_empty())
        && phase["full_native_state_equal"].as_bool() == Some(true)
}

fn first_divergence(phase: &Value, index: usize) -> Value {
    let mut events = Vec::new();
    for field in ["honest_submissions", "honest_history"] {
        if let Some(rows) = phase[field].as_array() {
            for (row_index, row) in rows.iter().enumerate() {
                if row["status"] != "ok"
                    || row["returned_after_window"] != false
                    || row["returned_after_deadline"] != false
                {
                    events.push(json!({"stage": field, "row_index": row_index,
                        "observed_ns": row["ended_ns"], "status": row["status"],
                        "error": row["error"], "response_error": row["response"]["value"]["error"],
                        "returned_after_window": row["returned_after_window"],
                        "returned_after_deadline": row["returned_after_deadline"]}));
                }
            }
        }
    }
    if let Some(rows) = phase["independent_history_page_replay"].as_array() {
        for (row_index, row) in rows.iter().enumerate() {
            if row["replay_accepted"] != true || !row["replay_error"].is_null() {
                events.push(json!({"stage": "independent_history_page_replay",
                    "row_index": row_index, "observed_ns": row["replay_ended_ns"],
                    "error": row["replay_error"],
                    "native_import_observation": row["native_import_observation"]}));
            }
        }
    }
    events.sort_by_key(|event| event["observed_ns"].as_u64().unwrap_or(u64::MAX));
    json!({
        "schema": "sp27-receiver-first-divergence-v1", "health_index": index,
        "qualification": "NO_GO", "raw_record": format!("raw/health-{index:03}.json"),
        "first_recorded_business_anomaly": events.first(), "ordered_business_anomalies": events,
        "event_order_scope": "known completion timestamps sorted ascending; missing timestamps are last and do not establish total chronological order",
        "native_final_gate": phase["client_confirmed_before_original_window_end"],
        "recorded_confirmation_ended_ns": phase["confirmation_ended_ns"],
        "recorded_endpoint_before_T": phase["confirmation_ended_ns"].as_u64().map(|end| end < WINDOW_NS),
        "finite_business_target_met": phase["finite_business_target_met"],
        "invariant_target_met": phase["invariant_target_met"],
        "full_native_state_equal": phase["full_native_state_equal"],
        "verification_errors": phase["verification_errors"],
        "service_error": phase["service"]["error"],
        "causal_status": "UNKNOWN: earliest recorded anomaly may be transient; it is not a proven cause of the final health failure",
        "remaining_health_phases": "NOT_EXECUTED_AFTER_FIRST_FAILURE",
        "pressure_controls": "NOT_EXECUTED_UNHEALTHY_BASELINE",
    })
}

fn panic_text(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string Rust panic payload")
}

fn prepare_business(path: &Path) -> (Settings, Vec<Packet>, Value) {
    let settings = Settings::development(Some(1_750_000_000)).unwrap();
    let mut producer = Node::open(&path.join("producer"), settings.clone(), 1).unwrap();
    let target = producer.expected_target(settings.genesis()).unwrap();
    let (a, b) = maintenance();
    let task = pon_work::task_id(&a, &b).unwrap();
    let tx = confirmation_transfer(
        &settings,
        producer.next_nonce(development_public(0).unwrap()).unwrap(),
    );
    let start = Instant::now();
    let cpu = process_cpu_ns();
    let mut packets = Vec::new();
    for height in 1..=7 {
        let packet = producer
            .mine(
                if height == 1 {
                    vec![tx.clone()]
                } else {
                    vec![]
                },
                settings.genesis_time() + height * 10,
                ingress::now().unwrap(),
            )
            .unwrap();
        assert_eq!(packet.header.target, target);
        assert_eq!(packet.header.work_task, task);
        packets.push(packet);
    }
    let acquisition = json!({
        "schema": "sp27-receiver-seven-packet-acquisition-v1",
        "network": hex::encode(settings.network()), "parameters": hex::encode(settings.parameters()),
        "genesis": hex::encode(settings.genesis()), "target": hex::encode(target),
        "task": hex::encode(task), "policy_id": hex::encode(policy().id()),
        "signed_honest_packets": packets.iter().map(|packet| hex::encode(packet.encode().unwrap())).collect::<Vec<_>>(),
        "packet_ids": packets.iter().map(|packet| hex::encode(packet.id().unwrap())).collect::<Vec<_>>(),
        "honest_chain_acquisition_wall_ns": ns(start),
        "honest_chain_process_cpu_ns": cpu.zip(process_cpu_ns()).and_then(|(start, end)| end.checked_sub(start)),
        "process_cpu_scope": "all process threads during seven-block mining; excludes earlier producer open/setup and later service; not pure W1 or exclusive actor CPU",
        "same_seven_packets_in_all_health_phases": true,
    });
    (settings, packets, acquisition)
}

#[test]
#[ignore = "explicit native health gate under the unchanged fixed Host; records NO_GO and stops before any pressure"]
fn repeated_unpressured_confirmation_stops_before_pressure_on_first_divergence() {
    let temporary = tempfile::tempdir().unwrap();
    let path = std::env::var_os("TRNM_SP27_RECEIVER_CONTROLS_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("sp27-receiver-controls"));
    fs::create_dir(&path).unwrap();
    fs::create_dir(path.join("raw")).unwrap();
    write_new_json(&path.join("plan.json"), &json!({
        "schema": "sp27-receiver-controls-plan-v1", "health_repetitions": HEALTH_REPEATS,
        "signed_packets": 7, "confirmation_depth": 6, "requested_window_ns": WINDOW_NS,
        "health_pressure_workers": 0, "pressure_workers_max": PRESSURE_WORKERS,
        "pressure_per_worker_attempt_cap": PRESSURE_CALLS_PER_WORKER,
        "fixed_parent": "/sys/fs/cgroup/trnmponpublic.slice",
        "required_cpu_quota_us": 25000, "required_cpu_period_us": 100000,
        "required_memory_bytes": 2147483648_u64, "required_swap_bytes": 0,
        "host_limits_and_exclusivity_owner": "existing fixed-Host runner; this test cannot provision resources",
        "health_state": "each phase opens fresh receiver and independent verifier; same acquired seven packets",
        "phase_order": "three unpressured health repetitions, stopping at first failure; pressure controls remain unexecuted in this selector",
        "future_pressure_order": "must be randomized or balanced in a separately frozen executable plan",
        "pressure_controls": planned_controls(),
        "success_scope": "health gate only; not causal attack evidence or publication qualification",
    })).unwrap();
    let before = identity_record();
    write_new_json(&path.join("identity-before.json"), &before).unwrap();
    let host_before = host_record();
    write_new_json(&path.join("host-before.json"), &host_before).unwrap();
    let mut completed = Vec::new();
    let mut attempted = 0;
    let mut failure = None;
    if host_before["verified"] != true || before["binary_sha256"].as_str().is_none() {
        failure = Some(json!({"schema": "sp27-receiver-first-divergence-v1",
            "qualification": "NO_GO", "stage": "pre-execution-identity-or-host",
            "host": host_before, "binary_identity_error": before["binary_identity_error"],
            "health_phases": "NOT_EXECUTED", "pressure_controls": "NOT_EXECUTED",
            "causal_status": "environment/identity eligibility failure; no attack experiment"}));
    } else {
        write_new_json(
            &path.join("acquisition-started.json"),
            &json!({
                "schema": "sp27-receiver-acquisition-started-v1", "planned_packets": 7,
                "status": "STARTED_NOT_YET_OBSERVED_COMPLETE"
            }),
        )
        .unwrap();
        match catch_unwind(AssertUnwindSafe(|| prepare_business(&path))) {
            Ok((settings, packets, acquisition)) => {
                write_new_json(&path.join("acquisition.json"), &acquisition).unwrap();
                // No pressure worker executes this builder. It deliberately
                // cannot construct a request or acquire a false-proof stream.
                let unused: ConfirmationAttackBuilder = Arc::new(|_, _| {
                    panic!("unpressured health gate must never request a pressure input")
                });
                for index in 0..HEALTH_REPEATS {
                    attempted += 1;
                    write_new_json(
                        &path.join(format!("raw/health-{index:03}-started.json")),
                        &json!({"schema": "sp27-receiver-health-started-v1", "health_index": index,
                            "status": "STARTED_NOT_YET_OBSERVED_COMPLETE", "pressure_workers": 0,
                            "requested_window_ns": WINDOW_NS}),
                    )
                    .unwrap();
                    let phase = catch_unwind(AssertUnwindSafe(|| {
                        signed_confirmation_phase_with_builder(
                            &path.join(format!("health-{index:03}")),
                            &settings,
                            &packets,
                            unused.clone(),
                            false,
                        )
                    }));
                    match phase {
                        Ok(phase) => {
                            // Save the exact original helper object before
                            // classification; annotations are separate files.
                            let raw = format!("raw/health-{index:03}.json");
                            write_new_json(&path.join(&raw), &phase).unwrap();
                            let passed = healthy(&phase);
                            completed.push(json!({"health_index": index, "raw_record": raw,
                                "raw_sha256": sha256_file(&path.join(&raw)).unwrap(),
                                "healthy": passed,
                                "native_final_gate": phase["client_confirmed_before_original_window_end"],
                                "confirmation_ended_ns": phase["confirmation_ended_ns"],
                                "finite_business_target_met": phase["finite_business_target_met"],
                                "invariant_target_met": phase["invariant_target_met"]}));
                            if !passed {
                                failure = Some(first_divergence(&phase, index));
                                break;
                            }
                        }
                        Err(payload) => {
                            let raw = format!("raw/health-{index:03}-panic.json");
                            let panic = json!({"schema": "sp27-receiver-native-panic-v1",
                                "health_index": index, "panic": panic_text(payload.as_ref()),
                                "native_confirmation_result": null,
                                "raw_phase_complete": false});
                            write_new_json(&path.join(&raw), &panic).unwrap();
                            failure = Some(json!({"schema": "sp27-receiver-first-divergence-v1",
                                "qualification": "NO_GO", "stage": "native-health-phase-panic",
                                "health_index": index, "raw_record": raw, "panic": panic,
                                "pressure_controls": "NOT_EXECUTED", "causal_status": "UNKNOWN"}));
                            break;
                        }
                    }
                }
            }
            Err(payload) => {
                failure = Some(json!({"schema": "sp27-receiver-first-divergence-v1",
                    "qualification": "NO_GO", "stage": "honest-packet-acquisition-panic",
                    "panic": panic_text(payload.as_ref()), "health_phases": "NOT_EXECUTED",
                    "pressure_controls": "NOT_EXECUTED", "causal_status": "UNKNOWN"}));
            }
        }
    }
    let host_after = host_record();
    write_new_json(&path.join("host-after.json"), &host_after).unwrap();
    let after = identity_record();
    write_new_json(&path.join("identity-after.json"), &after).unwrap();
    let binary_unchanged =
        before["binary_sha256"].is_string() && before["binary_sha256"] == after["binary_sha256"];
    if failure.is_none() && (host_after["verified"] != true || !binary_unchanged) {
        failure = Some(json!({"schema": "sp27-receiver-first-divergence-v1",
            "qualification": "NO_GO", "stage": "post-execution-identity-or-host",
            "host": host_after, "binary_unchanged": binary_unchanged,
            "pressure_controls": "NOT_EXECUTED", "causal_status": "UNKNOWN"}));
    }
    if let Some(failure) = &failure {
        write_new_json(&path.join("first-divergence.json"), failure).unwrap();
    }
    let health_gate_passed = failure.is_none()
        && completed.len() == HEALTH_REPEATS
        && completed.iter().all(|phase| phase["healthy"] == true);
    let report = json!({
        "schema": "sp27-receiver-health-gate-v1",
        "qualification": if health_gate_passed { "HEALTH_GATE_PASSED_CONTROLS_PENDING" } else { "NO_GO" },
        "health_gate_passed": health_gate_passed, "planned_health_repetitions": HEALTH_REPEATS,
        "attempted_health_repetitions": attempted,
        "completed_health_repetitions": completed.len(), "health_phases": completed,
        "not_executed_health_repetitions": HEALTH_REPEATS - attempted,
        "incomplete_health_repetitions": attempted - completed.len(),
        "requested_window_ns": WINDOW_NS, "binary_unchanged": binary_unchanged,
        "host_before_verified": host_before["verified"], "host_after_verified": host_after["verified"],
        "first_divergence": failure, "pressure_controls": planned_controls(),
        "pressure_controls_executed": 0, "causal_mechanism_status": "UNKNOWN",
        "qualification_requires_runner_exact_limits_and_exclusive_lease": true,
        "native_exit_zero_means": "observation collection finished; read qualification and raw records for health outcome",
        "publication_qualified": false, "public_network_ready": false, "production_activation": false,
    });
    write_new_json(&path.join("report.json"), &report).unwrap();
    println!(
        "{}",
        json!({"schema": report["schema"], "qualification": report["qualification"],
        "report_path": path.join("report.json")})
    );
}

#[test]
fn health_gate_requires_native_final_gate_and_strict_original_deadline() {
    // Synthetic unit observations exercise classification only. They are not
    // saved as native service evidence or included in an experiment denominator.
    let mut value = json!({"requested_window_ns": WINDOW_NS, "workers": 0,
        "invariant_target_met": true, "finite_business_target_met": true,
        "client_confirmed_before_original_window_end": true,
        "client_confirmed_transactions": 1, "confirmation_ended_ns": WINDOW_NS - 1,
        "verification_errors": [], "full_native_state_equal": true});
    assert!(healthy(&value));
    value["client_confirmed_before_original_window_end"] = json!(false);
    assert!(!healthy(&value));
    value
        .as_object_mut()
        .unwrap()
        .remove("client_confirmed_before_original_window_end");
    assert!(!healthy(&value));
    value["client_confirmed_before_original_window_end"] = json!(true);
    for end in [WINDOW_NS, WINDOW_NS + 1] {
        value["confirmation_ended_ns"] = json!(end);
        assert!(!healthy(&value));
    }
    value["confirmation_ended_ns"] = json!(WINDOW_NS - 1);
    value["invariant_target_met"] = json!(false);
    assert!(!healthy(&value));
}

#[test]
fn raw_health_report_is_create_only() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("raw.json");
    let original = json!({"unit_test_only": true, "native_final_gate": false});
    write_new_json(&path, &original).unwrap();
    let before = fs::read(&path).unwrap();
    assert_eq!(
        write_new_json(&path, &json!({"native_final_gate": true}))
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert_eq!(fs::read(path).unwrap(), before);
}
