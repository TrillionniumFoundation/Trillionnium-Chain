//! Bounded balanced controls. Historical native phases and raw schemas stay unchanged.
use super::sp27_receiver_controls::{
    first_divergence, healthy, host_record, identity_record, prepare_business, sha256_file,
    write_new_json,
};
use super::sp27_receiver_strata::{prepare_strata_inputs, strata_phase};
use super::*;
use sha2::{Digest, Sha256};
use std::{any::Any, panic::{catch_unwind, AssertUnwindSafe}, path::Path};

const WINDOW_NS: u64 = 4_000_000_000;
const ARM_NAMES: [&str; 4] = ["transport", "early-reject", "late-reject", "valid-expensive"];
const BALANCED_ORDER: [usize; 8] = [0, 1, 2, 3, 3, 2, 1, 0];

struct PlannedPhase {
    id: String,
    kind: &'static str,
    arm: Option<usize>,
    health_index: Option<usize>,
    control_index: Option<usize>,
}

fn campaign_plan() -> Vec<PlannedPhase> {
    let mut plan = Vec::new();
    for index in 0..3 {
        plan.push(PlannedPhase { id: format!("health-{index:03}"),
            kind: "initial-health", arm: None, health_index: Some(index), control_index: None });
    }
    for (index, arm) in BALANCED_ORDER.into_iter().enumerate() {
        plan.push(PlannedPhase { id: format!("control-{index:03}-{}", ARM_NAMES[arm]),
            kind: "pressure-control", arm: Some(arm), health_index: None, control_index: Some(index) });
        if index == 3 || index == 7 {
            let health_index = if index == 3 { 3 } else { 4 };
            plan.push(PlannedPhase { id: format!("health-{health_index:03}"),
                kind: if index == 3 { "midpoint-sentinel" } else { "terminal-sentinel" },
                arm: None, health_index: Some(health_index), control_index: None });
        }
    }
    plan
}

fn plan_value(index: usize, phase: &PlannedPhase) -> Value {
    json!({ "planned_index": index, "phase_id": phase.id, "kind": phase.kind,
        "arm": phase.arm.map(|arm| ARM_NAMES[arm]), "health_index": phase.health_index,
        "control_index": phase.control_index, "requested_window_ns": WINDOW_NS,
        "workers_max": if phase.arm.is_some() { 16 } else { 0 },
        "per_worker_attempt_cap": if phase.arm.is_some() { 1 } else { 0 },
        "control_scheduled_arrival_ns": if phase.arm.is_some() { Some(100_000_000_u64) } else { None } })
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload.downcast_ref::<String>().map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string Rust panic payload")
}

fn pressure_integrity(phase: &Value) -> bool {
    // A missed business confirmation or accepted valid request is not itself a stop.
    phase["control_integrity_met"] == true
        && phase["requested_window_ns"].as_u64() == Some(WINDOW_NS)
        && phase["workers"].as_u64() == Some(16)
}

fn run_one_phase(
    root: &Path, planned_index: usize, planned: &PlannedPhase,
    records: &mut Vec<Value>, operation: impl FnOnce() -> Value,
) -> Option<Value> {
    let prefix = format!("raw/{}", planned.id);
    let mut record = plan_value(planned_index, planned);
    record["attempted"] = json!(true);
    record["helper_invoked"] = json!(false);
    record["completed"] = json!(false);
    record["raw_phase_record"] = Value::Null;
    record["raw_phase_sha256"] = Value::Null;
    write_new_json(&root.join(format!("{prefix}-started.json")),
        &json!({"schema": "sp27-receiver-campaign-phase-started-v1", "plan": record,
            "status": "STARTED_NOT_YET_OBSERVED_COMPLETE",
            "attempted_scope": "started eligibility check; helper invocation has a separate marker"})).unwrap();
    let before = host_record();
    write_new_json(&root.join(format!("{prefix}-host-before.json")), &before).unwrap();
    record["host_before_verified"] = before["verified"].clone();
    let mut failure = if before["verified"] != true {
        Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
            "qualification": "NO_GO", "stage": "phase-pre-host",
            "phase_id": planned.id, "planned_index": planned_index, "host": before,
            "native_phase_invoked": false, "causal_status": "UNKNOWN"}))
    } else { None };
    if failure.is_none() {
        write_new_json(&root.join(format!("{prefix}-invoked.json")),
            &json!({"schema": "sp27-receiver-campaign-phase-invoked-v1",
                "phase_id": planned.id, "planned_index": planned_index,
                "requested_window_ns": WINDOW_NS, "helper_invoked": true})).unwrap();
        record["helper_invoked"] = json!(true);
        match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(phase) => {
                // Preserve the original returned object before any classification.
                let raw = format!("{prefix}.json");
                write_new_json(&root.join(&raw), &phase).unwrap();
                record["completed"] = json!(true);
                record["raw_phase_record"] = json!(raw);
                record["raw_phase_sha256"] = json!(sha256_file(&root.join(&raw)).unwrap());
                for field in ["confirmation_ended_ns", "client_confirmed_transactions",
                    "control_integrity_met", "invariant_target_met", "finite_business_target_met"] {
                    record[field] = phase[field].clone();
                }
                record["native_final_gate"] =
                    phase["client_confirmed_before_original_window_end"].clone();
                record["business_result_is_not_campaign_integrity"] = json!(planned.arm.is_some());
                if let Some(health_index) = planned.health_index {
                    let passed = healthy(&phase)
                        && phase["requested_window_ns"].as_u64() == Some(WINDOW_NS);
                    record["healthy"] = json!(passed);
                    if !passed {
                        failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                            "qualification": "NO_GO", "stage": "unhealthy-sentinel",
                            "phase_id": planned.id, "kind": planned.kind, "planned_index": planned_index,
                            "native_first_divergence": first_divergence(&phase, health_index),
                            "subsequent_phases": "NOT_EXECUTED_AFTER_FIRST_FAILURE",
                            "causal_status": "UNKNOWN"}));
                    }
                } else if !pressure_integrity(&phase) {
                    failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                        "qualification": "NO_GO", "stage": "control-integrity",
                        "phase_id": planned.id, "planned_index": planned_index,
                        "control_integrity_met": phase["control_integrity_met"],
                        "requested_window_ns": phase["requested_window_ns"], "workers": phase["workers"],
                        "raw_phase_record": record["raw_phase_record"],
                        "native_final_gate": phase["client_confirmed_before_original_window_end"],
                        "business_nonconfirmation_alone_is_not_stop": true, "causal_status": "UNKNOWN"}));
                }
            }
            Err(payload) => {
                let raw = format!("{prefix}-panic.json");
                let panic = json!({"schema": "sp27-receiver-campaign-native-panic-v1",
                    "phase_id": planned.id, "planned_index": planned_index,
                    "panic": panic_message(payload.as_ref()), "raw_phase_complete": false,
                    "native_confirmation_result": null});
                write_new_json(&root.join(&raw), &panic).unwrap();
                record["panic_record"] = json!(raw);
                failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                    "qualification": "NO_GO", "stage": "native-phase-panic",
                    "phase_id": planned.id, "planned_index": planned_index,
                    "panic_record": record["panic_record"], "panic": panic, "causal_status": "UNKNOWN"}));
            }
        }
    }
    let after = host_record();
    write_new_json(&root.join(format!("{prefix}-host-after.json")), &after).unwrap();
    record["host_after_verified"] = after["verified"].clone();
    if after["verified"] != true && failure.is_none() {
        failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
            "qualification": "NO_GO", "stage": "phase-post-host", "phase_id": planned.id,
            "planned_index": planned_index, "host": after, "causal_status": "UNKNOWN"}));
    }
    record["stopped_campaign"] = json!(failure.is_some());
    write_new_json(&root.join(format!("{prefix}-index.json")), &record).unwrap();
    records.push(record);
    failure
}

fn run_health(
    root: &Path, index: usize, planned: &PlannedPhase, settings: &Settings,
    packets: &[Packet], records: &mut Vec<Value>,
) -> Option<Value> {
    let unused: ConfirmationAttackBuilder = Arc::new(|_, _| {
        panic!("unpressured sentinel must not prepare a pressure request")
    });
    run_one_phase(root, index, planned, records, || {
        signed_confirmation_phase_with_builder(
            &root.join(&planned.id), settings, packets, unused, false)
    })
}

fn campaign_identity() -> Value {
    let mut value = identity_record();
    value["compiled_strata_module_sha256"] =
        json!(hex::encode(Sha256::digest(include_bytes!("sp27_receiver_strata.rs"))));
    value["compiled_campaign_module_sha256"] =
        json!(hex::encode(Sha256::digest(include_bytes!("sp27_receiver_campaign.rs"))));
    value
}

fn acquire_control_inputs(root: &Path, settings: &Settings) -> Result<Vec<Arc<Vec<String>>>, Value> {
    write_new_json(&root.join("strata-acquisition-started.json"),
        &json!({"schema": "sp27-receiver-campaign-acquisition-started-v1",
            "kind": "four-control-streams", "initial_health_confirmed": 3,
            "arm_names": ARM_NAMES, "status": "STARTED_NOT_YET_OBSERVED_COMPLETE"})).unwrap();
    let started = Instant::now();
    let cpu_started = process_cpu_ns();
    match catch_unwind(AssertUnwindSafe(|| {
        prepare_strata_inputs(&root.join("strata-acquisition"), settings)
    })) {
        Ok((inputs, acquisition)) => {
            write_new_json(&root.join("strata-input-acquisition-native.json"), &acquisition).unwrap();
            let mut input_index = Vec::new();
            for (index, requests) in inputs.iter().enumerate() {
                let raw = format!("inputs/arm-{index:03}.json");
                write_new_json(&root.join(&raw),
                    &json!({"schema": "sp27-receiver-control-request-stream-v1",
                        "arm_index": index, "arm": ARM_NAMES.get(index),
                        "requests": requests.as_ref(), "request_count": requests.len(),
                        "request_encoding": "packet hex strings serialized as Request::Submit by the native phase",
                        "packet_hex_bytes": requests.iter().map(|s| s.len()).sum::<usize>(),
                        "canonical_submit_body_bytes": requests.iter().map(|s|
                            serde_json::to_vec(&Request::Submit { packet: s.clone() }).unwrap().len())
                            .collect::<Vec<_>>()})).unwrap();
                input_index.push(json!({"arm_index": index, "arm": ARM_NAMES.get(index),
                    "raw_record": raw, "sha256": sha256_file(&root.join(&raw)).unwrap(),
                    "request_count": requests.len()}));
            }
            write_new_json(&root.join("strata-inputs-index.json"),
                &json!({"schema": "sp27-receiver-control-input-index-v1",
                    "inputs": input_index, "wall_ns": ns(started),
                    "process_cpu_ns": cpu_started.zip(process_cpu_ns())
                        .and_then(|(start, end)| end.checked_sub(start)),
                    "cost_scope": "whole process during acquisition and observer persistence; original returned cost object is separate; nested costs are not additive",
                    "same_request_streams_for_balanced_repeats": true})).unwrap();
            if inputs.len() != 4 || inputs.iter().any(|stream| stream.len() != 16) {
                Err(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                    "qualification": "NO_GO", "stage": "invalid-control-input-roster",
                    "arm_count": inputs.len(), "required_requests_per_arm": 16, "causal_status": "UNKNOWN"}))
            } else { Ok(inputs) }
        }
        Err(payload) => {
            let failure = json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                "qualification": "NO_GO", "stage": "strata-input-acquisition-panic",
                "panic": panic_message(payload.as_ref()), "causal_status": "UNKNOWN"});
            write_new_json(&root.join("strata-acquisition-panic.json"), &failure).unwrap();
            Err(failure)
        }
    }
}

#[test]
#[ignore = "explicit balanced native controls under the original fixed Host; first unhealthy sentinel or integrity failure stops collection"]
fn balanced_native_stage_controls_stop_on_unhealthy_sentinel() {
    let temporary = tempfile::tempdir().unwrap();
    let root = std::env::var_os("TRNM_SP27_RECEIVER_STRATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| temporary.path().join("sp27-receiver-strata"));
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("raw")).unwrap();
    fs::create_dir(root.join("inputs")).unwrap();
    let plan = campaign_plan();
    let planned: Vec<_> = plan.iter().enumerate()
        .map(|(index, phase)| plan_value(index, phase)).collect();
    write_new_json(&root.join("plan.json"),
        &json!({"schema": "sp27-receiver-strata-campaign-plan-v1",
            "planned_phases": planned, "initial_health_repetitions": 3,
            "control_phase_count": 8, "sentinel_count": 2,
            "arm_names": ARM_NAMES, "balanced_arm_indices": BALANCED_ORDER,
            "order_kind": "predeclared forward and reverse; not randomized",
            "same_seven_signed_packets": true, "confirmation_depth": 6,
            "requested_window_ns": WINDOW_NS, "pressure_workers_max": 16,
            "pressure_per_worker_attempt_cap": 1, "control_scheduled_arrival_ns": 100_000_000_u64,
            "global_per_worker_attempt_ceiling": 1024,
            "fixed_parent": "/sys/fs/cgroup/trnmponpublic.slice",
            "required_cpu_quota_us": 25000, "required_cpu_period_us": 100000,
            "required_memory_bytes": 2147483648_u64, "required_swap_bytes": 0,
            "outer_selector_timeout_seconds": 90,
            "resource_lease_owner": "original Host runner; this module cannot provision or relax resources",
            "pressure_input_preparation": "only after three healthy phases; original inputs and full returned cost object retained",
            "phase_state": "fresh receiver and independent verifier; same input stream for balanced repeats",
            "stop_rule": "first unhealthy initial/sentinel phase, Host/identity failure, native panic, or control_integrity_met not true",
            "pressure_business_failure": "retained outcome; does not alone stop the campaign",
            "valid_expensive_acceptance": "not an attack failure; integrity must record business/state confounds",
            "outer_timeout_scope": "runner preserves incomplete started phases; original deadline remains unchanged"})).unwrap();
    let before = campaign_identity();
    write_new_json(&root.join("identity-before.json"), &before).unwrap();
    let host_before = host_record();
    write_new_json(&root.join("host-before.json"), &host_before).unwrap();
    let mut records = Vec::new();
    let mut failure = None;
    let mut acquired_inputs = false;
    let mut initial_health_passed = false;
    if host_before["verified"] != true || before["binary_sha256"].as_str().is_none() {
        failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
            "qualification": "NO_GO", "stage": "pre-execution-identity-or-host",
            "host": host_before, "binary_identity_error": before["binary_identity_error"],
            "phases_executed": 0, "causal_status": "UNKNOWN"}));
    } else {
        write_new_json(&root.join("business-acquisition-started.json"),
            &json!({"schema": "sp27-receiver-campaign-acquisition-started-v1",
                "kind": "honest-seven-packets", "status": "STARTED_NOT_YET_OBSERVED_COMPLETE"})).unwrap();
        match catch_unwind(AssertUnwindSafe(|| prepare_business(&root))) {
            Ok((settings, packets, acquisition)) => {
                write_new_json(&root.join("business-acquisition.json"), &acquisition).unwrap();
                for (index, phase) in plan.iter().take(3).enumerate() {
                    failure = run_health(&root, index, phase, &settings, &packets, &mut records);
                    if failure.is_some() { break; }
                }
                initial_health_passed = failure.is_none() && records.len() == 3;
                if initial_health_passed {
                    match acquire_control_inputs(&root, &settings) {
                        Ok(inputs) => {
                            acquired_inputs = true;
                            for (index, phase) in plan.iter().enumerate().skip(3) {
                                failure = if let Some(arm) = phase.arm {
                                    run_one_phase(&root, index, phase, &mut records, || {
                                        strata_phase(&root.join(&phase.id), &settings, &packets,
                                            inputs[arm].clone(), ARM_NAMES[arm])
                                    })
                                } else {
                                    run_health(&root, index, phase, &settings, &packets, &mut records)
                                };
                                if failure.is_some() { break; }
                            }
                        }
                        Err(value) => { failure = Some(value); }
                    }
                }
            }
            Err(payload) => {
                failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
                    "qualification": "NO_GO", "stage": "business-acquisition-panic",
                    "panic": panic_message(payload.as_ref()), "causal_status": "UNKNOWN"}));
                write_new_json(&root.join("business-acquisition-panic.json"), failure.as_ref().unwrap()).unwrap();
            }
        }
    }
    let host_after = host_record();
    write_new_json(&root.join("host-after.json"), &host_after).unwrap();
    let after = campaign_identity();
    write_new_json(&root.join("identity-after.json"), &after).unwrap();
    let binary_unchanged = before["binary_sha256"].is_string()
        && before["binary_sha256"] == after["binary_sha256"];
    if failure.is_none() && (host_after["verified"] != true || !binary_unchanged) {
        failure = Some(json!({"schema": "sp27-receiver-campaign-first-divergence-v1",
            "qualification": "NO_GO", "stage": "post-execution-identity-or-host",
            "host": host_after, "binary_unchanged": binary_unchanged, "causal_status": "UNKNOWN"}));
    }
    if let Some(value) = &failure {
        write_new_json(&root.join("first-divergence.json"), value).unwrap();
    }
    let completed = records.iter().filter(|p| p["completed"] == true).count();
    let invoked = records.iter().filter(|p| p["helper_invoked"] == true).count();
    let controls: Vec<_> = records.iter().filter(|p| p["kind"] == "pressure-control").collect();
    let control_completed = controls.iter().filter(|p| p["completed"] == true).count();
    let health: Vec<_> = records.iter().filter(|p| p["kind"] != "pressure-control").collect();
    let collected = failure.is_none() && completed == plan.len() && acquired_inputs;
    let report = json!({
        "schema": "sp27-receiver-strata-campaign-v1",
        "qualification": if collected { "COLLECTED_CONTROL_SERIES" } else { "NO_GO" },
        "planned_phases": plan.len(), "attempted_phases": records.len(),
        "helper_invoked_phases": invoked, "completed_phases": completed,
        "incomplete_phases": records.len() - completed, "unstarted_phases": plan.len() - records.len(),
        "attempted_scope": "phase started marker includes Host eligibility; helper_invoked counts actual native calls",
        "health_gate_passed": initial_health_passed,
        "planned_health_repetitions": 3, "planned_sentinels": 2,
        "healthy_completed_phases": health.iter().filter(|p| p["healthy"] == true).count(),
        "health_phases": health, "control_phases": controls, "phases": records,
        "pressure_controls_planned": 8, "pressure_controls_attempted": controls.len(),
        "pressure_controls_executed": control_completed, "pressure_controls_unstarted": 8 - controls.len(),
        "control_inputs_acquired": acquired_inputs, "balanced_arm_indices": BALANCED_ORDER,
        "requested_window_ns": WINDOW_NS, "binary_unchanged": binary_unchanged,
        "host_before_verified": host_before["verified"], "host_after_verified": host_after["verified"],
        "first_divergence": failure, "mechanism_status": "UNKNOWN", "causal_mechanism_status": "UNKNOWN",
        "native_exit_zero_means": "observation collection finished; read qualification, planned denominator and originals",
        "qualification_requires_runner_exact_limits_and_exclusive_lease": true,
        "publication_qualified": false, "public_network_ready": false, "production_activation": false,
    });
    write_new_json(&root.join("report.json"), &report).unwrap();
    println!("{}", json!({"schema": report["schema"], "qualification": report["qualification"],
        "report_path": root.join("report.json")}));
}

#[test]
fn balanced_campaign_plan_keeps_sentinels_and_reversed_arms() {
    let plan = campaign_plan();
    assert_eq!(plan.len(), 13);
    assert!(plan[..3].iter().all(|phase| phase.kind == "initial-health"));
    assert_eq!(plan[7].kind, "midpoint-sentinel");
    assert_eq!(plan[12].kind, "terminal-sentinel");
    let arms: Vec<_> = plan.iter().filter_map(|phase| phase.arm).collect();
    assert_eq!(arms, BALANCED_ORDER);
}

#[test]
fn pressure_business_failure_or_valid_acceptance_is_not_itself_integrity_failure() {
    let mut phase = json!({"control_integrity_met": true,
        "requested_window_ns": WINDOW_NS, "workers": 16,
        "client_confirmed_before_original_window_end": false,
        "client_confirmed_transactions": 0, "accepted_attack_proofs": 1});
    assert!(pressure_integrity(&phase));
    phase["workers"] = json!(15);
    assert!(!pressure_integrity(&phase));
    phase["workers"] = json!(17);
    assert!(!pressure_integrity(&phase));
    phase["workers"] = json!(16);
    assert!(pressure_integrity(&phase));
    phase["control_integrity_met"] = json!(false);
    assert!(!pressure_integrity(&phase));
    phase["control_integrity_met"] = json!(true);
    phase["requested_window_ns"] = json!(WINDOW_NS + 1);
    assert!(!pressure_integrity(&phase));
}
