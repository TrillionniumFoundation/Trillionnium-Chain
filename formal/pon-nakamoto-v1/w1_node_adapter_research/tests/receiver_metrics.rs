//! Cold receiver boundaries use the actual retained packet, complete proofs and
//! SQLite-backed development Node. Timing assertions do not claim performance.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use w1_node_adapter_research::proof_start_owner::{ProofStartOwner, ProofStartPolicy};
use w1_node_adapter_research::{OperatorPlan, digest};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/node-input-v1")
}

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_w1-node-adapter-research"))
}

fn common_only(parent: &Path) -> PathBuf {
    let input = parent.join("common-input");
    fs::create_dir(&input).unwrap();
    for name in ["operator-plan.json", "packet.bin"] {
        fs::copy(fixture().join(name), input.join(name)).unwrap();
    }
    input
}

fn events(output: &Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn terminal(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value = events(output).pop().unwrap();
    assert!(value["result"].is_object());
    value
}

fn check_metrics(value: &Value, mode: &str) {
    let metrics = &value["result"]["metrics"];
    assert_eq!(metrics["schema"], "trnm-w1-receiver-metrics-v1");
    assert_eq!(metrics["mode"], mode);
    assert_eq!(metrics["phases_are_disjoint"], true);
    assert_eq!(metrics["proof_preprocessing_reused"], false);
    assert_eq!(metrics["new_complete_proofs_generated"], 0);
    assert_eq!(metrics["network_transport_measured"], false);
    assert_eq!(metrics["production_activation"], false);
    let phases = metrics["phases"].as_array().unwrap();
    assert!(!phases.is_empty());
    let mut names = BTreeSet::new();
    let mut sum = 0.0;
    for phase in phases {
        assert!(names.insert(phase["stage"].as_str().unwrap()));
        let seconds = phase["wall_seconds"].as_f64().unwrap();
        assert!(seconds.is_finite() && seconds >= 0.0);
        assert!(matches!(phase["outcome"].as_str(), Some("ok" | "error")));
        sum += seconds;
    }
    assert!(sum <= value["outer_seconds"].as_f64().unwrap() + 1e-6);
}

fn check_identity(record: &Value, input: &Path) {
    let packet = fs::read(input.join("packet.bin")).unwrap();
    let plan = fs::read(input.join("operator-plan.json")).unwrap();
    assert_eq!(record["input_identity"]["packet_sha256"], digest(&packet));
    assert_eq!(
        record["input_identity"]["operator_plan_sha256"],
        digest(&plan)
    );
    assert_eq!(record["input_identity"]["packet_bytes"], packet.len());
}

fn provision_owner(parent: &Path) -> (PathBuf, PathBuf) {
    let plan: OperatorPlan =
        serde_json::from_slice(&fs::read(fixture().join("operator-plan.json")).unwrap()).unwrap();
    let policy = ProofStartPolicy::for_plan("63".repeat(32), 1, &plan).unwrap();
    let policy_path = parent.join("expected-policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy).unwrap()).unwrap();
    let owner_path = fs::canonicalize(parent).unwrap().join("proof-owner");
    ProofStartOwner::create(&owner_path, policy).unwrap();
    (owner_path, policy_path)
}

fn exercise(output: &Path, cancellation: &str, owner: &Path, policy: &Path) -> Output {
    command()
        .arg("exercise")
        .arg(fixture())
        .arg(fixture())
        .arg(output)
        .arg(cancellation)
        .arg(owner)
        .arg(policy)
        .output()
        .unwrap()
}

#[test]
fn native_cli_accepts_only_common_inputs_with_real_node_metrics() {
    let dir = tempfile::tempdir().unwrap();
    let input = common_only(dir.path());
    let output = dir.path().join("native-output");
    let result = command()
        .arg("native-admit")
        .arg(&input)
        .arg(&output)
        .output()
        .unwrap();
    let value = terminal(&result);
    check_metrics(&value, "native");
    let record = &value["result"];
    check_identity(record, &input);
    assert_eq!(record["schema"], "trnm-w1-node-native-admit-v1");
    assert_eq!(record["native_admitted"], true);
    assert_eq!(record["native_admission_path_invoked"], true);
    assert_eq!(record["node_opened"], true);
    assert_eq!(record["both_real_proofs_verified"], false);
    assert_eq!(record["native_observation"]["stored_exact"], true);
    assert_eq!(record["native_observation"]["active_chain_member"], true);
    assert!(record["activation_error"].is_null());
    assert!(record["native_observation_error"].is_null());
    assert_eq!(record["qualification"], "HOLD_NO_GO");
    assert_eq!(record["production_activation"], false);
    let plan: Value =
        serde_json::from_slice(&fs::read(input.join("operator-plan.json")).unwrap()).unwrap();
    assert_eq!(record["active_before"], plan["genesis"]);
    assert_eq!(record["generation_before"], 0);
    assert_eq!(
        record["metrics"]["payload_bytes"],
        fs::metadata(input.join("packet.bin")).unwrap().len()
    );
    assert!(!input.join("statement.bin").exists());
    assert!(!input.join("sha.proof.bin").exists());
    let saved: Value =
        serde_json::from_slice(&fs::read(output.join("native-admit.json")).unwrap()).unwrap();
    assert_eq!(&saved, record);
}

#[test]
fn native_cli_rejects_changed_independent_binding_before_node_open() {
    for field in ["expected_header", "expected_artifacts", "profile"] {
        let dir = tempfile::tempdir().unwrap();
        let input = common_only(dir.path());
        let plan_path = input.join("operator-plan.json");
        let mut plan: Value = serde_json::from_slice(&fs::read(&plan_path).unwrap()).unwrap();
        if field == "profile" {
            plan[field] = "another-profile".into();
        } else {
            let mut bytes = hex::decode(plan[field].as_str().unwrap()).unwrap();
            bytes[0] ^= 1;
            plan[field] = hex::encode(bytes).into();
        }
        fs::write(plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
        let output = dir.path().join("refused-output");
        let result = command()
            .arg("native-admit")
            .arg(input)
            .arg(&output)
            .output()
            .unwrap();
        assert!(!result.status.success(), "{field}");
        assert!(!output.join("receiver-node").exists(), "{field}");
        assert!(!output.join("native-admit.json").exists(), "{field}");
        let finished = events(&result)
            .into_iter()
            .find(|event| {
                event["event"] == "receiver_phase_finished"
                    && event["measurement"]["stage"] == "native_input_read_binding"
            })
            .unwrap();
        assert_eq!(finished["measurement"]["outcome"], "error");
    }
}

#[test]
fn native_cli_never_overwrites_an_existing_output() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("existing-output");
    fs::create_dir(&output).unwrap();
    fs::write(output.join("sentinel"), b"original").unwrap();
    let result = command()
        .arg("native-admit")
        .arg(fixture())
        .arg(&output)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(fs::read(output.join("sentinel")).unwrap(), b"original");
    assert!(!output.join("receiver-node").exists());
}

#[test]
fn proof_cli_reports_disjoint_cold_receiver_metrics_and_spent_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, policy) = provision_owner(dir.path());
    let result = exercise(&dir.path().join("proof-output"), "none", &owner, &policy);
    let value = terminal(&result);
    check_metrics(&value, "proof-plus-native");
    let record = &value["result"];
    check_identity(record, &fixture());
    assert_eq!(record["schema"], "trnm-w1-node-adapter-exercise-v2");
    assert!(record["error"].is_null());
    assert_eq!(record["node_opened"], true);
    assert_eq!(
        record["outcome"]["schema"],
        "trnm-w1-node-adapter-admission-v3"
    );
    assert_eq!(record["outcome"]["both_real_proofs_verified"], true);
    assert_eq!(record["outcome"]["native_admitted"], true);
    assert_eq!(record["native_observation"]["stored_exact"], true);
    assert_eq!(record["native_observation"]["active_chain_member"], true);
    assert_eq!(record["proof_start_owner_snapshot"]["occupied_slots"], 1);
    assert_eq!(record["proof_start_owner_snapshot"]["exhausted"], true);
    let payload_bytes: u64 = [
        "packet.bin",
        "statement.bin",
        "sha.proof.bin",
        "arith.proof.bin",
    ]
    .iter()
    .map(|name| fs::metadata(fixture().join(name)).unwrap().len())
    .sum();
    assert_eq!(record["metrics"]["payload_bytes"], payload_bytes);
    let phases = record["metrics"]["phases"].as_array().unwrap();
    assert!(phases.iter().all(|phase| phase["outcome"] == "ok"));
    let proof_seconds = phases
        .iter()
        .find(|phase| phase["stage"] == "complete_proof_verification")
        .unwrap()["wall_seconds"]
        .as_f64()
        .unwrap();
    let proof_phases = record["outcome"]["proof_phases"].as_array().unwrap();
    assert_eq!(proof_phases.len(), 6);
    assert_eq!(proof_phases[0]["stage"], "fixed_shape_scans_and_decode");
    assert_eq!(
        proof_phases[1]["stage"],
        "canonical_plans_and_public_only_air"
    );
    let subtotal: f64 = proof_phases
        .iter()
        .map(|phase| phase["wall_seconds"].as_f64().unwrap())
        .sum();
    assert!(subtotal <= proof_seconds + 1e-6);
    assert_eq!(
        record["outcome"]["native_detail_metrics"]["schema"],
        "trnm-w1-native-admission-metrics-v1"
    );
}

#[test]
fn cancelled_proof_keeps_failed_phase_cost_and_does_not_open_node() {
    let dir = tempfile::tempdir().unwrap();
    let (owner, policy) = provision_owner(dir.path());
    let output = dir.path().join("cancelled-output");
    let result = exercise(&output, "BeforeProof", &owner, &policy);
    let value = terminal(&result);
    check_metrics(&value, "proof-plus-native");
    let record = &value["result"];
    assert!(record["outcome"].is_null());
    assert!(
        record["error"]
            .as_str()
            .unwrap()
            .contains("REQUEST_CANCELLED")
    );
    assert_eq!(record["node_opened"], false);
    assert!(!output.join("receiver-node").exists());
    assert_eq!(record["proof_start_owner_snapshot"]["occupied_slots"], 1);
    let phases = record["metrics"]["phases"].as_array().unwrap();
    let rejected = phases
        .iter()
        .find(|phase| phase["stage"] == "complete_proof_verification")
        .unwrap();
    assert_eq!(rejected["outcome"], "error");
    assert!(
        !phases
            .iter()
            .any(|phase| phase["stage"] == "node_open_recovery")
    );
}
