//! Replay retained Hepta learning receipts on a fresh, locally signed development ledger.
use super::*;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    commit: String,
    tree: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePair {
    chain: Source,
    hepta: Source,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayInputs {
    schema: String,
    materials: PathBuf,
    bindings: PathBuf,
    initial_sha256: String,
    bindings_sha256: String,
    operation_id: String,
    invocation_id: String,
    source_pair: SourcePair,
}

fn digest(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}

fn reader() -> Command {
    let mut command = Command::new("python3");
    command
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.."))
        .arg("scripts/cell_learning_business_join.py");
    command
}

fn checked_json(command: &mut Command) -> Value {
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn replay(label: &str, input_path: &Path) -> String {
    let input_path = input_path.canonicalize().unwrap();
    let directory = input_path.parent().unwrap();
    let mut raw = Vec::new();
    std::fs::File::open(&input_path)
        .unwrap()
        .take(16_385)
        .read_to_end(&mut raw)
        .unwrap();
    assert!(
        raw.len() <= 16_384,
        "development replay input exceeds 16 KiB"
    );
    let archive: ReplayInputs = serde_json::from_slice(&raw).unwrap();
    assert_eq!(archive.schema, "trnm-isolated-learning-dev-replay-input-v1");
    let materials = directory.join(archive.materials);
    let bindings = directory.join(archive.bindings);
    let admission = checked_json(
        reader()
            .args(["prepare-request", "--contract-fields", "--initial"])
            .arg(materials.join("initial.bin"))
            .args([
                "--initial-sha256",
                &archive.initial_sha256,
                "--operation-id",
                &archive.operation_id,
                "--invocation-id",
                &archive.invocation_id,
                "--chain-commit",
                &archive.source_pair.chain.commit,
                "--chain-tree",
                &archive.source_pair.chain.tree,
                "--hepta-commit",
                &archive.source_pair.hepta.commit,
                "--hepta-tree",
                &archive.source_pair.hepta.tree,
            ]),
    );

    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    let journal_path = directory.path().join("operation.sqlite");
    let mut node = open(&node_path, Backend::Authenticated).unwrap();
    let cfg = node.settings().clone();
    let terms = FundedServiceContractV1 {
        request: digest(&admission["request"]),
        model: digest(&admission["model"]),
        input: digest(&admission["input"]),
        evaluation_protocol: digest(&admission["evaluation_protocol"]),
        ..contract(1).0
    };
    let task = terms.task_id(cfg.network(), cfg.parameters(), public(0), 1);
    let bind = binding(
        task,
        terms.digest(cfg.network(), cfg.parameters(), public(0)),
        CLAIM,
        OPERATION,
    );
    let reserve = signed(
        &cfg,
        0,
        1,
        2,
        FundedServiceReservationV1 {
            task,
            contract: terms.clone(),
        }
        .encode()
        .unwrap(),
    );
    let reserved = mine(&mut node, cfg.genesis(), vec![reserve]);
    let mut store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();
    store.reserve(&mut node, bind.clone()).unwrap();
    assert_eq!(store.snapshot(CLAIM).unwrap().reserved.output, None);
    assert_eq!(
        store.begin(&mut node, CLAIM).unwrap(),
        NativeBudgetReplayV1::New
    );

    // Only after reserve and begin do we read the terminal learning materials.
    let mut read = reader();
    read.arg("--bindings")
        .arg(&bindings)
        .arg("--bindings-sha256")
        .arg(&archive.bindings_sha256);
    for (option, file) in [
        ("--selection", "selection.bin"),
        ("--completed", "completed.bin"),
        ("--readback", "readback.json"),
        ("--freeze", "freeze.json"),
        ("--expected", "expected.json"),
    ] {
        read.arg(option).arg(materials.join(file));
    }
    let reviewed = checked_json(&mut read);
    let decision = reviewed["decision"].as_str().unwrap();
    assert!(matches!(decision, "Selection" | "NoUpdate"));
    assert_eq!(reviewed["funded_request_digest"], admission["request"]);
    assert_eq!(reviewed["funded_mapping_observed"], false);
    assert_eq!(reviewed["independent_consumer_verified"], false);
    let output = digest(&reviewed["funded_result_digest"]);
    let completed_head = digest(&reviewed["completion_review"]["completed_learning_head"]);
    // Deliberately controlled resource declaration, separate from historical training.
    store
        .record_costs(
            CLAIM,
            NativeResourceOutcomeV1::NoGain,
            resources(3),
            NativeTaskCostBreakdownV2 {
                training_units: 1,
                evaluation_units: 1,
                storage_units: 1,
                serving_units: 1,
                unit: [71; 32],
                measurement_receipt: [72; 32],
            },
        )
        .unwrap();
    store
        .complete(CLAIM, OPERATION, output, completed_head)
        .unwrap();
    let settlement = settle_dev_output(&mut node, &mut store, &bind, reserved, output);
    drop(store);
    drop(node);

    let node = open(&node_path, Backend::Authenticated).unwrap();
    let store = NativeTaskOperationStoreV2::open(&journal_path, configuration(&cfg)).unwrap();
    let paid = node
        .observe_current_native_task_operation_v3(&store, &bind, &terms, 23)
        .unwrap();
    assert_eq!(paid["native_status"], "settled");
    assert_eq!(paid["original_full_contract"]["terms"], json!(terms));
    assert_eq!(paid["output"], reviewed["funded_result_digest"]);
    assert_eq!(
        paid["target_receipt_commitment"],
        hex::encode(completed_head)
    );
    assert_eq!(
        paid["current_payment"]["operation"],
        hex::encode(settlement.payment_operation)
    );
    assert_eq!(paid["current_payment"]["gross_escrow_debit"], AMOUNT);
    assert_eq!(paid["current_payment"]["beneficiary_credit"], AMOUNT);
    assert_eq!(paid["remaining_native_escrow"], 0);
    assert_eq!(paid["actual_consumer_use_verified"], false);
    assert_eq!(paid["learning_improvement_bonus"], false);
    assert_eq!(paid["chainwork_awarded"], 0);
    let changed = FundedServiceContractV1 {
        model: output,
        ..terms
    };
    assert!(node
        .observe_current_native_task_operation_v3(&store, &bind, &changed, 23)
        .is_err());
    capture_current_fixture(
        Backend::Authenticated,
        label,
        "reopened-archived-learning-dev-payment",
        &paid,
    );
    decision.to_owned()
}

fn retained_input(phase: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../evidence/cell-learning-native-dev-payment-20261123")
        .join(format!("{phase}-input.json"))
}

#[test]
fn archived_selection_binds_native_development_payment_after_reopen() {
    assert_eq!(replay("adopt-v1", &retained_input("adopt-v1")), "Selection");
}

#[test]
fn archived_no_update_binds_native_development_service_fee_after_reopen() {
    assert_eq!(
        replay("no-update-v9", &retained_input("no-update-v9")),
        "NoUpdate"
    );
}

#[test]
#[ignore = "requires a caller-supplied local development replay input"]
fn supplied_learning_contract_replays_on_isolated_dev_ledger() {
    let path = std::env::var_os("TRNM_DEV_LEARNING_INPUT")
        .expect("set TRNM_DEV_LEARNING_INPUT to the absolute input JSON path");
    let path = Path::new(&path);
    assert!(
        path.is_absolute(),
        "TRNM_DEV_LEARNING_INPUT must be absolute"
    );
    replay("caller-supplied", path);
}
