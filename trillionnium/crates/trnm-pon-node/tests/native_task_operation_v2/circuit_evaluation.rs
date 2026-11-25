//! Run a new offline Hepta evaluation after a funded local development reservation.
use super::*;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{env, fs, io::Write, path::PathBuf, process::Command};

fn read(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}
fn write(path: &Path, value: Value) {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    serde_json::to_writer(&mut f, &value).unwrap();
    f.write_all(b"\n").unwrap();
    f.sync_all().unwrap();
}
fn file_digest(path: &Path) -> Hash {
    Sha256::digest(fs::read(path).unwrap()).into()
}
fn digest(value: &Value) -> Hash {
    hex::decode(value.as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap()
}
fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}
struct EvaluationCase {
    test_script: &'static str,
    prepare_mode: &'static str,
    input_environment: &'static str,
    model_environment: &'static str,
    namespace: &'static str,
    work: &'static [u8],
    delivered_input: &'static str,
}
const CIRCUIT: EvaluationCase = EvaluationCase {
    test_script: "dev_circuit_evaluation.py",
    prepare_mode: "prepare",
    input_environment: "TRNM_DEV_PAIRED_REQUEST_SHA256",
    model_environment: "TRNM_DEV_CIRCUIT_SHA256",
    namespace: "dev-circuit-evaluation",
    work: b"paired offline inference",
    delivered_input: "paired_request",
};
const HISTORY: EvaluationCase = EvaluationCase {
    test_script: "dev_historical_evaluation.py",
    prepare_mode: "prepare",
    input_environment: "TRNM_DEV_PUBLIC_PARQUET_SHA256",
    model_environment: "TRNM_DEV_HISTORICAL_MODEL_SHA256",
    namespace: "dev-historical-evaluation",
    work: b"retrospective historical A and authored retention",
    delivered_input: "retrospective_request",
};
const PAIRED: EvaluationCase = EvaluationCase {
    test_script: "dev_intake_evaluation.py",
    prepare_mode: "prepare",
    input_environment: "TRNM_DEV_PAIRED_REQUEST_SHA256",
    model_environment: "TRNM_DEV_PAIRED_MODEL_SHA256",
    namespace: "dev-plain-paired-intake-evaluation",
    work: b"one released plain-model request and frozen retention",
    delivered_input: "paired_request",
};
const BOUND_PAIRED: EvaluationCase = EvaluationCase {
    prepare_mode: "prepare-bound",
    namespace: "dev-bound-paired-loop-evaluation-v2",
    work: b"one identity-bound released plain-model request and frozen retention",
    ..PAIRED
};
impl EvaluationCase {
    fn commitment(&self, suffix: &str, parts: &[&[u8]]) -> Hash {
        hash(format!("{}-{suffix}", self.namespace).as_bytes(), parts)
    }
}

fn bound_evaluation_schemas(identity: &Value) -> Option<(&'static str, &'static str)> {
    match identity["schema"].as_str() {
        Some("hepta.paired-learning.loop-identity.v1") => Some((
            "trnm-isolated-bound-paired-evaluation-request-v2",
            "trnm-isolated-bound-paired-evaluation-delivery-v2",
        )),
        Some("hepta.paired-learning.loop-identity.v2") => Some((
            "trnm-isolated-bound-paired-evaluation-request-v3",
            "trnm-isolated-bound-paired-evaluation-delivery-v3",
        )),
        _ => None,
    }
}

#[test]
fn bound_identity_versions_select_exact_request_and_delivery_namespaces() {
    for (version, request_version) in [("v1", "v2"), ("v2", "v3")] {
        let identity = json!({"schema": format!("hepta.paired-learning.loop-identity.{version}")});
        let (request, delivery) = bound_evaluation_schemas(&identity).unwrap();
        assert_eq!(
            request,
            format!("trnm-isolated-bound-paired-evaluation-request-{request_version}")
        );
        assert_eq!(
            delivery,
            format!("trnm-isolated-bound-paired-evaluation-delivery-{request_version}")
        );
    }
    for identity in [
        json!({}),
        json!({"schema": true}),
        json!({"schema": "hepta.paired-learning.loop-identity.v3"}),
    ] {
        assert!(bound_evaluation_schemas(&identity).is_none());
    }
}

fn execute_service(
    case: &EvaluationCase,
    mode: &str,
    job: &Path,
    materials: &Path,
    extra: &[String],
) {
    let tool = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../scripts")
        .join(case.test_script);
    let s = Command::new(var("TRNM_DEV_HEPTA_PYTHON"))
        .arg("-B")
        .arg(tool)
        .arg(mode)
        .arg(job)
        .arg(materials)
        .args(extra)
        .status()
        .unwrap();
    assert!(s.success(), "paired evaluation {mode} failed");
}

fn evaluation_binding(
    case: &EvaluationCase,
    cfg: &Settings,
    terms: &FundedServiceContractV1,
    admission: &Value,
) -> NativeTaskOperationBindingV2 {
    let request = terms.request;
    let task = terms.task_id(cfg.network(), cfg.parameters(), public(0), 1);
    let contract_digest = terms.digest(cfg.network(), cfg.parameters(), public(0));
    let claim = case.commitment("claim", &[&task]);
    let operation = case.commitment("operation", &[&task, &request]);
    let cpu_cap = admission["cpu_limit_ns"].as_u64().unwrap();
    let examples = admission["evaluated_examples"].as_u64().unwrap();
    NativeTaskOperationBindingV2 {
        claim,
        task,
        contract_digest,
        operation,
        beneficiary: public(1),
        target_scope: terms.evaluation_protocol,
        resource_cap: NativeBudgetResourcesV1::Evaluation {
            evaluation_cpu_ns: cpu_cap,
            evaluated_examples: examples,
        },
    }
}

#[test]
#[ignore = "requires pinned local Hepta materials, Linux user/network namespaces and an offline Python environment"]
fn funded_offline_circuit_evaluation_reopens_paid_native_operation() {
    funded_evaluation(&CIRCUIT);
}

#[test]
#[ignore = "requires pinned public historical materials and an offline Python environment"]
fn funded_historical_a_replay_reopens_paid_native_operation() {
    funded_evaluation(&HISTORY);
}

#[test]
#[ignore = "requires a released paired request, local frozen weights and an offline Linux Python environment"]
fn funded_plain_paired_intake_reopens_paid_native_operation() {
    funded_evaluation(&PAIRED);
}

#[test]
#[ignore = "requires an independently pinned loop identity, original released pair and offline Linux Python environment"]
fn funded_bound_paired_loop_reopens_paid_native_operation() {
    funded_evaluation(&BOUND_PAIRED);
}

fn funded_evaluation(case: &EvaluationCase) {
    let job = PathBuf::from(var("TRNM_DEV_EVAL_JOB"));
    assert!(job.is_absolute(), "supply a fresh absolute output path");
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&job).unwrap();
    }
    #[cfg(not(unix))]
    {
        assert_ne!(
            case.test_script, PAIRED.test_script,
            "private paired evaluation requires Linux"
        );
        fs::create_dir(&job).unwrap();
    }
    let materials = fs::canonicalize(var("TRNM_DEV_HEPTA_MATERIALS")).unwrap();
    execute_service(
        case,
        case.prepare_mode,
        &job,
        &materials,
        &[
            var("TRNM_DEV_HEPTA_SOURCE"),
            var("TRNM_DEV_FREEZE_SHA256"),
            var(case.input_environment),
            var(case.model_environment),
        ],
    );
    let admission_path = job.join("ADMISSION.json");
    let admission = read(&admission_path);
    if case.prepare_mode == "prepare-bound" {
        let original_identity = read(Path::new(&var("TRNM_DEV_LOOP_IDENTITY_FILE")));
        let (request_schema, delivery_schema) = bound_evaluation_schemas(&original_identity)
            .expect("unsupported bound loop identity schema");
        assert_eq!(admission["loop_identity"], original_identity);
        assert_eq!(admission["schema"], request_schema);
        assert_eq!(admission["output_schema"], delivery_schema);
        assert_eq!(
            admission["loop_identity_sha256"],
            var("TRNM_DEV_LOOP_IDENTITY_SHA256")
        );
    }
    let request = file_digest(&admission_path);
    let cfg = settings();
    let terms = FundedServiceContractV1 {
        request,
        model: digest(&admission["pins"]["candidate"]),
        input: digest(&admission["pins"]["request"]),
        output_spec: case.commitment(
            "output-spec",
            &[admission["output_schema"].as_str().unwrap().as_bytes()],
        ),
        qualified_work: case.commitment("service", &[case.work]),
        evaluation_protocol: digest(&admission["source_listing_sha256"]),
        fee_schedule: case.commitment("flat-fee", &[&AMOUNT.to_le_bytes()]),
        dispute_policy: case.commitment("verdict", &[b"development arbitrator"]),
        ..contract(1).0
    };
    let bind = evaluation_binding(case, &cfg, &terms, &admission);
    let task = bind.task;
    let claim = bind.claim;
    let operation = bind.operation;
    let cpu_cap = admission["cpu_limit_ns"].as_u64().unwrap();
    let examples = admission["evaluated_examples"].as_u64().unwrap();
    let node_path = job.join("node");
    let journal = job.join("operation.sqlite");
    let mut node = open(&node_path, Backend::Authenticated).unwrap();
    let mut store = NativeTaskOperationStoreV2::open(&journal, configuration(&cfg)).unwrap();
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
    let reservation_block = mine(&mut node, cfg.genesis(), vec![reserve.clone()]);
    store.reserve(&mut node, bind.clone()).unwrap();
    let reserved_state = store.snapshot(claim).unwrap().reserved;
    assert_eq!(reserved_state.output, None);
    assert_eq!(reserved_state.remaining, AMOUNT);
    assert_eq!(
        store.begin(&mut node, claim).unwrap(),
        NativeBudgetReplayV1::New
    );
    let checkpoint = store.checkpoint().unwrap();
    write(
        &job.join("RESERVATION.json"),
        json!({
        "schema":"trnm-isolated-circuit-evaluation-reservation-v1",
        "request":hex::encode(request),"task":hex::encode(task),"claim":hex::encode(claim),"operation":hex::encode(operation),
        "terms":terms,"reserved_units":reserved_state.remaining,"reservation_block":hex::encode(reservation_block),
        "signed_reservation":hex::encode(reserve),"m12_after_begin":{"sequence":checkpoint.sequence,"root":hex::encode(checkpoint.root)}}),
    );
    assert!(!job.join("evaluation").exists());
    execute_service(case, "execute", &job, &materials, &[]);
    let delivery_path = job.join("DELIVERY.json");
    let delivered = read(&delivery_path);
    assert_eq!(delivered["schema"], admission["output_schema"]);
    let output = file_digest(&delivery_path);
    let result = file_digest(&job.join("evaluation/RESULT.json"));
    let cost = file_digest(&job.join("COST.json"));
    assert_eq!(digest(&delivered["task"]), task);
    assert_eq!(digest(&delivered["request"]), request);
    assert_eq!(digest(&delivered["model"]), terms.model);
    assert_eq!(digest(&delivered[case.delivered_input]), terms.input);
    assert_eq!(digest(&delivered["result_sha256"]), result);
    assert_eq!(digest(&delivered["cost_sha256"]), cost);
    let metered = read(&job.join("COST.json"));
    let used = metered["cpu_ns"].as_u64().unwrap();
    assert!((1..=cpu_cap).contains(&used));
    assert_eq!(metered["evaluated_examples"], examples);
    store
        .record_costs(
            claim,
            NativeResourceOutcomeV1::NoGain,
            NativeBudgetResourcesV1::Evaluation {
                evaluation_cpu_ns: used,
                evaluated_examples: examples,
            },
            NativeTaskCostBreakdownV2 {
                training_units: 0,
                evaluation_units: used,
                storage_units: 0,
                serving_units: 0,
                unit: case.commitment("cpu-unit", &[b"nanosecond"]),
                measurement_receipt: cost,
            },
        )
        .unwrap();
    store.complete(claim, operation, output, result).unwrap();
    let settlement = settle_dev_output(
        &mut node,
        &mut store,
        &bind,
        reservation_block,
        output,
        result,
    );
    write(
        &job.join("SIGNED_EFFECTS.json"),
        json!({"signed_delivery":hex::encode(&settlement.original_receipt),
        "signed_arbitration":hex::encode(&settlement.original_payment)}),
    );
    drop(store);
    drop(node);
    let node = open(&node_path, Backend::Authenticated).unwrap();
    let store = NativeTaskOperationStoreV2::open(&journal, configuration(&cfg)).unwrap();
    let paid = node
        .observe_current_native_task_operation_v3(&store, &bind, &terms, 23)
        .unwrap();
    assert_eq!(paid["native_status"], "settled");
    assert_eq!(paid["output"], hex::encode(output));
    assert_eq!(paid["target_receipt_commitment"], hex::encode(result));
    assert_eq!(paid["original_full_contract"]["terms"], json!(terms));
    assert_eq!(
        paid["current_payment"]["operation"],
        hex::encode(settlement.payment_operation)
    );
    assert_eq!(paid["current_payment"]["gross_escrow_debit"], AMOUNT);
    assert_eq!(paid["current_payment"]["beneficiary_credit"], AMOUNT);
    assert_eq!(paid["remaining_native_escrow"], 0);
    assert_eq!(
        paid["declared_costs"]["measurement_receipt"],
        hex::encode(cost)
    );
    assert_eq!(paid["declared_costs"]["evaluation_units"], used);
    assert_eq!(paid["actual_consumer_use_verified"], false);
    assert_eq!(paid["learning_improvement_bonus"], false);
    assert_eq!(paid["chainwork_awarded"], 0);
    write(&job.join("CURRENT.json"), paid);
}

#[test]
fn retained_evaluation_reopens_the_same_native_payment_from_copied_stores() {
    reobserve(&CIRCUIT, "cell-circuit-funded-evaluation-20261123");
}

#[test]
fn retained_historical_a_reopens_the_same_native_payment_from_copied_stores() {
    reobserve(&HISTORY, "cell-historical-funded-evaluation-20261123");
}

#[test]
fn retained_plain_paired_intake_reopens_the_same_payment_from_copied_stores() {
    reobserve(&PAIRED, "cell-released-pair-funded-evaluation-20261123");
}

fn reobserve(case: &EvaluationCase, directory_name: &str) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../evidence")
        .join(directory_name);
    let verifier =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/dev_circuit_evaluation.py");
    let status = Command::new("python3")
        .arg("-B")
        .arg(verifier)
        .arg("verify")
        .arg(&root)
        .status()
        .unwrap();
    assert!(status.success());
    let admission = read(&root.join("ADMISSION.json"));
    let reservation = read(&root.join("RESERVATION.json"));
    let terms: FundedServiceContractV1 =
        serde_json::from_value(reservation["terms"].clone()).unwrap();
    assert_eq!(terms.request, file_digest(&root.join("ADMISSION.json")));
    let cfg = settings();
    let bind = evaluation_binding(case, &cfg, &terms, &admission);
    let directory = tempfile::tempdir().unwrap();
    let node_path = directory.path().join("node");
    fs::create_dir(&node_path).unwrap();
    fs::copy(
        root.join("node/native.sqlite"),
        node_path.join("native.sqlite"),
    )
    .unwrap();
    let journal = directory.path().join("operation.sqlite");
    fs::copy(root.join("operation.sqlite"), &journal).unwrap();
    let node = open(&node_path, Backend::Authenticated).unwrap();
    let store = NativeTaskOperationStoreV2::open(&journal, configuration(&cfg)).unwrap();
    let current = node
        .observe_current_native_task_operation_v3(&store, &bind, &terms, 23)
        .unwrap();
    assert_eq!(current, read(&root.join("CURRENT.json")));
    let wrong = FundedServiceContractV1 {
        model: terms.input,
        ..terms
    };
    assert!(node
        .observe_current_native_task_operation_v3(&store, &bind, &wrong, 23)
        .is_err());
}
