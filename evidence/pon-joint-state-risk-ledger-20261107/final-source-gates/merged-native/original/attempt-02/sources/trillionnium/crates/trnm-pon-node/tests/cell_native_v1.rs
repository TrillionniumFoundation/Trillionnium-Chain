//! Actual native Node/CLI and full-W1 controls for the bounded Cell profile.
//! These are local correctness fixtures, not independently administered demand,
//! deployed FinalUse, production adoption, quality or work-cost qualification.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::{Command, Output},
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};
use tempfile::TempDir;
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{
    cell_native_v1::{self as cell, ExpectedCellTask, OwnerAdmission},
    development_public, Node, Settings,
};
use trnm_protocol::pon_wire::{hash, Hash};

fn fixture() -> &'static Value {
    static FIXTURE: OnceLock<Value> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        serde_json::from_slice(include_bytes!("data/cell_native_v1_oracle.json")).unwrap()
    })
}

fn case(name: &str) -> &'static Value {
    fixture()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == name)
        .unwrap()
}

fn admission(name: &str) -> OwnerAdmission {
    serde_json::from_value(case(name)["admission"].clone()).unwrap()
}

fn node(authenticated: bool) -> (TempDir, Node) {
    let directory = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(150)).unwrap();
    let node = if authenticated {
        Node::open_with_authenticated_state(directory.path(), settings, 1)
    } else {
        Node::open(directory.path(), settings, 1)
    }
    .unwrap();
    (directory, node)
}

fn expected(node: &Node, admission: &OwnerAdmission) -> ExpectedCellTask {
    let raw = cell::canonical(admission).unwrap();
    node.cell_expected_from_owner(node.settings().genesis(), &raw, Sha256::digest(&raw).into())
        .unwrap()
}

fn retain_bytes(case: &str, filename: &str, raw: &[u8]) {
    let Some(path) = std::env::var_os("CELL_NATIVE_V1_EVIDENCE_DIR") else {
        return;
    };
    assert!(case
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'));
    assert!(!filename.contains('/') && !filename.contains('\\'));
    let directory = std::path::PathBuf::from(path)
        .join("native-cases")
        .join(case);
    fs::create_dir_all(&directory).unwrap();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join(filename))
        .unwrap();
    std::io::Write::write_all(&mut file, raw).unwrap();
}

/// Record the independent admission before constructing its producer claim.
/// Packet bytes are retained separately for non-genesis cold reconstruction.
fn retain_admission(
    case: &str,
    node: &Node,
    request: &OwnerAdmission,
    expected: &ExpectedCellTask,
    authenticated: bool,
) {
    let owner = cell::canonical(request).unwrap();
    let sha: Hash = Sha256::digest(&owner).into();
    assert_eq!(sha, expected.owner_admission_sha256());
    retain_bytes(case, "owner-admission.json", &owner);
    let settings = json!({
        "schema":format!("{}/retained-owner-inputs",cell::PROFILE),
        "settings_constructor":"Settings::development(Some(150))",
        "genesis_time_unix_seconds":node.settings().genesis_time(),
        "genesis_id":hex::encode(node.settings().genesis()),
        "network":hex::encode(node.settings().network()),
        "parameters":hex::encode(node.settings().parameters()),
        "evaluation_policy":"legacy-first-two-v3",
        "task_profile":node.settings().task_profile(),"model_profile":"linear-expert-dev-v1",
        "state_backend":if authenticated {"authenticated-v1"} else {"legacy-v2"},
        "owner_admission_sha256":hex::encode(sha),
        "contract_id":hex::encode(expected.contract_id()),
        "parent_context":expected.parent_context(),
        "fixture_owner_independent_of_claim":true,"independent_administration":false,
        "checkpoint_committed":false,"production_activation":false,
    });
    retain_bytes(
        case,
        "settings-and-context.json",
        &cell::canonical(&settings).unwrap(),
    );
}

fn claim(expected: &ExpectedCellTask) -> Value {
    serde_json::from_slice(&cell::prove_reference(expected, 1).unwrap()).unwrap()
}

#[track_caller]
fn refusal<T>(result: trnm_pon_node::Result<T>, code: &str) {
    match result {
        Ok(_) => panic!("unexpected acceptance, expected {code}"),
        Err(error) => assert!(
            error.to_string().contains(code),
            "expected {code}, observed {error}"
        ),
    }
}

fn numeric_state(mut value: Value) -> Value {
    let object = value.as_object_mut().unwrap();
    object.remove("schema");
    object.remove("model_artifact");
    if let Some(optimizer) = object["optimizer"].as_object() {
        let mut optimizer = optimizer.clone();
        optimizer.remove("schema");
        object.insert("optimizer".into(), Value::Object(optimizer));
    }
    value
}

fn stage<'a>(claim: &'a Value, name: &str) -> &'a Value {
    claim["segments"]
        .as_array()
        .unwrap()
        .iter()
        .find(|stage| stage["stage"] == name)
        .unwrap()
}

#[test]
fn seven_python_v2_controls_match_native_complete_values_and_all_five_w1_tiles() {
    let (_directory, node) = node(false);
    for retained in fixture()["cases"].as_array().unwrap() {
        let name = retained["name"].as_str().unwrap();
        let request = admission(name);
        let expected = expected(&node, &request);
        retain_admission(name, &node, &request, &expected, false);
        let raw = cell::prove_reference(&expected, 1).unwrap();
        retain_bytes(name, "claim.json", &raw);
        let verified = cell::verify_historical(&expected, &raw).unwrap();
        let observed: Value = serde_json::from_slice(&raw).unwrap();
        let oracle = &retained["oracle"];
        let mut output = observed["output"].clone();
        output.as_object_mut().unwrap().remove("schema");
        assert_eq!(output, oracle["output"], "{name}: output");
        assert_eq!(
            numeric_state(observed["after_state"].clone()),
            oracle["after_state"],
            "{name}: state"
        );
        for matrix in ["base", "router", "deltas"] {
            assert_eq!(
                observed["after_model"][matrix], oracle["after_model"][matrix],
                "{name}: {matrix}"
            );
        }
        assert_eq!(
            stage(&observed, "five-w1-products")["outputs"]["values"],
            oracle["products"],
            "{name}: products"
        );
        let source_features: Vec<_> = stage(&observed, "source-preprocessing")["outputs"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["features"].clone())
            .collect();
        assert_eq!(
            json!(source_features),
            oracle["source_features"],
            "{name}: actual preprocessing"
        );
        for (i, wanted) in oracle["decisions"].as_array().unwrap().iter().enumerate() {
            assert_eq!(
                stage(&observed, &format!("decision/{i}"))["outputs"],
                *wanted,
                "{name}: decision {i}"
            );
        }
        for wanted in oracle["training"].as_array().unwrap() {
            let mut output = stage(&observed, wanted["stage"].as_str().unwrap())["outputs"].clone();
            output.as_object_mut().unwrap().remove("model");
            output.as_object_mut().unwrap().remove("optimizer");
            assert_eq!(output, wanted["outputs"], "{name}: training tensor");
        }
        assert_eq!(observed["tiles"].as_array().unwrap().len(), 5);
        let receipt = verified.observation();
        assert_eq!(receipt["computed_historical"], true);
        for name in [
            "computed_live",
            "operation_consumed",
            "checkpoint_committed",
            "final_use_granted",
            "model_later_used",
            "consensus_work_admitted",
            "external_delivery_verified",
            "production_activation",
        ] {
            assert_eq!(
                receipt[name], false,
                "{name} must remain outside pure verification"
            );
        }
    }
}

#[test]
fn owner_pin_and_foreign_task_never_come_from_the_claim() {
    let (_directory, node) = node(false);
    let original = admission("tool_proposal");
    let owner = expected(&node, &original);
    let raw = cell::prove_reference(&owner, 1).unwrap();
    let mut other = original.clone();
    other.request_id = "aa".repeat(32);
    let other_expected = expected(&node, &other);
    refusal(
        cell::verify_historical(&other_expected, &raw),
        "CELL_EXPECTED_CONTRACT",
    );
    let bytes = cell::canonical(&original).unwrap();
    refusal(
        node.cell_expected_from_owner(node.settings().genesis(), &bytes, [0; 32]),
        "CELL_OWNER_ADMISSION_SHA256",
    );
    refusal(
        node.cell_expected_from_owner([255; 32], &bytes, Sha256::digest(&bytes).into()),
        "UNKNOWN_PARENT",
    );
    // Even complete producer JSON with its own advertised contract cannot be
    // parsed as the mandatory independently retained owner admission.
    refusal(
        node.cell_expected_from_owner(node.settings().genesis(), &raw, Sha256::digest(&raw).into()),
        "CELL_INPUT_SCHEMA",
    );
}

fn rehash_segments(claim: &mut Value) {
    let cid: Hash = hex::decode(claim["contract_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let mut predecessor = hex::encode(hash(
        b"pon-cell-stateful-native-int257-v1/segment-start",
        &[&cid],
    ));
    for segment in claim["segments"].as_array_mut().unwrap() {
        segment["predecessor"] = json!(predecessor);
        let mut body = segment.clone();
        body.as_object_mut().unwrap().remove("segment_id");
        predecessor = hex::encode(hash(
            b"pon-cell-stateful-native-int257-v1/segment",
            &[&cell::canonical(&body).unwrap()],
        ));
        segment["segment_id"] = json!(predecessor);
    }
}

#[test]
fn rehashed_intermediate_tensor_and_checkpoint_substitution_fail_after_valid_w1() {
    let (_directory, node) = node(false);
    let expected = expected(&node, &admission("masked_sampling_training"));
    let original = claim(&expected);
    let mut after = original.clone();
    let old = after["after_state"]["memory"][0].as_i64().unwrap();
    after["after_state"]["memory"][0] = json!(old + 1);
    let last = after["segments"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    last["outputs"]["after_state"]["memory"][0] = json!(old + 1);
    rehash_segments(&mut after);
    refusal(
        cell::verify_historical(&expected, &cell::canonical(&after).unwrap()),
        "CELL_AFTER_STATE_RELATION",
    );
    for kind in [
        "source-preprocessing",
        "feature-mask",
        "five-w1-products",
        "training-backward",
    ] {
        let mut tensor = original.clone();
        let selected = tensor["segments"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|stage| stage["stage"] == kind)
            .unwrap();
        match kind {
            "source-preprocessing" => selected["outputs"]["rows"][0]["features"][0] = json!(7),
            "feature-mask" => selected["outputs"]["values"][0][0] = json!(7),
            "five-w1-products" => selected["outputs"]["shape"] = json!([5, 12]),
            _ => selected["outputs"]["gradients"]["base"][0][0] = json!(7),
        }
        rehash_segments(&mut tensor);
        refusal(
            cell::verify_historical(&expected, &cell::canonical(&tensor).unwrap()),
            "CELL_SEGMENT_DATAFLOW_RELATION",
        );
    }
}

#[test]
fn every_w1_tile_requires_full_material_product_transcript_and_challenge() {
    let (_directory, node) = node(false);
    let expected = expected(&node, &admission("negative_floor_and_ties"));
    let original = claim(&expected);
    for index in 0..5 {
        for (offset, error) in [
            (4, "CELL_WORK_MATERIAL"),
            (4 + 2 * pon_work::CELLS * 4, "CELL_FULL_W1_RELATION"),
            (pon_work::PROOF_BYTES - 1, "CELL_FULL_W1_RELATION"),
        ] {
            let mut changed = original.clone();
            let mut bytes =
                hex::decode(changed["tiles"][index]["proof_hex"].as_str().unwrap()).unwrap();
            bytes[offset] ^= 1;
            changed["tiles"][index]["proof_hex"] = json!(hex::encode(bytes));
            refusal(
                cell::verify_historical(&expected, &cell::canonical(&changed).unwrap()),
                error,
            );
        }
        let mut changed = original.clone();
        changed["tiles"][index]["nonce"] = json!(1);
        refusal(
            cell::verify_historical(&expected, &cell::canonical(&changed).unwrap()),
            "CELL_FULL_W1_RELATION",
        );
    }
    let mut old = original.clone();
    old["schema"] = json!("pon-useful-cell-stateful-int257-v2/witness");
    refusal(
        cell::verify_historical(&expected, &cell::canonical(&old).unwrap()),
        "CELL_CLAIM_PROFILE",
    );
    old["schema"] = json!("pon-useful-cell-multimodal-int-v3/witness");
    refusal(
        cell::verify_historical(&expected, &cell::canonical(&old).unwrap()),
        "CELL_CLAIM_PROFILE",
    );
}

#[test]
fn historical_is_repeatable_after_expiry_but_live_checks_both_clock_cuts() {
    let (_directory, node) = node(false);
    let expected = expected(&node, &admission("tool_proposal"));
    let raw = cell::prove_reference(&expected, 1).unwrap();
    let first = cell::verify_historical(&expected, &raw)
        .unwrap()
        .observation();
    let second = cell::verify_historical(&expected, &raw)
        .unwrap()
        .observation();
    assert_eq!(first, second);
    refusal(
        node.verify_cell_live(&expected, &raw, || Ok(201)),
        "CELL_LIVE_START_WINDOW",
    );
    for (cuts, error) in [
        ([199, 201], "CELL_LIVE_FINISH_WINDOW"),
        ([160, 159], "CELL_LIVE_FINISH_WINDOW"),
    ] {
        let mut cuts = cuts.into_iter();
        refusal(
            node.verify_cell_live(&expected, &raw, || Ok(cuts.next().unwrap())),
            error,
        );
    }
    let live = node
        .verify_cell_live(&expected, &raw, || Ok(150))
        .unwrap()
        .observation();
    assert_eq!(live["computed_live"], true);
    assert_eq!(live["live_window_unix_seconds"], json!([150, 150]));
    assert_eq!(live["operation_consumed"], false);
    assert_eq!(
        cell::verify_historical(&expected, &raw)
            .unwrap()
            .observation(),
        first
    );
}

#[test]
fn two_real_node_stores_and_cold_recovery_agree_on_history_after_active_tip_changes() {
    for authenticated in [false, true] {
        let (directory, mut first) = node(authenticated);
        let (_other_directory, mut second) = node(authenticated);
        let request = admission("abstain_before_rng");
        let owner_raw = cell::canonical(&request).unwrap();
        let owner_pin: Hash = Sha256::digest(&owner_raw).into();
        // Both Nodes verify the same real block, not a producer-supplied root
        // or a test-only ParentContext constructor. The Cell parent is height 1.
        let packet = first
            .make(
                first.settings().genesis(),
                vec![],
                development_public(0).unwrap(),
                160,
                64,
            )
            .unwrap();
        let parent = first.admit(&packet, 160).unwrap();
        assert_eq!(second.admit(&packet, 160).unwrap(), parent);
        first.activate(parent).unwrap();
        second.activate(parent).unwrap();
        let before = first
            .cell_expected_from_owner(parent, &owner_raw, owner_pin)
            .unwrap();
        let independent = second
            .cell_expected_from_owner(parent, &owner_raw, owner_pin)
            .unwrap();
        let case = if authenticated {
            "history-authenticated"
        } else {
            "history-legacy"
        };
        retain_admission(case, &first, &request, &before, authenticated);
        retain_bytes(case, "parent.packet", &packet.encode().unwrap());
        assert_eq!(before.contract_id(), independent.contract_id());
        let raw = cell::prove_reference(&before, 1).unwrap();
        retain_bytes(case, "claim.json", &raw);
        let observation = cell::verify_historical(&before, &raw)
            .unwrap()
            .observation();
        assert_eq!(observation["parent_context"]["parent_height"], 1);
        assert_eq!(observation["parent_context"]["task_height"], 2);
        assert_eq!(
            observation["parent_context"]["consensus_time_unix_seconds"],
            160
        );
        assert_eq!(
            cell::verify_historical(&independent, &raw)
                .unwrap()
                .observation(),
            observation
        );
        let packet = first
            .make(parent, vec![], development_public(0).unwrap(), 170, 64)
            .unwrap();
        let id = first.admit(&packet, 170).unwrap();
        retain_bytes(case, "successor.packet", &packet.encode().unwrap());
        first.activate(id).unwrap();
        refusal(
            first.verify_cell_live(&before, &raw, || Ok(170)),
            "CELL_LIVE_PARENT",
        );
        assert_eq!(
            cell::verify_historical(&before, &raw)
                .unwrap()
                .observation(),
            observation
        );
        drop(first);
        let settings = Settings::development(Some(150)).unwrap();
        let reopened = if authenticated {
            Node::open_with_authenticated_state(directory.path(), settings, 1)
        } else {
            Node::open(directory.path(), settings, 1)
        }
        .unwrap();
        let reloaded = reopened
            .cell_expected_from_owner(parent, &owner_raw, owner_pin)
            .unwrap();
        assert_eq!(
            cell::verify_historical(&reloaded, &raw)
                .unwrap()
                .observation(),
            observation
        );
    }
}

#[test]
fn malformed_owner_schema_numbers_masks_and_utf8_fail_before_any_proof() {
    let (_directory, node) = node(false);
    let original = case("tool_proposal")["admission"].clone();
    let check = |raw: Vec<u8>, error: &str| {
        refusal(
            node.cell_expected_from_owner(
                node.settings().genesis(),
                &raw,
                Sha256::digest(&raw).into(),
            ),
            error,
        );
    };
    let mut unknown = original.clone();
    unknown["relation_valid"] = json!(true);
    check(cell::canonical(&unknown).unwrap(), "CELL_INPUT_SCHEMA");
    let mut boolean = original.clone();
    boolean["before"]["generation"] = json!(true);
    check(cell::canonical(&boolean).unwrap(), "CELL_INPUT_SCHEMA");
    let mut floating = original.clone();
    floating["before"]["sequence"] = json!(1.0);
    check(serde_json::to_vec(&floating).unwrap(), "CELL_INPUT_SCHEMA");
    let raw = cell::canonical(&original).unwrap();
    let duplicate = [b"{\"schema\":\"duplicate\",".as_slice(), &raw[1..]].concat();
    check(duplicate, "CELL_INPUT_SCHEMA");
    check([b" ".as_slice(), &raw].concat(), "CELL_CANONICAL_BYTES");
    let mut masked = original.clone();
    masked["policy"]["feature_mask"][256] = json!(false);
    check(cell::canonical(&masked).unwrap(), "CELL_FEATURE_MASK");
    masked = original.clone();
    masked["policy"]["expert_mask"][0] = json!([false, false, false]);
    check(cell::canonical(&masked).unwrap(), "CELL_EXPERT_MASK");
    let mut source = original.clone();
    source["inputs"][0]["content_hex"] = json!("ff");
    check(cell::canonical(&source).unwrap(), "CELL_SOURCE_UTF8");
    source = original.clone();
    source["inputs"][0]["content_hex"] = json!("CA");
    check(cell::canonical(&source).unwrap(), "CELL_SOURCE_HEX");
    let mut time = original;
    time["issued_at_unix_seconds"] = json!(151);
    check(cell::canonical(&time).unwrap(), "CELL_HISTORICAL_WINDOW");
}

#[test]
fn state_counter_weight_and_action_rules_refuse_instead_of_saturation_or_fallback() {
    let (_directory, node) = node(false);
    let mut request = admission("masked_sampling_training");
    request.before.sequence = u64::MAX;
    refusal(
        cell::prove_reference(&expected(&node, &request), 1),
        "CELL_SEQUENCE_OVERFLOW",
    );
    request.before.sequence = 11;
    request.before.rng_counter = u64::MAX;
    refusal(
        cell::prove_reference(&expected(&node, &request), 1),
        "CELL_RNG_COUNTER_OVERFLOW",
    );
    request.before.rng_counter = 3;
    request.policy.training.as_mut().unwrap().learning_rate_num = 1 << 20;
    request.policy.training.as_mut().unwrap().learning_rate_den = 1;
    refusal(
        cell::prove_reference(&expected(&node, &request), 1),
        "CELL_TRAINED_WEIGHT_RANGE",
    );
    let mut stopped = admission("all_stop_training_preserves");
    stopped.policy.allowed_actions = vec![cell::Action::Emit];
    refusal(
        cell::prove_reference(&expected(&node, &stopped), 1),
        "CELL_ACTION_NOT_ALLOWED",
    );
}

#[test]
fn maximum_batch_and_raw_source_token_cap_replay_all_columns_and_reject_one_more() {
    let (_directory, node) = node(false);
    let mut request = admission("coefficient_boundary");
    request.inputs = (0..64)
        .map(|index| cell::SourceSnippet {
            id: hex::encode(Sha256::digest(format!("maximum-batch/{index}"))),
            origin: format!("fixture/maximum-{index}.rs"),
            content_hex: hex::encode(b"b ".repeat(2048)),
            label: (index % 3) as u8,
        })
        .collect();
    request.policy.expert_mask = vec![vec![true; 3]; 64];
    request.before.remaining_steps = 64;
    let expected = expected(&node, &request);
    retain_admission("maximum-batch", &node, &request, &expected, false);
    let raw = cell::prove_reference(&expected, 1).unwrap();
    retain_bytes("maximum-batch", "claim.json", &raw);
    let verified = cell::verify_historical(&expected, &raw).unwrap();
    assert_eq!(verified.output()["row_ids"].as_array().unwrap().len(), 64);
    assert_eq!(verified.after_state().remaining_steps, 0);
    let decoded: Value = serde_json::from_slice(&raw).unwrap();
    for row in stage(&decoded, "source-preprocessing")["outputs"]["rows"]
        .as_array()
        .unwrap()
    {
        assert_eq!(row["used_tokens"], 1024);
        assert_eq!(row["features"][256], 8);
    }
    let mut oversized = request.clone();
    oversized.inputs.push(oversized.inputs[0].clone());
    let bytes = cell::canonical(&oversized).unwrap();
    refusal(
        node.cell_expected_from_owner(
            node.settings().genesis(),
            &bytes,
            Sha256::digest(&bytes).into(),
        ),
        "CELL_BATCH",
    );
    request.inputs[0].content_hex.push_str("20");
    let bytes = cell::canonical(&request).unwrap();
    refusal(
        node.cell_expected_from_owner(
            node.settings().genesis(),
            &bytes,
            Sha256::digest(&bytes).into(),
        ),
        "CELL_SOURCE_HEX",
    );
}

#[test]
fn a_following_native_task_really_consumes_the_verified_successor_model_and_state() {
    let (_directory, node) = node(false);
    let first_request = admission("masked_sampling_training");
    let first_expected = expected(&node, &first_request);
    let first_raw = cell::prove_reference(&first_expected, 1).unwrap();
    let first = cell::verify_historical(&first_expected, &first_raw).unwrap();
    assert_ne!(first.after_model(), &first_request.model);
    let mut following = first_request.clone();
    following.request_id = "77".repeat(32);
    following.model = first.after_model().clone();
    following.before = first.after_state().clone();
    for (index, input) in following.inputs.iter_mut().enumerate() {
        input.id = hex::encode(Sha256::digest(format!("following-native-task/{index}")));
        input
            .content_hex
            .push_str(&hex::encode(b" native_successor_task"));
    }
    let next_expected = expected(&node, &following);
    retain_admission("following-task", &node, &following, &next_expected, false);
    let next_raw = cell::prove_reference(&next_expected, 1).unwrap();
    retain_bytes("following-task", "claim.json", &next_raw);
    let next = cell::verify_historical(&next_expected, &next_raw).unwrap();
    assert_eq!(
        next.after_state().sequence,
        first.after_state().sequence + 1
    );
    assert_eq!(
        next.after_state().remaining_steps,
        first.after_state().remaining_steps - 4
    );
    let mut retired_model = following;
    retired_model.model = first_request.model;
    retired_model.before.model_artifact = cell::model_artifact(&retired_model.model).unwrap();
    let retired_expected = expected(&node, &retired_model);
    retain_admission(
        "retired-model-control",
        &node,
        &retired_model,
        &retired_expected,
        false,
    );
    let retired_raw = cell::prove_reference(&retired_expected, 1).unwrap();
    retain_bytes("retired-model-control", "claim.json", &retired_raw);
    let retired = cell::verify_historical(&retired_expected, &retired_raw).unwrap();
    assert_ne!(retired.output()["logits"], next.output()["logits"]);
    refusal(
        cell::verify_historical(&next_expected, &retired_raw),
        "CELL_EXPECTED_CONTRACT",
    );
    assert_eq!(next.observation()["checkpoint_committed"], false);
}

static CLI_ORDINAL: AtomicU64 = AtomicU64::new(0);

fn run_cli(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    if let Some(path) = std::env::var_os("CELL_NATIVE_V1_EVIDENCE_DIR") {
        let directory = std::path::PathBuf::from(path);
        fs::create_dir_all(&directory).unwrap();
        let ordinal = CLI_ORDINAL.fetch_add(1, Ordering::Relaxed);
        let prefix = directory.join(format!("cell-cli-{ordinal:03}"));
        for (extension, bytes) in [
            ("stdout", output.stdout.as_slice()),
            ("stderr", output.stderr.as_slice()),
        ] {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(prefix.with_extension(extension))
                .unwrap();
            std::io::Write::write_all(&mut file, bytes).unwrap();
        }
        fs::write(
            prefix.with_extension("json"),
            serde_json::to_vec(&json!({
                "actual_returncode":output.status.code(),"child_wait_completed":true,
                "local_correctness_fixture":true,"production_activation":false,
            }))
            .unwrap(),
        )
        .unwrap();
    }
    output
}

fn cli(command: &str, store: &Path, owner: &Path, pin: &str, parent: Hash) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    cmd.args([command, "--development", "--genesis-time", "150", "--store"])
        .arg(store)
        .arg("--cell-expected")
        .arg(owner)
        .args([
            "--cell-expected-sha256",
            pin,
            "--cell-parent",
            &hex::encode(parent),
        ]);
    cmd
}

#[track_caller]
fn cli_refusal(output: Output, code: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8(output.stderr).unwrap().contains(code),
        "expected {code}"
    );
}

#[test]
fn ordinary_native_cli_uses_separate_owner_input_and_real_node_parent_for_cold_historical_replay() {
    let (directory, node) = node(false);
    let request = admission("masked_sampling_training");
    let owner_bytes = cell::canonical(&request).unwrap();
    let pin = hex::encode(Sha256::digest(&owner_bytes));
    let parent = node.settings().genesis();
    let owner = directory.path().join("expected.json");
    let proof = directory.path().join("claim.json");
    fs::write(&owner, &owner_bytes).unwrap();
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
    drop(node);
    let produced = run_cli(
        cli(
            "cell-prove-reference",
            directory.path(),
            &owner,
            &pin,
            parent,
        )
        .arg("--output")
        .arg(&proof),
    );
    assert!(
        produced.status.success(),
        "{}",
        String::from_utf8_lossy(&produced.stderr)
    );
    let mut observed = Vec::new();
    for _ in 0..2 {
        let accepted = run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&proof),
        );
        assert!(
            accepted.status.success(),
            "{}",
            String::from_utf8_lossy(&accepted.stderr)
        );
        let receipt: Value = serde_json::from_slice(&accepted.stdout).unwrap();
        assert_eq!(receipt["clock_scope"], "verified-parent-state-unix-seconds");
        assert_eq!(receipt["result"]["computed_historical"], true);
        assert_eq!(receipt["result"]["consensus_work_admitted"], false);
        observed.push(receipt);
    }
    assert_eq!(observed[0], observed[1]);
    cli_refusal(
        run_cli(
            cli("cell-verify-live", directory.path(), &owner, &pin, parent)
                .arg("--cell-claim")
                .arg(&proof),
        ),
        "CELL_LIVE_START_WINDOW",
    );
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &pin,
                [255; 32],
            )
            .arg("--cell-claim")
            .arg(&proof),
        ),
        "UNKNOWN_PARENT",
    );
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&proof)
            .args(["--logical-now", "150"]),
        ),
        "CELL_CLOCK_NOT_CONFIGURABLE",
    );
    let producer_pin = hex::encode(Sha256::digest(fs::read(&proof).unwrap()));
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &proof,
                &producer_pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&proof),
        ),
        "CELL_INPUT_SCHEMA",
    );
    let mut foreign = request;
    foreign.consumer = "producer-chosen-consumer".into();
    fs::write(&owner, cell::canonical(&foreign).unwrap()).unwrap();
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&proof),
        ),
        "CELL_OWNER_ADMISSION_SHA256",
    );
    let foreign_pin = hex::encode(Sha256::digest(fs::read(&owner).unwrap()));
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &foreign_pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&proof),
        ),
        "CELL_EXPECTED_CONTRACT",
    );
}

#[test]
fn native_cli_refuses_writable_symlinked_missing_owner_inputs_and_new_store_creation() {
    let (directory, node) = node(false);
    let parent = node.settings().genesis();
    let bytes = cell::canonical(&admission("tool_proposal")).unwrap();
    let pin = hex::encode(Sha256::digest(&bytes));
    let owner = directory.path().join("expected.json");
    let link = directory.path().join("expected-link.json");
    let claim = directory.path().join("claim.json");
    fs::write(&owner, &bytes).unwrap();
    fs::write(&claim, b"{}").unwrap();
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o666)).unwrap();
    symlink(&owner, &link).unwrap();
    drop(node);
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &owner,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&claim),
        ),
        "CELL_OWNER_FILE",
    );
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                directory.path(),
                &link,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&claim),
        ),
        "CELL_INPUT_FILE",
    );
    fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
    let missing_store = directory.path().join("must-not-be-created");
    cli_refusal(
        run_cli(
            cli(
                "cell-verify-historical",
                &missing_store,
                &owner,
                &pin,
                parent,
            )
            .arg("--cell-claim")
            .arg(&claim),
        ),
        "CELL_EXISTING_STORE_REQUIRED",
    );
    assert!(!missing_store.exists());
    let mut missing = Command::new(env!("CARGO_BIN_EXE_trnm-pon-node"));
    missing
        .args([
            "cell-verify-historical",
            "--development",
            "--genesis-time",
            "150",
            "--store",
        ])
        .arg(directory.path())
        .args([
            "--cell-expected-sha256",
            &pin,
            "--cell-parent",
            &hex::encode(parent),
        ])
        .arg("--cell-claim")
        .arg(&claim);
    cli_refusal(run_cli(&mut missing), "missing --cell-expected");
}
