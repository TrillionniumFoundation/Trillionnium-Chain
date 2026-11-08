//! Continuing public-branch research with exact conditional receiver schedules.
//! The honest producer has an isolated view until the four-second horizon.
use super::{
    assert_python_source_snapshot, digest, initialize_history, json_new, logical_now,
    native_sources, native_verify, packet_record, probe_complete_candidate_checks,
    read_bridge_input, read_packet, root, work, write_new, CLOCK_ORIGIN, GENESIS_TIME,
};
use crate::{consensus, development_public, maintenance, Node, Packet, Settings};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::Hash;

const INPUTS: &[&str] = &[
    "native-fixture.json",
    "native-competition-plan.json",
    "native-competition-fixture.json",
    "competition-certificates.json",
    "competition-samples.json",
];
const SCENARIOS: [&str; 2] = [
    "honest-before-private-publication",
    "honest-after-private-publication",
];

fn plan() -> Value {
    json!({
        "schema":"trnm-w1-native-competition-plan-v1","horizon_seconds":"4",
        "max_private_attempts":2,"sample_seed":9,"honest_heights":[17,18],
        "honest_timestamps":[CLOCK_ORIGIN+1,CLOCK_ORIGIN+2],
        "max_honest_attempts_per_block":4096,
        "public_producer_view":"isolated-public-branch-until-horizon",
        "equal_time_order":"honest-before-private-parent-first",
        "scenario_times":{
            "honest-before-private-publication":[{"numerator":1,"denominator":1},{"numerator":3,"denominator":1}],
            "honest-after-private-publication":[{"numerator":5,"denominator":2},{"numerator":7,"denominator":2}]
        },
        "selection":"source-declared schedule before honest packet generation; no external timestamp attestation",
        "native_honest_production_wall_time_is_arrival_time":false
    })
}

fn ledger_row(file: &mut fs::File, value: &Value) {
    file.write_all(&serde_json::to_vec(value).unwrap()).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_data().unwrap();
}

fn produce_honest(
    node: &mut Node,
    directory: &Path,
    stem: &str,
    height: u64,
    now: u64,
) -> (Packet, Value, Value) {
    let started = Instant::now();
    let parent = node.read_active().unwrap().0;
    let parent_work = work(node);
    let ledger_name = format!("honest-production-{stem}-h{height}.jsonl");
    let ledger_path = directory.join(&ledger_name);
    let mut ledger = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&ledger_path)
        .unwrap();
    ledger_row(
        &mut ledger,
        &json!({"event":"started","parent_id":hex::encode(parent),
        "height":height,"logical_observed_now":now,"max_attempts":4096}),
    );
    let preparation = Instant::now();
    let (a, b) = maintenance();
    let candidate = node
        .prepare_from_matrices(
            parent,
            vec![],
            development_public(0).unwrap(),
            CLOCK_ORIGIN + height - 16,
            &a,
            &b,
        )
        .unwrap();
    let prepare_elapsed_ns = preparation.elapsed().as_nanos();
    assert_eq!(candidate.header.height, height);
    assert_eq!(candidate.header.nonce, 0);
    assert_eq!(
        candidate.header.target,
        node.expected_target(parent).unwrap()
    );
    ledger_row(
        &mut ledger,
        &json!({"event":"prepared","prepare_elapsed_ns":prepare_elapsed_ns}),
    );
    let credit = parent_work
        .checked_add(consensus::required_work(candidate.header.target).unwrap())
        .unwrap();
    let mut attempts = Vec::new();
    let mut selected = None;
    for nonce in 0..4096 {
        let mut header = candidate.header.clone();
        header.nonce = nonce;
        let proof_started = Instant::now();
        let packet = Packet {
            proof: candidate.prepared.prove(header.challenge()).unwrap(),
            header,
            transactions: candidate.transactions.clone(),
        };
        let proof_elapsed_ns = proof_started.elapsed().as_nanos();
        let verify_started = Instant::now();
        let verdict = native_verify(&packet);
        let verification_elapsed_ns = verify_started.elapsed().as_nanos();
        let winner = verdict.is_ok();
        if let Err(error) = &verdict {
            assert_eq!(*error, pon_work::WorkError::Target);
        }
        let mut block = packet_record(&packet, credit, directory);
        block["native_winner"] = json!(winner);
        block["native_verifier_error"] = json!(verdict.err().map(|error| format!("{error:?}")));
        block["complete_native_proof_generated"] = json!(true);
        let mut attempt = block.clone();
        attempt["proof_elapsed_ns"] = json!(proof_elapsed_ns);
        attempt["verification_elapsed_ns"] = json!(verification_elapsed_ns);
        ledger_row(&mut ledger, &json!({"event":"attempt","outcome":attempt}));
        attempts.push(attempt);
        if winner {
            selected = Some((packet, block));
            break;
        }
    }
    if selected.is_none() {
        ledger_row(
            &mut ledger,
            &json!({"event":"exhausted","completed_attempts":attempts.len()}),
        );
    }
    let (packet, block) =
        selected.expect("bounded honest proof search exhausted; all attempts retained");
    let admission = Instant::now();
    let id = node.admit(&packet, now).unwrap();
    assert_eq!(id, packet.id().unwrap());
    assert_eq!(node.activate_observed(id, now).unwrap(), id);
    assert_eq!(work(node), credit);
    let admit_activate_elapsed_ns = admission.elapsed().as_nanos();
    ledger_row(
        &mut ledger,
        &json!({"event":"admitted","selected_block_id":hex::encode(id),
        "admit_activate_elapsed_ns":admit_activate_elapsed_ns}),
    );
    let complete_pipeline_elapsed_ns = started.elapsed().as_nanos();
    drop(ledger);
    let ledger_bytes = fs::read(&ledger_path).unwrap();
    let receipt = json!({
        "height":height,"parent_id":hex::encode(parent),"selected_block_id":hex::encode(id),
        "prepare_elapsed_ns":prepare_elapsed_ns,"attempts":attempts,"max_attempts":4096,
        "admit_activate_elapsed_ns":admit_activate_elapsed_ns,
        "complete_pipeline_elapsed_ns":complete_pipeline_elapsed_ns,
        "logical_observed_now":now,"native_producer_admitted":true,
        "ledger_file":ledger_name,"ledger_bytes":ledger_bytes.len(),"ledger_sha256":digest(&ledger_bytes),
        "scope":"fresh isolated-view honest producer; every failed proof retained; CPU wall times are not scheduled arrival times",
        "pipeline_clock_scope":"prepare through admission and ledger append/fsync; excludes later readback/digest, metadata serialization and separately recorded preexisting-history replay",
        "quantum_hardware_executed":false
    });
    (packet, block, receipt)
}

#[test]
#[ignore = "explicit native continuing-public-branch fixture after the base DAG export"]
fn export_source_bound_native_competition_fixture() {
    let directory = PathBuf::from(std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR").unwrap());
    let source_before = native_sources();
    let base_bytes = read_bridge_input(&directory.join("native-fixture.json"));
    let base: Value = serde_json::from_slice(&base_bytes).unwrap();
    assert_eq!(base["native_source"], source_before);
    assert_eq!(base["genesis_timestamp"], GENESIS_TIME);
    assert_eq!(base["clock_origin_timestamp"], CLOCK_ORIGIN);
    let fixed_plan = plan();
    json_new(&directory.join("native-competition-plan.json"), &fixed_plan);
    json_new(
        &directory.join("native-competition-source-before.json"),
        &source_before,
    );
    let temporary = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
    let mut producer =
        Node::open_with_authenticated_state(&temporary.path().join("honest"), settings, 1).unwrap();
    let preexisting_replay_elapsed_ns = initialize_history(&mut producer, &directory, &base);
    let mut blocks = Vec::new();
    let mut production = Vec::new();
    for height in 17..=18 {
        let (_, block, receipt) = produce_honest(
            &mut producer,
            &directory,
            "fixture",
            height,
            CLOCK_ORIGIN + height - 16,
        );
        blocks.push(block);
        production.push(receipt);
    }
    let scenarios: Vec<_> = SCENARIOS
        .iter()
        .map(|name| {
            let arrivals: Vec<_> = blocks
                .iter()
                .zip(fixed_plan["scenario_times"][*name].as_array().unwrap())
                .map(|(block, at)| json!({"block_id":block["block_id"],"at_seconds":at}))
                .collect();
            json!({"scenario_id":name,"arrivals":arrivals})
        })
        .collect();
    assert_eq!(source_before, native_sources());
    assert_eq!(
        base_bytes,
        read_bridge_input(&directory.join("native-fixture.json"))
    );
    let report = json!({
        "schema":"trnm-w1-native-competition-fixture-v1","native_source":source_before,
        "base_fixture_file_sha256":digest(&base_bytes),
        "base_fixture_canonical_sha256":digest(&serde_json::to_vec(&base).unwrap()),
        "plan_file_sha256":digest(&read_bridge_input(&directory.join("native-competition-plan.json"))),
        "fixed_plan":fixed_plan,"public_producer_view":"isolated-public-branch-until-horizon",
        "equal_time_order":"honest-before-private-parent-first",
        "honest_blocks":blocks,"honest_production":production,"scenarios":scenarios,
        "initial_resources":{"preexisting_history_replay_elapsed_ns":preexisting_replay_elapsed_ns,
            "honest_production_costs":"all complete proof attempts, failed and accepted, and actual CPU stage clocks retained",
            "network_condition":"public producer does not receive private publication before horizon; receiver follows the declared event order",
            "arrival_times":"conditional exact logical schedule; no production-rate or network-latency calibration"},
        "claims":{"complete_native_honest_proofs_generated":true,"all_failed_honest_attempts_retained":true,
            "offline_native_honest_chain_admitted":true,
            "conditional_arrivals_are_measured_mining_or_network_times":false,
            "honest_producer_receives_private_publications_before_horizon":false,
            "native_public_ingress_executed":false,"quantum_hardware_executed":false,
            "quantum_mining_qualified":false,"production_activation":false}
    });
    json_new(&directory.join("native-competition-fixture.json"), &report);
    eprintln!(
        "native_w1_competition_fixture {}",
        json!({"honest_blocks":2,"scenarios":2,
        "complete_honest_attempts":report["honest_production"].as_array().unwrap().iter()
            .map(|row|row["attempts"].as_array().unwrap().len()).sum::<usize>(),"quantum_hardware_executed":false})
    );
}

fn assert_receipt(
    receipt: &Value,
    inputs: &BTreeMap<&str, Vec<u8>>,
    samples: &Value,
    source: &Value,
) {
    assert_eq!(receipt["schema"], "trnm-w1-native-competition-samples-v1");
    assert_eq!(receipt["status"], "VERIFIED");
    assert_eq!(
        receipt["runs"].as_u64().unwrap(),
        samples["runs"].as_array().unwrap().len() as u64
    );
    let hashes: BTreeMap<_, _> = inputs
        .iter()
        .map(|(name, raw)| (*name, digest(raw)))
        .collect();
    assert_eq!(receipt["verified_inputs"], json!(hashes));
    assert_eq!(receipt["source_snapshot"], samples["source"]);
    assert_eq!(receipt["source_snapshot"]["git_head"], source["git_head"]);
    assert!(Path::new(receipt["runtime_identity"]["executable"].as_str().unwrap()).is_absolute());
    for field in ["version", "implementation"] {
        assert!(!receipt["runtime_identity"][field]
            .as_str()
            .unwrap()
            .is_empty());
    }
    assert_eq!(receipt["native_blocks_admitted_by_python_reader"], 0);
    assert_eq!(receipt["quantum_hardware_executed"], false);
}

fn assert_honest_ledgers(directory: &Path, fixture: &Value) {
    for row in fixture["honest_production"].as_array().unwrap() {
        let name = row["ledger_file"].as_str().unwrap();
        assert!(
            name.starts_with("honest-production-fixture-h")
                && name.ends_with(".jsonl")
                && !name.contains('/')
                && !name.contains('\\')
        );
        let raw = read_bridge_input(&directory.join(name));
        assert_eq!(raw.len() as u64, row["ledger_bytes"].as_u64().unwrap());
        assert_eq!(digest(&raw), row["ledger_sha256"]);
    }
}

fn assert_payload_snapshot(directory: &Path, base: &Value, fixture: &Value, receipt: &Value) {
    let mut expected = BTreeMap::new();
    let mut packets = base["prefix"]["packets"].as_array().unwrap().clone();
    packets.push(base["public_tip"].clone());
    for context in base["contexts"].as_array().unwrap() {
        packets.extend(context["all_nonce_outcomes"].as_array().unwrap().clone());
    }
    for row in fixture["honest_production"].as_array().unwrap() {
        packets.extend(row["attempts"].as_array().unwrap().clone());
    }
    for row in packets {
        let name = row["packet_file"].as_str().unwrap().to_owned();
        assert!(name.starts_with("packets/") && !name.contains("..") && !name.contains('\\'));
        let hash = row["packet_sha256"].as_str().unwrap().to_owned();
        if let Some(previous) = expected.insert(name, hash.clone()) {
            assert_eq!(previous, hash);
        }
    }
    for row in fixture["honest_production"].as_array().unwrap() {
        let name = row["ledger_file"].as_str().unwrap().to_owned();
        assert!(
            name.starts_with("honest-production-fixture-h")
                && !name.contains('/')
                && !name.contains('\\')
        );
        assert!(expected
            .insert(name, row["ledger_sha256"].as_str().unwrap().to_owned())
            .is_none());
    }
    assert_eq!(receipt["verified_payloads"], json!(expected));
    for (name, hash) in expected {
        assert_eq!(digest(&read_bridge_input(&directory.join(name))), hash);
    }
}

#[test]
fn competition_receipt_binds_every_input_and_preserves_failed_attempt_ledgers() {
    let inputs: BTreeMap<&str, Vec<u8>> = INPUTS
        .iter()
        .map(|name| (*name, name.as_bytes().to_vec()))
        .collect();
    let source = json!({"git_head":"source","source_sha256":{"reader":"digest"}});
    let samples = json!({"source":source,"runs":[]});
    let hashes: BTreeMap<_, _> = inputs
        .iter()
        .map(|(name, raw)| (*name, digest(raw)))
        .collect();
    let receipt = json!({"schema":"trnm-w1-native-competition-samples-v1","status":"VERIFIED","runs":0,
        "verified_inputs":hashes,"source_snapshot":source,
        "runtime_identity":{"executable":"/usr/bin/python3","version":"structural control","implementation":"cpython"},
        "native_blocks_admitted_by_python_reader":0,"quantum_hardware_executed":false});
    assert_receipt(&receipt, &inputs, &samples, &source);
    for name in INPUTS {
        let mut changed = inputs.clone();
        changed.get_mut(name).unwrap().push(b' ');
        assert!(
            std::panic::catch_unwind(|| assert_receipt(&receipt, &changed, &samples, &source))
                .is_err()
        );
    }
    let temporary = tempfile::tempdir().unwrap();
    let name = "honest-production-fixture-h17.jsonl";
    write_new(&temporary.path().join(name), b"retained failed attempt\n");
    let fixture = json!({"honest_production":[{"ledger_file":name,"ledger_bytes":b"retained failed attempt\n".len(),
        "ledger_sha256":digest(b"retained failed attempt\n")}]});
    assert_honest_ledgers(temporary.path(), &fixture);
    fs::write(temporary.path().join(name), b"removed miss\n").unwrap();
    assert!(
        std::panic::catch_unwind(|| assert_honest_ledgers(temporary.path(), &fixture)).is_err()
    );
}

#[test]
#[ignore = "explicit native interleaved replay of verified continuing-public-branch samples"]
fn replay_source_bound_native_competition_samples() {
    let directory = PathBuf::from(std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR").unwrap());
    let source_before = native_sources();
    let inputs: BTreeMap<&str, Vec<u8>> = INPUTS
        .iter()
        .map(|name| (*name, read_bridge_input(&directory.join(name))))
        .collect();
    let base: Value = serde_json::from_slice(&inputs["native-fixture.json"]).unwrap();
    let fixture: Value =
        serde_json::from_slice(&inputs["native-competition-fixture.json"]).unwrap();
    let samples: Value = serde_json::from_slice(&inputs["competition-samples.json"]).unwrap();
    assert_eq!(base["native_source"], source_before);
    assert_eq!(fixture["native_source"], source_before);
    assert_eq!(base["genesis_timestamp"], GENESIS_TIME);
    assert_eq!(base["clock_origin_timestamp"], CLOCK_ORIGIN);
    assert_eq!(samples["schema"], "trnm-w1-native-competition-samples-v1");
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    assert_honest_ledgers(&directory, &fixture);
    let python = std::env::var_os("TRNM_RESEARCH_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(python)
        .arg(root().join("formal/pon-nakamoto-v1/experiments/w1_native_competition.py"))
        .arg("--verify")
        .arg(&directory)
        .output()
        .unwrap();
    write_new(
        &directory.join("native-competition-pre-replay-python.stdout"),
        &output.stdout,
    );
    write_new(
        &directory.join("native-competition-pre-replay-python.stderr"),
        &output.stderr,
    );
    assert!(
        output.status.success(),
        "competition verifier refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verifier_receipt: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_receipt(&verifier_receipt, &inputs, &samples, &source_before);
    assert_payload_snapshot(&directory, &base, &fixture, &verifier_receipt);
    assert_eq!(source_before, native_sources());
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    for (name, raw) in &inputs {
        assert_eq!(*raw, read_bridge_input(&directory.join(name)));
    }
    let mut results = Vec::new();
    for (run_index, sample) in samples["runs"].as_array().unwrap().iter().enumerate() {
        let temporary = tempfile::tempdir().unwrap();
        let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
        let receiver_path = temporary.path().join("receiver");
        let mut receiver =
            Node::open_with_authenticated_state(&receiver_path, settings.clone(), 1).unwrap();
        let receiver_history_ns = initialize_history(&mut receiver, &directory, &base);
        let mut private = Node::open_with_authenticated_state(
            &temporary.path().join("private"),
            settings.clone(),
            1,
        )
        .unwrap();
        let private_history_ns = initialize_history(&mut private, &directory, &base);
        let mut honest = Node::open_with_authenticated_state(
            &temporary.path().join("honest"),
            settings.clone(),
            1,
        )
        .unwrap();
        let honest_history_ns = initialize_history(&mut honest, &directory, &base);
        let (candidate_probes, mut private_packets) =
            probe_complete_candidate_checks(&mut private, &directory, &base, sample);
        let expected_checks = sample["raw_observation"]["trajectory"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["edge"]["observation"]["candidate_check_complete"] == true)
            .count();
        assert_eq!(candidate_probes.len(), expected_checks);
        let private_proofs_held = private_packets.len();
        let private_ids: BTreeSet<String> = sample["packets_to_submit"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["block_id"].as_str().unwrap().to_owned())
            .collect();
        let before_stats = receiver.stats().unwrap();
        let mut receipts = Vec::new();
        let mut honest_production = Vec::new();
        let mut ever_private_replacement = false;
        for event in sample["receiver_events"].as_array().unwrap() {
            let now = logical_now(&event["at_seconds"]);
            let owner = event["owner"].as_str().unwrap();
            let id: Hash = hex::decode(event["block_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let packet = match owner {
                "honest" => {
                    let retained = fixture["honest_blocks"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|row| row["block_id"] == event["block_id"])
                        .unwrap();
                    let (packet, block, receipt) = produce_honest(
                        &mut honest,
                        &directory,
                        &format!("run-{run_index}"),
                        event["height"].as_u64().unwrap(),
                        now,
                    );
                    assert_eq!(block, *retained);
                    assert_eq!(
                        packet.encode().unwrap(),
                        read_packet(&directory, retained).encode().unwrap()
                    );
                    honest_production.push(receipt);
                    packet
                }
                "private" => {
                    assert_eq!(sample["publication_complete"], true);
                    assert!(private_ids.contains(event["block_id"].as_str().unwrap()));
                    private_packets.remove(&id).unwrap()
                }
                _ => panic!("undeclared event owner"),
            };
            let selected_before = receiver.read_active().unwrap().0;
            assert_eq!(hex::encode(selected_before), event["selected_tip_before"]);
            assert_eq!(packet.id().unwrap(), id);
            assert_eq!(hex::encode(packet.header.parent), event["parent_id"]);
            let verification = Instant::now();
            native_verify(&packet).unwrap();
            let actual_verification_elapsed_ns = verification.elapsed().as_nanos();
            let admission = Instant::now();
            assert_eq!(receiver.admit(&packet, now).unwrap(), id);
            let actual_admission_elapsed_ns = admission.elapsed().as_nanos();
            let activation = Instant::now();
            let selected = receiver.activate_observed(id, now).unwrap();
            let actual_activation_elapsed_ns = activation.elapsed().as_nanos();
            assert_eq!(hex::encode(selected), event["selected_tip"]);
            assert_eq!(
                hex::encode(work(&receiver).bytes()),
                event["selected_chainwork_hex"]
            );
            assert_eq!(
                selected != selected_before,
                event["selection_changed"].as_bool().unwrap()
            );
            let replacement = owner == "private"
                && selected == id
                && !private_ids.contains(&hex::encode(selected_before));
            assert_eq!(replacement, event["private_replacement"].as_bool().unwrap());
            ever_private_replacement |= replacement;
            receipts.push(json!({"expected_event":event,"logical_observed_now":now,
                "selected_tip":hex::encode(selected),"selected_chainwork_hex":hex::encode(work(&receiver).bytes()),
                "native_library_admitted":true,"packet_sha256":digest(&packet.encode().unwrap()),
                "proof_sha256":digest(&packet.proof),"actual_verification_elapsed_ns":actual_verification_elapsed_ns,
                "actual_admission_elapsed_ns":actual_admission_elapsed_ns,"actual_activation_elapsed_ns":actual_activation_elapsed_ns}));
        }
        assert_eq!(honest_production.len(), 2);
        let after = receiver.read_active().unwrap();
        let after_stats = receiver.stats().unwrap();
        let private_active_at_horizon = private_ids.contains(&hex::encode(after.0));
        assert_eq!(
            ever_private_replacement,
            sample["expected_ever_private_replacement"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            private_active_at_horizon,
            sample["expected_private_active_at_horizon"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(
            hex::encode(after.0),
            sample["expected_selected_tip_at_horizon"]
        );
        assert_eq!(
            hex::encode(work(&receiver).bytes()),
            sample["expected_selected_chainwork_at_horizon_hex"]
        );
        drop(receiver);
        let reopened = Node::open_with_authenticated_state(&receiver_path, settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), after);
        assert_eq!(reopened.stats().unwrap(), after_stats);
        for receipt in &receipts {
            let id: Hash = hex::decode(receipt["expected_event"]["block_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                digest(&reopened.packet(id).unwrap().encode().unwrap()),
                receipt["packet_sha256"]
            );
        }
        results.push(json!({"name":sample["name"],"observation_kind":sample["observation_kind"],
            "scenario_id":sample["scenario_id"],"execution_kind":sample["execution_kind"],
            "candidate_probes":candidate_probes,"completed_candidate_checks_replayed":expected_checks,
            "private_proofs_held":private_proofs_held,"private_proofs_not_published":private_packets.len(),
            "honest_production":honest_production,"receiver_admissions":receipts,
            "receiver_history_replay_elapsed_ns":receiver_history_ns,"private_history_replay_elapsed_ns":private_history_ns,
            "honest_history_replay_elapsed_ns":honest_history_ns,"before":before_stats,"after":after_stats,
            "ever_private_replacement":ever_private_replacement,"private_active_at_horizon":private_active_at_horizon,
            "authenticated_reopen_equal":true,"logical_receiver_horizon_seconds":"4",
            "private_honest_cpu_probes_are_offline_reexecution":true,"quantum_hardware_executed":false}));
    }
    assert_eq!(source_before, native_sources());
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    assert_honest_ledgers(&directory, &fixture);
    assert_payload_snapshot(&directory, &base, &fixture, &verifier_receipt);
    for (name, raw) in &inputs {
        assert_eq!(*raw, read_bridge_input(&directory.join(name)));
    }
    let report = json!({"schema":"trnm-w1-native-competition-replay-v1","native_source":source_before,
        "verified_inputs":verifier_receipt["verified_inputs"],"independent_python_verifier":verifier_receipt,
        "verifier_stdout_sha256":digest(&output.stdout),"verifier_stderr_sha256":digest(&output.stderr),"runs":results,
        "claims":{"native_library_node_executed":true,"fresh_receiver_and_two_producers_per_run":true,
            "all_completed_private_checks_replayed":true,"all_honest_attempts_freshly_replayed":true,
            "honest_arrivals_continue_after_private_termination":true,"authenticated_reopens_equal":true,
            "verified_raw_inputs_unchanged_through_replay":true,"real_time_search_budget_verified":false,
            "conditional_receiver_schedule_only":true,"public_ingress_executed":false,
            "stochastic_continuing_honest_mining_covered":false,"quantum_hardware_executed":false,
            "quantum_mining_qualified":false,"production_activation":false}});
    json_new(&directory.join("native-competition-replay.json"), &report);
    eprintln!(
        "native_w1_competition_replay {}",
        json!({"runs":report["runs"].as_array().unwrap().len(),
        "native_library_node_executed":true,"quantum_hardware_executed":false})
    );
}
