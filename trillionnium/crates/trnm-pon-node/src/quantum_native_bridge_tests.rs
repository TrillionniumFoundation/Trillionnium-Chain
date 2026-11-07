//! Explicit research harness: real PNW1/Node execution, conditional model clocks.
//! The offline DAG census and prefix are retained advice, not free online mining.
//! Neither these tests nor a selected q=0 path execute quantum hardware.
mod competition;

use crate::{consensus, development_public, maintenance, Node, Packet, Settings};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Instant,
};
use trnm_crypto_primitives::pon_work;
use trnm_protocol::pon_wire::{Hash, Header};

const GENESIS_TIME: u64 = 1_750_000_000;
const CLOCK_ORIGIN: u64 = GENESIS_TIME + 160;
const NONCE_BITS: u64 = 3;
const NATIVE_SOURCE_PREFIXES: &[&str] = &[
    "trillionnium",
    "config",
    "rust-toolchain.toml",
    "scripts/project-preflight.sh",
];

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn json_new(path: &Path, value: &Value) {
    write_new(path, &serde_json::to_vec_pretty(value).unwrap());
}

fn native_sources() -> Value {
    let repo = root();
    let head = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(head.status.success());
    let mut command = Command::new("git");
    command
        .args([
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
        ])
        .args(NATIVE_SOURCE_PREFIXES)
        .current_dir(&repo);
    let output = command.output().unwrap();
    assert!(output.status.success());
    let mut files = BTreeMap::new();
    for name in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|s| !s.is_empty())
    {
        let name = std::str::from_utf8(name).unwrap();
        let path = repo.join(name);
        assert!(fs::symlink_metadata(&path).unwrap().file_type().is_file());
        files.insert(name.to_owned(), digest(&fs::read(path).unwrap()));
    }
    let status = Command::new("git")
        .args(["status", "--porcelain=v1", "--untracked-files=all", "--"])
        .args(NATIVE_SOURCE_PREFIXES)
        .current_dir(&repo)
        .output()
        .unwrap();
    assert!(status.status.success());
    let binary = std::env::current_exe().unwrap();
    json!({
        "git_head":String::from_utf8(head.stdout).unwrap().trim(),
        "source_sha256":files,
        "worktree_status":String::from_utf8(status.stdout).unwrap(),
        "binary_sha256":digest(&fs::read(binary).unwrap()),
        "compiler_source_binding":"requires separate exact-source build receipt; this is runtime inventory"
    })
}

const BRIDGE_INPUT_NAMES: &[&str] = &[
    "native-fixture.json",
    "finite-certificate.json",
    "classical-certificate.json",
    "bridge-samples.json",
];

fn read_bridge_input(path: &Path) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).unwrap();
    assert!(metadata.file_type().is_file());
    assert!(metadata.len() <= 32_000_000);
    fs::read(path).unwrap()
}

fn assert_python_source_snapshot(snapshot: &Value, git_head: &Value) {
    assert_eq!(snapshot["git_head"], *git_head);
    let repo = root();
    let manifest = snapshot["source_sha256"].as_object().unwrap();
    assert!(!manifest.is_empty());
    for (name, expected) in manifest {
        let relative = Path::new(name);
        assert!(!relative.as_os_str().is_empty());
        assert!(relative
            .components()
            .all(|c| matches!(c, Component::Normal(_))));
        let path = repo.join(relative);
        assert!(path.canonicalize().unwrap().starts_with(&repo));
        assert_eq!(digest(&read_bridge_input(&path)), *expected);
    }
}

fn assert_bridge_verifier_receipt(
    receipt: &Value,
    inputs: &BTreeMap<&str, Vec<u8>>,
    samples: &Value,
    native_source: &Value,
) {
    assert_eq!(receipt["schema"], "trnm-w1-native-bridge-samples-v1");
    assert_eq!(receipt["status"], "VERIFIED");
    assert_eq!(
        receipt["runs"].as_u64().unwrap(),
        samples["runs"].as_array().unwrap().len() as u64
    );
    let expected: BTreeMap<_, _> = inputs
        .iter()
        .map(|(name, bytes)| (*name, digest(bytes)))
        .collect();
    assert_eq!(receipt["verified_inputs"], json!(expected));
    assert_eq!(receipt["source_snapshot"], samples["source"]);
    assert_eq!(
        receipt["source_snapshot"]["git_head"],
        native_source["git_head"]
    );
    let runtime = &receipt["runtime_identity"];
    assert!(Path::new(runtime["executable"].as_str().unwrap()).is_absolute());
    for field in ["version", "implementation"] {
        assert!(!runtime[field].as_str().unwrap().is_empty());
    }
    assert_eq!(receipt["native_blocks_admitted_by_python_reader"], 0);
    assert_eq!(receipt["quantum_hardware_executed"], false);
}

#[test]
fn bridge_verifier_receipt_binds_raw_inputs_source_and_runtime() {
    let inputs: BTreeMap<&str, Vec<u8>> = BRIDGE_INPUT_NAMES
        .iter()
        .map(|name| (*name, format!("{{\"name\":\"{name}\"}}\n").into_bytes()))
        .collect();
    let source = json!({"git_head":"exact-head","source_sha256":{"reader.py":"digest"}});
    let samples = json!({"source":source,"runs":[{"name":"fixed-q0-seed9"}]});
    let native = json!({"git_head":"exact-head"});
    let hashes: BTreeMap<_, _> = inputs
        .iter()
        .map(|(name, bytes)| (*name, digest(bytes)))
        .collect();
    let receipt = json!({"schema":"trnm-w1-native-bridge-samples-v1","status":"VERIFIED",
        "runs":1,"verified_inputs":hashes,"source_snapshot":source,
        "runtime_identity":{"executable":"/usr/bin/python3","version":"unit structural fixture","implementation":"cpython"},
        "native_blocks_admitted_by_python_reader":0,"quantum_hardware_executed":false});
    assert_bridge_verifier_receipt(&receipt, &inputs, &samples, &native);
    // Even semantically unchanged whitespace after verification changes raw bytes.
    for name in BRIDGE_INPUT_NAMES {
        let mut changed = inputs.clone();
        changed.get_mut(name).unwrap().push(b' ');
        assert!(std::panic::catch_unwind(|| assert_bridge_verifier_receipt(
            &receipt, &changed, &samples, &native
        ))
        .is_err());
    }
    for field in ["schema", "status", "source_snapshot", "runtime_identity"] {
        let mut changed = receipt.clone();
        changed[field] = Value::Null;
        assert!(std::panic::catch_unwind(|| assert_bridge_verifier_receipt(
            &changed, &inputs, &samples, &native
        ))
        .is_err());
    }
}

fn work(node: &Node) -> consensus::Work {
    consensus::Work::from_bytes(
        hex::decode(node.stats().unwrap()["chainwork_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    )
}

fn packet_record(packet: &Packet, chainwork: consensus::Work, directory: &Path) -> Value {
    let id = packet.id().unwrap();
    let bytes = packet.encode().unwrap();
    let file = format!("packets/{}.pnk", hex::encode(id));
    let path = directory.join(&file);
    if path.exists() {
        assert_eq!(fs::read(path).unwrap(), bytes);
    } else {
        write_new(&path, &bytes);
    }
    json!({
        "block_id":hex::encode(id),"parent_id":hex::encode(packet.header.parent),
        "height":packet.header.height,"timestamp":packet.header.timestamp,
        "target_hex":hex::encode(packet.header.target),"chainwork_hex":hex::encode(chainwork.bytes()),
        "required_work_hex":hex::encode(consensus::required_work(packet.header.target).unwrap().bytes()),
        "header_hex":hex::encode(packet.header.encode()),"nonce":packet.header.nonce,
        "trace":hex::encode(&packet.proof[packet.proof.len()-32..]),
        "packet_file":file,"packet_sha256":digest(&bytes),
        "proof_sha256":digest(&packet.proof),"proof_bytes":packet.proof.len()
    })
}

fn native_verify(packet: &Packet) -> Result<pon_work::VerifiedWork, pon_work::WorkError> {
    pon_work::verify(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
}

fn export_context(
    node: &mut Node,
    parent: Hash,
    parent_work: consensus::Work,
    depth: u64,
    directory: &Path,
    contexts: &mut Vec<Value>,
) -> String {
    let context_id = if depth == 1 {
        "private-h16".to_owned()
    } else {
        format!("private-h17-{}", hex::encode(parent))
    };
    let (a, b) = maintenance();
    let preparation = Instant::now();
    let candidate = node
        .prepare_from_matrices(
            parent,
            vec![],
            development_public(1).unwrap(),
            GENESIS_TIME + 15 + depth,
            &a,
            &b,
        )
        .unwrap();
    let prepare_elapsed_ns = preparation.elapsed().as_nanos();
    assert_eq!(candidate.header.nonce, 0);
    assert_eq!(candidate.header.height, 15 + depth);
    assert_eq!(
        candidate.header.target,
        node.expected_target(parent).unwrap()
    );
    let template = json!({
        "schema":"trnm-w1-constructive-phase-oracle-v1",
        "shape":{"n":64,"r":8,"field_bits":32,"noise_counters":128},
        "header_hex":hex::encode(candidate.header.encode()),"a":a,"b":b,
        "nonce_bits":NONCE_BITS
    });
    let mut winners = Vec::new();
    let mut outcomes = Vec::new();
    let mut descendants = Vec::new();
    for nonce in 0..1 << NONCE_BITS {
        let started = Instant::now();
        let mut header = candidate.header.clone();
        header.nonce = nonce;
        let proof = candidate.prepared.prove(header.challenge()).unwrap();
        let proof_elapsed_ns = started.elapsed().as_nanos();
        let packet = Packet {
            header,
            transactions: candidate.transactions.clone(),
            proof,
        };
        let verify_started = Instant::now();
        let verdict = native_verify(&packet);
        let verify_elapsed_ns = verify_started.elapsed().as_nanos();
        let winner = verdict.is_ok();
        if let Err(error) = &verdict {
            assert_eq!(*error, pon_work::WorkError::Target);
        }
        let next_work = parent_work
            .checked_add(consensus::required_work(packet.header.target).unwrap())
            .unwrap();
        let mut row = packet_record(&packet, next_work, directory);
        row["complete_native_proof_generated"] = json!(true);
        row["native_winner"] = json!(winner);
        row["native_verifier_error"] = json!(verdict.err().map(|error| format!("{error:?}")));
        row["proof_elapsed_ns"] = json!(proof_elapsed_ns);
        row["verification_elapsed_ns"] = json!(verify_elapsed_ns);
        if winner {
            let admission = Instant::now();
            let id = node.admit(&packet, CLOCK_ORIGIN).unwrap();
            assert_eq!(id, packet.id().unwrap());
            assert_eq!(
                node.packet(id).unwrap().encode().unwrap(),
                packet.encode().unwrap()
            );
            row["native_admission_elapsed_ns"] = json!(admission.elapsed().as_nanos());
            row["native_fixture_admitted"] = json!(true);
            let child = (depth == 1).then(|| format!("private-h17-{}", hex::encode(id)));
            let mut winner_row = row.clone();
            winner_row["child_context_id"] = json!(child);
            winners.push(winner_row);
            if depth == 1 {
                descendants.push((id, next_work));
            }
        } else {
            row["native_fixture_admitted"] = json!(false);
            assert!(node.packet(packet.id().unwrap()).is_err());
        }
        outcomes.push(row);
    }
    contexts.push(json!({
        "context_id":context_id,"parent_id":hex::encode(parent),"height":15+depth,
        "declared_depth":depth,"template_spec":template,"native_parent_admitted":true,
        "observed_now":CLOCK_ORIGIN,"prepare_elapsed_ns":prepare_elapsed_ns,
        "winner_children":winners,"all_nonce_outcomes":outcomes,
        "census_scope":"offline complete native proof generation and native DAG admission; not online miner work"
    }));
    for (id, next_work) in descendants {
        export_context(node, id, next_work, depth + 1, directory, contexts);
    }
    context_id
}

fn winning_packet(mut header: Header) -> Packet {
    let (a, b) = maintenance();
    let prepared = pon_work::PreparedTask::new(&a, &b).unwrap();
    for nonce in 0..4096 {
        header.nonce = nonce;
        let packet = Packet {
            proof: prepared.prove(header.challenge()).unwrap(),
            header: header.clone(),
            transactions: vec![],
        };
        if native_verify(&packet).is_ok() {
            return packet;
        }
    }
    panic!("bounded native control proof search exhausted");
}

fn negative_controls(node: &mut Node, parent: Hash, directory: &Path) -> Value {
    let (a, b) = maintenance();
    let prepared = node
        .prepare_from_matrices(
            parent,
            vec![],
            development_public(2).unwrap(),
            GENESIS_TIME + 16,
            &a,
            &b,
        )
        .unwrap();
    let mut target = prepared.header.clone();
    target.target = [255; 32];
    target.target[0] = 127;
    let wrong_target = winning_packet(target);
    let mut future = prepared.header.clone();
    future.timestamp = CLOCK_ORIGIN + 121;
    let future = winning_packet(future);
    let mut unknown = prepared.header;
    unknown.parent = [202; 32];
    let unknown = winning_packet(unknown);
    let before = node.read_active().unwrap();
    let mut rows = Vec::new();
    for (name, packet, expected) in [
        ("mathematically-valid-wrong-target", wrong_target, "TARGET"),
        (
            "mathematically-valid-future-time",
            future.clone(),
            "TIME_DEFERRED",
        ),
        (
            "mathematically-valid-unknown-parent",
            unknown,
            "UNKNOWN_PARENT",
        ),
    ] {
        native_verify(&packet).unwrap();
        let error = node.admit(&packet, CLOCK_ORIGIN).unwrap_err().to_string();
        assert_eq!(error, expected);
        assert!(node.packet(packet.id().unwrap()).is_err());
        assert_eq!(node.read_active().unwrap(), before);
        let mut row = packet_record(&packet, consensus::Work::default(), directory);
        row["name"] = json!(name);
        row["complete_native_work_verification"] = json!(true);
        row["native_admission_error"] = json!(error);
        row["observed_now"] = json!(CLOCK_ORIGIN);
        row["credited_chainwork"] = json!(false);
        rows.push(row);
    }
    let id = node.admit(&future, CLOCK_ORIGIN + 1).unwrap();
    assert_eq!(id, future.id().unwrap());
    assert_eq!(node.read_active().unwrap(), before);
    json!({
        "rows":rows,"identical_future_packet_later_admitted":true,
        "later_observed_now":CLOCK_ORIGIN+1,"activation_requested":false,
        "control_proof_search_budget":4096,"controls_are_mining_strategy":false
    })
}

#[test]
#[ignore = "explicit full native W1 DAG research; requires a fresh evidence directory"]
fn export_source_bound_native_dag_fixture() {
    let directory = PathBuf::from(
        std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR")
            .expect("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR"),
    );
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("packets")).unwrap();
    let source_before = native_sources();
    json_new(&directory.join("native-source-before.json"), &source_before);
    let temporary = tempfile::tempdir().unwrap();
    let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
    let mut node = Node::open_with_authenticated_state(
        &temporary.path().join("fixture-node"),
        settings.clone(),
        1,
    )
    .unwrap();
    let initial_work = work(&node);
    assert_eq!(initial_work, consensus::Work::default());
    let mut prefix = Vec::new();
    let mut parent = settings.genesis();
    let mut cumulative = initial_work;
    let started = Instant::now();
    for height in 1..=15 {
        let step_started = Instant::now();
        let packet = node
            .make(
                parent,
                vec![],
                development_public(0).unwrap(),
                GENESIS_TIME + height,
                4096,
            )
            .unwrap();
        let make_elapsed_ns = step_started.elapsed().as_nanos();
        let admission = Instant::now();
        native_verify(&packet).unwrap();
        parent = node.admit(&packet, GENESIS_TIME + height * 10).unwrap();
        assert_eq!(
            node.activate_observed(parent, GENESIS_TIME + height * 10)
                .unwrap(),
            parent
        );
        cumulative = cumulative
            .checked_add(consensus::required_work(packet.header.target).unwrap())
            .unwrap();
        assert_eq!(work(&node), cumulative);
        let mut row = packet_record(&packet, cumulative, &directory);
        row["observed_now"] = json!(GENESIS_TIME + height * 10);
        row["complete_classical_proof_attempts"] = json!(packet.header.nonce + 1);
        row["make_elapsed_ns"] = json!(make_elapsed_ns);
        row["verify_admit_activate_elapsed_ns"] = json!(admission.elapsed().as_nanos());
        prefix.push(row);
    }
    let prefix_elapsed_ns = started.elapsed().as_nanos();
    let prefix_tip = parent;
    let mut history = prefix.iter().rev().cloned().collect::<Vec<_>>();
    let mut pow_limit = [255; 32];
    pow_limit[0] = 127;
    history.push(json!({
        "block_id":hex::encode(settings.genesis()),"parent_id":null,"height":0,
        "timestamp":GENESIS_TIME,"target_hex":hex::encode(pow_limit),
        "chainwork_hex":hex::encode(initial_work.bytes()),"header_hex":null,"packet_file":null
    }));
    let public_started = Instant::now();
    let public = node
        .make(
            parent,
            vec![],
            development_public(0).unwrap(),
            CLOCK_ORIGIN,
            4096,
        )
        .unwrap();
    native_verify(&public).unwrap();
    let public_id = node.admit(&public, CLOCK_ORIGIN).unwrap();
    assert_eq!(
        node.activate_observed(public_id, CLOCK_ORIGIN).unwrap(),
        public_id
    );
    let public_work = cumulative
        .checked_add(consensus::required_work(public.header.target).unwrap())
        .unwrap();
    assert_eq!(work(&node), public_work);
    let mut public_tip = packet_record(&public, public_work, &directory);
    public_tip["publication_at_seconds"] = json!("0");
    public_tip["generation_verify_admit_activate_elapsed_ns"] =
        json!(public_started.elapsed().as_nanos());
    public_tip["complete_classical_proof_attempts"] = json!(public.header.nonce + 1);
    let census_started = Instant::now();
    let mut contexts = Vec::new();
    let root_context_id = export_context(
        &mut node,
        prefix_tip,
        cumulative,
        1,
        &directory,
        &mut contexts,
    );
    let census_elapsed_ns = census_started.elapsed().as_nanos();
    assert!(contexts.len() <= 9);
    assert_eq!(node.read_active().unwrap().0, public_id);
    let controls = negative_controls(&mut node, prefix_tip, &directory);
    let source_after = native_sources();
    assert_eq!(
        source_before, source_after,
        "native source changed while generating fixture"
    );
    let report = json!({
        "schema":"trnm-w1-native-finite-dag-v1","native_source":source_after,
        "network":hex::encode(settings.network()),"parameters":hex::encode(settings.parameters()),
        "genesis":hex::encode(settings.genesis()),"genesis_timestamp":GENESIS_TIME,
        "clock_origin_timestamp":CLOCK_ORIGIN,"interval":16,"spacing_seconds":10,
        "future_skew_seconds":120,"pow_limit_hex":hex::encode(pow_limit),
        "initial_resources":{
            "prefix_public_tip_and_complete_dag":"offline native generation with receipts below",
            "prefix_generation_elapsed_ns":prefix_elapsed_ns,
            "public_tip_generation_elapsed_ns":public_tip["generation_verify_admit_activate_elapsed_ns"],
            "offline_census_elapsed_ns":census_elapsed_ns,
            "cost_scope":"conditional preexisting classical history and public input bytes; offline generation is not included in the four-second modeled quantum horizon",
            "coherent_quantum_state_supplied":false,
            "winner_advice_available_to_fixed_policy_sampler":false,
            "observer_has_full_census":true,
            "all_classical_costs_and_hardware_clocks_are_separate_premises":true
        },
        "root_context_id":root_context_id,"max_private_extensions":2,"nonce_bits":NONCE_BITS,
        "prefix":{"tip_id":hex::encode(prefix_tip),"height":15,"timestamp":GENESIS_TIME+15,
            "target_hex":prefix.last().unwrap()["target_hex"],"chainwork_hex":hex::encode(cumulative.bytes()),
            "parent_first_headers":history,"packets_parent_first":false,"packets":prefix,
            "upfront_generation_receipt":{"elapsed_ns":prefix_elapsed_ns,"workers":1,"max_attempts_per_block":4096,
                "cost_treatment":"explicit conditional preexisting prefix; not credited as free online attacker work"}},
        "public_tip":public_tip,"contexts":contexts,"native_negative_controls":controls,
        "offline_census_elapsed_ns":census_elapsed_ns,
        "fixed_plan":{"nonce_bits":NONCE_BITS,"private_miner":1,"root_timestamp":GENESIS_TIME+16,
            "child_timestamp":GENESIS_TIME+17,"sample_seed":9,"horizon_seconds":"4","max_attempts":2},
        "claims":{"full_native_W1_proofs_generated":true,"offline_native_dag_admitted":true,
            "online_search_sample_executed":false,"native_public_ingress_executed":false,
            "prefix_and_census_are_conditional_advice":true,"logical_validation_clock":true,
            "wall_clock_consensus_cadence_measured":false,"quantum_hardware_executed":false,
            "original_service_profile_requalified":false,"mining_profitability_proved":false,
            "quantum_mining_qualified":false,"production_activation":false}
    });
    json_new(&directory.join("native-fixture.json"), &report);
    eprintln!(
        "native_w1_bridge_fixture {}",
        json!({"contexts":report["contexts"].as_array().unwrap().len(),"fixture_sha256":digest(&fs::read(directory.join("native-fixture.json")).unwrap()),"native_winners":report["contexts"].as_array().unwrap().iter().map(|c|c["winner_children"].as_array().unwrap().len()).sum::<usize>(),"quantum_hardware_executed":false})
    );
}

fn read_packet(directory: &Path, row: &Value) -> Packet {
    let name = row["packet_file"].as_str().unwrap();
    assert!(name.starts_with("packets/") && !name.contains("..") && !name.contains('\\'));
    let bytes = fs::read(directory.join(name)).unwrap();
    assert_eq!(digest(&bytes), row["packet_sha256"].as_str().unwrap());
    let packet = Packet::decode(&bytes).unwrap();
    assert_eq!(packet.encode().unwrap(), bytes);
    assert_eq!(
        hex::encode(packet.id().unwrap()),
        row["block_id"].as_str().unwrap()
    );
    assert_eq!(digest(&packet.proof), row["proof_sha256"].as_str().unwrap());
    packet
}

fn initialize_history(node: &mut Node, directory: &Path, fixture: &Value) -> u128 {
    let initialized = Instant::now();
    for row in fixture["prefix"]["packets"].as_array().unwrap() {
        let packet = read_packet(directory, row);
        let now = row["observed_now"].as_u64().unwrap();
        let id = node.admit(&packet, now).unwrap();
        assert_eq!(node.activate_observed(id, now).unwrap(), id);
    }
    let public = read_packet(directory, &fixture["public_tip"]);
    let public_id = node.admit(&public, CLOCK_ORIGIN).unwrap();
    assert_eq!(
        node.activate_observed(public_id, CLOCK_ORIGIN).unwrap(),
        public_id
    );
    initialized.elapsed().as_nanos()
}

fn logical_now(time: &Value) -> u64 {
    let numerator = u128::from(time["numerator"].as_u64().unwrap());
    let denominator = u128::from(time["denominator"].as_u64().unwrap());
    assert!(denominator > 0 && numerator <= 4 * denominator);
    CLOCK_ORIGIN + u64::try_from(numerator / denominator).unwrap()
}

fn probe_complete_candidate_checks(
    producer: &mut Node,
    directory: &Path,
    fixture: &Value,
    sample: &Value,
) -> (Vec<Value>, BTreeMap<Hash, Packet>) {
    let mut rows = Vec::new();
    let mut ready_packets = BTreeMap::new();
    for (index, step) in sample["raw_observation"]["trajectory"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let observed = &step["edge"]["observation"];
        if observed["candidate_check_complete"] != true {
            continue;
        }
        // A classical draw is available without being a quantum measurement.
        // Only a completed modeled candidate check triggers this native probe.
        let nonce = observed["nonce"].as_u64().unwrap();
        let context_id = observed["context_id"].as_str().unwrap();
        let context = fixture["contexts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|context| context["context_id"] == context_id)
            .unwrap();
        assert_eq!(context["parent_id"], observed["parent_id"]);
        let row = context["all_nonce_outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["nonce"] == nonce)
            .unwrap();
        let retained = read_packet(directory, row);
        let (a, b) = maintenance();
        let preparation = Instant::now();
        let candidate = producer
            .prepare_from_matrices(
                retained.header.parent,
                retained.transactions.clone(),
                retained.header.miner,
                retained.header.timestamp,
                &a,
                &b,
            )
            .unwrap();
        let actual_prepare_elapsed_ns = preparation.elapsed().as_nanos();
        let mut header = candidate.header;
        header.nonce = nonce;
        assert_eq!(header, retained.header);
        let proof_started = Instant::now();
        let packet = Packet {
            proof: candidate.prepared.prove(header.challenge()).unwrap(),
            header,
            transactions: candidate.transactions,
        };
        let actual_proof_elapsed_ns = proof_started.elapsed().as_nanos();
        assert_eq!(packet.encode().unwrap(), retained.encode().unwrap());
        let checked = Instant::now();
        let verdict = native_verify(&packet);
        let actual_candidate_verification_elapsed_ns = checked.elapsed().as_nanos();
        let winner = verdict.is_ok();
        let error = verdict.err().map(|error| format!("{error:?}"));
        assert_eq!(winner, observed["winner"].as_bool().unwrap());
        if !winner {
            assert_eq!(error.as_deref(), Some("Target"));
        }
        let id = packet.id().unwrap();
        let proof_complete = observed["proof_complete"].as_bool().unwrap();
        let now = logical_now(&observed["time"]);
        let mut actual_private_admission_elapsed_ns = None;
        if proof_complete {
            assert!(winner);
            assert_eq!(observed["block_id"], hex::encode(id));
            let admitted = Instant::now();
            assert_eq!(producer.admit(&packet, now).unwrap(), id);
            actual_private_admission_elapsed_ns = Some(admitted.elapsed().as_nanos());
        } else {
            assert!(producer.packet(id).is_err());
        }
        rows.push(json!({
            "trajectory_index":index,"context_id":context_id,"nonce":nonce,
            "parent_id":hex::encode(packet.header.parent),"candidate_block_id":hex::encode(id),
            "nonce_source":observed.get("nonce_source"),
            "modeled_measurement_complete":observed["measurement_complete"],
            "modeled_candidate_check_complete":true,"modeled_proof_complete":proof_complete,
            "logical_observed_now":now,"native_winner":winner,"native_verifier_error":error,
            "proof_sha256":digest(&packet.proof),"packet_sha256":digest(&packet.encode().unwrap()),
            "actual_prepare_elapsed_ns":actual_prepare_elapsed_ns,
            "actual_proof_elapsed_ns":actual_proof_elapsed_ns,
            "actual_candidate_verification_elapsed_ns":actual_candidate_verification_elapsed_ns,
            "actual_private_admission_elapsed_ns":actual_private_admission_elapsed_ns,
            "native_private_producer_admitted":proof_complete,
            "native_receiver_admission_authorized_by_this_probe":false,
            "actual_cpu_proof_used_as_quantum_clock_calibration":false,
            "scope":"fresh offline native probe of every completed modeled candidate check, including misses"
        }));
        if proof_complete {
            assert!(ready_packets.insert(id, packet).is_none());
        }
    }
    (rows, ready_packets)
}

#[test]
#[ignore = "explicit fresh Node replay of independently verified finite-search records"]
fn replay_source_bound_native_search_samples() {
    let directory = PathBuf::from(
        std::env::var_os("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR")
            .expect("TRNM_W1_NATIVE_BRIDGE_EVIDENCE_DIR"),
    );
    let source_before = native_sources();
    let inputs: BTreeMap<&str, Vec<u8>> = BRIDGE_INPUT_NAMES
        .iter()
        .map(|name| (*name, read_bridge_input(&directory.join(name))))
        .collect();
    let fixture_bytes = &inputs["native-fixture.json"];
    let samples_bytes = &inputs["bridge-samples.json"];
    let fixture: Value = serde_json::from_slice(fixture_bytes).unwrap();
    let samples: Value = serde_json::from_slice(samples_bytes).unwrap();
    assert_eq!(fixture["native_source"], source_before);
    assert_eq!(samples["schema"], "trnm-w1-native-bridge-samples-v1");
    assert_eq!(samples["fixture_sha256"], digest(fixture_bytes));
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    let python = std::env::var_os("TRNM_RESEARCH_PYTHON").unwrap_or_else(|| "python3".into());
    let output = Command::new(python)
        .arg(root().join("formal/pon-nakamoto-v1/experiments/w1_native_bridge.py"))
        .arg("--verify")
        .arg(&directory)
        .output()
        .unwrap();
    write_new(
        &directory.join("native-pre-replay-python.stdout"),
        &output.stdout,
    );
    write_new(
        &directory.join("native-pre-replay-python.stderr"),
        &output.stderr,
    );
    assert!(
        output.status.success(),
        "independent bridge replay refused: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verifier_receipt: Value = serde_json::from_slice(&output.stdout)
        .expect("verifier must emit one complete JSON receipt");
    assert_bridge_verifier_receipt(&verifier_receipt, &inputs, &samples, &source_before);
    assert_eq!(source_before, native_sources());
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    for (name, bytes) in &inputs {
        assert_eq!(*bytes, read_bridge_input(&directory.join(name)));
    }
    let mut results = Vec::new();
    for sample in samples["runs"].as_array().unwrap() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("receiver");
        let settings = Settings::development(Some(GENESIS_TIME)).unwrap();
        let mut node = Node::open_with_authenticated_state(&path, settings.clone(), 1).unwrap();
        let preexisting_replay_elapsed_ns = initialize_history(&mut node, &directory, &fixture);
        let before = node.read_active().unwrap();
        let before_stats = node.stats().unwrap();
        let mut producer = Node::open_with_authenticated_state(
            &temporary.path().join("private-producer"),
            settings.clone(),
            1,
        )
        .unwrap();
        let private_preexisting_replay_elapsed_ns =
            initialize_history(&mut producer, &directory, &fixture);
        let (candidate_probes, mut fresh_packets) =
            probe_complete_candidate_checks(&mut producer, &directory, &fixture, sample);
        let expected_checks = sample["raw_observation"]["trajectory"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|step| step["edge"]["observation"]["candidate_check_complete"] == true)
            .count();
        assert_eq!(candidate_probes.len(), expected_checks);
        let private_proofs_held = fresh_packets.len();
        let now = sample["native_observed_now"].as_u64().unwrap();
        assert!((CLOCK_ORIGIN..=CLOCK_ORIGIN + 4).contains(&now));
        let mut receipts = Vec::new();
        for selected in sample["packets_to_submit"].as_array().unwrap() {
            let context_id = selected["context_id"].as_str().unwrap();
            let context = fixture["contexts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["context_id"] == context_id)
                .unwrap();
            let row = context["winner_children"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["nonce"] == selected["nonce"] && r["block_id"] == selected["block_id"])
                .unwrap();
            let retained = read_packet(&directory, row);
            assert_eq!(context["parent_id"], hex::encode(retained.header.parent));
            assert_eq!(sample["publication_complete"], true);
            let packet = fresh_packets.remove(&retained.id().unwrap()).unwrap();
            assert_eq!(packet.encode().unwrap(), retained.encode().unwrap());
            let verification = Instant::now();
            native_verify(&packet).unwrap();
            let actual_verification_elapsed_ns = verification.elapsed().as_nanos();
            let admission = Instant::now();
            let id = node.admit(&packet, now).unwrap();
            let actual_admission_elapsed_ns = admission.elapsed().as_nanos();
            let activation = Instant::now();
            let selected_tip = node.activate_observed(id, now).unwrap();
            receipts.push(json!({
                "context_id":context_id,"nonce":packet.header.nonce,"block_id":hex::encode(id),
                "parent_id":hex::encode(packet.header.parent),"selected_tip":hex::encode(selected_tip),
                "observed_now":now,"proof_sha256":digest(&packet.proof),
                "packet_sha256":digest(&packet.encode().unwrap()),
                "actual_verification_elapsed_ns":actual_verification_elapsed_ns,
                "actual_admission_elapsed_ns":actual_admission_elapsed_ns,
                "actual_activation_elapsed_ns":activation.elapsed().as_nanos(),
                "stats":node.stats().unwrap(),"native_library_admitted":true,
                "public_ingress_executed":false,"quantum_hardware_executed":false
            }));
        }
        let after = node.read_active().unwrap();
        let after_stats = node.stats().unwrap();
        let changed = after.0 != before.0;
        assert_eq!(
            changed,
            sample["expected_reorganization"].as_bool().unwrap()
        );
        if receipts.is_empty() {
            assert_eq!(before, after);
            assert_eq!(before_stats, after_stats);
        }
        drop(node);
        let reopened = Node::open_with_authenticated_state(&path, settings, 1).unwrap();
        assert_eq!(reopened.read_active().unwrap(), after);
        assert_eq!(reopened.stats().unwrap(), after_stats);
        for receipt in &receipts {
            let id: Hash = hex::decode(receipt["block_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                digest(&reopened.packet(id).unwrap().encode().unwrap()),
                receipt["packet_sha256"]
            );
        }
        results.push(json!({
            "name":sample["name"],"observation_kind":sample["observation_kind"],
            "sample_sha256":digest(&serde_json::to_vec(sample).unwrap()),
            "preexisting_history_replay_elapsed_ns":preexisting_replay_elapsed_ns,
            "private_producer_history_replay_elapsed_ns":private_preexisting_replay_elapsed_ns,
            "candidate_probes":candidate_probes,"completed_candidate_checks_replayed":expected_checks,
            "private_proofs_held":private_proofs_held,
            "before":before_stats,"admissions":receipts,"after":after_stats,
            "authenticated_reopen_equal":true,"reorganized":changed,
            "logical_validation_clock":true,"real_quantum_machine":false
        }));
    }
    assert_eq!(source_before, native_sources());
    assert_python_source_snapshot(&samples["source"], &source_before["git_head"]);
    for (name, bytes) in &inputs {
        assert_eq!(*bytes, read_bridge_input(&directory.join(name)));
    }
    let report = json!({
        "schema":"trnm-w1-native-bridge-replay-v1","native_source":source_before,
        "fixture_sha256":digest(fixture_bytes),"samples_sha256":digest(samples_bytes),
        "independent_python_replay_exit_success":true,
        "independent_python_verifier":{"stdout_sha256":digest(&output.stdout),
            "stderr_sha256":digest(&output.stderr),"receipt":verifier_receipt},
        "verified_raw_inputs_unchanged_through_native_replay":true,"runs":results,
        "claims":{"native_library_node_executed":true,"fresh_authenticated_receiver_per_run":true,
            "fresh_private_producer_per_run":true,"all_completed_candidate_checks_natively_replayed":true,
            "native_public_ingress_executed":false,"real_time_search_budget_verified":false,
            "conditional_model_clock_only":true,"prefix_and_census_costs_are_conditional_advice":true,
            "quantum_hardware_executed":false,"quantum_mining_qualified":false,
            "original_service_profile_requalified":false,"production_activation":false}
    });
    json_new(&directory.join("native-replay.json"), &report);
    eprintln!(
        "native_w1_bridge_replay {}",
        json!({"runs":report["runs"].as_array().unwrap().len(),"native_library_node_executed":true,"quantum_hardware_executed":false})
    );
}
