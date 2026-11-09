use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::{Value, json};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{Node, Packet, Settings, development_public};
use trnm_protocol::pon_wire::{Header, hash};
use w1_full_public_stark_research::arith_air::Q;
use w1_full_public_stark_research::proof_wire::{Component, limits};
use w1_full_public_stark_research::public::{PUBLIC_BYTES, PublicStatement};
use w1_full_public_stark_research::sha_plan::{
    HEADER_BYTES, INPUT_BYTES, MATRIX_BYTES, PREFIX_BYTES,
};
use w1_node_adapter_research::{
    MAX_PACKET_BYTES, OperatorPlan, PROFILE, PreparedBundle, Result, Stage, admit,
    check_current_packet, digest, err, observe_verified, read_bounded, verify_reserved_bundle,
    write_new,
};

use w1_node_adapter_research::proof_start_owner::{
    ProofStartOwner, ProofStartPolicy, ProofStartPurpose,
};

pub const GENESIS_TIME: u64 = 1_800_000_000;
pub const OBSERVED_NOW: u64 = GENESIS_TIME + 100;
const METRICS_SCHEMA: &str = "trnm-w1-receiver-metrics-v1";

/// Diagnostic timing only. A started event without a finish remains unfinished;
/// it is never a zero-cost observation or an admission receipt.
fn measured<T>(
    phases: &mut Vec<Value>,
    stage: &str,
    action: impl FnOnce() -> Result<T>,
) -> Result<T> {
    println!(
        "{}",
        json!({"event":"receiver_phase_started","schema":METRICS_SCHEMA,"stage":stage})
    );
    let start = Instant::now();
    let result = action();
    let phase = json!({"stage":stage,"wall_seconds":start.elapsed().as_secs_f64(),
        "outcome":if result.is_ok() { "ok" } else { "error" }});
    println!(
        "{}",
        json!({"event":"receiver_phase_finished","schema":METRICS_SCHEMA,"measurement":&phase})
    );
    phases.push(phase);
    result
}

fn receiver_metrics(mode: &str, payload_bytes: usize, phases: Vec<Value>) -> Value {
    json!({"schema":METRICS_SCHEMA,"mode":mode,"phases_are_disjoint":true,
        "payload_bytes":payload_bytes,"phases":phases,"proof_preprocessing_reused":false,
        "new_complete_proofs_generated":0,
        "scope":"disjoint CLI workload phases; proof/native subphases are nested and must not be added again; the external process clock also pays event reporting, final record serialization and teardown",
        "payload_scope":"native packet, plus public statement and both proofs only in proof-plus-native mode; independent operator plan is local input, not counted as transmitted payload",
        "network_transport_measured":false,"production_activation":false})
}

struct CommonInput {
    plan: OperatorPlan,
    packet_bytes: Vec<u8>,
    identity: Value,
}

fn load_common_input(fixture: &Path) -> Result<CommonInput> {
    let plan_bytes = read_bounded(&fixture.join("operator-plan.json"), 4096, None)?;
    let plan = serde_json::from_slice(&plan_bytes).map_err(err)?;
    let packet_bytes = read_bounded(&fixture.join("packet.bin"), MAX_PACKET_BYTES, None)?;
    let identity = json!({"operator_plan_sha256":digest(&plan_bytes),
        "packet_sha256":digest(&packet_bytes),"packet_bytes":packet_bytes.len()});
    Ok(CommonInput {
        plan,
        packet_bytes,
        identity,
    })
}

/// The native comparator binds the same independent inputs without reading a
/// public witness or certificate. Actual W1 checking still occurs in Node::admit.
fn decode_native_input(input: &CommonInput) -> Result<Packet> {
    let expected = input.plan.expected()?;
    let packet = Packet::decode(&input.packet_bytes).map_err(err)?;
    if packet.encode().map_err(err)? != input.packet_bytes {
        return Err("noncanonical packet".into());
    }
    if packet.header.encode() != expected.header {
        return Err("packet expected header".into());
    }
    if hex::encode(packet.header.network) != input.plan.network
        || hex::encode(packet.header.parameters) != input.plan.parameters
    {
        return Err("packet context".into());
    }
    if packet.proof.len() != INPUT_BYTES - HEADER_BYTES || &packet.proof[..4] != b"PNW1" {
        return Err("native comparator requires the fixed PNW1 relation".into());
    }
    let a = &packet.proof[4..4 + MATRIX_BYTES];
    let b = &packet.proof[4 + MATRIX_BYTES..4 + 2 * MATRIX_BYTES];
    let mut artifacts = hash(b"artifact", &[a]).to_vec();
    artifacts.extend(hash(b"qualified-task-input-v1", &[b]));
    if artifacts.as_slice() != expected.artifacts.as_slice() {
        return Err("native independent artifact binding".into());
    }
    Ok(packet)
}

fn settings() -> Result<Settings> {
    Settings::development(Some(GENESIS_TIME)).map_err(err)
}

fn save_json(path: &Path, value: &impl serde::Serialize) -> Result<()> {
    write_new(path, &serde_json::to_vec_pretty(value).map_err(err)?)
}

fn load_plan(path: &Path) -> Result<OperatorPlan> {
    serde_json::from_slice(&read_bounded(&path.join("operator-plan.json"), 4096, None)?)
        .map_err(err)
}

fn fixture(path: &Path) -> Result<Value> {
    fs::create_dir(path).map_err(err)?;
    let cfg = settings()?;
    let node = Node::open(&path.join("proposer-node"), cfg.clone(), 1).map_err(err)?;
    let packet = node
        .make(
            cfg.genesis(),
            vec![],
            development_public(3).map_err(err)?,
            GENESIS_TIME + 10,
            4096,
        )
        .map_err(err)?;
    let (a, b) = trnm_pon_node::maintenance();
    let a_bytes: Vec<_> = a.iter().flat_map(|x| x.to_le_bytes()).collect();
    let b_bytes: Vec<_> = b.iter().flat_map(|x| x.to_le_bytes()).collect();
    if packet.proof[4..4 + a_bytes.len()] != a_bytes
        || packet.proof[4 + a_bytes.len()..4 + a_bytes.len() + b_bytes.len()] != b_bytes
    {
        return Err("independent Node maintenance material mismatch".into());
    }
    let mut artifacts = hash(b"artifact", &[&a_bytes]).to_vec();
    artifacts.extend(hash(b"qualified-task-input-v1", &[&b_bytes]));
    let plan = OperatorPlan {
        profile: PROFILE.into(),
        network: hex::encode(cfg.network()),
        parameters: hex::encode(cfg.parameters()),
        genesis: hex::encode(cfg.genesis()),
        expected_header: hex::encode(packet.header.encode()),
        expected_artifacts: hex::encode(&artifacts),
    };
    let mut raw = packet.header.encode();
    raw.extend_from_slice(&packet.proof);
    let mut statement = PublicStatement::honest(raw.clone(), vec![0; PREFIX_BYTES])?;
    // Exact original bi,bj,bk,i,j prefix order, including every one of 32768 cells.
    let mut prefix = Vec::with_capacity(PREFIX_BYTES);
    for bi in 0..8 {
        for bj in 0..8 {
            let mut accumulator = [0_u32; 64];
            for bk in 0..8 {
                for i in 0..8 {
                    for j in 0..8 {
                        let value = (0..8).fold(u128::from(accumulator[i * 8 + j]), |s, k| {
                            s + u128::from(
                                statement.arithmetic.a_hat[(bi * 8 + i) * 64 + bk * 8 + k],
                            ) * u128::from(
                                statement.arithmetic.b_hat[(bk * 8 + k) * 64 + bj * 8 + j],
                            )
                        });
                        accumulator[i * 8 + j] = (value % u128::from(Q)) as u32;
                        prefix.extend(accumulator[i * 8 + j].to_le_bytes());
                    }
                }
            }
        }
    }
    statement.prefix = prefix.clone();
    let expected = plan.expected()?;
    let (sha, arith) = statement.plans(&expected)?;
    for message in sha.messages() {
        if digest(&message.bytes) != hex::encode(message.expected_digest) {
            return Err(format!(
                "generated prefix/hash plan disagrees with native packet: {}",
                message.name
            ));
        }
    }
    pon_work::verify(
        packet.header.challenge(),
        packet.header.work_task,
        packet.header.target,
        &packet.proof,
    )
    .map_err(|e| format!("{e:?}"))?;
    write_new(&path.join("packet.bin"), &packet.encode().map_err(err)?)?;
    write_new(&path.join("input.bin"), &raw)?;
    write_new(&path.join("prefix.bin"), &prefix)?;
    write_new(&path.join("expected_header.bin"), &expected.header)?;
    write_new(&path.join("expected_artifacts.bin"), &artifacts)?;
    write_new(&path.join("statement.bin"), &statement.encode()?)?;
    save_json(&path.join("operator-plan.json"), &plan)?;
    let result = json!({"schema":"trnm-w1-node-adapter-fixture-v1","native_node_packet_generated":true,
        "native_work_verified":true,"statement_proved":false,"node_admitted":false,
        "native_block":hex::encode(packet.id().map_err(err)?),"raw_sha256":digest(&raw),
        "public_bytes":PUBLIC_BYTES,"hash_messages":sha.messages().len(),"arithmetic_rows":arith.real_rows(),
        "independent_artifacts_source":"actual Node maintenance() material, compared to produced packet",
        "genesis_time":GENESIS_TIME,"observed_now":OBSERVED_NOW,"production_activation":false,"qualification":"HOLD_NO_GO"});
    save_json(&path.join("fixture.json"), &result)?;
    Ok(result)
}

fn load_bundle(fixture: &Path, proof: &Path) -> Result<(PreparedBundle, Value)> {
    let input = load_common_input(fixture)?;
    let bundle = PreparedBundle::new(
        input.plan,
        input.packet_bytes,
        read_bounded(
            &fixture.join("statement.bin"),
            PUBLIC_BYTES,
            Some(PUBLIC_BYTES),
        )?,
        read_bounded(
            &proof.join("sha.proof.bin"),
            limits(Component::ScheduledSha).maximum_bytes,
            None,
        )?,
        read_bounded(
            &proof.join("arith.proof.bin"),
            limits(Component::PackedCarry).maximum_bytes,
            None,
        )?,
    )?;
    Ok((bundle, input.identity))
}

fn checkpoint(name: &str, stage: Stage) -> Result<()> {
    println!(
        "{}",
        json!({"event":"checkpoint","stage":format!("{stage:?}")})
    );
    if name == format!("{stage:?}") {
        Err(format!("REQUEST_CANCELLED:{stage:?}"))
    } else {
        Ok(())
    }
}

fn load_owner_policy(path: &Path) -> Result<ProofStartPolicy> {
    let policy: ProofStartPolicy =
        serde_json::from_slice(&read_bounded(path, 4096, None)?).map_err(err)?;
    policy.validate()?;
    Ok(policy)
}

fn owner_init(policy_path: &Path, owner_path: &Path) -> Result<Value> {
    let owner = ProofStartOwner::create(owner_path, load_owner_policy(policy_path)?)?;
    Ok(
        json!({"owner":owner.snapshot()?,"qualification":"HOLD_NO_GO","production_activation":false}),
    )
}

fn owner_status(policy_path: &Path, owner_path: &Path) -> Result<Value> {
    let owner = ProofStartOwner::open(owner_path, load_owner_policy(policy_path)?)?;
    Ok(
        json!({"owner":owner.snapshot()?,"qualification":"HOLD_NO_GO","production_activation":false}),
    )
}

fn exercise(
    fixture: &Path,
    proof: &Path,
    output: &Path,
    cancellation: &str,
    owner_path: &Path,
    policy_path: &Path,
) -> Result<Value> {
    let mut phases = Vec::new();
    let (budget, reservation) =
        measured(&mut phases, "proof_start_owner_open_and_reserve", || {
            let budget = ProofStartOwner::open(owner_path, load_owner_policy(policy_path)?)?;
            let reservation = budget.reserve(ProofStartPurpose::Admission)?;
            Ok((budget, reservation))
        })?;
    let proof_start = reservation.record().clone();
    println!(
        "{}",
        json!({"event":"proof_start_reserved","proof_start":proof_start})
    );
    measured(&mut phases, "output_directory_create", || {
        fs::create_dir(output).map_err(err)
    })?;
    let (bundle, input_identity) = measured(&mut phases, "proof_input_read_binding", || {
        load_bundle(fixture, proof)
    })?;
    let payload_bytes = bundle.total_bytes();
    let operation = measured(&mut phases, "proof_bundle_persistence", || {
        bundle.persist(&output.join("bundles"))
    })?;
    let mut node_opened = false;
    let mut active_before = None;
    let mut generation_before = None;
    let mut native_observation = None;
    let mut native_observation_error = None;
    // Verify first: a rejected certificate never opens or recovers a Node store.
    let result = match measured(&mut phases, "complete_proof_verification", || {
        verify_reserved_bundle(&bundle, reservation, |s| checkpoint(cancellation, s))
    }) {
        Ok(verified) => {
            let mut node = measured(&mut phases, "node_open_recovery", || {
                Node::open(&output.join("receiver-node"), settings()?, 1).map_err(err)
            })?;
            node_opened = true;
            let before = measured(&mut phases, "node_before_observation", || {
                node.active().map_err(err)
            })?;
            active_before = Some(hex::encode(before.0));
            generation_before = Some(before.1);
            let result = measured(&mut phases, "node_admission_activation_readback", || {
                admit(&mut node, verified, OBSERVED_NOW, true, |s| {
                    checkpoint(cancellation, s)
                })
            });
            match measured(&mut phases, "post_admission_readback", || {
                node.exact_packet_observation(bundle.packet()).map_err(err)
            }) {
                Ok(value) => native_observation = Some(value),
                Err(error) => native_observation_error = Some(error),
            }
            result
        }
        Err(error) => Err(error),
    };
    let owner_snapshot = measured(&mut phases, "proof_start_owner_snapshot", || {
        budget.snapshot()
    });
    let record = json!({"schema":"trnm-w1-node-adapter-exercise-v2","operation_directory":operation,
        "input_identity":input_identity,"metrics":receiver_metrics("proof-plus-native",payload_bytes,phases),
        "requested_cancellation":cancellation,"outcome":result.as_ref().ok(),"error":result.as_ref().err(),
        "node_opened":node_opened,"active_before":active_before,"generation_before":generation_before,
        "native_observation":native_observation,"native_observation_error":native_observation_error,
        "proof_start":proof_start,"proof_start_owner_snapshot":owner_snapshot.as_ref().ok(),"proof_start_owner_snapshot_error":owner_snapshot.as_ref().err(),"qualification":"HOLD_NO_GO","production_activation":false});
    save_json(&output.join("exercise.json"), &record)?;
    Ok(record)
}

/// Cold native development-Node comparator. It reads no public witness or proof,
/// opens a fresh Node, and pays the original admission, activation and readback.
fn native_admit(fixture: &Path, output: &Path) -> Result<Value> {
    let mut phases = Vec::new();
    measured(&mut phases, "output_directory_create", || {
        fs::create_dir(output).map_err(err)
    })?;
    let (input, packet) = measured(&mut phases, "native_input_read_binding", || {
        let input = load_common_input(fixture)?;
        let packet = decode_native_input(&input)?;
        Ok((input, packet))
    })?;
    let mut node = measured(&mut phases, "node_open_recovery", || {
        Node::open(&output.join("receiver-node"), settings()?, 1).map_err(err)
    })?;
    let before = measured(
        &mut phases,
        "node_current_context_and_before_observation",
        || {
            check_current_packet(&node, &input.plan, &packet)?;
            node.active().map_err(err)
        },
    )?;
    let (id, native_admission_seconds) = measured(&mut phases, "native_admission", || {
        let start = Instant::now();
        let id = node
            .admit(&packet, OBSERVED_NOW)
            .map_err(|e| format!("NODE_ADMISSION:{e}"))?;
        Ok((id, start.elapsed().as_secs_f64()))
    })?;
    // A later activation/readback/reporting failure must not erase this commit.
    println!(
        "{}",
        json!({"event":"native_packet_committed","block":hex::encode(id),"native_admitted":true})
    );
    let activation = measured(&mut phases, "native_activation", || {
        node.activate(id).map(|_| ()).map_err(err)
    });
    let observation = measured(&mut phases, "native_readback", || {
        node.exact_packet_observation(&packet).map_err(err)
    });
    let record = json!({"schema":"trnm-w1-node-native-admit-v1","profile":PROFILE,
        "input_identity":input.identity,"block":hex::encode(id),"node_opened":true,
        "native_admitted":true,"native_admission_path_invoked":true,
        "both_real_proofs_verified":false,"native_admission_seconds":native_admission_seconds,
        "activation_requested":true,"activation_error":activation.as_ref().err(),
        "active_before":hex::encode(before.0),"generation_before":before.1,
        "native_observation":observation.as_ref().ok(),"native_observation_error":observation.as_ref().err(),
        "metrics":receiver_metrics("native",input.packet_bytes.len(),phases),
        "qualification":"HOLD_NO_GO","production_activation":false});
    save_json(&output.join("native-admit.json"), &record)?;
    Ok(record)
}

fn reopen(
    fixture: &Path,
    output: &Path,
    operation: &Path,
    owner_path: &Path,
    policy_path: &Path,
) -> Result<Value> {
    let budget = ProofStartOwner::open(owner_path, load_owner_policy(policy_path)?)?;
    let reservation = budget.reserve(ProofStartPurpose::ReopenObservation)?;
    println!(
        "{}",
        json!({"event":"proof_start_reserved","proof_start":reservation.record()})
    );
    let bundle = PreparedBundle::reload(operation, load_plan(fixture)?)?;
    let verified = verify_reserved_bundle(&bundle, reservation, |_| Ok(()))?;
    // Original Node::open performs real recovery; only open after proof success.
    let node = Node::open(&output.join("receiver-node"), settings()?, 1).map_err(err)?;
    observe_verified(&node, verified)
}

fn native(raw: &Path, header: &Path, repeats: usize) -> Result<Value> {
    if !(1..=1000).contains(&repeats) {
        return Err("native repeats".into());
    }
    let raw = read_bounded(raw, INPUT_BYTES, Some(INPUT_BYTES))?;
    let expected = read_bounded(header, HEADER_BYTES, Some(HEADER_BYTES))?;
    if raw[..HEADER_BYTES] != expected {
        return Err("native independent header".into());
    }
    let header = Header::decode(&expected).map_err(|e| format!("{e:?}"))?;
    let mut times = Vec::with_capacity(repeats);
    for _ in 0..repeats {
        let start = Instant::now();
        pon_work::verify(
            header.challenge(),
            header.work_task,
            header.target,
            &raw[HEADER_BYTES..],
        )
        .map_err(|e| format!("{e:?}"))?;
        times.push(start.elapsed().as_secs_f64());
    }
    Ok(
        json!({"schema":"trnm-w1-current-native-comparator-v1","calls":repeats,"seconds":times,
        "raw_sha256":digest(&raw),"default_kernel":"FullLimb","process_startup_included_in_call_samples":false,
        "header_challenge_computation_included":true,"node_admission_performed":false,
        "qualification":"HOLD_NO_GO","production_activation":false}),
    )
}

fn run() -> Result<Value> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    match a.first().map(String::as_str) {
        Some("fixture") if a.len() == 2 => fixture(Path::new(&a[1])),
        Some("owner-init") if a.len() == 3 => owner_init(Path::new(&a[1]), Path::new(&a[2])),
        Some("owner-status") if a.len() == 3 => owner_status(Path::new(&a[1]), Path::new(&a[2])),
        Some("exercise") if a.len() == 7 => exercise(Path::new(&a[1]), Path::new(&a[2]), Path::new(&a[3]), &a[4], Path::new(&a[5]), Path::new(&a[6])),
        Some("reopen") if a.len() == 6 => reopen(Path::new(&a[1]), Path::new(&a[2]), Path::new(&a[3]), Path::new(&a[4]), Path::new(&a[5])),
        Some("native") if a.len() == 4 => native(Path::new(&a[1]), Path::new(&a[2]), a[3].parse().map_err(err)?),
        Some("native-admit") if a.len() == 3 => native_admit(Path::new(&a[1]), Path::new(&a[2])),
        _ => Err("usage: fixture NEW_DIR | owner-init EXPECTED_POLICY NEW_OWNER_DIR | owner-status EXPECTED_POLICY OWNER_DIR | exercise FIXTURE PROOF NEW_OUTPUT CANCEL_STAGE_OR_none OWNER_DIR EXPECTED_POLICY | reopen FIXTURE OUTPUT OPERATION_DIR OWNER_DIR EXPECTED_POLICY | native RAW EXPECTED_HEADER REPEATS | native-admit FIXTURE NEW_OUTPUT".into()),
    }
}

fn main() {
    let start = Instant::now();
    match run() {
        Ok(value) => println!(
            "{}",
            json!({"result":value,"outer_seconds":start.elapsed().as_secs_f64()})
        ),
        Err(error) => {
            eprintln!(
                "{}",
                json!({"error":error,"outer_seconds":start.elapsed().as_secs_f64(),"qualification":"HOLD_NO_GO"})
            );
            std::process::exit(2);
        }
    }
}
