use std::fs;
use std::path::Path;
use std::time::Instant;

use serde_json::{Value, json};
use trnm_crypto_primitives::pon_work;
use trnm_pon_node::{Node, Settings, development_public};
use trnm_protocol::pon_wire::{Header, hash};
use w1_full_public_stark_research::arith_air::Q;
use w1_full_public_stark_research::proof_wire::{Component, limits};
use w1_full_public_stark_research::public::{PUBLIC_BYTES, PublicStatement};
use w1_full_public_stark_research::sha_plan::{HEADER_BYTES, INPUT_BYTES, PREFIX_BYTES};
use w1_node_adapter_research::{
    OperatorPlan, PROFILE, PreparedBundle, Result, Stage, WorkStartBudget, admit, digest, err,
    observe_verified, read_bounded, verify_bundle, write_new,
};

pub const GENESIS_TIME: u64 = 1_800_000_000;
pub const OBSERVED_NOW: u64 = GENESIS_TIME + 100;

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

fn load_bundle(fixture: &Path, proof: &Path) -> Result<PreparedBundle> {
    PreparedBundle::new(
        load_plan(fixture)?,
        read_bounded(&fixture.join("packet.bin"), 1_048_576, None)?,
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
    )
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

fn exercise(fixture: &Path, proof: &Path, output: &Path, cancellation: &str) -> Result<Value> {
    fs::create_dir(output).map_err(err)?;
    let mut budget = WorkStartBudget::new(1)?;
    budget.reserve()?;
    let bundle = load_bundle(fixture, proof)?;
    let operation = bundle.persist(&output.join("bundles"))?;
    let mut node_opened = false;
    let mut active_before = None;
    let mut generation_before = None;
    let mut native_observation = None;
    let mut native_observation_error = None;
    // Verify first: a rejected certificate never opens or recovers a Node store.
    let result = match verify_bundle(&bundle, |s| checkpoint(cancellation, s)) {
        Ok(verified) => {
            let mut node =
                Node::open(&output.join("receiver-node"), settings()?, 1).map_err(err)?;
            node_opened = true;
            let before = node.active().map_err(err)?;
            active_before = Some(hex::encode(before.0));
            generation_before = Some(before.1);
            let result = admit(&mut node, verified, OBSERVED_NOW, true, |s| {
                checkpoint(cancellation, s)
            });
            match node.exact_packet_observation(bundle.packet()) {
                Ok(value) => native_observation = Some(value),
                Err(error) => native_observation_error = Some(err(error)),
            }
            result
        }
        Err(error) => Err(error),
    };
    let record = json!({"schema":"trnm-w1-node-adapter-exercise-v1","operation_directory":operation,
        "requested_cancellation":cancellation,"outcome":result.as_ref().ok(),"error":result.as_ref().err(),
        "node_opened":node_opened,"active_before":active_before,"generation_before":generation_before,
        "native_observation":native_observation,"native_observation_error":native_observation_error,"work_starts_spent":budget.spent(),
        "next_work_start_refused":budget.reserve().is_err(),"qualification":"HOLD_NO_GO","production_activation":false});
    save_json(&output.join("exercise.json"), &record)?;
    Ok(record)
}

fn reopen(fixture: &Path, output: &Path, operation: &Path) -> Result<Value> {
    let bundle = PreparedBundle::reload(operation, load_plan(fixture)?)?;
    let verified = verify_bundle(&bundle, |_| Ok(()))?;
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
        Some("exercise") if a.len() == 5 => exercise(Path::new(&a[1]), Path::new(&a[2]), Path::new(&a[3]), &a[4]),
        Some("reopen") if a.len() == 4 => reopen(Path::new(&a[1]), Path::new(&a[2]), Path::new(&a[3])),
        Some("native") if a.len() == 4 => native(Path::new(&a[1]), Path::new(&a[2]), a[3].parse().map_err(err)?),
        _ => Err("usage: fixture NEW_DIR | exercise FIXTURE PROOF NEW_OUTPUT CANCEL_STAGE_OR_none | reopen FIXTURE OUTPUT OPERATION_DIR | native RAW EXPECTED_HEADER REPEATS".into()),
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
