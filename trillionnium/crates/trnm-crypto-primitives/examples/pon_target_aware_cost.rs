//! Separate fixed target-aware producer observation. No V1/V2 runner change.
//! Wall stage times on this host are observations, not physical cost bounds.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write, time::Instant};
use trnm_crypto_primitives::pon_work::{
    self, Hash, PreparedGenerationProgress as Point, PreparedTask, CELLS, PROOF_BYTES, Q,
};

const SCHEMA: &str = "pon-target-aware-attempt-observation-v1";
const SAMPLES: u64 = 8;
const ATTEMPT_LIMIT: u64 = 4096;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn emit(mut value: Value) -> Result<()> {
    value
        .as_object_mut()
        .ok_or("RECORD")?
        .insert("schema".into(), SCHEMA.into());
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &value)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[derive(PartialEq, Eq)]
struct Identity {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    hit: bool,
}
struct Search {
    trials: Vec<Identity>,
    winner: Option<(Hash, Vec<u8>)>,
}

fn search(
    class: &str,
    a: &[u32],
    b: &[u32],
    sample: u64,
    target: Hash,
    lazy: bool,
) -> Result<Search> {
    let arm = if lazy {
        "target-aware"
    } else {
        "original-complete-proof"
    };
    let task = pon_work::task_id(a, b).map_err(|error| format!("TASK:{error:?}"))?;
    let setup = Instant::now();
    let producer = PreparedTask::new(a, b).map_err(|error| format!("SETUP:{error:?}"))?;
    let setup_ns = setup.elapsed().as_nanos();
    emit(
        json!({"kind":"setup","class":class,"sample":sample,"target":hex::encode(target),
        "task":hex::encode(task),"arm":arm,"setup_ns":setup_ns}),
    )?;
    let mut observed = Search {
        trials: Vec::new(),
        winner: None,
    };
    for nonce in 0..ATTEMPT_LIMIT {
        let context = pon_work::hash(
            b"pon-target-aware-attempt-challenge-v1",
            &[&task, &target, &sample.to_le_bytes(), &nonce.to_le_bytes()],
        );
        let started = Instant::now();
        let mut before_proof_ns = None;
        let mut callbacks = 0usize;
        let mut progress = |point| {
            callbacks += 1;
            if point == Point::BeforeProof {
                before_proof_ns = Some(started.elapsed().as_nanos());
            }
            Ok::<_, ()>(())
        };
        let (trace, ticket, proof, serialized_bytes) = if lazy {
            let attempt =
                black_box(producer.search_attempt_with_progress(context, target, &mut progress))
                    .map_err(|error| format!("ATTEMPT:{error:?}"))?;
            let trace = attempt.trace();
            let ticket = attempt.ticket();
            let bytes = attempt.proof().map_or(0, <[u8]>::len);
            (trace, ticket, attempt.into_proof(), bytes)
        } else {
            let proof = black_box(producer.prove_with_progress(context, &mut progress))
                .map_err(|error| format!("PROOF:{error:?}"))?;
            let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
            let ticket = pon_work::hash(b"ticket", &[&context, &trace]);
            // Include destruction of the original losing proof inside its
            // attempt interval; evidence records are emitted after both paths.
            let proof = if ticket <= target {
                Some(proof)
            } else {
                drop(proof);
                None
            };
            (trace, ticket, proof, PROOF_BYTES)
        };
        let attempt_ns = started.elapsed().as_nanos();
        let replay_ns = before_proof_ns.ok_or("MISSING_COMPLETE_REPLAY")?;
        let hit = ticket <= target;
        if hit != proof.is_some() {
            return Err("THRESHOLD_DISAGREEMENT".into());
        }
        emit(
            json!({"kind":"attempt","class":class,"sample":sample,"target":hex::encode(target),
            "arm":arm,"nonce":nonce,"challenge":hex::encode(context),"trace":hex::encode(trace),
            "ticket":hex::encode(ticket),"target_hit":hit,"callbacks":callbacks,
            "complete_replay_ns":replay_ns,"finalize_ticket_proof_ns":attempt_ns-replay_ns,
            "complete_attempt_ns":attempt_ns,"serialized_proof_bytes":serialized_bytes}),
        )?;
        observed.trials.push(Identity {
            nonce,
            challenge: context,
            trace,
            ticket,
            hit,
        });
        if let Some(proof) = proof {
            let verified_at = Instant::now();
            let native = black_box(pon_work::verify(context, task, target, &proof));
            let production_verify_ns = verified_at.elapsed().as_nanos();
            let native = native.map_err(|error| format!("NATIVE:{error:?}"))?;
            let verified_at = Instant::now();
            let reference = black_box(pon_work::verify_reference(context, task, target, &proof));
            let scalar_verify_ns = verified_at.elapsed().as_nanos();
            let reference = reference.map_err(|error| format!("SCALAR:{error:?}"))?;
            if native.product() != reference.product() || native.ticket() != ticket {
                return Err("NATIVE_STATEMENT_DISAGREEMENT".into());
            }
            emit(
                json!({"kind":"winner","class":class,"sample":sample,"target":hex::encode(target),
                "arm":arm,"attempts":nonce+1,"proof_sha256":hex::encode(Sha256::digest(&proof)),
                "proof_hex":hex::encode(&proof),"production_verify_ns":production_verify_ns,
                "scalar_verify_ns":scalar_verify_ns}),
            )?;
            observed.winner = Some((context, proof));
            break;
        }
    }
    emit(
        json!({"kind":"search-end","class":class,"sample":sample,"target":hex::encode(target),
        "arm":arm,"attempts":observed.trials.len(),"exhausted":observed.winner.is_none()}),
    )?;
    Ok(observed)
}

fn main() -> Result<()> {
    if std::env::args().skip(1).collect::<Vec<_>>() != ["--target-aware-v1"] {
        return Err("EXPLICIT_FIXED_SELECTOR_REQUIRED".into());
    }
    let material_started = Instant::now();
    let dense: Vec<u32> = (0..CELLS)
        .map(|i| (i * 97 + i / 64 * 31 + 11) as u32)
        .collect();
    let extreme: Vec<u32> = (0..CELLS)
        .map(|i| if i % 3 == 0 { (Q - 1) as u32 } else { i as u32 })
        .collect();
    let rank_one: Vec<u32> = (0..CELLS)
        .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
        .collect();
    let materials = [
        ("zero", vec![0; CELLS], vec![0; CELLS]),
        ("dense-extreme", dense.clone(), extreme.clone()),
        ("extreme-dense", extreme, dense),
        ("one-zero-rank-one", rank_one, vec![0; CELLS]),
    ];
    let material_setup_ns = material_started.elapsed().as_nanos();
    emit(
        json!({"kind":"campaign","samples":SAMPLES,"attempt_limit":ATTEMPT_LIMIT,
        "classes":materials.iter().map(|(class,_,_)|*class).collect::<Vec<_>>(),
        "targets_first_byte":[127,7],"material_setup_ns":material_setup_ns,
        "clock":"monotonic-wall-ns","timed_cpu":false,
        "scope":"setup and full native attempts with identical checkpoints; JSON/hex/retention and verification outside attempt intervals",
        "production_speedup_accepted":false,"hardness_accepted":false,
        "hardware_qualified":false,"public_service_accepted":false,"production_activation":false}),
    )?;
    let mut pairs = 0;
    for (class, a, b) in materials {
        for target_first in [127, 7] {
            let mut target = [255; 32];
            target[0] = target_first;
            for sample in 0..SAMPLES {
                let first_lazy = sample % 2 == 1;
                let first = search(class, &a, &b, sample, target, first_lazy)?;
                let second = search(class, &a, &b, sample, target, !first_lazy)?;
                if first.trials != second.trials || first.winner != second.winner {
                    return Err("PAIRED_COMPLETE_STREAM_DISAGREEMENT".into());
                }
                pairs += 1;
            }
        }
    }
    emit(json!({"kind":"end","pairs":pairs,"complete":true}))
}
