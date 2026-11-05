//! Explicit cost-observation V2. Existing W1 and all V1 reports are unchanged.
//! Clocks and every attempted proof are observations, never work-cost lower bounds.
#[path = "support/w1_from_zero.rs"]
mod w1_from_zero;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;

use serde_json::{json, Value};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{
    self,
    facts::{FactCounters, FactError, WorkFactCache, MAX_FACT_SLOTS},
    Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES, Q,
};
use w1_cost_producers::{raw, sha, Clock, Producer, Result, Search, Timing, Trial, Winner, ARMS};

const SCHEMA: &str = "pon-w1-all-producers-cost-v2";
const SAMPLES: u64 = 8;
const LIMIT: u64 = 4096;
const SEED: u64 = 0;

fn emit(mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("COST_RECORD_OBJECT")?
        .insert("schema".into(), SCHEMA.into());
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &row)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn target() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}
fn challenge(task: Hash, sample: u64, nonce: u64) -> Hash {
    pon_work::hash(
        b"pon-w1-cost-matrix-challenge-v2",
        &[
            &task,
            &SEED.to_le_bytes(),
            &sample.to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

fn legal_search(producer: &Producer, task: Hash, sample: u64, limit: u64) -> Result<Search> {
    w1_cost_producers::search(producer, target(), limit, |nonce| {
        challenge(task, sample, nonce)
    })
}
fn producer_row(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    order: usize,
    canonical: &mut Option<Search>,
) -> Result<()> {
    let index = (sample as usize + order) % ARMS.len();
    let total = Clock::start();
    let setup = Clock::start();
    let prepared =
        Producer::new(index, &material.a, &material.b).map_err(|e| format!("PREPARATION:{e:?}"))?;
    let setup = setup.finish();
    let (searched, search) = if let Some(producer) = prepared {
        let started = Clock::start();
        let searched = legal_search(&producer, task, sample, LIMIT)?;
        let measured = started.finish();
        (Some(searched), Some(measured))
    } else {
        (None, None)
    };
    let total = total.finish();
    let status = match &searched {
        None => "unsupported",
        Some(s) if s.winner.is_none() => "exhausted",
        Some(_) => "target-hit-unverified",
    };
    let row = json!({"kind":"producer","class":material.name,"sample":sample,"arm":ARMS[index],
        "invocation_order":order,"task":hex::encode(task),"target":hex::encode(target()),
        "status":status,"setup_calls":1,"setup":setup,"search":search,"total":total,
        "attempts":searched.as_ref().map(|s|s.attempts.as_slice()).unwrap_or(&[]),
        "winner":searched.as_ref().and_then(|s|s.winner.as_ref()).map(|w|
            json!({"challenge":hex::encode(w.challenge),"proof_sha256":sha(&w.proof)}))});
    // Preserve the actual arm before failing a byte-equivalence assertion.
    emit(row)?;
    if let Some(searched) = searched {
        if let Some(original) = canonical {
            if original.attempts != searched.attempts || original.winner != searched.winner {
                return Err("SUPPORTED_PRODUCER_STREAM_DISAGREEMENT".into());
            }
        } else {
            *canonical = Some(searched);
        }
    }
    Ok(())
}

struct Forgery {
    proof: Option<Vec<u8>>,
    attempts: Vec<Trial>,
    setup: Timing,
    search: Timing,
    total: Timing,
}
fn false_trace(material: &w1_material::Material, context: Hash, limit: u64) -> Result<Forgery> {
    let total = Clock::start();
    let setup = Clock::start();
    let mut prefix = w1_from_zero::proof_prefix(&material.a, &material.b)
        .map_err(|e| format!("FALSE_PREFIX:{e:?}"))?;
    let setup = setup.finish();
    let search = Clock::start();
    let mut attempts = Vec::new();
    let mut proof = None;
    for nonce in 0..limit {
        let (trace, ticket) = w1_from_zero::trial(context, nonce);
        let hit = ticket <= target();
        attempts.push(Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: None,
            target_hit: hit,
        });
        if hit {
            prefix[PROOF_BYTES - 32..].copy_from_slice(&trace);
            proof = Some(prefix);
            break;
        }
    }
    Ok(Forgery {
        proof,
        attempts,
        setup,
        search: search.finish(),
        total: total.finish(),
    })
}
fn wrong_product(original: &[u8]) -> Forgery {
    let total = Clock::start();
    let setup = Clock::start().finish();
    let search = Clock::start();
    let mut proof = original.to_vec();
    let offset = PROOF_BYTES - 36;
    let old = u32::from_le_bytes(proof[offset..offset + 4].try_into().unwrap());
    let changed = ((u128::from(old) + 1) % Q) as u32;
    proof[offset..offset + 4].copy_from_slice(&changed.to_le_bytes());
    Forgery {
        proof: Some(proof),
        attempts: Vec::new(),
        setup,
        search: search.finish(),
        total: total.finish(),
    }
}
fn forged_row(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    winner: &Winner,
    variant: &str,
    forged: &Forgery,
) -> Result<()> {
    let acquired = variant == "product-last";
    emit(
        json!({"kind":"forgery","class":material.name,"sample":sample,"variant":variant,
        "challenge":hex::encode(winner.challenge),"task":hex::encode(task),"target":hex::encode(target()),
        "status":if forged.proof.is_some(){"target-hit-unverified"}else{"exhausted"},
        "setup":forged.setup,"search":forged.search,"total":forged.total,"attempts":forged.attempts,
        "winner":forged.proof.as_ref().map(|p|json!({"trace":hex::encode(&p[PROOF_BYTES-32..]),"proof_sha256":sha(p)})),
        "valid_proof_acquisition_used":acquired,"construction_scope":if acquired{
            "existing-valid-proof-clone-and-canonical-last-cell-increment"
        }else{"full-public-prefix-and-all-hash-trials"}}),
    )
}
fn accepted(work: VerifiedWork, proof: &[u8]) -> String {
    if raw(work.product()) == proof[4 + 8 * CELLS..PROOF_BYTES - 32] {
        "Accepted".into()
    } else {
        "AcceptedWrongProduct".into()
    }
}
fn regular_outcome(result: std::result::Result<VerifiedWork, WorkError>, proof: &[u8]) -> String {
    match result {
        Ok(work) => accepted(work, proof),
        Err(error) => format!("{error:?}"),
    }
}
fn fact_outcome(
    result: std::result::Result<VerifiedWork, FactError<std::convert::Infallible>>,
    proof: &[u8],
) -> String {
    match result {
        Ok(work) => accepted(work, proof),
        Err(FactError::Relation(error)) => format!("{error:?}"),
        Err(FactError::Cancelled(never)) => match never {},
        Err(FactError::Unavailable) => "Unavailable".into(),
    }
}
fn counters(value: FactCounters) -> Value {
    json!({"full_replays":value.full_replays,"hits":value.hits,
        "wait_polls":value.wait_polls,"evictions":value.evictions})
}
fn verifiers(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    winner: &Winner,
    case: &str,
    proof: &[u8],
) -> Result<()> {
    for path in ["production", "facts-cold", "facts-warm"] {
        let mut row = json!({"kind":"verifier","class":material.name,"sample":sample,"case":case,
            "path":path,"challenge":hex::encode(winner.challenge),"task":hex::encode(task),
            "target":hex::encode(target()),"proof_sha256":sha(proof),
            "cache_capacity":null,"cache_before":null,"cache_after":null,
            "cache_setup":null,"warmup":null});
        let (timing, outcome) = if path == "production" {
            let started = Clock::start();
            let native = black_box(pon_work::verify(winner.challenge, task, target(), proof));
            (started.finish(), regular_outcome(native, proof))
        } else {
            let setup = Clock::start();
            let cache = WorkFactCache::new(MAX_FACT_SLOTS).map_err(|e| e.to_string())?;
            row["cache_setup"] = serde_json::to_value(setup.finish())?;
            row["cache_capacity"] = MAX_FACT_SLOTS.into();
            if path == "facts-warm" {
                let started = Clock::start();
                let native =
                    black_box(cache.verify(winner.challenge, task, target(), &winner.proof));
                let timing = started.finish();
                let outcome = fact_outcome(native, &winner.proof);
                row["warmup"] = json!({"timing":timing,"outcome":outcome,
                    "proof_sha256":sha(&winner.proof)});
            }
            row["cache_before"] = counters(cache.counters());
            let started = Clock::start();
            let native = black_box(cache.verify(winner.challenge, task, target(), proof));
            let timing = started.finish();
            row["cache_after"] = counters(cache.counters());
            (timing, fact_outcome(native, proof))
        };
        row["timing"] = serde_json::to_value(timing)?;
        row["outcome"] = outcome.into();
        emit(row)?;
    }
    Ok(())
}
fn run() -> Result<()> {
    if std::env::args_os().len() != 1 {
        return Err("V2_FIXED_CAMPAIGN_NO_ARGUMENTS".into());
    }
    let material_started = Clock::start();
    let mut materials = w1_material::materials(None, None)?;
    let nonzero: Vec<u32> = (0..CELLS)
        .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
        .collect();
    materials.push(w1_material::Material {
        name: "one-zero-left-rank-one",
        source: "synthetic-fixture",
        a: vec![0; CELLS],
        b: nonzero.clone(),
    });
    materials.push(w1_material::Material {
        name: "one-zero-right-rank-one",
        source: "synthetic-fixture",
        a: nonzero,
        b: vec![0; CELLS],
    });
    let material_setup = material_started.finish();
    emit(
        json!({"kind":"campaign","samples":SAMPLES,"attempt_budget":LIMIT,"seed":SEED,
        "target":hex::encode(target()),"arms":ARMS,"classes":materials.iter().map(|m|m.name).collect::<Vec<_>>(),
        "clock":"thread-cpu-and-monotonic-wall-ns","material_setup":material_setup,
        "setup_amortization":"modeled-setup-divisor-not-observed-multiwinner",
        "public_listener_uses_work_facts":false,"hardness_accepted":false,"production_activation":false}),
    )?;
    let (mut producer_count, mut candidate_count, mut forgery_count, mut verifier_count) =
        (0, 0, 0, 0);
    for material in &materials {
        let task =
            pon_work::task_id(&material.a, &material.b).map_err(|e| format!("MATERIAL:{e:?}"))?;
        emit(
            json!({"kind":"material","class":material.name,"source":material.source,"task":hex::encode(task),
            "a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            let mut canonical = None;
            for order in 0..ARMS.len() {
                producer_row(material, task, sample, order, &mut canonical)?;
                producer_count += 1;
            }
            if let Some(winner) = canonical.and_then(|searched| searched.winner) {
                emit(
                    json!({"kind":"candidate","class":material.name,"sample":sample,
                    "task":hex::encode(task),"target":hex::encode(target()),
                    "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                    "proof_sha256":sha(&winner.proof)}),
                )?;
                candidate_count += 1;
                verifiers(material, task, sample, &winner, "legal", &winner.proof)?;
                verifier_count += 3;
                for (variant, forged) in [
                    (
                        "from-zero-transcript",
                        false_trace(material, winner.challenge, LIMIT)?,
                    ),
                    ("product-last", wrong_product(&winner.proof)),
                ] {
                    forged_row(material, task, sample, &winner, variant, &forged)?;
                    forgery_count += 1;
                    if let Some(proof) = &forged.proof {
                        verifiers(material, task, sample, &winner, variant, proof)?;
                        verifier_count += 3;
                    }
                }
            }
        }
    }
    emit(
        json!({"kind":"end","material_count":materials.len(),"producer_count":producer_count,
        "candidate_count":candidate_count,"forgery_count":forgery_count,
        "verifier_count":verifier_count,"complete":true}),
    )
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_existing_arm_is_exercised_without_unsupported_fallback() {
        let zero = vec![0; CELLS];
        let supported: Vec<_> = (0..ARMS.len())
            .filter(|i| Producer::new(*i, &zero, &zero).unwrap().is_some())
            .collect();
        assert_eq!(supported, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        let (a, b) = trnm_mvcc_fee::continuity_v1::maintenance_matrices();
        let supported: Vec<_> = (0..ARMS.len())
            .filter(|i| Producer::new(*i, &a, &b).unwrap().is_some())
            .collect();
        assert_eq!(supported, vec![0, 1, 3, 4, 5, 9, 10, 11, 12]);
    }
    #[test]
    fn exact_complete_proofs_and_fact_cold_warm_outcomes_match() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let first = legal_search(
            &Producer::new(1, &zero, &zero).unwrap().unwrap(),
            task,
            0,
            LIMIT,
        )
        .unwrap();
        let winner = first.winner.as_ref().unwrap();
        for index in [0, 2, 3, 4, 5, 6, 7] {
            let checked = legal_search(
                &Producer::new(index, &zero, &zero).unwrap().unwrap(),
                task,
                0,
                LIMIT,
            )
            .unwrap();
            assert_eq!(checked.attempts, first.attempts);
            assert!(checked.winner == first.winner);
        }
        let cache = WorkFactCache::new(MAX_FACT_SLOTS).unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &winner.proof),
                &winner.proof
            ),
            "Accepted"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (1, 0)
        );
        let changed = wrong_product(&winner.proof).proof.unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &changed),
                &changed
            ),
            "Product"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (1, 1)
        );
        let material = w1_material::Material {
            name: "zero",
            source: "synthetic-fixture",
            a: zero.clone(),
            b: zero,
        };
        let changed = false_trace(&material, winner.challenge, LIMIT)
            .unwrap()
            .proof
            .unwrap();
        assert_eq!(
            fact_outcome(
                cache.verify(winner.challenge, task, target(), &changed),
                &changed
            ),
            "Transcript"
        );
        assert_eq!(
            (cache.counters().full_replays, cache.counters().hits),
            (2, 1)
        );
    }

    #[test]
    fn all_thirteen_preparations_reused_across_challenges_preserve_full_w1() {
        // This closes a reuse-correctness gap in the thirteen-arm diagnostic.
        // It is not an observed [1,8,64]-winner cost cohort or a hardness bound.
        // The fixed V2 campaign, original target, attempt limit and reader are
        // unchanged; no cost acceptance is inferred from this native test.
        let mut materials = w1_material::materials(None, None).unwrap();
        let rank_one: Vec<_> = (0..CELLS)
            .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
            .collect();
        materials.extend([
            w1_material::Material {
                name: "one-zero-left-rank-one",
                source: "synthetic-fixture",
                a: vec![0; CELLS],
                b: rank_one.clone(),
            },
            w1_material::Material {
                name: "one-zero-right-rank-one",
                source: "synthetic-fixture",
                a: rank_one,
                b: vec![0; CELLS],
            },
        ]);
        for material in materials {
            let task = pon_work::task_id(&material.a, &material.b).unwrap();
            let original = Producer::new(0, &material.a, &material.b).unwrap().unwrap();
            let reference: Vec<_> = (0..3)
                .map(|sample| legal_search(&original, task, sample, LIMIT).unwrap())
                .collect();
            for searched in &reference {
                let winner = searched
                    .winner
                    .as_ref()
                    .expect("bounded fixed-fixture winner");
                pon_work::verify_reference(winner.challenge, task, target(), &winner.proof)
                    .unwrap();
            }
            assert_ne!(
                reference[0].winner.as_ref().unwrap().challenge,
                reference[1].winner.as_ref().unwrap().challenge
            );
            for (index, arm) in ARMS.iter().enumerate() {
                let expected_supported = match index {
                    0 | 1 | 3 | 4 | 5 => true,
                    2 => matches!(
                        material.name,
                        "zero"
                            | "identity"
                            | "rank-one"
                            | "sparse-diagonal"
                            | "one-zero-left-rank-one"
                            | "one-zero-right-rank-one"
                    ),
                    6 | 7 => material.name == "zero",
                    8 => material.name.starts_with("one-zero-"),
                    _ => material.name == "continuity-maintenance-v1",
                };
                // A single actual constructor stays alive across independent
                // searches. No reconstruction or generic fallback masks reuse.
                let prepared = Producer::new(index, &material.a, &material.b).unwrap();
                assert_eq!(
                    prepared.is_some(),
                    expected_supported,
                    "{}/{arm} support",
                    material.name
                );
                let Some(prepared) = prepared else {
                    continue;
                };
                for (sample, baseline) in reference.iter().enumerate() {
                    let observed = legal_search(&prepared, task, sample as u64, LIMIT).unwrap();
                    assert_eq!(
                        observed.attempts, baseline.attempts,
                        "{}/{arm}/{sample}: every target miss and complete proof commitment",
                        material.name
                    );
                    let winner = observed.winner.as_ref().unwrap();
                    let expected = baseline.winner.as_ref().unwrap();
                    assert_eq!(winner.challenge, expected.challenge);
                    assert_eq!(winner.proof, expected.proof);
                    pon_work::verify(winner.challenge, task, target(), &winner.proof).unwrap();
                }
            }
            let winner = reference[0].winner.as_ref().unwrap();
            let changed = wrong_product(&winner.proof).proof.unwrap();
            pon_work::precheck_proof_statement(winner.challenge, task, target(), &changed).unwrap();
            assert_eq!(
                pon_work::verify(winner.challenge, task, target(), &changed).unwrap_err(),
                WorkError::Product
            );
            // Find a distinct context that passes the original cheap ticket
            // gate using the retained trace. A task-level preparation never
            // turns that earlier challenge's proof into a new Work capability.
            let other = (0..LIMIT)
                .map(|nonce| challenge(task, 1000, nonce))
                .find(|context| {
                    *context != winner.challenge
                        && pon_work::precheck_proof_statement(
                            *context,
                            task,
                            target(),
                            &winner.proof,
                        )
                        .is_ok()
                })
                .expect("bounded distinct-context ticket");
            assert_eq!(
                pon_work::verify(other, task, target(), &winner.proof).unwrap_err(),
                WorkError::Transcript
            );
        }
    }
}
