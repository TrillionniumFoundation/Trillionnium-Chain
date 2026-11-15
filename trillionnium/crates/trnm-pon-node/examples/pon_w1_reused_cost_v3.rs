//! Explicit actual-reuse observation; the default V2 campaign is unchanged.
//! One real preparation stays alive for four independent complete searches.
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{raw, sha, Clock, Producer, Result, Search, Timing, ARMS};

const SCHEMA: &str = "pon-w1-reused-producers-cost-v3";
const SELECTOR: &str = "--actual-reuse-v3";
const SAMPLES: u64 = 8;
const SEARCHES: usize = 4;
const LIMIT: u64 = 4096;
const SEED: u64 = 0;

fn target() -> Hash {
    let mut result = [255; 32];
    result[0] = 127;
    result
}
fn challenge(task: Hash, sample: u64, search: usize, nonce: u64) -> Hash {
    pon_work::hash(
        b"pon-w1-reused-challenge-v3",
        &[
            &task,
            &SEED.to_le_bytes(),
            &sample.to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}
fn emit(mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("REUSED_RECORD_OBJECT")?
        .insert("schema".into(), SCHEMA.into());
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &row)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn verdict(result: std::result::Result<VerifiedWork, WorkError>, proof: &[u8]) -> String {
    match result {
        Ok(work) if raw(work.product()) == proof[4 + 8 * CELLS..PROOF_BYTES - 32] => {
            "Accepted".into()
        }
        Ok(_) => "AcceptedWrongProduct".into(),
        Err(error) => format!("{error:?}"),
    }
}

#[derive(Default)]
struct Counts {
    cohorts: usize,
    searches: usize,
    candidates: usize,
    verifiers: usize,
}
struct MeasuredSearch {
    result: Search,
    timing: Timing,
}

fn cohort(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    order: usize,
    canonical: &mut [Option<Search>; SEARCHES],
    counts: &mut Counts,
) -> Result<()> {
    let index = (sample as usize + order) % ARMS.len();
    let total = Clock::start();
    let setup = Clock::start();
    // The only constructor invocation for this entire cohort. Unsupported is
    // retained as an actual outcome, never replaced with a generic producer.
    let prepared =
        Producer::new(index, &material.a, &material.b).map_err(|e| format!("PREPARATION:{e:?}"))?;
    let setup = setup.finish();
    let mut searches = Vec::with_capacity(SEARCHES);
    if let Some(producer) = &prepared {
        for search in 0..SEARCHES {
            let started = Clock::start();
            let result = w1_cost_producers::search(producer, target(), LIMIT, |nonce| {
                challenge(task, sample, search, nonce)
            })?;
            searches.push(MeasuredSearch {
                timing: started.finish(),
                result,
            });
        }
    }
    let total = total.finish();
    // Timing ends before JSON, stream comparison or either verifier. All trial
    // SHA/hex/retention and failed target attempts remain inside each search.
    emit(
        json!({"kind":"cohort","class":material.name,"sample":sample,
        "arm":ARMS[index],"invocation_order":order,"task":hex::encode(task),
        "target":hex::encode(target()),"status":if prepared.is_some(){"supported"}else{"unsupported"},
        "setup_calls":1,"searches":searches.len(),"setup":setup,"total":total}),
    )?;
    counts.cohorts += 1;
    for (search, measured) in searches.into_iter().enumerate() {
        let searched = measured.result;
        emit(
            json!({"kind":"search","class":material.name,"sample":sample,
            "arm":ARMS[index],"search_index":search,"task":hex::encode(task),
            "target":hex::encode(target()),"setup_calls":0,"timing":measured.timing,
            "status":if searched.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "attempts":searched.attempts,"winner":searched.winner.as_ref().map(|w|
                json!({"challenge":hex::encode(w.challenge),"proof_sha256":sha(&w.proof)}))}),
        )?;
        counts.searches += 1;
        if let Some(original) = &canonical[search] {
            if original.attempts != searched.attempts || original.winner != searched.winner {
                return Err("REUSED_SUPPORTED_STREAM_DISAGREEMENT".into());
            }
        }
        if let Some(winner) = &searched.winner {
            for verification_order in 0..2 {
                let reference = (sample as usize + order + search + verification_order) % 2 == 1;
                let started = Clock::start();
                let native = if reference {
                    black_box(pon_work::verify_reference(
                        winner.challenge,
                        task,
                        target(),
                        &winner.proof,
                    ))
                } else {
                    black_box(pon_work::verify(
                        winner.challenge,
                        task,
                        target(),
                        &winner.proof,
                    ))
                };
                let timing = started.finish();
                let outcome = verdict(native, &winner.proof);
                emit(
                    json!({"kind":"verifier","class":material.name,"sample":sample,
                    "arm":ARMS[index],"search_index":search,"task":hex::encode(task),
                    "target":hex::encode(target()),"path":if reference{"reference"}else{"production"},
                    "invocation_order":verification_order,"challenge":hex::encode(winner.challenge),
                    "proof_sha256":sha(&winner.proof),"outcome":outcome,"timing":timing}),
                )?;
                counts.verifiers += 1;
                if outcome != "Accepted" {
                    return Err("REUSED_NATIVE_VERIFIER_DISAGREEMENT".into());
                }
            }
        }
        if canonical[search].is_none() {
            canonical[search] = Some(searched);
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    if arguments != [SELECTOR] {
        return Err("V3_EXPLICIT_FIXED_SELECTOR_REQUIRED".into());
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
        json!({"kind":"campaign","selector":SELECTOR,"samples":SAMPLES,
        "searches_per_setup":SEARCHES,"attempt_budget":LIMIT,"seed":SEED,
        "target":hex::encode(target()),"arms":ARMS,"classes":materials.iter().map(|m|m.name).collect::<Vec<_>>(),
        "clock":"thread-cpu-and-monotonic-wall-ns","material_setup":material_setup,
        "setup_reuse":"one-actual-preparation-four-independent-searches",
        "producer_timing_scope":"actual-setup-and-complete-search-retention-excludes-json-comparison-verification",
        "verifier_timing_scope":"native-full-verification-call-only-no-fact-cache",
        "hardness_accepted":false,"work_profile_qualified":false,"resource_fairness_qualified":false,
        "independent_hardware_qualified":false,"public_network_ready":false,
        "public_service_measured":false,"production_activation":false}),
    )?;
    let mut counts = Counts::default();
    for material in &materials {
        let task =
            pon_work::task_id(&material.a, &material.b).map_err(|e| format!("MATERIAL:{e:?}"))?;
        emit(
            json!({"kind":"material","class":material.name,"source":material.source,
            "task":hex::encode(task),"a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            let mut canonical: [Option<Search>; SEARCHES] = std::array::from_fn(|_| None);
            for order in 0..ARMS.len() {
                cohort(material, task, sample, order, &mut canonical, &mut counts)?;
            }
            for (search, searched) in canonical.into_iter().enumerate() {
                let searched = searched.ok_or("REUSED_CANONICAL_SEARCH_MISSING")?;
                if let Some(winner) = searched.winner {
                    emit(
                        json!({"kind":"candidate","class":material.name,"sample":sample,
                        "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
                        "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                        "proof_sha256":sha(&winner.proof)}),
                    )?;
                    counts.candidates += 1;
                }
            }
        }
    }
    emit(
        json!({"kind":"end","material_count":materials.len(),"cohort_count":counts.cohorts,
        "search_count":counts.searches,"candidate_count":counts.candidates,
        "verifier_count":counts.verifiers,"complete":true}),
    )
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_search_domain_binds_each_fixed_coordinate() {
        let task = [7; 32];
        let first = challenge(task, 0, 0, 0);
        assert_ne!(first, challenge([8; 32], 0, 0, 0));
        assert_ne!(first, challenge(task, 1, 0, 0));
        assert_ne!(first, challenge(task, 0, 1, 0));
        assert_ne!(first, challenge(task, 0, 0, 1));
    }

    #[test]
    fn one_actual_preparation_keeps_full_exhaustion_and_four_full_searches() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let prepared = Producer::new(7, &zero, &zero).unwrap().unwrap();
        let exhausted =
            w1_cost_producers::search(&prepared, [0; 32], 4, |nonce| challenge(task, 0, 0, nonce))
                .unwrap();
        assert_eq!(exhausted.attempts.len(), 4);
        assert!(exhausted.winner.is_none());
        assert!(exhausted.attempts.iter().all(|trial| !trial.target_hit));
        for search in 0..SEARCHES {
            let actual = w1_cost_producers::search(&prepared, target(), LIMIT, |nonce| {
                challenge(task, 0, search, nonce)
            })
            .unwrap();
            let winner = actual.winner.unwrap();
            pon_work::verify(winner.challenge, task, target(), &winner.proof).unwrap();
            pon_work::verify_reference(winner.challenge, task, target(), &winner.proof).unwrap();
        }
    }
}
