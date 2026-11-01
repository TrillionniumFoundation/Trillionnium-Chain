//! Actual public-prefix reuse by an attacker that never acquires a valid proof.
//! The original V2/V3 campaigns, consensus and resource budgets are unchanged.
#[allow(dead_code)] // Share the exact clocks/records, not the legal producers.
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "support/w1_from_zero.rs"]
mod w1_from_zero;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{raw, sha, Clock, Result, Search, Timing, Trial, Winner};

const SCHEMA: &str = "pon-w1-false-trace-actual-reuse-v1";
const SELECTOR: &str = "--false-trace-actual-reuse-v1";
const SAMPLES: u64 = 8;
const SEARCHES: usize = 4;
const LIMIT: u64 = 4096;
const PATHS: [&str; 4] = [
    "production",
    "reference",
    "limb",
    "column-limb-experimental",
];
const FULL_LIMB_PATHS: [&str; 5] = [
    "production",
    "reference",
    "limb",
    "column-limb-experimental",
    "full-limb-experimental",
];
struct Campaign {
    schema: &'static str,
    selector: &'static str,
    paths: &'static [&'static str],
}
const ORIGINAL: Campaign = Campaign { schema: SCHEMA, selector: SELECTOR, paths: &PATHS };
const FULL_LIMB: Campaign = Campaign {
    schema: "pon-w1-false-trace-full-limb-v1",
    selector: "--false-trace-full-limb-v1",
    paths: &FULL_LIMB_PATHS,
};

fn target() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}
fn challenge(task: Hash, sample: u64, search: usize) -> Hash {
    pon_work::hash(
        b"pon-w1-false-trace-reuse-challenge-v1",
        &[
            &task,
            &0u64.to_le_bytes(),
            &sample.to_le_bytes(),
            &(search as u64).to_le_bytes(),
        ],
    )
}
fn emit(campaign: &Campaign, mut row: Value) -> Result<()> {
    row.as_object_mut()
        .ok_or("FALSE_REUSE_RECORD_OBJECT")?
        .insert("schema".into(), campaign.schema.into());
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &row)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
fn false_search(prefix: &[u8], context: Hash, target: Hash, limit: u64) -> Search {
    let mut result = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let (trace, ticket) = w1_from_zero::trial(context, nonce);
        let hit = ticket <= target;
        result.attempts.push(Trial {
            nonce,
            challenge: hex::encode(context),
            trace: hex::encode(trace),
            ticket: hex::encode(ticket),
            proof_sha256: None,
            target_hit: hit,
        });
        if hit {
            // A real clone is inside the search interval. The shared public
            // prefix is never reconstructed or mutated between searches.
            let mut proof = prefix.to_vec();
            proof[PROOF_BYTES - 32..].copy_from_slice(&trace);
            result.winner = Some(Winner {
                challenge: context,
                proof,
            });
            break;
        }
    }
    result
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
struct MeasuredSearch {
    result: Search,
    timing: Timing,
}
#[derive(Default)]
struct Counts {
    cohorts: usize,
    searches: usize,
    candidates: usize,
    verifiers: usize,
}

fn cohort(
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    counts: &mut Counts,
    campaign: &Campaign,
) -> Result<()> {
    let total = Clock::start();
    let setup = Clock::start();
    // Exactly one public-material validation/serialization. C and claimed trace
    // start at zero; no honest producer or valid-proof input is involved.
    let prefix = w1_from_zero::proof_prefix(&material.a, &material.b)
        .map_err(|error| format!("FALSE_REUSE_PREFIX:{error:?}"))?;
    let setup = setup.finish();
    let mut searches = Vec::with_capacity(SEARCHES);
    for search in 0..SEARCHES {
        let started = Clock::start();
        let context = challenge(task, sample, search);
        let result = false_search(&prefix, context, target(), LIMIT);
        searches.push(MeasuredSearch {
            timing: started.finish(),
            result,
        });
    }
    let total = total.finish();
    emit(campaign,
        json!({"kind":"cohort","class":material.name,"sample":sample,
        "task":hex::encode(task),"target":hex::encode(target()),"setup_calls":1,
        "searches":SEARCHES,"setup":setup,"total":total}),
    )?;
    counts.cohorts += 1;
    for (search, measured) in searches.into_iter().enumerate() {
        let searched = measured.result;
        emit(campaign,
            json!({"kind":"search","class":material.name,"sample":sample,
            "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
            "setup_calls":0,"timing":measured.timing,
            "status":if searched.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "attempts":searched.attempts,"winner":searched.winner.as_ref().map(|w|
                json!({"challenge":hex::encode(w.challenge),"proof_sha256":sha(&w.proof)}))}),
        )?;
        counts.searches += 1;
        if let Some(winner) = searched.winner {
            emit(campaign,
                json!({"kind":"candidate","class":material.name,"sample":sample,
                "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
                "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                "proof_sha256":sha(&winner.proof)}),
            )?;
            counts.candidates += 1;
            for order in 0..campaign.paths.len() {
                let index = (sample as usize + search + order) % campaign.paths.len();
                let started = Clock::start();
                let native = black_box(match index {
                    0 => pon_work::verify(winner.challenge, task, target(), &winner.proof),
                    1 => {
                        pon_work::verify_reference(winner.challenge, task, target(), &winner.proof)
                    }
                    2 => pon_work::verify_limb(winner.challenge, task, target(), &winner.proof),
                    3 => pon_work::verify_column_limb(
                        winner.challenge,
                        task,
                        target(),
                        &winner.proof,
                    ),
                    _ => pon_work::verify_full_limb(winner.challenge, task, target(), &winner.proof),
                });
                let timing = started.finish();
                let outcome = verdict(native, &winner.proof);
                // Preserve unexpected outcomes; the reader reports them.
                emit(campaign,
                    json!({"kind":"verifier","class":material.name,"sample":sample,
                    "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
                    "path":campaign.paths[index],"invocation_order":order,
                    "challenge":hex::encode(winner.challenge),"proof_sha256":sha(&winner.proof),
                    "outcome":outcome,"timing":timing}),
                )?;
                counts.verifiers += 1;
            }
        }
    }
    Ok(())
}
fn run() -> Result<()> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let campaign = match arguments.as_slice() {
        [selector] if selector == ORIGINAL.selector => &ORIGINAL,
        [selector] if selector == FULL_LIMB.selector => &FULL_LIMB,
        _ => return Err("FALSE_REUSE_EXPLICIT_FIXED_SELECTOR_REQUIRED".into()),
    };
    let started = Clock::start();
    let mut materials = w1_material::materials(None, None)?;
    let nonzero: Vec<u32> = (0..CELLS)
        .map(|i| ((i / 64 + 1) * (i % 64 + 2)) as u32)
        .collect();
    materials.extend([
        w1_material::Material {
            name: "one-zero-left-rank-one",
            source: "synthetic-fixture",
            a: vec![0; CELLS],
            b: nonzero.clone(),
        },
        w1_material::Material {
            name: "one-zero-right-rank-one",
            source: "synthetic-fixture",
            a: nonzero,
            b: vec![0; CELLS],
        },
    ]);
    let material_setup = started.finish();
    emit(campaign,
        json!({"kind":"campaign","selector":campaign.selector,"samples":SAMPLES,
        "searches_per_setup":SEARCHES,"attempt_budget":LIMIT,"seed":0,
        "target":hex::encode(target()),"paths":campaign.paths,"classes":materials.iter().map(|m|m.name).collect::<Vec<_>>(),
        "clock":"thread-cpu-and-monotonic-wall-ns","material_setup":material_setup,
        "setup_reuse":"one-public-prefix-four-independent-false-trace-searches",
        "attacker_timing_scope":"actual-prefix-setup-and-all-searches-including-challenge-hashes-trial-retention-and-winner-clone",
        "verifier_timing_scope":"native-full-verification-call-only-no-fact-cache",
        "valid_proof_acquisition_used":false,"hardness_accepted":false,
        "work_profile_qualified":false,"resource_fairness_qualified":false,
        "independent_hardware_qualified":false,"public_network_ready":false,
        "public_service_measured":false,"production_activation":false}),
    )?;
    let mut counts = Counts::default();
    for material in &materials {
        let task = pon_work::task_id(&material.a, &material.b)
            .map_err(|error| format!("FALSE_REUSE_MATERIAL:{error:?}"))?;
        emit(campaign,
            json!({"kind":"material","class":material.name,"source":material.source,
            "task":hex::encode(task),"a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            cohort(material, task, sample, &mut counts, campaign)?;
        }
    }
    emit(campaign,
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
    fn public_challenge_binds_task_sample_and_search_without_a_legal_winner() {
        let task = [9; 32];
        let first = challenge(task, 0, 0);
        assert_ne!(first, challenge([8; 32], 0, 0));
        assert_ne!(first, challenge(task, 1, 0));
        assert_ne!(first, challenge(task, 0, 1));
    }
    #[test]
    fn one_public_prefix_reused_for_distinct_forged_proofs_is_never_valid_work() {
        let a = vec![0; CELLS];
        let b = vec![1; CELLS];
        let task = pon_work::task_id(&a, &b).unwrap();
        let prefix = w1_from_zero::proof_prefix(&a, &b).unwrap();
        let original = prefix.clone();
        for search in 0..SEARCHES {
            let context = challenge(task, 0, search);
            let forged = false_search(&prefix, context, target(), LIMIT);
            let winner = forged.winner.unwrap();
            assert_eq!(
                &winner.proof[..PROOF_BYTES - 32],
                &prefix[..PROOF_BYTES - 32]
            );
            assert!(forged
                .attempts
                .iter()
                .all(|trial| trial.proof_sha256.is_none()));
            assert_eq!(prefix, original);
            pon_work::precheck_proof_statement(context, task, target(), &winner.proof).unwrap();
            for native in [
                pon_work::verify(context, task, target(), &winner.proof),
                pon_work::verify_reference(context, task, target(), &winner.proof),
                pon_work::verify_limb(context, task, target(), &winner.proof),
                pon_work::verify_column_limb(context, task, target(), &winner.proof),
                pon_work::verify_full_limb(context, task, target(), &winner.proof),
            ] {
                assert_eq!(native.unwrap_err(), WorkError::Transcript);
            }
        }
    }
    #[test]
    fn exhausted_hash_search_keeps_every_miss_without_a_candidate() {
        let zero = vec![0; CELLS];
        let prefix = w1_from_zero::proof_prefix(&zero, &zero).unwrap();
        let context = challenge(pon_work::task_id(&zero, &zero).unwrap(), 0, 0);
        let exhausted = false_search(&prefix, context, [0; 32], 4);
        assert_eq!(exhausted.attempts.len(), 4);
        assert!(exhausted.winner.is_none());
        assert!(exhausted.attempts.iter().all(|trial| !trial.target_hit));
        assert!(exhausted
            .attempts
            .iter()
            .all(|trial| trial.proof_sha256.is_none()));
    }
}
