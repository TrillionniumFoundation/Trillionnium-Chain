//! Correct-product, fresh false-trace counterexperiment from public A/B only.
//! The original V2/V3 campaigns, consensus and resource budgets are unchanged.
#[allow(dead_code)] // Share the exact clocks/records, not the legal producers.
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{raw, sha, Clock, Result, Search, Timing, Trial, Winner};

const SCHEMA: &str = "pon-w1-false-trace-correct-product-v1";
const SELECTOR: &str = "--false-trace-correct-product-v1";
const SAMPLES: u64 = 8;
const SEARCHES: usize = 4;
const LIMIT: u64 = 4096;
const PATHS: [&str; 1] = ["production"];
struct Campaign {
    schema: &'static str,
    selector: &'static str,
    paths: &'static [&'static str],
}
const CORRECT_PRODUCT: Campaign = Campaign {
    schema: SCHEMA,
    selector: SELECTOR,
    paths: &PATHS,
};

// Independent ordinary field multiplication of the public task. This setup
// never obtains a valid transcript/proof, and performs no challenge computation.
// N canonical products sum to less than 2^70, well inside u128.
fn correct_product_prefix(a: &[u32], b: &[u32]) -> std::result::Result<Vec<u8>, WorkError> {
    pon_work::task_id(a, b)?;
    let mut proof = Vec::with_capacity(PROOF_BYTES);
    proof.extend_from_slice(b"PNW1");
    for matrix in [a, b] {
        for value in matrix {
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    for i in 0..pon_work::N {
        for j in 0..pon_work::N {
            let sum: u128 = (0..pon_work::N)
                .map(|k| u128::from(a[i * pon_work::N + k]) * u128::from(b[k * pon_work::N + j]))
                .sum();
            let value = (sum % pon_work::Q) as u32;
            proof.extend_from_slice(&value.to_le_bytes());
        }
    }
    proof.resize(PROOF_BYTES, 0);
    Ok(proof)
}

fn target() -> Hash {
    let mut value = [255; 32];
    value[0] = 127;
    value
}
fn challenge(task: Hash, sample: u64, search: usize) -> Hash {
    pon_work::hash(
        b"pon-w1-false-trace-correct-product-challenge-v1",
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
        // The original two-hash forged-trace trial, without its zero-C builder.
        let trace = pon_work::hash(b"public-v3-from-zero-v1", &[&context, &nonce.to_le_bytes()]);
        let ticket = pon_work::hash(b"ticket", &[&context, &trace]);
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
    // Exactly one charged public-material validation, complete scalar AB, and
    // serialization. Only the claimed trace starts at zero; no valid transcript
    // or proof input is acquired. All four searches reuse this actual prefix.
    let prefix = correct_product_prefix(&material.a, &material.b)
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
    emit(
        campaign,
        json!({"kind":"cohort","class":material.name,"sample":sample,
        "task":hex::encode(task),"target":hex::encode(target()),"setup_calls":1,
        "searches":SEARCHES,"setup":setup,"total":total}),
    )?;
    counts.cohorts += 1;
    for (search, measured) in searches.into_iter().enumerate() {
        let searched = measured.result;
        emit(
            campaign,
            json!({"kind":"search","class":material.name,"sample":sample,
            "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
            "setup_calls":0,"timing":measured.timing,
            "status":if searched.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "attempts":searched.attempts,"winner":searched.winner.as_ref().map(|w|
                json!({"challenge":hex::encode(w.challenge),"proof_sha256":sha(&w.proof)}))}),
        )?;
        counts.searches += 1;
        if let Some(winner) = searched.winner {
            emit(
                campaign,
                json!({"kind":"candidate","class":material.name,"sample":sample,
                "search_index":search,"task":hex::encode(task),"target":hex::encode(target()),
                "challenge":hex::encode(winner.challenge),"proof_hex":hex::encode(&winner.proof),
                "proof_sha256":sha(&winner.proof)}),
            )?;
            counts.candidates += 1;
            for order in 0..campaign.paths.len() {
                let index = (sample as usize + search + order) % campaign.paths.len();
                let started = Clock::start();
                let native = black_box(pon_work::verify(
                    winner.challenge,
                    task,
                    target(),
                    &winner.proof,
                ));
                let timing = started.finish();
                let outcome = verdict(native, &winner.proof);
                // Preserve unexpected outcomes; the reader reports them.
                emit(
                    campaign,
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
        [selector] if selector == CORRECT_PRODUCT.selector => &CORRECT_PRODUCT,
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
    emit(
        campaign,
        json!({"kind":"campaign","selector":campaign.selector,"samples":SAMPLES,
        "searches_per_setup":SEARCHES,"attempt_budget":LIMIT,"seed":0,
        "target":hex::encode(target()),"paths":campaign.paths,"classes":materials.iter().map(|m|m.name).collect::<Vec<_>>(),
        "clock":"thread-cpu-and-monotonic-wall-ns","material_setup":material_setup,
        "setup_reuse":"one-public-scalar-product-prefix-four-independent-false-trace-searches",
        "attacker_timing_scope":"actual-scalar-product-prefix-setup-and-all-searches-including-challenge-hashes-trial-retention-and-winner-clone",
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
        emit(
            campaign,
            json!({"kind":"material","class":material.name,"source":material.source,
            "task":hex::encode(task),"a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
        )?;
        for sample in 0..SAMPLES {
            cohort(material, task, sample, &mut counts, campaign)?;
        }
    }
    emit(
        campaign,
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
    fn correct_public_product_is_canonical_without_any_valid_transcript() {
        let a: Vec<u32> = (0..CELLS).map(|i| ((17 * i + 3) % 257) as u32).collect();
        let identity: Vec<u32> = (0..CELLS)
            .map(|i| u32::from(i / pon_work::N == i % pon_work::N))
            .collect();
        let prefix = correct_product_prefix(&a, &identity).unwrap();
        assert_eq!(prefix.len(), PROOF_BYTES);
        assert_eq!(&prefix[4 + 8 * CELLS..PROOF_BYTES - 32], raw(&a));
        assert_eq!(&prefix[PROOF_BYTES - 32..], &[0; 32]);
        assert_eq!(
            correct_product_prefix(&[], &identity).unwrap_err(),
            WorkError::Length
        );
        assert_eq!(
            correct_product_prefix(&vec![pon_work::Q as u32; CELLS], &identity).unwrap_err(),
            WorkError::Field
        );
        let top = vec![pon_work::Q as u32 - 1; CELLS];
        let extreme = correct_product_prefix(&top, &top).unwrap();
        for word in extreme[4 + 8 * CELLS..PROOF_BYTES - 32].chunks_exact(4) {
            assert_eq!(
                u32::from_le_bytes(word.try_into().unwrap()),
                pon_work::N as u32
            );
        }
    }

    #[test]
    fn correct_product_false_traces_still_owe_every_original_transcript_tile() {
        let dense: Vec<u32> = (0..CELLS).map(|i| ((i * 7 + 1) % 37) as u32).collect();
        let zero = vec![0; CELLS];
        for (a, b) in [(&dense, &dense), (&zero, &zero), (&dense, &zero)] {
            let prefix = correct_product_prefix(a, b).unwrap();
            let original = prefix.clone();
            let task = pon_work::task_id(a, b).unwrap();
            for search in 0..SEARCHES {
                let context = challenge(task, 0, search);
                let searched = false_search(&prefix, context, target(), LIMIT);
                let winner = searched.winner.unwrap();
                assert_eq!(
                    &winner.proof[..PROOF_BYTES - 32],
                    &prefix[..PROOF_BYTES - 32]
                );
                assert!(searched
                    .attempts
                    .iter()
                    .all(|trial| trial.proof_sha256.is_none()));
                pon_work::precheck_proof_statement(context, task, target(), &winner.proof).unwrap();
                let mut tiles = 0;
                let result = pon_work::verify_with_progress(
                    context,
                    task,
                    target(),
                    &winner.proof,
                    &mut |point| {
                        if matches!(point, pon_work::VerificationProgress::TranscriptTile { .. }) {
                            tiles += 1;
                        }
                        Ok::<(), ()>(())
                    },
                );
                assert_eq!(
                    result.unwrap_err(),
                    pon_work::VerificationError::Relation(WorkError::Transcript)
                );
                assert_eq!(tiles, 512);
            }
            assert_eq!(prefix, original);
        }
    }

    #[test]
    fn separate_challenge_domain_binds_every_search_without_relabelling_old_capture() {
        let task = [9; 32];
        let first = challenge(task, 0, 0);
        assert_ne!(first, challenge([8; 32], 0, 0));
        assert_ne!(first, challenge(task, 1, 0));
        assert_ne!(first, challenge(task, 0, 1));
        let old = pon_work::hash(
            b"pon-w1-false-trace-reuse-challenge-v1",
            &[
                &task,
                &0_u64.to_le_bytes(),
                &0_u64.to_le_bytes(),
                &0_u64.to_le_bytes(),
            ],
        );
        assert_ne!(first, old);
        let zero = vec![0; CELLS];
        let prefix = correct_product_prefix(&zero, &zero).unwrap();
        let exhausted = false_search(&prefix, first, [0; 32], 4);
        assert_eq!(exhausted.attempts.len(), 4);
        assert!(exhausted.winner.is_none());
        assert!(exhausted.attempts.iter().all(|trial| !trial.target_hit));
    }
}
