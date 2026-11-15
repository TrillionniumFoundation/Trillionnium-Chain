//! Factorial complete-attempt comparison: fixed-product preparation x materialization.
//! Every arm uses the existing FullLimb transcript kernel. External bytes are
//! accepted only as canonical A/B inputs, never as attested Hepta provenance.
//! Each invocation is one fixed shard; none changes mining/admission policy.
#[allow(dead_code)]
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::legal_attempt::{
    Arithmetic, Materialization, Preparation, Task,
};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{raw, sha, Clock, Result, Timing};

const SCHEMA: &str = "pon-w1-preparation-strategy-v4";
const SELECTOR: &str = "--preparation-strategy-v4";
const SAMPLES: u64 = 8;
const LIMIT: u64 = 4096;
const HORIZONS: [usize; 3] = [1, 8, 64];
const CLASSES: [&str; 6] = [
    "full-rank-field",
    "zero",
    "rank-one",
    "sparse-diagonal",
    "sparse-field",
    "maximum-field",
];
const STRATEGIES: [&str; 4] = [
    "dense-eager-full-limb",
    "dense-lazy-full-limb",
    "sparse-eager-full-limb",
    "sparse-lazy-full-limb",
];
const ARITHMETIC: [&str; 4] = ["full-limb"; 4];
const PREPARATION: [&str; 4] = ["dense", "dense", "sparse", "sparse"];
const MATERIALIZATION: [&str; 4] = ["every-attempt", "target-hit", "every-attempt", "target-hit"];
const PATHS: [&str; 2] = ["production", "reference"];
const VERIFIER_CASES: [&str; 2] = ["legal", "product-last"];

struct Shard {
    class: String,
    target_index: usize,
    horizon: usize,
    model: Option<std::path::PathBuf>,
    input: Option<std::path::PathBuf>,
}
impl Shard {
    fn parse(args: &[String]) -> Result<Self> {
        if ![7, 11].contains(&args.len())
            || args[0] != SELECTOR
            || args[1] != "--class"
            || args[3] != "--target-index"
            || args[5] != "--reuse-winners"
        {
            return Err("PREPARATION_STRATEGY_FIXED_SHARD_REQUIRED".into());
        }
        let supplied = args[2] == "supplied-material";
        if (supplied && (args.len() != 11 || args[7] != "--model" || args[9] != "--input"))
            || (!supplied && (args.len() != 7 || !CLASSES.contains(&args[2].as_str())))
        {
            return Err("PREPARATION_STRATEGY_MATERIAL_SELECTION".into());
        }
        let target_index = match args[4].as_str() {
            "0" => 0,
            "1" => 1,
            "2" => 2,
            "3" => 3,
            _ => return Err("PREPARATION_STRATEGY_TARGET".into()),
        };
        let horizon = match args[6].as_str() {
            "1" => 1,
            "8" => 8,
            "64" => 64,
            _ => return Err("PREPARATION_STRATEGY_REUSE".into()),
        };
        if target_index >= 2 && horizon != 1 {
            return Err("PREPARATION_STRATEGY_CONTROL_HORIZON".into());
        }
        Ok(Self {
            class: args[2].clone(),
            target_index,
            horizon,
            model: supplied.then(|| args[8].as_str().into()),
            input: supplied.then(|| args[10].as_str().into()),
        })
    }
    fn target(&self) -> Hash {
        let mut target = [255; 32];
        match self.target_index {
            0 => target[0] = 127,
            1 => target[0] = 7,
            2 => {
                target.fill(0);
                target[31] = 1;
            }
            3 => (),
            _ => unreachable!("validated target"),
        }
        target
    }
    fn limit(&self) -> u64 {
        if self.target_index < 2 {
            LIMIT
        } else {
            3
        }
    }
    fn purpose(&self) -> &'static str {
        match self.target_index {
            0 | 1 => "search-cost",
            2 => "exhaustion-control",
            3 => "first-hit-control",
            _ => unreachable!("validated target"),
        }
    }
}

fn material(shard: &Shard) -> Result<w1_material::Material> {
    let mut materials = w1_material::materials(shard.model.as_deref(), shard.input.as_deref())?;
    if shard.class == "maximum-field" {
        return Ok(w1_material::Material {
            name: "maximum-field",
            source: "synthetic-fixture",
            a: vec![pon_work::Q as u32 - 1; CELLS],
            b: vec![pon_work::Q as u32 - 1; CELLS],
        });
    }
    if shard.class == "sparse-field" {
        let dense = materials
            .iter_mut()
            .find(|m| m.name == "full-rank-field")
            .ok_or("PREPARATION_STRATEGY_DENSE_RECIPE")?;
        let a = dense
            .a
            .iter()
            .enumerate()
            .map(|(i, v)| if i % 17 == 0 { *v } else { 0 })
            .collect();
        let b = dense
            .b
            .iter()
            .enumerate()
            .map(|(i, v)| if i % 19 == 0 { *v } else { 0 })
            .collect();
        return Ok(w1_material::Material {
            name: "sparse-field",
            source: "synthetic-fixture",
            a,
            b,
        });
    }
    materials
        .into_iter()
        .find(|m| m.name == shard.class)
        .ok_or_else(|| "PREPARATION_STRATEGY_MATERIAL".into())
}

fn challenge(task: Hash, target: Hash, sample: u64, search: usize, nonce: u64) -> Hash {
    // Horizon is deliberately absent: each reuse experiment has the SAME search
    // prefix. Different horizons are not additional independent mining samples.
    pon_work::hash(
        b"pon-w1-preparation-strategy-challenge-v4",
        &[
            &task,
            &target,
            &0u64.to_le_bytes(),
            &sample.to_le_bytes(),
            &(search as u64).to_le_bytes(),
            &nonce.to_le_bytes(),
        ],
    )
}

fn prepare(strategy: usize, a: &[u32], b: &[u32]) -> Result<Task> {
    let preparation = if strategy < 2 {
        Preparation::Dense
    } else {
        Preparation::Sparse
    };
    Task::with_preparation(a, b, Arithmetic::FullLimb, preparation)
        .map_err(|error| format!("PREPARATION_STRATEGY_SETUP:{error:?}").into())
}

fn materialization(strategy: usize) -> Materialization {
    if strategy.is_multiple_of(2) {
        Materialization::EveryAttempt
    } else {
        Materialization::TargetHit
    }
}

#[derive(Clone, PartialEq, Eq)]
struct Trial {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    proof_materialized: bool,
    hit: bool,
}
#[derive(Clone, PartialEq, Eq)]
struct Search {
    attempts: Vec<Trial>,
    winner: Option<(Hash, Vec<u8>)>,
}
fn search(
    producer: &Task,
    strategy: usize,
    task: Hash,
    target: Hash,
    sample: u64,
    index: usize,
    limit: u64,
) -> Result<Search> {
    if limit == 0 || limit > LIMIT {
        return Err("PREPARATION_STRATEGY_ATTEMPT_BUDGET".into());
    }
    let mut observed = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let context = challenge(task, target, sample, index, nonce);
        let attempt = black_box(
            producer
                .attempt(context, target, materialization(strategy))
                .map_err(|error| format!("PREPARATION_STRATEGY_PROVE:{error:?}"))?,
        );
        // Apply the same observation to every factorial cell. In particular,
        // an eager losing Vec must exist with its bytes; observing just length
        // would let optimized builds elide materialization before destruction.
        black_box(&attempt);
        if attempt.challenge != context
            || attempt.target_hit != (attempt.ticket <= target)
            || attempt.proof.is_some() != (strategy.is_multiple_of(2) || attempt.target_hit)
            || attempt
                .proof
                .as_ref()
                .is_some_and(|bytes| bytes.len() != PROOF_BYTES)
        {
            return Err("PREPARATION_STRATEGY_ATTEMPT_IDENTITY".into());
        }
        observed.attempts.push(Trial {
            nonce,
            challenge: context,
            trace: attempt.trace,
            ticket: attempt.ticket,
            proof_materialized: attempt.proof.is_some(),
            hit: attempt.target_hit,
        });
        if attempt.target_hit {
            observed.winner = Some((
                context,
                attempt.proof.ok_or("PREPARATION_STRATEGY_WINNER_BYTES")?,
            ));
            break;
        }
        // Any eager losing proof is dropped here, inside the producer timer.
    }
    Ok(observed)
}

fn same_legal_stream(left: &Search, right: &Search) -> bool {
    left.winner == right.winner
        && left.attempts.len() == right.attempts.len()
        && left.attempts.iter().zip(&right.attempts).all(|(a, b)| {
            (a.nonce, a.challenge, a.trace, a.ticket, a.hit)
                == (b.nonce, b.challenge, b.trace, b.ticket, b.hit)
        })
}

fn trial_evidence(prefix: &[u8], observed: &Search) -> Vec<Value> {
    // Evidence reconstruction occurs after the producer timer. Every complete
    // attempt's digest is retained; no losing nonce is priced as a free attempt.
    let mut prepared_digest = Sha256::new();
    prepared_digest.update(prefix);
    observed
        .attempts
        .iter()
        .map(|trial| {
            let mut digest = prepared_digest.clone();
            digest.update(trial.trace);
            json!({"nonce":trial.nonce,"challenge":hex::encode(trial.challenge),
            "trace":hex::encode(trial.trace),"ticket":hex::encode(trial.ticket),
            "proof_sha256":hex::encode(digest.finalize()),
            "proof_materialized":trial.proof_materialized,"target_hit":trial.hit})
        })
        .collect()
}

fn emit(kind: &str, mut value: Value) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or("PREPARATION_STRATEGY_RECORD_OBJECT")?;
    object.insert("schema".into(), SCHEMA.into());
    object.insert("kind".into(), kind.into());
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &value)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
fn verdict(
    result: std::result::Result<VerifiedWork, WorkError>,
    challenge: Hash,
    task: Hash,
    proof: &[u8],
) -> String {
    match result {
        Ok(work)
            if work.challenge() != challenge
                || work.task() != task
                || work.ticket()
                    != pon_work::hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]) =>
        {
            "AcceptedWrongStatement".into()
        }
        Ok(work) if raw(work.product()) == proof[4 + 8 * CELLS..PROOF_BYTES - 32] => {
            "Accepted".into()
        }
        Ok(_) => "AcceptedWrongProduct".into(),
        Err(error) => format!("{error:?}"),
    }
}

fn product_last(proof: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    if proof.len() != PROOF_BYTES {
        return Err("PREPARATION_STRATEGY_PRODUCT_MUTATION_WIDTH".into());
    }
    let offset = PROOF_BYTES - 36;
    let before = u32::from_le_bytes(proof[offset..offset + 4].try_into()?);
    if u128::from(before) >= pon_work::Q {
        return Err("PREPARATION_STRATEGY_PRODUCT_MUTATION_FIELD".into());
    }
    let after = ((u128::from(before) + 1) % pon_work::Q) as u32;
    let mut changed = proof.to_vec();
    changed[offset..offset + 4].copy_from_slice(&after.to_le_bytes());
    Ok((changed, before, after))
}
struct Measured {
    search: Search,
    timing: Timing,
}
#[derive(Default)]
struct Counts {
    cohorts: usize,
    searches: usize,
    candidates: usize,
    mutations: usize,
    verifiers: usize,
}

fn cohort(
    shard: &Shard,
    material: &w1_material::Material,
    task: Hash,
    sample: u64,
    order: usize,
    canonical: &mut [Option<Search>],
    counts: &mut Counts,
) -> Result<()> {
    let strategy = (sample as usize + shard.target_index + order) % STRATEGIES.len();
    let total = Clock::start();
    let setup = Clock::start();
    let producer = prepare(strategy, &material.a, &material.b)?;
    let setup = setup.finish();
    let mut searches = Vec::with_capacity(shard.horizon);
    for index in 0..shard.horizon {
        let started = Clock::start();
        let result = search(
            &producer,
            strategy,
            task,
            shard.target(),
            sample,
            index,
            shard.limit(),
        )?;
        searches.push(Measured {
            search: result,
            timing: started.finish(),
        });
    }
    let total = total.finish();
    emit(
        "cohort",
        json!({"sample":sample,"strategy":STRATEGIES[strategy],"invocation_order":order,
        "setup_calls":1,"searches":shard.horizon,"arithmetic":ARITHMETIC[strategy],"preparation":PREPARATION[strategy],"materialization":MATERIALIZATION[strategy],
        "setup":setup,"total":total}),
    )?;
    counts.cohorts += 1;
    for (index, measured) in searches.into_iter().enumerate() {
        let observed = measured.search;
        if canonical[index]
            .as_ref()
            .is_some_and(|old| !same_legal_stream(old, &observed))
        {
            return Err("PREPARATION_STRATEGY_COMPLETE_STREAM_DISAGREEMENT".into());
        }
        let evidence_started = Clock::start();
        let trials = trial_evidence(producer.proof_prefix(), &observed);
        let evidence_timing = evidence_started.finish();
        let materializations = observed
            .attempts
            .iter()
            .filter(|t| t.proof_materialized)
            .count();
        emit(
            "search",
            json!({"sample":sample,"strategy":STRATEGIES[strategy],"search_index":index,
            "setup_calls":0,"timing":measured.timing,"attempts":trials,
            "evidence_timing":evidence_timing,"proof_materializations":materializations,"serialized_proof_bytes":materializations*PROOF_BYTES,
            "status":if observed.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "winner":observed.winner.as_ref().map(|(context, proof)| json!({
                "challenge":hex::encode(context),"proof_sha256":sha(proof)}))}),
        )?;
        counts.searches += 1;
        if let Some((context, proof)) = &observed.winner {
            if canonical[index].is_none() {
                emit(
                    "candidate",
                    json!({"sample":sample,"search_index":index,
                    "challenge":hex::encode(context),"proof_hex":hex::encode(proof),"proof_sha256":sha(proof)}),
                )?;
                counts.candidates += 1;
            }
            // The acquisition above remains charged once to this strategy.
            // Clone/mutation is a separately measured diagnostic phase, not a
            // fictitious new mined winner or cost-free accepted certificate.
            let mutation_started = Clock::start();
            let (changed, before, after) = product_last(proof)?;
            let mutation = mutation_started.finish();
            emit(
                "product_mutation",
                json!({"sample":sample,"strategy":STRATEGIES[strategy],"search_index":index,
                "source_proof_sha256":sha(proof),"proof_sha256":sha(&changed),"offset":PROOF_BYTES-36,
                "before":before,"after":after,"timing":mutation}),
            )?;
            counts.mutations += 1;
            for (case_index, candidate) in [proof.as_slice(), changed.as_slice()]
                .into_iter()
                .enumerate()
            {
                for verification_order in 0..PATHS.len() {
                    let path = (sample as usize + order + index + verification_order) % PATHS.len();
                    let started = Clock::start();
                    let actual = black_box(match path {
                        0 => pon_work::verify(*context, task, shard.target(), candidate),
                        _ => pon_work::verify_reference(*context, task, shard.target(), candidate),
                    });
                    let timing = started.finish();
                    emit(
                        "verifier",
                        json!({"sample":sample,"strategy":STRATEGIES[strategy],"search_index":index,
                        "case":VERIFIER_CASES[case_index],"invocation_order":verification_order,
                        "path":PATHS[path],"challenge":hex::encode(context),"proof_sha256":sha(candidate),
                        "outcome":verdict(actual, *context, task, candidate),"timing":timing}),
                    )?;
                    counts.verifiers += 1;
                }
            }
        }
        if canonical[index].is_none() {
            canonical[index] = Some(observed);
        }
    }
    Ok(())
}

fn run() -> Result<()> {
    let shard = Shard::parse(&std::env::args().skip(1).collect::<Vec<_>>())?;
    let started = Clock::start();
    let material = material(&shard)?;
    let task = pon_work::task_id(&material.a, &material.b)
        .map_err(|error| format!("MATERIAL:{error:?}"))?;
    let material_setup = started.finish();
    emit(
        "campaign",
        json!({"selector":SELECTOR,"class":shard.class,"target_index":shard.target_index,
        "target":hex::encode(shard.target()),"reuse_winners":shard.horizon,"samples":SAMPLES,
        "attempt_budget":shard.limit(),"purpose":shard.purpose(),"seed":0,"classes":CLASSES,"horizons":HORIZONS,"strategies":STRATEGIES,
        "paths":PATHS,"cases":VERIFIER_CASES,"arithmetic":ARITHMETIC,"preparation":PREPARATION,"materialization":MATERIALIZATION,"material_setup":material_setup,
        "clock":"thread-cpu-and-monotonic-wall-ns",
        "producer_timing_scope":"one-actual-setup-and-all-complete-transcripts-tickets-and-proof-materializations-including-misses-and-binary-trial-retention-excludes-evidence-digests-hex-json-verification-and-retained-buffer-destruction",
        "evidence_timing_scope":"complete-attempt-digests-and-json-value-construction-after-producer-timer-excludes-json-serialization-write-and-native-verification",
        "mutation_timing_scope":"clone-and-canonical-last-product-word-increment-only-excludes-proof-hashing-json-and-verification",
        "verifier_timing_scope":"native-full-verification-call-only-no-fact-cache",
        "cross_horizon_challenges":"same-prefix-not-independent",
        "hardness_accepted":false,"work_profile_qualified":false,"resource_fairness_qualified":false,
        "public_service_measured":false,"independent_hardware_qualified":false,"public_network_ready":false,
        "production_activation":false}),
    )?;
    emit(
        "material",
        json!({"class":material.name,"source":material.source,"task":hex::encode(task),
        "a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b)),
        "a_sha256":sha(&raw(&material.a)),"b_sha256":sha(&raw(&material.b)),
        "provenance_verified":false}),
    )?;
    let mut counts = Counts::default();
    for sample in 0..SAMPLES {
        let mut canonical = vec![None; shard.horizon];
        for order in 0..STRATEGIES.len() {
            cohort(
                &shard,
                &material,
                task,
                sample,
                order,
                &mut canonical,
                &mut counts,
            )?;
        }
    }
    emit(
        "end",
        json!({"cohort_count":counts.cohorts,"search_count":counts.searches,
        "candidate_count":counts.candidates,"product_mutation_count":counts.mutations,"verifier_count":counts.verifiers,"complete":true}),
    )
}
fn main() -> Result<()> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_shards_reject_unfrozen_targets_horizons_and_extra_arguments() {
        let make = |target: &str, horizon: &str| {
            [
                SELECTOR,
                "--class",
                "zero",
                "--target-index",
                target,
                "--reuse-winners",
                horizon,
            ]
            .map(str::to_owned)
            .to_vec()
        };
        for horizon in ["1", "8", "64"] {
            for target in ["0", "1"] {
                assert!(Shard::parse(&make(target, horizon)).is_ok());
            }
        }
        for (target, horizon) in [
            ("4", "64"),
            ("2", "8"),
            ("3", "64"),
            ("0", "4"),
            ("00", "1"),
            ("0", "064"),
        ] {
            assert!(Shard::parse(&make(target, horizon)).is_err());
        }
        let mut extra = make("0", "64");
        extra.push("--fastest".into());
        assert!(Shard::parse(&extra).is_err());
    }
    #[test]
    fn factorial_search_keeps_every_miss_and_identical_complete_winners() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let mut target = [0; 32];
        target[31] = 1;
        let mut canonical = None;
        for strategy in 0..STRATEGIES.len() {
            let producer = prepare(strategy, &zero, &zero).unwrap();
            let missed = search(&producer, strategy, task, target, 0, 0, 3).unwrap();
            assert_eq!(missed.attempts.len(), 3);
            assert!(missed.winner.is_none());
            assert!(missed
                .attempts
                .iter()
                .all(|t| t.proof_materialized == strategy.is_multiple_of(2)));
            if let Some(old) = &canonical {
                assert!(same_legal_stream(old, &missed));
            } else {
                canonical = Some(missed);
            }
            let winner = search(&producer, strategy, task, [255; 32], 0, 1, 3).unwrap();
            let (context, proof) = winner.winner.as_ref().unwrap();
            let evidence = trial_evidence(producer.proof_prefix(), &winner);
            assert_eq!(evidence[0]["proof_sha256"], sha(proof));
            assert!(pon_work::verify_reference(*context, task, [255; 32], proof).is_ok());
        }
    }
    #[test]
    fn both_preparations_reject_noncanonical_material_even_in_zero_products() {
        let zero = vec![0; CELLS];
        let mut malformed = zero.clone();
        malformed[CELLS - 1] = pon_work::Q as u32;
        for strategy in 0..STRATEGIES.len() {
            assert!(prepare(strategy, &zero[..CELLS - 1], &zero).is_err());
            assert!(prepare(strategy, &malformed, &zero).is_err());
            assert!(prepare(strategy, &zero, &malformed).is_err());
            let producer = prepare(strategy, &zero, &zero).unwrap();
            let task = pon_work::task_id(&zero, &zero).unwrap();
            assert!(search(&producer, strategy, task, [255; 32], 0, 0, 0).is_err());
            assert!(search(&producer, strategy, task, [255; 32], 0, 0, LIMIT + 1).is_err());
            assert!(search(&producer, strategy, task, [0; 32], 0, 0, 3).is_err());
        }
    }

    #[test]
    fn all_six_structures_match_full_limb_and_independent_scalar_replay() {
        for class in CLASSES {
            let shard = Shard {
                class: class.into(),
                target_index: 3,
                horizon: 1,
                model: None,
                input: None,
            };
            let m = material(&shard).unwrap();
            let task = pon_work::task_id(&m.a, &m.b).unwrap();
            let mut baseline = None;
            for strategy in 0..STRATEGIES.len() {
                let producer = prepare(strategy, &m.a, &m.b).unwrap();
                let found = search(&producer, strategy, task, [255; 32], 0, 0, 3).unwrap();
                assert_eq!(found.attempts.len(), 1, "first hit must stop");
                let (context, proof) = found.winner.as_ref().unwrap();
                assert!(pon_work::verify(*context, task, [255; 32], proof).is_ok());
                assert!(pon_work::verify_reference(*context, task, [255; 32], proof).is_ok());
                if let Some(previous) = &baseline {
                    assert!(same_legal_stream(previous, &found));
                } else {
                    baseline = Some(found);
                }
            }
        }
    }

    #[test]
    fn external_raw_material_is_exact_bounded_and_never_promoted_to_provenance() {
        let temp = tempfile::tempdir().unwrap();
        let a_path = temp.path().join("a.bin");
        let b_path = temp.path().join("b.bin");
        let bytes = raw(&vec![pon_work::Q as u32 - 1; CELLS]);
        std::fs::write(&a_path, &bytes).unwrap();
        std::fs::write(&b_path, &bytes).unwrap();
        let mut args = [
            SELECTOR,
            "--class",
            "supplied-material",
            "--target-index",
            "3",
            "--reuse-winners",
            "1",
            "--model",
        ]
        .map(str::to_owned)
        .to_vec();
        args.extend([
            a_path.display().to_string(),
            "--input".into(),
            b_path.display().to_string(),
        ]);
        let shard = Shard::parse(&args).unwrap();
        let m = material(&shard).unwrap();
        assert_eq!(m.source, "caller-supplied-provenance-not-verified");
        assert_eq!(raw(&m.a), bytes);
        assert_eq!(raw(&m.b), bytes);
        assert!(Shard::parse(&args[..7]).is_err());
        args[2] = "zero".into();
        assert!(Shard::parse(&args).is_err());
        for invalid in [
            vec![0; CELLS * 4 - 1],
            vec![0; CELLS * 4 + 1],
            vec![255; CELLS * 4],
        ] {
            std::fs::write(&a_path, invalid).unwrap();
            assert!(material(&shard).is_err());
        }
    }

    #[test]
    fn last_product_mutation_wraps_canonically_and_changes_only_that_word() {
        let offset = PROOF_BYTES - 36;
        for before in [0, 1, pon_work::Q as u32 - 1] {
            let mut original = vec![0; PROOF_BYTES];
            original[..4].copy_from_slice(b"PNW1");
            original[offset..offset + 4].copy_from_slice(&before.to_le_bytes());
            let (changed, recorded_before, after) = product_last(&original).unwrap();
            assert_eq!(recorded_before, before);
            assert_eq!(u128::from(after), (u128::from(before) + 1) % pon_work::Q);
            assert_ne!(before, after);
            assert_eq!(&changed[..offset], &original[..offset]);
            assert_eq!(&changed[offset + 4..], &original[offset + 4..]);
            assert_eq!(&changed[offset..offset + 4], &after.to_le_bytes());
        }
        assert!(product_last(&vec![0; PROOF_BYTES - 1]).is_err());
        let mut noncanonical = vec![0; PROOF_BYTES];
        noncanonical[offset..offset + 4].copy_from_slice(&(pon_work::Q as u32).to_le_bytes());
        assert!(product_last(&noncanonical).is_err());
    }
    #[test]
    fn valid_acquisition_and_late_product_refusal_keep_full_statement_identity() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let context = [7; 32];
        let proof = pon_work::prove(context, &zero, &zero).unwrap();
        let (changed, _, _) = product_last(&proof).unwrap();
        for verify in [
            pon_work::verify,
            pon_work::verify_reference,
            pon_work::verify_limb,
            pon_work::verify_full_limb,
        ] {
            assert_eq!(
                verdict(
                    verify(context, task, [255; 32], &proof),
                    context,
                    task,
                    &proof
                ),
                "Accepted"
            );
            assert_eq!(
                verdict(
                    verify(context, task, [255; 32], &changed),
                    context,
                    task,
                    &changed
                ),
                "Product"
            );
            assert_eq!(
                verdict(
                    verify(context, task, [255; 32], &proof),
                    [8; 32],
                    task,
                    &proof
                ),
                "AcceptedWrongStatement"
            );
        }
    }
}
