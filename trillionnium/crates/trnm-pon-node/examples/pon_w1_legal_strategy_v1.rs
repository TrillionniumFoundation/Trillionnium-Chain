//! Frozen legal strategy comparison with actual preparation reuse and targets.
//! Each invocation is one fixed shard; none changes mining/admission policy.
#[allow(dead_code)]
#[path = "support/w1_cost_producers.rs"]
mod w1_cost_producers;
#[path = "../../trnm-crypto-primitives/examples/support/w1_material.rs"]
mod w1_material;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{hint::black_box, io::Write};
use trnm_crypto_primitives::pon_work::{self, Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES};
use w1_cost_producers::{raw, sha, Clock, Producer, Result, Timing, ARMS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Profile {
    schema: &'static str,
    selector: &'static str,
    samples: u64,
    challenge_domain: &'static [u8],
}
const V1: Profile = Profile {
    schema: "pon-w1-legal-strategy-v1",
    selector: "--legal-strategy-v1",
    samples: 2,
    challenge_domain: b"pon-w1-legal-strategy-challenge-v1",
};
const V2: Profile = Profile {
    schema: "pon-w1-legal-strategy-v2",
    selector: "--legal-strategy-v2",
    samples: 8,
    challenge_domain: b"pon-w1-legal-strategy-challenge-v2",
};
const LIMIT: u64 = 4096;
const HORIZONS: [usize; 3] = [1, 8, 64];
const CLASSES: [&str; 5] = [
    "full-rank-field",
    "zero",
    "continuity-maintenance-v1",
    "one-zero-left-rank-one",
    "one-zero-right-rank-one",
];
const STRATEGIES: [&str; 2] = ["prepared-generic", "frozen-public-dispatch-v1"];
const PATHS: [&str; 4] = ["production", "reference", "limb", "full-limb-experimental"];
const VERIFIER_CASES: [&str; 2] = ["legal", "product-last"];
const DISPATCH: [usize; 4] = [12, 7, 8, 5];

struct Shard {
    profile: Profile,
    class: String,
    target_index: usize,
    horizon: usize,
}
impl Shard {
    fn parse(args: &[String]) -> Result<Self> {
        if args.len() != 7
            || ![V1.selector, V2.selector].contains(&args[0].as_str())
            || args[1] != "--class"
            || args[3] != "--target-index"
            || args[5] != "--reuse-winners"
            || !CLASSES.contains(&args[2].as_str())
        {
            return Err("LEGAL_STRATEGY_FIXED_SHARD_REQUIRED".into());
        }
        let target_index = match args[4].as_str() {
            "0" => 0,
            "1" => 1,
            _ => return Err("LEGAL_STRATEGY_TARGET".into()),
        };
        let horizon = match args[6].as_str() {
            "1" => 1,
            "8" => 8,
            "64" => 64,
            _ => return Err("LEGAL_STRATEGY_REUSE".into()),
        };
        Ok(Self {
            profile: if args[0] == V1.selector { V1 } else { V2 },
            class: args[2].clone(),
            target_index,
            horizon,
        })
    }
    fn target(&self) -> Hash {
        let mut target = [255; 32];
        target[0] = [127, 7][self.target_index];
        target
    }
}

fn challenge(
    profile: Profile,
    task: Hash,
    target: Hash,
    sample: u64,
    search: usize,
    nonce: u64,
) -> Hash {
    // Horizon is deliberately absent: each reuse experiment has the SAME search
    // prefix. Different horizons are not additional independent mining samples.
    pon_work::hash(
        profile.challenge_domain,
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

fn prepare(strategy: usize, a: &[u32], b: &[u32]) -> Result<(Producer, Vec<&'static str>)> {
    let candidates: &[usize] = if strategy == 0 { &[1] } else { &DISPATCH };
    let mut probes = Vec::with_capacity(candidates.len());
    for &index in candidates {
        probes.push(ARMS[index]);
        // Every failed structural check and the chosen preparation are inside
        // the same setup timer. There is no per-sample timing oracle or tuning.
        if let Some(producer) =
            Producer::new(index, a, b).map_err(|error| format!("LEGAL_STRATEGY_SETUP:{error:?}"))?
        {
            return Ok((producer, probes));
        }
    }
    Err("LEGAL_STRATEGY_MISSING_GENERIC_FALLBACK".into())
}

#[derive(Clone, PartialEq, Eq)]
struct Trial {
    nonce: u64,
    challenge: Hash,
    trace: Hash,
    ticket: Hash,
    proof_sha256: Hash,
    hit: bool,
}
#[derive(Clone, PartialEq, Eq)]
struct Search {
    attempts: Vec<Trial>,
    winner: Option<(Hash, Vec<u8>)>,
}
fn search(
    profile: Profile,
    producer: &Producer,
    task: Hash,
    target: Hash,
    sample: u64,
    index: usize,
    limit: u64,
) -> Result<Search> {
    let mut observed = Search {
        attempts: Vec::new(),
        winner: None,
    };
    for nonce in 0..limit {
        let context = challenge(profile, task, target, sample, index, nonce);
        let proof = producer
            .prove(context)
            .map_err(|error| format!("LEGAL_STRATEGY_PROVE:{error:?}"))?;
        if proof.len() != PROOF_BYTES {
            return Err("LEGAL_STRATEGY_PROOF_WIDTH".into());
        }
        let trace: Hash = proof[PROOF_BYTES - 32..].try_into()?;
        let ticket = pon_work::hash(b"ticket", &[&context, &trace]);
        let hit = ticket <= target;
        observed.attempts.push(Trial {
            nonce,
            challenge: context,
            trace,
            ticket,
            proof_sha256: Sha256::digest(&proof).into(),
            hit,
        });
        if hit {
            observed.winner = Some((context, proof));
            break;
        }
    }
    Ok(observed)
}

fn emit(profile: Profile, kind: &str, mut value: Value) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or("LEGAL_STRATEGY_RECORD_OBJECT")?;
    object.insert("schema".into(), profile.schema.into());
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
        return Err("LEGAL_STRATEGY_PRODUCT_MUTATION_WIDTH".into());
    }
    let offset = PROOF_BYTES - 36;
    let before = u32::from_le_bytes(proof[offset..offset + 4].try_into()?);
    if u128::from(before) >= pon_work::Q {
        return Err("LEGAL_STRATEGY_PRODUCT_MUTATION_FIELD".into());
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
    let (producer, probes) = prepare(strategy, &material.a, &material.b)?;
    let setup = setup.finish();
    let mut searches = Vec::with_capacity(shard.horizon);
    for index in 0..shard.horizon {
        let started = Clock::start();
        let result = search(
            shard.profile,
            &producer,
            task,
            shard.target(),
            sample,
            index,
            LIMIT,
        )?;
        searches.push(Measured {
            search: result,
            timing: started.finish(),
        });
    }
    let total = total.finish();
    emit(
        shard.profile,
        "cohort",
        json!({"sample":sample,"strategy":STRATEGIES[strategy],"invocation_order":order,
        "setup_calls":1,"searches":shard.horizon,"probes":probes,"selected_arm":probes.last(),
        "setup":setup,"total":total}),
    )?;
    counts.cohorts += 1;
    for (index, measured) in searches.into_iter().enumerate() {
        let observed = measured.search;
        if canonical[index]
            .as_ref()
            .is_some_and(|old| *old != observed)
        {
            return Err("LEGAL_STRATEGY_COMPLETE_STREAM_DISAGREEMENT".into());
        }
        let trials: Vec<_> = observed.attempts.iter().map(|trial| json!({
            "nonce":trial.nonce,"challenge":hex::encode(trial.challenge),"trace":hex::encode(trial.trace),
            "ticket":hex::encode(trial.ticket),"proof_sha256":hex::encode(trial.proof_sha256),"target_hit":trial.hit})).collect();
        emit(
            shard.profile,
            "search",
            json!({"sample":sample,"strategy":STRATEGIES[strategy],"search_index":index,
            "setup_calls":0,"timing":measured.timing,"attempts":trials,
            "status":if observed.winner.is_some(){"target-hit-unverified"}else{"exhausted"},
            "winner":observed.winner.as_ref().map(|(context, proof)| json!({
                "challenge":hex::encode(context),"proof_sha256":sha(proof)}))}),
        )?;
        counts.searches += 1;
        if let Some((context, proof)) = &observed.winner {
            if canonical[index].is_none() {
                emit(
                    shard.profile,
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
                shard.profile,
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
                        1 => pon_work::verify_reference(*context, task, shard.target(), candidate),
                        2 => pon_work::verify_limb(*context, task, shard.target(), candidate),
                        _ => pon_work::verify_full_limb(*context, task, shard.target(), candidate),
                    });
                    let timing = started.finish();
                    emit(
                        shard.profile,
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
    let mut materials = w1_material::materials(None, None)?;
    let rank_one: Vec<u32> = (0..CELLS)
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
    let material = materials
        .into_iter()
        .find(|material| material.name == shard.class)
        .ok_or("LEGAL_STRATEGY_MATERIAL")?;
    let task = pon_work::task_id(&material.a, &material.b)
        .map_err(|error| format!("MATERIAL:{error:?}"))?;
    let material_setup = started.finish();
    emit(
        shard.profile,
        "campaign",
        json!({"selector":shard.profile.selector,"class":shard.class,"target_index":shard.target_index,
        "target":hex::encode(shard.target()),"reuse_winners":shard.horizon,"samples":shard.profile.samples,
        "attempt_budget":LIMIT,"seed":0,"classes":CLASSES,"horizons":HORIZONS,"strategies":STRATEGIES,
        "paths":PATHS,"cases":VERIFIER_CASES,"dispatch_arms":DISPATCH.map(|index|ARMS[index]),"material_setup":material_setup,
        "clock":"thread-cpu-and-monotonic-wall-ns",
        "producer_timing_scope":"one-actual-setup-and-all-complete-searches-including-failed-attempts-binary-retention-and-proof-hashing-excludes-hex-json-verification-and-retained-buffer-destruction",
        "mutation_timing_scope":"clone-and-canonical-last-product-word-increment-only-excludes-proof-hashing-json-and-verification",
        "verifier_timing_scope":"native-full-verification-call-only-no-fact-cache",
        "cross_horizon_challenges":"same-prefix-not-independent",
        "hardness_accepted":false,"work_profile_qualified":false,"resource_fairness_qualified":false,
        "public_service_measured":false,"independent_hardware_qualified":false,"public_network_ready":false,
        "production_activation":false}),
    )?;
    emit(
        shard.profile,
        "material",
        json!({"class":material.name,"source":material.source,"task":hex::encode(task),
        "a_hex":hex::encode(raw(&material.a)),"b_hex":hex::encode(raw(&material.b))}),
    )?;
    let mut counts = Counts::default();
    for sample in 0..shard.profile.samples {
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
        shard.profile,
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
                V1.selector,
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
        for (target, horizon) in [("2", "64"), ("0", "4"), ("00", "1"), ("0", "064")] {
            assert!(Shard::parse(&make(target, horizon)).is_err());
        }
        let mut extra = make("0", "64");
        extra.push("--fastest".into());
        assert!(Shard::parse(&extra).is_err());
    }
    #[test]
    fn versions_keep_exact_namespaces_and_eight_new_sample_streams() {
        let make = |selector: &str| {
            [
                selector,
                "--class",
                "zero",
                "--target-index",
                "0",
                "--reuse-winners",
                "64",
            ]
            .map(str::to_owned)
            .to_vec()
        };
        assert_eq!(Shard::parse(&make(V1.selector)).unwrap().profile, V1);
        assert_eq!(Shard::parse(&make(V2.selector)).unwrap().profile, V2);
        for selector in [
            "--legal-strategy",
            "--legal-strategy-v3",
            "--legal-strategy-v02",
        ] {
            assert!(Shard::parse(&make(selector)).is_err());
        }
        assert_eq!((V1.samples, V2.samples), (2, 8));
        let task = [19; 32];
        let target = [127; 32];
        let historical = pon_work::hash(
            b"pon-w1-legal-strategy-challenge-v1",
            &[
                &task,
                &target,
                &0u64.to_le_bytes(),
                &1u64.to_le_bytes(),
                &3u64.to_le_bytes(),
                &5u64.to_le_bytes(),
            ],
        );
        assert_eq!(challenge(V1, task, target, 1, 3, 5), historical);
        let mut streams = std::collections::BTreeSet::new();
        for sample in 0..V2.samples {
            let context = challenge(V2, task, target, sample, 3, 5);
            assert!(streams.insert(context));
            assert_ne!(context, challenge(V1, task, target, sample, 3, 5));
            assert_ne!(context, challenge(V2, [20; 32], target, sample, 3, 5));
            assert_ne!(context, challenge(V2, task, [126; 32], sample, 3, 5));
            assert_ne!(context, challenge(V2, task, target, sample, 4, 5));
            assert_ne!(context, challenge(V2, task, target, sample, 3, 6));
        }
        assert_eq!(streams.len(), 8);
    }
    #[test]
    fn v2_final_sample_keeps_both_legal_producers_and_complete_negative_verification() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let (generic, _) = prepare(0, &zero, &zero).unwrap();
        let (dispatch, _) = prepare(1, &zero, &zero).unwrap();
        let left = search(V2, &generic, task, [255; 32], 7, 63, 3).unwrap();
        let right = search(V2, &dispatch, task, [255; 32], 7, 63, 3).unwrap();
        assert!(left == right);
        let (context, proof) = left.winner.unwrap();
        let (changed, _, _) = product_last(&proof).unwrap();
        assert!(pon_work::verify_reference(context, task, [255; 32], &proof).is_ok());
        assert!(matches!(
            pon_work::verify_reference(context, task, [255; 32], &changed),
            Err(WorkError::Product)
        ));
    }
    #[test]
    fn public_dispatch_keeps_complete_bytes_and_all_misses() {
        let zero = vec![0; CELLS];
        let task = pon_work::task_id(&zero, &zero).unwrap();
        let (generic, generic_probes) = prepare(0, &zero, &zero).unwrap();
        let (dispatch, dispatch_probes) = prepare(1, &zero, &zero).unwrap();
        assert_eq!(generic_probes, ["prepared-generic"]);
        assert_eq!(
            dispatch_probes,
            ["maintenance-limb", "blocked-zero-integer-paired"]
        );
        let left = search(V1, &generic, task, [0; 32], 0, 0, 3).unwrap();
        let right = search(V1, &dispatch, task, [0; 32], 0, 0, 3).unwrap();
        assert!(left == right);
        assert_eq!(left.attempts.len(), 3);
        assert!(left.winner.is_none());
        let left = search(V1, &generic, task, [255; 32], 0, 1, 3).unwrap();
        let right = search(V1, &dispatch, task, [255; 32], 0, 1, 3).unwrap();
        assert!(left == right);
        let (context, proof) = left.winner.unwrap();
        assert!(pon_work::verify_reference(context, task, [255; 32], &proof).is_ok());
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
