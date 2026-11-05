//! Repeated independent searches on one W1 task, with actual cold/reused setup.
//! Observations include every attempted proof and common harness hashing. They
//! do not establish CPU accounting, fastest-adversary cost or work hardness.
#[path = "support/w1_material.rs"]
mod w1_material;

use sha2::{Digest, Sha256};
use std::{
    env, error::Error, ffi::OsString, fmt::Write, hint::black_box, path::PathBuf, time::Instant,
};
use trnm_crypto_primitives::pon_work::{
    structured::{StructuredPreparedTask, TileKernel, TiledPreparedTask},
    *,
};
use w1_material::{materials, rank, Material};

const TICKET_STREAM_DOMAIN: &[u8] = b"TRNM-PON-W1-REUSED-TICKET-STREAM1\0";
const PROOF_STREAM_DOMAIN: &[u8] = b"TRNM-PON-W1-REUSED-PROOF-STREAM1\0";

#[derive(Debug)]
struct Options {
    model: Option<PathBuf>,
    input: Option<PathBuf>,
    samples: u64,
    searches: u64,
    attempts: u64,
    seed: u64,
}
impl Options {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, Box<dyn Error>> {
        let mut options = Self {
            model: None,
            input: None,
            samples: 4,
            searches: 4,
            attempts: 256,
            seed: 0,
        };
        let mut seen = [false; 6];
        let mut arguments = arguments.into_iter();
        while let Some(flag) = arguments.next() {
            let index = match flag.to_str() {
                Some("--model") => 0,
                Some("--input") => 1,
                Some("--samples") => 2,
                Some("--searches") => 3,
                Some("--attempt-budget") => 4,
                Some("--seed") => 5,
                _ => return Err(
                    "expected --model, --input, --samples, --searches, --attempt-budget or --seed"
                        .into(),
                ),
            };
            if seen[index] {
                return Err("duplicate option".into());
            }
            seen[index] = true;
            let value = arguments.next().ok_or("each flag requires a value")?;
            match index {
                0 => options.model = Some(value.into()),
                1 => options.input = Some(value.into()),
                _ => {
                    let number: u64 = value.to_str().ok_or("numeric option encoding")?.parse()?;
                    match index {
                        2 => options.samples = number,
                        3 => options.searches = number,
                        4 => options.attempts = number,
                        _ => options.seed = number,
                    }
                }
            }
        }
        if options.model.is_some() != options.input.is_some()
            || !(1..=32).contains(&options.samples)
            || !(1..=32).contains(&options.searches)
            || !(1..=4096).contains(&options.attempts)
        {
            return Err(
                "paired materials, 1..32 samples, 1..32 searches and 1..4096 attempts are required"
                    .into(),
            );
        }
        Ok(options)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    Scalar,
    Generic,
    Structured,
    Classical,
    Strassen,
}
impl Strategy {
    const ALL: [Self; 5] = [
        Self::Scalar,
        Self::Generic,
        Self::Structured,
        Self::Classical,
        Self::Strassen,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Scalar => "scalar-original",
            Self::Generic => "prepared-generic",
            Self::Structured => "prepared-structured",
            Self::Classical => "tiled-classical",
            Self::Strassen => "tiled-strassen-one-level",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Cold,
    Reused,
}
impl Mode {
    fn name(self) -> &'static str {
        match self {
            Self::Cold => "cold-per-search",
            Self::Reused => "reused-one-setup",
        }
    }
}

enum Producer<'a> {
    Scalar(&'a Material),
    Generic(PreparedTask),
    Structured(StructuredPreparedTask),
    Classical(TiledPreparedTask),
    Strassen(TiledPreparedTask),
    Unsupported,
}
impl Producer<'_> {
    fn method(&self) -> &'static str {
        match self {
            Self::Scalar(_) => "scalar-full-generation",
            Self::Generic(_) => "generic-product-and-transcript",
            Self::Structured(task) => task.method(),
            Self::Classical(_) => "tiled-classical-full-transcript",
            Self::Strassen(_) => "tiled-strassen-one-level-full-transcript",
            Self::Unsupported => "unsupported",
        }
    }

    fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Scalar(material) => prove(challenge, &material.a, &material.b),
            Self::Generic(task) => task.prove(challenge),
            Self::Structured(task) => task.prove(challenge),
            Self::Classical(task) | Self::Strassen(task) => task.prove(challenge),
            Self::Unsupported => unreachable!("unsupported producers are never searched"),
        }
    }
}

fn prepare(material: &Material, strategy: Strategy) -> Result<Producer<'_>, WorkError> {
    Ok(match strategy {
        Strategy::Scalar => Producer::Scalar(material),
        Strategy::Generic => Producer::Generic(PreparedTask::new(&material.a, &material.b)?),
        Strategy::Structured => match StructuredPreparedTask::new(&material.a, &material.b)? {
            Some(task) => Producer::Structured(task),
            None => Producer::Unsupported,
        },
        Strategy::Classical => Producer::Classical(TiledPreparedTask::new(
            &material.a,
            &material.b,
            TileKernel::Classical,
        )?),
        Strategy::Strassen => Producer::Strassen(TiledPreparedTask::new(
            &material.a,
            &material.b,
            TileKernel::StrassenOneLevel,
        )?),
    })
}

#[derive(Clone, Copy)]
struct SearchPlan {
    task: Hash,
    target: Hash,
    seed: u64,
    sample: u64,
    searches: u64,
    budget: u64,
}

#[derive(Debug)]
struct Search {
    attempts: u64,
    elapsed: u128,
    ticket_stream: Hash,
    proof_stream: Hash,
    // Only the winning complete proof is retained. Every target miss is hashed
    // completely before it is discarded, keeping retained memory bounded.
    winning: Option<(Hash, Vec<u8>)>,
}

fn search(
    plan: SearchPlan,
    search_index: u64,
    mut producer: impl FnMut(Hash) -> Result<Vec<u8>, WorkError>,
) -> Result<Search, WorkError> {
    let start = Instant::now();
    let mut tickets = Sha256::new();
    let mut proofs = Sha256::new();
    tickets.update(TICKET_STREAM_DOMAIN);
    proofs.update(PROOF_STREAM_DOMAIN);
    let mut winning = None;
    let mut attempts = 0;
    for nonce in 0..plan.budget {
        let challenge = hash(
            b"reused-cost-v1",
            &[
                &plan.task,
                &plan.seed.to_le_bytes(),
                &plan.sample.to_le_bytes(),
                &search_index.to_le_bytes(),
                &plan.target,
                &nonce.to_le_bytes(),
            ],
        );
        let proof = producer(challenge)?;
        if proof.len() != PROOF_BYTES {
            return Err(WorkError::Length);
        }
        let ticket = hash(b"ticket", &[&challenge, &proof[PROOF_BYTES - 32..]]);
        tickets.update(nonce.to_le_bytes());
        tickets.update(challenge);
        tickets.update(ticket);
        proofs.update(nonce.to_le_bytes());
        proofs.update(challenge);
        proofs.update((proof.len() as u64).to_le_bytes());
        proofs.update(&proof);
        attempts += 1;
        if ticket <= plan.target {
            winning = Some((challenge, proof));
            break;
        }
    }
    let ticket_stream = tickets.finalize().into();
    let proof_stream = proofs.finalize().into();
    Ok(Search {
        attempts,
        elapsed: start.elapsed().as_nanos(),
        ticket_stream,
        proof_stream,
        winning,
    })
}

struct Observation {
    strategy: Strategy,
    method: &'static str,
    mode: Mode,
    setup_observations: Vec<u128>,
    outcomes: Vec<Option<Search>>,
}
impl Observation {
    fn setup_elapsed(&self) -> u128 {
        self.setup_observations.iter().sum()
    }

    fn search_elapsed(&self) -> u128 {
        self.outcomes.iter().flatten().map(|s| s.elapsed).sum()
    }
}

fn observe(
    material: &Material,
    plan: SearchPlan,
    strategy: Strategy,
    mode: Mode,
) -> Result<Observation, WorkError> {
    observe_with(material, plan, strategy, mode, || {
        prepare(material, strategy)
    })
}

// The injected constructor makes the actual constructor count testable. The
// measured production path calls exactly the same closure and cohort loop.
fn observe_with<'a>(
    material: &'a Material,
    plan: SearchPlan,
    strategy: Strategy,
    mode: Mode,
    mut constructor: impl FnMut() -> Result<Producer<'a>, WorkError>,
) -> Result<Observation, WorkError> {
    let mut setups = Vec::new();
    let mut measured_prepare = || {
        if strategy == Strategy::Scalar {
            return Ok(Producer::Scalar(material));
        }
        let start = Instant::now();
        let result = constructor();
        setups.push(start.elapsed().as_nanos());
        result
    };
    let reused = if mode == Mode::Reused {
        Some(measured_prepare()?)
    } else {
        None
    };
    let mut method = None;
    let mut outcomes = Vec::with_capacity(plan.searches as usize);
    for search_index in 0..plan.searches {
        let cold;
        let producer = match &reused {
            Some(producer) => producer,
            None => {
                cold = measured_prepare()?;
                &cold
            }
        };
        if let Some(previous) = method {
            assert_eq!(previous, producer.method());
        }
        method = Some(producer.method());
        outcomes.push(if matches!(producer, Producer::Unsupported) {
            None
        } else {
            Some(search(plan, search_index, |challenge| {
                producer.prove(challenge)
            })?)
        });
    }
    Ok(Observation {
        strategy,
        method: method.expect("options require at least one search"),
        mode,
        setup_observations: setups,
        outcomes,
    })
}

fn assert_same_outcomes(baseline: &Observation, observation: &Observation) {
    assert_eq!(baseline.outcomes.len(), observation.outcomes.len());
    for (expected, observed) in baseline.outcomes.iter().zip(&observation.outcomes) {
        if let Some(observed) = observed {
            let expected = expected.as_ref().expect("scalar baseline is supported");
            assert_eq!(observed.attempts, expected.attempts);
            assert_eq!(observed.ticket_stream, expected.ticket_stream);
            assert_eq!(observed.proof_stream, expected.proof_stream);
            // Compare the entire winner, not only a digest or the ticket.
            assert_eq!(observed.winning, expected.winning);
        }
    }
}

fn verifier_times(
    challenge: Hash,
    plan: SearchPlan,
    proof: &[u8],
    reference_first: bool,
) -> Result<(u128, u128), WorkError> {
    let production = || -> Result<u128, WorkError> {
        let start = Instant::now();
        black_box(verify(challenge, plan.task, plan.target, proof)?);
        Ok(start.elapsed().as_nanos())
    };
    let reference = || -> Result<u128, WorkError> {
        let start = Instant::now();
        black_box(verify_reference(challenge, plan.task, plan.target, proof)?);
        Ok(start.elapsed().as_nanos())
    };
    if reference_first {
        let reference_ns = reference()?;
        Ok((production()?, reference_ns))
    } else {
        let production_ns = production()?;
        Ok((production_ns, reference()?))
    }
}

fn outcome_json(
    search_index: usize,
    searched: &Option<Search>,
    plan: SearchPlan,
) -> Result<String, WorkError> {
    let Some(searched) = searched else {
        return Ok(format!("{{\"search_index\":{search_index},\"status\":\"unsupported\",\"attempts\":0,\"search_elapsed_ns\":0,\"ticket_stream_commitment\":null,\"proof_stream_commitment\":null,\"winning_challenge\":null,\"winner_proof_commitment\":null,\"production_verifier_elapsed_ns\":null,\"reference_verifier_elapsed_ns\":null,\"reference_verifier_first\":null}}"));
    };
    let mut json = format!("{{\"search_index\":{search_index},\"status\":\"{}\",\"attempts\":{},\"search_elapsed_ns\":{},\"ticket_stream_commitment\":\"{}\",\"proof_stream_commitment\":\"{}\"", if searched.winning.is_some() { "winner" } else { "exhausted" }, searched.attempts, searched.elapsed, hex::encode(searched.ticket_stream), hex::encode(searched.proof_stream));
    match &searched.winning {
        Some((challenge, proof)) => {
            let reference_first = (plan.sample + search_index as u64).is_multiple_of(2);
            let (production, reference) = verifier_times(*challenge, plan, proof, reference_first)?;
            write!(json, ",\"winning_challenge\":\"{}\",\"winner_proof_commitment\":\"{}\",\"production_verifier_elapsed_ns\":{production},\"reference_verifier_elapsed_ns\":{reference},\"reference_verifier_first\":{reference_first}", hex::encode(challenge), hex::encode(hash(b"reused-cost-winner-v1", &[proof]))).unwrap();
        }
        None => json.push_str(",\"winning_challenge\":null,\"winner_proof_commitment\":null,\"production_verifier_elapsed_ns\":null,\"reference_verifier_elapsed_ns\":null,\"reference_verifier_first\":null"),
    }
    json.push('}');
    Ok(json)
}

fn observation_json(
    material: &Material,
    ranks: (usize, usize),
    plan: SearchPlan,
    invocation_order: usize,
    row: &Observation,
) -> Result<String, WorkError> {
    let setup = row.setup_elapsed();
    let search = row.search_elapsed();
    let mut json = format!("{{\"class\":\"{}\",\"input_source\":\"{}\",\"task\":\"{}\",\"rank_a\":{},\"rank_b\":{},\"target\":\"{}\",\"sample\":{},\"invocation_order\":{invocation_order},\"strategy\":\"{}\",\"method\":\"{}\",\"mode\":\"{}\",\"proof_bytes\":{PROOF_BYTES},\"setup_observations_ns\":{:?},\"setup_calls\":{},\"setup_elapsed_ns\":{setup},\"search_elapsed_ns\":{search},\"total_elapsed_ns\":{},\"outcomes\":[", material.name, material.source, hex::encode(plan.task), ranks.0, ranks.1, hex::encode(plan.target), plan.sample, row.strategy.name(), row.method, row.mode.name(), row.setup_observations, row.setup_observations.len(), setup + search);
    for (search_index, outcome) in row.outcomes.iter().enumerate() {
        if search_index != 0 {
            json.push(',');
        }
        json.push_str(&outcome_json(search_index, outcome, plan)?);
    }
    json.push_str("]}");
    Ok(json)
}

fn targets() -> [Hash; 2] {
    let mut targets = [[255; 32]; 2];
    targets[0][0] = 127;
    targets[1][0] = 7;
    targets
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = Options::parse(env::args_os().skip(1))?;
    let materials = materials(options.model.as_deref(), options.input.as_deref())?;
    let targets = targets();
    print!("{{\"schema\":\"pon-w1-reused-search-v1\",\"targets\":[\"{}\",\"{}\"],\"seed\":{},\"samples_per_case_target\":{},\"searches_per_cohort\":{},\"attempt_budget\":{},\"timing\":\"monotonic-wall-elapsed-nanoseconds-not-cpu-accounting\",\"timing_scope\":{{\"actual_setup_per_mode\":true,\"all_attempts_including_target_misses\":true,\"challenge_ticket_and_full_proof_stream_hashing_in_search\":true,\"material_generation_rank_checks_and_cross_strategy_comparison_timed\":false,\"verifier_timing_after_generation\":true}},\"observations\":[", hex::encode(targets[0]), hex::encode(targets[1]), options.seed, options.samples, options.searches, options.attempts);
    let mut first = true;
    for material in materials {
        let task = task_id(&material.a, &material.b).map_err(work_error)?;
        let ranks = (rank(&material.a), rank(&material.b));
        for target in targets {
            for sample in 0..options.samples {
                let plan = SearchPlan {
                    task,
                    target,
                    seed: options.seed,
                    sample,
                    searches: options.searches,
                    budget: options.attempts,
                };
                let mut observations = Vec::with_capacity(10);
                // Rotate all ten invocations, including mode order, by sample.
                for offset in 0..10 {
                    let invocation = (sample as usize + offset) % 10;
                    let strategy = Strategy::ALL[invocation / 2];
                    let mode = if invocation.is_multiple_of(2) {
                        Mode::Cold
                    } else {
                        Mode::Reused
                    };
                    observations
                        .push(observe(&material, plan, strategy, mode).map_err(work_error)?);
                }
                let baseline = observations
                    .iter()
                    .find(|row| row.strategy == Strategy::Scalar && row.mode == Mode::Cold)
                    .expect("rotation includes the scalar cold baseline");
                for row in &observations {
                    assert_same_outcomes(baseline, row);
                }
                // Both verifiers run only after every strategy/mode completed
                // generation for this sample. Their cost is reported separately.
                for (order, row) in observations.iter().enumerate() {
                    let json =
                        observation_json(&material, ranks, plan, order, row).map_err(work_error)?;
                    if !first {
                        print!(",");
                    }
                    first = false;
                    print!("{json}");
                }
            }
        }
    }
    println!("],\"fastest_adversary_qualified\":false,\"work_hardness_accepted\":false,\"public_service_measured\":false,\"input_provenance_verified\":false,\"production_activation\":false}}");
    Ok(())
}

fn work_error(error: WorkError) -> String {
    format!("W1 generation or verification failed: {error:?}")
}

fn main() -> Result<(), Box<dyn Error>> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn fixture() -> Material {
        Material {
            name: "zero",
            source: "synthetic-fixture",
            a: vec![0; CELLS],
            b: vec![0; CELLS],
        }
    }

    fn plan(material: &Material) -> SearchPlan {
        SearchPlan {
            task: task_id(&material.a, &material.b).unwrap(),
            target: [255; 32],
            seed: 17,
            sample: 2,
            searches: 2,
            budget: 2,
        }
    }

    #[test]
    fn actual_constructor_calls_and_all_winners_match_in_both_modes() {
        let material = fixture();
        let plan = plan(&material);
        let baseline = observe(&material, plan, Strategy::Scalar, Mode::Cold).unwrap();
        for strategy in Strategy::ALL {
            for mode in [Mode::Cold, Mode::Reused] {
                let calls = Cell::new(0);
                let observation = observe_with(&material, plan, strategy, mode, || {
                    calls.set(calls.get() + 1);
                    prepare(&material, strategy)
                })
                .unwrap();
                let expected = match (strategy, mode) {
                    (Strategy::Scalar, _) => 0,
                    (_, Mode::Cold) => plan.searches as usize,
                    (_, Mode::Reused) => 1,
                };
                assert_eq!(calls.get(), expected);
                assert_eq!(observation.setup_observations.len(), expected);
                assert_eq!(observation.outcomes.len(), plan.searches as usize);
                assert_same_outcomes(&baseline, &observation);
                for outcome in observation.outcomes.iter().flatten() {
                    let (challenge, proof) = outcome.winning.as_ref().unwrap();
                    assert_eq!(outcome.attempts, 1);
                    verify(*challenge, plan.task, plan.target, proof).unwrap();
                    verify_reference(*challenge, plan.task, plan.target, proof).unwrap();
                }
            }
        }
        assert_ne!(
            baseline.outcomes[0].as_ref().unwrap().winning,
            baseline.outcomes[1].as_ref().unwrap().winning
        );
    }

    #[test]
    fn exhaustion_retains_every_attempt_and_complete_proof_stream() {
        let material = fixture();
        let mut plan = plan(&material);
        plan.target = [0; 32];
        plan.target[31] = 1;
        let baseline = observe(&material, plan, Strategy::Scalar, Mode::Cold).unwrap();
        for strategy in Strategy::ALL {
            for mode in [Mode::Cold, Mode::Reused] {
                let row = observe(&material, plan, strategy, mode).unwrap();
                assert_same_outcomes(&baseline, &row);
                for (index, outcome) in row.outcomes.iter().enumerate() {
                    let searched = outcome.as_ref().unwrap();
                    assert_eq!(searched.attempts, plan.budget);
                    assert!(searched.winning.is_none());
                    let json = outcome_json(index, outcome, plan).unwrap();
                    assert!(json.contains("\"status\":\"exhausted\""));
                    assert!(json.contains("\"winner_proof_commitment\":null"));
                    assert!(json.contains("\"production_verifier_elapsed_ns\":null"));
                    assert!(json.contains("\"reference_verifier_elapsed_ns\":null"));
                }
                assert_eq!(
                    row.search_elapsed(),
                    row.outcomes
                        .iter()
                        .flatten()
                        .map(|s| s.elapsed)
                        .sum::<u128>()
                );
            }
        }

        // Retain a tiny test-only trace to compare every full proof, including
        // target misses. Production retains only streaming hashes and winners.
        let mut scalar_trace = Vec::new();
        let scalar = search(plan, 0, |challenge| {
            let proof = prove(challenge, &material.a, &material.b)?;
            scalar_trace.push((challenge, proof.clone()));
            Ok(proof)
        })
        .unwrap();
        for strategy in Strategy::ALL {
            let producer = prepare(&material, strategy).unwrap();
            let mut index = 0;
            let alternative = search(plan, 0, |challenge| {
                let proof = producer.prove(challenge)?;
                assert_eq!(
                    (challenge, &proof),
                    (scalar_trace[index].0, &scalar_trace[index].1)
                );
                index += 1;
                Ok(proof)
            })
            .unwrap();
            assert_eq!(index, plan.budget as usize);
            assert_eq!(alternative.proof_stream, scalar.proof_stream);
            assert_eq!(alternative.ticket_stream, scalar.ticket_stream);
        }
        // Alter an early proof byte without altering its trace/ticket. This must
        // change the full-proof commitment even though all ticket bytes agree.
        let producer = prepare(&material, Strategy::Structured).unwrap();
        let modified = search(plan, 0, |challenge| {
            let mut proof = producer.prove(challenge)?;
            proof[4] ^= 1;
            Ok(proof)
        })
        .unwrap();
        assert_eq!(scalar.ticket_stream, modified.ticket_stream);
        assert_ne!(scalar.proof_stream, modified.proof_stream);
    }

    #[test]
    fn unsupported_structured_retains_real_setup_count_and_outcomes() {
        let mut material = fixture();
        material.a = (0..CELLS).map(|i| (i % 31) as u32).collect();
        material.b = (0..CELLS).map(|i| ((i * 7) % 37) as u32).collect();
        let plan = plan(&material);
        for mode in [Mode::Cold, Mode::Reused] {
            let row = observe(&material, plan, Strategy::Structured, mode).unwrap();
            assert_eq!(row.method, "unsupported");
            assert_eq!(row.outcomes.len(), plan.searches as usize);
            assert!(row.outcomes.iter().all(Option::is_none));
            assert_eq!(row.search_elapsed(), 0);
            assert_eq!(
                row.setup_observations.len(),
                if mode == Mode::Cold { 2 } else { 1 }
            );
        }
    }

    #[test]
    fn options_enforce_bounds_pairing_and_unambiguous_flags() {
        let parse = |arguments: &[&str]| Options::parse(arguments.iter().map(OsString::from));
        let defaults = parse(&[]).unwrap();
        assert_eq!(
            (
                defaults.samples,
                defaults.searches,
                defaults.attempts,
                defaults.seed
            ),
            (4, 4, 256, 0)
        );
        assert!(parse(&[
            "--samples",
            "32",
            "--searches",
            "32",
            "--attempt-budget",
            "4096",
            "--seed",
            "18446744073709551615"
        ])
        .is_ok());
        for arguments in [
            vec!["--samples", "0"],
            vec!["--samples", "33"],
            vec!["--searches", "0"],
            vec!["--searches", "33"],
            vec!["--attempt-budget", "0"],
            vec!["--attempt-budget", "4097"],
            vec!["--seed", "-1"],
            vec!["--seed", "18446744073709551616"],
            vec!["--model", "a"],
            vec!["--input", "b"],
            vec!["--samples"],
            vec!["--samples", "1", "--samples", "1"],
            vec!["--unknown", "1"],
        ] {
            assert!(parse(&arguments).is_err(), "accepted {arguments:?}");
        }
    }

    #[test]
    fn constructors_and_search_reject_invalid_material_or_proof_lengths() {
        let mut material = fixture();
        material.a.pop();
        for strategy in Strategy::ALL.into_iter().filter(|s| *s != Strategy::Scalar) {
            assert!(matches!(
                prepare(&material, strategy),
                Err(WorkError::Length)
            ));
        }
        let mut material = fixture();
        material.b[0] = Q as u32;
        for strategy in Strategy::ALL.into_iter().filter(|s| *s != Strategy::Scalar) {
            assert!(matches!(
                prepare(&material, strategy),
                Err(WorkError::Field)
            ));
        }
        let material = fixture();
        assert!(matches!(
            search(plan(&material), 0, |_| Ok(vec![])),
            Err(WorkError::Length)
        ));
    }
}
