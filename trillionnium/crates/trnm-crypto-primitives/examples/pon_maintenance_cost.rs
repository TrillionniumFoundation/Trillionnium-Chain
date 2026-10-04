//! Fixed genesis-maintenance paired-product comparison with actual cold/reused setup.
//! Every target miss and full-proof stream hash remains timed. These measurements
//! are wall observations, not a cheapest-producer bound or native mining change.
use sha2::{Digest, Sha256};
use std::{env, error::Error, ffi::OsString, fmt::Write, hint::black_box, time::Instant};
use trnm_crypto_primitives::pon_work::{
    paired_product::PairedPreparedTask,
    structured::{TileKernel, TiledPreparedTask},
    *,
};

const TICKET_STREAM_DOMAIN: &[u8] = b"TRNM-PON-W1-MAINTENANCE-PAIRED-TICKET-STREAM1\0";
const PROOF_STREAM_DOMAIN: &[u8] = b"TRNM-PON-W1-MAINTENANCE-PAIRED-PROOF-STREAM1\0";

struct Material {
    name: &'static str,
    source: &'static str,
    a: Vec<u32>,
    b: Vec<u32>,
}
impl Material {
    fn maintenance() -> Self {
        Self {
            name: "continuity-maintenance-v1",
            source: "genesis-policy-public-deterministic-fixture",
            a: (0..CELLS).map(|i| ((13 * i + 17) % 257) as u32).collect(),
            b: (0..CELLS).map(|i| ((29 * i + 31) % 263) as u32).collect(),
        }
    }
}

// Classification is outside the measured producer constructor. Use ordinary field
// elimination rather than trusting the fixture label or the producer's detector.
fn rank(matrix: &[u32]) -> usize {
    let multiply = |a: u32, b: u32| (u128::from(a) * u128::from(b) % Q) as u32;
    let mut rows: Vec<_> = matrix.chunks_exact(N).map(<[u32]>::to_vec).collect();
    let mut rank = 0;
    for column in 0..N {
        let Some(pivot) = (rank..N).find(|row| rows[*row][column] != 0) else {
            continue;
        };
        rows.swap(rank, pivot);
        let mut power = rows[rank][column];
        let mut inverse = 1;
        let mut exponent = Q - 2;
        while exponent != 0 {
            if exponent & 1 != 0 {
                inverse = multiply(inverse, power);
            }
            power = multiply(power, power);
            exponent >>= 1;
        }
        for value in &mut rows[rank][column..] {
            *value = multiply(*value, inverse);
        }
        let pivot_row = rows[rank].clone();
        for row in rows.iter_mut().skip(rank + 1) {
            let scale = row[column];
            for index in column..N {
                row[index] = ((u128::from(row[index]) + Q
                    - u128::from(multiply(scale, pivot_row[index])))
                    % Q) as u32;
            }
        }
        rank += 1;
    }
    rank
}

#[derive(Debug)]
struct Options {
    samples: u64,
    searches: u64,
    attempts: u64,
    seed: u64,
}
impl Options {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, Box<dyn Error>> {
        let mut options = Self {
            samples: 4,
            searches: 4,
            attempts: 256,
            seed: 0,
        };
        let mut seen = [false; 4];
        let mut arguments = arguments.into_iter();
        while let Some(flag) = arguments.next() {
            let index = match flag.to_str() {
                Some("--samples") => 0,
                Some("--searches") => 1,
                Some("--attempt-budget") => 2,
                Some("--seed") => 3,
                _ => {
                    return Err("expected --samples, --searches, --attempt-budget or --seed".into())
                }
            };
            if seen[index] {
                return Err("duplicate option".into());
            }
            seen[index] = true;
            let value = arguments.next().ok_or("each flag requires a value")?;
            let number: u64 = value.to_str().ok_or("numeric option encoding")?.parse()?;
            match index {
                0 => options.samples = number,
                1 => options.searches = number,
                2 => options.attempts = number,
                _ => options.seed = number,
            }
        }
        if !(1..=32).contains(&options.samples)
            || !(1..=32).contains(&options.searches)
            || !(1..=4096).contains(&options.attempts)
        {
            return Err("1..32 samples, 1..32 searches and 1..4096 attempts are required".into());
        }
        Ok(options)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Strategy {
    Generic,
    Classical,
    Strassen,
    Paired,
}
impl Strategy {
    const ALL: [Self; 4] = [Self::Generic, Self::Classical, Self::Strassen, Self::Paired];
    fn name(self) -> &'static str {
        match self {
            Self::Generic => "prepared-generic",
            Self::Classical => "tiled-classical",
            Self::Strassen => "tiled-strassen-one-level",
            Self::Paired => "paired-product",
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

enum Producer {
    Generic(PreparedTask),
    Tiled(TiledPreparedTask),
    Paired(PairedPreparedTask),
}
impl Producer {
    fn method(&self) -> &'static str {
        match self {
            Self::Generic(_) => "generic-product-and-transcript",
            Self::Tiled(task) => task.method(),
            Self::Paired(task) => task.method(),
        }
    }
    fn prove(&self, challenge: Hash) -> Result<Vec<u8>, WorkError> {
        match self {
            Self::Generic(task) => task.prove(challenge),
            Self::Tiled(task) => task.prove(challenge),
            Self::Paired(task) => task.prove(challenge),
        }
    }
}
fn prepare(material: &Material, strategy: Strategy) -> Result<Producer, WorkError> {
    // Every strategy validates both complete operands and computes its own fixed
    // product in the timed constructor. There is no supplied product or fallback.
    match strategy {
        Strategy::Generic => Ok(Producer::Generic(PreparedTask::new(
            &material.a,
            &material.b,
        )?)),
        Strategy::Classical | Strategy::Strassen => Ok(Producer::Tiled(TiledPreparedTask::new(
            &material.a,
            &material.b,
            if strategy == Strategy::Classical {
                TileKernel::Classical
            } else {
                TileKernel::StrassenOneLevel
            },
        )?)),
        Strategy::Paired => Ok(Producer::Paired(PairedPreparedTask::new(
            &material.a,
            &material.b,
        )?)),
    }
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
            b"maintenance-paired-cost-v1",
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
    outcomes: Vec<Search>,
}
impl Observation {
    fn setup_elapsed(&self) -> u128 {
        self.setup_observations.iter().sum()
    }

    fn search_elapsed(&self) -> u128 {
        self.outcomes.iter().map(|s| s.elapsed).sum()
    }
}

fn observe(
    material: &Material,
    plan: SearchPlan,
    strategy: Strategy,
    mode: Mode,
) -> Result<Observation, WorkError> {
    observe_with(plan, strategy, mode, || prepare(material, strategy))
}

// Tests count actual constructor invocations through the same measured path.
fn observe_with(
    plan: SearchPlan,
    strategy: Strategy,
    mode: Mode,
    mut constructor: impl FnMut() -> Result<Producer, WorkError>,
) -> Result<Observation, WorkError> {
    let mut setups = Vec::new();
    let mut measured_prepare = || {
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
        outcomes.push(search(plan, search_index, |challenge| {
            producer.prove(challenge)
        })?);
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
        assert_eq!(observed.attempts, expected.attempts);
        assert_eq!(observed.ticket_stream, expected.ticket_stream);
        assert_eq!(observed.proof_stream, expected.proof_stream);
        assert_eq!(observed.winning, expected.winning);
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
    searched: &Search,
    plan: SearchPlan,
) -> Result<String, WorkError> {
    let mut json = format!("{{\"search_index\":{search_index},\"status\":\"{}\",\"attempts\":{},\"search_elapsed_ns\":{},\"ticket_stream_commitment\":\"{}\",\"proof_stream_commitment\":\"{}\"", if searched.winning.is_some() { "winner" } else { "exhausted" }, searched.attempts, searched.elapsed, hex::encode(searched.ticket_stream), hex::encode(searched.proof_stream));
    match &searched.winning {
        Some((challenge, proof)) => {
            let reference_first = (plan.sample + search_index as u64).is_multiple_of(2);
            let (production, reference) = verifier_times(*challenge, plan, proof, reference_first)?;
            write!(json, ",\"winning_challenge\":\"{}\",\"winner_proof_commitment\":\"{}\",\"production_verifier_elapsed_ns\":{production},\"reference_verifier_elapsed_ns\":{reference},\"reference_verifier_first\":{reference_first}", hex::encode(challenge), hex::encode(hash(b"maintenance-paired-cost-winner-v1", &[proof]))).unwrap();
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

// Adjacent samples execute the same rotated sequence forwards and backwards.
// Every arm has mean position 3.5 in each complete pair, including the fixed
// two/four-sample campaigns. This is no control of all cache or thermal effects.
fn invocation(sample: u64, offset: usize) -> usize {
    let direction = if sample.is_multiple_of(2) {
        offset
    } else {
        7 - offset
    };
    ((sample / 2) as usize + direction) % 8
}

fn run() -> Result<(), Box<dyn Error>> {
    let options = Options::parse(env::args_os().skip(1))?;
    let targets = targets();
    print!("{{\"schema\":\"pon-w1-maintenance-paired-v1\",\"genesis_maintenance_material_only\":true,\"task_profile\":\"consensus-maintenance-continuity-dev-v1\",\"targets\":[\"{}\",\"{}\"],\"seed\":{},\"samples_per_case_target\":{},\"searches_per_cohort\":{},\"attempt_budget\":{},\"timing\":\"monotonic-wall-elapsed-nanoseconds-not-cpu-accounting\",\"timing_scope\":{{\"actual_setup_per_mode\":true,\"all_attempts_including_target_misses\":true,\"challenge_ticket_and_full_proof_stream_hashing_in_search\":true,\"material_generation_rank_checks_and_cross_strategy_comparison_timed\":false,\"verifier_timing_after_generation\":true}},\"observations\":[", hex::encode(targets[0]), hex::encode(targets[1]), options.seed, options.samples, options.searches, options.attempts);
    let mut first = true;
    for material in [Material::maintenance()] {
        let task = task_id(&material.a, &material.b).map_err(work_error)?;
        let ranks = (rank(&material.a), rank(&material.b));
        assert_eq!(ranks, (56, 32));
        assert_eq!(
            hex::encode(task),
            "c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496"
        );
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
                let mut observations = Vec::with_capacity(8);
                for offset in 0..8 {
                    let invocation = invocation(sample, offset);
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
                    .find(|row| row.strategy == Strategy::Generic && row.mode == Mode::Cold)
                    .expect("rotation includes generic cold baseline");
                for row in &observations {
                    assert_same_outcomes(baseline, row);
                }
                // Verify only after all eight generation runs complete. Both verifier
                // costs and output formatting remain outside setup/search timing.
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
    format!("maintenance paired experiment generation or verification failed: {error:?}")
}
fn main() -> Result<(), Box<dyn Error>> {
    run()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

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
    fn exact_maintenance_material_and_observed_ranks_are_bound_to_the_fixed_task() {
        let material = Material::maintenance();
        assert_eq!((rank(&material.a), rank(&material.b)), (56, 32));
        assert_eq!(
            hex::encode(task_id(&material.a, &material.b).unwrap()),
            "c982eea0545c228d0bf48d6d06e623020b4031f2ba79da56cc6bdccde2c63496"
        );
        assert_eq!(
            material.source,
            "genesis-policy-public-deterministic-fixture"
        );
        assert!(material.a.iter().any(|value| *value != 0));
        assert!(material.b.iter().any(|value| *value != 0));
    }

    #[test]
    fn actual_cold_and_reused_setup_counts_and_complete_search_outcomes_agree() {
        let material = Material::maintenance();
        let plan = plan(&material);
        let baseline = observe(&material, plan, Strategy::Generic, Mode::Cold).unwrap();
        for strategy in Strategy::ALL {
            for mode in [Mode::Cold, Mode::Reused] {
                let calls = Cell::new(0);
                let result = observe_with(plan, strategy, mode, || {
                    calls.set(calls.get() + 1);
                    prepare(&material, strategy)
                })
                .unwrap();
                let expected = if mode == Mode::Cold {
                    plan.searches as usize
                } else {
                    1
                };
                assert_eq!(calls.get(), expected);
                assert_eq!(result.setup_observations.len(), expected);
                assert_same_outcomes(&baseline, &result);
                for outcome in &result.outcomes {
                    assert_eq!(outcome.attempts, 1);
                    let (challenge, proof) = outcome.winning.as_ref().unwrap();
                    verify(*challenge, plan.task, plan.target, proof).unwrap();
                    verify_reference(*challenge, plan.task, plan.target, proof).unwrap();
                }
                assert_eq!(
                    result.search_elapsed(),
                    result.outcomes.iter().map(|o| o.elapsed).sum::<u128>()
                );
            }
        }
        assert_ne!(baseline.outcomes[0].winning, baseline.outcomes[1].winning);
    }

    #[test]
    fn exhausted_searches_keep_all_attempts_costs_and_full_proof_streams() {
        let material = Material::maintenance();
        let mut plan = plan(&material);
        plan.target = [0; 32];
        let baseline = observe(&material, plan, Strategy::Generic, Mode::Cold).unwrap();
        for strategy in Strategy::ALL {
            for mode in [Mode::Cold, Mode::Reused] {
                let row = observe(&material, plan, strategy, mode).unwrap();
                assert_same_outcomes(&baseline, &row);
                for (index, outcome) in row.outcomes.iter().enumerate() {
                    assert_eq!(outcome.attempts, plan.budget);
                    assert!(outcome.winning.is_none());
                    let json = outcome_json(index, outcome, plan).unwrap();
                    assert!(json.contains("\"status\":\"exhausted\""));
                    assert!(json.contains("\"winner_proof_commitment\":null"));
                    assert!(json.contains("\"production_verifier_elapsed_ns\":null"));
                    assert!(json.contains("\"reference_verifier_elapsed_ns\":null"));
                }
            }
        }
        // A small retained unit-test trace compares every losing byte array.
        // The cost report retains the complete stream commitment and each winner.
        let mut originals = Vec::new();
        search(plan, 0, |challenge| {
            let proof = prove(challenge, &material.a, &material.b)?;
            originals.push((challenge, proof.clone()));
            Ok(proof)
        })
        .unwrap();
        for strategy in Strategy::ALL {
            let prepared = prepare(&material, strategy).unwrap();
            let mut index = 0;
            search(plan, 0, |challenge| {
                let proof = prepared.prove(challenge)?;
                assert_eq!(
                    (challenge, &proof),
                    (originals[index].0, &originals[index].1)
                );
                index += 1;
                Ok(proof)
            })
            .unwrap();
            assert_eq!(index, plan.budget as usize);
        }
    }

    #[test]
    fn options_and_material_rejection_are_explicit_without_substitutions() {
        let parse = |args: &[&str]| Options::parse(args.iter().map(OsString::from));
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
        for args in [
            vec!["--samples", "0"],
            vec!["--samples", "33"],
            vec!["--searches", "0"],
            vec!["--searches", "33"],
            vec!["--attempt-budget", "0"],
            vec!["--attempt-budget", "4097"],
            vec!["--seed", "-1"],
            vec!["--seed", "18446744073709551616"],
            vec!["--samples"],
            vec!["--samples", "1", "--samples", "1"],
            vec!["--model", "unread"],
            vec!["--input", "unread"],
        ] {
            assert!(parse(&args).is_err(), "accepted {args:?}");
        }
        let mut material = Material::maintenance();
        material.a.pop();
        for strategy in Strategy::ALL {
            assert!(matches!(
                prepare(&material, strategy),
                Err(WorkError::Length)
            ));
        }
        let mut material = Material::maintenance();
        material.b[CELLS - 1] = Q as u32;
        for strategy in Strategy::ALL {
            assert!(matches!(
                prepare(&material, strategy),
                Err(WorkError::Field)
            ));
        }
        let material = Material::maintenance();
        assert!(matches!(
            search(plan(&material), 0, |_| Ok(vec![])),
            Err(WorkError::Length)
        ));
        for first_sample in (0..32).step_by(2) {
            for arm in 0..8 {
                let forward = (0..8)
                    .find(|offset| invocation(first_sample, *offset) == arm)
                    .unwrap();
                let reverse = (0..8)
                    .find(|offset| invocation(first_sample + 1, *offset) == arm)
                    .unwrap();
                assert_eq!(forward + reverse, 7);
            }
        }
    }
}
