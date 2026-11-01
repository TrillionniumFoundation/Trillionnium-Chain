#[allow(dead_code)]
mod pon_work;

use pon_work::arithmetic_facts::{
    ArithmeticFactCache, ArithmeticObservation, ArithmeticPublication, FactError,
};
use pon_work::{Hash, VerifiedWork, WorkError, CELLS, PROOF_BYTES, Q};
use rustix::time::{clock_gettime, ClockId};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{convert::Infallible, time::Instant};

const CALLS: usize = 128;
const SEEDS: [u64; 3] = [7, 19, 43];
type Outcome = Result<VerifiedWork, FactError<Infallible>>;

fn cpu_ns() -> u64 {
    let now = clock_gettime(ClockId::ThreadCPUTime);
    u64::try_from(now.tv_sec)
        .unwrap()
        .checked_mul(1_000_000_000)
        .unwrap()
        + u64::try_from(now.tv_nsec).unwrap()
}

struct Clock {
    cpu: u64,
    wall: Instant,
}
impl Clock {
    fn start() -> Self {
        Self {
            cpu: cpu_ns(),
            wall: Instant::now(),
        }
    }
    fn end(self) -> (u64, u128) {
        (
            cpu_ns().checked_sub(self.cpu).unwrap(),
            self.wall.elapsed().as_nanos(),
        )
    }
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

struct Fixture {
    challenge: Hash,
    task: Hash,
    target: Hash,
    valid: Vec<u8>,
    false_trace: Vec<u8>,
    last_product: Vec<u8>,
    expected_product: Vec<u32>,
    ticket: Hash,
}

fn fixture(seed: u64, variant: u64) -> Fixture {
    let matrix = |label: u8| -> Vec<u32> {
        (0..CELLS)
            .map(|index| {
                let bytes = pon_work::hash(
                    b"cache-benchmark-material-v1",
                    &[&seed.to_le_bytes(), &[label], &(index as u64).to_le_bytes()],
                );
                (u128::from(u32::from_le_bytes(bytes[..4].try_into().unwrap())) % Q) as u32
            })
            .collect()
    };
    let a = matrix(0);
    let b = matrix(1);
    let task = pon_work::task_id(&a, &b).unwrap();
    let challenge = pon_work::hash(
        b"cache-benchmark-challenge-v1",
        &[&seed.to_le_bytes(), &variant.to_le_bytes()],
    );
    // An explicitly easy diagnostic target. No search or attacker lower-bound
    // interpretation: the fixture is fully constructed outside call timing.
    let target = [255; 32];
    let valid = pon_work::prove(challenge, &a, &b).unwrap();
    let reference = pon_work::verify_reference(challenge, task, target, &valid).unwrap();
    let mut false_trace = valid.clone();
    false_trace[PROOF_BYTES - 1] ^= 1;
    let mut last_product = valid.clone();
    let last = 4 + 3 * CELLS * 4 - 4;
    let value = u32::from_le_bytes(last_product[last..last + 4].try_into().unwrap());
    last_product[last..last + 4].copy_from_slice(&((u128::from(value) + 1) % Q).to_le_bytes()[..4]);
    assert_eq!(
        pon_work::verify_reference(challenge, task, target, &false_trace).unwrap_err(),
        WorkError::Transcript,
    );
    assert_eq!(
        pon_work::verify_reference(challenge, task, target, &last_product).unwrap_err(),
        WorkError::Product,
    );
    Fixture {
        challenge,
        task,
        target,
        valid,
        false_trace,
        last_product,
        expected_product: reference.product().to_vec(),
        ticket: reference.ticket(),
    }
}

#[derive(Clone, Copy)]
enum Case {
    ColdValid,
    ColdFalseTrace,
    ColdLastProduct,
    WarmValid,
    WarmFalseTrace,
    WarmLastProduct,
    TraceUpgrade,
    AlternatingChallengeEviction,
}
impl Case {
    fn name(self) -> &'static str {
        match self {
            Self::ColdValid => "cold_valid",
            Self::ColdFalseTrace => "cold_false_trace",
            Self::ColdLastProduct => "cold_last_product",
            Self::WarmValid => "warm_valid",
            Self::WarmFalseTrace => "warm_false_trace",
            Self::WarmLastProduct => "warm_last_product",
            Self::TraceUpgrade => "trace_only_upgrade",
            Self::AlternatingChallengeEviction => "capacity1_alternating_challenge_eviction",
        }
    }
    fn error(self) -> Option<WorkError> {
        match self {
            Self::ColdFalseTrace | Self::WarmFalseTrace => Some(WorkError::Transcript),
            Self::ColdLastProduct | Self::WarmLastProduct => Some(WorkError::Product),
            _ => None,
        }
    }
    fn proof(self, fixture: &Fixture) -> &[u8] {
        match self {
            Self::ColdFalseTrace | Self::WarmFalseTrace => &fixture.false_trace,
            Self::ColdLastProduct | Self::WarmLastProduct => &fixture.last_product,
            _ => &fixture.valid,
        }
    }
    fn cold_slot(self) -> bool {
        matches!(
            self,
            Self::ColdValid | Self::ColdFalseTrace | Self::ColdLastProduct | Self::TraceUpgrade
        )
    }
    fn prefill(self) -> Option<bool> {
        match self {
            Self::WarmValid | Self::WarmLastProduct => Some(false),
            Self::WarmFalseTrace | Self::TraceUpgrade => Some(true),
            _ => None,
        }
    }
}

fn check_result(result: Outcome, fixture: &Fixture, expected: Option<WorkError>) {
    match (result, expected) {
        (Ok(value), None) => {
            assert_eq!(value.challenge(), fixture.challenge);
            assert_eq!(value.task(), fixture.task);
            assert_eq!(value.ticket(), fixture.ticket);
            assert_eq!(value.product(), fixture.expected_product.as_slice());
        }
        (Err(FactError::Relation(actual)), Some(expected)) => assert_eq!(actual, expected),
        (actual, expected) => panic!("semantic mismatch: actual={actual:?}, expected={expected:?}"),
    }
}

fn check_observation(observation: &ArithmeticObservation, case: Case) {
    assert!(!observation.lookup_contended);
    match case {
        Case::WarmValid | Case::WarmLastProduct => {
            assert!(
                observation.exact_fact_found
                    && observation.trace_reused
                    && observation.product_reused
            );
            assert!(!observation.transcript_entered && !observation.product_entered);
        }
        Case::WarmFalseTrace => {
            assert!(observation.exact_fact_found && observation.trace_reused);
            assert!(!observation.product_reused && !observation.transcript_entered);
        }
        Case::ColdFalseTrace => {
            assert!(!observation.exact_fact_found && observation.transcript_completed);
            assert!(!observation.product_entered);
            assert_eq!(observation.publication, ArithmeticPublication::Trace);
        }
        Case::TraceUpgrade => {
            assert!(
                observation.exact_fact_found
                    && observation.transcript_completed
                    && observation.product_completed
            );
            assert!(!observation.trace_reused && !observation.product_reused);
            assert_eq!(observation.publication, ArithmeticPublication::Product);
        }
        Case::ColdValid | Case::ColdLastProduct | Case::AlternatingChallengeEviction => {
            assert!(
                !observation.exact_fact_found
                    && observation.transcript_completed
                    && observation.product_completed
            );
            assert_eq!(observation.publication, ArithmeticPublication::Product);
        }
    }
}

fn run_case(variant: &str, round: u64, seed: u64, case: Case, fixtures: &[Fixture; 2]) {
    let setup = Clock::start();
    let cache_count = if case.cold_slot() { CALLS } else { 1 };
    let caches: Vec<_> = (0..cache_count)
        .map(|_| ArithmeticFactCache::new(1).unwrap())
        .collect();
    let mut prefill_calls = 0;
    if let Some(false_trace) = case.prefill() {
        for cache in &caches {
            let fixture = &fixtures[0];
            let proof = if false_trace {
                &fixture.false_trace
            } else {
                &fixture.valid
            };
            let result = cache.verify(fixture.challenge, fixture.task, fixture.target, proof);
            check_result(
                result,
                fixture,
                false_trace.then_some(WorkError::Transcript),
            );
            prefill_calls += 1;
        }
    }
    let software_bytes_per_cache = caches[0].software_bytes();
    let mut captures = Vec::with_capacity(CALLS);
    let (setup_cpu_ns, setup_wall_ns) = setup.end();
    let timer = Clock::start();
    for call in 0..CALLS {
        let fixture_index = if matches!(case, Case::AlternatingChallengeEviction) {
            call % 2
        } else {
            0
        };
        let fixture = &fixtures[fixture_index];
        let cache_index = if case.cold_slot() { call } else { 0 };
        let mut observation = ArithmeticObservation::default();
        let result = caches[cache_index].verify_with_observation(
            fixture.challenge,
            fixture.task,
            fixture.target,
            case.proof(fixture),
            &mut |_| Ok::<(), Infallible>(()),
            &mut observation,
        );
        captures.push((fixture_index, result, observation));
    }
    let (call_cpu_ns, call_wall_ns) = timer.end();
    // All complete values, exact error variants and actual cache paths are
    // checked after timing. Retaining outcomes is identical in both binaries.
    let mut transcript_replays = 0;
    let mut products = 0;
    let mut trace_hits = 0;
    let mut product_hits = 0;
    for (fixture_index, result, observation) in captures {
        check_result(result, &fixtures[fixture_index], case.error());
        check_observation(&observation, case);
        transcript_replays += usize::from(observation.transcript_completed);
        products += usize::from(observation.product_completed);
        trace_hits += usize::from(observation.trace_reused);
        product_hits += usize::from(observation.product_reused);
    }
    println!(
        "{}",
        json!({
            "schema":"pon-arithmetic-cache-selected-source-diagnostic-v1", "kind":"measurement",
            "variant":variant, "round":round, "seed":seed, "case":case.name(), "calls":CALLS,
            "setup_cpu_ns":setup_cpu_ns, "setup_wall_ns":setup_wall_ns,
            "prefill_calls":prefill_calls, "cache_count":cache_count, "capacity":1,
            "software_bytes_per_cache":software_bytes_per_cache,
            "call_cpu_ns":call_cpu_ns, "call_wall_ns":call_wall_ns,
            "transcript_replays":transcript_replays, "products_completed":products,
            "trace_reused":trace_hits, "product_reused":product_hits,
            "all_results_and_paths_checked":true,
            "fixture_and_cache_setup_excluded_from_call_timing":true,
            "timed_scope":"single-thread verify_with_observation plus fixed loop and preallocated outcome retention; result checks and JSON excluded",
            "attacker_cost_measurement":false, "whole_workspace_qualified":false,
            "host_qualified":false, "public_service_qualified":false,
        })
    );
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: cache-benchmark baseline|candidate round"
    );
    let variant = &args[1];
    assert!(matches!(variant.as_str(), "baseline" | "candidate"));
    let round: u64 = args[2].parse().unwrap();
    println!(
        "{}",
        json!({"kind":"configuration", "schema":"pon-arithmetic-cache-selected-source-diagnostic-v1",
        "variant":variant, "round":round, "calls_per_case":CALLS, "seeds":SEEDS,
        "clock":"rustix::time::clock_gettime(ClockId::ThreadCPUTime)",
        "target":hex::encode([255_u8;32]), "matrix_class":"deterministic dense field elements",
        "eviction_scope":"two distinct challenges alternate in one capacity-1 cache; each is absent at entry, not globally unique challenge samples",
        "fixture_setup_is_not_attacker_cost":true})
    );
    for seed in SEEDS {
        let setup = Clock::start();
        let fixtures = [fixture(seed, 0), fixture(seed, 1)];
        assert_eq!(fixtures[0].task, fixtures[1].task);
        assert_ne!(fixtures[0].challenge, fixtures[1].challenge);
        let (cpu, wall) = setup.end();
        for (index, fixture) in fixtures.iter().enumerate() {
            let product: Vec<_> = fixture
                .expected_product
                .iter()
                .flat_map(|v| v.to_le_bytes())
                .collect();
            println!(
                "{}",
                json!({"kind":"fixture", "variant":variant, "round":round, "seed":seed, "index":index,
                "challenge":hex::encode(fixture.challenge), "task":hex::encode(fixture.task),
                "valid_sha256":sha(&fixture.valid), "false_trace_sha256":sha(&fixture.false_trace),
                "last_product_sha256":sha(&fixture.last_product), "expected_product_sha256":sha(&product),
                "paired_fixture_setup_cpu_ns":cpu, "paired_fixture_setup_wall_ns":wall,
                "pair_interval_repeated_for_identity_only_do_not_sum":true,
                "reference_checks":"full reference verifier, valid and both exact invalid variants"})
            );
        }
        for case in [
            Case::ColdValid,
            Case::ColdFalseTrace,
            Case::ColdLastProduct,
            Case::WarmValid,
            Case::WarmFalseTrace,
            Case::WarmLastProduct,
            Case::TraceUpgrade,
            Case::AlternatingChallengeEviction,
        ] {
            run_case(variant, round, seed, case, &fixtures);
        }
    }
}
