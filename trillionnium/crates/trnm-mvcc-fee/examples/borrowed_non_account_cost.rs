//! Standard-allocator wall observation of one non-account root component.
//! Allocation observations run in the separate borrowed_non_account_allocations
//! executable; neither this crate nor its shared support installs an allocator.
#![forbid(unsafe_code)]

#[path = "support/borrowed_non_account_cost.rs"]
mod support;

use serde_json::{json, Value};
use std::time::Instant;
use support::{emit, Arm, Cohort, COHORTS, ORDER, ROUNDS};

fn median(mut values: Vec<f64>) -> f64 {
    values.sort_by(f64::total_cmp);
    (values[(values.len() - 1) / 2] + values[values.len() / 2]) / 2.0
}

fn p95(values: &[u128]) -> u128 {
    let mut values = values.to_vec();
    values.sort_unstable();
    values[(values.len() * 95).div_ceil(100) - 1]
}

fn cohort(cells: usize, accounts: usize, warm: bool, campaign: Instant) -> Result<Value, String> {
    let cohort = Cohort::new(cells, accounts, warm)?;
    let mut caches = cohort.caches()?;
    let mut timings: [Vec<u128>; 2] = std::array::from_fn(|_| Vec::with_capacity(2 * ROUNDS));
    let mut ratios = Vec::with_capacity(ROUNDS);
    let mut last_observations = [None, None];
    for round in 0..ROUNDS {
        let mut totals = [0u128; 2];
        for (position, arm) in ORDER.into_iter().enumerate() {
            let index = arm.index();
            cohort.reset_if_cold(&mut caches[index]);
            emit(
                &json!({"record":"sample_started","mode":"wall","cohort":cohort.id,
                "round":round,"position":position,"arm":arm.name()}),
            )?;
            // JSONL output and flushing are outside this measured interval.
            // No custom GlobalAlloc or TLS observer is installed in this binary.
            let started = Instant::now();
            let actual = arm.calculate(std::hint::black_box(&cohort.state), &mut caches[index]);
            let finished = Instant::now();
            let elapsed_ns = finished.duration_since(started).as_nanos();
            let check = cohort.check(&actual, &caches[index]);
            let observation = caches[index].observation();
            emit(
                &json!({"record":"sample_completed","mode":"wall","cohort":cohort.id,
                "round":round,"position":position,"arm":arm.name(),
                "started_monotonic_ns":started.duration_since(campaign).as_nanos(),
                "finished_monotonic_ns":finished.duration_since(campaign).as_nanos(),
                "elapsed_ns":elapsed_ns,"check":check,"arithmetic":support::arithmetic_json(observation)}),
            )?;
            check.require_valid()?;
            if elapsed_ns == 0 {
                return Err("zero-resolution wall observation".into());
            }
            totals[index] += elapsed_ns;
            timings[index].push(elapsed_ns);
            last_observations[index] = Some(observation);
        }
        if last_observations[0] != last_observations[1] {
            return Err("arithmetic observations differ between identical-input arms".into());
        }
        ratios.push(totals[Arm::Borrowed.index()] as f64 / totals[Arm::Owned.index()] as f64);
    }
    let paired_median = median(ratios.clone());
    let original_p95 = p95(&timings[Arm::Owned.index()]);
    let borrowed_p95 = p95(&timings[Arm::Borrowed.index()]);
    let p95_ratio = borrowed_p95 as f64 / original_p95 as f64;
    let result = json!({"record":"cohort_completed","mode":"wall","cohort":cohort.id,
        "payload_cells":cells,"account_rows":accounts,"warm":warm,
        "completed_samples_per_arm":2 * ROUNDS,"completed_abba_rounds":ROUNDS,
        "paired_wall_ratios":ratios,"paired_median_wall_ratio":paired_median,
        "original_wall_p95_ns":original_p95,"borrowed_wall_p95_ns":borrowed_p95,
        "p95_wall_ratio":p95_ratio,
        "wall_nonregression_pass":paired_median <= 1.0 && p95_ratio <= 1.10,
        "wall_five_percent_improvement_pass":paired_median <= 0.95 && p95_ratio <= 1.10,
        "p99":null});
    emit(&result)?;
    Ok(result)
}

fn run() -> Result<(), String> {
    support::require_argument("--run-component-observation")?;
    let campaign = Instant::now();
    support::start("wall")?;
    let mut results = Vec::with_capacity(COHORTS.len() * 2);
    for (cells, accounts) in COHORTS {
        for warm in [false, true] {
            results.push(cohort(cells, accounts, warm, campaign)?);
        }
    }
    emit(&json!({"record":"campaign_completed","mode":"wall",
        "completed_cohorts":results.len(),"completed_wall_samples":COHORTS.len()*2*ROUNDS*ORDER.len(),
        "allocator":"standard Rust allocator; no custom GlobalAlloc in this executable",
        "wall_nonregression_all_cohorts":results.iter().all(|r|r["wall_nonregression_pass"]==true),
        "wall_five_percent_improvement_all_cohorts":results.iter().all(|r|r["wall_five_percent_improvement_pass"]==true),
        "allocation_rule_evaluated":false,"cohort_results":results,
        "combined_component_verdict":"requires matching-source allocation campaign",
        "service_cpu_gate_qualified":false,"host_qualified":false,"public_throughput_claim":false}))
}

fn main() {
    if let Err(error) = run() {
        let _ = emit(
            &json!({"record":"campaign_failed","mode":"wall","error":error,
            "campaign_complete":false,"acceptance_pass":false}),
        );
        eprintln!("borrowed non-account wall observation failed: {error}");
        std::process::exit(1);
    }
}
