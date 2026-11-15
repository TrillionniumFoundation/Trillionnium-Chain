//! Allocation-only companion. Wall acceptance uses a different executable with
//! the standard allocator; this allocator's observation overhead is never timed.

#[path = "support/borrowed_non_account_cost.rs"]
mod support;

use serde::Serialize;
use serde_json::{json, Value};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use support::{emit, Cohort, COHORTS, ORDER};

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct Allocations {
    allocation_requests: usize,
    reallocation_requests: usize,
    deallocations: usize,
    requested_bytes: usize,
    overflow: bool,
}

thread_local! {
    static ALLOCATIONS: Cell<Option<Allocations>> = const { Cell::new(None) };
}

fn add_saturating(value: &mut usize, increment: usize) -> bool {
    match value.checked_add(increment) {
        Some(next) => {
            *value = next;
            false
        }
        None => {
            *value = usize::MAX;
            true
        }
    }
}

fn count_allocation(bytes: usize, allocation: bool, reallocation: bool) {
    let _ = ALLOCATIONS.try_with(|counter| {
        if let Some(mut current) = counter.get() {
            current.overflow |=
                add_saturating(&mut current.allocation_requests, usize::from(allocation));
            current.overflow |= add_saturating(
                &mut current.reallocation_requests,
                usize::from(reallocation),
            );
            current.overflow |= add_saturating(
                &mut current.deallocations,
                usize::from(!allocation && !reallocation),
            );
            current.overflow |= add_saturating(&mut current.requested_bytes, bytes);
            counter.set(Some(current));
        }
    });
}

struct ObservedAllocator;

// SAFETY: unchanged pointer/layout arguments are forwarded to System. The
// const-initialized TLS Cell neither allocates nor accesses observed allocations.
// Saturating integer arithmetic cannot panic; overflow invalidates the sample.
unsafe impl GlobalAlloc for ObservedAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size(), true, false);
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size(), true, false);
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        count_allocation(0, false, false);
        unsafe { System.dealloc(pointer, layout) }
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation(size, false, true);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: ObservedAllocator = ObservedAllocator;

fn cohort(cells: usize, accounts: usize, warm: bool) -> Result<Value, String> {
    let cohort = Cohort::new(cells, accounts, warm)?;
    let mut caches = cohort.caches()?;
    let mut counts = [Allocations::default(); 4];
    let mut last_observations = [None, None];
    for (position, arm) in ORDER.into_iter().enumerate() {
        let index = arm.index();
        cohort.reset_if_cold(&mut caches[index]);
        emit(
            &json!({"record":"sample_started","mode":"allocations","cohort":cohort.id,
            "position":position,"arm":arm.name()}),
        )?;
        ALLOCATIONS.with(|counter| counter.set(Some(Allocations::default())));
        let actual = arm.calculate(std::hint::black_box(&cohort.state), &mut caches[index]);
        let captured = ALLOCATIONS.with(Cell::take);
        // Observation, checking and output allocate only after counters stop.
        let check = cohort.check(&actual, &caches[index]);
        let observation = caches[index].observation();
        emit(
            &json!({"record":"sample_completed","mode":"allocations","cohort":cohort.id,
            "position":position,"arm":arm.name(),"counts":captured,
            "measurement_available":captured.is_some(),"check":check,"arithmetic":support::arithmetic_json(observation)}),
        )?;
        check.require_valid()?;
        let captured = captured.ok_or("allocation observation missing")?;
        if captured.overflow {
            return Err("allocation counter overflow; sample invalid".into());
        }
        counts[position] = captured;
        last_observations[index] = Some(observation);
    }
    if last_observations[0] != last_observations[1] {
        return Err("arithmetic observations differ between identical-input arms".into());
    }
    let deterministic = counts[0] == counts[3] && counts[1] == counts[2];
    let original = counts[0].requested_bytes;
    let borrowed = counts[1].requested_bytes;
    let reduction_pass =
        deterministic && original > 0 && (borrowed as u128) * 100 <= (original as u128) * 95;
    let result = json!({"record":"cohort_completed","mode":"allocations","cohort":cohort.id,
        "payload_cells":cells,"account_rows":accounts,"warm":warm,"completed_samples":ORDER.len(),
        "deterministic_samples":deterministic,"original_requested_bytes":original,"borrowed_requested_bytes":borrowed,
        "requested_bytes_reduction":(original as i128)-(borrowed as i128),
        "requested_bytes_reduction_fraction":(original>0).then(||1.0-borrowed as f64/original as f64),
        "allocation_five_percent_reduction_pass":reduction_pass,"overflow":false,
        "counts_in_abba_order":counts,"requested_bytes_are_peak_or_rss":false});
    emit(&result)?;
    if !deterministic {
        return Err("allocation samples not deterministic; see raw cohort".into());
    }
    Ok(result)
}

fn run() -> Result<(), String> {
    support::require_argument("--run-allocation-observation")?;
    support::start("allocations")?;
    let mut results = Vec::with_capacity(COHORTS.len() * 2);
    for (cells, accounts) in COHORTS {
        for warm in [false, true] {
            results.push(cohort(cells, accounts, warm)?);
        }
    }
    emit(
        &json!({"record":"campaign_completed","mode":"allocations","completed_cohorts":results.len(),
        "completed_allocation_samples":COHORTS.len()*2*ORDER.len(),"overflow":false,
        "allocation_five_percent_reduction_all_cohorts":results.iter().all(|r|r["allocation_five_percent_reduction_pass"]==true),
        "wall_rule_evaluated":false,"cohort_results":results,
        "combined_component_verdict":"requires matching-source standard-allocator wall campaign",
        "service_cpu_gate_qualified":false,"host_qualified":false,"public_throughput_claim":false}),
    )
}

fn main() {
    if let Err(error) = run() {
        let _ = emit(
            &json!({"record":"campaign_failed","mode":"allocations","error":error,
            "campaign_complete":false,"acceptance_pass":false}),
        );
        eprintln!("borrowed non-account allocation observation failed: {error}");
        std::process::exit(1);
    }
}

#[test]
fn saturated_allocator_observations_flag_overflow_without_panicking() {
    let near_limit = Allocations {
        allocation_requests: usize::MAX,
        reallocation_requests: usize::MAX,
        deallocations: usize::MAX,
        requested_bytes: usize::MAX,
        overflow: false,
    };
    ALLOCATIONS.with(|counter| counter.set(Some(near_limit)));
    count_allocation(1, true, false);
    count_allocation(1, false, true);
    count_allocation(0, false, false);
    let captured = ALLOCATIONS.with(Cell::take).unwrap();
    assert!(captured.overflow);
    assert_eq!(captured.allocation_requests, usize::MAX);
    assert_eq!(captured.reallocation_requests, usize::MAX);
    assert_eq!(captured.deallocations, usize::MAX);
    assert_eq!(captured.requested_bytes, usize::MAX);
}
