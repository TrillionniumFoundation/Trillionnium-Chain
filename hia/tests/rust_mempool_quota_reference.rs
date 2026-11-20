//! Independent adapter compiling the actual original lane quota/fairness modules.
//! The minimal queue shell is not a copied quota implementation; the decisions
//! below execute the original Rust methods via their unmodified source files.
#![allow(dead_code)]
use std::io::{self, BufRead};

struct Queue {
    capacity: usize,
    queue: Vec<u64>,
}
struct LaneAdmissionGate {
    normal: Queue,
    critical: Queue,
    total_capacity: usize,
    critical_served_streak: usize,
    critical_burst_limit: usize,
    normal_has_dedicated_capacity: bool,
}
#[derive(Clone, Copy)]
enum AdmitOutcome {
    Accepted,
    Duplicate,
    Backpressured,
}
#[path = "../../trillionnium/crates/trnm-mempool/src/lane_quota.rs"]
mod original_lane_quota;
#[path = "../../trillionnium/crates/trnm-mempool/src/lane_fairness.rs"]
mod original_lane_fairness;

fn main() {
    for input in io::stdin().lock().lines() {
        let line = input.expect("reference input read");
        let items: Vec<u64> = line.split_ascii_whitespace()
            .map(|s| s.parse::<u64>().expect("reference integer")).collect();
        assert_eq!(items.len(), 7, "reference expects op and six exact u64");
        let mode = items[0];
        let total = usize::try_from(items[1]).expect("usize total");
        let reserve = usize::try_from(items[2]).expect("usize reserve").min(total);
        let normal = usize::try_from(items[3]).expect("usize normal count");
        let critical = usize::try_from(items[4]).expect("usize critical count");
        let streak = usize::try_from(items[5]).expect("usize streak");
        let burst = usize::try_from(items[6]).expect("usize burst limit");
        assert!(normal <= 32 && critical <= 32, "finite original queue adapter");
        let mut gate = LaneAdmissionGate {
            normal: Queue {capacity: total.saturating_sub(reserve),
                           queue: vec![0; normal]},
            critical: Queue {capacity: reserve, queue: vec![0; critical]},
            total_capacity: total,
            critical_served_streak: streak,
            critical_burst_limit: burst,
            normal_has_dedicated_capacity: total > reserve,
        };
        let value = match mode {
            0 => u64::from(gate.lane_has_global_capacity(
                    normal.saturating_add(critical))),
            1 => gate.critical_free_slots() as u64,
            2 => u64::from(gate.normal_has_capacity_for_critical_spillover()),
            3 => u64::from(gate.can_normal_borrow_critical_slot(
                    gate.critical_free_slots())),
            4 => u64::from(gate.prefer_normal_on_pop()),
            5 => {
                gate.record_pop_fairness(true);
                gate.critical_served_streak as u64
            },
            6 => {
                gate.record_pop_fairness(false);
                gate.critical_served_streak as u64
            },
            7..=12 => {
                let normal_was_empty = ((mode - 7) & 1) != 0;
                let outcome = match (mode - 7) / 2 {
                    0 => AdmitOutcome::Accepted,
                    1 => AdmitOutcome::Duplicate,
                    2 => AdmitOutcome::Backpressured,
                    _ => unreachable!("bounded original outcome"),
                };
                gate.maybe_warm_normal_fairness(normal_was_empty, outcome);
                gate.critical_served_streak as u64
            },
            19 => {
                // Execute the unchanged original fairness method on the
                // selected lane. IDs do not affect this pure transition.
                let served = if gate.prefer_normal_on_pop()
                    || (gate.critical.queue.is_empty() && !gate.normal.queue.is_empty())
                {
                    Some(false)
                } else if !gate.critical.queue.is_empty() {
                    Some(true)
                } else {
                    None
                };
                if let Some(critical) = served {
                    if critical {
                        gate.critical.queue.pop();
                    } else {
                        gate.normal.queue.pop();
                    }
                    gate.record_pop_fairness(critical);
                    if gate.normal.queue.is_empty() && gate.critical.queue.is_empty() {
                        // Public pop_ready cold-resets after full drain.
                        gate.critical_served_streak = 0;
                    }
                } else {
                    // The original public pop_ready() calls reset_idle_state(true)
                    // on an empty queue, including an existing stale fairness
                    // streak. This adapter must reproduce that branch instead
                    // of returning the caller-injected stale streak unchanged.
                    // Zero-capacity mode preserves seen metadata, not fairness.
                    gate.critical_served_streak = 0;
                }
                gate.critical_served_streak as u64
            },
            20..=22 => {
                // Exact finite queue counts after a selected dequeue. The
                // unchanged full public pop_ready is also compared separately.
                let served_normal = gate.prefer_normal_on_pop()
                    || (gate.critical.queue.is_empty() && !gate.normal.queue.is_empty());
                let popped = if served_normal {
                    gate.normal.queue.pop().is_some()
                } else {
                    gate.critical.queue.pop().is_some()
                };
                match mode {
                    20 => gate.normal.queue.len() as u64,
                    21 => gate.critical.queue.len() as u64,
                    _ => u64::from(popped),
                }
            },
            _ => panic!("unknown original query"),
        };
        println!("{value}");
    }
}
