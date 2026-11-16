//! Query the unchanged original public LaneAdmissionGate with real admissions
//! and a real pop_ready.  Pre/post QoS snapshots identify the popped queue,
//! including cross-lane spillover, without copying the dequeue implementation.
use std::io::{self, BufRead};
use trnm_mempool::{AdmitOutcome, IngressClass, LaneAdmissionGate};

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("original pop input read");
        let words: Vec<u64> = line.split_ascii_whitespace()
            .map(|part| part.parse::<u64>().expect("original integer"))
            .collect();
        assert_eq!(words.len(), 3, "total reserve pattern");
        let total = usize::try_from(words[0]).expect("total usize");
        let reserve = usize::try_from(words[1]).expect("reserve usize");
        let pattern = words[2];
        assert!(total <= 8 && reserve <= 10 && pattern <= 6,
                "finite original dequeue fixture");
        let mut gate = LaneAdmissionGate::new(total, reserve);
        let burst = reserve.min(total).saturating_mul(2).max(1);
        // These patterns contain no intermediate dequeues.  The only possible
        // fairness warmup is a successful admission into a newly nonempty
        // normal lane while critical work is already backlogged.
        let events: &[(IngressClass, u64)] = match pattern {
            0 => &[],
            1 => &[(IngressClass::Normal, 101)],
            2 => &[(IngressClass::Critical, 201)],
            3 => &[(IngressClass::Critical, 201), (IngressClass::Normal, 101)],
            4 => &[(IngressClass::Normal, 101), (IngressClass::Critical, 201)],
            5 => &[(IngressClass::Critical, 201), (IngressClass::Normal, 101),
                   (IngressClass::Normal, 102)],
            6 => &[(IngressClass::Normal, 101), (IngressClass::Critical, 201),
                   (IngressClass::Critical, 202)],
            _ => unreachable!(),
        };
        let mut streak = 0;
        for &(class, id) in events {
            let before = gate.qos_snapshot();
            let outcome = gate.admit(id, class);
            let after = gate.qos_snapshot();
            if outcome == AdmitOutcome::Accepted
                && total > reserve.min(total)
                && before.normal_queued == 0
                && after.normal_queued > 0
                && after.critical_queued > 0
            {
                streak = burst;
            }
        }
        let before = gate.qos_snapshot();
        let popped = gate.pop_ready();
        let after = gate.qos_snapshot();
        let lane = if before.normal_queued > after.normal_queued {
            assert!(popped.is_some());
            1u8
        } else if before.critical_queued > after.critical_queued {
            assert!(popped.is_some());
            2u8
        } else {
            assert!(popped.is_none());
            0u8
        };
        println!("{} {} {} {} {} {} {} {}",
                 before.normal_queued, before.critical_queued,
                 streak, burst, lane,
                 after.normal_queued, after.critical_queued,
                 u8::from(popped.is_some()));
    }
}
