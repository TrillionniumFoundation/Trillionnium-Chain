use std::collections::{HashSet, VecDeque};

use crate::AdmitOutcome;

#[derive(Debug)]
pub struct AdmissionGate {
    pub(crate) capacity: usize,
    pub(crate) queue: VecDeque<u64>,
    pub(crate) seen: HashSet<u64>,
}

impl AdmissionGate {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            // Pre-size hot-path structures to reduce allocator churn during
            // sustained ingress bursts while preserving zero-capacity semantics.
            queue: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        }
    }

    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.queue.len() >= self.capacity {
            // Saturated fast path: preserve duplicate-vs-backpressure semantics
            // without insert-then-remove churn for fresh ids.
            return if self.seen.contains(&tx_id) {
                AdmitOutcome::Duplicate
            } else {
                AdmitOutcome::Backpressured
            };
        }
        if !self.seen.insert(tx_id) {
            return AdmitOutcome::Duplicate;
        }
        self.queue.push_back(tx_id);
        AdmitOutcome::Accepted
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_capacity_gate_preserves_duplicate_vs_backpressure_contract() {
        let mut gate = AdmissionGate::new(0);

        // Simulate restored duplicate knowledge for a hard-stopped lane: known ids
        // must remain Duplicate while fresh ingress stays fail-closed.
        gate.seen.insert(7);

        assert_eq!(gate.admit(7), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(8), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), None);
        assert!(gate.seen.contains(&7));
    }

    #[test]
    fn zero_capacity_fresh_retry_bursts_do_not_poison_duplicate_tracking() {
        let mut gate = AdmissionGate::new(0);

        // Hard-stop mode must fail closed for fresh ids without mutating duplicate
        // knowledge, even under repeated retry bursts.
        for _ in 0..3 {
            assert_eq!(gate.admit(41), AdmitOutcome::Backpressured);
            assert_eq!(gate.admit(42), AdmitOutcome::Backpressured);
        }
        assert!(gate.queue.is_empty());
        assert!(gate.seen.is_empty());

        // Known ids imported from restored state must still classify as Duplicate,
        // and fresh retry bursts must not disturb that bookkeeping.
        gate.seen.insert(9);
        assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(41), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(42), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), None);
        assert_eq!(gate.seen.iter().copied().collect::<Vec<_>>(), vec![9]);
    }

    #[test]
    fn saturated_fresh_retry_recovers_as_first_admission_after_headroom_reopens() {
        let mut gate = AdmissionGate::new(1);

        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // A fresh retry under saturation must stay backpressured without being
        // inserted into duplicate tracking.
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

        // Once headroom reopens, that same id must still enter as a fresh tx.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Duplicate);
    }

    #[test]
    fn saturated_probe_noise_does_not_disturb_fifo_or_seen_contract() {
        let mut gate = AdmissionGate::new(2);

        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

        // Once saturated, duplicate and fresh probe noise must not mutate queue
        // order or poison future admission for still-fresh ids.
        assert_eq!(gate.admit(10), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Duplicate);
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(10));
        assert_eq!(gate.pop_ready(), Some(11));
        assert_eq!(gate.pop_ready(), None);

        // The previously backpressured id must remain fresh after the queue drains.
        assert_eq!(gate.admit(12), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(12), AdmitOutcome::Duplicate);
    }
}
