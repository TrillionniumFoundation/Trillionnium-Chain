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
}
