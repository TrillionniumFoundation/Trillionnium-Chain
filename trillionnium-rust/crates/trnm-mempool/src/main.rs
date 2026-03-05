use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    Accepted,
    Duplicate,
    Backpressured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GateMetrics {
    pub accepted: usize,
    pub duplicates: usize,
    pub backpressured: usize,
    pub backpressure_duplicates: usize,
    pub fairness_deferrals: usize,
}

#[derive(Debug)]
pub struct AdmissionGate {
    capacity: usize,
    queue: VecDeque<u64>,
    seen: HashSet<u64>,
    backpressured_ids: HashSet<u64>,
    backpressured_fifo: VecDeque<u64>,
    retry_reservations: usize,
    metrics: GateMetrics,
}

impl AdmissionGate {
    fn remember_backpressured(&mut self, tx_id: u64) {
        if self.backpressured_ids.insert(tx_id) {
            self.backpressured_fifo.push_back(tx_id);
            while self.backpressured_ids.len() > self.capacity {
                let mut evicted = false;
                while let Some(candidate) = self.backpressured_fifo.pop_front() {
                    if self.backpressured_ids.remove(&candidate) {
                        evicted = true;
                        break;
                    }
                }
                if !evicted {
                    break;
                }
            }
        }
    }

    pub fn new(capacity: usize) -> Self {
        // Keep the gate live even if operators accidentally configure zero capacity.
        // This prevents a permanent backpressure state with unbounded retry key growth.
        let capacity = capacity.max(1);
        Self {
            capacity,
            queue: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
            backpressured_ids: HashSet::with_capacity(capacity),
            backpressured_fifo: VecDeque::with_capacity(capacity),
            retry_reservations: 0,
            metrics: GateMetrics::default(),
        }
    }

    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.seen.contains(&tx_id) {
            self.metrics.duplicates += 1;
            return AdmitOutcome::Duplicate;
        }

        if self.queue.len() >= self.capacity {
            if self.backpressured_ids.contains(&tx_id) {
                self.metrics.duplicates += 1;
                self.metrics.backpressure_duplicates += 1;
                return AdmitOutcome::Duplicate;
            }
            self.remember_backpressured(tx_id);
            self.metrics.backpressured += 1;
            return AdmitOutcome::Backpressured;
        }

        // Fairness guard: once we have known backpressured retries, reserve newly
        // opened capacity for them first. Fresh ids are briefly backpressured so
        // retry traffic cannot be perpetually starved by new ingress.
        if self.retry_reservations > 0
            && !self.backpressured_ids.is_empty()
            && !self.backpressured_ids.contains(&tx_id)
        {
            self.remember_backpressured(tx_id);
            self.metrics.backpressured += 1;
            self.metrics.fairness_deferrals += 1;
            self.retry_reservations -= 1;
            return AdmitOutcome::Backpressured;
        }

        self.backpressured_ids.remove(&tx_id);
        if self.retry_reservations > 0 {
            self.retry_reservations -= 1;
        }
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        self.metrics.accepted += 1;
        AdmitOutcome::Accepted
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        // Reserve one newly opened slot for known retries to reduce starvation.
        self.retry_reservations = self.retry_reservations.saturating_add(1).min(self.capacity);
        // Keep retry memory across partial drain so repeated retries stay idempotent
        // when the queue quickly re-saturates before the original sender retries.
        Some(id)
    }

    pub fn metrics(&self) -> GateMetrics {
        self.metrics
    }
}

fn main() {
    let mut gate = AdmissionGate::new(1024);
    let _ = gate.admit(1);
    println!("mempool gate ready (queued={})", gate.queue.len());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_admission_is_idempotent() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(42), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(42), AdmitOutcome::Duplicate);

        let m = gate.metrics();
        assert_eq!(m.accepted, 1);
        assert_eq!(m.duplicates, 1);
        assert_eq!(m.backpressured, 0);
        assert_eq!(m.backpressure_duplicates, 0);
        assert_eq!(m.fairness_deferrals, 0);
    }

    #[test]
    fn capacity_exhaustion_triggers_backpressure() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.accepted, 1);
        assert_eq!(m.duplicates, 0);
        assert_eq!(m.backpressured, 1);
        assert_eq!(m.backpressure_duplicates, 0);
        assert_eq!(m.fairness_deferrals, 0);
    }

    #[test]
    fn released_slot_allows_new_admission() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    }

    #[test]
    fn repeated_backpressured_retry_is_idempotent_until_capacity_opens() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);

        let m = gate.metrics();
        assert_eq!(m.backpressured, 1);
        assert_eq!(m.duplicates, 1);
        assert_eq!(m.backpressure_duplicates, 1);
        assert_eq!(m.fairness_deferrals, 0);

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
    }

    #[test]
    fn zero_capacity_is_clamped_to_keep_forward_progress() {
        let mut gate = AdmissionGate::new(0);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
    }

    #[test]
    fn backpressure_retry_cache_is_bounded_by_capacity() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

        // 10 is evicted from the bounded retry cache once a third unique id is observed.
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.backpressured, 4);
        assert_eq!(m.duplicates, 0);
        assert_eq!(m.backpressure_duplicates, 0);
        assert_eq!(m.fairness_deferrals, 0);
    }

    #[test]
    fn stale_fifo_entries_do_not_break_bounded_retry_tracking() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

        // Admit one retry so its stale fifo marker remains but is removed from set.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        assert!(!gate.backpressured_ids.contains(&10));

        // New retries should remain bounded by active set size despite stale markers.
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(13), AdmitOutcome::Backpressured);
        assert!(gate.backpressured_ids.len() <= 2);
    }

    #[test]
    fn accepted_retry_id_is_removed_from_backpressure_set() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(11), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(10));
        assert_eq!(gate.admit(12), AdmitOutcome::Accepted);

        assert!(!gate.backpressured_ids.contains(&12));
    }

    #[test]
    fn backpressure_retry_memory_survives_partial_drain_and_resaturation() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // A single slot opens but is consumed by another tx before id=9 retries.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

        // Retry should be admitted ahead of fresh ingress to avoid starvation.
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.backpressured, 2);
        assert_eq!(m.backpressure_duplicates, 0);
        assert_eq!(m.fairness_deferrals, 1);
    }

    #[test]
    fn opened_capacity_is_reserved_for_known_retries_before_fresh_ingress() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(4), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
    }

    #[test]
    fn fairness_reservation_does_not_deadlock_fresh_ingress_when_retries_disappear() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(1));
        // First fresh ingress is deferred to give retry id=2 one chance.
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);
        // If no retry shows up, subsequent fresh ingress must still make progress.
        assert_eq!(gate.admit(4), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
    }
}
