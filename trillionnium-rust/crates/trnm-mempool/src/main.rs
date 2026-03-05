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
    fn compact_backpressured_fifo(&mut self) {
        if self.backpressured_fifo.len() <= self.capacity.saturating_mul(4) {
            return;
        }

        let mut rebuilt = VecDeque::with_capacity(self.backpressured_ids.len());
        let mut seen = HashSet::with_capacity(self.backpressured_ids.len());
        while let Some(candidate) = self.backpressured_fifo.pop_front() {
            if self.backpressured_ids.contains(&candidate) && seen.insert(candidate) {
                rebuilt.push_back(candidate);
            }
        }
        self.backpressured_fifo = rebuilt;
    }

    fn remember_backpressured(&mut self, tx_id: u64) {
        if self.backpressured_ids.insert(tx_id) {
            self.backpressured_fifo.push_back(tx_id);
            self.compact_backpressured_fifo();
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

    fn remember_backpressured_without_eviction(&mut self, tx_id: u64) {
        if self.backpressured_ids.contains(&tx_id) || self.backpressured_ids.len() < self.capacity {
            self.remember_backpressured(tx_id);
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
            self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
            return AdmitOutcome::Duplicate;
        }

        if self.queue.len() >= self.capacity {
            if self.backpressured_ids.contains(&tx_id) {
                self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
                self.metrics.backpressure_duplicates =
                    self.metrics.backpressure_duplicates.saturating_add(1);
                return AdmitOutcome::Duplicate;
            }
            self.remember_backpressured(tx_id);
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            return AdmitOutcome::Backpressured;
        }

        // Fairness guard: once we have known backpressured retries, reserve newly
        // opened capacity for them first. Fresh ids are briefly backpressured so
        // retry traffic cannot be perpetually starved by new ingress.
        if self.retry_reservations > 0
            && !self.backpressured_ids.is_empty()
            && !self.backpressured_ids.contains(&tx_id)
        {
            // Deferring fresh ingress should not evict older retries from bounded memory,
            // otherwise long-waiting retries can lose their anti-starvation preference.
            self.remember_backpressured_without_eviction(tx_id);
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            self.metrics.fairness_deferrals = self.metrics.fairness_deferrals.saturating_add(1);
            self.retry_reservations -= 1;
            return AdmitOutcome::Backpressured;
        }

        let accepted_was_retry = self.backpressured_ids.remove(&tx_id);
        if accepted_was_retry && self.backpressured_fifo.len() > self.capacity.saturating_mul(4) {
            // Under sustained retry drain with little/no new ingress, stale FIFO markers can
            // accumulate without hitting remember_backpressured() compaction. Compact eagerly
            // once a retry is accepted to keep retry-memory bookkeeping bounded.
            self.compact_backpressured_fifo();
        }
        if self.retry_reservations > 0 {
            self.retry_reservations -= 1;
        }
        if accepted_was_retry && self.backpressured_ids.is_empty() {
            // As soon as all known retries are drained, release any stale fairness reservations
            // so newly arriving free-ingress traffic is not pointlessly deferred.
            self.retry_reservations = 0;
        }
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        self.metrics.accepted = self.metrics.accepted.saturating_add(1);
        AdmitOutcome::Accepted
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        // Reserve one newly opened slot for known retries to reduce starvation.
        // Bound reservations by currently known retry ids so free-ingress throughput
        // is not over-deferred after multi-pop bursts with only a few retry candidates.
        let retry_budget = self.backpressured_ids.len().min(self.capacity);
        if retry_budget == 0 {
            self.retry_reservations = 0;
        } else {
            self.retry_reservations = self.retry_reservations.saturating_add(1).min(retry_budget);
        }
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

    #[test]
    fn fairness_deferral_does_not_evict_older_retries_from_bounded_memory() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

        // Deferring fresh ingress should not evict long-waiting retries from fairness tracking.
        assert!(gate.backpressured_ids.contains(&9));
        assert!(gate.backpressured_ids.contains(&10));
        assert!(!gate.backpressured_ids.contains(&3));
    }

    #[test]
    fn retry_reservation_is_capped_by_known_retry_population() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);

        // Only one known retry id exists.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Open two slots before retry arrives.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));

        // Only one fresh ingress should be deferred; the second should progress.
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
    }

    #[test]
    fn stale_retry_fifo_is_compacted_under_high_churn() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        for i in 0..24u64 {
            let retry_id = 100 + i;
            assert_eq!(gate.admit(retry_id), AdmitOutcome::Backpressured);
        }

        // Retry set is capacity-bounded and fifo gets compacted during churn.
        assert!(gate.backpressured_ids.len() <= 2);
        assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
    }

    #[test]
    fn burst_capacity_release_only_defers_fresh_ingress_for_known_retry_budget() {
        let mut gate = AdmissionGate::new(4);
        for tx_id in 1..=4 {
            assert_eq!(gate.admit(tx_id), AdmitOutcome::Accepted);
        }

        // Only two known retries exist.
        assert_eq!(gate.admit(90), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(91), AdmitOutcome::Backpressured);

        // Free three slots in a burst.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));
        assert_eq!(gate.pop_ready(), Some(3));

        // Only two fresh admissions should be deferred; later fresh ingress must progress.
        assert_eq!(gate.admit(1000), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(1001), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(1002), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(1003), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 2);
    }

    #[test]
    fn accepted_retry_compacts_stale_backpressure_fifo_without_new_ingress() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

        // Simulate stale marker buildup from prior churn; only 10/11 remain active retries.
        gate.backpressured_fifo
            .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
        assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);

        // Retry admission should compact stale markers even without new backpressured inserts.
        assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
    }

    #[test]
    fn draining_last_known_retry_clears_stale_fairness_reservations() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Build up reservations by freeing slots before retry arrives.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

        // No retry ids remain; fresh ingress should not be deferred.
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 0);
    }

    #[test]
    fn metrics_counters_saturate_instead_of_overflowing() {
        let mut gate = AdmissionGate::new(1);
        gate.metrics.duplicates = usize::MAX;
        gate.metrics.backpressured = usize::MAX;
        gate.metrics.backpressure_duplicates = usize::MAX;
        gate.metrics.fairness_deferrals = usize::MAX;

        // Duplicate path saturates duplicates.
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(1), AdmitOutcome::Duplicate);

        // Backpressure + duplicate(backpressured) path saturates both counters.
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(2), AdmitOutcome::Duplicate);

        // Fairness deferral path saturates fairness_deferrals/backpressured.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.duplicates, usize::MAX);
        assert_eq!(m.backpressured, usize::MAX);
        assert_eq!(m.backpressure_duplicates, usize::MAX);
        assert_eq!(m.fairness_deferrals, usize::MAX);
    }
}
