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
    last_fairness_deferred: Option<u64>,
    metrics: GateMetrics,
}

impl AdmissionGate {
    fn compact_backpressured_fifo(&mut self) {
        if self.backpressured_fifo.len() <= self.capacity.saturating_mul(4) {
            return;
        }

        if self.backpressured_ids.is_empty() {
            // Fast-path stale retry marker cleanup after full retry drain.
            self.backpressured_fifo.clear();
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

    fn remember_backpressured(&mut self, tx_id: u64) -> bool {
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
            true
        } else {
            false
        }
    }

    fn remember_backpressured_without_eviction(&mut self, tx_id: u64) {
        // Known retry ids are already tracked; avoid a second hash-table probe/insert
        // attempt on the hot fairness-deferral path.
        if self.backpressured_ids.contains(&tx_id) {
            return;
        }

        // Fairness deferral must never evict older retry ids. When bounded memory has
        // room, insert directly and append a FIFO marker (no eviction/compaction path).
        if self.backpressured_ids.len() < self.capacity {
            self.backpressured_ids.insert(tx_id);
            self.backpressured_fifo.push_back(tx_id);
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
            last_fairness_deferred: None,
            metrics: GateMetrics::default(),
        }
    }

    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.seen.contains(&tx_id) {
            self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
            return AdmitOutcome::Duplicate;
        }

        // Keep fairness reservations bounded to currently known retry population.
        // This guards restored/corrupted state from over-deferring free ingress.
        let retry_budget = self.backpressured_ids.len().min(self.capacity);
        self.retry_reservations = self.retry_reservations.min(retry_budget);
        if self.backpressured_ids.is_empty() {
            // Restored/corrupted state may carry stale fairness marker + reservation even
            // when retry memory is empty. Clear both so free ingress is never mis-deduped.
            self.retry_reservations = 0;
            self.last_fairness_deferred = None;
        }
        if self.retry_reservations == 0 {
            if self.backpressured_ids.is_empty() {
                self.last_fairness_deferred = None;
            } else if self.last_fairness_deferred == Some(tx_id) {
                // Preserve idempotency for immediate repeats of a just-deferred fresh id,
                // even when only a single retry reservation was available.
                self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
                self.metrics.backpressure_duplicates =
                    self.metrics.backpressure_duplicates.saturating_add(1);
                return AdmitOutcome::Duplicate;
            }
        }

        if self.queue.len() >= self.capacity {
            // If a fresh id was just fairness-deferred, preserve idempotency even when
            // the queue re-saturates before the sender retries; avoid churning bounded
            // retry memory and over-counting backpressure for immediate repeats.
            if self.last_fairness_deferred == Some(tx_id) {
                self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
                self.metrics.backpressure_duplicates =
                    self.metrics.backpressure_duplicates.saturating_add(1);
                return AdmitOutcome::Duplicate;
            }

            self.last_fairness_deferred = None;
            if !self.remember_backpressured(tx_id) {
                self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
                self.metrics.backpressure_duplicates =
                    self.metrics.backpressure_duplicates.saturating_add(1);
                return AdmitOutcome::Duplicate;
            }
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            return AdmitOutcome::Backpressured;
        }

        // Preserve idempotency for immediate repeats of a fairness-deferred id
        // while reservations remain active, even if throughput guard would allow
        // fresh ingress in the current queue state.
        //
        // Hot fresh-ingress path commonly runs with an empty retry set. Skip the
        // hash probe in that case so admission stays branch/lightweight under
        // free-ingress bursts.
        let has_known_retries = !self.backpressured_ids.is_empty();
        let is_known_retry = has_known_retries && self.backpressured_ids.contains(&tx_id);
        if self.retry_reservations > 0
            && self.last_fairness_deferred == Some(tx_id)
            && !is_known_retry
        {
            self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
            self.metrics.backpressure_duplicates =
                self.metrics.backpressure_duplicates.saturating_add(1);
            return AdmitOutcome::Duplicate;
        }

        // Fairness guard: once we have known backpressured retries, reserve newly
        // opened capacity for them first. Fresh ids are briefly backpressured so
        // retry traffic cannot be perpetually starved by new ingress.
        //
        // Throughput guard: only defer when admitting fresh ingress would consume a
        // slot that must remain reserved for retry traffic. If there are more free
        // slots than retry reservations, admit immediately to avoid unnecessary
        // free-ingress throttling.
        let free_slots = self.capacity.saturating_sub(self.queue.len());
        if self.retry_reservations > 0
            && free_slots <= self.retry_reservations
            && !self.backpressured_ids.is_empty()
            && !is_known_retry
        {

            // Deferring fresh ingress should not evict older retries from bounded memory,
            // otherwise long-waiting retries can lose their anti-starvation preference.
            self.remember_backpressured_without_eviction(tx_id);
            self.last_fairness_deferred = Some(tx_id);
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            self.metrics.fairness_deferrals = self.metrics.fairness_deferrals.saturating_add(1);
            self.retry_reservations -= 1;
            return AdmitOutcome::Backpressured;
        }

        // Fast-path fresh ingress: skip retry-set remove hash probe when we already
        // know this tx id was not tracked as a deferred retry candidate.
        let accepted_was_retry = if is_known_retry {
            self.backpressured_ids.remove(&tx_id)
        } else {
            false
        };
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
        // Fairness deferral idempotency is only intended for immediate repeats of a just-deferred
        // fresh id. Once any admission succeeds, clear the marker so unrelated later retries are
        // not misclassified as duplicates under a future saturation wave.
        self.last_fairness_deferred = None;
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
            // Once retry memory is empty, clear stale fairness marker immediately so
            // pop-only drain cycles restore a clean fast-path state before new ingress.
            self.last_fairness_deferred = None;
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
    fn repeated_fairness_deferral_of_same_fresh_id_is_idempotent() {
        let mut gate = AdmissionGate::new(4);
        for tx_id in 1..=4 {
            assert_eq!(gate.admit(tx_id), AdmitOutcome::Accepted);
        }
        // Fill bounded retry memory to capacity.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(12), AdmitOutcome::Backpressured);

        // Open two slots to create a multi-step fairness reservation window.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));

        // Fresh id=20 is deferred while retry memory is full, so it cannot be
        // remembered in backpressured_ids and should dedupe via last_fairness_deferred.
        assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(20), AdmitOutcome::Duplicate);

        let m = gate.metrics();
        assert_eq!(m.backpressured, 5);
        assert_eq!(m.fairness_deferrals, 1);
        assert_eq!(m.duplicates, 1);
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

        // With spare capacity beyond the one retry reservation, fresh ingress
        // should progress without deferral.
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 0);
    }

    #[test]
    fn fairness_reservation_preserves_free_ingress_when_spare_capacity_exists() {
        let mut gate = AdmissionGate::new(4);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(4), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Two slots open while only one retry id is known.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));

        // Queue now has two free slots. Fresh ingress should proceed without deferral
        // because one slot can still remain reserved for retry traffic.
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        assert_eq!(gate.metrics().fairness_deferrals, 0);

        // Known retry can still consume the reserved slot.
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
    }

    #[test]
    fn repeated_single_slot_fairness_deferral_stays_idempotent() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        // One known retry + one freed slot => a single fairness reservation.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), Some(1));

        // First fresh ingress is deferred; immediate repeat must dedupe instead of
        // being accepted and stealing the reserved slot from retry traffic.
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Duplicate);

        // The reserved slot remains available for known retry.
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
        assert_eq!(m.duplicates, 1);
    }

    #[test]
    fn fairness_deferral_duplicate_increments_backpressure_duplicate_metric() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        // Seed one known retry so fresh ingress is fairness-deferred after a pop.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), Some(1));

        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Duplicate);

        // Duplicate generated by fairness-idempotency is still a backpressure-
        // induced retry signal and should be reflected in backpressure telemetry.
        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
        assert_eq!(m.duplicates, 1);
        assert_eq!(m.backpressure_duplicates, 1);
    }

    #[test]
    fn fairness_deferred_repeat_stays_duplicate_after_queue_resaturates() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        // One known retry => one fairness reservation after a pop.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), Some(1));

        // Fresh id is fairness-deferred.
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        // Queue re-saturates before sender retries deferred id.
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        // Immediate repeat should still dedupe instead of churning retry cache.
        assert_eq!(gate.admit(10), AdmitOutcome::Duplicate);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
        assert_eq!(m.duplicates, 1);
        assert_eq!(m.backpressure_duplicates, 1);
    }

    #[test]
    fn stale_fairness_marker_is_cleared_after_successful_admission() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        // Fill bounded retry memory.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);

        // Open one slot and fairness-defer a fresh id that cannot be remembered
        // because retry memory is already full.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);

        // A different fresh admission succeeds and must clear stale fairness marker state.
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.pop_ready(), Some(2));

        // If marker was stale, this would be a duplicate despite not being in retry memory.
        assert_eq!(gate.admit(20), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 2);
        assert_eq!(m.backpressure_duplicates, 0);
    }

    #[test]
    fn stale_retry_reservation_is_clamped_before_fairness_deferral() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Open one slot and then simulate stale/restored over-large reservation state.
        assert_eq!(gate.pop_ready(), Some(1));
        gate.retry_reservations = 99;

        // Clamp should limit deferral pressure to the one known retry id.
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 1);
    }

    #[test]
    fn stale_fairness_marker_without_known_retries_does_not_force_duplicate() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // Simulate restored stale state with no known retries left.
        gate.retry_reservations = 1;
        gate.last_fairness_deferred = Some(9);
        gate.backpressured_ids.clear();

        // With no retry memory, fresh id should be treated as backpressured, not duplicate.
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.duplicates, 0);
        assert_eq!(m.backpressured, 1);
    }

    #[test]
    fn pop_ready_clears_stale_fairness_marker_when_retry_memory_is_empty() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // Simulate stale/restored marker state with no known retries.
        gate.last_fairness_deferred = Some(99);
        gate.retry_reservations = 1;
        gate.backpressured_ids.clear();

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.retry_reservations, 0);
        assert_eq!(gate.last_fairness_deferred, None);
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

        // Spare capacity exceeds retry reservation budget, so fresh ingress should
        // proceed without additional fairness deferrals.
        assert_eq!(gate.admit(1000), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(1001), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(1002), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(1003), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 0);
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
    fn compaction_clears_stale_fifo_immediately_when_retry_set_is_empty() {
        let mut gate = AdmissionGate::new(2);
        // Simulate restored/churned state where retry set drained but fifo still carries stale markers.
        gate.backpressured_fifo
            .extend([42, 43, 42, 43, 42, 43, 42, 43, 42]);
        gate.backpressured_ids.clear();
        assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

        gate.compact_backpressured_fifo();
        assert!(gate.backpressured_fifo.is_empty());
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
    fn zero_capacity_configuration_still_allows_progress() {
        // Capacity is clamped to 1 so a misconfigured zero-capacity gate does not
        // deadlock all ingress into permanent backpressure.
        let mut gate = AdmissionGate::new(0);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.accepted, 2);
        assert_eq!(m.backpressured, 1);
    }

    #[test]
    fn metrics_counters_saturate_instead_of_overflowing() {
        let mut gate = AdmissionGate::new(1);
        gate.metrics.accepted = usize::MAX;
        gate.metrics.duplicates = usize::MAX;
        gate.metrics.backpressured = usize::MAX;
        gate.metrics.backpressure_duplicates = usize::MAX;
        gate.metrics.fairness_deferrals = usize::MAX;

        // Accepted path saturates accepted.
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        // Duplicate path saturates duplicates.
        assert_eq!(gate.admit(1), AdmitOutcome::Duplicate);

        // Backpressure + duplicate(backpressured) path saturates both counters.
        assert_eq!(gate.admit(2), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(2), AdmitOutcome::Duplicate);

        // Fairness deferral path saturates fairness_deferrals/backpressured.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(3), AdmitOutcome::Backpressured);

        let m = gate.metrics();
        assert_eq!(m.accepted, usize::MAX);
        assert_eq!(m.duplicates, usize::MAX);
        assert_eq!(m.backpressured, usize::MAX);
        assert_eq!(m.backpressure_duplicates, usize::MAX);
        assert_eq!(m.fairness_deferrals, usize::MAX);
    }
}

