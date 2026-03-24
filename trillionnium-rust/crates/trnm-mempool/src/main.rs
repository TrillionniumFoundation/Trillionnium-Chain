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
        if self.backpressured_fifo.len() < self.capacity.saturating_mul(4) {
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
            if self.backpressured_fifo.len() < self.backpressured_ids.len() {
                // Restored-state skew can drop FIFO markers while retaining retry ids.
                // Rebuild deterministic markers when marker coverage is incomplete so
                // bounded eviction avoids repeated set-wide fallback trimming.
                let mut rebuilt: Vec<u64> = self.backpressured_ids.iter().copied().collect();
                rebuilt.sort_unstable();
                self.backpressured_fifo = rebuilt.into_iter().collect();
            }
            while self.backpressured_ids.len() > self.capacity {
                let mut evicted = false;
                while let Some(candidate) = self.backpressured_fifo.pop_front() {
                    if candidate == tx_id
                        && self.backpressured_ids.len().saturating_sub(1) >= self.capacity
                    {
                        // Restored state may miss historical fifo markers. Keep the
                        // newly inserted retry id and let deterministic set trimming
                        // evict older entries instead of immediately dropping tx_id.
                        continue;
                    }
                    if self.backpressured_ids.remove(&candidate) {
                        evicted = true;
                        break;
                    }
                }
                if !evicted {
                    // Restored/corrupted state can carry a retry set larger than
                    // capacity with missing fifo markers. Fall back to deterministic
                    // set trimming so fairness quota remains bounded.
                    let overflow = self.backpressured_ids.len().saturating_sub(self.capacity);
                    if overflow == 0 {
                        break;
                    }
                    // HashSet iteration order is randomized; sort for stable trimming so
                    // restored-state recovery stays deterministic across runs/nodes.
                    // Preserve the newly inserted tx_id when possible so immediate
                    // retries for the fresh backpressured id stay idempotent.
                    let mut to_drop: Vec<u64> = self
                        .backpressured_ids
                        .iter()
                        .copied()
                        .filter(|id| *id != tx_id)
                        .collect();
                    to_drop.sort_unstable();
                    to_drop.truncate(overflow);
                    for tx in to_drop {
                        self.backpressured_ids.remove(&tx);
                    }
                    // If overflow remains (e.g. capacity=0 before clamping and only tx_id
                    // was present), fall back to removing the inserted id as a last resort.
                    if self.backpressured_ids.len() > self.capacity {
                        self.backpressured_ids.remove(&tx_id);
                    }
                    break;
                }
            }
            if self.backpressured_fifo.len() > self.backpressured_ids.len() {
                // Restored-state repair can deterministically trim retry ids while stale
                // FIFO markers survive. Rebuild markers immediately so bounded retry
                // bookkeeping stays aligned without waiting for a later compaction pass.
                let mut rebuilt: Vec<u64> = self.backpressured_ids.iter().copied().collect();
                rebuilt.sort_unstable();
                self.backpressured_fifo = rebuilt.into_iter().collect();
            }
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    fn remember_backpressured_without_eviction(&mut self, tx_id: u64) {
        // Fairness deferral must never evict older retry ids. When bounded memory has
        // room, insert directly and append a FIFO marker (no eviction/compaction path).
        if self.backpressured_ids.is_empty() && !self.backpressured_fifo.is_empty() {
            // After a full retry drain, fairness-only deferrals can be the next writer
            // to retry bookkeeping. Drop stale FIFO markers eagerly so the first new
            // deferred id starts from a clean bounded state instead of carrying old tails.
            self.backpressured_fifo.clear();
        }
        if self.backpressured_ids.len() < self.capacity && self.backpressured_ids.insert(tx_id) {
            self.backpressured_fifo.push_back(tx_id);
            // Fairness-only deferrals can run for long windows without hitting the
            // saturation insertion path; keep stale FIFO markers bounded here too.
            self.compact_backpressured_fifo();
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
        let known_retry_count = self.backpressured_ids.len();
        let retry_budget = known_retry_count.min(self.capacity);
        self.retry_reservations = self.retry_reservations.min(retry_budget);
        if known_retry_count == 0 {
            // Restored/corrupted state may carry stale fairness marker + reservation even
            // when retry memory is empty. Clear both so free ingress is never mis-deduped.
            self.retry_reservations = 0;
            self.last_fairness_deferred = None;
            // Retry memory can also keep stale FIFO markers after partial state restore.
            // Drop them eagerly on the no-retry fast path so bookkeeping stays bounded.
            if !self.backpressured_fifo.is_empty() {
                self.backpressured_fifo.clear();
            }
        }
        if self.retry_reservations == 0 {
            if known_retry_count == 0 {
                self.last_fairness_deferred = None;
            } else if self.last_fairness_deferred == Some(tx_id)
                && !self.backpressured_ids.contains(&tx_id)
            {
                // Preserve idempotency for immediate repeats of a just-deferred fresh id,
                // even when only a single retry reservation was available.
                // If the marker points at a known retry id, never shadow its admission.
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
            // Hot saturated retry path: if this tx id is already tracked as backpressured,
            // classify immediately as duplicate and skip bounded retry-cache churn.
            // Guard the hash probe with known_retry_count so fully drained retry state
            // stays on the no-retry fast path under sustained full-queue ingress.
            if known_retry_count != 0 && self.backpressured_ids.contains(&tx_id) {
                self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
                self.metrics.backpressure_duplicates =
                    self.metrics.backpressure_duplicates.saturating_add(1);
                return AdmitOutcome::Duplicate;
            }

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
        let has_known_retries = known_retry_count != 0;
        // Hot free-ingress path usually has zero active retry reservations; skip
        // retry-set hash probes in that case and only consult retry memory when
        // fairness logic is actually armed.
        let is_known_retry_for_fairness = if self.retry_reservations > 0 && has_known_retries {
            self.backpressured_ids.contains(&tx_id)
        } else {
            false
        };
        if self.retry_reservations > 0
            && self.last_fairness_deferred == Some(tx_id)
            && !is_known_retry_for_fairness
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
            && has_known_retries
            && !is_known_retry_for_fairness
        {
            // Fairness-only deferral is tracked via last_fairness_deferred. Do not
            // promote this fresh id into retry memory here; otherwise an immediate
            // repeat can be misclassified as a known retry and consume the reserved slot.
            self.last_fairness_deferred = Some(tx_id);
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            self.metrics.fairness_deferrals = self.metrics.fairness_deferrals.saturating_add(1);
            self.retry_reservations -= 1;
            return AdmitOutcome::Backpressured;
        }

        // Fast-path fresh ingress: when fairness is armed we already probed retry
        // membership above. Reuse that signal to avoid a second hash-table lookup
        // on the common non-retry acceptance path.
        let accepted_was_retry = if is_known_retry_for_fairness {
            self.backpressured_ids.remove(&tx_id)
        } else if self.retry_reservations > 0 {
            false
        } else {
            has_known_retries && self.backpressured_ids.remove(&tx_id)
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
            // Also drop stale retry FIFO markers immediately instead of waiting for the next
            // admit()/pop_ready() boundary. This keeps retry bookkeeping cold after the last
            // recovered retry is accepted during low-churn recovery windows.
            self.backpressured_fifo.clear();
        }
        // Keep fairness marker until the next dequeue boundary. This preserves
        // idempotency for a just-deferred id when the queue re-saturates before
        // sender retry, while still allowing pop_ready() to clear stale markers.
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        self.metrics.accepted = self.metrics.accepted.saturating_add(1);
        AdmitOutcome::Accepted
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        // Dequeue boundary ends immediate fairness-deferral idempotency window.
        self.last_fairness_deferred = None;
        // Reserve one newly opened slot for known retries to reduce starvation.
        // Bound reservations by currently known retry ids so free-ingress throughput
        // is not over-deferred after multi-pop bursts with only a few retry candidates.
        let retry_budget = self.backpressured_ids.len().min(self.capacity);
        if retry_budget == 0 {
            self.retry_reservations = 0;
            // Once retry memory is empty, clear stale fairness marker immediately so
            // pop-only drain cycles restore a clean fast-path state before new ingress.
            self.last_fairness_deferred = None;
            // Retry memory is fully drained; drop stale fifo markers eagerly so
            // idle drain windows do not carry unnecessary backpressure bookkeeping.
            self.backpressured_fifo.clear();
        } else {
            self.retry_reservations = self.retry_reservations.saturating_add(1).min(retry_budget);
            if self.backpressured_fifo.len() > self.capacity.saturating_mul(4) {
                // Pop-heavy recovery windows can retain oversized stale FIFO marker tails
                // from restored/churned state without hitting admit() compaction paths.
                // Compact on dequeue boundaries to keep retry bookkeeping memory bounded.
                self.compact_backpressured_fifo();
            }
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
    fn saturated_known_retry_duplicate_does_not_churn_retry_fifo() {
        let mut gate = AdmissionGate::new(1);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);
        let fifo_len_before = gate.backpressured_fifo.len();

        for _ in 0..8 {
            assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
        }

        // Repeated saturated retries should dedupe without growing retry FIFO markers.
        assert_eq!(gate.backpressured_fifo.len(), fifo_len_before);
        let m = gate.metrics();
        assert_eq!(m.backpressured, 1);
        assert_eq!(m.duplicates, 8);
        assert_eq!(m.backpressure_duplicates, 8);
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
    fn stale_retry_bookkeeping_is_cleared_before_free_ingress_admission() {
        let mut gate = AdmissionGate::new(2);

        // Simulate restored/corrupted bookkeeping: no known retries but stale
        // reservation/marker/fifo state remains.
        gate.retry_reservations = 2;
        gate.last_fairness_deferred = Some(99);
        gate.backpressured_fifo.push_back(99);

        assert_eq!(gate.admit(100), AdmitOutcome::Accepted);
        assert_eq!(gate.retry_reservations, 0);
        assert_eq!(gate.last_fairness_deferred, None);
        assert!(gate.backpressured_fifo.is_empty());
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
    fn retry_acceptance_clears_tracking_even_without_active_fairness_reservations() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // Simulate restored-state skew: retry memory knows about tx=9 but fairness
        // reservations are already exhausted.
        gate.backpressured_ids.insert(9);
        gate.retry_reservations = 0;

        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);
        assert!(!gate.backpressured_ids.contains(&9));
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
    fn fairness_armed_fresh_acceptance_keeps_known_retry_memory_intact() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Two slots open; fairness remains armed with a single known retry id.
        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.pop_ready(), Some(2));

        // Fresh ingress is accepted because free_slots > retry_reservations.
        assert_eq!(gate.admit(10), AdmitOutcome::Accepted);
        // Retry memory must remain intact so id=9 is still admitted later.
        assert!(gate.backpressured_ids.contains(&9));
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
    fn fairness_marker_does_not_shadow_known_retry_id_admission() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Open one slot to arm retry fairness, then simulate restored stale marker that
        // points to the known retry id itself.
        assert_eq!(gate.pop_ready(), Some(1));
        gate.last_fairness_deferred = Some(9);

        // Known retry must be admitted, not misclassified as fairness-duplicate.
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

        let m = gate.metrics();
        assert_eq!(m.accepted, 3);
        assert_eq!(m.duplicates, 0);
        assert_eq!(m.backpressure_duplicates, 0);
    }

    #[test]
    fn saturated_retry_remains_idempotent_when_stale_fairness_marker_points_to_known_retry() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Simulate restored stale fairness marker while queue is still saturated.
        gate.last_fairness_deferred = Some(9);
        gate.retry_reservations = 0;

        // Retry should stay idempotent duplicate (not a fresh backpressure event), and
        // retry memory must keep tracking the tx id for later admission once capacity opens.
        assert_eq!(gate.admit(9), AdmitOutcome::Duplicate);
        assert!(gate.backpressured_ids.contains(&9));

        let m = gate.metrics();
        assert_eq!(m.backpressured, 1);
        assert_eq!(m.duplicates, 1);
        assert_eq!(m.backpressure_duplicates, 1);
    }

    #[test]
    fn pop_ready_clears_stale_fairness_marker_when_retry_memory_is_empty() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // Simulate stale/restored marker state with no known retries.
        gate.last_fairness_deferred = Some(99);
        gate.retry_reservations = 1;
        gate.backpressured_ids.clear();
        gate.backpressured_fifo.extend([42, 43, 42]);

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.retry_reservations, 0);
        assert_eq!(gate.last_fairness_deferred, None);
        assert!(gate.backpressured_fifo.is_empty());
    }

    #[test]
    fn admit_fast_path_clears_stale_retry_fifo_when_retry_set_is_empty() {
        let mut gate = AdmissionGate::new(3);

        // Simulate restored-state skew: stale retry fifo markers remain, but retry
        // memory itself is empty.
        gate.backpressured_fifo.extend([7, 8, 7, 9]);
        gate.backpressured_ids.clear();
        gate.retry_reservations = 2;
        gate.last_fairness_deferred = Some(7);

        assert_eq!(gate.admit(100), AdmitOutcome::Accepted);
        assert!(gate.backpressured_fifo.is_empty());
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
    fn pop_ready_compacts_oversized_retry_fifo_when_retry_memory_is_non_empty() {
        let mut gate = AdmissionGate::new(2);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(10), AdmitOutcome::Backpressured);
        assert_eq!(gate.admit(11), AdmitOutcome::Backpressured);

        // Simulate restored/churned state where stale markers are oversized while
        // active retry ids still exist.
        gate.backpressured_fifo
            .extend([10, 11, 10, 11, 10, 11, 10, 11, 10, 11]);
        assert!(gate.backpressured_fifo.len() > gate.capacity.saturating_mul(4));

        assert_eq!(gate.pop_ready(), Some(1));

        // Dequeue boundary should compact stale retry markers even before retry admission.
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
    fn compaction_triggers_at_threshold_to_bound_stale_fifo_growth() {
        let mut gate = AdmissionGate::new(2);
        // Exactly 4x stale markers should compact immediately instead of waiting
        // for an extra insert above threshold.
        gate.backpressured_fifo.extend([1, 2, 1, 2, 1, 2, 1, 2]);
        gate.backpressured_ids.clear();
        assert_eq!(
            gate.backpressured_fifo.len(),
            gate.capacity.saturating_mul(4)
        );

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
    fn admitting_last_known_retry_clears_stale_retry_fifo_markers_immediately() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3), AdmitOutcome::Accepted);
        assert_eq!(gate.admit(9), AdmitOutcome::Backpressured);

        // Simulate restored/churned runtime state where stale FIFO markers survived
        // around the one real retry id.
        gate.backpressured_fifo.extend([9, 42, 9, 43]);
        assert!(!gate.backpressured_fifo.is_empty());

        assert_eq!(gate.pop_ready(), Some(1));
        assert_eq!(gate.admit(9), AdmitOutcome::Accepted);

        assert!(gate.backpressured_ids.is_empty());
        assert!(gate.backpressured_fifo.is_empty());
        assert_eq!(gate.retry_reservations, 0);
    }

    #[test]
    fn stale_retry_reservations_are_clamped_before_fresh_ingress_deferral() {
        let mut gate = AdmissionGate::new(3);
        assert_eq!(gate.admit(1), AdmitOutcome::Accepted);

        // Simulate restored/churned runtime state with one known retry id but
        // stale oversized reservation count.
        gate.backpressured_ids.insert(99);
        gate.retry_reservations = 3;

        // With free_slots=2 and retry_budget=1, stale reservations must be
        // clamped so fresh ingress is accepted instead of over-deferred.
        assert_eq!(gate.admit(2), AdmitOutcome::Accepted);

        // Clamp should now be observable in runtime state.
        assert_eq!(gate.retry_reservations, 0);

        let m = gate.metrics();
        assert_eq!(m.fairness_deferrals, 0);
        assert_eq!(m.backpressured, 0);
    }

    #[test]
    fn fairness_only_deferral_path_compacts_stale_fifo_markers() {
        let mut gate = AdmissionGate::new(2);

        // Simulate fairness-only deferred ids being inserted and later drained,
        // which can leave stale FIFO markers behind without saturation inserts.
        gate.backpressured_ids.insert(1);
        for i in 0..32u64 {
            let deferred = 1000 + i;
            gate.remember_backpressured_without_eviction(deferred);
            gate.backpressured_ids.remove(&deferred);
        }

        assert!(gate.backpressured_fifo.len() <= gate.capacity.saturating_mul(4));
    }

    #[test]
    fn fairness_only_deferral_clears_stale_fifo_before_first_new_retry_marker() {
        let mut gate = AdmissionGate::new(2);

        gate.backpressured_fifo.extend([7, 8, 9]);
        assert!(gate.backpressured_ids.is_empty());

        gate.remember_backpressured_without_eviction(42);

        assert_eq!(gate.backpressured_fifo, [42]);
        assert_eq!(gate.backpressured_ids, [42].into_iter().collect());
    }

    #[test]
    fn restored_retry_set_without_fifo_markers_is_rebounded_to_capacity() {
        let mut gate = AdmissionGate::new(2);

        // Simulate restored/corrupted state: retry set exceeds capacity but fifo is missing.
        gate.backpressured_ids.extend([100, 101, 102]);
        gate.backpressured_fifo.clear();

        // Any new backpressure insert should rebalance retry memory to quota bounds.
        assert!(gate.remember_backpressured(103));
        assert!(gate.backpressured_ids.len() <= gate.capacity);

        // Fallback trim is deterministic: oldest/smallest ids are dropped first.
        assert!(gate.backpressured_ids.contains(&102));
        assert!(gate.backpressured_ids.contains(&103));
    }

    #[test]
    fn restored_retry_set_trim_preserves_newly_backpressured_id_when_fifo_markers_missing() {
        let mut gate = AdmissionGate::new(2);

        // Corrupted restore: oversized retry memory with no FIFO markers.
        gate.backpressured_ids.extend([8, 9, 10]);
        gate.backpressured_fifo.clear();

        // Insert a smaller id so deterministic trimming would drop it first unless
        // we explicitly preserve the newly backpressured id.
        assert!(gate.remember_backpressured(1));

        assert!(gate.backpressured_ids.len() <= gate.capacity);
        assert!(gate.backpressured_ids.contains(&1));
    }

    #[test]
    fn restored_retry_ids_rehydrate_fifo_before_bounded_eviction() {
        let mut gate = AdmissionGate::new(2);

        // Corrupted restore: retry ids exist but FIFO markers are missing.
        gate.backpressured_ids.extend([41, 42]);
        gate.backpressured_fifo.clear();

        assert!(gate.remember_backpressured(99));

        // Rehydrated FIFO should stay aligned with bounded retry tracking.
        assert!(!gate.backpressured_fifo.is_empty());
        assert!(gate.backpressured_fifo.len() <= gate.backpressured_ids.len());
        assert!(gate.backpressured_ids.contains(&99));
    }

    #[test]
    fn restored_retry_trim_rebuilds_fifo_after_stale_marker_eviction_fallback() {
        let mut gate = AdmissionGate::new(2);

        // Corrupted restore: retry ids and stale markers disagree, so eviction falls
        // back to deterministic set trimming while old FIFO markers survive.
        gate.backpressured_ids.extend([41, 42, 43]);
        gate.backpressured_fifo.extend([7, 8]);

        assert!(gate.remember_backpressured(99));

        assert_eq!(gate.backpressured_ids.len(), 2);
        assert_eq!(gate.backpressured_fifo.len(), gate.backpressured_ids.len());
        assert_eq!(
            gate.backpressured_fifo.iter().copied().collect::<Vec<_>>(),
            vec![43, 99]
        );
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
