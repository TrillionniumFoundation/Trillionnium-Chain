use std::collections::{HashSet, VecDeque};

mod fairness;
mod retry_bookkeeping;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_support;

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

        let known_retry_count = self.clamp_retry_reservations();
        self.clear_stale_retry_state_if_empty(known_retry_count);
        if self.fairness_duplicate_without_active_reservation(tx_id) {
            return AdmitOutcome::Duplicate;
        }

        if self.queue.len() >= self.capacity {
            return self.saturated_duplicate_or_backpressure(tx_id, known_retry_count);
        }

        let is_known_retry_for_fairness = self.known_retry_for_fairness(known_retry_count, tx_id);
        if self.fairness_duplicate_with_active_reservation(tx_id, is_known_retry_for_fairness) {
            return AdmitOutcome::Duplicate;
        }
        if self.maybe_fairness_defer_fresh_ingress(
            tx_id,
            known_retry_count,
            is_known_retry_for_fairness,
        ) {
            return AdmitOutcome::Backpressured;
        }

        self.accept_with_retry_tracking(tx_id, known_retry_count, is_known_retry_for_fairness)
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let Some(id) = self.queue.pop_front() else {
            let known_retry_count = self.backpressured_ids.len();
            self.clear_stale_retry_state_if_empty(known_retry_count);
            if known_retry_count != 0
                && self.backpressured_fifo.len() > self.capacity.saturating_mul(4)
            {
                // Idle poll loops can repeatedly probe an already-drained queue while
                // restored/churned retry bookkeeping still carries stale FIFO markers.
                // Compact on empty-pop boundaries too so anti-spam memory stays bounded
                // even before any new admission arrives.
                self.compact_backpressured_fifo();
            }
            return None;
        };
        self.seen.remove(&id);
        self.update_retry_reservations_on_pop();
        // Keep retry memory across partial drain so repeated retries stay idempotent
        // when the queue quickly re-saturates before the original sender retries.
        Some(id)
    }

    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    pub fn metrics(&self) -> GateMetrics {
        self.metrics
    }
}
