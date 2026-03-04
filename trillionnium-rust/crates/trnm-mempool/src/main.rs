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
}

#[derive(Debug)]
pub struct AdmissionGate {
    capacity: usize,
    queue: VecDeque<u64>,
    seen: HashSet<u64>,
    backpressured_ids: HashSet<u64>,
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
            metrics: GateMetrics::default(),
        }
    }

    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.seen.contains(&tx_id) {
            self.metrics.duplicates += 1;
            return AdmitOutcome::Duplicate;
        }

        if self.queue.len() >= self.capacity {
            if !self.backpressured_ids.insert(tx_id) {
                self.metrics.duplicates += 1;
                return AdmitOutcome::Duplicate;
            }
            self.metrics.backpressured += 1;
            return AdmitOutcome::Backpressured;
        }

        self.backpressured_ids.remove(&tx_id);
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        self.metrics.accepted += 1;
        AdmitOutcome::Accepted
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        // Opening capacity starts a new backpressure epoch.
        self.backpressured_ids.clear();
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
}
