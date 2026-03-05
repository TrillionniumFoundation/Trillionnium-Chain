use std::collections::{HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitOutcome {
    Accepted,
    Duplicate,
    Backpressured,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngressClass {
    Normal,
    Critical,
}

#[derive(Debug)]
pub struct AdmissionGate {
    capacity: usize,
    queue: VecDeque<u64>,
    seen: HashSet<u64>,
}
impl AdmissionGate {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            queue: VecDeque::new(),
            seen: HashSet::new(),
        }
    }
    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.seen.contains(&tx_id) {
            return AdmitOutcome::Duplicate;
        }
        if self.queue.len() >= self.capacity {
            return AdmitOutcome::Backpressured;
        }
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        AdmitOutcome::Accepted
    }
    pub fn pop_ready(&mut self) -> Option<u64> {
        let id = self.queue.pop_front()?;
        self.seen.remove(&id);
        Some(id)
    }
}

#[derive(Debug)]
pub struct LaneAdmissionGate {
    normal: AdmissionGate,
    critical: AdmissionGate,
    total_capacity: usize,
    seen_global: HashSet<u64>,
    critical_served_streak: usize,
    critical_burst_limit: usize,
}
impl LaneAdmissionGate {
    pub fn new(total_capacity: usize, critical_reserve: usize) -> Self {
        let total = total_capacity.max(1);
        let reserve = critical_reserve.min(total);
        let normal_cap = total.saturating_sub(reserve);
        Self {
            normal: AdmissionGate::new(normal_cap),
            critical: AdmissionGate::new(reserve),
            total_capacity: total,
            seen_global: HashSet::new(),
            critical_served_streak: 0,
            critical_burst_limit: reserve.saturating_mul(2).max(1),
        }
    }
    pub fn admit(&mut self, tx_id: u64, class: IngressClass) -> AdmitOutcome {
        if self.seen_global.contains(&tx_id) {
            return AdmitOutcome::Duplicate;
        }
        let total_queued = self.normal.queue.len() + self.critical.queue.len();
        if total_queued >= self.total_capacity {
            return AdmitOutcome::Backpressured;
        }
        let out = match class {
            IngressClass::Normal => {
                let primary = self.normal.admit(tx_id);
                if matches!(primary, AdmitOutcome::Backpressured)
                    && self.normal.capacity == 0
                    && self.critical.queue.len() < self.critical.capacity
                {
                    // Keep free-ingress throughput live for degenerate reserve-only
                    // configs (normal capacity == 0) by borrowing available
                    // critical-lane headroom instead of requiring it to be fully idle.
                    self.critical.admit(tx_id)
                } else {
                    primary
                }
            }
            IngressClass::Critical => {
                let primary = self.critical.admit(tx_id);
                if matches!(primary, AdmitOutcome::Backpressured)
                    && self.normal.queue.len() < self.normal.capacity
                {
                    // Keep free-ingress throughput high under critical bursts by
                    // allowing bounded spillover into normal capacity.
                    self.normal.admit(tx_id)
                } else {
                    primary
                }
            }
        };
        if matches!(out, AdmitOutcome::Accepted) {
            self.seen_global.insert(tx_id);
        }
        out
    }
    pub fn pop_ready(&mut self) -> Option<u64> {
        let prefer_normal = self.critical_served_streak >= self.critical_burst_limit
            && !self.normal.queue.is_empty();

        let (id, served_critical) = if prefer_normal {
            if let Some(id) = self.normal.pop_ready() {
                (id, false)
            } else {
                (self.critical.pop_ready()?, true)
            }
        } else if let Some(id) = self.critical.pop_ready() {
            (id, true)
        } else {
            (self.normal.pop_ready()?, false)
        };

        if served_critical {
            self.critical_served_streak = self.critical_served_streak.saturating_add(1);
        } else if !self.normal.queue.is_empty() && !self.critical.queue.is_empty() {
            // When both lanes remain backlogged, keep fairness warm so normal traffic
            // is not forced to wait through another full critical burst.
            self.critical_served_streak = self.critical_burst_limit.saturating_sub(1);
        } else {
            self.critical_served_streak = 0;
        }

        self.seen_global.remove(&id);
        Some(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn critical_lane_makes_progress_under_flood() {
        let mut g = LaneAdmissionGate::new(4, 1);
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(4, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(99));
    }

    #[test]
    fn duplicate_is_rejected_across_ingress_classes_until_drained() {
        let mut g = LaneAdmissionGate::new(4, 1);
        assert_eq!(g.admit(7, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(7, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.pop_ready(), Some(7));
        assert_eq!(g.admit(7, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn normal_lane_gets_turn_after_bounded_critical_burst() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.pop_ready(), Some(21));
    }

    #[test]
    fn critical_lane_spills_over_to_free_normal_capacity() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

        // Critical reserved slot is full, but total capacity still has one slot.
        assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(5, IngressClass::Critical), AdmitOutcome::Backpressured);
    }

    #[test]
    fn lane_gate_enforces_global_capacity_even_when_lane_mins_apply() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Backpressured);

        assert_eq!(g.pop_ready(), Some(100));
        assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn normal_lane_does_not_spill_when_critical_lane_is_busy() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);
    }

    #[test]
    fn full_critical_reserve_allows_normal_when_critical_lane_idle() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Backpressured);
        assert_eq!(g.pop_ready(), Some(1));
    }

    #[test]
    fn full_critical_reserve_allows_normal_to_use_free_headroom_while_critical_busy() {
        let mut g = LaneAdmissionGate::new(3, 3);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        // Even with critical backlog present, reserve-only configs should keep
        // free-ingress throughput live while total capacity has room.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
    }

    #[test]
    fn sustained_dual_lane_backlog_keeps_normal_progress_after_first_fairness_turn() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Prime both lanes.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

        // Sustain critical pressure while preserving normal backlog.
        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(21));
        assert_eq!(g.admit(23, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(22));
        assert_eq!(g.admit(24, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(23));

        // Fairness turn.
        assert_eq!(g.pop_ready(), Some(10));

        // Warm fairness: one critical then normal, instead of another full burst.
        assert_eq!(g.pop_ready(), Some(24));
        assert_eq!(g.pop_ready(), Some(11));
    }

    #[test]
    fn zero_critical_reserve_preserves_normal_capacity_with_critical_spillover() {
        let mut g = LaneAdmissionGate::new(3, 0);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);

        // With zero reserve configured, critical ingress still has a path via
        // spillover into free normal capacity once pressure clears.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn spillover_admission_remains_globally_idempotent_until_drained() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Keep one free total slot while saturating the critical reserve, then
        // force a critical tx to spill into normal capacity.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);

        // Even though tx 51 was admitted via spillover, duplicate admission from
        // either ingress class must still be rejected until it is drained.
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Drain until tx 51 leaves the queue, then re-admission is allowed.
        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.pop_ready(), Some(51));
        assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn backpressured_tx_id_is_not_marked_seen_and_can_be_admitted_after_drain() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);

        // tx 3 is backpressured at global capacity; this must not poison global
        // idempotency tracking.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);

        // Once a slot is freed, tx 3 should admit cleanly (not duplicate).
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);
    }
}
