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
            capacity: capacity.max(1),
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
    seen_global: HashSet<u64>,
    critical_served_streak: usize,
    critical_burst_limit: usize,
}
impl LaneAdmissionGate {
    pub fn new(total_capacity: usize, critical_reserve: usize) -> Self {
        let total = total_capacity.max(1);
        let reserve = critical_reserve.min(total).max(1);
        let normal_cap = total.saturating_sub(reserve).max(1);
        Self {
            normal: AdmissionGate::new(normal_cap),
            critical: AdmissionGate::new(reserve),
            seen_global: HashSet::new(),
            critical_served_streak: 0,
            critical_burst_limit: reserve.saturating_mul(2).max(1),
        }
    }
    pub fn admit(&mut self, tx_id: u64, class: IngressClass) -> AdmitOutcome {
        if self.seen_global.contains(&tx_id) {
            return AdmitOutcome::Duplicate;
        }
        let out = match class {
            IngressClass::Normal => self.normal.admit(tx_id),
            IngressClass::Critical => self.critical.admit(tx_id),
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
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Backpressured);

        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(22));

        // After two consecutive critical dispatches (burst limit for reserve=1),
        // normal lane is served before another critical id.
        assert_eq!(g.admit(23, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(10));
    }
}
