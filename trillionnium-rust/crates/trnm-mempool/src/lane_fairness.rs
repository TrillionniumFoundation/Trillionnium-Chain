use crate::{AdmitOutcome, LaneAdmissionGate};

impl LaneAdmissionGate {
    pub(super) fn maybe_warm_normal_fairness(&mut self, normal_was_empty: bool, out: AdmitOutcome) {
        if self.normal_has_dedicated_capacity
            && matches!(out, AdmitOutcome::Accepted)
            && normal_was_empty
            && !self.normal.queue.is_empty()
            && !self.critical.queue.is_empty()
        {
            // Centralize the dual-backlog warmup contract so normal-arrival and
            // critical-spillover paths refill fairness identically.
            self.critical_served_streak = self.critical_burst_limit;
        }
    }

    pub(super) fn prefer_normal_on_pop(&self) -> bool {
        self.normal_has_dedicated_capacity
            && self.critical_served_streak >= self.critical_burst_limit
            && !self.normal.queue.is_empty()
    }

    pub(super) fn record_pop_fairness(&mut self, served_critical: bool) {
        if self.normal_has_dedicated_capacity {
            if served_critical {
                // Keep streak bounded to the fairness threshold. This preserves
                // dequeue semantics while avoiding unbounded counter growth under
                // prolonged critical-only drains.
                self.critical_served_streak = self
                    .critical_served_streak
                    .saturating_add(1)
                    .min(self.critical_burst_limit);
            } else if !self.normal.queue.is_empty() && !self.critical.queue.is_empty() {
                // When both lanes remain backlogged, keep fairness warm so normal traffic
                // is not forced to wait through another full critical burst.
                self.critical_served_streak = self.critical_burst_limit.saturating_sub(1);
            } else {
                self.critical_served_streak = 0;
            }
        } else {
            // Reserve-only mode has no dedicated normal-lane fairness target.
            // Keep streak cold to avoid carrying stale fairness state across
            // prolonged spillover drains.
            self.critical_served_streak = 0;
        }
    }
}
