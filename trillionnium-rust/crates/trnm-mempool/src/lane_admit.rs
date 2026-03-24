use crate::{AdmitOutcome, IngressClass, LaneAdmissionGate};

impl LaneAdmissionGate {
    pub(super) fn admit_with_class(&mut self, tx_id: u64, class: IngressClass) -> AdmitOutcome {
        match class {
            IngressClass::Normal => self.admit_normal_with_spillover(tx_id),
            IngressClass::Critical => self.admit_critical_with_spillover(tx_id),
        }
    }

    pub fn admit(&mut self, tx_id: u64, class: IngressClass) -> AdmitOutcome {
        if self.total_capacity == 0 {
            // Hard-stop mode: preserve duplicate semantics for restored-state backlog
            // while still backpressuring fresh ingress.
            let is_duplicate = self.seen_global.contains(&tx_id)
                || self.normal.seen.contains(&tx_id)
                || self.critical.seen.contains(&tx_id);
            return if is_duplicate {
                AdmitOutcome::Duplicate
            } else {
                AdmitOutcome::Backpressured
            };
        }

        let (lane_total, lane_was_empty) = self.sync_before_admit();
        let is_duplicate = self.detect_duplicate_after_sync(tx_id, lane_total, lane_was_empty);

        if !self.lane_has_global_capacity(lane_total) {
            // Saturated hot path: avoid insert-then-remove churn for fresh ids while
            // preserving duplicate-vs-backpressure semantics under full queues.
            return if is_duplicate {
                AdmitOutcome::Duplicate
            } else {
                AdmitOutcome::Backpressured
            };
        }

        if is_duplicate {
            return AdmitOutcome::Duplicate;
        }

        let out = self.admit_with_class(tx_id, class);
        if matches!(out, AdmitOutcome::Accepted) {
            self.seen_global.insert(tx_id);
        }
        out
    }
}
