use crate::{AdmitOutcome, LaneAdmissionGate};

impl LaneAdmissionGate {
    pub(super) fn admit_normal_with_spillover(&mut self, tx_id: u64) -> AdmitOutcome {
        let normal_was_empty = self.normal.queue.is_empty();
        let primary = self.normal.admit(tx_id);
        let out = if matches!(primary, AdmitOutcome::Backpressured) {
            let critical_free = self.critical_free_slots();

            if self.can_normal_borrow_critical_slot(critical_free) {
                // Keep free-ingress throughput live for reserve-only configs
                // (normal capacity == 0) by borrowing available critical
                // headroom.
                //
                // For non-degenerate splits, allow bounded normal spillover
                // while preserving one immediate critical slot whenever
                // critical backlog is active. If the critical lane is idle,
                // temporarily borrow the last free critical slot to keep
                // normal free-ingress throughput live.
                self.critical.admit(tx_id)
            } else {
                primary
            }
        } else {
            primary
        };

        self.maybe_warm_normal_fairness(normal_was_empty, out);
        out
    }

    pub(super) fn admit_critical_with_spillover(&mut self, tx_id: u64) -> AdmitOutcome {
        let normal_was_empty = self.normal.queue.is_empty();
        let primary = self.critical.admit(tx_id);
        let out = if matches!(primary, AdmitOutcome::Backpressured)
            && self.normal_has_capacity_for_critical_spillover()
        {
            // Keep free-ingress throughput high under critical bursts by
            // allowing bounded spillover into normal capacity.
            self.normal.admit(tx_id)
        } else {
            primary
        };

        self.maybe_warm_normal_fairness(normal_was_empty, out);
        out
    }
}
