use crate::LaneAdmissionGate;

impl LaneAdmissionGate {
    pub(super) fn lane_has_global_capacity(&self, lane_total: usize) -> bool {
        lane_total < self.total_capacity
    }

    pub(super) fn critical_free_slots(&self) -> usize {
        self.critical
            .capacity
            .saturating_sub(self.critical.queue.len())
    }

    pub(super) fn normal_has_capacity_for_critical_spillover(&self) -> bool {
        self.normal.queue.len() < self.normal.capacity
    }

    pub(super) fn can_normal_borrow_critical_slot(&self, critical_free: usize) -> bool {
        if critical_free == 0 {
            // Fail closed: once no critical reserve headroom remains, normal
            // ingress must never borrow its way past anti-spam backpressure.
            return false;
        }

        let critical_idle = self.critical.queue.is_empty();

        if self.normal.capacity == 0 {
            // Reserve-only mode has no dedicated normal lane, so any truly free
            // critical slot may be borrowed to keep ingress live.
            true
        } else {
            critical_free > 1 || (critical_idle && critical_free == 1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_critical_backlog_guards_last_reserved_slot_from_normal_borrow() {
        let mut gate = LaneAdmissionGate::new(3, 1);

        // Leave exactly one aggregate slot free, but keep it reserved for fresh
        // critical ingress because backlog is already active.
        assert_eq!(gate.admit(1, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.admit(3, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);

        assert_eq!(gate.critical_free_slots(), 0);
        assert!(!gate.can_normal_borrow_critical_slot(0));

        gate.critical.pop_ready();

        // The final critical slot reopens, but backlog is still active because the
        // critical queue will refill before normal traffic may borrow it.
        gate.critical.seen.insert(99);
        assert_eq!(gate.critical_free_slots(), 1);
        assert!(!gate.can_normal_borrow_critical_slot(1));
    }

    #[test]
    fn reserve_only_mode_allows_borrowing_any_reopened_critical_slot() {
        let gate = LaneAdmissionGate::new(2, 2);

        // With no dedicated normal capacity, reserve-only mode intentionally keeps
        // free ingress live by letting normal traffic borrow any truly free critical
        // slot.
        assert_eq!(gate.normal.capacity, 0);
        assert!(gate.can_normal_borrow_critical_slot(1));
        assert!(gate.can_normal_borrow_critical_slot(2));
        assert!(!gate.can_normal_borrow_critical_slot(0));
    }
}
