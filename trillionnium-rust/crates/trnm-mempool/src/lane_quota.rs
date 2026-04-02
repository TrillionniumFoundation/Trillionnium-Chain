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
    fn non_reserve_only_mode_allows_borrowing_last_reserved_slot_only_while_critical_is_idle() {
        let mut gate = LaneAdmissionGate::new(3, 1);

        assert_eq!(gate.normal.capacity, 2);
        assert!(gate.critical.queue.is_empty());
        assert!(gate.can_normal_borrow_critical_slot(1));

        // Once critical backlog appears, the same final reserved slot must stay
        // protected for fresh critical ingress instead of remaining borrowable.
        assert_eq!(gate.admit(11, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
        assert!(!gate.critical.queue.is_empty());
        assert!(!gate.can_normal_borrow_critical_slot(1));
    }

    #[test]
    fn non_reserve_only_mode_keeps_surplus_reserved_headroom_borrowable_under_critical_backlog() {
        let mut gate = LaneAdmissionGate::new(4, 2);

        assert_eq!(gate.normal.capacity, 2);
        assert_eq!(gate.critical.capacity, 2);
        assert_eq!(gate.admit(11, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
        assert!(!gate.critical.queue.is_empty());
        assert_eq!(gate.critical_free_slots(), 1);
        assert!(!gate.can_normal_borrow_critical_slot(1));

        gate.critical.pop_ready();
        assert!(gate.critical.queue.is_empty());
        assert_eq!(gate.critical_free_slots(), 2);

        // With more than one reserved slot free, normal traffic may still borrow
        // surplus critical headroom without consuming the final protected slot.
        assert!(gate.can_normal_borrow_critical_slot(2));

        assert_eq!(gate.admit(21, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
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

    #[test]
    fn reserve_only_mode_keeps_last_free_slot_borrowable_even_with_active_critical_backlog() {
        let mut gate = LaneAdmissionGate::new(3, 3);

        assert_eq!(gate.normal.capacity, 0);
        assert_eq!(gate.critical.capacity, 3);
        assert_eq!(gate.admit(10, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
        assert!(!gate.critical.queue.is_empty());
        assert_eq!(gate.critical_free_slots(), 2);
        assert!(gate.can_normal_borrow_critical_slot(2));

        assert_eq!(gate.admit(11, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.critical_free_slots(), 1);

        // Reserve-only mode shares the critical lane across both classes, so even
        // with active critical backlog the final truly free slot stays borrowable
        // until aggregate anti-spam capacity is actually exhausted.
        assert!(gate.can_normal_borrow_critical_slot(1));
        assert_eq!(gate.admit(12, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.critical_free_slots(), 0);
        assert!(!gate.can_normal_borrow_critical_slot(0));
    }

    #[test]
    fn oversized_reserve_clamp_keeps_reserve_only_borrowing_semantics_under_backlog() {
        let mut gate = LaneAdmissionGate::new(2, 9);

        // Misconfigured reserve > total must clamp into reserve-only semantics
        // instead of fabricating a dedicated normal lane or hiding the last truly
        // free critical slot from normal ingress.
        assert_eq!(gate.normal.capacity, 0);
        assert_eq!(gate.critical.capacity, 2);
        assert_eq!(gate.admit(41, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.critical_free_slots(), 1);
        assert!(gate.can_normal_borrow_critical_slot(1));

        assert_eq!(gate.admit(42, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.critical_free_slots(), 0);
        assert!(!gate.can_normal_borrow_critical_slot(0));
    }

    #[test]
    fn stale_critical_seen_metadata_does_not_fake_active_backlog_on_reopened_last_slot() {
        let mut gate = LaneAdmissionGate::new(3, 1);

        assert_eq!(gate.normal.capacity, 2);
        assert_eq!(gate.critical.capacity, 1);
        assert_eq!(gate.admit(1, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.admit(2, crate::IngressClass::Normal), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.admit(50, crate::IngressClass::Critical), crate::AdmitOutcome::Accepted);
        assert_eq!(gate.critical_free_slots(), 0);
        assert!(!gate.can_normal_borrow_critical_slot(0));

        // After the real critical item drains, only queued backlog should control
        // the last-slot guard. Stale duplicate/seen metadata alone must not keep
        // free ingress closed once the critical queue is actually idle again.
        gate.critical.pop_ready();
        gate.critical.seen.insert(999);
        assert!(gate.critical.queue.is_empty());
        assert_eq!(gate.critical_free_slots(), 1);
        assert!(gate.can_normal_borrow_critical_slot(1));
    }

    #[test]
    fn lane_has_global_capacity_is_strict_at_total_capacity_boundary() {
        let gate = LaneAdmissionGate::new(3, 1);

        assert!(gate.lane_has_global_capacity(0));
        assert!(gate.lane_has_global_capacity(2));
        assert!(!gate.lane_has_global_capacity(3));
        assert!(!gate.lane_has_global_capacity(4));
    }

    #[test]
    fn zero_total_capacity_reports_no_global_headroom() {
        let gate = LaneAdmissionGate::new(0, 0);

        assert!(!gate.lane_has_global_capacity(0));
        assert!(!gate.lane_has_global_capacity(1));
    }
}
