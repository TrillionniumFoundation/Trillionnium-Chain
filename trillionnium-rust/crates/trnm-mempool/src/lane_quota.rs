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
