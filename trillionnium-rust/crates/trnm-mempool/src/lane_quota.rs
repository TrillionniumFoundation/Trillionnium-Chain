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
        let critical_idle = self.critical.queue.is_empty();

        if self.normal.capacity == 0 {
            critical_free > 0
        } else {
            critical_free > 1 || (critical_idle && critical_free > 0)
        }
    }
}
