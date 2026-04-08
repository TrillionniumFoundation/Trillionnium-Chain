use crate::LaneAdmissionGate;

impl LaneAdmissionGate {
    pub(crate) fn lane_total(&self) -> usize {
        self.normal
            .queue
            .len()
            .saturating_add(self.critical.queue.len())
    }

    pub(crate) fn clear_lane_seen(&mut self) {
        self.normal.seen.clear();
        self.critical.seen.clear();
    }

    pub(crate) fn rebuild_seen_from_queues(&mut self) {
        self.normal.seen.clear();
        self.normal.seen.extend(self.normal.queue.iter().copied());
        self.critical.seen.clear();
        self.critical
            .seen
            .extend(self.critical.queue.iter().copied());
        self.rebuild_seen_global_from_queues();
    }

    pub(crate) fn rebuild_seen_global_from_queues(&mut self) {
        self.seen_global.clear();
        self.seen_global.extend(self.normal.queue.iter().copied());
        self.seen_global.extend(self.critical.queue.iter().copied());
    }

    pub(crate) fn reset_idle_state(&mut self, preserve_zero_capacity_duplicates: bool) {
        if !(preserve_zero_capacity_duplicates && self.total_capacity == 0)
            && !(self.normal.seen.is_empty()
                && self.critical.seen.is_empty()
                && self.seen_global.is_empty())
        {
            self.clear_lane_seen();
            self.seen_global.clear();
        }
        if self.critical_served_streak != 0 {
            self.critical_served_streak = 0;
        }
    }

    pub(crate) fn sync_before_admit(&mut self) -> (usize, bool) {
        let lane_total = self.lane_total();
        let lane_was_empty = lane_total == 0;

        if lane_was_empty {
            // Defensive restored-state self-heal: with no queued work, lane-local and
            // lane-wide idempotency sets must be empty. Clear only when needed so
            // repeated empty-lane admits avoid redundant HashSet clear work.
            self.reset_idle_state(false);
        } else {
            let lane_local_seen_total = self
                .normal
                .seen
                .len()
                .saturating_add(self.critical.seen.len());
            if lane_local_seen_total != lane_total {
                // Lane-local seen sets are stale (typically from restored-state skew).
                // Rebuild from authoritative queue contents so duplicate probes stay
                // correct without scanning queues on the steady-state hot path.
                self.rebuild_seen_from_queues();
            } else if self.seen_global.len() != lane_total {
                // Defensive self-heal for transient restored-state skew: lane-local queues
                // remain source of truth for saturation, and rebuild lane-wide id set.
                self.rebuild_seen_global_from_queues();
            }
        }

        (lane_total, lane_was_empty)
    }
}
