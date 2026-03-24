use crate::LaneAdmissionGate;

impl LaneAdmissionGate {
    pub fn queued_counts(&self) -> (usize, usize, usize) {
        let normal = self.normal.queue.len();
        let critical = self.critical.queue.len();
        let total = normal.saturating_add(critical);

        debug_assert_eq!(total, self.lane_total());

        (normal, critical, total)
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        if self.normal.queue.is_empty() && self.critical.queue.is_empty() {
            // Idle dequeue polls are common in long-lived schedulers. Treat them as a
            // self-heal boundary too so restored-state ghost caches/fairness state do
            // not survive indefinitely when no fresh admit() arrives to reset them.
            //
            // Exception: zero-capacity hard-stop mode intentionally preserves restored
            // duplicate knowledge even though no queue slots exist, so repeated idle
            // polls must not erase that recovery metadata.
            self.reset_idle_state(true);
            return None;
        }

        let prefer_normal = self.prefer_normal_on_pop();

        let (id, served_critical) = if prefer_normal {
            // prefer_normal is only true when normal queue is known non-empty.
            // In restored-state edge cases, degrade gracefully instead of panicking.
            if let Some(id) = self.normal.pop_ready() {
                (id, false)
            } else if let Some(id) = self.critical.pop_ready() {
                (id, true)
            } else {
                return None;
            }
        } else if let Some(id) = self.critical.pop_ready() {
            (id, true)
        } else {
            (self.normal.pop_ready()?, false)
        };

        self.record_pop_fairness(served_critical);
        self.repair_seen_after_pop(id);

        Some(id)
    }
}
