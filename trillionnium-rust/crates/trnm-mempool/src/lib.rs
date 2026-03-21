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
            capacity,
            // Pre-size hot-path structures to reduce allocator churn during
            // sustained ingress bursts while preserving zero-capacity semantics.
            queue: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
        }
    }
    pub fn admit(&mut self, tx_id: u64) -> AdmitOutcome {
        if self.queue.len() >= self.capacity {
            // Saturated fast path: preserve duplicate-vs-backpressure semantics
            // without insert-then-remove churn for fresh ids.
            return if self.seen.contains(&tx_id) {
                AdmitOutcome::Duplicate
            } else {
                AdmitOutcome::Backpressured
            };
        }
        if !self.seen.insert(tx_id) {
            return AdmitOutcome::Duplicate;
        }
        self.queue.push_back(tx_id);
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
    total_capacity: usize,
    seen_global: HashSet<u64>,
    critical_served_streak: usize,
    critical_burst_limit: usize,
    normal_has_dedicated_capacity: bool,
}
impl LaneAdmissionGate {
    fn clear_seen_caches(&mut self) {
        self.normal.seen.clear();
        self.critical.seen.clear();
        self.seen_global.clear();
    }

    fn lane_total(&self) -> usize {
        self.normal
            .queue
            .len()
            .saturating_add(self.critical.queue.len())
    }

    fn lane_is_idle(&self) -> bool {
        self.lane_total() == 0
    }

    fn reset_idle_state(&mut self, preserve_zero_capacity_seen: bool) {
        if !(preserve_zero_capacity_seen && self.total_capacity == 0)
            && !(self.normal.seen.is_empty()
                && self.critical.seen.is_empty()
                && self.seen_global.is_empty())
        {
            self.clear_seen_caches();
        }
        if self.critical_served_streak != 0 {
            self.critical_served_streak = 0;
        }
    }

    fn rebuild_lane_seen_from_queues(&mut self) {
        self.normal.seen.clear();
        self.normal.seen.extend(self.normal.queue.iter().copied());
        self.critical.seen.clear();
        self.critical
            .seen
            .extend(self.critical.queue.iter().copied());
    }

    fn rebuild_global_seen_from_queues(&mut self) {
        self.seen_global.clear();
        self.seen_global.extend(self.normal.queue.iter().copied());
        self.seen_global.extend(self.critical.queue.iter().copied());
    }

    fn lane_local_seen_total(&self) -> usize {
        self.normal
            .seen
            .len()
            .saturating_add(self.critical.seen.len())
    }

    fn rebuild_seen_from_queues(&mut self) {
        self.rebuild_lane_seen_from_queues();
        self.rebuild_global_seen_from_queues();
    }

    fn repair_global_seen_after_pop(&mut self, drained_id: u64) {
        if !self.seen_global.remove(&drained_id) {
            // Defensive self-heal: restored-state skew can leave lane-wide cache
            // stale while lane-local queues remain authoritative.
            if self.lane_is_idle() {
                // Hot full-drain skew path: avoid redundant iterator setup when no
                // queued survivors exist after dequeue.
                self.seen_global.clear();
            } else {
                self.rebuild_global_seen_from_queues();
            }
            return;
        }

        let lane_total = self.lane_total();
        if self.seen_global.len() != lane_total {
            // Keep idempotency cache in sync even when a stale ghost id survives
            // removal of the drained tx id.
            if lane_total == 0 {
                // Hot idle path after full drain: clear stale cache entries.
                self.seen_global.clear();
            } else {
                self.rebuild_global_seen_from_queues();
            }
        }
    }

    fn maybe_warm_normal_fairness(&mut self, normal_was_empty: bool, out: AdmitOutcome) {
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

    fn critical_free_slots(&self) -> usize {
        self.critical
            .capacity
            .saturating_sub(self.critical.queue.len())
    }

    fn critical_backlog_active(&self) -> bool {
        !self.critical.queue.is_empty()
    }

    fn critical_has_single_borrowable_slot(&self) -> bool {
        self.critical_free_slots() == 1
    }

    fn critical_has_borrowable_headroom(&self) -> bool {
        self.critical_free_slots() > 0
    }

    fn normal_last_reserved_critical_slot_is_guarded(&self) -> bool {
        self.normal.capacity > 0
            && self.critical_backlog_active()
            && self.critical_has_single_borrowable_slot()
    }

    fn normal_can_borrow_critical_headroom(&self) -> bool {
        if self.normal.capacity == 0 {
            // Reserve-only mode keeps free-ingress throughput live by borrowing any
            // idle critical headroom because there is no dedicated normal lane.
            return self.critical_has_borrowable_headroom();
        }

        self.critical_has_borrowable_headroom()
            && !self.normal_last_reserved_critical_slot_is_guarded()
    }

    fn critical_can_borrow_normal_headroom(&self) -> bool {
        // Critical spillover is bounded to already-free normal slots only. This
        // keeps saturated retry bursts from bypassing backpressure once normal
        // dedicated capacity is fully occupied.
        self.normal.queue.len() < self.normal.capacity
    }

    fn queues_contain_tx(&self, tx_id: u64, in_normal_seen: bool, in_critical_seen: bool) -> bool {
        if in_normal_seen && in_critical_seen {
            self.normal.queue.contains(&tx_id) || self.critical.queue.contains(&tx_id)
        } else if in_normal_seen {
            self.normal.queue.contains(&tx_id)
        } else if in_critical_seen {
            self.critical.queue.contains(&tx_id)
        } else {
            false
        }
    }

    fn classify_duplicate_probe(&self, is_duplicate: bool) -> AdmitOutcome {
        if is_duplicate {
            AdmitOutcome::Duplicate
        } else {
            AdmitOutcome::Backpressured
        }
    }

    fn seen_caches_contain_tx(&self, tx_id: u64) -> bool {
        self.seen_global.contains(&tx_id)
            || self.normal.seen.contains(&tx_id)
            || self.critical.seen.contains(&tx_id)
    }

    fn classify_seen_probe(&self, tx_id: u64) -> AdmitOutcome {
        self.classify_duplicate_probe(self.seen_caches_contain_tx(tx_id))
    }

    fn classify_hard_stop_probe(&self, tx_id: u64) -> AdmitOutcome {
        // Hard-stop mode preserves restored duplicate knowledge while keeping
        // fresh retry bursts backpressured without touching lane admit paths.
        self.classify_seen_probe(tx_id)
    }

    fn classify_saturated_probe(&self, is_duplicate: bool) -> AdmitOutcome {
        // Saturated retry probes are hot under ingress bursts. Return the final
        // duplicate-vs-backpressure classification directly so callers avoid
        // drifting into lane-specific admit paths that would only re-check the
        // same capacity guards.
        self.classify_duplicate_probe(is_duplicate)
    }

    fn lane_has_global_headroom(&self, lane_total: usize) -> bool {
        lane_total < self.total_capacity
    }

    fn classify_pre_admission_probe(
        &self,
        lane_total: usize,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        if !self.lane_has_global_headroom(lane_total) {
            return Some(self.classify_saturated_probe(is_duplicate));
        }

        if is_duplicate {
            Some(AdmitOutcome::Duplicate)
        } else {
            None
        }
    }

    fn classify_reserved_slot_guard_probe(
        &self,
        class: IngressClass,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        // When aggregate capacity remains but reserve policy blocks this ingress
        // class, preserve the same duplicate-vs-backpressure contract that the
        // saturated path already guarantees so bounded retries do not drift into
        // lane-specific admit paths.
        self.classify_lane_backpressure_guard(class, is_duplicate)
    }

    fn classify_headroom_probe(
        &self,
        lane_total: usize,
        class: IngressClass,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        if let Some(out) = self.classify_pre_admission_probe(lane_total, is_duplicate) {
            return Some(out);
        }

        self.classify_reserved_slot_guard_probe(class, is_duplicate)
    }

    fn normal_queue_has_headroom(&self) -> bool {
        self.normal.queue.len() < self.normal.capacity
    }

    fn critical_queue_has_headroom(&self) -> bool {
        self.critical.queue.len() < self.critical.capacity
    }

    fn normal_has_admission_headroom(&self) -> bool {
        self.normal_queue_has_headroom() || self.normal_can_borrow_critical_headroom()
    }

    fn critical_has_admission_headroom(&self) -> bool {
        self.critical_queue_has_headroom() || self.critical_can_borrow_normal_headroom()
    }

    fn class_has_admission_headroom(&self, class: IngressClass) -> bool {
        match class {
            IngressClass::Normal => self.normal_has_admission_headroom(),
            IngressClass::Critical => self.critical_has_admission_headroom(),
        }
    }

    fn lane_backpressure_guard_blocks(&self, class: IngressClass) -> bool {
        !self.class_has_admission_headroom(class)
    }

    fn classify_lane_backpressure_guard(
        &self,
        class: IngressClass,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        if self.lane_backpressure_guard_blocks(class) {
            Some(self.classify_duplicate_probe(is_duplicate))
        } else {
            None
        }
    }

    fn finish_admission(&mut self, tx_id: u64, out: AdmitOutcome) -> AdmitOutcome {
        if matches!(out, AdmitOutcome::Accepted) {
            self.seen_global.insert(tx_id);
        }
        out
    }

    pub fn new(total_capacity: usize, critical_reserve: usize) -> Self {
        // Preserve explicit zero-capacity semantics so callers can hard-stop
        // ingress without accidentally admitting one tx.
        let total = total_capacity;
        let reserve = critical_reserve.min(total);
        let normal_cap = total.saturating_sub(reserve);
        Self {
            normal: AdmissionGate::new(normal_cap),
            critical: AdmissionGate::new(reserve),
            total_capacity: total,
            // Bound global idempotency set to lane-wide capacity so bursty dual-lane
            // ingress does not pay avoidable HashSet reallocation churn.
            seen_global: HashSet::with_capacity(total),
            critical_served_streak: 0,
            critical_burst_limit: reserve.saturating_mul(2).max(1),
            normal_has_dedicated_capacity: normal_cap > 0,
        }
    }
    pub fn admit(&mut self, tx_id: u64, class: IngressClass) -> AdmitOutcome {
        if self.total_capacity == 0 {
            // Hard-stop mode: preserve duplicate semantics for restored-state backlog
            // while still backpressuring fresh ingress.
            return self.classify_hard_stop_probe(tx_id);
        }

        // Fast-path saturation check from the lane-wide idempotency set: this tracks
        // all currently queued tx ids and avoids touching both lane queues on every
        // ingress probe while the cache is in sync.
        let lane_total = self.lane_total();
        let lane_was_empty = self.lane_is_idle();

        if lane_was_empty {
            // Defensive restored-state self-heal: with no queued work, lane-local and
            // lane-wide idempotency sets must be empty. Clear only when needed so
            // repeated empty-lane admits avoid redundant HashSet clear work.
            // Fully idle lane state must also reset fairness streak; otherwise a
            // restored stale streak can spuriously preempt fresh critical work.
            self.reset_idle_state(false);
        } else {
            let lane_local_seen_total = self.lane_local_seen_total();
            if lane_local_seen_total != lane_total {
                // Lane-local seen sets are stale (typically from restored-state skew).
                // Rebuild from authoritative queue contents so duplicate probes stay
                // correct without scanning queues on the steady-state hot path.
                self.rebuild_seen_from_queues();
            } else if self.seen_global.len() != lane_total {
                // Defensive self-heal for transient restored-state skew: lane-local queues
                // remain source of truth for saturation, and rebuild lane-wide id set.
                self.rebuild_global_seen_from_queues();
            }
        }

        // When cache and lane queue cardinality are aligned, lane-wide membership
        // is authoritative for duplicate checks on both saturated and free paths.
        //
        // Defensive fallback: restored-state skew can theoretically keep cardinality
        // aligned while replacing one queued id with a ghost id in seen_global. In
        // that case, trust lane-local seen sets and repair lane-wide cache inline.
        let mut is_duplicate = if lane_was_empty {
            false
        } else {
            self.seen_global.contains(&tx_id)
        };
        if is_duplicate {
            let in_normal_seen = self.normal.seen.contains(&tx_id);
            let in_critical_seen = self.critical.seen.contains(&tx_id);

            // Restored-state skew can leave lane-wide and lane-local membership out
            // of sync while preserving cardinality. When lane-local caches claim the
            // id is absent, rebuild from authoritative queue state immediately instead
            // of probing both queues first.
            if !in_normal_seen && !in_critical_seen {
                self.rebuild_seen_from_queues();
                is_duplicate = self.seen_global.contains(&tx_id);
            } else {
                // Duplicate probes are hot under replay pressure. Narrow queue probes to
                // lanes that claim membership instead of always scanning both queues.
                let queue_contains =
                    self.queues_contain_tx(tx_id, in_normal_seen, in_critical_seen);

                if !queue_contains {
                    // Defensive self-heal: restored-state skew can preserve lane-wide
                    // cardinality while lane-local caches drift via ghost ids. Queue
                    // membership remains authoritative for duplicate classification, so
                    // rebuild both lane-local and lane-wide caches before deciding.
                    self.rebuild_seen_from_queues();
                    is_duplicate = self.seen_global.contains(&tx_id);
                }
            }
        }

        if !is_duplicate && !lane_was_empty {
            // Hot free-ingress path: probe lane-local idempotency sets first, but
            // confirm queue membership before classifying as duplicate so restored-
            // state ghost entries cannot poison fresh ingress.
            let in_normal_seen = self.normal.seen.contains(&tx_id);
            let in_critical_seen = self.critical.seen.contains(&tx_id);
            let lane_local_duplicate = in_normal_seen || in_critical_seen;
            if lane_local_duplicate {
                let queue_contains =
                    self.queues_contain_tx(tx_id, in_normal_seen, in_critical_seen);

                if queue_contains {
                    is_duplicate = true;
                    self.seen_global.insert(tx_id);
                } else {
                    self.rebuild_seen_from_queues();
                    is_duplicate = self.seen_global.contains(&tx_id);
                }
            } else {
                // Defensive fallback for restored-state skew where queue membership can
                // diverge from lane-local id sets after the initial sync window.
                let lane_local_seen_total = self.lane_local_seen_total();
                if lane_local_seen_total != lane_total
                    && (self.normal.queue.contains(&tx_id) || self.critical.queue.contains(&tx_id))
                {
                    is_duplicate = true;
                    self.seen_global.insert(tx_id);
                }
            }
        }

        if let Some(out) = self.classify_headroom_probe(lane_total, class, is_duplicate) {
            // Exit before lane-specific admission attempts once aggregate headroom
            // and class-specific reserve guards have already determined the final
            // duplicate-vs-backpressure outcome.
            return out;
        }

        let out = match class {
            IngressClass::Normal => {
                let normal_was_empty = self.normal.queue.is_empty();
                let primary = self.normal.admit(tx_id);
                let out = if matches!(primary, AdmitOutcome::Backpressured)
                    && self.normal_can_borrow_critical_headroom()
                {
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
                };

                self.maybe_warm_normal_fairness(normal_was_empty, out);

                out
            }
            IngressClass::Critical => {
                let normal_was_empty = self.normal.queue.is_empty();
                let primary = self.critical.admit(tx_id);
                let out = if matches!(primary, AdmitOutcome::Backpressured)
                    && self.critical_can_borrow_normal_headroom()
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
        };
        self.finish_admission(tx_id, out)
    }
    pub fn queued_counts(&self) -> (usize, usize, usize) {
        let normal = self.normal.queue.len();
        let critical = self.critical.queue.len();
        (normal, critical, self.lane_total())
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        if self.lane_is_idle() {
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

        let prefer_normal = self.normal_has_dedicated_capacity
            && self.critical_served_streak >= self.critical_burst_limit
            && !self.normal.queue.is_empty();

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

        self.repair_global_seen_after_pop(id);

        if self.normal.queue.is_empty() && self.critical.queue.is_empty() {
            // Full-drain boundary: reuse the centralized idle reset so lane-local,
            // lane-wide, and fairness caches all cold-reset before any subsequent
            // idle poll or retry-admit probes the emptied gate.
            self.reset_idle_state(false);
        }

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
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);

        // With an idle critical lane, one normal tx may borrow the final reserved
        // slot; fresh critical ingress then backpressures until a dequeue opens space.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.pop_ready(), Some(4));
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
    fn stale_dual_lane_seen_flags_do_not_poison_fresh_admission() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // Simulate restored-state skew where both lane-local seen caches claim the
        // same ghost id while neither queue actually contains it.
        g.normal.seen.insert(99);
        g.critical.seen.insert(99);
        g.seen_global.clear();

        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 0, 1));
    }

    #[test]
    fn normal_lane_gets_turn_after_bounded_critical_burst() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.pop_ready(), Some(21));
    }

    #[test]
    fn critical_lane_spills_over_to_free_normal_capacity() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

        // Critical reserved slot is full, but total capacity still has one slot.
        assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(5, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn lane_gate_enforces_global_capacity_even_when_lane_mins_apply() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(101, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        assert_eq!(g.pop_ready(), Some(100));
        assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn saturated_retry_burst_stays_backpressured_until_headroom_reopens() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 1, 2));

        for class in [
            IngressClass::Critical,
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
        ] {
            assert_eq!(g.admit(30, class), AdmitOutcome::Backpressured);
            assert_eq!(g.queued_counts(), (1, 1, 2));
        }

        assert!(matches!(g.pop_ready(), Some(10) | Some(20)));
        assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    }

    #[test]
    fn normal_lane_does_not_spill_when_critical_lane_is_busy() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(3, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn normal_lane_can_borrow_only_surplus_critical_headroom() {
        let mut g = LaneAdmissionGate::new(6, 2);

        // Fill normal lane first.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);

        // With two critical slots free, normal may borrow one for better free-ingress throughput.
        assert_eq!(g.admit(5, IngressClass::Normal), AdmitOutcome::Accepted);

        // Borrowing preserves one immediate critical slot while critical backlog is active.
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);

        // With critical backlog active and no surplus headroom left, further normal
        // spillover is blocked.
        assert_eq!(
            g.admit(6, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn normal_lane_can_borrow_last_critical_slot_when_critical_lane_idle() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Critical lane is idle with exactly one free slot; allow temporary borrow
        // instead of backpressuring fresh normal ingress.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

        // Once borrowed, fresh critical ingress should backpressure until dequeue.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn full_critical_reserve_allows_normal_when_critical_lane_idle() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(2, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.pop_ready(), Some(1));
    }

    #[test]
    fn full_critical_reserve_allows_normal_to_use_free_headroom_while_critical_busy() {
        let mut g = LaneAdmissionGate::new(3, 3);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        // Even with critical backlog present, reserve-only configs should keep
        // free-ingress throughput live while total capacity has room.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(4, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn reserve_only_normal_borrowing_does_not_preempt_critical_drain_order() {
        let mut g = LaneAdmissionGate::new(3, 3);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
        // Normal ingress borrows reserve-only headroom.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

        // With no dedicated normal capacity configured, borrowed normal traffic
        // should not preempt pending critical work.
        assert_eq!(g.pop_ready(), Some(100));
        assert_eq!(g.pop_ready(), Some(101));
        assert_eq!(g.pop_ready(), Some(1));
    }

    #[test]
    fn critical_spillover_can_fill_normal_lane_until_global_capacity() {
        let mut g = LaneAdmissionGate::new(4, 2);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

        // With reserve saturated, critical traffic should spill into free normal
        // headroom until global capacity is fully consumed.
        assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(103, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(1, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn reserve_only_normal_borrowed_admission_is_globally_idempotent_until_drained() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Normal ingress borrows critical headroom when normal lane has zero reserved capacity.
        assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Accepted);

        // Replays from either class must dedupe until the tx is drained.
        assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);

        assert_eq!(g.pop_ready(), Some(41));
        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn sustained_dual_lane_backlog_keeps_normal_progress_after_first_fairness_turn() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Prime both lanes.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(12, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

        // Sustain critical pressure while preserving normal backlog.
        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(21));
        assert_eq!(g.admit(23, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(22));
        assert_eq!(g.admit(24, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(23));

        // Fairness turn.
        assert_eq!(g.pop_ready(), Some(10));

        // Warm fairness: one critical then normal, instead of another full burst.
        assert_eq!(g.pop_ready(), Some(24));
        assert_eq!(g.pop_ready(), Some(11));
    }

    #[test]
    fn ghost_lane_seen_entry_does_not_misclassify_fresh_ingress_as_duplicate() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew: lane-local seen set contains a stale id
        // that is not present in either queue.
        g.normal.seen.insert(77);

        // Fresh ingress for the ghost id should still admit (not duplicate).
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn ghost_seen_global_entry_with_matching_cardinality_does_not_poison_fresh_admit() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 0, 1));

        // Simulate restored-state skew where lane-wide membership drifts while
        // cardinality stays aligned with queued work.
        g.seen_global.clear();
        g.seen_global.insert(77);
        assert_eq!(g.seen_global.len(), 1);

        // Fresh ingress for the ghost id must self-heal lane-wide membership and
        // admit cleanly instead of being misclassified as a duplicate.
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 1, 2));

        // The original queued id must remain globally deduped after the rebuild.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);
    }

    #[test]
    fn idle_lane_ghost_seen_entry_is_cleared_before_first_fresh_admission() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Simulate restored idle state with stale lane-local/global seen caches.
        g.normal.seen.insert(123);
        g.critical.seen.insert(456);
        g.seen_global.insert(789);
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // First fresh ingress must self-heal stale caches and admit cleanly.
        assert_eq!(g.admit(123, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn idle_pop_clears_nonzero_capacity_ghost_seen_before_next_fresh_retry() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Simulate restored idle state with stale duplicate metadata plus fairness.
        g.normal.seen.insert(123);
        g.critical.seen.insert(456);
        g.seen_global.insert(789);
        g.critical_served_streak = 1;
        assert_eq!(g.queued_counts(), (0, 0, 0));

        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.admit(789, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));
    }

    #[test]
    fn zero_critical_reserve_preserves_normal_capacity_with_critical_spillover() {
        let mut g = LaneAdmissionGate::new(3, 0);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(4, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        // With zero reserve configured, critical ingress still has a path via
        // spillover into free normal capacity once pressure clears.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn spillover_admission_remains_globally_idempotent_until_drained() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Keep one free total slot while saturating the critical reserve, then
        // force a critical tx to spill into normal capacity.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);

        // Even though tx 51 was admitted via spillover, duplicate admission from
        // either ingress class must still be rejected until it is drained.
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Drain until tx 51 leaves the queue, then re-admission is allowed.
        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.pop_ready(), Some(51));
        assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn backpressured_tx_id_is_not_marked_seen_and_can_be_admitted_after_drain() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);

        // tx 3 is backpressured at global capacity; this must not poison global
        // idempotency tracking.
        assert_eq!(
            g.admit(3, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        // Once a slot is freed, tx 3 should admit cleanly (not duplicate).
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn critical_backpressured_tx_id_can_admit_from_other_class_after_drain() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);

        // Global capacity backpressures fresh critical ingress and must not poison
        // cross-class idempotency for the same tx id.
        assert_eq!(
            g.admit(30, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // Drain one critical and one normal so normal class has explicit headroom.
        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.pop_ready(), Some(10));

        // The previously backpressured id must still be treated as fresh.
        assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn reserve_only_normal_borrowed_admission_stays_globally_idempotent() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Normal lane has zero dedicated capacity, so normal ingress borrows
        // free headroom from critical capacity.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);

        // Even though tx 42 was admitted through borrowed critical headroom,
        // it must be globally deduped across both ingress classes.
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);

        // After drain, re-admission should proceed as a fresh tx id.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(42));
        assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn reserve_only_mode_keeps_fairness_streak_cold_during_spillover_drains() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Zero dedicated normal capacity (reserve-only): normal ingress borrows
        // critical headroom but fairness streak should stay cold.
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.critical_served_streak, 0);

        // Critical remains preferred when available and the streak remains reset.
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.critical_served_streak, 0);
        assert_eq!(g.pop_ready(), Some(11));
        assert_eq!(g.critical_served_streak, 0);
    }

    #[test]
    fn reserve_guarded_normal_retry_burst_keeps_queue_counts_flat_until_critical_slot_reopens() {
        let mut g = LaneAdmissionGate::new(5, 2);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // One aggregate slot remains free, but it is the final reserved critical slot.
        // Repeated same-class normal retries must stay backpressured and must not
        // perturb queue accounting until the critical backlog drains enough to
        // reopen borrowable headroom.
        for _ in 0..3 {
            assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Backpressured);
            assert_eq!(g.queued_counts(), (3, 1, 4));
        }

        assert_eq!(g.admit(5, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 2, 5));

        assert!(matches!(g.pop_ready(), Some(4) | Some(5)));
        assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        assert!(matches!(g.pop_ready(), Some(4) | Some(5)));
        assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
    }

    #[test]
    fn fairness_warmup_does_not_slow_critical_when_normal_lane_drains() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Build a short mixed backlog so fairness warmup is exercised.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Critical), AdmitOutcome::Accepted);

        // Fairness grants one normal turn after the critical burst limit is hit.
        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.pop_ready(), Some(10));

        // Once normal backlog is drained, critical throughput should continue
        // immediately without another fairness-induced detour.
        assert_eq!(g.pop_ready(), Some(21));

        // New critical ingress should keep making progress while normal remains empty.
        assert_eq!(g.admit(22, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(22));
    }

    #[test]
    fn newly_arrived_normal_backlog_gets_turn_during_critical_flood() {
        let mut g = LaneAdmissionGate::new(7, 3);

        // Build critical pressure and consume a few critical turns first.
        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(100));
        assert_eq!(g.pop_ready(), Some(101));

        // Normal traffic appears while critical lane stays backlogged.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

        // Anti-starvation target: once normal backlog appears under active
        // critical pressure, fairness should immediately grant a normal turn.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(102));
    }

    #[test]
    fn newly_arrived_critical_backlog_preempts_normal_flood_without_waiting_for_burst_reset() {
        let mut g = LaneAdmissionGate::new(8, 2);

        // Build only normal backlog and consume one normal turn.
        for id in 1..=4 {
            assert_eq!(g.admit(id, IngressClass::Normal), AdmitOutcome::Accepted);
        }
        assert_eq!(g.pop_ready(), Some(1));

        // Critical traffic appears while normal backlog remains active.
        assert_eq!(g.admit(900, IngressClass::Critical), AdmitOutcome::Accepted);

        // Critical ingress should preempt immediately to keep high-priority
        // latency bounded even during an existing normal flood.
        assert_eq!(g.pop_ready(), Some(900));
    }

    #[test]
    fn normal_fairness_warmup_survives_active_critical_refill() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Keep critical lane active first.
        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(100));

        // Normal backlog appears while critical pressure is still active.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);

        // Refill critical immediately so pressure remains continuous.
        assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);

        // Anti-starvation contract: fairness warmup must still force a normal turn
        // immediately (or at worst within one additional dequeue) under active
        // critical refill.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(101));
    }

    #[test]
    fn zero_capacity_admission_gate_does_not_poison_idempotency_after_backpressure() {
        let mut g = AdmissionGate::new(0);

        // Capacity exhaustion should reject ingress without marking tx ids as seen.
        assert_eq!(g.admit(7), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(7), AdmitOutcome::Backpressured);
        assert_eq!(g.pop_ready(), None);
    }

    #[test]
    fn zero_total_capacity_lane_gate_backpressures_all_ingress_without_poisoning_seen_ids() {
        let mut g = LaneAdmissionGate::new(0, 0);

        assert_eq!(
            g.admit(1, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(1, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(2, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.pop_ready(), None);
    }

    #[test]
    fn zero_total_capacity_preserves_duplicate_semantics_for_restored_seen_ids() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored-state backlog metadata while ingress remains hard-stopped.
        g.seen_global.insert(41);
        g.normal.seen.insert(41);
        g.critical.seen.insert(42);

        assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.pop_ready(), None);
    }

    #[test]
    fn duplicate_stays_duplicate_when_lane_is_globally_full() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(9, IngressClass::Critical), AdmitOutcome::Accepted);
        // Full-queue fast path must still preserve duplicate semantics.
        assert_eq!(g.admit(9, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(10, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn duplicate_semantics_survive_stale_seen_global_under_saturation() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate transient restored-state skew: tx 1 is still queued in lane-local
        // sets, but lane-wide idempotency cache is stale.
        g.seen_global.remove(&1);

        // Duplicate must still be detected under saturated fast-path.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(3, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn stale_seen_global_ghost_id_is_healed_without_false_duplicate_under_saturation() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew with preserved cardinality: the lane-wide
        // cache contains a ghost id and misses one actually queued id.
        g.seen_global.remove(&20);
        g.seen_global.insert(99);
        assert_eq!(g.seen_global.len(), 2);

        // Fresh ingress matching the ghost id must not be misclassified as duplicate.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // After the self-heal rebuild, the real queued id is deduped again.
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
    }

    #[test]
    fn stale_seen_global_ghost_id_cross_class_retry_stays_backpressured_until_drain() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew with preserved saturation cardinality: the
        // lane-wide cache drops the queued normal id and replaces it with a ghost id.
        g.seen_global.remove(&20);
        g.seen_global.insert(99);
        assert_eq!(g.seen_global.len(), 2);

        // Cross-class retries for the ghost id must remain Backpressured while the
        // lane is full; the ghost cache entry must not poison classification.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        // Once a real queued tx drains, the ghost id should admit as fresh on retry.
        assert!(matches!(g.pop_ready(), Some(10) | Some(20)));
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn queued_counts_track_spillover_and_drain() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.queued_counts(), (0, 0, 0));

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        // Critical reserve full; tx 51 spills into normal queue.
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.queued_counts(), (3, 0, 3));

        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.pop_ready(), Some(51));
        assert_eq!(g.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn seen_global_len_matches_lane_queues_across_spillover_and_drain() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.seen_global.len(), 0);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.seen_global.len(), 1);

        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        // Critical reserve full; tx 51 spills into normal queue.
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.seen_global.len(), 4);

        // Backpressured ids must not inflate the queued count invariant.
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.seen_global.len(), 4);

        let (_, _, total) = g.queued_counts();
        assert_eq!(g.seen_global.len(), total);

        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.pop_ready(), Some(1));
        let (_, _, total_after_drain) = g.queued_counts();
        assert_eq!(g.seen_global.len(), total_after_drain);
    }

    #[test]
    fn stale_seen_global_self_heals_without_dropping_duplicate_or_fresh_semantics() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate transient restored-state skew where lane-wide idempotency cache
        // is stale, but lane-local queues remain authoritative.
        g.seen_global.clear();

        // Non-saturated admission should self-heal from lane-local state first.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

        // Duplicate semantics for pre-existing queued ids must survive healing.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Fresh ids still admit until global capacity is reached.
        assert_eq!(g.admit(4, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.admit(5, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        let (_, _, total) = g.queued_counts();
        assert_eq!(g.seen_global.len(), total);
    }

    #[test]
    fn stale_seen_global_ghost_id_does_not_poison_fresh_admission_after_self_heal() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-wide cache carries a ghost id
        // that is not present in either lane queue.
        g.seen_global.insert(999);

        // Self-heal should rebuild from lane-local truth and keep fresh ingress live.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);

        // Queue is now globally full; ghost id must not appear as a duplicate.
        assert_eq!(
            g.admit(999, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // After one dequeue, the same id should admit as fresh.
        let drained = g.pop_ready();
        assert!(drained == Some(1) || drained == Some(2) || drained == Some(3));
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn drained_ghost_id_from_repaired_seen_global_can_reenter_as_fresh() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew with preserved cardinality: lane-wide cache
        // drops one real queued id and replaces it with a ghost id.
        g.seen_global.remove(&11);
        g.seen_global.insert(99);
        assert_eq!(g.seen_global.len(), 2);

        // The ghost id must not be treated as duplicate while the lane still has room.
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
        // Repair also restores duplicate semantics for the real queued id.
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Duplicate);

        // Once the repaired ghost-backed tx drains, the same id should be admitted
        // again as fresh instead of being poisoned by prior cache skew.
        let first = g.pop_ready();
        let second = g.pop_ready();
        let third = g.pop_ready();
        assert_eq!(first, Some(11));
        assert!(second == Some(10) || second == Some(99));
        assert!(third == Some(10) || third == Some(99));
        assert_ne!(second, third);
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn equal_cardinality_seen_global_skew_still_preserves_duplicate_semantics() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-wide cache keeps the same
        // cardinality but drops a queued id in favor of a ghost id.
        g.seen_global.remove(&10);
        g.seen_global.insert(999);
        assert_eq!(g.seen_global.len(), 2);

        // Duplicate for tx 10 must still be detected via lane-local truth.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Ghost id should not be treated as duplicate while lane still has room.
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn equal_cardinality_skew_under_saturation_keeps_fresh_ids_backpressured_not_duplicated() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Restore-state skew keeps cardinality aligned while replacing a queued id
        // with a ghost id in lane-wide cache.
        g.seen_global.remove(&10);
        g.seen_global.insert(999);
        assert_eq!(g.seen_global.len(), 2);

        // With queues saturated, fresh ids must remain backpressured (not duplicate)
        // even while duplicate semantics for queued ids still hold.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(999, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // After one dequeue, the previously fresh id can admit cleanly.
        assert!(matches!(g.pop_ready(), Some(10) | Some(11)));
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn pop_ready_self_heals_stale_seen_global_without_new_admission() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-wide cache drops queued ids and
        // only keeps ghost entries.
        g.seen_global.clear();
        g.seen_global.insert(999);

        // pop_ready should rebuild lane-wide cache from lane-local truth even when
        // no new admission occurs.
        let drained = g.pop_ready();
        assert!(drained == Some(1) || drained == Some(2));

        let (_, _, total) = g.queued_counts();
        assert_eq!(g.seen_global.len(), total);
        let survivor = if drained == Some(1) { 2 } else { 1 };
        assert!(g.seen_global.contains(&survivor));
        assert!(!g.seen_global.contains(&999));
    }

    #[test]
    fn pop_ready_self_heals_when_ghost_id_survives_successful_remove() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Keep queued ids so remove(id) succeeds, but inject a ghost entry that
        // should be pruned by post-pop cardinality self-heal.
        g.seen_global.insert(999);

        let drained = g.pop_ready();
        assert!(drained == Some(1) || drained == Some(2));

        let (_, _, total) = g.queued_counts();
        assert_eq!(g.seen_global.len(), total);
        assert!(!g.seen_global.contains(&999));
    }

    #[test]
    fn full_drain_clears_stale_lane_local_seen_without_waiting_for_next_admit() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew: stale ghost ids exist in lane-local seen sets.
        g.normal.seen.insert(7001);
        g.critical.seen.insert(7002);

        // Drain both queued txs.
        assert!(matches!(g.pop_ready(), Some(1) | Some(2)));
        assert!(matches!(g.pop_ready(), Some(1) | Some(2)));

        // Full-drain boundary should proactively clear stale lane-local seen caches.
        assert!(g.normal.seen.is_empty());
        assert!(g.critical.seen.is_empty());
        assert_eq!(g.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn full_drain_cold_resets_fairness_even_when_pop_self_heals_seen_global() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew right before the final drain: the lane still
        // has one real queued tx, but fairness bookkeeping is stale-hot and the
        // lane-wide id cache carries an extra ghost id that post-pop self-heal must prune.
        g.critical_served_streak = g.critical_burst_limit;
        g.seen_global.insert(999);

        assert_eq!(g.pop_ready(), Some(11));
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert!(g.seen_global.is_empty());
        assert_eq!(g.critical_served_streak, 0);
    }

    #[test]
    fn idle_self_heal_resets_stale_fairness_streak_before_new_mixed_ingress() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Simulate restored idle state with stale fairness/bookkeeping counters.
        g.critical_served_streak = g.critical_burst_limit;
        g.seen_global.insert(777);

        // Trigger idle self-heal path via first admission.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        // Then add critical ingress. This path should not arm fairness warmup because
        // normal backlog was already present before critical arrived.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);

        // Critical should not be spuriously preempted by stale fairness state.
        assert_eq!(g.pop_ready(), Some(1));
    }

    #[test]
    fn idle_pop_ready_self_heals_stale_restored_state_without_waiting_for_admit() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Simulate restored idle state where no queued work remains but lane-local,
        // lane-wide, and fairness bookkeeping are all stale-hot.
        g.normal.seen.insert(7001);
        g.critical.seen.insert(7002);
        g.seen_global.insert(7003);
        g.critical_served_streak = g.critical_burst_limit;
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // Idle dequeue polls should act as a self-heal boundary even before any new
        // ingress arrives.
        assert_eq!(g.pop_ready(), None);
        assert!(g.normal.seen.is_empty());
        assert!(g.critical.seen.is_empty());
        assert!(g.seen_global.is_empty());
        assert_eq!(g.critical_served_streak, 0);
    }

    #[test]
    fn full_drain_resets_fairness_streak_immediately_without_waiting_for_next_admit() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

        // Build non-zero fairness streak during critical service.
        assert_eq!(g.pop_ready(), Some(2));
        assert!(g.critical_served_streak > 0);

        // Drain remaining backlog completely.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // Full-drain boundary should cold-reset fairness immediately.
        assert_eq!(g.critical_served_streak, 0);
    }

    #[test]
    fn equal_cardinality_lane_seen_skew_does_not_false_duplicate_fresh_id() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew: lane-local seen/global caches keep cardinality
        // but replace a queued id with a ghost id.
        g.normal.seen.remove(&11);
        g.normal.seen.insert(999);
        g.seen_global.remove(&11);
        g.seen_global.insert(999);

        // Fresh ghost id must not be misclassified as duplicate.
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn stale_cross_lane_seen_membership_self_heals_before_duplicate_classification() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-local seen membership is swapped
        // across lanes while cardinalities remain unchanged.
        g.normal.seen.remove(&200);
        g.critical.seen.remove(&100);
        g.normal.seen.insert(100);
        g.critical.seen.insert(200);

        // Duplicate for a queued tx must still be detected after inline self-heal.
        assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Fresh ingress remains admitted while global capacity is still available.
        assert_eq!(g.admit(300, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn saturated_cross_lane_seen_membership_skew_keeps_duplicate_semantics() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-local seen membership is swapped
        // across lanes while cardinalities remain unchanged under saturation.
        g.normal.seen.remove(&200);
        g.critical.seen.remove(&100);
        g.normal.seen.insert(100);
        g.critical.seen.insert(200);

        // Duplicate for a queued tx must still be preserved even on the saturated
        // fast path, and a fresh id must remain backpressured instead of duplicate.
        assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(300, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn seen_global_duplicate_without_lane_local_membership_self_heals_and_stays_duplicate() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew: lane-wide cache still carries tx 1, while
        // lane-local seen caches lose it.
        g.critical.seen.remove(&1);

        // Duplicate must still be preserved after inline self-heal.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Fresh ingress should remain admissible while global capacity has headroom.
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn hard_stop_mode_preserves_duplicate_semantics_for_restored_backlog() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored-state backlog under a temporary hard-stop config.
        g.seen_global.insert(42);
        g.normal.seen.insert(42);

        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(7, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn hard_stop_mode_preserves_duplicate_semantics_across_ingress_classes() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored-state backlog where duplicate knowledge spans the
        // lane-wide cache and the opposite class's local cache.
        g.seen_global.insert(42);
        g.critical.seen.insert(42);

        // Replaying the same tx through either class must stay Duplicate even
        // though the queue itself is empty under temporary hard-stop mode.
        assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);

        // Distinct fresh ids must still be backpressured while the stop is active.
        assert_eq!(
            g.admit(7, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn hard_stop_mode_lane_local_duplicate_survives_repeated_cross_class_probes_without_poisoning_fresh_ids(
    ) {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored-state duplicate knowledge carried only by lane-local
        // caches while the lane-wide cache is temporarily empty.
        g.normal.seen.insert(55);

        // Repeated probes through either ingress class must continue to classify
        // the restored tx id as Duplicate instead of degrading to Backpressured.
        assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(55, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);

        // Fresh ids must remain backpressured and must not become duplicate on
        // subsequent retries just because hard-stop mode observed them before.
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn hard_stop_idle_pop_preserves_restored_duplicate_metadata() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate metadata while a temporary hard-stop keeps the
        // lane queue empty. Idle scheduler polls must not erase this knowledge.
        g.normal.seen.insert(41);
        g.critical.seen.insert(42);
        g.seen_global.insert(43);
        g.critical_served_streak = 7;

        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.pop_ready(), None);

        // Duplicate semantics for restored ids must survive idle polling in hard-stop
        // mode, while fairness bookkeeping still cold-resets.
        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(43, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.critical_served_streak, 0);

        // Fresh ids remain backpressured rather than being poisoned into duplicate.
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn hard_stop_fresh_retry_burst_keeps_backpressure_guard_flat_across_classes() {
        let mut g = LaneAdmissionGate::new(0, 0);

        for class in [
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
            IngressClass::Critical,
        ] {
            assert_eq!(g.admit(88, class), AdmitOutcome::Backpressured);
            assert!(g.seen_global.is_empty());
            assert!(g.normal.seen.is_empty());
            assert!(g.critical.seen.is_empty());
            assert_eq!(g.queued_counts(), (0, 0, 0));
        }
    }

    #[test]
    fn saturated_equal_cardinality_lane_local_ghost_seen_id_stays_backpressured_not_duplicate() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew under saturation with preserved lane-local
        // cardinality: one queued normal id is replaced by a ghost id while totals
        // stay aligned.
        g.normal.seen.remove(&20);
        g.normal.seen.insert(999);
        assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 2);

        // Fresh ingress matching the ghost id must remain backpressured at full
        // capacity, not be misclassified as duplicate.
        assert_eq!(
            g.admit(999, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // The real queued id must still be deduped correctly.
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
    }

    #[test]
    fn equal_cardinality_cross_lane_and_global_skew_self_heals_without_false_duplicate_or_poisoned_retry(
    ) {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew where lane-local membership is swapped across
        // lanes and lane-wide cache mirrors the same ghost replacement while keeping
        // total cardinality unchanged.
        g.normal.seen.remove(&200);
        g.critical.seen.remove(&100);
        g.normal.seen.insert(100);
        g.critical.seen.insert(999);
        g.seen_global.remove(&100);
        g.seen_global.remove(&200);
        g.seen_global.insert(100);
        g.seen_global.insert(999);
        assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 2);
        assert_eq!(g.seen_global.len(), 2);

        // Fresh ghost id must not be misclassified as duplicate while lane still has room.
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);

        // Inline self-heal must also restore duplicate semantics for the real queued ids.
        assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(200, IngressClass::Critical),
            AdmitOutcome::Duplicate
        );
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn pop_self_heal_prunes_ghost_seen_global_so_cross_class_retry_can_admit_after_drain() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew while globally full: lane-wide membership drops
        // one real queued id and replaces it with a ghost id, preserving cardinality.
        g.seen_global.remove(&21);
        g.seen_global.insert(99);
        assert_eq!(g.seen_global.len(), 3);

        // While saturated, the ghost id must stay fresh/backpressured rather than duplicate.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // Drain once to trigger pop-side self-heal and remove the saturation boundary.
        assert!(matches!(g.pop_ready(), Some(10) | Some(20)));
        assert_eq!(g.seen_global.len(), 2);
        assert!(!g.seen_global.contains(&99));

        // After self-heal plus freed capacity, the same ghost id must admit cleanly on a
        // cross-class retry instead of remaining poisoned by stale lane-wide membership.
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
    }
}
