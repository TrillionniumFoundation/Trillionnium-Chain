use std::collections::{HashSet, VecDeque};

mod typed_admission;

pub use typed_admission::{
    AdmissionReject, CanonicalSignerId, CanonicalTxDigest, ResourceLimits, SignedAdmissionHooks,
    SignedEnvelopeMetadata, SignedEnvelopeView, TypedAdmissionGate, TypedAdmitOutcome,
    DEFAULT_MAX_ADMISSION_BODY_BYTES,
};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaneQosSnapshot {
    pub normal_queued: usize,
    pub critical_queued: usize,
    pub total_queued: usize,
    pub normal_headroom: usize,
    pub critical_headroom: usize,
    pub total_headroom: usize,
    pub fresh_normal_admissible: bool,
    pub fresh_critical_admissible: bool,
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

        if self.queue.is_empty() && !self.seen.is_empty() {
            // Defensive self-heal for restored-state skew in standalone gate usage:
            // once the authoritative queue fully drains, no duplicate metadata
            // should survive to poison the next fresh admission batch.
            self.seen.clear();
        }

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
        if !(preserve_zero_capacity_seen && self.total_capacity == 0
            || self.normal.seen.is_empty()
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

    fn critical_has_borrowable_headroom(&self) -> bool {
        self.critical_free_slots() > 0
    }

    fn normal_uses_reserve_only_mode(&self) -> bool {
        self.normal.capacity == 0
    }

    fn normal_can_borrow_last_idle_critical_slot(&self) -> bool {
        !self.normal_uses_reserve_only_mode()
            && !self.critical_backlog_active()
            && self.critical_free_slots() == 1
    }

    fn normal_has_surplus_critical_headroom(&self) -> bool {
        self.critical_free_slots() > 1
    }

    fn normal_can_borrow_critical_headroom(&self) -> bool {
        if self.normal_uses_reserve_only_mode() {
            // Reserve-only mode keeps free-ingress throughput live by borrowing any
            // idle critical headroom because there is no dedicated normal lane.
            return self.critical_has_borrowable_headroom();
        }

        if self.normal_can_borrow_last_idle_critical_slot() {
            // Preserve one-slot burst throughput when the critical lane is still
            // idle, but let the guard snap shut as soon as critical backlog appears.
            return true;
        }

        // Once critical backlog appears, keep the final reserved slot protected and
        // only permit normal spillover against genuinely surplus critical headroom.
        self.normal_has_surplus_critical_headroom()
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

    fn classify_bounded_retry_probe(&self, is_duplicate: bool) -> AdmitOutcome {
        // Saturated/global-stop/reserve-guard retry probes all share the same
        // contract: queued ids stay Duplicate, fresh ids stay Backpressured, and
        // callers never drift into lane-specific admit paths just to rediscover
        // the same capacity guard.
        self.classify_duplicate_probe(is_duplicate)
    }

    fn classify_duplicate_or_retry_probe(
        &self,
        blocked: bool,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        self.classify_duplicate_after_open_headroom(is_duplicate)
            .or_else(|| self.classify_retry_probe_when_blocked(blocked, is_duplicate))
    }

    fn lane_has_global_headroom(&self, lane_total: usize) -> bool {
        lane_total < self.total_capacity
    }

    fn lane_is_globally_saturated(&self, lane_total: usize) -> bool {
        !self.lane_has_global_headroom(lane_total)
    }

    fn classify_retry_probe_when_blocked(
        &self,
        blocked: bool,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        blocked.then(|| self.classify_bounded_retry_probe(is_duplicate))
    }

    fn classify_duplicate_after_open_headroom(&self, is_duplicate: bool) -> Option<AdmitOutcome> {
        is_duplicate.then_some(AdmitOutcome::Duplicate)
    }

    fn classify_guarded_probe(
        &self,
        guard_blocks: bool,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        self.classify_duplicate_or_retry_probe(guard_blocks, is_duplicate)
    }

    fn classify_pre_admission_probe(
        &self,
        lane_total: usize,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        self.classify_guarded_probe(self.lane_is_globally_saturated(lane_total), is_duplicate)
    }

    fn reserve_slot_guard_blocks_with_lane_total(
        &self,
        lane_total: usize,
        class: IngressClass,
    ) -> bool {
        self.lane_backpressure_guard_blocks(class) && self.lane_has_global_headroom(lane_total)
    }

    fn classify_reserved_slot_guard_probe(
        &self,
        lane_total: usize,
        class: IngressClass,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        // When aggregate capacity remains but reserve policy blocks this ingress
        // class, preserve the same duplicate-vs-backpressure contract that the
        // saturated path already guarantees so bounded retries do not drift into
        // lane-specific admit paths.
        self.classify_guarded_probe(
            self.reserve_slot_guard_blocks_with_lane_total(lane_total, class),
            is_duplicate,
        )
    }

    fn classify_headroom_probe(
        &self,
        lane_total: usize,
        class: IngressClass,
        is_duplicate: bool,
    ) -> Option<AdmitOutcome> {
        self.classify_pre_admission_probe(lane_total, is_duplicate)
            .or_else(|| self.classify_reserved_slot_guard_probe(lane_total, class, is_duplicate))
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

    fn fresh_admissible(&self, class: IngressClass) -> bool {
        self.lane_has_global_headroom(self.lane_total())
            && !self.lane_backpressure_guard_blocks(class)
    }

    fn normal_backpressure_guard_blocks(&self) -> bool {
        !self.normal_has_admission_headroom()
    }

    fn critical_backpressure_guard_blocks(&self) -> bool {
        !self.critical_has_admission_headroom()
    }

    fn lane_backpressure_guard_blocks(&self, class: IngressClass) -> bool {
        match class {
            IngressClass::Normal => self.normal_backpressure_guard_blocks(),
            IngressClass::Critical => self.critical_backpressure_guard_blocks(),
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
                    // Self-heal both lane-local and lane-wide caches immediately when
                    // authoritative queue membership contradicts stale seen sets so
                    // repeated retry bursts do not keep limping on partial repairs.
                    self.rebuild_seen_from_queues();
                    is_duplicate = self.seen_global.contains(&tx_id);
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
                    //
                    // Borrowed normal ingress is queued on the critical side on
                    // purpose, so the reopened reserved slot stays represented by
                    // the same dequeue / duplicate-accounting path until it drains.
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
    fn prefer_normal_on_pop(&self) -> bool {
        self.normal_has_dedicated_capacity
            && self.critical_served_streak >= self.critical_burst_limit
            && !self.normal.queue.is_empty()
    }

    fn record_pop_fairness(&mut self, served_critical: bool) {
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

    pub fn queued_counts(&self) -> (usize, usize, usize) {
        let normal = self.normal.queue.len();
        let critical = self.critical.queue.len();
        let total = self.lane_total();

        debug_assert_eq!(normal.saturating_add(critical), total);

        (normal, critical, total)
    }

    pub fn qos_snapshot(&self) -> LaneQosSnapshot {
        let normal_queued = self.normal.queue.len();
        let critical_queued = self.critical.queue.len();
        let total_queued = self.lane_total();
        let normal_headroom = self.normal.capacity.saturating_sub(normal_queued);
        let critical_headroom = self.critical.capacity.saturating_sub(critical_queued);
        let total_headroom = self.total_capacity.saturating_sub(total_queued);
        let fresh_normal_admissible = self.fresh_admissible(IngressClass::Normal);
        let fresh_critical_admissible = self.fresh_admissible(IngressClass::Critical);

        debug_assert_eq!(normal_queued.saturating_add(critical_queued), total_queued);

        LaneQosSnapshot {
            normal_queued,
            critical_queued,
            total_queued,
            normal_headroom,
            critical_headroom,
            total_headroom,
            fresh_normal_admissible,
            fresh_critical_admissible,
        }
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
    fn qos_snapshot_reports_lane_and_global_headroom() {
        let mut g = LaneAdmissionGate::new(5, 2);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 3,
                critical_headroom: 2,
                total_headroom: 5,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Accepted);

        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 1,
                critical_queued: 2,
                total_queued: 3,
                normal_headroom: 2,
                critical_headroom: 0,
                total_headroom: 2,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_tracks_zero_reserve_spillover_headroom() {
        let mut g = LaneAdmissionGate::new(2, 0);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);

        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 1,
                critical_queued: 0,
                total_queued: 1,
                normal_headroom: 1,
                critical_headroom: 0,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_fail_closes_in_zero_capacity_hard_stop_mode() {
        let mut g = LaneAdmissionGate::new(0, 0);

        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        assert_eq!(
            g.admit(10, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(11, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.pop_ready(), None);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn zero_capacity_hard_stop_duplicate_probe_noise_keeps_qos_snapshot_flat() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge while the lane remains fail-closed.
        // Duplicate probes from either ingress class must not fabricate queue or
        // headroom state, and fresh retry noise must remain pure backpressure.
        g.normal.seen.insert(41);

        let hard_stop_snapshot = g.qos_snapshot();
        assert_eq!(
            hard_stop_snapshot,
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), hard_stop_snapshot);

        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), hard_stop_snapshot);

        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), hard_stop_snapshot);

        assert_eq!(
            g.admit(100, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), hard_stop_snapshot);

        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.qos_snapshot(), hard_stop_snapshot);
    }

    #[test]
    fn zero_capacity_hard_stop_idle_polls_preserve_restored_duplicate_knowledge_from_all_seen_caches(
    ) {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate metadata skew across every seen cache. Idle
        // polls in hard-stop mode must preserve this recovery knowledge instead of
        // silently clearing it before a real queue-backed drain can occur.
        g.critical.seen.insert(55);
        g.seen_global.insert(55);

        for _ in 0..3 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.admit(55, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(
                g.qos_snapshot(),
                LaneQosSnapshot {
                    normal_queued: 0,
                    critical_queued: 0,
                    total_queued: 0,
                    normal_headroom: 0,
                    critical_headroom: 0,
                    total_headroom: 0,
                    fresh_normal_admissible: false,
                    fresh_critical_admissible: false,
                }
            );
        }

        assert_eq!(
            g.admit(56, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(56, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
    }

    #[test]
    fn qos_snapshot_zero_reserve_recloses_after_critical_spillover_consumes_last_normal_slot() {
        let mut g = LaneAdmissionGate::new(2, 0);

        // With zero reserved critical capacity, fresh critical ingress reaches the
        // mempool only via spillover into normal headroom.
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 1,
                critical_queued: 0,
                total_queued: 1,
                normal_headroom: 1,
                critical_headroom: 0,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Once the final normal slot is also consumed by critical spillover,
        // observability must fail closed for both ingress classes.
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn qos_snapshot_zero_reserve_recloses_after_normal_ingress_consumes_last_shared_slot() {
        let mut g = LaneAdmissionGate::new(2, 0);

        // Zero-reserve mode routes both ingress classes through shared normal
        // headroom, so a plain normal occupant should also consume public
        // admissibility exactly like critical spillover does.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 1,
                critical_queued: 0,
                total_queued: 1,
                normal_headroom: 1,
                critical_headroom: 0,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Once the final shared slot is consumed by normal ingress, QoS must fail
        // closed for both classes because zero-reserve mode exposes no hidden
        // critical-only headroom.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn duplicate_probe_does_not_consume_reopened_zero_reserve_shared_slot() {
        let mut g = LaneAdmissionGate::new(2, 0);

        // Zero-reserve mode routes both ingress classes through the same shared
        // normal lane. After one real drain reopens headroom, duplicate probes
        // against the surviving id must remain purely classificatory.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(1));

        let reopened_snapshot = LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 0,
            total_queued: 1,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), reopened_snapshot);

        // The queued shared-lane id must stay globally duplicate across classes
        // without consuming the reopened slot or perturbing QoS observability.
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), reopened_snapshot);

        // The slot remains genuinely available for fresh ingress immediately after.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn zero_reserve_full_shared_queue_keeps_qos_flat_across_cross_class_duplicate_and_retry_noise()
    {
        let mut g = LaneAdmissionGate::new(2, 0);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        let saturated_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), saturated_snapshot);

        // Under zero reserve, a queued normal id retried through the critical path
        // must stay Duplicate, while a fresh critical retry must stay Backpressured.
        // Neither probe may perturb queue accounting or the public QoS surface.
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(g.queued_counts(), (2, 0, 2));

        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(g.queued_counts(), (2, 0, 2));
    }

    #[test]
    fn qos_snapshot_tracks_critical_spillover_into_free_normal_headroom() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 1, 2));

        // Critical reserve is already full, but the second critical tx spilled into
        // free normal capacity. Observability must keep advertising fresh critical
        // admissibility while spare normal headroom remains available for spillover.
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 1,
                critical_queued: 1,
                total_queued: 2,
                normal_headroom: 2,
                critical_headroom: 0,
                total_headroom: 2,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_tracks_reserve_only_headroom_while_critical_backlog_is_active() {
        let mut g = LaneAdmissionGate::new(3, 3);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));

        // Reserve-only mode has no dedicated normal queue, but fresh normal ingress
        // should still be reported admissible while aggregate headroom remains.
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 2,
                total_headroom: 2,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_stops_advertising_fresh_critical_after_reserve_only_normal_borrows_last_slot() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Reserve-only mode: normal ingress borrows from critical headroom because
        // there is no dedicated normal capacity.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Once the last reserve-only slot is also borrowed by normal traffic,
        // observability must stop advertising fresh critical headroom.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 2,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn qos_snapshot_stops_advertising_fresh_normal_after_reserve_only_critical_consumes_last_slot()
    {
        let mut g = LaneAdmissionGate::new(2, 2);

        // In reserve-only mode, all ingress shares the critical queue, so the
        // public QoS contract must fail closed regardless of which class consumes
        // the final shared slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Once the last shared slot is consumed by critical ingress, both classes
        // must see the reserve-only lane as closed to fresh admission.
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 2,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn reserve_only_active_critical_backlog_fresh_normal_retry_keeps_qos_snapshot_flat() {
        let mut g = LaneAdmissionGate::new(3, 3);

        // Reserve-only mode routes both classes through the shared critical lane.
        // While aggregate headroom remains, both classes should still see fresh
        // admission as available.
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        let open_snapshot = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 1,
            total_queued: 1,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), open_snapshot);

        // Additional critical backlog should keep the same operator-facing QoS
        // contract open until the shared reserve-only queue actually saturates.
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        let still_open_snapshot = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), still_open_snapshot);

        // Fresh normal retry noise while headroom remains must admit cleanly and
        // only then consume the final shared slot, rather than perturbing the open
        // snapshot beforehand.
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
        let saturated_snapshot = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 3,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), saturated_snapshot);

        // Once saturated, repeated fresh normal retries must stay backpressured and
        // leave the public QoS surface flat until a real drain reopens capacity.
        assert_eq!(
            g.admit(100, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(g.queued_counts(), (0, 3, 3));
    }

    #[test]
    fn reserve_only_borrowed_last_slot_probe_noise_keeps_qos_snapshot_flat_until_drain() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // In reserve-only mode, normal ingress borrows critical capacity. Once the
        // final slot is consumed by borrowed normal traffic, both classes must
        // observe the lane as fail-closed until a dequeue reopens headroom.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        let borrowed_snapshot = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 2,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);

        // Duplicate probes for the borrowed occupant and fresh retry noise from the
        // opposite class must not perturb operator-facing QoS while the final slot
        // remains consumed.
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(g.queued_counts(), (0, 2, 2));

        // After one borrowed occupant drains, both classes should immediately see
        // reserve-only headroom reopen for fresh ingress.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
    }

    #[test]
    fn qos_snapshot_exposes_guarded_class_admissibility_not_just_raw_headroom() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Fill dedicated normal capacity, then activate critical backlog while one
        // aggregate slot still remains reserved for fresh critical ingress.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 3,
                critical_queued: 1,
                total_queued: 4,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_reports_borrowed_last_critical_slot_as_consumed() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity first.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                // With the critical lane idle, normal ingress may still borrow the
                // final reserved slot for free-ingress throughput.
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Borrow the last reserved critical slot. Observability must stop advertising
        // fresh critical headroom once that slot is actually consumed by borrowed work.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 1,
                total_queued: 3,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn qos_snapshot_reopens_borrowed_last_critical_slot_after_critical_lane_drains() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity, then borrow the final idle reserved slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // While the borrowed reserved slot is occupied, no class has fresh headroom.
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        // Once the borrowed critical-lane occupant drains and the critical lane goes
        // idle again, observability must immediately advertise that the final reserved
        // slot is borrowable for fresh normal ingress again.
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.queued_counts(), (2, 0, 2));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn borrowed_last_critical_slot_probe_noise_keeps_qos_snapshot_flat_until_drain() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity, then borrow the final idle critical slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        let borrowed_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);

        // Duplicate probes for the borrowed occupant and fresh critical retry noise
        // must not perturb the public QoS surface while the last reserved slot stays
        // consumed by borrowed normal work.
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // After the borrowed occupant drains, that same critical tx id should admit
        // cleanly again and QoS should reopen immediately.
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn borrowed_last_critical_slot_same_class_duplicate_probe_keeps_qos_snapshot_flat() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity, then borrow the final idle critical slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        let borrowed_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);

        // Same-class duplicate probes for the borrowed normal occupant must stay
        // Duplicate and must not perturb queue accounting or the public QoS surface.
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // Fresh normal retry noise must also stay fail-closed while the borrowed
        // reserved slot remains occupied.
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), borrowed_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn qos_snapshot_keeps_last_reserved_critical_slot_guarded_under_active_backlog() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Fill dedicated normal capacity while leaving exactly one reserved critical
        // slot free under active critical backlog.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 1,
                total_queued: 3,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                // Active critical backlog keeps the last reserved slot guarded,
                // so only fresh critical ingress remains admissible here.
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );

        // Fresh normal ingress must stay fail-closed here: the final reserved
        // critical slot cannot be borrowed while critical backlog is active.
        assert_eq!(
            g.admit(3, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (2, 1, 3));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 1,
                total_queued: 3,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_stays_flat_across_guarded_duplicate_and_fresh_normal_probe_noise() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Fill dedicated normal capacity while leaving exactly one reserved critical
        // slot guarded by active critical backlog.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Under the reserve guard, already queued ids must stay Duplicate while fresh
        // normal retries stay Backpressured, and neither probe may perturb the
        // operator-facing QoS snapshot.
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn qos_snapshot_stays_flat_across_guarded_same_class_duplicate_probe_noise() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Leave one aggregate slot free, but keep it reserved for fresh critical
        // ingress while dedicated normal capacity is already exhausted.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Same-class duplicate probes against the queued critical id must remain
        // Duplicate and must not perturb the public QoS surface while the final
        // reserved slot stays guarded.
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn guarded_last_reserved_slot_recloses_qos_after_fresh_critical_claims_it() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Leave one aggregate slot free, but keep it reserved exclusively for fresh
        // critical ingress while dedicated normal capacity is already exhausted.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Once a fresh critical tx claims the final reserved slot, QoS must
        // immediately fail closed for both classes.
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        let saturated_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 2,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(g.queued_counts(), (2, 2, 4));

        // Under the now-saturated lane, a queued critical id must still dedupe and
        // a fresh normal probe must remain backpressured without perturbing QoS.
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), saturated_snapshot);
        assert_eq!(g.queued_counts(), (2, 2, 4));
    }

    #[test]
    fn guarded_last_reserved_slot_keeps_queued_normal_retry_duplicate() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Fill dedicated normal capacity while leaving one aggregate slot guarded
        // for fresh critical ingress.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Even though fresh normal ingress is blocked by the reserve guard, an
        // already queued normal tx id must stay Duplicate rather than degrading to
        // Backpressured.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn guarded_last_reserved_slot_keeps_cross_class_normal_duplicate_flat() {
        let mut g = LaneAdmissionGate::new(4, 2);

        // Fill dedicated normal capacity while leaving one aggregate slot guarded
        // for fresh critical ingress.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // The lane-wide duplicate set is authoritative across ingress classes.
        // Under the reserve guard, probing a queued normal id through the critical
        // path must stay Duplicate and must not perturb the public QoS surface.
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.queued_counts(), (2, 1, 3));
    }

    #[test]
    fn qos_snapshot_resets_cleanly_after_spillover_full_drain_and_idle_poll() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        // Critical reserve full; tx 51 spills into borrowed normal capacity.
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 3,
                critical_queued: 1,
                total_queued: 4,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.pop_ready(), Some(51));
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // Idle dequeue polls are the self-heal boundary for long-lived schedulers;
        // observability should also cold-reset here instead of reporting stale
        // spillover occupancy or blocked class headroom.
        assert_eq!(g.pop_ready(), None);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 3,
                critical_headroom: 1,
                total_headroom: 4,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_reopens_critical_admissibility_as_soon_as_dedicated_reserve_reopens() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Fill normal capacity, then force one critical tx to spill into normal
        // capacity while another occupies the dedicated reserve slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        // Draining the dedicated critical occupant should immediately reopen fresh
        // critical admissibility even though an older critical copy still occupies
        // borrowed normal capacity.
        assert_eq!(g.pop_ready(), Some(50));
        assert_eq!(g.queued_counts(), (3, 0, 3));
        assert!(g.qos_snapshot().fresh_critical_admissible);
        assert!(g.qos_snapshot().fresh_normal_admissible);
    }

    #[test]
    fn reopened_dedicated_critical_reserve_keeps_qos_snapshot_flat_under_duplicate_probe_noise() {
        let mut g = LaneAdmissionGate::new(4, 1);

        // Fill normal capacity and force one critical tx to spill into normal
        // capacity while another occupies the dedicated critical reserve slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(50, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // Once the dedicated reserve occupant drains, the older spilled critical copy
        // must remain globally duplicate while operator-facing QoS advertises the
        // reopened reserve headroom consistently.
        assert_eq!(g.pop_ready(), Some(50));
        let reopened_snapshot = LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 0,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), reopened_snapshot);

        assert_eq!(g.admit(51, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), reopened_snapshot);
        assert_eq!(g.admit(51, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), reopened_snapshot);
        assert_eq!(g.queued_counts(), (3, 0, 3));
    }

    #[test]
    fn qos_snapshot_reopens_normal_only_after_critical_backlog_fully_clears() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Fill dedicated normal capacity and leave exactly one guarded critical
        // slot while critical backlog is active.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(g.qos_snapshot().fresh_critical_admissible);

        // Once the only active critical backlog clears, normal admissibility may
        // reopen immediately because the final reserved slot is no longer guarded.
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.queued_counts(), (3, 0, 3));
        assert!(g.qos_snapshot().fresh_normal_admissible);
        assert!(g.qos_snapshot().fresh_critical_admissible);
    }

    #[test]
    fn qos_snapshot_keeps_normal_closed_until_last_active_critical_backlog_entry_drains() {
        let mut g = LaneAdmissionGate::new(6, 2);

        // Exhaust dedicated normal capacity while keeping two critical occupants
        // active so the final reserved slot stays guarded after only one drain.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (4, 2, 6));
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        // Draining one critical entry reopens aggregate headroom, but normal must
        // stay fail-closed because critical backlog is still active and guards the
        // last reserved slot for fresh critical ingress only.
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.queued_counts(), (4, 1, 5));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 4,
                critical_queued: 1,
                total_queued: 5,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );

        // Only after the last active critical backlog entry drains may the normal
        // class borrow again from the now-idle reserved slot.
        assert_eq!(g.pop_ready(), Some(11));
        assert_eq!(g.queued_counts(), (4, 0, 4));
        assert!(g.qos_snapshot().fresh_normal_admissible);
        assert!(g.qos_snapshot().fresh_critical_admissible);
    }

    #[test]
    fn qos_snapshot_keeps_normal_closed_when_only_critical_spillover_headroom_remains() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Fill the dedicated normal lane and occupy one reserved critical slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // One aggregate slot remains, but it is reachable only by fresh critical
        // spillover into the still-free normal headroom. Fresh normal ingress must
        // stay closed because the last reserved critical slot is guarded.
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 3,
                critical_queued: 1,
                total_queued: 4,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn critical_spillover_only_headroom_keeps_normal_closed_across_duplicate_and_retry_noise() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Leave exactly one aggregate slot free, but make it reachable only by fresh
        // critical spillover into normal headroom while the final reserved critical
        // slot remains guarded against normal ingress.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        let spillover_only_snapshot = LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), spillover_only_snapshot);

        // Cross-class retries of the already queued normal occupant must remain
        // Duplicate, and fresh normal retry noise must remain Backpressured, without
        // perturbing the operator-facing QoS contract.
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), spillover_only_snapshot);
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), spillover_only_snapshot);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // The remaining aggregate slot is still genuinely available only to fresh
        // critical ingress. Because one dedicated critical slot is still free, the
        // next critical tx should claim that final reserved slot directly, and QoS
        // must then fail closed for both classes immediately.
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 2, 5));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 3,
                critical_queued: 2,
                total_queued: 5,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );
    }

    #[test]
    fn qos_snapshot_resets_cleanly_after_reserve_only_full_drain_and_idle_poll() {
        let mut g = LaneAdmissionGate::new(3, 3);

        // Reserve-only mode routes all ingress through critical capacity.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 3, 3));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 3,
                total_queued: 3,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.queued_counts(), (0, 0, 0));

        // After the full drain and one idle scheduler poll, observability should
        // reopen reserve-only borrowed headroom for both ingress classes.
        assert_eq!(g.pop_ready(), None);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 3,
                total_headroom: 3,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn qos_snapshot_reopens_both_classes_immediately_after_one_reserve_only_drain() {
        let mut g = LaneAdmissionGate::new(3, 3);

        // Reserve-only mode routes both ingress classes through critical capacity,
        // so once aggregate headroom reappears it should be advertised to both
        // classes immediately without waiting for a full drain or idle poll.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 3, 3));
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.queued_counts(), (0, 2, 2));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 2,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
    }

    #[test]
    fn oversized_critical_reserve_clamp_reopens_both_classes_after_one_drain() {
        let mut g = LaneAdmissionGate::new(2, 99);

        // Oversized reserve clamps into reserve-only mode, so once the aggregate
        // queue saturates, draining a single occupant must immediately reopen the
        // shared admission surface for both ingress classes.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.queued_counts(), (0, 1, 1));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // The remaining queued id must still dedupe globally across classes, while
        // the reopened shared slot admits fresh work again.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
    }

    #[test]
    fn oversized_critical_reserve_clamps_to_reserve_only_without_leaking_fake_normal_headroom() {
        let mut g = LaneAdmissionGate::new(2, 99);

        // Misconfigured reserve > total must clamp into reserve-only mode rather
        // than exposing impossible dedicated normal headroom or admitting past the
        // aggregate anti-spam cap.
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 2,
                total_headroom: 2,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 2,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        // Under the clamped reserve-only split, queued ids must still dedupe
        // globally while fresh retries remain fail-closed until a real drain.
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Duplicate);
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
    fn oversized_critical_reserve_clamp_preserves_zero_capacity_hard_stop() {
        let mut g = LaneAdmissionGate::new(0, 99);

        // A misconfigured reserve larger than total capacity must still collapse
        // into the same fail-closed zero-capacity posture: no hidden headroom,
        // fresh ingress backpressured, restored duplicates preserved.
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        g.seen_global.insert(42);

        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(7, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot().total_headroom, 0);
        assert_eq!(g.queued_counts(), (0, 0, 0));
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
    fn critical_spillover_stays_fail_closed_once_dedicated_normal_headroom_is_gone() {
        let mut g = LaneAdmissionGate::new(3, 1);

        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 0,
                total_queued: 0,
                normal_headroom: 2,
                critical_headroom: 1,
                total_headroom: 3,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Consume all dedicated normal headroom while aggregate capacity remains.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 0, 2));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 0,
                total_queued: 2,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // The last aggregate slot is a real reserved critical slot, not hidden
        // spillover headroom: critical may claim it directly, then both classes
        // must observe the lane as fully closed.
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 1,
                total_queued: 3,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
        );

        assert_eq!(
            g.admit(11, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(11, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (2, 1, 3));
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
    fn normal_lane_can_still_borrow_surplus_reserved_headroom_while_critical_backlog_is_active() {
        let mut g = LaneAdmissionGate::new(5, 3);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 2,
                critical_headroom: 2,
                total_headroom: 4,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        // Even with active critical backlog, normal ingress may still consume only
        // genuinely surplus reserved headroom; the final reserved slot must remain guarded.
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(22, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 2, 4));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 2,
                total_queued: 4,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: false,
                fresh_critical_admissible: true,
            }
        );

        assert_eq!(
            g.admit(23, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (2, 2, 4));
    }

    #[test]
    fn reopened_surplus_reserved_headroom_is_borrowable_before_final_guard_slot() {
        let mut g = LaneAdmissionGate::new(5, 3);

        // Fill the dedicated normal lane first, then leave exactly one free reserved
        // critical slot while backlog remains active.
        assert_eq!(g.admit(20, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 2, 4));

        // With only the final guarded reserved slot free, fresh normal ingress must stay blocked.
        assert_eq!(
            g.admit(22, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (2, 2, 4));

        // After one critical dequeue, backlog is still active but one surplus reserved
        // slot reopens. Normal ingress may borrow that surplus slot only, while the
        // final reserved critical slot remains guarded.
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.queued_counts(), (2, 1, 3));
        assert_eq!(g.admit(22, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 2, 4));
        assert_eq!(
            g.admit(23, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.admit(12, IngressClass::Critical), AdmitOutcome::Accepted);
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
    fn guarded_normal_retry_stays_fresh_until_all_active_critical_backlog_clears() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Fill dedicated normal capacity and arm active critical backlog while one
        // aggregate slot remains reachable only by fresh critical spillover.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(g.qos_snapshot().fresh_critical_admissible);

        // A fresh normal id is reserve-guarded here and must stay fresh on retry.
        assert_eq!(
            g.admit(77, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(77, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // Fresh critical ingress may still claim the final guarded slot.
        assert_eq!(g.admit(91, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 2, 5));
        assert_eq!(
            g.admit(77, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        // Draining only one critical item still leaves active critical backlog, so the
        // same normal id must remain fresh-but-guarded instead of becoming duplicate.
        assert_eq!(g.pop_ready(), Some(90));
        assert_eq!(
            g.admit(77, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );

        // Once critical backlog fully clears, the earlier guarded id should admit as
        // fresh rather than being poisoned by stale anti-spam metadata.
        assert_eq!(g.pop_ready(), Some(91));
        assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
    }

    #[test]
    fn guarded_normal_retry_can_escalate_via_critical_path_without_pre_poisoning_duplicate_state() {
        let mut g = LaneAdmissionGate::new(5, 2);

        // Fill dedicated normal capacity and arm active critical backlog while one
        // aggregate slot remains reachable only by fresh critical spillover.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

        // A fresh normal id blocked by the reserve guard must remain fresh, not become
        // duplicate metadata just because it first arrived through the normal path.
        assert_eq!(
            g.admit(77, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // The same tx id may still claim the final guarded slot through the critical
        // path, and only after that real admission should duplicate semantics engage.
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 2, 5));
        assert_eq!(g.admit(77, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(77, IngressClass::Critical), AdmitOutcome::Duplicate);
    }

    #[test]
    fn borrowed_last_idle_critical_slot_reopens_critical_retry_after_drain() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity, then borrow the last idle critical slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // While the borrowed slot is occupied, repeated critical retries must stay
        // fail-closed rather than bypassing reserve protection.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        // Draining the borrowed normal occupant should immediately reopen that last
        // reserved slot for fresh critical ingress.
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
    }

    #[test]
    fn borrowed_last_idle_critical_slot_keeps_cross_class_fresh_retry_unpoisoned_until_drain() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Fill dedicated normal capacity, then borrow the last idle critical slot.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // A fresh critical tx blocked by the borrowed slot must remain fresh across
        // cross-class retry noise instead of being poisoned into lane-wide duplicate
        // metadata while reserve protection is still active.
        assert_eq!(
            g.admit(99, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (2, 1, 3));

        // Once the borrowed occupant drains, the same tx id should still admit as
        // fresh through the critical path and only then become globally duplicate.
        assert_eq!(g.pop_ready(), Some(3));
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Duplicate);
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
    fn reserve_only_stale_seen_metadata_does_not_hide_reopened_shared_slot() {
        let mut g = LaneAdmissionGate::new(2, 2);

        assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.qos_snapshot().total_headroom, 0);
        assert!(!g.qos_snapshot().fresh_normal_admissible);
        assert!(!g.qos_snapshot().fresh_critical_admissible);

        // Once one real occupant drains, reserve-only mode should immediately
        // reopen the shared slot for both ingress classes. Stale critical seen
        // metadata alone must not pin the public contract in a phantom fail-closed
        // state.
        assert_eq!(g.pop_ready(), Some(41));
        g.critical.seen.insert(777);
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );
        assert_eq!(g.admit(43, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(43, IngressClass::Critical), AdmitOutcome::Duplicate);
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
    fn critical_spillover_duplicate_probe_stays_globally_duplicate_until_spilled_copy_drains() {
        let mut g = LaneAdmissionGate::new(4, 2);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);

        // Fill free normal headroom via critical spillover while keeping one of the
        // spilled tx ids live across both ingress classes.
        assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 2, 3));

        // Even though tx 102 spilled into normal capacity, duplicate probes from
        // either class must remain Duplicate until the queued copy drains.
        assert_eq!(
            g.admit(102, IngressClass::Critical),
            AdmitOutcome::Duplicate
        );
        assert_eq!(g.admit(102, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.queued_counts(), (1, 2, 3));

        // Re-admission stays blocked until the spilled copy itself leaves the queue,
        // regardless of whether fairness pops it before or after the reserved
        // critical backlog.
        let first = g.pop_ready();
        assert!(matches!(first, Some(100) | Some(101) | Some(102)));
        if first != Some(102) {
            assert_eq!(g.admit(102, IngressClass::Normal), AdmitOutcome::Duplicate);
            let second = g.pop_ready();
            assert!(matches!(second, Some(100) | Some(101) | Some(102)));
            if second != Some(102) {
                assert_eq!(g.admit(102, IngressClass::Normal), AdmitOutcome::Duplicate);
                assert_eq!(g.pop_ready(), Some(102));
            }
        }
        assert_eq!(g.admit(102, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn critical_spillover_duplicate_probe_keeps_qos_flat_until_final_dedicated_normal_slot_is_claimed(
    ) {
        let mut g = LaneAdmissionGate::new(4, 2);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(102, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 2, 3));

        let spillover_snapshot = LaneQosSnapshot {
            normal_queued: 1,
            critical_queued: 2,
            total_queued: 3,
            normal_headroom: 1,
            critical_headroom: 0,
            total_headroom: 1,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), spillover_snapshot);

        // The spilled critical occupant must stay globally duplicate across ingress
        // classes without perturbing operator-facing headroom.
        assert_eq!(g.admit(102, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.qos_snapshot(), spillover_snapshot);
        assert_eq!(g.queued_counts(), (1, 2, 3));

        // Because one dedicated normal slot is still genuinely free, fresh normal
        // ingress should claim that slot directly rather than being mistaken for
        // reserve-guarded retry noise.
        assert_eq!(g.admit(999, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (2, 2, 4));
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 2,
                critical_queued: 2,
                total_queued: 4,
                normal_headroom: 0,
                critical_headroom: 0,
                total_headroom: 0,
                fresh_normal_admissible: false,
                fresh_critical_admissible: false,
            }
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
    fn reserve_only_stale_hot_fairness_does_not_synthesize_normal_preemption() {
        let mut g = LaneAdmissionGate::new(2, 2);

        assert_eq!(g.admit(10, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(11, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate stale restored-state bookkeeping: reserve-only mode should still
        // refuse to synthesize a dedicated-normal fairness turn.
        g.critical_served_streak = g.critical_burst_limit;
        assert_eq!(g.pop_ready(), Some(10));
        assert_eq!(g.critical_served_streak, 0);
        assert_eq!(g.pop_ready(), Some(11));
    }

    #[test]
    fn reserve_only_idle_self_heal_clears_stale_fairness_before_new_mixed_ingress() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Simulate restored idle state with stale-hot fairness bookkeeping.
        g.critical_served_streak = g.critical_burst_limit;

        // Idle scheduler polls should cold-reset fairness even in reserve-only mode.
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.critical_served_streak, 0);

        // New mixed ingress still shares the critical lane, so stale fairness must
        // not fabricate a dedicated-normal turn after the first critical dequeue.
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(21, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.pop_ready(), Some(20));
        assert_eq!(g.critical_served_streak, 0);
        assert_eq!(g.pop_ready(), Some(21));
    }

    #[test]
    fn reserve_only_backpressured_tx_id_stays_fresh_until_headroom_reopens() {
        let mut g = LaneAdmissionGate::new(2, 2);

        // Reserve-only mode routes both classes through critical capacity.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));

        // A fresh tx id rejected under aggregate saturation must remain fresh across
        // both ingress classes rather than poisoning cross-class idempotency.
        assert_eq!(
            g.admit(30, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(30, IngressClass::Critical),
            AdmitOutcome::Backpressured
        );

        assert_eq!(g.pop_ready(), Some(1));

        // Once headroom reopens, the previously backpressured id should admit
        // cleanly and then become globally Duplicate again.
        assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(30, IngressClass::Normal), AdmitOutcome::Duplicate);
    }

    #[test]
    fn reserve_only_reopened_shared_slot_ignores_stale_critical_seen_metadata() {
        let mut g = LaneAdmissionGate::new(2, 2);

        assert_eq!(g.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(71, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
        assert_eq!(g.critical_free_slots(), 0);
        assert!(!g.normal_can_borrow_critical_headroom());

        assert_eq!(g.pop_ready(), Some(70));

        // Reserve-only mode shares the critical lane across both classes, so stale
        // duplicate metadata alone must not fabricate active backlog or hide the
        // reopened shared slot from fresh ingress.
        g.critical.seen.insert(999);

        assert_eq!(g.critical_free_slots(), 1);
        assert!(g.normal_can_borrow_critical_headroom());
        assert_eq!(
            g.qos_snapshot(),
            LaneQosSnapshot {
                normal_queued: 0,
                critical_queued: 1,
                total_queued: 1,
                normal_headroom: 0,
                critical_headroom: 1,
                total_headroom: 1,
                fresh_normal_admissible: true,
                fresh_critical_admissible: true,
            }
        );

        assert_eq!(g.admit(72, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 2, 2));
        assert_eq!(g.seen_global.len(), 2);
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
            assert_eq!(
                g.admit(70, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
            assert_eq!(g.queued_counts(), (3, 1, 4));
        }

        assert_eq!(g.admit(5, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 2, 5));

        assert!(matches!(g.pop_ready(), Some(4) | Some(5)));
        assert_eq!(
            g.admit(70, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.queued_counts(), (3, 1, 4));

        assert!(matches!(g.pop_ready(), Some(4) | Some(5)));
        assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
    }

    #[test]
    fn reserve_guarded_normal_duplicate_probe_stays_duplicate_until_critical_copy_drains() {
        let mut g = LaneAdmissionGate::new(5, 2);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        // Aggregate headroom remains, but the final free slot is reserved for critical
        // traffic. A retry of the already-queued critical tx id from the normal class
        // must stay Duplicate rather than drifting to Backpressured.
        assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        assert_eq!(g.pop_ready(), Some(70));
        assert_eq!(g.admit(70, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));
    }

    #[test]
    fn reserve_guarded_fresh_normal_retry_stays_fresh_until_critical_backlog_clears() {
        let mut g = LaneAdmissionGate::new(5, 2);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(70, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (3, 1, 4));

        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 3,
            critical_queued: 1,
            total_queued: 4,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.seen_global.len(), 4);

        // Fresh normal ingress is blocked by the final reserved critical slot, but the
        // rejected tx id must stay fresh rather than poisoning cross-class dedupe.
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(
            g.admit(99, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), guarded_snapshot);
        assert_eq!(g.queued_counts(), (3, 1, 4));
        assert_eq!(g.seen_global.len(), 4);

        // Once the active critical backlog drains, the previously guarded tx id should
        // admit cleanly instead of being misclassified as a duplicate.
        assert_eq!(g.pop_ready(), Some(70));
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Accepted);
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
    fn duplicate_or_backpressured_probe_noise_does_not_mutate_fairness_state() {
        let mut g = LaneAdmissionGate::new(3, 1);

        // Warm fairness under genuine mixed backlog.
        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.critical_served_streak, g.critical_burst_limit);

        let warmed = g.critical_served_streak;

        // Once the lane is saturated, duplicate and fresh retry probes must keep the
        // existing fairness state unchanged instead of masquerading as new backlog.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.critical_served_streak, warmed);

        assert_eq!(
            g.admit(9, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.critical_served_streak, warmed);
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
    fn zero_capacity_admission_gate_preserves_restored_duplicate_metadata_across_idle_polls() {
        let mut g = AdmissionGate::new(0);

        // Simulate restored duplicate knowledge while the standalone gate remains
        // fail-closed. Idle polls and noisy probes must not erase that metadata or
        // fabricate queue state.
        g.seen.insert(41);

        for _ in 0..3 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.admit(41), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(99), AdmitOutcome::Backpressured);
            assert!(g.queue.is_empty());
            assert!(g.seen.contains(&41));
            assert!(!g.seen.contains(&99));
        }
    }

    #[test]
    fn drained_standalone_duplicate_metadata_reopens_as_fresh_after_real_queue_drain() {
        let mut g = AdmissionGate::new(2);

        assert_eq!(g.admit(1), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2), AdmitOutcome::Accepted);

        // Simulate restored-state skew: duplicate metadata retains an extra ghost id
        // while one fresh id is still only blocked by saturation.
        g.seen.insert(99);
        assert_eq!(g.admit(99), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(100), AdmitOutcome::Backpressured);

        // Once the authoritative queue fully drains, stale duplicate metadata must
        // be cleared immediately so earlier fresh retries can re-enter cleanly.
        assert_eq!(g.pop_ready(), Some(1));
        assert_eq!(g.pop_ready(), Some(2));
        assert!(g.seen.is_empty());
        assert_eq!(g.admit(99), AdmitOutcome::Accepted);
        assert_eq!(g.admit(100), AdmitOutcome::Accepted);
    }

    #[test]
    fn drained_standalone_fresh_retry_reopens_cleanly_across_idle_polls() {
        let mut g = AdmissionGate::new(1);

        assert_eq!(g.admit(7), AdmitOutcome::Accepted);

        // A fresh retry under saturation must stay backpressured without entering
        // duplicate tracking.
        assert_eq!(g.admit(8), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(8), AdmitOutcome::Backpressured);

        // After a real full drain, repeated idle polls must not leave behind stale
        // duplicate metadata that poisons the earlier fresh retry.
        assert_eq!(g.pop_ready(), Some(7));
        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.pop_ready(), None);
        assert!(g.queue.is_empty());
        assert!(g.seen.is_empty());

        // The previously backpressured id must still admit as fresh and only then
        // become Duplicate.
        assert_eq!(g.admit(8), AdmitOutcome::Accepted);
        assert_eq!(g.admit(8), AdmitOutcome::Duplicate);
    }

    #[test]
    fn full_drain_clears_stale_seen_ghosts_before_next_fresh_admission() {
        let mut g = AdmissionGate::new(2);

        assert_eq!(g.admit(21), AdmitOutcome::Accepted);
        assert_eq!(g.admit(22), AdmitOutcome::Accepted);

        // Simulate restored-state skew: metadata retains a ghost id that is not
        // actually queued. Once the authoritative queue fully drains, the next
        // batch must start fresh rather than inheriting stale duplicate poison.
        g.seen.insert(999);

        assert_eq!(g.pop_ready(), Some(21));
        assert_eq!(g.pop_ready(), Some(22));
        assert_eq!(g.pop_ready(), None);
        assert!(g.seen.is_empty());

        assert_eq!(g.admit(999), AdmitOutcome::Accepted);
        assert_eq!(g.admit(999), AdmitOutcome::Duplicate);
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

        // Long-lived schedulers may keep polling a hard-stopped lane before any
        // new capacity appears. Those idle polls must preserve restored duplicate
        // metadata instead of erasing it as if the lane had drained normally.
        for _ in 0..3 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.admit(41, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(99, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
        }
    }

    #[test]
    fn qos_snapshot_stays_hard_stopped_while_restored_duplicate_metadata_survives_idle_polls() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge carried only by caches while the
        // hard-stop lane remains empty.
        g.seen_global.insert(41);
        g.normal.seen.insert(41);
        g.critical.seen.insert(42);
        g.critical_served_streak = 7;

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        assert_eq!(g.qos_snapshot(), expected);

        // Idle scheduler polls must keep observability pinned to hard-stop semantics
        // while preserved duplicate knowledge continues to classify restored ids.
        for _ in 0..3 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.qos_snapshot(), expected);
            assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(99, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
        }

        // Even though duplicate metadata is preserved, idle self-heal should still
        // cold-reset fairness bookkeeping under hard-stop mode.
        assert_eq!(g.critical_served_streak, 0);
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
    fn final_pop_clears_ghost_seen_global_when_drained_id_is_already_missing() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(7, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (0, 1, 1));

        // Simulate restored-state skew right before the final dequeue: lane-wide
        // cache lost the real queued id but still carries unrelated ghost state.
        g.seen_global.remove(&7);
        g.seen_global.insert(999);
        assert_eq!(g.seen_global.len(), 1);

        // Final dequeue should clear ghost lane-wide state even though remove(id)
        // misses, because the authoritative queues become idle afterwards.
        assert_eq!(g.pop_ready(), Some(7));
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert!(g.seen_global.is_empty());

        // The drained id must immediately re-enter as fresh instead of being
        // poisoned by the earlier ghost cache skew.
        assert_eq!(g.admit(7, IngressClass::Normal), AdmitOutcome::Accepted);
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
    fn saturated_cross_lane_and_seen_global_skew_keeps_real_duplicate_and_ghost_retry_distinct() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(200, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.queued_counts(), (1, 1, 2));

        // Simulate restored-state skew under saturation where lane-local membership
        // is swapped across lanes and lane-wide membership preserves cardinality by
        // replacing one real queued id with a ghost id.
        g.normal.seen.remove(&200);
        g.critical.seen.remove(&100);
        g.normal.seen.insert(100);
        g.critical.seen.insert(200);
        g.seen_global.remove(&200);
        g.seen_global.insert(999);
        assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 2);
        assert_eq!(g.seen_global.len(), 2);

        // The real queued id must stay Duplicate even though both lane-local and
        // lane-wide caches drifted, while the ghost id must remain merely fresh and
        // therefore Backpressured under aggregate saturation.
        assert_eq!(g.admit(100, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(
            g.admit(999, IngressClass::Critical),
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
    fn missing_lane_local_membership_rebuilds_seen_caches_before_repeated_duplicate_probe() {
        let mut g = LaneAdmissionGate::new(4, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);

        // Simulate restored-state skew: tx 1 remains queued, but lane-local and
        // lane-wide seen caches both drop it while preserving non-empty backlog.
        g.critical.seen.remove(&1);
        g.seen_global.remove(&1);
        assert_eq!(g.queued_counts(), (1, 1, 2));

        // The first duplicate probe should rebuild all seen caches from queue truth.
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert!(g.critical.seen.contains(&1));
        assert!(g.seen_global.contains(&1));

        // Repeated duplicate probes should stay on the healed fast path.
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Duplicate);
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
    fn hard_stop_seen_global_only_duplicate_survives_cross_class_retries_and_idle_polls() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge carried only by the lane-wide cache.
        g.seen_global.insert(42);
        let hard_stop_snapshot = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        for _ in 0..2 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.qos_snapshot(), hard_stop_snapshot);
            assert_eq!(g.queued_counts(), (0, 0, 0));

            assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(42, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(99, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
            assert_eq!(
                g.admit(99, IngressClass::Critical),
                AdmitOutcome::Backpressured
            );

            assert_eq!(g.qos_snapshot(), hard_stop_snapshot);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert!(g.seen_global.contains(&42));
            assert!(!g.seen_global.contains(&99));
            assert!(g.normal.seen.is_empty());
            assert!(g.critical.seen.is_empty());
        }
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
    fn hard_stop_idle_polls_preserve_mixed_restored_duplicate_sources_and_flat_qos() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Mix lane-local and lane-wide restored duplicate metadata the way recovery
        // skew can surface it, then verify idle polls keep QoS fail-closed while
        // preserving duplicate-vs-backpressure classification across classes.
        g.normal.seen.insert(41);
        g.critical.seen.insert(42);
        g.seen_global.insert(41);
        g.critical_served_streak = 3;

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        for _ in 0..2 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);

            assert_eq!(g.admit(41, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(42, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(99, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
            assert_eq!(
                g.admit(99, IngressClass::Critical),
                AdmitOutcome::Backpressured
            );
            assert_eq!(g.qos_snapshot(), expected);
        }

        assert_eq!(g.critical_served_streak, 0);
        assert!(g.normal.seen.contains(&41));
        assert!(g.critical.seen.contains(&42));
        assert!(g.seen_global.contains(&41));
    }

    #[test]
    fn hard_stop_idle_polls_preserve_lane_local_duplicates_without_reviving_queue_state() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge carried only by one lane-local cache.
        g.critical.seen.insert(55);
        g.critical_served_streak = 3;

        for _ in 0..3 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot().total_queued, 0);
            assert_eq!(g.admit(55, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(99, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
        }

        // Idle self-heal may cold-reset fairness bookkeeping, but it must not erase
        // restored duplicate metadata or fabricate queued work in hard-stop mode.
        assert_eq!(g.critical_served_streak, 0);
        assert!(g.seen_global.is_empty());
        assert!(g.normal.seen.is_empty());
        assert!(g.critical.seen.contains(&55));
        assert_eq!(g.queued_counts(), (0, 0, 0));
    }

    #[test]
    fn hard_stop_probe_noise_keeps_qos_snapshot_and_queue_counts_flat() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate metadata under a temporary hard-stop.
        g.normal.seen.insert(41);
        g.seen_global.insert(41);

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        for class in [
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
        ] {
            assert_eq!(g.admit(41, class), AdmitOutcome::Duplicate);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }

        for class in [
            IngressClass::Critical,
            IngressClass::Normal,
            IngressClass::Critical,
        ] {
            assert_eq!(g.admit(99, class), AdmitOutcome::Backpressured);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }
    }

    #[test]
    fn hard_stop_lane_local_duplicate_probe_noise_keeps_qos_snapshot_flat_without_seen_global() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge carried only by lane-local caches.
        g.critical.seen.insert(55);

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        for class in [
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
        ] {
            assert_eq!(g.admit(55, class), AdmitOutcome::Duplicate);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }

        for class in [IngressClass::Critical, IngressClass::Normal] {
            assert_eq!(g.admit(99, class), AdmitOutcome::Backpressured);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }
    }

    #[test]
    fn hard_stop_lane_local_duplicates_keep_qos_fail_closed_through_idle_polls() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge that survived only in lane-local
        // caches. Idle polls may cold-reset fairness bookkeeping, but they must not
        // reopen QoS, fabricate queue occupancy, or degrade restored duplicates into
        // Backpressured.
        g.normal.seen.insert(55);
        g.critical.seen.insert(56);
        g.critical_served_streak = 3;

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        for _ in 0..2 {
            assert_eq!(g.pop_ready(), None);
            assert_eq!(g.qos_snapshot(), expected);
            assert_eq!(g.queued_counts(), (0, 0, 0));

            assert_eq!(g.admit(55, IngressClass::Critical), AdmitOutcome::Duplicate);
            assert_eq!(g.admit(56, IngressClass::Normal), AdmitOutcome::Duplicate);
            assert_eq!(
                g.admit(404, IngressClass::Normal),
                AdmitOutcome::Backpressured
            );
            assert_eq!(
                g.admit(404, IngressClass::Critical),
                AdmitOutcome::Backpressured
            );

            assert_eq!(g.qos_snapshot(), expected);
            assert_eq!(g.queued_counts(), (0, 0, 0));
        }

        assert_eq!(g.critical_served_streak, 0);
    }

    #[test]
    fn hard_stop_cross_class_duplicate_and_fresh_probe_noise_keeps_qos_flat_through_idle_poll() {
        let mut g = LaneAdmissionGate::new(0, 0);

        // Simulate restored duplicate knowledge carried only by the opposite lane.
        // Cross-class replay probes must stay Duplicate while fresh retries remain
        // Backpressured, and QoS must stay pinned to fail-closed semantics.
        g.critical.seen.insert(55);

        let expected = LaneQosSnapshot {
            normal_queued: 0,
            critical_queued: 0,
            total_queued: 0,
            normal_headroom: 0,
            critical_headroom: 0,
            total_headroom: 0,
            fresh_normal_admissible: false,
            fresh_critical_admissible: false,
        };

        assert_eq!(g.qos_snapshot(), expected);

        for class in [
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
        ] {
            assert_eq!(g.admit(55, class), AdmitOutcome::Duplicate);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }

        for class in [
            IngressClass::Critical,
            IngressClass::Normal,
            IngressClass::Critical,
            IngressClass::Normal,
        ] {
            assert_eq!(g.admit(99, class), AdmitOutcome::Backpressured);
            assert_eq!(g.queued_counts(), (0, 0, 0));
            assert_eq!(g.qos_snapshot(), expected);
        }

        assert_eq!(g.pop_ready(), None);
        assert_eq!(g.queued_counts(), (0, 0, 0));
        assert_eq!(g.qos_snapshot(), expected);
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

    #[test]
    fn reserve_guard_seen_cache_skew_does_not_poison_fresh_retry_after_critical_backlog_clears() {
        let mut g = LaneAdmissionGate::new(4, 2);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(90, IngressClass::Critical), AdmitOutcome::Accepted);

        let guarded_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 1,
            total_queued: 3,
            normal_headroom: 0,
            critical_headroom: 1,
            total_headroom: 1,
            fresh_normal_admissible: false,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Simulate restored-state skew: one real normal id disappears from seen caches
        // and is replaced by a ghost id while queue contents stay authoritative.
        g.normal.seen.remove(&2);
        g.normal.seen.insert(999);
        g.seen_global.remove(&2);
        g.seen_global.insert(999);
        assert_eq!(g.normal.seen.len() + g.critical.seen.len(), 3);
        assert_eq!(g.seen_global.len(), 3);

        // With the final slot still guarded for fresh critical ingress, the ghost id
        // must remain fresh/backpressured and must not perturb the public QoS surface.
        assert_eq!(
            g.admit(999, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
        assert_eq!(g.qos_snapshot(), guarded_snapshot);

        // Once the active critical backlog drains, the reserved headroom really reopens.
        assert_eq!(g.pop_ready(), Some(90));
        let reopened_snapshot = LaneQosSnapshot {
            normal_queued: 2,
            critical_queued: 0,
            total_queued: 2,
            normal_headroom: 0,
            critical_headroom: 2,
            total_headroom: 2,
            fresh_normal_admissible: true,
            fresh_critical_admissible: true,
        };
        assert_eq!(g.qos_snapshot(), reopened_snapshot);

        // The previously blocked ghost id must admit cleanly after the real reopen,
        // while the real queued id still self-heals back to duplicate semantics.
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Duplicate);
    }
}
