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
            // Hard-stop mode: keep zero-capacity ingress semantics O(1) and avoid
            // unnecessary lane/cache probes on hot backpressured paths.
            return AdmitOutcome::Backpressured;
        }

        // Fast-path saturation check from the lane-wide idempotency set: this tracks
        // all currently queued tx ids and avoids touching both lane queues on every
        // ingress probe while the cache is in sync.
        let lane_total = self
            .normal
            .queue
            .len()
            .saturating_add(self.critical.queue.len());
        if self.seen_global.len() != lane_total {
            // Defensive self-heal for transient restored-state skew: lane-local queues
            // remain source of truth for saturation, and rebuild lane-wide id set.
            if lane_total == 0 {
                // Hot idle path after burst drains: clear stale cache entries without
                // touching lane-local sets.
                self.seen_global.clear();
                // Fully idle lane state must also reset fairness streak; otherwise a
                // restored stale streak can spuriously preempt fresh critical work.
                self.critical_served_streak = 0;
            } else {
                self.seen_global.clear();
                self.seen_global.extend(self.normal.seen.iter().copied());
                self.seen_global.extend(self.critical.seen.iter().copied());
            }
        }

        // When cache and lane queue cardinality are aligned, lane-wide membership
        // is authoritative for duplicate checks on both saturated and free paths.
        //
        // Defensive fallback: restored-state skew can theoretically keep cardinality
        // aligned while replacing one queued id with a ghost id in seen_global. In
        // that case, trust lane-local seen sets and repair lane-wide cache inline.
        let mut is_duplicate = self.seen_global.contains(&tx_id);
        if is_duplicate
            && !self.normal.seen.contains(&tx_id)
            && !self.critical.seen.contains(&tx_id)
        {
            // Defensive self-heal: restored-state skew can preserve cardinality while
            // leaving stale ids in the lane-wide cache. Rebuild from lane-local truth
            // so fresh ingress is not misclassified as duplicate.
            self.seen_global.clear();
            self.seen_global.extend(self.normal.seen.iter().copied());
            self.seen_global.extend(self.critical.seen.iter().copied());
            is_duplicate = self.seen_global.contains(&tx_id);
        }

        if !is_duplicate {
            // Defensive fallback for rare restored-state skew where lane-wide cache and
            // queue cardinality match but one queued id is missing from seen_global.
            // Probe lane-local id sets (O(1)) rather than queue scans (O(n)) to keep
            // free-ingress admission lightweight under bursty concurrency.
            let lane_local_duplicate =
                self.normal.seen.contains(&tx_id) || self.critical.seen.contains(&tx_id);
            if lane_local_duplicate {
                is_duplicate = true;
                self.seen_global.insert(tx_id);
            }
        }

        if lane_total >= self.total_capacity {
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

        let out = match class {
            IngressClass::Normal => {
                let normal_was_empty = self.normal.queue.is_empty();
                let primary = self.normal.admit(tx_id);
                let out = if matches!(primary, AdmitOutcome::Backpressured) {
                    let critical_free = self
                        .critical
                        .capacity
                        .saturating_sub(self.critical.queue.len());

                    let critical_idle = self.critical.queue.is_empty();
                    if (self.normal.capacity == 0 && critical_free > 0)
                        || (self.normal.capacity > 0
                            && (critical_free > 1 || (critical_idle && critical_free > 0)))
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
                    }
                } else {
                    primary
                };

                if self.normal_has_dedicated_capacity
                    && matches!(out, AdmitOutcome::Accepted)
                    && normal_was_empty
                    && !self.normal.queue.is_empty()
                    && !self.critical.queue.is_empty()
                {
                    // Anti-starvation: when normal backlog appears during an active
                    // critical flood, warm fairness so normal gets a turn after at
                    // most one additional critical dequeue.
                    self.critical_served_streak = self.critical_burst_limit;
                }

                out
            }
            IngressClass::Critical => {
                let normal_was_empty = self.normal.queue.is_empty();
                let primary = self.critical.admit(tx_id);
                let out = if matches!(primary, AdmitOutcome::Backpressured)
                    && self.normal.queue.len() < self.normal.capacity
                {
                    // Keep free-ingress throughput high under critical bursts by
                    // allowing bounded spillover into normal capacity.
                    self.normal.admit(tx_id)
                } else {
                    primary
                };

                if self.normal_has_dedicated_capacity
                    && matches!(out, AdmitOutcome::Accepted)
                    && normal_was_empty
                    && !self.normal.queue.is_empty()
                    && !self.critical.queue.is_empty()
                {
                    // Mirror fairness warmup for critical spillover into the normal
                    // lane: once overflow traffic appears there under active critical
                    // pressure, grant a normal-lane turn within one dequeue.
                    self.critical_served_streak = self.critical_burst_limit;
                }

                out
            }
        };
        if matches!(out, AdmitOutcome::Accepted) {
            self.seen_global.insert(tx_id);
        }
        out
    }
    pub fn queued_counts(&self) -> (usize, usize, usize) {
        let normal = self.normal.queue.len();
        let critical = self.critical.queue.len();
        (normal, critical, normal + critical)
    }

    pub fn pop_ready(&mut self) -> Option<u64> {
        let prefer_normal = self.normal_has_dedicated_capacity
            && self.critical_served_streak >= self.critical_burst_limit
            && !self.normal.queue.is_empty();

        let (id, served_critical) = if prefer_normal {
            if let Some(id) = self.normal.pop_ready() {
                (id, false)
            } else {
                (self.critical.pop_ready()?, true)
            }
        } else if let Some(id) = self.critical.pop_ready() {
            (id, true)
        } else {
            (self.normal.pop_ready()?, false)
        };

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

        if !self.seen_global.remove(&id) {
            // Defensive self-heal: restored-state skew can leave lane-wide cache
            // stale while lane-local queues remain authoritative.
            self.seen_global.clear();
            self.seen_global.extend(self.normal.seen.iter().copied());
            self.seen_global.extend(self.critical.seen.iter().copied());
        } else {
            let lane_total = self
                .normal
                .queue
                .len()
                .saturating_add(self.critical.queue.len());
            if self.seen_global.len() != lane_total {
                // Keep idempotency cache in sync even when a stale ghost id
                // survives removal of the drained tx id.
                if lane_total == 0 {
                    // Hot idle path after full drain: clear stale cache entries without
                    // touching lane-local sets.
                    self.seen_global.clear();
                } else {
                    self.seen_global.clear();
                    self.seen_global.extend(self.normal.seen.iter().copied());
                    self.seen_global.extend(self.critical.seen.iter().copied());
                }
            }
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
        assert_eq!(
            g.admit(4, IngressClass::Normal),
            AdmitOutcome::Backpressured
        );
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
        assert_eq!(g.admit(5, IngressClass::Critical), AdmitOutcome::Backpressured);
    }

    #[test]
    fn lane_gate_enforces_global_capacity_even_when_lane_mins_apply() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(100, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Backpressured);

        assert_eq!(g.pop_ready(), Some(100));
        assert_eq!(g.admit(101, IngressClass::Normal), AdmitOutcome::Accepted);
    }

    #[test]
    fn normal_lane_does_not_spill_when_critical_lane_is_busy() {
        let mut g = LaneAdmissionGate::new(2, 1);

        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(6, IngressClass::Normal), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);
    }

    #[test]
    fn full_critical_reserve_allows_normal_when_critical_lane_idle() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Backpressured);
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
    fn zero_critical_reserve_preserves_normal_capacity_with_critical_spillover() {
        let mut g = LaneAdmissionGate::new(3, 0);

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(2, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Accepted);
        assert_eq!(g.admit(4, IngressClass::Normal), AdmitOutcome::Backpressured);

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
        assert_eq!(g.admit(3, IngressClass::Normal), AdmitOutcome::Backpressured);

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
        assert_eq!(g.admit(30, IngressClass::Critical), AdmitOutcome::Backpressured);

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

        assert_eq!(g.admit(1, IngressClass::Normal), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(1, IngressClass::Critical), AdmitOutcome::Backpressured);
        assert_eq!(g.admit(2, IngressClass::Critical), AdmitOutcome::Backpressured);
        assert_eq!(g.pop_ready(), None);
    }

    #[test]
    fn duplicate_stays_duplicate_when_lane_is_globally_full() {
        let mut g = LaneAdmissionGate::new(1, 1);

        assert_eq!(g.admit(9, IngressClass::Critical), AdmitOutcome::Accepted);
        // Full-queue fast path must still preserve duplicate semantics.
        assert_eq!(g.admit(9, IngressClass::Normal), AdmitOutcome::Duplicate);
        assert_eq!(g.admit(10, IngressClass::Normal), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(3, IngressClass::Critical), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(99, IngressClass::Critical), AdmitOutcome::Backpressured);

        // After the self-heal rebuild, the real queued id is deduped again.
        assert_eq!(g.admit(20, IngressClass::Critical), AdmitOutcome::Duplicate);
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
        assert_eq!(g.admit(99, IngressClass::Normal), AdmitOutcome::Backpressured);
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
        assert_eq!(g.admit(5, IngressClass::Normal), AdmitOutcome::Backpressured);

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
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Backpressured);

        // After one dequeue, the same id should admit as fresh.
        let drained = g.pop_ready();
        assert!(drained == Some(1) || drained == Some(2) || drained == Some(3));
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Accepted);
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
        assert_eq!(g.admit(999, IngressClass::Critical), AdmitOutcome::Backpressured);

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
}
