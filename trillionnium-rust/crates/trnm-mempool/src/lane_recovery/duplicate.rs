use crate::LaneAdmissionGate;

impl LaneAdmissionGate {
    pub(crate) fn queue_contains_in_seen_lanes(
        &self,
        tx_id: u64,
        in_normal_seen: bool,
        in_critical_seen: bool,
    ) -> bool {
        if in_normal_seen && in_critical_seen {
            self.normal.queue.contains(&tx_id) || self.critical.queue.contains(&tx_id)
        } else if in_normal_seen {
            self.normal.queue.contains(&tx_id)
        } else {
            self.critical.queue.contains(&tx_id)
        }
    }

    pub(crate) fn detect_duplicate_after_sync(
        &mut self,
        tx_id: u64,
        lane_total: usize,
        lane_was_empty: bool,
    ) -> bool {
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
                    self.queue_contains_in_seen_lanes(tx_id, in_normal_seen, in_critical_seen);

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
                    self.queue_contains_in_seen_lanes(tx_id, in_normal_seen, in_critical_seen);

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
                let lane_local_seen_total = self
                    .normal
                    .seen
                    .len()
                    .saturating_add(self.critical.seen.len());
                if lane_local_seen_total != lane_total
                    && (self.normal.queue.contains(&tx_id) || self.critical.queue.contains(&tx_id))
                {
                    is_duplicate = true;
                    self.seen_global.insert(tx_id);
                }
            }
        }

        is_duplicate
    }

    pub(crate) fn repair_seen_after_pop(&mut self, id: u64) {
        if !self.seen_global.remove(&id) {
            // Defensive self-heal: restored-state skew can leave lane-wide cache
            // stale while lane-local queues remain authoritative.
            if self.normal.queue.is_empty() && self.critical.queue.is_empty() {
                // Hot full-drain skew path: avoid redundant iterator setup when no
                // queued survivors exist after dequeue.
                self.seen_global.clear();
            } else {
                self.rebuild_seen_global_from_queues();
            }
        } else {
            let lane_total = self.lane_total();
            if self.seen_global.len() != lane_total {
                // Keep idempotency cache in sync even when a stale ghost id
                // survives removal of the drained tx id.
                if lane_total == 0 {
                    // Hot idle path after full drain: clear stale cache entries.
                    self.seen_global.clear();
                } else {
                    self.rebuild_seen_global_from_queues();
                }
            }
        }

        if self.normal.queue.is_empty() && self.critical.queue.is_empty() {
            // Full-drain boundary: aggressively clear lane-local id caches so
            // restored-state ghost markers cannot survive until the next admit().
            self.clear_lane_seen();
            // Also cold-reset fairness bookkeeping immediately on idle so no stale
            // streak survives between dequeue loops in long-lived schedulers.
            self.critical_served_streak = 0;
        }
    }
}
