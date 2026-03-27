use std::collections::{HashSet, VecDeque};

use super::AdmissionGate;

impl AdmissionGate {
    pub(super) fn compact_backpressured_fifo(&mut self) {
        if self.backpressured_fifo.len() < self.capacity.saturating_mul(4) {
            return;
        }

        if self.backpressured_ids.is_empty() {
            // Fast-path stale retry marker cleanup after full retry drain.
            self.backpressured_fifo.clear();
            return;
        }

        let mut rebuilt = VecDeque::with_capacity(self.backpressured_ids.len());
        let mut seen = HashSet::with_capacity(self.backpressured_ids.len());
        while let Some(candidate) = self.backpressured_fifo.pop_front() {
            if self.backpressured_ids.contains(&candidate) && seen.insert(candidate) {
                rebuilt.push_back(candidate);
            }
        }
        self.backpressured_fifo = rebuilt;
    }

    pub(super) fn remember_backpressured(&mut self, tx_id: u64) -> bool {
        if self.backpressured_ids.insert(tx_id) {
            self.backpressured_fifo.push_back(tx_id);
            self.compact_backpressured_fifo();
            if self.backpressured_fifo.len() < self.backpressured_ids.len() {
                // Restored-state skew can drop FIFO markers while retaining retry ids.
                // Rebuild deterministic markers when marker coverage is incomplete so
                // bounded eviction avoids repeated set-wide fallback trimming.
                let mut rebuilt: Vec<u64> = self.backpressured_ids.iter().copied().collect();
                rebuilt.sort_unstable();
                self.backpressured_fifo = rebuilt.into_iter().collect();
            }
            while self.backpressured_ids.len() > self.capacity {
                let mut evicted = false;
                while let Some(candidate) = self.backpressured_fifo.pop_front() {
                    if candidate == tx_id
                        && self.backpressured_ids.len().saturating_sub(1) >= self.capacity
                    {
                        // Restored state may miss historical fifo markers. Keep the
                        // newly inserted retry id and let deterministic set trimming
                        // evict older entries instead of immediately dropping tx_id.
                        continue;
                    }
                    if self.backpressured_ids.remove(&candidate) {
                        evicted = true;
                        break;
                    }
                }
                if !evicted {
                    // Restored/corrupted state can carry a retry set larger than
                    // capacity with missing fifo markers. Fall back to deterministic
                    // set trimming so fairness quota remains bounded.
                    let overflow = self.backpressured_ids.len().saturating_sub(self.capacity);
                    if overflow == 0 {
                        break;
                    }
                    // HashSet iteration order is randomized; sort for stable trimming so
                    // restored-state recovery stays deterministic across runs/nodes.
                    // Preserve the newly inserted tx_id when possible so immediate
                    // retries for the fresh backpressured id stay idempotent.
                    let mut to_drop: Vec<u64> = self
                        .backpressured_ids
                        .iter()
                        .copied()
                        .filter(|id| *id != tx_id)
                        .collect();
                    to_drop.sort_unstable();
                    to_drop.truncate(overflow);
                    for tx in to_drop {
                        self.backpressured_ids.remove(&tx);
                    }
                    // If overflow remains (e.g. capacity=0 before clamping and only tx_id
                    // was present), fall back to removing the inserted id as a last resort.
                    if self.backpressured_ids.len() > self.capacity {
                        self.backpressured_ids.remove(&tx_id);
                    }
                    break;
                }
            }
            if self.backpressured_fifo.len() > self.backpressured_ids.len() {
                // Restored-state repair can deterministically trim retry ids while stale
                // FIFO markers survive. Rebuild markers immediately so bounded retry
                // bookkeeping stays aligned without waiting for a later compaction pass.
                let mut rebuilt: Vec<u64> = self.backpressured_ids.iter().copied().collect();
                rebuilt.sort_unstable();
                self.backpressured_fifo = rebuilt.into_iter().collect();
            }
            true
        } else {
            false
        }
    }

    #[cfg(test)]
    pub(super) fn remember_backpressured_without_eviction(&mut self, tx_id: u64) {
        // Fairness deferral must never evict older retry ids. When bounded memory has
        // room, insert directly and append a FIFO marker (no eviction/compaction path).
        if self.backpressured_ids.is_empty() && !self.backpressured_fifo.is_empty() {
            // After a full retry drain, fairness-only deferrals can be the next writer
            // to retry bookkeeping. Drop stale FIFO markers eagerly so the first new
            // deferred id starts from a clean bounded state instead of carrying old tails.
            self.backpressured_fifo.clear();
        }
        if self.backpressured_ids.len() < self.capacity && self.backpressured_ids.insert(tx_id) {
            self.backpressured_fifo.push_back(tx_id);
            // Fairness-only deferrals can run for long windows without hitting the
            // saturation insertion path; keep stale FIFO markers bounded here too.
            self.compact_backpressured_fifo();
        }
    }
}
