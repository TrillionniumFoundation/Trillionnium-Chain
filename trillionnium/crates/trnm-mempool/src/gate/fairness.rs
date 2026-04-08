use super::{AdmissionGate, AdmitOutcome};

impl AdmissionGate {
    pub(super) fn clamp_retry_reservations(&mut self) -> usize {
        // Keep fairness reservations bounded to currently known retry population.
        // This guards restored/corrupted state from over-deferring free ingress.
        let known_retry_count = self.backpressured_ids.len();
        let retry_budget = known_retry_count.min(self.capacity);
        self.retry_reservations = self.retry_reservations.min(retry_budget);
        known_retry_count
    }

    pub(super) fn clear_stale_retry_state_if_empty(&mut self, known_retry_count: usize) {
        if known_retry_count == 0 {
            // Restored/corrupted state may carry stale fairness marker + reservation even
            // when retry memory is empty. Clear both so free ingress is never mis-deduped.
            self.retry_reservations = 0;
            self.last_fairness_deferred = None;
            // Retry memory can also keep stale FIFO markers after partial state restore.
            // Drop them eagerly on the no-retry fast path so bookkeeping stays bounded.
            if !self.backpressured_fifo.is_empty() {
                self.backpressured_fifo.clear();
            }
        }
    }

    pub(super) fn fairness_duplicate_without_active_reservation(&mut self, tx_id: u64) -> bool {
        if self.retry_reservations == 0 {
            if self.backpressured_ids.is_empty() {
                self.last_fairness_deferred = None;
            } else if self.last_fairness_deferred == Some(tx_id)
                && !self.backpressured_ids.contains(&tx_id)
            {
                // Preserve idempotency for immediate repeats of a just-deferred fresh id,
                // even when only a single retry reservation was available.
                // If the marker points at a known retry id, never shadow its admission.
                self.note_backpressure_duplicate();
                return true;
            }
        }
        false
    }

    pub(super) fn saturated_duplicate_or_backpressure(
        &mut self,
        tx_id: u64,
        known_retry_count: usize,
    ) -> AdmitOutcome {
        // If a fresh id was just fairness-deferred, preserve idempotency even when
        // the queue re-saturates before the sender retries; avoid churning bounded
        // retry memory and over-counting backpressure for immediate repeats.
        if self.last_fairness_deferred == Some(tx_id) {
            self.note_backpressure_duplicate();
            return AdmitOutcome::Duplicate;
        }

        self.last_fairness_deferred = None;
        // Hot saturated retry path: if this tx id is already tracked as backpressured,
        // classify immediately as duplicate and skip bounded retry-cache churn.
        // Guard the hash probe with known_retry_count so fully drained retry state
        // stays on the no-retry fast path under sustained full-queue ingress.
        if known_retry_count != 0 && self.backpressured_ids.contains(&tx_id) {
            self.note_backpressure_duplicate();
            return AdmitOutcome::Duplicate;
        }

        if !self.remember_backpressured(tx_id) {
            self.note_backpressure_duplicate();
            return AdmitOutcome::Duplicate;
        }
        self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
        AdmitOutcome::Backpressured
    }

    pub(super) fn fairness_duplicate_with_active_reservation(
        &mut self,
        tx_id: u64,
        is_known_retry_for_fairness: bool,
    ) -> bool {
        if self.retry_reservations > 0
            && self.last_fairness_deferred == Some(tx_id)
            && !is_known_retry_for_fairness
        {
            self.note_backpressure_duplicate();
            return true;
        }
        false
    }

    pub(super) fn known_retry_for_fairness(&self, known_retry_count: usize, tx_id: u64) -> bool {
        if self.retry_reservations > 0 && known_retry_count != 0 {
            self.backpressured_ids.contains(&tx_id)
        } else {
            false
        }
    }

    pub(super) fn maybe_fairness_defer_fresh_ingress(
        &mut self,
        tx_id: u64,
        known_retry_count: usize,
        is_known_retry_for_fairness: bool,
    ) -> bool {
        // Fairness guard: once we have known backpressured retries, reserve newly
        // opened capacity for them first. Fresh ids are briefly backpressured so
        // retry traffic cannot be perpetually starved by new ingress.
        //
        // Throughput guard: only defer when admitting fresh ingress would consume a
        // slot that must remain reserved for retry traffic. If there are more free
        // slots than retry reservations, admit immediately to avoid unnecessary
        // free-ingress throttling.
        let free_slots = self.capacity.saturating_sub(self.queue.len());
        if self.retry_reservations > 0
            && free_slots <= self.retry_reservations
            && known_retry_count != 0
            && !is_known_retry_for_fairness
        {
            // Fairness-only deferral is tracked via last_fairness_deferred. Do not
            // promote this fresh id into retry memory here; otherwise an immediate
            // repeat can be misclassified as a known retry and consume the reserved slot.
            self.last_fairness_deferred = Some(tx_id);
            self.metrics.backpressured = self.metrics.backpressured.saturating_add(1);
            self.metrics.fairness_deferrals = self.metrics.fairness_deferrals.saturating_add(1);
            self.retry_reservations -= 1;
            return true;
        }
        false
    }

    pub(super) fn accept_with_retry_tracking(
        &mut self,
        tx_id: u64,
        known_retry_count: usize,
        is_known_retry_for_fairness: bool,
    ) -> AdmitOutcome {
        // Fast-path fresh ingress: when fairness is armed we already probed retry
        // membership above. Reuse that signal to avoid a second hash-table lookup
        // on the common non-retry acceptance path.
        let accepted_was_retry = if is_known_retry_for_fairness {
            self.backpressured_ids.remove(&tx_id)
        } else if self.retry_reservations > 0 {
            false
        } else {
            known_retry_count != 0 && self.backpressured_ids.remove(&tx_id)
        };
        if accepted_was_retry && self.backpressured_fifo.len() > self.capacity.saturating_mul(4) {
            // Under sustained retry drain with little/no new ingress, stale FIFO markers can
            // accumulate without hitting remember_backpressured() compaction. Compact eagerly
            // once a retry is accepted to keep retry-memory bookkeeping bounded.
            self.compact_backpressured_fifo();
        }
        if self.retry_reservations > 0 {
            self.retry_reservations -= 1;
        }
        if accepted_was_retry && self.backpressured_ids.is_empty() {
            // As soon as all known retries are drained, release any stale fairness reservations
            // so newly arriving free-ingress traffic is not pointlessly deferred.
            self.retry_reservations = 0;
            // No known retries remain, so any earlier fairness-deferral marker is now stale too.
            // Clear it immediately instead of carrying warm marker state until a later pop/admit.
            self.last_fairness_deferred = None;
            // Also drop stale retry FIFO markers immediately instead of waiting for the next
            // admit()/pop_ready() boundary. This keeps retry bookkeeping cold after the last
            // recovered retry is accepted during low-churn recovery windows.
            self.backpressured_fifo.clear();
        }
        // Keep fairness marker until the next dequeue boundary. This preserves
        // idempotency for a just-deferred id when the queue re-saturates before
        // sender retry, while still allowing pop_ready() to clear stale markers.
        self.queue.push_back(tx_id);
        self.seen.insert(tx_id);
        self.metrics.accepted = self.metrics.accepted.saturating_add(1);
        AdmitOutcome::Accepted
    }

    pub(super) fn update_retry_reservations_on_pop(&mut self) {
        // Dequeue boundary ends immediate fairness-deferral idempotency window.
        self.last_fairness_deferred = None;
        // Reserve one newly opened slot for known retries to reduce starvation.
        // Bound reservations by currently known retry ids so free-ingress throughput
        // is not over-deferred after multi-pop bursts with only a few retry candidates.
        let retry_budget = self.backpressured_ids.len().min(self.capacity);
        if retry_budget == 0 {
            self.retry_reservations = 0;
            // Once retry memory is empty, clear stale fairness marker immediately so
            // pop-only drain cycles restore a clean fast-path state before new ingress.
            self.last_fairness_deferred = None;
            // Retry memory is fully drained; drop stale fifo markers eagerly so
            // idle drain windows do not carry unnecessary backpressure bookkeeping.
            self.backpressured_fifo.clear();
        } else {
            self.retry_reservations = self.retry_reservations.saturating_add(1).min(retry_budget);
            if self.backpressured_fifo.len() > self.capacity.saturating_mul(4) {
                // Pop-heavy recovery windows can retain oversized stale FIFO marker tails
                // from restored/churned state without hitting admit() compaction paths.
                // Compact on dequeue boundaries to keep retry bookkeeping memory bounded.
                self.compact_backpressured_fifo();
            }
        }
    }

    fn note_backpressure_duplicate(&mut self) {
        self.metrics.duplicates = self.metrics.duplicates.saturating_add(1);
        self.metrics.backpressure_duplicates =
            self.metrics.backpressure_duplicates.saturating_add(1);
    }
}
