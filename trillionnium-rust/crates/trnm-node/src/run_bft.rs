use crate::bft::model::BftHeightResult;
use crate::hot::missed_proposals_added_since;

#[derive(Debug, Clone)]
pub(crate) struct BftHeightTelemetry {
    pub(crate) observed_heights: u64,
    pub(crate) committed_heights: u64,
    pub(crate) round_change_total: u64,
    pub(crate) round_change_active_heights: u64,
    pub(crate) round_change_backoff_active_heights: u64,
    pub(crate) double_vote_total: u64,
    pub(crate) auth_reject_bad_sig_total: u64,
    pub(crate) auth_reject_replay_total: u64,
    pub(crate) auth_reject_stale_nonce_total: u64,
    pub(crate) round_change_backoff_total_ms: u64,
    pub(crate) round_change_backoff_max_ms: u64,
    pub(crate) leader_missed_active_heights: u64,
    leader_missed_previous_snapshot: Vec<u64>,
}

impl BftHeightTelemetry {
    pub(crate) fn new(validators: usize) -> Self {
        Self {
            observed_heights: 0,
            committed_heights: 0,
            round_change_total: 0,
            round_change_active_heights: 0,
            round_change_backoff_active_heights: 0,
            double_vote_total: 0,
            auth_reject_bad_sig_total: 0,
            auth_reject_replay_total: 0,
            auth_reject_stale_nonce_total: 0,
            round_change_backoff_total_ms: 0,
            round_change_backoff_max_ms: 0,
            leader_missed_active_heights: 0,
            leader_missed_previous_snapshot: vec![0; validators.max(1)],
        }
    }

    pub(crate) fn record(&mut self, bft: &BftHeightResult) {
        self.observed_heights = self.observed_heights.saturating_add(1);
        if bft.committed {
            self.committed_heights = self.committed_heights.saturating_add(1);
        }
        self.round_change_total = self.round_change_total.saturating_add(bft.round_changes);
        if bft.round_changes > 0 {
            self.round_change_active_heights = self.round_change_active_heights.saturating_add(1);
        }
        self.double_vote_total = self
            .double_vote_total
            .saturating_add(bft.double_vote_events as u64);
        self.auth_reject_bad_sig_total = self
            .auth_reject_bad_sig_total
            .saturating_add(bft.auth_reject_bad_sig as u64);
        self.auth_reject_replay_total = self
            .auth_reject_replay_total
            .saturating_add(bft.auth_reject_replay as u64);
        self.auth_reject_stale_nonce_total = self
            .auth_reject_stale_nonce_total
            .saturating_add(bft.auth_reject_stale_nonce as u64);
        self.round_change_backoff_total_ms = self
            .round_change_backoff_total_ms
            .saturating_add(bft.round_change_backoff_total_ms);
        if bft.round_change_backoff_total_ms > 0 {
            self.round_change_backoff_active_heights = self
                .round_change_backoff_active_heights
                .saturating_add(1);
        }
        self.round_change_backoff_max_ms = self
            .round_change_backoff_max_ms
            .max(bft.round_change_backoff_max_ms);

        let leader_missed_added = missed_proposals_added_since(
            &self.leader_missed_previous_snapshot,
            &bft.leader_missed_snapshot,
        );
        if leader_missed_added > 0 {
            self.leader_missed_active_heights =
                self.leader_missed_active_heights.saturating_add(1);
        }
        self.leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
    }
}
