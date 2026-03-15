use trnm_state::StateStore;

use crate::bft::model::LeaderHealth;
use crate::hot::{
    hot_object_tail_share_ppm, hot_object_top_label_share_ppm, summarize_hot_objects,
};
use crate::run_apply::{AppliedHeightOutcome, ApplyRuntimeTelemetry};
use crate::run_bft::BftHeightTelemetry;
use crate::summary::{emit_consensus_summary, ConsensusSummaryInputs};
use crate::types::{MockTx, OrderingDecision};

#[derive(Debug, Default, Clone)]
pub(crate) struct RuntimeMetrics {
    finality_samples_ms: Vec<u128>,
    scheduler_samples_ms: Vec<u128>,
    preexec_samples_ms: Vec<u128>,
    commit_samples_ms: Vec<u128>,
    state_root_total_samples_ms: Vec<u128>,
    critical_wait_blocks_samples: Vec<u128>,
    critical_wait_active_heights: u64,
    critical_wait_total: u64,
    block_txs_samples: Vec<u128>,
    block_groups_samples: Vec<u128>,
    rollback_samples: Vec<u128>,
    avg_group_size_samples: Vec<u128>,
    hot_object_share_samples_ppm: Vec<u128>,
    hot_object_top_label_share_samples_ppm: Vec<u128>,
    hot_object_tail_share_samples_ppm: Vec<u128>,
    hot_object_active_heights: u64,
    hot_object_active_top_label_share_total_ppm: u128,
    hot_object_active_tail_share_total_ppm: u128,
    preexec_reject_total: u64,
    preexec_reject_active_heights: u64,
    rollback_block_total: u64,
}

impl RuntimeMetrics {
    pub(crate) fn record_ordering(
        &mut self,
        state: &StateStore,
        picked: &[MockTx],
        ordering_decision: &OrderingDecision,
        scheduler_elapsed_ms: u128,
    ) {
        self.scheduler_samples_ms.push(scheduler_elapsed_ms);
        self.preexec_samples_ms
            .push(ordering_decision.preexec_elapsed_ms);
        self.critical_wait_blocks_samples
            .push(ordering_decision.critical_wait_blocks as u128);
        self.critical_wait_total = self
            .critical_wait_total
            .saturating_add(ordering_decision.critical_wait_blocks);
        if ordering_decision.critical_wait_blocks > 0 {
            self.critical_wait_active_heights =
                self.critical_wait_active_heights.saturating_add(1);
        }
        self.preexec_reject_total = self
            .preexec_reject_total
            .saturating_add(ordering_decision.rejected);
        if ordering_decision.rejected > 0 {
            self.preexec_reject_active_heights =
                self.preexec_reject_active_heights.saturating_add(1);
        }

        let group_count = ordering_decision.group_count;
        let avg_group_size = if group_count == 0 {
            0u128
        } else {
            ((picked.len() as u128) * 1000) / (group_count as u128)
        };
        self.avg_group_size_samples.push(avg_group_size);

        let hot_object_summary = summarize_hot_objects(state, picked);
        let hot_object_share_ppm = if picked.is_empty() {
            0u128
        } else {
            ((hot_object_summary.hot_tx_count as u128) * 1_000_000) / (picked.len() as u128)
        };
        let hot_object_top_label_share_ppm = hot_object_top_label_share_ppm(&hot_object_summary);
        let hot_object_tail_share_ppm = hot_object_tail_share_ppm(&hot_object_summary);
        self.hot_object_share_samples_ppm.push(hot_object_share_ppm);
        self.hot_object_top_label_share_samples_ppm
            .push(hot_object_top_label_share_ppm);
        self.hot_object_tail_share_samples_ppm
            .push(hot_object_tail_share_ppm);
        if hot_object_summary.hot_tx_count > 0 {
            self.hot_object_active_heights = self.hot_object_active_heights.saturating_add(1);
            self.hot_object_active_top_label_share_total_ppm = self
                .hot_object_active_top_label_share_total_ppm
                .saturating_add(hot_object_top_label_share_ppm);
            self.hot_object_active_tail_share_total_ppm = self
                .hot_object_active_tail_share_total_ppm
                .saturating_add(hot_object_tail_share_ppm);
        }
    }

    pub(crate) fn record_commit(
        &mut self,
        apply_outcome: &AppliedHeightOutcome,
        group_count: usize,
        elapsed_ms: u128,
        commit_elapsed_ms: u128,
    ) {
        self.commit_samples_ms.push(commit_elapsed_ms);
        self.state_root_total_samples_ms
            .push(apply_outcome.state_root_total_ms);
        self.block_txs_samples.push(apply_outcome.applied as u128);
        self.block_groups_samples.push(group_count as u128);
        self.rollback_samples
            .push(apply_outcome.rollback_count as u128);
        if apply_outcome.rollback_count > 0 {
            self.rollback_block_total = self.rollback_block_total.saturating_add(1);
        }
        self.finality_samples_ms.push(elapsed_ms);
    }

    pub(crate) fn emit_summary(
        &self,
        apply_telemetry: &ApplyRuntimeTelemetry,
        bft_telemetry: &BftHeightTelemetry,
        leader_health: &[LeaderHealth],
    ) {
        emit_consensus_summary(ConsensusSummaryInputs {
            finality_samples_ms: &self.finality_samples_ms,
            scheduler_samples_ms: &self.scheduler_samples_ms,
            preexec_samples_ms: &self.preexec_samples_ms,
            commit_samples_ms: &self.commit_samples_ms,
            state_root_total_samples_ms: &self.state_root_total_samples_ms,
            critical_wait_blocks_samples: &self.critical_wait_blocks_samples,
            block_txs_samples: &self.block_txs_samples,
            block_groups_samples: &self.block_groups_samples,
            rollback_samples: &self.rollback_samples,
            avg_group_size_samples: &self.avg_group_size_samples,
            hot_object_share_samples_ppm: &self.hot_object_share_samples_ppm,
            hot_object_top_label_share_samples_ppm: &self.hot_object_top_label_share_samples_ppm,
            hot_object_tail_share_samples_ppm: &self.hot_object_tail_share_samples_ppm,
            hot_object_active_heights: self.hot_object_active_heights,
            hot_object_active_top_label_share_total_ppm: self
                .hot_object_active_top_label_share_total_ppm,
            hot_object_active_tail_share_total_ppm: self.hot_object_active_tail_share_total_ppm,
            critical_wait_active_heights: self.critical_wait_active_heights,
            critical_wait_total: self.critical_wait_total,
            preexec_reject_total: self.preexec_reject_total,
            preexec_reject_active_heights: self.preexec_reject_active_heights,
            apply_error_total: apply_telemetry.apply_error_total,
            apply_error_preexec_conflict_miss_total: apply_telemetry
                .apply_error_preexec_conflict_miss_total,
            apply_error_version_conflict_total: apply_telemetry
                .apply_error_version_conflict_total,
            apply_error_invalid_transition_total: apply_telemetry
                .apply_error_invalid_transition_total,
            apply_error_deadline_exceeded_total: apply_telemetry
                .apply_error_deadline_exceeded_total,
            apply_error_semantic_fail_total: apply_telemetry.apply_error_semantic_fail_total,
            rollback_total: apply_telemetry.rollback_total,
            rollback_block_total: self.rollback_block_total,
            timeout_migrated_total: apply_telemetry.timeout_migrated_total,
            bft_observed_heights: bft_telemetry.observed_heights,
            bft_committed_heights: bft_telemetry.committed_heights,
            bft_round_change_total: bft_telemetry.round_change_total,
            bft_round_change_active_heights: bft_telemetry.round_change_active_heights,
            bft_round_change_backoff_total_ms: bft_telemetry.round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights: bft_telemetry
                .round_change_backoff_active_heights,
            bft_round_change_backoff_max_ms: bft_telemetry.round_change_backoff_max_ms,
            bft_leader_missed_active_heights: bft_telemetry.leader_missed_active_heights,
            leader_health,
            bft_double_vote_total: bft_telemetry.double_vote_total,
            bft_auth_reject_bad_sig_total: bft_telemetry.auth_reject_bad_sig_total,
            bft_auth_reject_replay_total: bft_telemetry.auth_reject_replay_total,
            bft_auth_reject_stale_nonce_total: bft_telemetry.auth_reject_stale_nonce_total,
        });
    }
}
