use std::collections::BTreeMap;
use trnm_state::StateStore;

use crate::metrics::ratio_ppm;
use crate::types::{HotObjectSummary, MockTx};
use crate::{
    CHALLENGE_ESCROW_ACCOUNT, CHALLENGE_FORFEIT_TREASURY_ACCOUNT, RESOLVE_AUTHORITY_HOT_LABEL,
    RESOLVE_PENDING_APPROVAL_HOT_LABEL, WORKER_SLASH_TREASURY_ACCOUNT,
};

pub(crate) fn summarize_hot_objects(st: &StateStore, txs: &[MockTx]) -> HotObjectSummary {
    let mut labels = BTreeMap::new();
    let mut hot_tx_count = 0usize;

    for tx in txs {
        if let MockTx::Resolve { task_id, .. } = tx {
            hot_tx_count += 1;
            for label in [
                CHALLENGE_ESCROW_ACCOUNT,
                CHALLENGE_FORFEIT_TREASURY_ACCOUNT,
                WORKER_SLASH_TREASURY_ACCOUNT,
                RESOLVE_PENDING_APPROVAL_HOT_LABEL,
                RESOLVE_AUTHORITY_HOT_LABEL,
            ] {
                *labels.entry(label.to_string()).or_insert(0) += 1;
            }
            if let Some(challenger) = st.get_task(*task_id).and_then(|t| t.challenger) {
                *labels.entry(challenger).or_insert(0) += 1;
            }
        }
    }

    HotObjectSummary {
        hot_tx_count,
        labels,
    }
}

pub(crate) fn hot_object_top_label_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(top_refs as u128, total_refs as u128)
}

pub(crate) fn hot_object_tail_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(
        total_refs.saturating_sub(top_refs) as u128,
        total_refs as u128,
    )
}

pub(crate) fn missed_proposals_added_since(previous: &[u64], current: &[u64]) -> u64 {
    current
        .iter()
        .enumerate()
        .map(|(idx, current_count)| {
            current_count.saturating_sub(previous.get(idx).copied().unwrap_or(0))
        })
        .sum()
}
