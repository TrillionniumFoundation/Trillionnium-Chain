use anyhow::Result;
use clap::Parser;
#[cfg(test)]
use std::collections::VecDeque;
#[cfg(test)]
use std::sync::Arc;
#[cfg(test)]
use std::{collections::HashMap, fs, path::PathBuf};
#[cfg(test)]
use std::collections::HashSet;
#[cfg(test)]
use trnm_pouw::{
    apply_accept_task, apply_accept_task_at_height, apply_challenge, apply_challenge_at_height,
    apply_commit_result, apply_commit_result_at_height, apply_create_task, apply_resolve,
    apply_resolve_at_height, apply_reveal_result, apply_reveal_result_at_height, apply_timeout,
};
#[cfg(test)]
use trnm_state::{CheckpointMeta, WalMeta};
#[cfg(test)]
use trnm_state::{PendingResolveApprovalSnapshot, StateStore};
#[cfg(test)]
use trnm_types::{ObjectRef, TaskMeteringSnapshot, TaskStatus};

mod accounting;
mod apply;
mod args;
mod bft;
mod config;
mod demo;
mod error_kind;
mod events;
mod hash;
mod hot;
mod mempool;
mod metrics;
mod ordering;
mod recovery;
mod risk;
mod rl;
mod rollback;
mod run;
mod rwset;
mod summary;
mod timeout;
mod txmeta;
mod types;
mod wal;

#[cfg(test)]
use crate::accounting::{
    balance_deltas_for_transition, diff_u128_to_i128, event_delta_from_balances, treasury_total,
};
#[cfg(test)]
use crate::apply::{apply_one, verified_signer_of};
use crate::args::Args;
use crate::run::run_node;
#[cfg(test)]
use crate::args::{WalDirMode, DEFAULT_BFT_WAL_DIR};
#[cfg(test)]
use crate::bft::core::{
    accept_signed_vote, aggregate_votes, round_change_backoff_ms, select_proposer, vote_signature,
    MAX_BFT_NONCE_FORWARD_JUMP, MAX_BFT_TOKEN_LEN,
};
#[cfg(test)]
use crate::bft::model::{AuthRejectStats, BftVote, SignedVote, VoteType};
#[cfg(test)]
use crate::bft::model::{BftJitterControl, LeaderHealth};
#[cfg(test)]
use crate::demo::compute_commitment;
#[cfg(test)]
use crate::error_kind::classify_apply_error;
#[cfg(test)]
use crate::events::{event_type_for_apply_outcome, format_task_metering_event_fields};
#[cfg(test)]
use crate::hot::{
    hot_object_tail_share_ppm, hot_object_top_label_share_ppm, missed_proposals_added_since,
    summarize_hot_objects,
};
#[cfg(test)]
use crate::mempool::{pick_txs_with_critical_guard, requeue_uncommitted_txs};
#[cfg(test)]
use crate::metrics::{
    average_or_zero, finality_budget_share_ppm, gap_percent_bps, ratio_milli_u64,
    ratio_percent_bps, ratio_ppm, ratio_ppm_u64, wall_time_share_ppm,
};
#[cfg(test)]
use crate::ordering::decide_order_for_commit;
#[cfg(test)]
use crate::ordering::{pre_execute_group_parallel, PreExecPool};
#[cfg(test)]
use crate::recovery::metadata_only_recovery_error;
#[cfg(test)]
use crate::recovery::{ensure_recoverable_wal_state, recover_wal_state};
#[cfg(test)]
use crate::risk::{is_high_risk_tx, is_rejected_by_emergency_pause};
#[cfg(test)]
use crate::rl::{RlAdvisor, ShadowOnlyRlAdvisor};
#[cfg(test)]
use crate::rollback::TxRollbackSnapshot;
#[cfg(test)]
use crate::rollback::{capture_rollback_snapshot, rollback_tx_snapshot};
#[cfg(test)]
use crate::timeout::scan_and_apply_timeouts;
#[cfg(test)]
use crate::txmeta::task_id_of;
#[cfg(test)]
use crate::txmeta::{challenger_of, now_unix_ms};
#[cfg(test)]
use crate::types::HotObjectSummary;
#[cfg(test)]
use crate::types::RecoveredWalState;
#[cfg(test)]
use crate::types::{ConsensusWal, MockTx, RlAdviceContext};
#[cfg(test)]
use crate::wal::{
    load_checkpoint_meta, load_wal_meta_entries, persist_checkpoint_meta, persist_consensus_wal,
    persist_wal_meta_entries, resolve_wal_dir,
};
#[cfg(test)]
use crate::wal::{wal_file, wal_meta_file};

const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const RESOLVE_PENDING_APPROVAL_HOT_LABEL: &str = "resolve.pending_approval";
const RESOLVE_AUTHORITY_HOT_LABEL: &str = "governance.resolve_authority";

#[cfg(test)]
mod tests;

fn main() -> Result<()> {
    let args = Args::parse();
    run_node(args)
}
