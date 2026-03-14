use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use trnm_state::CheckpointMeta;
use trnm_types::Hash32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MockTx {
    CreateTask {
        task_id: u64,
        creator: String,
        bounty: u128,
    },
    AcceptTask {
        task_id: u64,
        worker: String,
    },
    Commit {
        task_id: u64,
        worker: String,
        committed_hash: Hash32,
    },
    Reveal {
        task_id: u64,
        result_hash: Hash32,
        reveal_salt: [u8; 32],
    },
    Challenge {
        task_id: u64,
        challenger: String,
        bond: u128,
    },
    Resolve {
        task_id: u64,
        slash_worker: bool,
        resolver: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RoundStep {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum VoteType {
    Prevote,
    Precommit,
}

#[derive(Debug, Clone)]
pub(crate) struct BftVote {
    pub(crate) validator: String,
    pub(crate) vote_type: VoteType,
    pub(crate) block_hash: String,
    pub(crate) byzantine: bool,
    pub(crate) height: u64,
    pub(crate) round: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct SignedVote {
    pub(crate) vote: BftVote,
    pub(crate) nonce: u64,
    pub(crate) signature: String,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct AuthRejectStats {
    pub(crate) bad_sig: usize,
    pub(crate) replay: usize,
    pub(crate) stale_nonce: usize,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LeaderHealth {
    pub(crate) missed_proposals: u64,
    pub(crate) penalty_until_round: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct BftJitterControl {
    pub(crate) missed_threshold: u64,
    pub(crate) penalty_rounds: u64,
    pub(crate) round_change_backoff_ms: u64,
    pub(crate) round_change_backoff_cap_ms: u64,
    pub(crate) leader_health: Vec<LeaderHealth>,
}

#[derive(Debug, Clone)]
pub(crate) struct BftHeightResult {
    pub(crate) committed: bool,
    pub(crate) committed_round: u64,
    pub(crate) round_changes: u64,
    pub(crate) prevote_count: usize,
    pub(crate) precommit_count: usize,
    pub(crate) double_vote_events: usize,
    pub(crate) auth_reject_bad_sig: usize,
    pub(crate) auth_reject_replay: usize,
    pub(crate) auth_reject_stale_nonce: usize,
    pub(crate) round_change_backoff_total_ms: u64,
    pub(crate) round_change_backoff_max_ms: u64,
    pub(crate) leader_missed_snapshot: Vec<u64>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct HotObjectSummary {
    pub(crate) hot_tx_count: usize,
    pub(crate) labels: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ConsensusWal {
    pub(crate) next_height: u64,
    pub(crate) last_round: u64,
    pub(crate) locked_block_hash: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct RecoveredWalState {
    pub(crate) next_height: u64,
    pub(crate) restored_lock: Option<String>,
    pub(crate) last_checkpoint: Option<CheckpointMeta>,
    pub(crate) truncated: bool,
    pub(crate) metadata_only_recovery: bool,
    pub(crate) wal_entries_retained: usize,
    pub(crate) checkpoint_height_retained: Option<u64>,
}

/// DA layer output consumed by ordering/consensus.
#[derive(Debug, Clone)]
pub(crate) struct DaBatch {
    pub(crate) tx_ids: Vec<u64>,
}

/// Ordering result passed into commit loop.
#[derive(Debug, Clone)]
pub(crate) struct OrderingDecision {
    pub(crate) ordered_ids: Vec<u64>,
    pub(crate) rejected: u64,
    pub(crate) preexec_elapsed_ms: u128,
    pub(crate) group_count: usize,
    pub(crate) critical_wait_blocks: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct RlAdviceContext {
    pub(crate) height: u64,
    pub(crate) ordered_ids: Vec<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct RlAdvice {
    pub(crate) suggested_ids: Vec<u64>,
    pub(crate) reason: &'static str,
}
