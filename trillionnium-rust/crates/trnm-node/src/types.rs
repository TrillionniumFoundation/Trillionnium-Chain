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
