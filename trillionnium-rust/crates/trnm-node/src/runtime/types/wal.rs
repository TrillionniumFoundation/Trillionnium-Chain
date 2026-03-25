use super::*;

pub(crate) const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
pub(crate) const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
pub(crate) const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
pub(crate) const RESOLVE_PENDING_APPROVAL_HOT_LABEL: &str = "resolve.pending_approval";
pub(crate) const RESOLVE_AUTHORITY_HOT_LABEL: &str = "governance.resolve_authority";

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct WalMetaList {
    pub(crate) entries: Vec<WalMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointMetaList {
    pub(crate) checkpoints: Vec<CheckpointMeta>,
}
