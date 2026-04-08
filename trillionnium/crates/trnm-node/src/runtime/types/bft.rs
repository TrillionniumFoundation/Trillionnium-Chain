use super::*;

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
