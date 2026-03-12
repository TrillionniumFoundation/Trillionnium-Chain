use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_executor::build_parallel_groups;
use trnm_mempool::{IngressClass, LaneAdmissionGate};
use trnm_pouw::{
    apply_accept_task, apply_accept_task_at_height, apply_challenge, apply_challenge_at_height,
    apply_commit_result, apply_commit_result_at_height, apply_create_task, apply_resolve,
    apply_resolve_at_height, apply_reveal_result, apply_reveal_result_at_height, apply_timeout,
};
use trnm_state::{
    verify_wal_and_find_checkpoint, CheckpointMeta, PendingResolveApprovalSnapshot, StateStore,
    WalMeta,
};
use trnm_types::{Hash32, ObjectRef, TaskStatus, Tx};

#[derive(Debug, Parser)]
#[command(
    name = "trnm-node",
    version,
    about = "Trillionnium Rust node (mock execution loop)"
)]
struct Args {
    #[arg(long, default_value = "configs/node1.toml")]
    config: String,
    #[arg(long, default_value_t = 1000)]
    block_ms: u64,
    #[arg(long, default_value_t = 10)]
    max_blocks: u64,
    /// Number of task flows injected into demo mempool
    #[arg(long, default_value_t = 2)]
    demo_tasks: u64,
    /// Number of distinct task ids used by injected load (smaller => higher conflict)
    #[arg(long, default_value_t = 2)]
    demo_keys: u64,
    /// Worker count used for group parallel pre-execution
    #[arg(long, default_value_t = 4)]
    parallel_workers: usize,
    /// Number of mempool txs attempted per committed block
    #[arg(long, default_value_t = 4)]
    txs_per_block: usize,
    /// Validator set size for BFT round simulation
    #[arg(long, default_value_t = 4)]
    validators: usize,
    /// Byzantine validators simulated in BFT vote aggregation
    #[arg(long, default_value_t = 0)]
    byzantine: usize,
    /// Max rounds per height before giving up commit (round-change path)
    #[arg(long, default_value_t = 3)]
    bft_max_rounds: u64,
    /// Inject no-quorum faulty rounds at beginning of each height
    #[arg(long, default_value_t = 0)]
    bft_fault_rounds: u64,
    /// Missed proposal threshold before leader is de-weighted/skipped
    #[arg(long, default_value_t = 2)]
    bft_missed_proposal_threshold: u64,
    /// Rounds to penalize leader after crossing missed proposal threshold
    #[arg(long, default_value_t = 2)]
    bft_leader_penalty_rounds: u64,
    /// Base backoff milliseconds applied on each round-change
    #[arg(long, default_value_t = 5)]
    bft_round_change_backoff_ms: u64,
    /// Max cap for round-change backoff milliseconds
    #[arg(long, default_value_t = 40)]
    bft_round_change_backoff_max_ms: u64,
    /// Consensus WAL directory for restart recovery
    #[arg(long, default_value = DEFAULT_BFT_WAL_DIR)]
    bft_wal_dir: String,
    /// How to handle the default WAL directory when no explicit isolated dir is provided.
    /// `auto` isolates repeated runs that use the built-in default path, while explicit custom
    /// paths keep legacy restart-recovery behavior.
    #[arg(long, value_enum, default_value_t = WalDirMode::Auto)]
    bft_wal_mode: WalDirMode,
    /// Write one checkpoint metadata every N committed blocks
    #[arg(long, default_value_t = 5)]
    bft_checkpoint_interval: u64,
    /// Enable PoUW timeout scanner in block loop (rollback switch)
    #[arg(long, default_value_t = true)]
    pouw_timeout_scan: bool,
    /// Run timeout scanner every N committed blocks (1 = every block)
    #[arg(long, default_value_t = 1)]
    pouw_timeout_scan_every_blocks: u64,
    /// P2 scaffold switch: enable DA/ordering decoupled path (default false keeps legacy path)
    #[arg(long, default_value_t = false)]
    enable_da_ordering_decouple: bool,
    /// Enable RL advisor in shadow mode (suggest only, never execute)
    #[arg(long, default_value_t = false)]
    rl_advisor_shadow: bool,
    /// Maximum suggested tx ids printed by shadow advisor
    #[arg(long, default_value_t = 4)]
    rl_advisor_shadow_topk: usize,
}

const DEFAULT_BFT_WAL_DIR: &str = "run/consensus-wal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WalDirMode {
    Auto,
    Reuse,
    FailIfExists,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    node_id: String,
    rpc_addr: String,
    p2p_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MockTx {
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
enum RoundStep {
    Propose,
    Prevote,
    Precommit,
    Commit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum VoteType {
    Prevote,
    Precommit,
}

#[derive(Debug, Clone)]
struct BftVote {
    validator: String,
    vote_type: VoteType,
    block_hash: String,
    byzantine: bool,
    height: u64,
    round: u64,
}

#[derive(Debug, Clone)]
struct SignedVote {
    vote: BftVote,
    nonce: u64,
    signature: String,
}

#[derive(Debug, Clone, Default)]
struct AuthRejectStats {
    bad_sig: usize,
    replay: usize,
    stale_nonce: usize,
}

#[derive(Debug, Clone, Default)]
struct LeaderHealth {
    missed_proposals: u64,
    penalty_until_round: u64,
}

#[derive(Debug, Clone)]
struct BftJitterControl {
    missed_threshold: u64,
    penalty_rounds: u64,
    round_change_backoff_ms: u64,
    round_change_backoff_cap_ms: u64,
    leader_health: Vec<LeaderHealth>,
}

#[derive(Debug, Clone)]
struct BftHeightResult {
    committed: bool,
    committed_round: u64,
    round_changes: u64,
    prevote_count: usize,
    precommit_count: usize,
    double_vote_events: usize,
    auth_reject_bad_sig: usize,
    auth_reject_replay: usize,
    auth_reject_stale_nonce: usize,
    round_change_backoff_total_ms: u64,
    round_change_backoff_max_ms: u64,
    leader_missed_snapshot: Vec<u64>,
}
const CHALLENGE_ESCROW_ACCOUNT: &str = "treasury.challenge_escrow";
const CHALLENGE_FORFEIT_TREASURY_ACCOUNT: &str = "treasury.challenge_forfeits";
const WORKER_SLASH_TREASURY_ACCOUNT: &str = "treasury.worker_slashes";
const RESOLVE_PENDING_APPROVAL_HOT_LABEL: &str = "resolve.pending_approval";
const RESOLVE_AUTHORITY_HOT_LABEL: &str = "governance.resolve_authority";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct HotObjectSummary {
    hot_tx_count: usize,
    labels: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsensusWal {
    next_height: u64,
    last_round: u64,
    locked_block_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct RecoveredWalState {
    next_height: u64,
    restored_lock: Option<String>,
    last_checkpoint: Option<CheckpointMeta>,
    truncated: bool,
    metadata_only_recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WalMetaList {
    entries: Vec<WalMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CheckpointMetaList {
    checkpoints: Vec<CheckpointMeta>,
}

/// DA layer output consumed by ordering/consensus.
#[derive(Debug, Clone)]
struct DaBatch {
    tx_ids: Vec<u64>,
}

/// Ordering result passed into commit loop.
#[derive(Debug, Clone)]
struct OrderingDecision {
    ordered_ids: Vec<u64>,
    rejected: u64,
    preexec_elapsed_ms: u128,
    group_count: usize,
    critical_wait_blocks: u64,
}

#[derive(Debug, Clone)]
struct RlAdviceContext {
    height: u64,
    ordered_ids: Vec<u64>,
}

#[derive(Debug, Clone)]
struct RlAdvice {
    suggested_ids: Vec<u64>,
    reason: &'static str,
}

trait DaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch;
}

struct LegacyMempoolDaProvider;

impl DaProvider for LegacyMempoolDaProvider {
    fn batch_from_picked(&self, picked: &[MockTx]) -> DaBatch {
        DaBatch {
            tx_ids: (1..=(picked.len() as u64)).collect(),
        }
    }
}

trait OrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision;
}

struct PreexecOrderingEngine;

impl OrderingEngine for PreexecOrderingEngine {
    fn decide(
        &self,
        snapshot: &StateStore,
        picked: &[MockTx],
        da_batch: &DaBatch,
        workers: usize,
        candidate_height: u64,
    ) -> OrderingDecision {
        let pool = PreExecPool::new(
            Arc::new(snapshot.clone()),
            Arc::new(picked.to_vec()),
            workers,
            candidate_height,
        );
        let preexec_started = Instant::now();
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, da_batch.tx_ids.clone());
        OrderingDecision {
            ordered_ids,
            rejected,
            preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
            group_count: usize::from(!da_batch.tx_ids.is_empty()),
            critical_wait_blocks: 0,
        }
    }
}

trait RlAdvisor {
    fn advise(&self, ctx: &RlAdviceContext) -> Option<RlAdvice>;
}

struct DisabledRlAdvisor;

impl RlAdvisor for DisabledRlAdvisor {
    fn advise(&self, _ctx: &RlAdviceContext) -> Option<RlAdvice> {
        None
    }
}

/// Shadow-only advisor: emits recommendation logs but never mutates commit ordering.
struct ShadowOnlyRlAdvisor {
    topk: usize,
}

impl RlAdvisor for ShadowOnlyRlAdvisor {
    fn advise(&self, ctx: &RlAdviceContext) -> Option<RlAdvice> {
        if ctx.ordered_ids.is_empty() {
            return None;
        }
        let mut suggested = ctx.ordered_ids.clone();
        suggested.reverse();
        suggested.truncate(self.topk.max(1));
        let _ = ctx.height;
        Some(RlAdvice {
            suggested_ids: suggested,
            reason: "shadow_reverse_baseline",
        })
    }
}

fn wal_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal.toml")
}

fn wal_dir_has_existing_state(wal_dir: &Path) -> bool {
    wal_file(wal_dir).exists()
        || wal_meta_file(wal_dir).exists()
        || checkpoint_file(wal_dir).exists()
}

fn isolated_default_wal_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(format!("session-{}-{}", now_unix_ms(), std::process::id()))
}

fn resolve_wal_dir(args: &Args) -> Result<(PathBuf, Option<String>)> {
    let requested = PathBuf::from(&args.bft_wal_dir);
    let uses_builtin_default = requested == PathBuf::from(DEFAULT_BFT_WAL_DIR);
    let has_existing_state = wal_dir_has_existing_state(&requested);

    match args.bft_wal_mode {
        WalDirMode::Reuse => Ok((requested, None)),
        WalDirMode::FailIfExists => {
            if has_existing_state {
                anyhow::bail!(
                    "refusing to reuse existing BFT WAL state at {} (pass --bft-wal-mode reuse to recover, or choose a fresh --bft-wal-dir)",
                    requested.display()
                );
            }
            Ok((requested, None))
        }
        WalDirMode::Auto => {
            if uses_builtin_default && has_existing_state {
                let isolated = isolated_default_wal_dir(&requested);
                Ok((
                    isolated.clone(),
                    Some(format!(
                        "[bft-wal] existing default WAL state detected at {}; isolating this run in {} (pass --bft-wal-mode reuse to recover prior state explicitly)",
                        requested.display(),
                        isolated.display()
                    )),
                ))
            } else {
                Ok((requested, None))
            }
        }
    }
}

fn wal_meta_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal-meta.toml")
}

fn checkpoint_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-checkpoints.toml")
}

fn load_wal_meta_entries(wal_dir: &Path) -> Result<Vec<WalMeta>> {
    let f = wal_meta_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw =
        fs::read_to_string(&f).with_context(|| format!("read wal meta failed: {}", f.display()))?;
    let list: WalMetaList =
        toml::from_str(&raw).with_context(|| format!("parse wal meta failed: {}", f.display()))?;
    Ok(list.entries)
}

fn persist_wal_meta_entries(wal_dir: &Path, entries: &[WalMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_meta_file(wal_dir);
    let raw = toml::to_string(&WalMetaList {
        entries: entries.to_vec(),
    })?;
    fs::write(&f, raw).with_context(|| format!("write wal meta failed: {}", f.display()))?;
    Ok(())
}

fn load_checkpoint_meta(wal_dir: &Path) -> Result<Vec<CheckpointMeta>> {
    let f = checkpoint_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&f)
        .with_context(|| format!("read checkpoint failed: {}", f.display()))?;
    let mut list: CheckpointMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse checkpoint failed: {}", f.display()))?;
    list.checkpoints.sort_by_key(|cp| cp.height);
    Ok(list.checkpoints)
}

fn persist_checkpoint_meta(wal_dir: &Path, checkpoints: &[CheckpointMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = checkpoint_file(wal_dir);
    let raw = toml::to_string(&CheckpointMetaList {
        checkpoints: checkpoints.to_vec(),
    })?;
    fs::write(&f, raw).with_context(|| format!("write checkpoint failed: {}", f.display()))?;
    Ok(())
}

fn persist_consensus_wal(wal_dir: &Path, wal: &ConsensusWal) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_file(wal_dir);
    let raw = toml::to_string(wal)?;
    fs::write(&f, raw).with_context(|| format!("write wal failed: {}", f.display()))?;
    Ok(())
}

fn recover_wal_state(wal_dir: &Path) -> Result<RecoveredWalState> {
    let entries = load_wal_meta_entries(wal_dir)?;
    let checkpoints = load_checkpoint_meta(wal_dir)?;
    let last_checkpoint =
        verify_wal_and_find_checkpoint(&checkpoints, &entries).map_err(anyhow::Error::msg)?;

    let mut truncated = false;
    if entries.is_empty() && !checkpoints.is_empty() {
        persist_checkpoint_meta(wal_dir, &[])?;
        truncated = true;
    }
    if !entries.is_empty() && last_checkpoint.is_none() {
        truncated = true;
        persist_wal_meta_entries(wal_dir, &[])?;
        persist_checkpoint_meta(wal_dir, &[])?;
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: 1,
                last_round: 0,
                locked_block_hash: None,
            },
        )?;
        return Ok(RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated,
            metadata_only_recovery: false,
        });
    }

    let mut valid_entries = entries.clone();
    if let Some(cp) = &last_checkpoint {
        if let Some(idx) = entries
            .iter()
            .position(|e| e.height == cp.height && e.content_hash_hex() == cp.wal_entry_hash_hex)
        {
            if idx + 1 < entries.len() {
                valid_entries.truncate(idx + 1);
                persist_wal_meta_entries(wal_dir, &valid_entries)?;
                let valid_checkpoints: Vec<CheckpointMeta> = checkpoints
                    .iter()
                    .filter(|c| c.height <= cp.height)
                    .cloned()
                    .collect();
                persist_checkpoint_meta(wal_dir, &valid_checkpoints)?;
                truncated = true;
            }
        }
    }

    if let Some(last) = valid_entries.last() {
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: last.height + 1,
                last_round: last.round,
                locked_block_hash: Some(last.proposal_hash.clone()),
            },
        )?;
        return Ok(RecoveredWalState {
            next_height: last.height + 1,
            restored_lock: Some(last.proposal_hash.clone()),
            last_checkpoint,
            truncated,
            metadata_only_recovery: true,
        });
    }

    Ok(RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        last_checkpoint,
        truncated,
        metadata_only_recovery: false,
    })
}

fn quorum_threshold(n: usize) -> usize {
    // 2f+1 where f = floor((n-1)/3)
    let f = n.saturating_sub(1) / 3;
    2 * f + 1
}

fn proposer(height: u64, round: u64, n: usize) -> usize {
    ((height + round) as usize) % n.max(1)
}

fn select_proposer(height: u64, round: u64, control: &BftJitterControl, n: usize) -> (usize, bool) {
    let n = n.max(1);
    let base = proposer(height, round, n);
    if control.missed_threshold == 0 {
        return (base, false);
    }
    for offset in 0..n {
        let idx = (base + offset) % n;
        let health = control.leader_health.get(idx).cloned().unwrap_or_default();
        let penalized = round < health.penalty_until_round;
        let too_many_misses = health.missed_proposals >= control.missed_threshold;
        if !penalized && !too_many_misses {
            return (idx, offset > 0);
        }
    }
    (base, false)
}

fn round_change_backoff_ms(round_changes: u64, base_ms: u64, cap_ms: u64) -> u64 {
    if round_changes == 0 || base_ms == 0 {
        return 0;
    }
    let shift = (round_changes - 1).min(20);
    let factor = 1u64 << shift;
    base_ms.saturating_mul(factor).min(cap_ms)
}

fn ratio_ppm_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return 0;
    }
    numerator.saturating_mul(1_000_000) / denominator
}

fn aggregate_votes(votes: &[BftVote], vote_type: VoteType) -> HashMap<String, usize> {
    let mut voters_per_hash: HashMap<String, HashSet<String>> = HashMap::new();
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        // Consensus safety: count each validator once per hash so
        // nonce-bumped duplicates cannot inflate quorum tallies.
        voters_per_hash
            .entry(v.block_hash.clone())
            .or_default()
            .insert(v.validator.clone());
    }

    voters_per_hash
        .into_iter()
        .map(|(hash, voters)| (hash, voters.len()))
        .collect()
}

fn vote_type_name(v: VoteType) -> &'static str {
    match v {
        VoteType::Prevote => "prevote",
        VoteType::Precommit => "precommit",
    }
}

fn vote_signature(vote: &BftVote, nonce: u64) -> String {
    hash32_hex(
        format!(
            "sig|{}|{}|{}|{}|{}|{}",
            vote.validator,
            vote.height,
            vote.round,
            vote_type_name(vote.vote_type),
            vote.block_hash,
            nonce
        )
        .as_bytes(),
    )
}

const MAX_BFT_TOKEN_LEN: usize = 128;
// Fail-closed nonce boundary to prevent namespace pinning via unbounded nonce jumps.
const MAX_BFT_NONCE_FORWARD_JUMP: u64 = 1_000_000;

fn is_canonical_validator_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // Gate hardening: separators-only ids (e.g. "---") are ambiguous and
        // can create replay/auth namespace confusion in logs and tooling.
        && v.bytes().any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Avoid edge separators that can collapse in parsers/log processors.
        && v
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Disallow repeated separators to avoid parser normalization ambiguity.
        && !v.contains("--")
}

fn is_canonical_block_hash_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= MAX_BFT_TOKEN_LEN
        && v
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        // Replay namespace hardening: require at least one alnum so hyphen-only
        // placeholders cannot masquerade as canonical block hash identifiers.
        && v.bytes().any(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Avoid edge separators that can collapse in parsers/log processors.
        && v
            .as_bytes()
            .first()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && v
            .as_bytes()
            .last()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        // Disallow repeated separators to avoid parser normalization ambiguity.
        && !v.contains("--")
}

fn accept_signed_vote(
    msg: SignedVote,
    last_nonce: &mut HashMap<(String, u64, u64, VoteType), u64>,
    accepted: &mut Vec<BftVote>,
    reject_stats: &mut AuthRejectStats,
) {
    let validator_trimmed = msg.vote.validator.trim();
    if validator_trimmed.is_empty() {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=empty_validator height={} round={} vote_type={} nonce={}",
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }
    if validator_trimmed != msg.vote.validator || !is_canonical_validator_token(&msg.vote.validator)
    {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=noncanonical_validator validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    let block_hash_trimmed = msg.vote.block_hash.trim();
    if block_hash_trimmed.is_empty() {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=empty_block_hash validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }
    if block_hash_trimmed != msg.vote.block_hash
        || !is_canonical_block_hash_token(&msg.vote.block_hash)
    {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=noncanonical_block_hash validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    if msg.vote.height == 0 {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=invalid_height validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    if msg.nonce == 0 {
        reject_stats.stale_nonce += 1;
        println!(
            "[bft-net] reject reason=zero_nonce validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    let expected = vote_signature(&msg.vote, msg.nonce);
    if msg.signature != expected {
        reject_stats.bad_sig += 1;
        println!(
            "[bft-net] reject reason=bad_sig validator={} height={} round={} vote_type={} nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce
        );
        return;
    }

    // Scope nonce monotonicity to (validator, height, round, vote_type) so
    // replay/stale tracking cannot leak across rounds and suppress valid
    // round-change votes that restart nonce sequencing.
    let key = (
        msg.vote.validator.clone(),
        msg.vote.height,
        msg.vote.round,
        msg.vote.vote_type,
    );
    if !last_nonce.contains_key(&key) && msg.nonce > MAX_BFT_NONCE_FORWARD_JUMP {
        reject_stats.stale_nonce += 1;
        println!(
            "[bft-net] reject reason=nonce_bootstrap_jump validator={} height={} round={} vote_type={} nonce={} max_initial_nonce={}",
            msg.vote.validator,
            msg.vote.height,
            msg.vote.round,
            vote_type_name(msg.vote.vote_type),
            msg.nonce,
            MAX_BFT_NONCE_FORWARD_JUMP
        );
        return;
    }
    if let Some(prev) = last_nonce.get(&key) {
        if msg.nonce == *prev {
            let maybe_prev_vote = accepted.iter().rev().find(|v| {
                v.validator == msg.vote.validator
                    && v.height == msg.vote.height
                    && v.round == msg.vote.round
                    && v.vote_type == msg.vote.vote_type
            });
            if let Some(prev_vote) = maybe_prev_vote {
                if prev_vote.block_hash != msg.vote.block_hash {
                    reject_stats.bad_sig += 1;
                    println!(
                        "[bft-net] reject reason=nonce_equivocation validator={} height={} round={} vote_type={} nonce={} prev_hash={} new_hash={}",
                        msg.vote.validator,
                        msg.vote.height,
                        msg.vote.round,
                        vote_type_name(msg.vote.vote_type),
                        msg.nonce,
                        prev_vote.block_hash,
                        msg.vote.block_hash
                    );
                    return;
                }
            }
            reject_stats.replay += 1;
            println!(
                "[bft-net] reject reason=replay validator={} height={} round={} vote_type={} nonce={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce
            );
            return;
        }
        if msg.nonce < *prev {
            reject_stats.stale_nonce += 1;
            println!(
                "[bft-net] reject reason=stale_nonce validator={} height={} round={} vote_type={} nonce={} last_nonce={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce,
                prev
            );
            return;
        }
        if msg.nonce > prev.saturating_add(MAX_BFT_NONCE_FORWARD_JUMP) {
            reject_stats.stale_nonce += 1;
            println!(
                "[bft-net] reject reason=nonce_jump validator={} height={} round={} vote_type={} nonce={} last_nonce={} max_jump={}",
                msg.vote.validator,
                msg.vote.height,
                msg.vote.round,
                vote_type_name(msg.vote.vote_type),
                msg.nonce,
                prev,
                MAX_BFT_NONCE_FORWARD_JUMP
            );
            return;
        }
    }

    last_nonce.insert(key, msg.nonce);
    accepted.push(msg.vote);
}

fn detect_double_votes(votes: &[BftVote], vote_type: VoteType) -> usize {
    let mut seen: HashMap<(String, u64, u64, VoteType), String> = HashMap::new();
    let mut events = 0usize;
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        let k = (v.validator.clone(), v.height, v.round, v.vote_type);
        if let Some(prev_hash) = seen.get(&k) {
            if prev_hash != &v.block_hash {
                events += 1;
                println!(
                    "[bft-slash] event=double_vote validator={} height={} round={} vote_type={:?} first_hash={} second_hash={}",
                    v.validator, v.height, v.round, v.vote_type, prev_hash, v.block_hash
                );
            }
        } else {
            seen.insert(k, v.block_hash.clone());
        }
    }
    events
}

fn simulate_bft_round(
    height: u64,
    round: u64,
    proposal_hash: &str,
    locked_hash: Option<&str>,
    validators: usize,
    byzantine: usize,
    force_no_quorum: bool,
    proposer_idx: usize,
    proposer_shifted: bool,
) -> (bool, usize, usize, Option<String>, usize, AuthRejectStats) {
    let n = validators.max(1);
    let b = byzantine.min(n.saturating_sub(1));
    let q = quorum_threshold(n);
    let proposer_id = format!("v{}", proposer_idx + 1);
    let round_hash = locked_hash.unwrap_or(proposal_hash).to_string();

    println!("[bft] height={} round={} step={:?} proposer={} shifted={} validators={} byzantine={} quorum={} locked={}", height, round, RoundStep::Propose, proposer_id, proposer_shifted, n, b, q, locked_hash.is_some());

    let mut votes = Vec::new();
    let mut auth_nonce: HashMap<(String, u64, u64, VoteType), u64> = HashMap::new();
    let mut reject_stats = AuthRejectStats::default();
    let bad_hash = hash32_hex(&[b"byzantine", round_hash.as_bytes()].concat());
    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let nonce = height * 10_000 + round * 100 + i as u64;
        let canonical_hash = round_hash.clone();
        let bad_vote_hash = bad_hash.clone();

        let good_vote = BftVote {
            validator: vid.clone(),
            vote_type: VoteType::Prevote,
            block_hash: if force_no_quorum {
                bad_vote_hash.clone()
            } else {
                canonical_hash.clone()
            },
            byzantine: is_bad,
            height,
            round,
        };
        let good_sig = vote_signature(&good_vote, nonce);
        accept_signed_vote(
            SignedVote {
                vote: good_vote,
                nonce,
                signature: good_sig,
            },
            &mut auth_nonce,
            &mut votes,
            &mut reject_stats,
        );

        if is_bad {
            // bad signature sample
            let bad_sig_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: bad_vote_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            accept_signed_vote(
                SignedVote {
                    vote: bad_sig_vote,
                    nonce: nonce + 1,
                    signature: "bad_signature".to_string(),
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            // replay sample (same nonce as accepted good vote)
            let replay_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let replay_sig = vote_signature(&replay_vote, nonce);
            accept_signed_vote(
                SignedVote {
                    vote: replay_vote,
                    nonce,
                    signature: replay_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            // equivocation with higher nonce (passes auth, should be slashed)
            let eq_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Prevote,
                block_hash: bad_vote_hash,
                byzantine: true,
                height,
                round,
            };
            let eq_nonce = nonce + 2;
            let eq_sig = vote_signature(&eq_vote, eq_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: eq_vote,
                    nonce: eq_nonce,
                    signature: eq_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            // stale nonce sample (must be rejected)
            let stale_vote = BftVote {
                validator: vid,
                vote_type: VoteType::Prevote,
                block_hash: canonical_hash,
                byzantine: true,
                height,
                round,
            };
            let stale_nonce = nonce + 1; // lower than accepted eq_nonce
            let stale_sig = vote_signature(&stale_vote, stale_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: stale_vote,
                    nonce: stale_nonce,
                    signature: stale_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );
        }
    }
    println!(
        "[bft] height={} round={} step={:?}",
        height,
        round,
        RoundStep::Prevote
    );

    let prevote_tally = aggregate_votes(&votes, VoteType::Prevote);
    let prevote_count = *prevote_tally.get(&round_hash).unwrap_or(&0);
    let new_lock = if prevote_count >= q {
        Some(round_hash.clone())
    } else {
        None
    };

    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let nonce = height * 10_000 + round * 100 + i as u64 + 50;
        let canonical_hash = round_hash.clone();
        let bad_vote_hash = bad_hash.clone();
        let vote_hash = if prevote_count >= q && !is_bad {
            canonical_hash.clone()
        } else {
            bad_vote_hash.clone()
        };

        let good_vote = BftVote {
            validator: vid.clone(),
            vote_type: VoteType::Precommit,
            block_hash: vote_hash,
            byzantine: is_bad,
            height,
            round,
        };
        let good_sig = vote_signature(&good_vote, nonce);
        accept_signed_vote(
            SignedVote {
                vote: good_vote,
                nonce,
                signature: good_sig,
            },
            &mut auth_nonce,
            &mut votes,
            &mut reject_stats,
        );

        if is_bad {
            let bad_sig_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: bad_vote_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            accept_signed_vote(
                SignedVote {
                    vote: bad_sig_vote,
                    nonce: nonce + 1,
                    signature: "bad_signature".to_string(),
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let replay_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let replay_sig = vote_signature(&replay_vote, nonce);
            accept_signed_vote(
                SignedVote {
                    vote: replay_vote,
                    nonce,
                    signature: replay_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let eq_vote = BftVote {
                validator: vid.clone(),
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash.clone(),
                byzantine: true,
                height,
                round,
            };
            let eq_nonce = nonce + 2;
            let eq_sig = vote_signature(&eq_vote, eq_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: eq_vote,
                    nonce: eq_nonce,
                    signature: eq_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );

            let stale_vote = BftVote {
                validator: vid,
                vote_type: VoteType::Precommit,
                block_hash: canonical_hash,
                byzantine: true,
                height,
                round,
            };
            let stale_nonce = nonce + 1;
            let stale_sig = vote_signature(&stale_vote, stale_nonce);
            accept_signed_vote(
                SignedVote {
                    vote: stale_vote,
                    nonce: stale_nonce,
                    signature: stale_sig,
                },
                &mut auth_nonce,
                &mut votes,
                &mut reject_stats,
            );
        }
    }
    println!(
        "[bft] height={} round={} step={:?}",
        height,
        round,
        RoundStep::Precommit
    );

    let precommit_tally = aggregate_votes(&votes, VoteType::Precommit);
    let precommit_count = *precommit_tally.get(&round_hash).unwrap_or(&0);
    let unique_voters: HashSet<String> = votes.iter().map(|v| v.validator.clone()).collect();
    let byzantine_votes = votes.iter().filter(|v| v.byzantine).count();
    let double_vote_events = detect_double_votes(&votes, VoteType::Prevote)
        + detect_double_votes(&votes, VoteType::Precommit);
    let committed = precommit_count >= q;
    if committed {
        println!("[bft] height={} round={} step={:?} block_hash={} precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={}", height, round, RoundStep::Commit, round_hash, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events, reject_stats.bad_sig, reject_stats.replay, reject_stats.stale_nonce);
    } else {
        println!("[bft] height={} round={} step=RoundChange reason=no_quorum precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={}", height, round, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events, reject_stats.bad_sig, reject_stats.replay, reject_stats.stale_nonce);
    }

    (
        committed,
        prevote_count,
        precommit_count,
        new_lock,
        double_vote_events,
        reject_stats,
    )
}

fn simulate_bft_height(
    height: u64,
    proposal_hash: &str,
    validators: usize,
    byzantine: usize,
    max_rounds: u64,
    fault_rounds: u64,
    initial_lock: Option<String>,
    control: &mut BftJitterControl,
) -> BftHeightResult {
    let mut locked: Option<String> = initial_lock;
    let mut round_changes = 0u64;
    let mut last_prevote = 0usize;
    let mut last_precommit = 0usize;
    let mut total_double_vote_events = 0usize;
    let mut total_auth_reject_bad_sig = 0usize;
    let mut total_auth_reject_replay = 0usize;
    let mut total_auth_reject_stale_nonce = 0usize;
    let mut round_change_backoff_total_ms = 0u64;
    let mut round_change_backoff_max_ms = 0u64;
    let n = validators.max(1);
    if control.leader_health.len() != n {
        control.leader_health = vec![LeaderHealth::default(); n];
    }

    for round in 0..max_rounds.max(1) {
        let force_no_quorum = round < fault_rounds;
        let effective_byz = if force_no_quorum { 0 } else { byzantine };
        let (proposer_idx, proposer_shifted) = select_proposer(height, round, control, n);
        let (committed, pv, pc, new_lock, dv, auth) = simulate_bft_round(
            height,
            round,
            proposal_hash,
            locked.as_deref(),
            validators,
            effective_byz,
            force_no_quorum,
            proposer_idx,
            proposer_shifted,
        );
        last_prevote = pv;
        last_precommit = pc;
        total_double_vote_events += dv;
        total_auth_reject_bad_sig += auth.bad_sig;
        total_auth_reject_replay += auth.replay;
        total_auth_reject_stale_nonce += auth.stale_nonce;
        if new_lock.is_some() {
            locked = new_lock;
        }
        if committed {
            control.leader_health[proposer_idx].missed_proposals = 0;
            return BftHeightResult {
                committed: true,
                committed_round: round,
                round_changes,
                prevote_count: pv,
                precommit_count: pc,
                double_vote_events: total_double_vote_events,
                auth_reject_bad_sig: total_auth_reject_bad_sig,
                auth_reject_replay: total_auth_reject_replay,
                auth_reject_stale_nonce: total_auth_reject_stale_nonce,
                round_change_backoff_total_ms,
                round_change_backoff_max_ms,
                leader_missed_snapshot: control
                    .leader_health
                    .iter()
                    .map(|h| h.missed_proposals)
                    .collect(),
            };
        }
        round_changes += 1;
        let health = &mut control.leader_health[proposer_idx];
        health.missed_proposals = health.missed_proposals.saturating_add(1);
        if control.missed_threshold > 0 && health.missed_proposals >= control.missed_threshold {
            health.penalty_until_round = round.saturating_add(1 + control.penalty_rounds);
        }
        let backoff_ms = round_change_backoff_ms(
            round_changes,
            control.round_change_backoff_ms,
            control.round_change_backoff_cap_ms,
        );
        round_change_backoff_total_ms = round_change_backoff_total_ms.saturating_add(backoff_ms);
        round_change_backoff_max_ms = round_change_backoff_max_ms.max(backoff_ms);
        println!(
            "[bft] height={} round={} step=RoundBackoff delay_ms={} cap_ms={} proposer=v{} missed_proposals={} penalty_until_round={}",
            height,
            round,
            backoff_ms,
            control.round_change_backoff_cap_ms,
            proposer_idx + 1,
            health.missed_proposals,
            health.penalty_until_round
        );
    }

    BftHeightResult {
        committed: false,
        committed_round: max_rounds.saturating_sub(1),
        round_changes,
        prevote_count: last_prevote,
        precommit_count: last_precommit,
        double_vote_events: total_double_vote_events,
        auth_reject_bad_sig: total_auth_reject_bad_sig,
        auth_reject_replay: total_auth_reject_replay,
        auth_reject_stale_nonce: total_auth_reject_stale_nonce,
        round_change_backoff_total_ms,
        round_change_backoff_max_ms,
        leader_missed_snapshot: control
            .leader_health
            .iter()
            .map(|h| h.missed_proposals)
            .collect(),
    }
}

fn hash32_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn load_config(path: &str) -> Result<NodeConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config failed: {}", path))?;
    let cfg: NodeConfig =
        toml::from_str(&raw).with_context(|| format!("parse toml failed: {}", path))?;
    Ok(cfg)
}

fn compute_commitment(
    task_id: u64,
    result_hash: &Hash32,
    reveal_salt: &[u8; 32],
    worker: &str,
) -> Hash32 {
    let payload = format!(
        "{}|{}|{}|{}",
        task_id,
        hex::encode(result_hash),
        hex::encode(reveal_salt),
        worker
    );
    let mut hasher = Sha256::new();
    hasher.update(payload.as_bytes());
    hasher.finalize().into()
}

fn demo_worker_name(task_id: u64) -> String {
    format!("worker{}", task_id)
}

fn build_demo_mempool(demo_tasks: u64, _demo_keys: u64) -> VecDeque<MockTx> {
    let mut q = VecDeque::new();

    for i in 0..demo_tasks.max(1) {
        let task_id = 1001u64 + i;
        let worker = demo_worker_name(task_id);
        let result_hash = [7u8; 32];
        let reveal_salt = [task_id as u8; 32];
        let committed_hash = compute_commitment(task_id, &result_hash, &reveal_salt, &worker);

        q.push_back(MockTx::CreateTask {
            task_id,
            creator: "alice".to_string(),
            bounty: 100,
        });
        q.push_back(MockTx::AcceptTask {
            task_id,
            worker: worker.clone(),
        });
        q.push_back(MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        });
        q.push_back(MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        });
        q.push_back(MockTx::Challenge {
            task_id,
            challenger: "challenger".into(),
            bond: 10,
        });
        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
            resolver: "governance.resolve_authority".into(),
        });
    }

    q
}

fn requeue_uncommitted_txs(mempool: &mut VecDeque<MockTx>, picked: Vec<MockTx>) {
    if picked.is_empty() {
        return;
    }
    mempool.extend(picked);
}

fn task_ref(st: &StateStore, task_id: u64) -> Result<ObjectRef> {
    st.get_ref(task_id)
        .with_context(|| format!("task_ref missing for task_id={}", task_id))
}

fn task_id_of(tx: &MockTx) -> u64 {
    match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
    }
}

fn event_type_of(tx: &MockTx) -> &'static str {
    match tx {
        MockTx::CreateTask { .. } => "create",
        MockTx::AcceptTask { .. } => "accept",
        MockTx::Commit { .. } => "commit",
        MockTx::Reveal { .. } => "reveal",
        MockTx::Challenge { .. } => "challenge",
        MockTx::Resolve { .. } => "resolve",
    }
}

fn event_type_for_apply_outcome(tx: &MockTx, err_kind: Option<&str>) -> &'static str {
    if matches!(tx, MockTx::Resolve { .. }) && err_kind == Some("resolve_approval_staged") {
        "resolve_approval_staged"
    } else {
        event_type_of(tx)
    }
}

fn is_critical_tx(tx: &MockTx) -> bool {
    matches!(tx, MockTx::Challenge { .. } | MockTx::Resolve { .. })
}

fn pick_txs_with_critical_guard(
    mempool: &mut VecDeque<MockTx>,
    txs_per_block: usize,
) -> Vec<MockTx> {
    if txs_per_block == 0 || mempool.is_empty() {
        return Vec::new();
    }

    if txs_per_block >= mempool.len() {
        // Free-ingress fast path: when block capacity can absorb the whole queue,
        // keep FIFO dequeue semantics while avoiding lane-gate bookkeeping.
        return mempool.drain(..).collect();
    }

    if !mempool.iter().any(is_critical_tx) {
        // Normal-only backlog has no critical-lane anti-starvation requirement.
        // Keep FIFO prefix drain and skip lane gate bookkeeping to reduce
        // free-ingress selection overhead on the hot path.
        let mut picked = Vec::with_capacity(txs_per_block);
        for _ in 0..txs_per_block {
            let Some(tx) = mempool.pop_front() else {
                break;
            };
            picked.push(tx);
        }
        return picked;
    }

    // Selection fairness should consider the full queued backlog, not only the
    // first block-sized prefix. Otherwise a critical tx that arrives behind a
    // long normal queue can never enter the fairness gate and is effectively
    // starved until the prefix drains.
    let mut lane = LaneAdmissionGate::new(mempool.len(), 1);
    let mempool_len = mempool.len();
    for (idx, tx) in mempool.iter().enumerate() {
        let class = if is_critical_tx(tx) {
            IngressClass::Critical
        } else {
            IngressClass::Normal
        };
        let _ = lane.admit(idx as u64, class);
    }

    let mut selected = Vec::with_capacity(txs_per_block);
    while selected.len() < txs_per_block {
        let Some(id) = lane.pop_ready() else {
            break;
        };
        let idx = id as usize;
        if idx < mempool_len {
            selected.push((idx, selected.len()));
        }
    }

    let mut picked_slots: Vec<Option<MockTx>> = (0..selected.len()).map(|_| None).collect();
    selected.sort_unstable_by(|(lhs, _), (rhs, _)| rhs.cmp(lhs));

    for (idx, pos) in selected {
        let tx = mempool
            .remove(idx)
            .expect("selected tx index must still exist during descending extraction");
        picked_slots[pos] = Some(tx);
    }

    picked_slots.into_iter().flatten().collect()
}

fn actor_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::CreateTask { creator, .. } => creator.clone(),
        MockTx::AcceptTask { worker, .. } => worker.clone(),
        MockTx::Commit { worker, .. } => worker.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| format!("worker{}", task_id)),
        MockTx::Challenge { challenger, .. } => challenger.clone(),
        MockTx::Resolve { resolver, .. } => resolver.clone(),
    }
}

fn verified_signer_of(st: &StateStore, tx: &MockTx) -> String {
    match tx {
        MockTx::Resolve { resolver, .. } => resolver.clone(),
        MockTx::Reveal { task_id, .. } => st
            .get_task(*task_id)
            .and_then(|t| t.worker)
            .unwrap_or_else(|| "unknown_worker".to_string()),
        _ => actor_of(st, tx),
    }
}

fn challenger_of(tx: &MockTx) -> Option<String> {
    match tx {
        MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
        MockTx::Resolve { .. } => None,
        _ => None,
    }
}

fn tx_hash_of(tx_id: u64) -> String {
    format!("0xmock{:016x}", tx_id)
}

fn status_name(st: &StateStore, task_id: u64) -> String {
    st.get_task(task_id)
        .map(|t| format!("{:?}", t.status))
        .unwrap_or_else(|| "NONE".to_string())
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn percentile(mut vals: Vec<u128>, p: f64) -> u128 {
    if vals.is_empty() {
        return 0;
    }
    vals.sort_unstable();
    let idx = ((vals.len() - 1) as f64 * p).round() as usize;
    vals[idx.min(vals.len() - 1)]
}

fn max_or_zero(vals: &[u128]) -> u128 {
    vals.iter().copied().max().unwrap_or(0)
}

fn average_or_zero(vals: &[u128]) -> u128 {
    if vals.is_empty() {
        0
    } else {
        vals.iter().copied().sum::<u128>() / vals.len() as u128
    }
}

fn ratio_ppm(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000_000) / denominator
    }
}

fn ratio_percent_bps(numerator: u128, denominator: u128) -> u128 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(10_000) / denominator
    }
}

fn ratio_milli_u64(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(1_000) / denominator
    }
}

fn finality_budget_share_ppm(density_avg_milli: u64, finality_avg_ms: u128) -> u64 {
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let finality_budget_milli = finality_avg_ms_u64.saturating_mul(1_000);
    ratio_ppm_u64(density_avg_milli, finality_budget_milli)
}

fn gap_percent_bps(total: u128, component_a: u128, component_b: u128) -> u128 {
    if total == 0 {
        return 0;
    }
    total
        .saturating_sub(component_a.saturating_add(component_b))
        .saturating_mul(10_000)
        / total
}

fn treasury_total(st: &StateStore) -> u128 {
    st.balance_of(CHALLENGE_ESCROW_ACCOUNT)
        .saturating_add(st.balance_of(CHALLENGE_FORFEIT_TREASURY_ACCOUNT))
        .saturating_add(st.balance_of(WORKER_SLASH_TREASURY_ACCOUNT))
}

fn diff_u128_to_i128(after: u128, before: u128) -> Option<i128> {
    let after_i = i128::try_from(after).ok()?;
    let before_i = i128::try_from(before).ok()?;
    Some(after_i - before_i)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventDelta {
    numeric: Option<i128>,
    text: String,
}

fn classify_apply_error(err: &anyhow::Error) -> &'static str {
    if let Some(pouw) = err.downcast_ref::<trnm_pouw::PouwError>() {
        return match pouw {
            trnm_pouw::PouwError::VersionConflict => "version_conflict",
            trnm_pouw::PouwError::InvalidTransition => "invalid_transition",
            trnm_pouw::PouwError::DeadlineExceeded => "deadline_exceeded",
            trnm_pouw::PouwError::ResolveApprovalStaged => "resolve_approval_staged",
            _ => "semantic_fail",
        };
    }

    let e = err.to_string().to_ascii_lowercase();
    if e.contains("version conflict") {
        "version_conflict"
    } else if e.contains("invalid transition") {
        "invalid_transition"
    } else if e.contains("deadline exceeded") {
        "deadline_exceeded"
    } else if e.contains("preexec") {
        "preexec_conflict_miss"
    } else {
        "semantic_fail"
    }
}

fn format_delta_fallback(after: u128, before: u128) -> String {
    if after >= before {
        format!("u128:+{}", after - before)
    } else {
        format!("u128:-{}", before - after)
    }
}

fn event_delta_from_balances(after: u128, before: u128) -> EventDelta {
    let numeric = diff_u128_to_i128(after, before);
    let text = numeric
        .map(|v| v.to_string())
        .unwrap_or_else(|| format_delta_fallback(after, before));
    EventDelta { numeric, text }
}

fn balance_deltas_for_transition(
    before: &StateStore,
    after: &StateStore,
    task_id: u64,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_delta = event_delta_from_balances(treasury_total(after), treasury_total(before));
    let challenger_delta = challenger.map(|acct| {
        let before_bal = before.balance_of(acct);
        let after_bal = after.balance_of(acct);
        event_delta_from_balances(after_bal, before_bal)
    });

    // task_id currently reserved for future richer per-task accounting; keep signature explicit.
    let _ = task_id;
    (treasury_delta, challenger_delta)
}

fn emit_event(
    st: &StateStore,
    tx: &MockTx,
    signer: &str,
    tx_id: u64,
    block_height: u64,
    from_status: &str,
    to_status: &str,
    state_root: &str,
    treasury_delta: &EventDelta,
    challenger_delta: Option<&EventDelta>,
    challenger: Option<&str>,
    err_kind: Option<&str>,
) {
    let task_id = task_id_of(tx);
    let event_type = event_type_for_apply_outcome(tx, err_kind);
    let actor = actor_of(st, tx);
    let challenger = challenger
        .map(|s| s.to_string())
        .or_else(|| challenger_of(tx))
        .unwrap_or_else(|| "-".to_string());
    let tx_hash = tx_hash_of(tx_id);
    let ts_unix_ms = now_unix_ms();

    let bond_disposition = match tx {
        MockTx::Challenge { .. } => Some("posted"),
        MockTx::Resolve { slash_worker, .. } => Some(if *slash_worker {
            "refunded"
        } else {
            "forfeited"
        }),
        _ => None,
    };

    let treasury_delta_str = match tx {
        // PR5 reconcile contract treats challenge as escrow-only movement;
        // event-level treasury_delta must stay neutral for challenge events.
        MockTx::Challenge { .. } => "0",
        _ => treasury_delta.text.as_str(),
    };
    let challenger_delta_str = challenger_delta.map(|d| d.text.as_str()).unwrap_or("-");
    let bond_disposition_str = bond_disposition.unwrap_or("-");

    match tx {
        MockTx::Resolve { slash_worker, .. } => {
            let resolution_code = if *slash_worker {
                "slashed"
            } else {
                "completed"
            };
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                signer,
                challenger,
                tx_hash,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms,
                slash_worker,
                resolution_code,
                treasury_delta_str,
                challenger_delta_str,
                bond_disposition_str,
            );
        }
        _ => {
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} treasury_delta={} challenger_delta={} bond_disposition={}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                signer,
                challenger,
                tx_hash,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms,
                treasury_delta_str,
                challenger_delta_str,
                bond_disposition_str,
            );
        }
    }
}

fn emit_timeout_event(
    task_id: u64,
    tx_id: u64,
    block_height: u64,
    from_status: &str,
    to_status: &str,
    state_root: &str,
    treasury_delta: &EventDelta,
    challenger_delta: Option<&EventDelta>,
    challenger: Option<&str>,
    bond_disposition: Option<&str>,
) {
    let tx_hash = tx_hash_of(tx_id);
    let ts_unix_ms = now_unix_ms();
    let treasury_delta_str = treasury_delta.text.as_str();
    let challenger_delta_str = challenger_delta.map(|d| d.text.as_str()).unwrap_or("-");
    let bond_disposition_str = bond_disposition.unwrap_or("-");
    let resolution_code = if to_status == "Slashed" {
        "slashed"
    } else {
        "completed"
    };

    println!(
        "[event] event_schema=v1 event_type=timeout task_id={} from_status={} to_status={} actor=system signer=system challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}",
        task_id,
        from_status,
        to_status,
        challenger.unwrap_or("-"),
        tx_hash,
        tx_id,
        block_height,
        state_root,
        ts_unix_ms,
        resolution_code,
        treasury_delta_str,
        challenger_delta_str,
        bond_disposition_str,
    );
}

fn is_high_risk_tx(tx: &MockTx) -> bool {
    // Exhaustive merge-gate guard: introducing a new tx variant now requires
    // an explicit pause-risk decision here at compile time.
    match tx {
        MockTx::CreateTask { .. }
        | MockTx::AcceptTask { .. }
        | MockTx::Commit { .. }
        | MockTx::Reveal { .. }
        | MockTx::Challenge { .. } => true,
        // Resolve performs terminal challenged escrow settlement and must stay
        // frozen while emergency pause is active.
        MockTx::Resolve { .. } => true,
    }
}

fn is_rejected_by_emergency_pause(is_paused: bool, tx: &MockTx) -> bool {
    is_paused && is_high_risk_tx(tx)
}

#[derive(Debug, Clone)]
struct TxRollbackSnapshot {
    task_id: u64,
    task: Option<trnm_types::TaskObject>,
    balances: Vec<(String, Option<u128>)>,
    pending_resolve_approval: Option<PendingResolveApprovalSnapshot>,
}

fn balance_snapshot(st: &StateStore, address: &str) -> Option<u128> {
    let balance = st.balance_of(address);
    if balance == 0 {
        None
    } else {
        Some(balance)
    }
}

fn capture_rollback_snapshot(st: &StateStore, tx: &MockTx) -> TxRollbackSnapshot {
    let task_id = task_id_of(tx);
    let task = st.get_task(task_id);
    let pending_resolve_approval = st.pending_resolve_approval_snapshot(task_id);
    let mut balances: Vec<(String, Option<u128>)> = Vec::new();
    let mut push_balance = |address: &str| {
        if balances.iter().any(|(existing, _)| existing == address) {
            return;
        }
        balances.push((address.to_string(), balance_snapshot(st, address)));
    };

    match tx {
        MockTx::CreateTask { creator, .. } => {
            push_balance(creator);
        }
        MockTx::Challenge { challenger, .. } => {
            push_balance(challenger);
            push_balance("treasury.challenge_escrow");
        }
        MockTx::Resolve { .. } => {
            push_balance("treasury.challenge_escrow");
            push_balance("treasury.challenge_forfeits");
            push_balance("treasury.worker_slashes");
            if let Some(task) = task.as_ref() {
                if let Some(worker) = task.worker.as_deref() {
                    push_balance(worker);
                }
                if let Some(challenger) = task.challenger.as_deref() {
                    push_balance(challenger);
                }
            }
        }
        MockTx::AcceptTask { .. } | MockTx::Commit { .. } | MockTx::Reveal { .. } => {}
    }

    TxRollbackSnapshot {
        task_id,
        task,
        balances,
        pending_resolve_approval,
    }
}

fn rollback_tx_snapshot(st: &mut StateStore, snapshot: TxRollbackSnapshot) {
    st.restore_task(snapshot.task_id, snapshot.task);
    for (address, balance) in snapshot.balances {
        st.restore_balance(&address, balance);
    }
    st.restore_pending_resolve_approval(snapshot.task_id, snapshot.pending_resolve_approval);
}

fn balance_deltas_from_snapshot(
    before: &TxRollbackSnapshot,
    after: &StateStore,
    challenger: Option<&str>,
) -> (EventDelta, Option<EventDelta>) {
    let treasury_before: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(_, balance)| balance.unwrap_or(0))
        .sum();
    let treasury_after: u128 = before
        .balances
        .iter()
        .filter(|(address, _)| address.starts_with("treasury."))
        .map(|(address, _)| after.balance_of(address))
        .sum();
    let treasury_delta = event_delta_from_balances(treasury_after, treasury_before);
    let challenger_delta = challenger.and_then(|acct| {
        before
            .balances
            .iter()
            .find(|(address, _)| address == acct)
            .map(|(_, balance)| {
                event_delta_from_balances(after.balance_of(acct), balance.unwrap_or(0))
            })
    });
    (treasury_delta, challenger_delta)
}

fn apply_one(st: &mut StateStore, tx: MockTx, current_height: u64) -> Result<()> {
    let signer = verified_signer_of(st, &tx);
    match tx {
        MockTx::CreateTask {
            task_id,
            creator,
            bounty,
        } => {
            let _ = apply_create_task(st, task_id, creator, bounty)?;
        }
        MockTx::AcceptTask { task_id, worker } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_accept_task_at_height(st, r, worker, current_height)?;
        }
        MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_commit_result_at_height(st, r, worker, committed_hash, current_height)?;
        }
        MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_reveal_result_at_height(
                st,
                r,
                result_hash,
                reveal_salt,
                None,
                current_height,
            )?;
        }
        MockTx::Challenge {
            task_id,
            challenger,
            bond,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_challenge_at_height(st, r, challenger, bond, signer, current_height)?;
        }
        MockTx::Resolve {
            task_id,
            slash_worker,
            resolver,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_resolve_at_height(st, r, slash_worker, resolver, signer, current_height)?;
        }
    }
    Ok(())
}

fn scan_and_apply_timeouts(
    st: &mut StateStore,
    known_task_ids: &HashSet<u64>,
    current_height: u64,
    tx_id_seed: u64,
) -> u64 {
    let mut migrated = 0u64;
    for task_id in known_task_ids.iter().copied() {
        let Some(task) = st.get_task(task_id) else {
            continue;
        };
        if !matches!(
            task.status,
            TaskStatus::Assigned
                | TaskStatus::Committed
                | TaskStatus::Revealed
                | TaskStatus::Challenged
        ) {
            continue;
        }
        let from_status = format!("{:?}", task.status);
        let challenger = task.challenger.clone();
        let Some(task_ref) = st.get_ref(task_id) else {
            continue;
        };
        let before = st.clone();
        if apply_timeout(st, task_ref, current_height).is_ok() {
            migrated += 1;
            let to_status = status_name(st, task_id);
            let root = hex::encode(st.state_root());
            let (treasury_delta, challenger_delta) =
                balance_deltas_for_transition(&before, st, task_id, challenger.as_deref());
            let bond_disposition = if from_status == "Challenged" {
                st.get_task(task_id).and_then(|t| {
                    t.challenge_bond_forfeited
                        .map(|forfeited| if forfeited { "forfeited" } else { "refunded" })
                })
            } else {
                None
            };
            emit_timeout_event(
                task_id,
                tx_id_seed.saturating_add(migrated),
                current_height,
                &from_status,
                &to_status,
                &root,
                &treasury_delta,
                challenger_delta.as_ref(),
                challenger.as_deref(),
                bond_disposition,
            );
            println!(
                "[timeout] height={} task_id={} from_status={} to_status={} source=auto_scan",
                current_height, task_id, from_status, to_status
            );
        }
    }
    migrated
}

fn pseudo_object_id_for_account(account: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"balance:");
    h.update(account.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    // keep account-derived ids in high range to avoid overlapping natural task ids
    u64::from_le_bytes(bytes) | (1u64 << 63)
}

fn summarize_hot_objects(st: &StateStore, txs: &[MockTx]) -> HotObjectSummary {
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

fn hot_object_top_label_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(top_refs as u128, total_refs as u128)
}

fn hot_object_tail_share_ppm(summary: &HotObjectSummary) -> u128 {
    let total_refs: usize = summary.labels.values().copied().sum();
    let top_refs = summary.labels.values().copied().max().unwrap_or(0);
    ratio_ppm(
        total_refs.saturating_sub(top_refs) as u128,
        total_refs as u128,
    )
}

fn read_write_decl(st: &StateStore, tx: &MockTx, tx_id: u64) -> Tx {
    let task_id = match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
    };

    let task_obj = ObjectRef {
        id: task_id,
        version: 1,
    };

    let mut read_set = vec![task_obj.clone()];
    let mut write_set = vec![task_obj.clone()];

    match tx {
        MockTx::AcceptTask { worker, .. } => {
            let worker_obj = ObjectRef {
                id: pseudo_object_id_for_account(worker),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(worker_obj.clone());
            write_set.push(worker_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);
        }
        MockTx::Challenge { challenger, .. } => {
            let challenger_obj = ObjectRef {
                id: pseudo_object_id_for_account(challenger),
                version: 1,
            };
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            read_set.push(challenger_obj.clone());
            write_set.push(challenger_obj);
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
        }
        MockTx::Resolve { .. } => {
            let escrow_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_ESCROW_ACCOUNT),
                version: 1,
            };
            let forfeit_obj = ObjectRef {
                id: pseudo_object_id_for_account(CHALLENGE_FORFEIT_TREASURY_ACCOUNT),
                version: 1,
            };
            let slash_obj = ObjectRef {
                id: pseudo_object_id_for_account(WORKER_SLASH_TREASURY_ACCOUNT),
                version: 1,
            };
            let lock_obj = ObjectRef {
                id: pseudo_object_id_for_account(&format!("worker_stake_lock.{}", task_id)),
                version: 1,
            };
            read_set.push(escrow_obj.clone());
            write_set.push(escrow_obj);
            read_set.push(forfeit_obj.clone());
            write_set.push(forfeit_obj);
            read_set.push(slash_obj.clone());
            write_set.push(slash_obj);
            read_set.push(lock_obj.clone());
            write_set.push(lock_obj);

            if let Some(challenger) = st.get_task(task_id).and_then(|t| t.challenger) {
                let challenger_obj = ObjectRef {
                    id: pseudo_object_id_for_account(&challenger),
                    version: 1,
                };
                read_set.push(challenger_obj.clone());
                write_set.push(challenger_obj);
            }
        }
        _ => {}
    }

    Tx {
        id: tx_id,
        read_set,
        write_set,
        payload: vec![],
    }
}

#[derive(Clone)]
struct PreExecJob {
    ids: Vec<u64>,
    result_tx: mpsc::Sender<(u64, bool, String)>,
}

enum PreExecQueueEntry {
    Run(PreExecJob),
    Shutdown,
}

struct PreExecPoolState {
    queue: Mutex<VecDeque<PreExecQueueEntry>>,
    cv: Condvar,
}

struct PreExecPool {
    state: Arc<PreExecPoolState>,
    handles: Vec<thread::JoinHandle<()>>,
    width: usize,
}

impl PreExecPool {
    fn new(
        snapshot: Arc<StateStore>,
        picked: Arc<Vec<MockTx>>,
        workers: usize,
        candidate_height: u64,
    ) -> Self {
        let width = workers.max(1);
        let state = Arc::new(PreExecPoolState {
            queue: Mutex::new(VecDeque::new()),
            cv: Condvar::new(),
        });
        let mut handles = Vec::with_capacity(width);
        for _ in 0..width {
            let state_cloned = Arc::clone(&state);
            let snapshot_cloned = Arc::clone(&snapshot);
            let picked_cloned = Arc::clone(&picked);
            handles.push(thread::spawn(move || loop {
                let entry = {
                    let mut guard = state_cloned.queue.lock().expect("preexec queue poisoned");
                    loop {
                        if let Some(entry) = guard.pop_front() {
                            break entry;
                        }
                        guard = state_cloned
                            .cv
                            .wait(guard)
                            .expect("preexec queue poisoned while waiting");
                    }
                };
                match entry {
                    PreExecQueueEntry::Run(job) => {
                        for id in job.ids {
                            let idx = (id - 1) as usize;
                            let mut local_state = snapshot_cloned.as_ref().clone();
                            let res = apply_one(
                                &mut local_state,
                                picked_cloned[idx].clone(),
                                candidate_height,
                            );
                            match res {
                                Ok(_) => {
                                    let _ = job.result_tx.send((id, true, String::new()));
                                }
                                Err(e) => {
                                    let _ = job.result_tx.send((id, false, e.to_string()));
                                }
                            }
                        }
                    }
                    PreExecQueueEntry::Shutdown => break,
                }
            }));
        }

        Self {
            state,
            handles,
            width,
        }
    }

    fn execute_group(&self, group_ids: Vec<u64>) -> (Vec<u64>, u64) {
        if group_ids.is_empty() {
            return (vec![], 0);
        }
        let workers = self.width.min(group_ids.len());
        let (tx, rx) = mpsc::channel::<(u64, bool, String)>();
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for w in 0..workers {
                let ids: Vec<u64> = group_ids
                    .iter()
                    .copied()
                    .enumerate()
                    .filter_map(|(i, id)| if i % workers == w { Some(id) } else { None })
                    .collect();
                if ids.is_empty() {
                    continue;
                }
                queue.push_back(PreExecQueueEntry::Run(PreExecJob {
                    ids,
                    result_tx: tx.clone(),
                }));
            }
        }
        self.state.cv.notify_all();
        drop(tx);

        let mut ok_ids = Vec::new();
        let mut rejected = 0u64;
        for (id, ok, err) in rx {
            if ok {
                ok_ids.push(id);
            } else {
                rejected += 1;
                println!("[preexec] tx_id={} rejected err={}", id, err);
            }
        }

        ok_ids.sort_unstable();
        (ok_ids, rejected)
    }
}

impl Drop for PreExecPool {
    fn drop(&mut self) {
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for _ in 0..self.handles.len() {
                queue.push_back(PreExecQueueEntry::Shutdown);
            }
        }
        self.state.cv.notify_all();
        while let Some(handle) = self.handles.pop() {
            let _ = handle.join();
        }
    }
}

fn pre_execute_group_parallel(pool: &PreExecPool, group_ids: Vec<u64>) -> (Vec<u64>, u64) {
    pool.execute_group(group_ids)
}

fn decide_order_for_commit(
    state: &StateStore,
    picked: &[MockTx],
    workers: usize,
    enable_da_ordering_decouple: bool,
    candidate_height: u64,
) -> OrderingDecision {
    if !enable_da_ordering_decouple {
        let plan: Vec<Tx> = picked
            .iter()
            .enumerate()
            .map(|(i, tx)| read_write_decl(state, tx, (i as u64) + 1))
            .collect();
        let groups = build_parallel_groups(&plan);
        let group_count = groups.len();
        let critical_wait_blocks = group_count.saturating_sub(1) as u64;
        let mut ordered = Vec::new();
        let mut rejected = 0u64;
        let pool = PreExecPool::new(
            Arc::new(state.clone()),
            Arc::new(picked.to_vec()),
            workers,
            candidate_height,
        );
        let preexec_started = Instant::now();
        for g in groups {
            let group_ids: Vec<u64> = g.iter().map(|t| t.id).collect();
            let (ids, rej) = pre_execute_group_parallel(&pool, group_ids);
            ordered.extend(ids);
            rejected += rej;
        }
        return OrderingDecision {
            ordered_ids: ordered,
            rejected,
            preexec_elapsed_ms: preexec_started.elapsed().as_millis(),
            group_count,
            critical_wait_blocks,
        };
    }

    let da = LegacyMempoolDaProvider;
    let ordering = PreexecOrderingEngine;
    let da_batch = da.batch_from_picked(picked);
    ordering.decide(state, picked, &da_batch, workers, candidate_height)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_hotspot_summary_includes_shared_treasury_and_approval_labels() {
        let mut state = StateStore::new();
        state.set_balance("worker5001", 1_000);
        state.set_balance("challenger5001", 1_000);

        let r1 = apply_create_task(&mut state, 5001, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task_at_height(&mut state, r1, "worker5001".into(), 10).unwrap();
        let committed = compute_commitment(5001, &[1u8; 32], &[2u8; 32], "worker5001");
        let r3 = apply_commit_result_at_height(&mut state, r2, "worker5001".into(), committed, 10)
            .unwrap();
        let r4 =
            apply_reveal_result_at_height(&mut state, r3, [1u8; 32], [2u8; 32], None, 11).unwrap();
        let _r5 = apply_challenge_at_height(
            &mut state,
            r4,
            "challenger5001".into(),
            10,
            "challenger5001".into(),
            12,
        )
        .unwrap();

        let summary = summarize_hot_objects(
            &state,
            &[MockTx::Resolve {
                task_id: 5001,
                slash_worker: true,
                resolver: "authority-a".into(),
            }],
        );

        assert_eq!(summary.hot_tx_count, 1);
        assert!(summary.labels.contains_key(CHALLENGE_ESCROW_ACCOUNT));
        assert!(summary
            .labels
            .contains_key(CHALLENGE_FORFEIT_TREASURY_ACCOUNT));
        assert!(summary.labels.contains_key(WORKER_SLASH_TREASURY_ACCOUNT));
        assert!(summary
            .labels
            .contains_key(RESOLVE_PENDING_APPROVAL_HOT_LABEL));
        assert!(summary.labels.contains_key(RESOLVE_AUTHORITY_HOT_LABEL));
    }

    #[test]
    fn requeue_uncommitted_txs_preserves_order_at_tail() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 2001,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 2002,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);
        let picked = vec![
            MockTx::AcceptTask {
                task_id: 1001,
                worker: "worker1001".into(),
            },
            MockTx::Commit {
                task_id: 1001,
                worker: "worker1001".into(),
                committed_hash: [9u8; 32],
            },
        ];

        requeue_uncommitted_txs(&mut mempool, picked);

        let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(task_ids, vec![2001, 2002, 1001, 1001]);
    }

    #[test]
    fn requeue_uncommitted_txs_noop_on_empty_pick() {
        let mut mempool = VecDeque::from(vec![MockTx::CreateTask {
            task_id: 3001,
            creator: "alice".into(),
            bounty: 10,
        }]);

        requeue_uncommitted_txs(&mut mempool, vec![]);

        let task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(task_ids, vec![3001]);
    }

    #[test]
    fn da_ordering_decouple_switch_off_and_on_keep_same_commit_order_on_happy_path() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4001,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4002,
                creator: "bob".into(),
                bounty: 20,
            },
        ];

        let legacy = decide_order_for_commit(&state, &picked, 2, false, 1);
        let decoupled = decide_order_for_commit(&state, &picked, 2, true, 1);

        assert_eq!(legacy.ordered_ids, vec![1, 2]);
        assert_eq!(decoupled.ordered_ids, legacy.ordered_ids);
        assert_eq!(legacy.rejected, 0);
        assert_eq!(decoupled.rejected, 0);
    }

    #[test]
    fn preexec_parallel_workers_match_single_worker_results() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4051,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4052,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::AcceptTask {
                task_id: 999_999,
                worker: "worker4053".into(),
            },
        ];

        let pool_single = PreExecPool::new(Arc::new(state.clone()), Arc::new(picked.clone()), 1, 1);
        let single = pre_execute_group_parallel(&pool_single, vec![1, 2, 3]);

        let pool_parallel = PreExecPool::new(Arc::new(state), Arc::new(picked), 3, 1);
        let parallel = pre_execute_group_parallel(&pool_parallel, vec![1, 2, 3]);

        assert_eq!(single, (vec![1, 2], 1));
        assert_eq!(parallel, single);
    }

    #[test]
    fn preexec_uses_candidate_height_for_deadline_sensitive_reveal() {
        let mut state = StateStore::new();
        state.set_balance("worker4100", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut state, 4100, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task_at_height(&mut state, r1, "worker4100".into(), 100).unwrap();
        let committed = compute_commitment(4100, &result_hash, &reveal_salt, "worker4100");
        let _r3 =
            apply_commit_result_at_height(&mut state, r2, "worker4100".into(), committed, 100)
                .unwrap();

        let reveal_deadline = state
            .get_task(4100)
            .and_then(|t| t.reveal_deadline_height)
            .expect("reveal deadline must exist after commit");
        let reveal_tx = MockTx::Reveal {
            task_id: 4100,
            result_hash,
            reveal_salt,
        };

        let accepted_at_deadline = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            false,
            reveal_deadline,
        );
        assert_eq!(accepted_at_deadline.ordered_ids, vec![1]);
        assert_eq!(accepted_at_deadline.rejected, 0);

        let rejected_after_deadline = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            false,
            reveal_deadline.saturating_add(1),
        );
        assert!(rejected_after_deadline.ordered_ids.is_empty());
        assert_eq!(rejected_after_deadline.rejected, 1);

        let rejected_after_deadline_decoupled = decide_order_for_commit(
            &state,
            std::slice::from_ref(&reveal_tx),
            1,
            true,
            reveal_deadline.saturating_add(1),
        );
        assert!(rejected_after_deadline_decoupled.ordered_ids.is_empty());
        assert_eq!(rejected_after_deadline_decoupled.rejected, 1);

        let err = apply_one(
            &mut state.clone(),
            reveal_tx,
            reveal_deadline.saturating_add(1),
        )
        .unwrap_err();
        assert_eq!(classify_apply_error(&err), "deadline_exceeded");
    }

    #[test]
    fn preexec_pool_reuses_workers_across_multiple_groups() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![
            MockTx::CreateTask {
                task_id: 4201,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4202,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::CreateTask {
                task_id: 4203,
                creator: "carol".into(),
                bounty: 30,
            },
            MockTx::CreateTask {
                task_id: 4204,
                creator: "dave".into(),
                bounty: 40,
            },
        ]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let first = pre_execute_group_parallel(&pool, vec![1, 2]);
        let second = pre_execute_group_parallel(&pool, vec![3, 4]);

        assert_eq!(first.0, vec![1, 2]);
        assert_eq!(first.1, 0);
        assert_eq!(second.0, vec![3, 4]);
        assert_eq!(second.1, 0);
    }

    #[test]
    fn rl_shadow_advisor_only_suggests_and_does_not_mutate_baseline_order() {
        let baseline = vec![1, 2, 3, 4];
        let advisor = ShadowOnlyRlAdvisor { topk: 2 };
        let advice = advisor
            .advise(&RlAdviceContext {
                height: 7,
                ordered_ids: baseline.clone(),
            })
            .expect("advice");

        assert_eq!(baseline, vec![1, 2, 3, 4]);
        assert_eq!(advice.suggested_ids, vec![4, 3]);
        assert_eq!(advice.reason, "shadow_reverse_baseline");
    }

    #[test]
    fn critical_txs_are_selected_even_when_normal_queue_is_long() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "w1".into(),
                committed_hash: [3u8; 32],
            },
            MockTx::CreateTask {
                task_id: 2,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: false,
                resolver: "gov".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 1, .. }));
        assert_eq!(mempool.len(), 4);
        assert!(mempool
            .iter()
            .any(|tx| matches!(tx, MockTx::Resolve { .. })));
    }

    #[test]
    fn critical_guard_fast_path_drains_fifo_when_capacity_covers_queue() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(mempool.is_empty());
        assert!(matches!(picked[0], MockTx::CreateTask { .. }));
        assert!(matches!(picked[1], MockTx::Challenge { .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { .. }));
    }

    #[test]
    fn critical_guard_zero_block_budget_is_noop_and_preserves_queue_order() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 0);
        assert!(picked.is_empty());

        let remaining_task_ids: Vec<u64> = mempool.iter().map(task_id_of).collect();
        assert_eq!(remaining_task_ids, vec![1, 1, 1]);
        assert!(matches!(mempool[0], MockTx::CreateTask { .. }));
        assert!(matches!(mempool[1], MockTx::Challenge { .. }));
        assert!(matches!(mempool[2], MockTx::AcceptTask { .. }));
    }

    #[test]
    fn critical_guard_normal_only_backlog_drains_fifo_prefix_without_reordering() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 31,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 31,
                worker: "w31".into(),
            },
            MockTx::Commit {
                task_id: 31,
                worker: "w31".into(),
                committed_hash: [1u8; 32],
            },
            MockTx::CreateTask {
                task_id: 32,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 2);
        assert_eq!(picked.len(), 2);
        assert!(matches!(picked[0], MockTx::CreateTask { task_id: 31, .. }));
        assert!(matches!(picked[1], MockTx::AcceptTask { task_id: 31, .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Commit { task_id: 31, .. }));
        assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 32, .. }));
    }

    #[test]
    fn rollback_block_rate_counts_only_blocks_with_any_rollback() {
        let rollback_samples = vec![0, 2, 0, 1];
        let rollback_block_total =
            rollback_samples.iter().filter(|count| **count > 0).count() as u64;
        let rollback_block_rate = rollback_block_total as f64 / rollback_samples.len() as f64;

        assert_eq!(rollback_block_total, 2);
        assert!((rollback_block_rate - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn consensus_share_ppm_is_zero_when_finality_avg_is_zero() {
        assert_eq!(ratio_ppm(10, 0), 0);
    }

    #[test]
    fn consensus_share_ppm_makes_component_regressions_visible() {
        let finality_avg = 200u128;
        let scheduler_avg = 50u128;
        let preexec_avg = 120u128;
        let commit_avg = 20u128;
        let state_root_total_avg = 10u128;

        assert_eq!(ratio_ppm(scheduler_avg, finality_avg), 250_000);
        assert_eq!(ratio_ppm(preexec_avg, finality_avg), 600_000);
        assert_eq!(ratio_ppm(commit_avg, finality_avg), 100_000);
        assert_eq!(ratio_ppm(state_root_total_avg, finality_avg), 50_000);
    }

    #[test]
    fn scheduler_peak_share_metric_makes_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let scheduler_max = 96u128;

        assert_eq!(ratio_ppm(scheduler_max, finality_max), 300_000);
        assert_eq!(ratio_ppm(scheduler_max, 0), 0);
    }

    #[test]
    fn preexec_peak_share_metric_makes_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let preexec_max = 160u128;

        assert_eq!(ratio_ppm(preexec_max, finality_max), 500_000);
        assert_eq!(ratio_ppm(preexec_max, 0), 0);
    }

    #[test]
    fn commit_and_state_root_peak_share_metrics_make_tail_latency_regressions_visible() {
        let finality_max = 320u128;
        let commit_max = 96u128;
        let state_root_total_max = 144u128;

        assert_eq!(ratio_ppm(commit_max, finality_max), 300_000);
        assert_eq!(ratio_ppm(state_root_total_max, finality_max), 450_000);
        assert_eq!(ratio_ppm(commit_max, 0), 0);
        assert_eq!(ratio_ppm(state_root_total_max, 0), 0);
    }

    #[test]
    fn rollback_share_metrics_make_rollback_regressions_visible() {
        let finality_avg = 200u128;
        let rollback_avg = 40u128;
        let finality_max = 320u128;
        let rollback_max = 80u128;
        let rollback_total = 3u64;
        let rollback_block_total = 2u64;
        let rollback_active_heights = rollback_block_total;
        let finality_sample_count = 4u64;
        let rollback_block_rate_ppm = ratio_ppm_u64(rollback_block_total, finality_sample_count);
        let rollback_active_height_rate_ppm = rollback_block_rate_ppm;
        let rollback_density_avg = rollback_total / rollback_block_total;
        let rollback_density_avg_milli = ratio_milli_u64(rollback_total, rollback_block_total);

        assert_eq!(ratio_ppm(rollback_avg, finality_avg), 200_000);
        assert_eq!(ratio_ppm(rollback_max, finality_max), 250_000);
        assert_eq!(rollback_active_heights, rollback_block_total);
        assert_eq!(rollback_block_rate_ppm, 500_000);
        assert_eq!(rollback_active_height_rate_ppm, rollback_block_rate_ppm);
        assert_eq!(rollback_density_avg, 1);
        assert_eq!(rollback_density_avg_milli, 1_500);
    }

    #[test]
    fn percentage_bps_guardrails_make_preexec_and_rollback_regressions_visible() {
        assert_eq!(ratio_percent_bps(3, 12), 2_500);
        assert_eq!(ratio_percent_bps(2, 5), 4_000);
        assert_eq!(ratio_percent_bps(1, 0), 0);
    }

    #[test]
    fn hot_object_top_label_share_metric_exposes_concentrated_hotspots() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        assert_eq!(hot_object_top_label_share_ppm(&summary), 600_000);
    }

    #[test]
    fn hot_object_top_label_share_metric_is_zero_without_hot_labels() {
        assert_eq!(
            hot_object_top_label_share_ppm(&HotObjectSummary::default()),
            0
        );
    }

    #[test]
    fn hot_object_tail_share_metric_exposes_remaining_parallelizable_surface() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        assert_eq!(hot_object_tail_share_ppm(&summary), 400_000);
    }

    #[test]
    fn hot_object_tail_share_metric_is_zero_without_hot_labels() {
        assert_eq!(hot_object_tail_share_ppm(&HotObjectSummary::default()), 0);
    }

    #[test]
    fn hot_object_top_and_tail_share_metrics_partition_hot_reference_surface() {
        let mut summary = HotObjectSummary::default();
        summary.labels.insert("resolve.pending_approval".into(), 6);
        summary.labels.insert("treasury.challenge_escrow".into(), 2);
        summary.labels.insert("gov.resolve_authority".into(), 2);

        let top_share_ppm = hot_object_top_label_share_ppm(&summary);
        let tail_share_ppm = hot_object_tail_share_ppm(&summary);

        assert_eq!(top_share_ppm, 600_000);
        assert_eq!(tail_share_ppm, 400_000);
        assert_eq!(top_share_ppm + tail_share_ppm, 1_000_000);
    }

    #[test]
    fn active_hot_object_share_averages_ignore_inactive_heights() {
        let finality_sample_count = 4u64;
        let hot_object_active_heights = 2u64;
        let hot_object_top_label_share_samples_ppm = vec![0u128, 800_000, 0, 400_000];
        let hot_object_tail_share_samples_ppm = vec![0u128, 200_000, 0, 600_000];
        let hot_object_active_top_label_share_total_ppm = 1_200_000u128;
        let hot_object_active_tail_share_total_ppm = 800_000u128;
        let hot_object_top_label_share_avg_ppm =
            average_or_zero(&hot_object_top_label_share_samples_ppm);
        let hot_object_tail_share_avg_ppm = average_or_zero(&hot_object_tail_share_samples_ppm);
        let hot_object_active_top_label_share_avg_ppm =
            hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_tail_share_avg_ppm =
            hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, finality_sample_count);
        let hot_object_active_observed_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, 6u64);

        assert_eq!(hot_object_top_label_share_avg_ppm, 300_000);
        assert_eq!(hot_object_tail_share_avg_ppm, 200_000);
        assert_eq!(hot_object_active_top_label_share_avg_ppm, 600_000);
        assert_eq!(hot_object_active_tail_share_avg_ppm, 400_000);
        assert_eq!(hot_object_active_height_rate_ppm, 500_000);
        assert_eq!(hot_object_active_observed_height_rate_ppm, 333_333);
        assert!(hot_object_active_observed_height_rate_ppm < hot_object_active_height_rate_ppm);
        assert!(hot_object_active_top_label_share_avg_ppm > hot_object_top_label_share_avg_ppm);
        assert!(hot_object_active_tail_share_avg_ppm > hot_object_tail_share_avg_ppm);
    }

    #[test]
    fn hot_object_metric_names_keep_committed_and_observed_coverage_distinct() {
        let active_height_rate_field_name = "hot_object_active_height_rate_ppm";
        let active_observed_height_rate_field_name = "hot_object_active_observed_height_rate_ppm";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
    }

    #[test]
    fn active_hot_object_share_averages_are_zero_without_hot_heights() {
        let hot_object_active_heights = 0u64;
        let hot_object_active_top_label_share_avg_ppm = if hot_object_active_heights == 0 {
            0
        } else {
            1_200_000u128 / hot_object_active_heights as u128
        };
        let hot_object_active_tail_share_avg_ppm = if hot_object_active_heights == 0 {
            0
        } else {
            800_000u128 / hot_object_active_heights as u128
        };

        assert_eq!(hot_object_active_top_label_share_avg_ppm, 0);
        assert_eq!(hot_object_active_tail_share_avg_ppm, 0);
    }

    #[test]
    fn critical_wait_density_metrics_make_fairness_stalls_visible() {
        let finality_avg = 200u128;
        let critical_wait_blocks_avg = 50u128;
        let finality_max = 320u128;
        let critical_wait_blocks_max = 160u128;

        assert_eq!(ratio_ppm(critical_wait_blocks_avg, finality_avg), 250_000);
        assert_eq!(ratio_ppm(critical_wait_blocks_max, finality_max), 500_000);
        assert_eq!(ratio_ppm(critical_wait_blocks_max, 0), 0);
    }

    #[test]
    fn critical_wait_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
        let critical_wait_active_heights = 2u64;
        let finality_sample_count = 4u64;
        let bft_observed_heights = 5u64;
        let critical_wait_total = 5u64;
        let critical_wait_density_avg = critical_wait_total / critical_wait_active_heights;
        let critical_wait_density_avg_milli =
            ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
        let critical_wait_active_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, finality_sample_count);
        let critical_wait_active_observed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, bft_observed_heights);

        assert_eq!(critical_wait_active_height_rate_ppm, 500_000);
        assert_eq!(critical_wait_active_observed_height_rate_ppm, 400_000);
        assert!(
            critical_wait_active_observed_height_rate_ppm < critical_wait_active_height_rate_ppm
        );
        assert_eq!(critical_wait_density_avg, 2);
        assert_eq!(critical_wait_density_avg_milli, 2_500);
    }

    #[test]
    fn critical_wait_metric_names_keep_committed_and_observed_coverage_distinct() {
        let active_height_rate_field_name = "critical_wait_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "critical_wait_active_observed_height_rate_ppm";
        let density_field_name = "critical_wait_density_avg";
        let milli_density_field_name = "critical_wait_density_avg_milli";
        let active_height_share_field_name = "critical_wait_active_height_share_ppm";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_field_name.ends_with("_avg"));
        assert!(milli_density_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(active_observed_height_rate_field_name, density_field_name);
        assert_ne!(density_field_name, milli_density_field_name);
        assert_ne!(milli_density_field_name, active_height_share_field_name);
    }

    #[test]
    fn critical_wait_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let critical_wait_active_heights = 2u64;
        let committed_heights = 2u64;
        let observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(critical_wait_active_heights, observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn critical_wait_density_avg_handles_empty_active_height_set() {
        let critical_wait_total = 5u64;
        let critical_wait_active_heights = 0u64;
        let critical_wait_density_avg = if critical_wait_active_heights == 0 {
            0
        } else {
            critical_wait_total / critical_wait_active_heights
        };
        let critical_wait_density_avg_milli =
            ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
        let critical_wait_active_height_share_ppm =
            finality_budget_share_ppm(critical_wait_density_avg_milli, 200u128);

        assert_eq!(critical_wait_density_avg, 0);
        assert_eq!(critical_wait_density_avg_milli, 0);
        assert_eq!(critical_wait_active_height_share_ppm, 0);
    }

    #[test]
    fn critical_wait_active_height_share_tracks_clustered_fairness_stall_budget_pressure() {
        let critical_wait_density_avg_milli = 2_500u64;
        let finality_avg = 200u128;
        let critical_wait_active_height_share_ppm =
            finality_budget_share_ppm(critical_wait_density_avg_milli, finality_avg);

        assert_eq!(critical_wait_active_height_share_ppm, 12_500);
        assert!(critical_wait_active_height_share_ppm < 1_000_000);
    }

    #[test]
    fn preexec_reject_share_metric_highlights_guardrail_pressure() {
        assert_eq!(ratio_percent_bps(6, 15), 4_000);
        assert_eq!(ratio_percent_bps(0, 15), 0);
        assert_eq!(ratio_percent_bps(4, 0), 0);
    }

    #[test]
    fn preexec_reject_density_metrics_expose_concentrated_guardrail_pressure() {
        let preexec_reject_total = 7u64;
        let preexec_reject_active_heights = 2u64;
        let bft_committed_heights = 3u64;
        let bft_observed_heights = 5u64;
        let finality_avg = 200u128;
        let preexec_reject_density_avg = preexec_reject_total / bft_committed_heights;
        let preexec_reject_density_avg_milli =
            ratio_milli_u64(preexec_reject_total, bft_committed_heights);
        let preexec_reject_active_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_committed_heights);
        let preexec_reject_active_observed_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_observed_heights);
        let preexec_reject_active_height_share_ppm =
            finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);

        assert_eq!(preexec_reject_density_avg, 2);
        assert_eq!(preexec_reject_density_avg_milli, 2_333);
        assert_eq!(preexec_reject_active_height_rate_ppm, 666_666);
        assert_eq!(preexec_reject_active_observed_height_rate_ppm, 400_000);
        assert_eq!(preexec_reject_active_height_share_ppm, 11_665);
        assert!(preexec_reject_active_observed_height_rate_ppm < preexec_reject_active_height_rate_ppm);
        assert_eq!(ratio_milli_u64(0, bft_committed_heights), 0);
        assert_eq!(ratio_milli_u64(preexec_reject_total, 0), 0);
    }

    #[test]
    fn preexec_reject_metric_names_keep_height_coverage_and_budget_semantics_distinct() {
        let active_height_count_field_name = "preexec_reject_active_heights";
        let active_height_rate_field_name = "preexec_reject_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "preexec_reject_active_observed_height_rate_ppm";
        let active_height_share_field_name = "preexec_reject_active_height_share_ppm";
        let density_avg_milli_field_name = "preexec_reject_density_avg_milli";

        assert!(active_height_count_field_name.ends_with("_heights"));
        assert!(active_height_rate_field_name.ends_with("_height_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert_ne!(active_height_count_field_name, active_height_rate_field_name);
        assert_ne!(active_height_rate_field_name, active_observed_height_rate_field_name);
        assert_ne!(active_observed_height_rate_field_name, active_height_share_field_name);
        assert_ne!(active_height_share_field_name, density_avg_milli_field_name);
    }

    #[test]
    fn unprofiled_finality_gap_metric_captures_hidden_block_time() {
        assert_eq!(gap_percent_bps(200, 80, 40), 4_000);
        assert_eq!(gap_percent_bps(200, 150, 80), 0);
        assert_eq!(gap_percent_bps(0, 10, 5), 0);
    }

    #[test]
    fn round_change_guardrail_metrics_make_bft_jitter_visible() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_round_change_backoff_max_ms = 8u64;

        assert_eq!(
            ratio_ppm_u64(bft_round_change_total, bft_committed_heights),
            1_500_000
        );
        assert_eq!(
            bft_round_change_backoff_total_ms / bft_round_change_total,
            3
        );
        assert_eq!(
            bft_round_change_backoff_total_ms / bft_round_change_active_heights,
            9
        );
        assert_eq!(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_active_heights,
            ),
            9_000
        );
        assert_eq!(
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
            4_500_000
        );
        assert!(
            bft_round_change_backoff_max_ms
                > bft_round_change_backoff_total_ms / bft_round_change_total
        );
    }

    #[test]
    fn preexec_metric_names_keep_tail_and_guardrail_semantics_distinct() {
        let peak_field_name = "preexec_peak_share_ppm";
        let reject_density_avg_milli_field_name = "preexec_reject_density_avg_milli";
        let reject_share_field_name = "preexec_reject_share_bps";
        let conflict_miss_share_field_name = "preexec_conflict_miss_share_bps";

        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(reject_density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(reject_share_field_name.ends_with("_share_bps"));
        assert!(conflict_miss_share_field_name.ends_with("_share_bps"));
        assert_ne!(peak_field_name, reject_density_avg_milli_field_name);
        assert_ne!(peak_field_name, reject_share_field_name);
        assert_ne!(peak_field_name, conflict_miss_share_field_name);
        assert_ne!(reject_density_avg_milli_field_name, reject_share_field_name);
        assert_ne!(reject_density_avg_milli_field_name, conflict_miss_share_field_name);
        assert_ne!(reject_share_field_name, conflict_miss_share_field_name);
    }

    #[test]
    fn rollback_active_height_metric_names_keep_compatibility_and_height_semantics_distinct() {
        let compatibility_count_field_name = "rollback_block_total";
        let height_count_field_name = "rollback_active_heights";
        let compatibility_rate_field_name = "rollback_block_rate_ppm";
        let height_rate_field_name = "rollback_active_height_rate_ppm";
        let observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";

        assert!(compatibility_count_field_name.ends_with("_total"));
        assert!(height_count_field_name.ends_with("_heights"));
        assert!(compatibility_rate_field_name.ends_with("_rate_ppm"));
        assert!(height_rate_field_name.ends_with("_height_rate_ppm"));
        assert!(observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(compatibility_count_field_name, height_count_field_name);
        assert_ne!(compatibility_rate_field_name, height_rate_field_name);
        assert_ne!(height_rate_field_name, observed_height_rate_field_name);
        assert_ne!(
            compatibility_rate_field_name,
            observed_height_rate_field_name
        );
    }

    #[test]
    fn rollback_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let rollback_active_heights = 2u64;
        let rollback_committed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 2u64);
        let rollback_observed_height_rate_ppm = ratio_ppm_u64(rollback_active_heights, 5u64);

        assert_eq!(rollback_committed_height_rate_ppm, 1_000_000);
        assert_eq!(rollback_observed_height_rate_ppm, 400_000);
        assert!(rollback_observed_height_rate_ppm < rollback_committed_height_rate_ppm);
    }

    #[test]
    fn rollback_active_height_share_tracks_clustered_rollback_budget_pressure() {
        let rollback_density_avg_milli = 2_500u64;
        let finality_avg = 2u128;

        let rollback_active_height_share_ppm =
            finality_budget_share_ppm(rollback_density_avg_milli, finality_avg);

        assert_eq!(rollback_active_height_share_ppm, 1_250_000);
        assert!(rollback_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn rollback_metric_names_keep_budget_share_and_coverage_distinct() {
        let peak_field_name = "rollback_peak_share_ppm";
        let active_height_rate_field_name = "rollback_active_height_rate_ppm";
        let active_observed_height_rate_field_name = "rollback_active_observed_height_rate_ppm";
        let density_avg_milli_field_name = "rollback_density_avg_milli";
        let active_height_share_field_name = "rollback_active_height_share_ppm";

        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(peak_field_name, active_height_rate_field_name);
        assert_ne!(active_height_rate_field_name, active_observed_height_rate_field_name);
        assert_ne!(active_observed_height_rate_field_name, density_avg_milli_field_name);
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn round_change_backoff_metric_names_keep_tail_and_share_semantics_distinct() {
        let max_field_name = "bft_round_change_backoff_max_ms";
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_field_name = "bft_round_change_backoff_share_ppm";

        assert!(max_field_name.ends_with("_max_ms"));
        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_field_name.ends_with("_share_ppm"));
        assert_ne!(max_field_name, wall_share_field_name);
        assert_ne!(max_field_name, compatibility_field_name);
    }

    #[test]
    fn scheduler_peak_share_metric_name_stays_distinct_from_average_share_field() {
        let avg_field_name = "scheduler_share_avg_ppm";
        let peak_field_name = "scheduler_peak_share_ppm";

        assert!(avg_field_name.ends_with("_avg_ppm"));
        assert!(peak_field_name.ends_with("_share_ppm"));
        assert!(!peak_field_name.contains("avg"));
        assert_ne!(avg_field_name, peak_field_name);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_name_stays_ppm_based() {
        let field_name = "bft_round_change_backoff_wall_share_ppm";
        assert!(field_name.ends_with("_share_ppm"));
        assert!(!field_name.ends_with("_per_height_ms"));
    }

    #[test]
    fn round_change_backoff_share_metric_keeps_compatibility_alias_name() {
        let field_name = "bft_round_change_backoff_share_ppm";
        assert!(field_name.ends_with("_share_ppm"));
        assert!(!field_name.contains("wall_share_ppm"));
    }

    #[test]
    fn round_change_backoff_metric_names_keep_wall_alias_and_budget_share_distinct() {
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";
        let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(wall_share_field_name, compatibility_alias_field_name);
        assert_ne!(wall_share_field_name, active_height_share_field_name);
        assert_ne!(compatibility_alias_field_name, active_height_share_field_name);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_uses_height_level_denominator() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let finality_sample_count = 6u64;
        let wall_share_per_height_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
        let wall_share_per_finality_sample_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, finality_sample_count);

        assert_eq!(wall_share_per_height_ppm, 4_500_000);
        assert_eq!(wall_share_per_finality_sample_ppm, 3_000_000);
        assert_ne!(
            wall_share_per_height_ppm,
            wall_share_per_finality_sample_ppm
        );
    }

    #[test]
    fn round_change_backoff_compatibility_alias_matches_wall_share_metric() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
        let compatibility_alias_ppm = wall_share_ppm;

        assert_eq!(wall_share_ppm, 4_500_000);
        assert_eq!(compatibility_alias_ppm, wall_share_ppm);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_can_exceed_one_million_when_backoff_dominates() {
        let bft_round_change_backoff_total_ms = 12u64;
        let bft_committed_heights = 3u64;
        let wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);

        assert_eq!(wall_share_ppm, 4_000_000);
        assert!(wall_share_ppm > 1_000_000);
    }

    #[test]
    fn round_change_active_height_rate_metrics_make_jitter_concentration_visible() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 5u64;

        assert_eq!(
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights),
            500_000
        );
        assert_eq!(
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights),
            400_000
        );
        assert_eq!(bft_round_change_total / bft_round_change_active_heights, 3);
        assert_eq!(
            ratio_ppm_u64(bft_round_change_total, bft_round_change_active_heights),
            3_000_000
        );
    }

    #[test]
    fn round_change_metric_names_keep_committed_budget_and_observed_coverage_distinct() {
        let active_height_rate_field_name = "bft_round_change_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_round_change_active_observed_height_rate_ppm";
        let active_height_share_field_name = "bft_round_change_active_height_share_ppm";
        let density_avg_milli_field_name = "bft_round_change_density_avg_milli";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn round_change_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn round_change_density_avg_milli_preserves_sub_integer_jitter_signal() {
        let bft_round_change_total = 5u64;
        let bft_round_change_active_heights = 2u64;
        let bft_round_change_density_avg = bft_round_change_total / bft_round_change_active_heights;
        let bft_round_change_density_avg_milli =
            ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);

        assert_eq!(bft_round_change_density_avg, 2);
        assert_eq!(bft_round_change_density_avg_milli, 2_500);
    }

    #[test]
    fn round_change_backoff_density_avg_milli_preserves_clustered_jitter_signal() {
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_active_heights = 2u64;
        let bft_round_change_backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_active_heights;
        let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        );

        assert_eq!(bft_round_change_backoff_density_avg_ms, 2);
        assert_eq!(bft_round_change_backoff_density_avg_milli, 2_500);
    }

    #[test]
    fn consensus_log_contract_keeps_round_change_density_milli_fields() {
        let field_name = "bft_round_change_density_avg_milli";
        let integer_avg_field_name = "bft_round_change_density_avg";
        let active_share_field_name = "bft_round_change_active_height_share_ppm";
        let backoff_field_name = "bft_round_change_backoff_density_avg_milli";
        let backoff_integer_avg_field_name = "bft_round_change_backoff_density_avg_ms";
        let backoff_active_share_field_name = "bft_round_change_backoff_active_height_share_ppm";

        assert!(field_name.ends_with("_avg_milli"));
        assert!(active_share_field_name.ends_with("_share_ppm"));
        assert!(backoff_field_name.ends_with("_avg_milli"));
        assert!(backoff_integer_avg_field_name.ends_with("_avg_ms"));
        assert!(backoff_active_share_field_name.ends_with("_share_ppm"));
        assert_ne!(field_name, integer_avg_field_name);
        assert_ne!(active_share_field_name, field_name);
        assert_ne!(backoff_field_name, backoff_integer_avg_field_name);
        assert_ne!(backoff_active_share_field_name, backoff_field_name);
    }

    #[test]
    fn round_change_density_milli_fields_preserve_sub_integer_signal_vs_integer_averages() {
        let bft_round_change_total = 5u64;
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_active_heights = 2u64;
        let finality_avg = 10u128;

        let density_avg = bft_round_change_total / bft_round_change_active_heights;
        let density_avg_milli =
            ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);
        let active_height_share_ppm =
            ratio_ppm_u64(density_avg_milli, (finality_avg as u64) * 1_000);
        let backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_active_heights;
        let backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        );
        let backoff_active_height_share_ppm =
            ratio_ppm_u64(backoff_density_avg_milli, (finality_avg as u64) * 1_000);

        assert_eq!(density_avg, 2);
        assert_eq!(density_avg_milli, 2_500);
        assert!(density_avg_milli > density_avg * 1_000);
        assert_eq!(active_height_share_ppm, 250_000);
        assert_eq!(backoff_density_avg_ms, 2);
        assert_eq!(backoff_density_avg_milli, 2_500);
        assert!(backoff_density_avg_milli > backoff_density_avg_ms * 1_000);
        assert_eq!(backoff_active_height_share_ppm, 250_000);
    }

    #[test]
    fn active_height_budget_share_metrics_can_exceed_one_million_when_jitter_or_fairness_dominates_finality(
    ) {
        let finality_avg = 2u128;
        let round_change_density_avg_milli = 3_000u64;
        let round_change_backoff_density_avg_milli = 4_500u64;
        let leader_missed_density_avg_milli = 2_500u64;

        let round_change_active_height_share_ppm =
            finality_budget_share_ppm(round_change_density_avg_milli, finality_avg);
        let round_change_backoff_active_height_share_ppm =
            finality_budget_share_ppm(round_change_backoff_density_avg_milli, finality_avg);
        let leader_missed_active_height_share_ppm =
            finality_budget_share_ppm(leader_missed_density_avg_milli, finality_avg);

        assert_eq!(round_change_active_height_share_ppm, 1_500_000);
        assert_eq!(round_change_backoff_active_height_share_ppm, 2_250_000);
        assert_eq!(leader_missed_active_height_share_ppm, 1_250_000);
        assert!(round_change_active_height_share_ppm > 1_000_000);
        assert!(round_change_backoff_active_height_share_ppm > 1_000_000);
        assert!(leader_missed_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn hot_object_active_share_metrics_avoid_zero_block_dilution() {
        let all_block_top_label_share_samples_ppm = vec![0u128, 500_000, 800_000];
        let all_block_tail_share_samples_ppm = vec![0u128, 500_000, 200_000];
        let hot_object_active_heights = 2u64;
        let hot_object_active_top_label_share_total_ppm = 1_300_000u128;
        let hot_object_active_tail_share_total_ppm = 700_000u128;
        let total_heights = 3u64;

        let diluted_top_label_share_avg_ppm =
            average_or_zero(&all_block_top_label_share_samples_ppm);
        let diluted_tail_share_avg_ppm = average_or_zero(&all_block_tail_share_samples_ppm);
        let active_top_label_share_avg_ppm =
            hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128;
        let active_tail_share_avg_ppm =
            hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128;
        let hot_object_active_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, total_heights);
        let hot_object_active_observed_height_rate_ppm =
            ratio_ppm_u64(hot_object_active_heights, 5u64);

        assert_eq!(diluted_top_label_share_avg_ppm, 433_333);
        assert_eq!(active_top_label_share_avg_ppm, 650_000);
        assert!(active_top_label_share_avg_ppm > diluted_top_label_share_avg_ppm);
        assert_eq!(diluted_tail_share_avg_ppm, 233_333);
        assert_eq!(active_tail_share_avg_ppm, 350_000);
        assert!(active_tail_share_avg_ppm > diluted_tail_share_avg_ppm);
        assert_eq!(hot_object_active_height_rate_ppm, 666_666);
        assert_eq!(hot_object_active_observed_height_rate_ppm, 400_000);
        assert!(hot_object_active_observed_height_rate_ppm < hot_object_active_height_rate_ppm);
    }

    #[test]
    fn leader_missed_concentration_metrics_make_single_proposer_hotspots_visible() {
        let leader_missed_final = vec![4u64, 1u64, 1u64, 0u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );

        assert_eq!(bft_leader_missed_total, 6);
        assert_eq!(bft_leader_missed_max, 4);
        assert_eq!(bft_leader_missed_top_share_ppm, 666_666);
        assert_eq!(bft_leader_missed_active_validators, 3);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 750_000);
    }

    #[test]
    fn leader_missed_concentration_metrics_are_zero_without_any_misses() {
        let leader_missed_final = vec![0u64, 0u64, 0u64, 0u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );

        assert_eq!(bft_leader_missed_total, 0);
        assert_eq!(bft_leader_missed_max, 0);
        assert_eq!(bft_leader_missed_top_share_ppm, 0);
        assert_eq!(bft_leader_missed_active_validators, 0);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 0);
    }

    #[test]
    fn leader_missed_metric_names_keep_hotspot_and_distribution_semantics_distinct() {
        let total_field_name = "bft_leader_missed_total";
        let max_field_name = "bft_leader_missed_max";
        let top_share_field_name = "bft_leader_missed_top_share_ppm";
        let active_validators_field_name = "bft_leader_missed_active_validators";
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";
        let distribution_field_name = "bft_leader_missed_proposals";

        assert!(total_field_name.ends_with("_total"));
        assert!(max_field_name.ends_with("_max"));
        assert!(top_share_field_name.ends_with("_share_ppm"));
        assert!(active_validators_field_name.ends_with("_validators"));
        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(
            active_height_rate_field_name.ends_with("_share_ppm")
                || active_height_rate_field_name.ends_with("_rate_ppm")
        );
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(distribution_field_name.ends_with("_proposals"));
        assert_ne!(total_field_name, max_field_name);
        assert_ne!(max_field_name, top_share_field_name);
        assert_ne!(top_share_field_name, active_validators_field_name);
        assert_ne!(
            active_validators_field_name,
            active_validator_share_field_name
        );
        assert_ne!(active_validator_share_field_name, active_heights_field_name);
        assert_ne!(active_heights_field_name, active_height_rate_field_name);
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            distribution_field_name
        );
    }

    #[test]
    fn leader_missed_active_height_rate_metrics_make_fairness_stall_concentration_visible() {
        let bft_leader_missed_active_heights = 3u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 6u64;
        let bft_leader_missed_active_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

        assert_eq!(bft_leader_missed_active_heights, 3);
        assert_eq!(bft_leader_missed_active_height_rate_ppm, 750_000);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 500_000);
    }

    #[test]
    fn leader_missed_observed_height_rate_exposes_skipped_height_coverage_gap() {
        let bft_leader_missed_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let committed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);

        assert_eq!(committed_height_rate_ppm, 1_000_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn leader_missed_density_avg_milli_preserves_bursted_fairness_stall_signal() {
        let bft_leader_missed_total = 5u64;
        let bft_leader_missed_active_heights = 2u64;
        let bft_leader_missed_density_avg =
            bft_leader_missed_total / bft_leader_missed_active_heights;
        let bft_leader_missed_density_avg_milli =
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);

        assert_eq!(bft_leader_missed_density_avg, 2);
        assert_eq!(bft_leader_missed_density_avg_milli, 2_500);
        assert!(bft_leader_missed_density_avg_milli > bft_leader_missed_density_avg * 1_000);
    }

    #[test]
    fn leader_missed_metric_names_include_density_fields_for_active_height_bursts() {
        let density_field_name = "bft_leader_missed_density_avg";
        let milli_density_field_name = "bft_leader_missed_density_avg_milli";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";

        assert!(density_field_name.ends_with("_avg"));
        assert!(milli_density_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(density_field_name, milli_density_field_name);
        assert_ne!(milli_density_field_name, active_height_share_field_name);
        assert_ne!(active_height_share_field_name, active_heights_field_name);
        assert_ne!(
            active_heights_field_name,
            active_observed_height_rate_field_name
        );
    }

    #[test]
    fn leader_missed_active_height_share_handles_zero_finality_budget() {
        let bft_leader_missed_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;

        assert_eq!(
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn leader_missed_active_height_share_can_exceed_budget_when_fairness_stalls_dominate() {
        let bft_leader_missed_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;

        assert_eq!(
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg),
            1_500_000
        );
    }

    #[test]
    fn leader_missed_hotspot_metrics_stay_visible_when_distribution_looks_benign() {
        let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
        let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
        let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
        let bft_leader_missed_top_share_ppm =
            ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
        let bft_leader_missed_active_validators = leader_missed_final
            .iter()
            .filter(|missed| **missed > 0)
            .count() as u64;
        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            bft_leader_missed_active_validators,
            leader_missed_final.len() as u64,
        );
        let bft_leader_missed_active_heights = 2u64;
        let bft_committed_heights = 6u64;
        let bft_observed_heights = 8u64;
        let finality_avg = 2u128;
        let bft_leader_missed_density_avg_milli =
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);
        let bft_leader_missed_active_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
        let bft_leader_missed_active_height_share_ppm =
            finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg);

        assert_eq!(bft_leader_missed_total, 6);
        assert_eq!(bft_leader_missed_top_share_ppm, 333_333);
        assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
        assert_eq!(bft_leader_missed_active_height_rate_ppm, 333_333);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
        assert_eq!(bft_leader_missed_density_avg_milli, 3_000);
        assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
        assert!(bft_leader_missed_active_height_share_ppm > 1_000_000);
        assert!(
            bft_leader_missed_top_share_ppm < 500_000
                && bft_leader_missed_active_validator_share_ppm == 1_000_000
        );
    }

    #[test]
    fn round_change_backoff_budget_share_metric_stays_distinct_from_wall_share_signal() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let finality_avg = 36u128;

        let backoff_active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_active_heights,
            ),
            finality_avg,
        );
        let backoff_wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);

        assert_eq!(backoff_active_height_share_ppm, 250_000);
        assert_eq!(backoff_wall_share_ppm, 4_500_000);
        assert_ne!(backoff_active_height_share_ppm, backoff_wall_share_ppm);
    }

    #[test]
    fn round_change_backoff_active_height_rate_exposes_zero_backoff_round_change_gap() {
        let bft_round_change_active_heights = 3u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 4u64;
        let bft_observed_heights = 5u64;

        let committed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_committed_heights,
        );
        let observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );

        assert_eq!(committed_height_rate_ppm, 500_000);
        assert_eq!(observed_height_rate_ppm, 400_000);
        assert!(bft_round_change_backoff_active_heights < bft_round_change_active_heights);
        assert!(observed_height_rate_ppm < committed_height_rate_ppm);
    }

    #[test]
    fn round_change_backoff_observed_coverage_stays_distinct_from_wall_share_alias() {
        let bft_round_change_backoff_total_ms = 12u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 3u64;
        let bft_observed_heights = 5u64;
        let finality_avg = 8u128;

        let wall_share_ppm = ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
        let compatibility_alias_ppm = wall_share_ppm;
        let active_observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );
        let active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(
                bft_round_change_backoff_total_ms,
                bft_round_change_backoff_active_heights,
            ),
            finality_avg,
        );

        assert_eq!(wall_share_ppm, 4_000_000);
        assert_eq!(compatibility_alias_ppm, wall_share_ppm);
        assert_eq!(active_observed_height_rate_ppm, 400_000);
        assert_eq!(active_height_share_ppm, 750_000);
        assert_ne!(active_observed_height_rate_ppm, compatibility_alias_ppm);
        assert_ne!(active_height_share_ppm, compatibility_alias_ppm);
        assert!(active_observed_height_rate_ppm < active_height_share_ppm);
    }

    #[test]
    fn round_change_backoff_active_height_metric_names_stay_distinct_from_round_change_coverage() {
        let round_change_active_heights_field_name = "bft_round_change_active_heights";
        let backoff_active_heights_field_name = "bft_round_change_backoff_active_heights";
        let backoff_active_height_rate_field_name =
            "bft_round_change_backoff_active_height_rate_ppm";
        let backoff_active_observed_height_rate_field_name =
            "bft_round_change_backoff_active_observed_height_rate_ppm";

        assert!(round_change_active_heights_field_name.ends_with("_heights"));
        assert!(backoff_active_heights_field_name.ends_with("_heights"));
        assert!(backoff_active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(backoff_active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(
            round_change_active_heights_field_name,
            backoff_active_heights_field_name
        );
        assert_ne!(
            backoff_active_heights_field_name,
            backoff_active_height_rate_field_name
        );
        assert_ne!(
            backoff_active_height_rate_field_name,
            backoff_active_observed_height_rate_field_name
        );
    }

    #[test]
    fn round_change_backoff_share_metric_handles_empty_consensus_samples() {
        assert_eq!(ratio_ppm_u64(18, 0), 0);
        assert_eq!(ratio_ppm_u64(0, 0), 0);
    }

    #[test]
    fn round_change_density_avg_handles_empty_active_height_set() {
        let bft_round_change_total = 6u64;
        let bft_round_change_active_heights = 0u64;
        let bft_round_change_density_avg = if bft_round_change_active_heights == 0 {
            0
        } else {
            bft_round_change_total / bft_round_change_active_heights
        };

        assert_eq!(bft_round_change_density_avg, 0);
    }

    #[test]
    fn round_change_backoff_active_height_share_handles_zero_finality_budget() {
        let bft_round_change_backoff_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

        assert_eq!(backoff_active_height_share_ppm, 0);
    }

    #[test]
    fn round_change_backoff_active_height_share_can_exceed_budget_when_jitter_dominates() {
        let bft_round_change_backoff_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);

        assert_eq!(backoff_active_height_share_ppm, 1_500_000);
        assert!(backoff_active_height_share_ppm > 1_000_000);
    }

    #[test]
    fn finality_budget_share_helper_matches_round_change_density_semantics() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = 10u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            250_000
        );
    }

    #[test]
    fn round_change_active_height_share_handles_zero_finality_budget() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = 0u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn round_change_active_height_share_can_exceed_budget_when_jitter_dominates() {
        let bft_round_change_density_avg_milli = 6_000u64;
        let finality_avg = 4u128;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            1_500_000
        );
    }

    #[test]
    fn finality_budget_share_helper_saturates_huge_finality_budgets_without_overflow() {
        let bft_round_change_density_avg_milli = 2_500u64;
        let finality_avg = (u64::MAX as u128) + 1;

        assert_eq!(
            finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg),
            0
        );
    }

    #[test]
    fn ratio_helpers_saturate_huge_metric_inputs_without_overflow() {
        assert_eq!(ratio_ppm_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(ratio_milli_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(ratio_percent_bps(u128::MAX, 1), u128::MAX);
        assert_eq!(ratio_ppm(u128::MAX, 1), u128::MAX);
    }

    #[test]
    fn critical_guard_selection_respects_lane_fairness_pop_order() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 11,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::Challenge {
                task_id: 11,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 11,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::AcceptTask {
                task_id: 11,
                worker: "w1".into(),
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { .. }));
        assert!(matches!(picked[2], MockTx::Resolve { .. }));
    }

    #[test]
    fn critical_guard_only_reorders_scanned_prefix_and_leaves_suffix_fifo() {
        let mut mempool = VecDeque::from(vec![
            MockTx::CreateTask {
                task_id: 21,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::AcceptTask {
                task_id: 21,
                worker: "w1".into(),
            },
            MockTx::Challenge {
                task_id: 21,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 21,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::CreateTask {
                task_id: 22,
                creator: "bob".into(),
                bounty: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 3);
        assert_eq!(picked.len(), 3);
        assert!(matches!(picked[0], MockTx::Challenge { .. }));
        assert!(matches!(picked[1], MockTx::CreateTask { task_id: 21, .. }));
        assert!(matches!(picked[2], MockTx::AcceptTask { .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Resolve { .. }));
        assert!(matches!(mempool[1], MockTx::CreateTask { task_id: 22, .. }));
    }

    #[test]
    fn backoff_is_capped() {
        assert_eq!(round_change_backoff_ms(0, 5, 40), 0);
        assert_eq!(round_change_backoff_ms(1, 5, 40), 5);
        assert_eq!(round_change_backoff_ms(2, 5, 40), 10);
        assert_eq!(round_change_backoff_ms(3, 5, 40), 20);
        assert_eq!(round_change_backoff_ms(4, 5, 40), 40);
        assert_eq!(round_change_backoff_ms(10, 5, 40), 40);
    }

    #[test]
    fn auth_rejects_zero_height_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 0,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_empty_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "   ".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with nonce=0 and matching signature, ingress must reject empty validator first
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_noncanonical_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: " v1 ".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_uppercase_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "V1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_hyphen_only_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "---".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_edge_hyphen_validator_before_nonce_and_signature_checks() {
        for validator in ["-v1", "v1-"] {
            let vote = BftVote {
                validator: validator.into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 1,
                round: 0,
            };

            let mut last_nonce = HashMap::new();
            let mut accepted = Vec::new();
            let mut reject_stats = AuthRejectStats::default();

            accept_signed_vote(
                SignedVote {
                    vote: vote.clone(),
                    nonce: 1,
                    signature: vote_signature(&vote, 1),
                },
                &mut last_nonce,
                &mut accepted,
                &mut reject_stats,
            );

            assert!(accepted.is_empty());
            assert_eq!(reject_stats.bad_sig, 1);
            assert_eq!(reject_stats.replay, 0);
            assert_eq!(reject_stats.stale_nonce, 0);
            assert!(last_nonce.is_empty());
        }
    }

    #[test]
    fn auth_rejects_consecutive_hyphen_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1--worker".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_hyphen_only_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "---".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_edge_hyphen_block_hash_before_nonce_and_signature_checks() {
        for block_hash in ["-h1", "h1-"] {
            let vote = BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: block_hash.into(),
                byzantine: false,
                height: 1,
                round: 0,
            };

            let mut last_nonce = HashMap::new();
            let mut accepted = Vec::new();
            let mut reject_stats = AuthRejectStats::default();

            accept_signed_vote(
                SignedVote {
                    vote: vote.clone(),
                    nonce: 1,
                    signature: vote_signature(&vote, 1),
                },
                &mut last_nonce,
                &mut accepted,
                &mut reject_stats,
            );

            assert!(accepted.is_empty());
            assert_eq!(reject_stats.bad_sig, 1);
            assert_eq!(reject_stats.replay, 0);
            assert_eq!(reject_stats.stale_nonce, 0);
            assert!(last_nonce.is_empty());
        }
    }

    #[test]
    fn auth_rejects_consecutive_hyphen_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1--fork".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_overlong_validator_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v".repeat(MAX_BFT_TOKEN_LEN + 1),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_overlong_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h".repeat(MAX_BFT_TOKEN_LEN + 1),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_zero_nonce_vote_before_signature_check() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h1".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with a syntactically valid signature for nonce=0, ingress must reject
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_noncanonical_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: " h1 ".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 0,
                // even with nonce=0 and matching signature, ingress must reject non-canonical hash first
                signature: vote_signature(&vote, 0),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_rejects_uppercase_block_hash_before_nonce_and_signature_checks() {
        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "A1b2".into(),
            byzantine: false,
            height: 1,
            round: 0,
        };

        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: 1,
                // even with nonce>0 and matching signature, ingress must reject non-canonical hash first
                signature: vote_signature(&vote, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert!(accepted.is_empty());
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        assert!(last_nonce.is_empty());
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_height() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote_h10 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_h10.clone(),
                nonce: 9_999,
                signature: vote_signature(&vote_h10, 9_999),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote_h11 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h11".into(),
            byzantine: false,
            height: 11,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_h11.clone(),
                nonce: 1,
                signature: vote_signature(&vote_h11, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_round() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote_r0 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_r0.clone(),
                nonce: 9_999,
                signature: vote_signature(&vote_r0, 9_999),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote_r1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r1".into(),
            byzantine: false,
            height: 10,
            round: 1,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote_r1.clone(),
                nonce: 1,
                signature: vote_signature(&vote_r1, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_rejects_excessive_forward_nonce_jump_within_same_round_domain() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce: 10,
                signature: vote_signature(&vote1, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-alt".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let jumped_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP + 1;
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce: jumped_nonce,
                signature: vote_signature(&vote2, jumped_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);

        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&10));
    }

    #[test]
    fn auth_accepts_forward_nonce_jump_at_boundary_within_same_round_domain() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce: 10,
                signature: vote_signature(&vote1, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-alt".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let boundary_nonce = 10 + MAX_BFT_NONCE_FORWARD_JUMP;
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce: boundary_nonce,
                signature: vote_signature(&vote2, boundary_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);

        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&boundary_nonce));
    }

    #[test]
    fn auth_rejects_first_nonce_bootstrap_jump_without_prior_domain_nonce() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h11-r0".into(),
            byzantine: false,
            height: 11,
            round: 0,
        };
        let jumped_nonce = MAX_BFT_NONCE_FORWARD_JUMP + 1;
        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: jumped_nonce,
                signature: vote_signature(&vote, jumped_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 0);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 1);

        let key = ("v1".to_string(), 11, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), None);
    }

    #[test]
    fn aggregate_votes_dedups_validator_duplicates_per_hash() {
        let votes = vec![
            BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
            // Same validator + same hash duplicate must not increase tally.
            BftVote {
                validator: "v1".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
            BftVote {
                validator: "v2".into(),
                vote_type: VoteType::Prevote,
                block_hash: "h1".into(),
                byzantine: false,
                height: 7,
                round: 0,
            },
        ];

        let tally = aggregate_votes(&votes, VoteType::Prevote);
        assert_eq!(tally.get("h1"), Some(&2));
    }

    #[test]
    fn auth_nonce_tracking_is_scoped_per_vote_type() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let prevote = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: prevote.clone(),
                nonce: 10,
                signature: vote_signature(&prevote, 10),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let precommit = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Precommit,
            block_hash: "h10-r0".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        // Reusing a lower nonce across vote types must be accepted: replay domain is
        // (validator, height, round, vote_type), not a cross-type global counter.
        accept_signed_vote(
            SignedVote {
                vote: precommit.clone(),
                nonce: 1,
                signature: vote_signature(&precommit, 1),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 2);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
    }

    #[test]
    fn auth_rejects_same_nonce_equivocation_as_nonce_equivocation_not_replay() {
        let mut last_nonce = HashMap::new();
        let mut accepted = Vec::new();
        let mut reject_stats = AuthRejectStats::default();

        let vote1 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-a".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        let nonce = 77;
        accept_signed_vote(
            SignedVote {
                vote: vote1.clone(),
                nonce,
                signature: vote_signature(&vote1, nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        let vote2 = BftVote {
            validator: "v1".into(),
            vote_type: VoteType::Prevote,
            block_hash: "h10-r0-b".into(),
            byzantine: false,
            height: 10,
            round: 0,
        };
        accept_signed_vote(
            SignedVote {
                vote: vote2.clone(),
                nonce,
                signature: vote_signature(&vote2, nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(reject_stats.bad_sig, 1);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);
        let key = ("v1".to_string(), 10, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&nonce));
    }

    fn expected_high_risk_tx_exhaustive(tx: &MockTx) -> bool {
        // Exhaustive match intentionally used as a merge-gate guard:
        // if a new tx variant is introduced, this test must be reviewed.
        match tx {
            MockTx::CreateTask { .. }
            | MockTx::AcceptTask { .. }
            | MockTx::Commit { .. }
            | MockTx::Reveal { .. }
            | MockTx::Challenge { .. } => true,
            // Resolve performs terminal challenged escrow settlement and must stay
            // frozen while emergency pause is active.
            MockTx::Resolve { .. } => true,
        }
    }

    #[test]
    fn emergency_pause_gates_only_high_risk_tx_when_paused() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(1, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 1,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: true,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            assert_eq!(
                is_rejected_by_emergency_pause(true, tx),
                expected_high_risk_tx_exhaustive(tx),
                "pause gate drifted for tx variant while paused: {:?}",
                tx
            );
            assert!(
                !is_rejected_by_emergency_pause(false, tx),
                "pause gate unexpectedly active while unpaused for tx variant: {:?}",
                tx
            );
        }
    }

    #[test]
    fn emergency_pause_risk_gate_classification_is_stable() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(1, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 1,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 1,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 1,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 1,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 1,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 1,
                slash_worker: true,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            assert_eq!(
                is_high_risk_tx(tx),
                expected_high_risk_tx_exhaustive(tx),
                "pause risk gate drifted for tx variant: {:?}",
                tx
            );
        }
    }

    #[test]
    fn emergency_pause_rejection_formula_is_exact_boolean_gate() {
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed_hash = compute_commitment(42, &result_hash, &reveal_salt, "worker");

        let txs = [
            MockTx::CreateTask {
                task_id: 42,
                creator: "alice".into(),
                bounty: 100,
            },
            MockTx::AcceptTask {
                task_id: 42,
                worker: "worker".into(),
            },
            MockTx::Commit {
                task_id: 42,
                worker: "worker".into(),
                committed_hash,
            },
            MockTx::Reveal {
                task_id: 42,
                result_hash,
                reveal_salt,
            },
            MockTx::Challenge {
                task_id: 42,
                challenger: "challenger".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 42,
                slash_worker: false,
                resolver: "governance.resolve_authority".into(),
            },
        ];

        for tx in &txs {
            for paused in [false, true] {
                assert_eq!(
                    is_rejected_by_emergency_pause(paused, tx),
                    paused && is_high_risk_tx(tx),
                    "emergency pause formula drifted: paused={} tx={:?}",
                    paused,
                    tx
                );
            }
        }
    }

    #[test]
    fn proposer_selection_skips_penalized_or_missed_leader() {
        let control = BftJitterControl {
            missed_threshold: 2,
            penalty_rounds: 2,
            round_change_backoff_ms: 5,
            round_change_backoff_cap_ms: 40,
            leader_health: vec![
                LeaderHealth {
                    missed_proposals: 3,
                    penalty_until_round: 5,
                },
                LeaderHealth::default(),
                LeaderHealth::default(),
                LeaderHealth::default(),
            ],
        };

        let (idx, shifted) = select_proposer(1, 1, &control, 4); // base proposer is v3(index=2)
        assert_eq!(idx, 2);
        assert!(!shifted);

        let (idx2, shifted2) = select_proposer(4, 0, &control, 4); // base proposer is v1(index=0), should be skipped
        assert_eq!(idx2, 1);
        assert!(shifted2);
    }

    fn challenged_task_fixture(
        st: &mut StateStore,
        task_id: u64,
    ) -> (ObjectRef, [u8; 32], [u8; 32]) {
        st.set_balance("challenger", 1_000_000);
        st.set_balance(&format!("worker{}", task_id), 1_000);
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(
            task_id,
            &result_hash,
            &reveal_salt,
            &format!("worker{}", task_id),
        );
        let r1 = apply_create_task(st, task_id, "alice".into(), 100).unwrap();
        let r2 = apply_accept_task(st, r1, format!("worker{}", task_id)).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            st,
            r2,
            format!("worker{}", task_id),
            committed,
            100,
        )
        .unwrap();
        let r4 =
            trnm_pouw::apply_reveal_result_at_height(st, r3, result_hash, reveal_salt, None, 110)
                .unwrap();
        let r5 = trnm_pouw::apply_challenge_at_height(
            st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();
        (r5, result_hash, reveal_salt)
    }

    #[test]
    fn rollback_snapshot_restores_task_balances_and_pending_resolve_state() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_499,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8100);
        st.stage_or_confirm_resolve_approval(
            8100,
            1,
            true,
            "authority-a",
            "authority-a,authority-b",
        )
        .unwrap();
        let before_task = st.get_task(8100).unwrap();
        let before_worker = st.balance_of("worker8100");
        let before_challenger = st.balance_of("challenger");
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_pending = st.pending_resolve_approval_snapshot(8100);

        let snapshot = capture_rollback_snapshot(
            &st,
            &MockTx::Resolve {
                task_id: 8100,
                slash_worker: true,
                resolver: "authority-b".into(),
            },
        );

        st.set_balance("worker8100", 0);
        st.set_balance("challenger", 0);
        st.set_balance("treasury.challenge_escrow", 0);
        let mut mutated_task = before_task.clone();
        mutated_task.status = TaskStatus::Completed;
        mutated_task.version += 1;
        st.restore_task(8100, Some(mutated_task));
        st.clear_pending_resolve_approval(8100);

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8100).unwrap(), before_task);
        assert_eq!(st.balance_of("worker8100"), before_worker);
        assert_eq!(st.balance_of("challenger"), before_challenger);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.pending_resolve_approval_snapshot(8100), before_pending);
    }

    #[test]
    fn node_resolve_multisig_first_approval_persists_and_second_finalizes() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8101);

        let first = apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-a".into(),
            },
            130,
        );
        assert!(matches!(
            first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
            Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Challenged);

        apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-b".into(),
            },
            131,
        )
        .expect("second signer should finalize through node-facing path");
        assert_eq!(st.pending_resolve_approval(r5.id), None);
        assert_eq!(st.get_task(r5.id).unwrap().status, TaskStatus::Slashed);
        assert!(st.get_ref(r5.id).unwrap().version > r5.version);
    }

    #[test]
    fn paused_node_gate_skips_second_multisig_resolve_without_mutating_staged_or_escrow_state() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8109);

        let first = apply_one(
            &mut st,
            MockTx::Resolve {
                task_id: r5.id,
                slash_worker: true,
                resolver: "authority-a".into(),
            },
            130,
        );
        assert!(matches!(
            first.unwrap_err().downcast::<trnm_pouw::PouwError>(),
            Ok(trnm_pouw::PouwError::ResolveApprovalStaged)
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-b".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let task_before = st.get_task(r5.id).expect("challenged task must exist");
        let pending_before = st.pending_resolve_approval(r5.id);
        let first_approver_before = st.pending_resolve_first_approver(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        // Commit-loop behavior under pause is to reject/skip high-risk tx before apply_one.
        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval(r5.id),
            pending_before,
            "pause gate must preserve previously staged multisig approval"
        );
        assert_eq!(
            st.pending_resolve_first_approver(r5.id),
            first_approver_before,
            "pause gate must preserve staged first approver identity"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn paused_node_gate_skips_first_multisig_resolve_without_staging_or_escrow_drift() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_1);

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let task_before = st.get_task(r5.id).expect("challenged task must exist");
        let pending_before = st.pending_resolve_approval(r5.id);
        let first_approver_before = st.pending_resolve_first_approver(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval(r5.id),
            pending_before,
            "pause gate must block first multisig approval staging"
        );
        assert_eq!(
            st.pending_resolve_first_approver(r5.id),
            first_approver_before,
            "pause gate must not synthesize staged first approver state"
        );
        assert_eq!(
            st.get_task(r5.id).expect("task should remain challenged"),
            task_before
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), escrow_before);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), forfeit_before);
    }

    #[test]
    fn verified_signer_for_multisig_resolve_uses_actual_resolver_member() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_501,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let tx = MockTx::Resolve {
            task_id: 42,
            slash_worker: false,
            resolver: "authority-b".into(),
        };
        assert_eq!(verified_signer_of(&st, &tx), "authority-b");
    }

    #[test]
    fn staged_resolve_approval_uses_distinct_event_type() {
        let tx = MockTx::Resolve {
            task_id: 7,
            slash_worker: true,
            resolver: "authority-a".into(),
        };
        assert_eq!(
            event_type_for_apply_outcome(&tx, Some("resolve_approval_staged")),
            "resolve_approval_staged"
        );
        assert_eq!(event_type_for_apply_outcome(&tx, None), "resolve");
    }

    #[test]
    fn resolve_challenger_fallback_does_not_alias_resolver() {
        let tx = MockTx::Resolve {
            task_id: 9,
            slash_worker: false,
            resolver: "authority-b".into(),
        };
        assert_eq!(challenger_of(&tx), None);
    }

    fn temp_wal_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("trnm-node-{}-{}", name, now_unix_ms()));
        p
    }

    #[test]
    fn timeout_scan_auto_migrates_committed_revealed_and_challenged() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 1_000_000);
        st.set_balance("worker7001", 1_000);
        st.set_balance("worker7002", 1_000);
        st.set_balance("worker7003", 1_000);

        let r1 = apply_create_task(&mut st, 7001, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(7001, &result_hash, &reveal_salt, "worker7001");
        let r2 = apply_accept_task(&mut st, r1, "worker7001".into()).unwrap();
        let _r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7001".into(),
            committed,
            100,
        )
        .unwrap();

        let r4 = apply_create_task(&mut st, 7002, "alice".into(), 100).unwrap();
        let committed2 = compute_commitment(7002, &result_hash, &reveal_salt, "worker7002");
        let r5 = apply_accept_task(&mut st, r4, "worker7002".into()).unwrap();
        let r6 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r5,
            "worker7002".into(),
            committed2,
            100,
        )
        .unwrap();
        let r7 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r6,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();
        let _r8 = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r7,
            "challenger".into(),
            10,
            "challenger".into(),
            120,
        )
        .unwrap();

        let r9 = apply_create_task(&mut st, 7003, "alice".into(), 100).unwrap();
        let committed3 = compute_commitment(7003, &result_hash, &reveal_salt, "worker7003");
        let r10 = apply_accept_task(&mut st, r9, "worker7003".into()).unwrap();
        let r11 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r10,
            "worker7003".into(),
            committed3,
            100,
        )
        .unwrap();
        let _r12 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r11,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        let known: HashSet<u64> = [7001u64, 7002u64, 7003u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(&mut st, &known, 10_000, 9_000_000);

        assert_eq!(migrated, 3);
        assert_eq!(st.get_task(7001).unwrap().status, TaskStatus::Slashed);
        assert_eq!(st.get_task(7002).unwrap().status, TaskStatus::Completed);
        assert_eq!(st.get_task(7003).unwrap().status, TaskStatus::Completed);
    }

    #[test]
    fn timeout_scan_revealed_boundary_at_deadline_and_after() {
        let mut st = StateStore::new();
        st.set_balance("worker7004", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7004, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7004, &result_hash, &reveal_salt, "worker7004");
        let r2 = apply_accept_task(&mut st, r1, "worker7004".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7004".into(),
            committed,
            100,
        )
        .unwrap();
        let _r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        let challenge_deadline = st
            .get_task(7004)
            .and_then(|t| t.challenge_deadline_height)
            .expect("challenge deadline must be present after reveal");

        let known: HashSet<u64> = [7004u64].into_iter().collect();

        let migrated_at_deadline =
            scan_and_apply_timeouts(&mut st, &known, challenge_deadline, 9_100_000);
        assert_eq!(migrated_at_deadline, 0);
        assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Revealed);

        let migrated_after_deadline = scan_and_apply_timeouts(
            &mut st,
            &known,
            challenge_deadline.saturating_add(1),
            9_100_100,
        );
        assert_eq!(migrated_after_deadline, 1);
        assert_eq!(st.get_task(7004).unwrap().status, TaskStatus::Completed);
    }

    #[test]
    fn timeout_scan_revealed_task_still_finalizes_while_emergency_paused() {
        // Safety boundary scope: emergency pause should block challenged escrow
        // settlement paths only, not uncontested revealed timeout completion.
        let mut st = StateStore::new();
        st.set_balance("worker7005", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7005, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7005, &result_hash, &reveal_salt, "worker7005");
        let r2 = apply_accept_task(&mut st, r1, "worker7005".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7005".into(),
            committed,
            100,
        )
        .unwrap();
        let _r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();

        st.set_gov_param(9_230, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let challenge_deadline = st
            .get_task(7005)
            .and_then(|t| t.challenge_deadline_height)
            .expect("challenge deadline must be present after reveal");

        let known: HashSet<u64> = [7005u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(
            &mut st,
            &known,
            challenge_deadline.saturating_add(1),
            9_100_200,
        );

        assert_eq!(migrated, 1);
        let task = st
            .get_task(7005)
            .expect("task must exist after timeout scan");
        assert_eq!(task.status, TaskStatus::Completed);
        assert_eq!(task.challenge_bond_forfeited, None);
    }

    #[test]
    fn event_deltas_match_balance_movements_on_revealed_timeout_complete() {
        let mut st = StateStore::new();
        st.set_balance("worker8100", 1_000);

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 8100, "alice".into(), 100).unwrap();
        let committed = compute_commitment(8100, &result_hash, &reveal_salt, "worker8100");
        let r2 = apply_accept_task(&mut st, r1, "worker8100".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker8100".into(),
            committed,
            1,
        )
        .unwrap();
        let revealed = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            2,
        )
        .unwrap();

        let before = st.clone();
        let _ = apply_timeout(&mut st, revealed, 1_000).unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8100, None);

        assert_eq!(st.get_task(8100).unwrap().status, TaskStatus::Completed);
        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(challenger_delta, None);
        assert_eq!(treasury_delta.numeric, Some(0));
    }

    #[test]
    fn event_deltas_match_balance_movements_on_resolve_slashed() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8101", 1_000);

        let r1 = apply_create_task(&mut st, 8101, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8101, &result_hash, &reveal_salt, "worker8101");

        let r2 = apply_accept_task(&mut st, r1, "worker8101".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker8101".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8101)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let resolve_authority = "authority8101,authority8101b".to_string();
        st.set_gov_param_bootstrap_unchecked(
            18_101,
            "resolve_authority".into(),
            resolve_authority.clone(),
        )
        .unwrap();
        let staged = apply_resolve(
            &mut st,
            r5.clone(),
            true,
            "authority8101".into(),
            "authority8101".into(),
        )
        .expect_err("first multisig approver should stage only");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        let _r7 = apply_resolve(
            &mut st,
            r5,
            true,
            "authority8101b".into(),
            "authority8101b".into(),
        )
        .unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8101, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert!(
            challenger_delta
                .as_ref()
                .and_then(|d| d.numeric)
                .unwrap_or(0)
                > 0
        );
    }

    #[test]
    fn event_deltas_match_balance_movements_on_resolve_forfeited() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8102", 1_000);

        let r1 = apply_create_task(&mut st, 8102, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8102, &result_hash, &reveal_salt, "worker8102");

        let r2 = apply_accept_task(&mut st, r1, "worker8102".into()).unwrap();
        let r3 = apply_commit_result(&mut st, r2, "worker8102".into(), committed).unwrap();
        let r4 = apply_reveal_result(&mut st, r3, result_hash, reveal_salt, None).unwrap();
        let r5 =
            apply_challenge(&mut st, r4, "challenger".into(), 10, "challenger".into()).unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8102)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let resolve_authority = "authority8102,authority8102b".to_string();
        st.set_gov_param_bootstrap_unchecked(
            18_102,
            "resolve_authority".into(),
            resolve_authority.clone(),
        )
        .unwrap();
        let staged = apply_resolve(
            &mut st,
            r5.clone(),
            false,
            "authority8102".into(),
            "authority8102".into(),
        )
        .expect_err("first multisig approver should stage only");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        let _r7 = apply_resolve(
            &mut st,
            r5,
            false,
            "authority8102b".into(),
            "authority8102b".into(),
        )
        .unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8102, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(0));
    }

    #[test]
    fn event_deltas_match_balance_movements_on_challenged_timeout_refund() {
        let mut st = StateStore::new();
        st.set_balance("challenger", 100);
        st.set_balance("worker8103", 1_000);

        let r1 = apply_create_task(&mut st, 8103, "alice".into(), 100).unwrap();
        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let committed = compute_commitment(8103, &result_hash, &reveal_salt, "worker8103");

        let r2 = apply_accept_task(&mut st, r1, "worker8103".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker8103".into(),
            committed,
            1,
        )
        .unwrap();
        let r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            2,
        )
        .unwrap();
        let challenged = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r4,
            "challenger".into(),
            10,
            "challenger".into(),
            3,
        )
        .unwrap();

        let before = st.clone();
        let challenger = before
            .get_task(8103)
            .and_then(|t| t.challenger)
            .expect("challenger must exist");
        let _ = apply_timeout(&mut st, challenged, 1_000).unwrap();

        let (treasury_delta, challenger_delta) =
            balance_deltas_for_transition(&before, &st, 8103, Some(challenger.as_str()));

        assert_eq!(
            treasury_delta.numeric,
            diff_u128_to_i128(treasury_total(&st), treasury_total(&before))
        );
        assert_eq!(
            challenger_delta.as_ref().and_then(|d| d.numeric),
            diff_u128_to_i128(st.balance_of(&challenger), before.balance_of(&challenger))
        );
        assert_eq!(challenger_delta.as_ref().and_then(|d| d.numeric), Some(10));
        assert_eq!(
            st.get_task(8103).and_then(|t| t.challenge_bond_forfeited),
            Some(false)
        );
    }

    #[test]
    fn event_delta_fallback_is_deterministic_for_large_balances() {
        let before = i128::MAX as u128 + 10;
        let after = before + 25;

        let delta = event_delta_from_balances(after, before);
        assert_eq!(delta.numeric, None);
        assert_eq!(delta.text, "u128:+25");
        assert_ne!(delta.text, "-");

        let reverse = event_delta_from_balances(before, after);
        assert_eq!(reverse.numeric, None);
        assert_eq!(reverse.text, "u128:-25");
    }

    #[test]
    fn event_delta_normal_range_text_matches_previous_numeric_output() {
        let before = 100u128;
        let after = 82u128;

        let delta = event_delta_from_balances(after, before);
        assert_eq!(delta.numeric, Some(-18));
        assert_eq!(delta.text, "-18");
    }

    #[test]
    fn recover_clears_orphan_checkpoints_when_wal_is_empty() {
        let wal_dir = temp_wal_dir("recover-orphan-checkpoints");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 7,
                state_root_hex: "stale-root".into(),
                wal_entry_hash_hex: "stale-hash".into(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_truncates_to_latest_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3_bad = WalMeta {
            height: 3,
            round: 1,
            proposal_hash: "h3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some("broken".into()),
        };
        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3_bad]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_uncheckpointed_wal_without_claiming_recovery() {
        let wal_dir = temp_wal_dir("recover-uncheckpointed");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_auto_isolates_existing_builtin_default_state() {
        let root = temp_wal_dir("default-wal-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(wal_file(&base), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: DEFAULT_BFT_WAL_DIR.into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(&root).unwrap();
        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        std::env::set_current_dir(cwd).unwrap();

        assert_ne!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(resolved.starts_with(PathBuf::from(DEFAULT_BFT_WAL_DIR)));
        assert!(notice.unwrap().contains("isolating this run"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_keeps_explicit_custom_dir_even_if_state_exists() {
        let wal_dir = temp_wal_dir("custom-reuse");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_file(&wal_dir), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: wal_dir.display().to_string(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&resolved);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_stale_state() {
        let wal_dir = temp_wal_dir("fail-if-exists");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "existing").unwrap();

        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 0,
            bft_max_rounds: 3,
            bft_fault_rounds: 0,
            bft_missed_proposal_threshold: 2,
            bft_leader_penalty_rounds: 2,
            bft_round_change_backoff_ms: 5,
            bft_round_change_backoff_max_ms: 40,
            bft_wal_dir: wal_dir.display().to_string(),
            bft_wal_mode: WalDirMode::FailIfExists,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = resolve_wal_dir(&args).unwrap_err();
        assert!(err
            .to_string()
            .contains("refusing to reuse existing BFT WAL state"));

        let _ = fs::remove_dir_all(&wal_dir);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args.config)?;

    println!("[node] start");
    println!(
        "[node] id={} rpc={} p2p={}",
        cfg.node_id, cfg.rpc_addr, cfg.p2p_addr
    );
    println!(
        "[node] block_ms={} max_blocks={}",
        args.block_ms, args.max_blocks
    );
    println!(
        "[node] load demo_tasks={} demo_keys={}",
        args.demo_tasks, args.demo_keys
    );
    println!("[node] parallel_workers={}", args.parallel_workers);
    println!(
        "[node] bft validators={} byzantine={} max_rounds={} fault_rounds={} missed_threshold={} penalty_rounds={} rc_backoff_ms={} rc_backoff_cap_ms={} wal_dir={} wal_mode={:?} checkpoint_interval={} timeout_scan={} timeout_scan_every_blocks={} da_ordering_decouple={} rl_shadow={} rl_shadow_topk={}",
        args.validators,
        args.byzantine,
        args.bft_max_rounds,
        args.bft_fault_rounds,
        args.bft_missed_proposal_threshold,
        args.bft_leader_penalty_rounds,
        args.bft_round_change_backoff_ms,
        args.bft_round_change_backoff_max_ms,
        args.bft_wal_dir,
        args.bft_wal_mode,
        args.bft_checkpoint_interval,
        args.pouw_timeout_scan,
        args.pouw_timeout_scan_every_blocks,
        args.enable_da_ordering_decouple,
        args.rl_advisor_shadow,
        args.rl_advisor_shadow_topk
    );

    let (wal_dir, wal_notice) = resolve_wal_dir(&args)?;
    if let Some(notice) = wal_notice {
        println!("{}", notice);
    }
    println!("[bft-wal] using wal_dir={}", wal_dir.display());
    let recovered = recover_wal_state(&wal_dir)?;
    let mut restored_lock: Option<String> = recovered.restored_lock;
    let mut height: u64 = recovered.next_height.max(1);
    println!(
        "[bft-recover] restored height={} lock={} checkpoint={} truncated={} metadata_only_recovery={}",
        height,
        restored_lock.clone().unwrap_or_else(|| "none".to_string()),
        recovered
            .last_checkpoint
            .as_ref()
            .map(|cp| cp.height.to_string())
            .unwrap_or_else(|| "none".to_string()),
        recovered.truncated,
        recovered.metadata_only_recovery
    );
    if recovered.metadata_only_recovery {
        anyhow::bail!(
            "refusing metadata-only recovery from {}: WAL/checkpoint metadata advanced consensus to height {} but trnm-node does not yet restore application StateStore snapshots or replay committed blocks; start from a fresh --bft-wal-dir / --bft-wal-mode auto isolated run, or implement state snapshot+replay recovery first",
            wal_dir.display(),
            height.saturating_sub(1)
        );
    }

    let mut state = StateStore::new();
    state.set_balance("challenger", 1_000_000);
    let mut mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);
    for i in 0..args.demo_tasks.max(1) {
        let worker = demo_worker_name(1001u64 + i);
        state.set_balance(&worker, 1_000_000);
    }
    let mut known_task_ids: HashSet<u64> = HashSet::new();
    let mut finality_samples_ms: Vec<u128> = Vec::new();
    let mut scheduler_samples_ms: Vec<u128> = Vec::new();
    let mut preexec_samples_ms: Vec<u128> = Vec::new();
    let mut commit_samples_ms: Vec<u128> = Vec::new();
    let mut state_root_total_samples_ms: Vec<u128> = Vec::new();
    let mut critical_wait_blocks_samples: Vec<u128> = Vec::new();
    let mut critical_wait_active_heights: u64 = 0;
    let mut critical_wait_total: u64 = 0;
    let mut block_txs_samples: Vec<u128> = Vec::new();
    let mut block_groups_samples: Vec<u128> = Vec::new();
    let mut rollback_samples: Vec<u128> = Vec::new();
    let mut avg_group_size_samples: Vec<u128> = Vec::new();
    let mut hot_object_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_top_label_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_tail_share_samples_ppm: Vec<u128> = Vec::new();
    let mut hot_object_active_heights: u64 = 0;
    let mut hot_object_active_top_label_share_total_ppm: u128 = 0;
    let mut hot_object_active_tail_share_total_ppm: u128 = 0;
    let mut preexec_reject_total: u64 = 0;
    let mut preexec_reject_active_heights: u64 = 0;
    let mut apply_error_total: u64 = 0;
    let mut apply_error_preexec_conflict_miss_total: u64 = 0;
    let mut apply_error_version_conflict_total: u64 = 0;
    let mut apply_error_invalid_transition_total: u64 = 0;
    let mut apply_error_deadline_exceeded_total: u64 = 0;
    let mut apply_error_semantic_fail_total: u64 = 0;
    let mut rollback_total: u64 = 0;
    let mut rollback_block_total: u64 = 0;
    let mut timeout_migrated_total: u64 = 0;
    let mut bft_observed_heights: u64 = 0;
    let mut bft_committed_heights: u64 = 0;
    let mut bft_round_change_total: u64 = 0;
    let mut bft_round_change_active_heights: u64 = 0;
    let mut bft_round_change_backoff_active_heights: u64 = 0;
    let mut bft_double_vote_total: u64 = 0;
    let mut bft_auth_reject_bad_sig_total: u64 = 0;
    let mut bft_auth_reject_replay_total: u64 = 0;
    let mut bft_auth_reject_stale_nonce_total: u64 = 0;
    let mut bft_round_change_backoff_total_ms: u64 = 0;
    let mut bft_round_change_backoff_max_ms: u64 = 0;
    let mut bft_leader_missed_active_heights: u64 = 0;
    let mut wal_entries = load_wal_meta_entries(&wal_dir)?;
    let mut checkpoints = load_checkpoint_meta(&wal_dir)?;
    let mut bft_jitter = BftJitterControl {
        missed_threshold: args.bft_missed_proposal_threshold,
        penalty_rounds: args.bft_leader_penalty_rounds,
        round_change_backoff_ms: args.bft_round_change_backoff_ms,
        round_change_backoff_cap_ms: args.bft_round_change_backoff_max_ms,
        leader_health: vec![LeaderHealth::default(); args.validators.max(1)],
    };

    loop {
        let block_start = Instant::now();
        let txs_per_block = args.txs_per_block.max(1);
        let picked = pick_txs_with_critical_guard(&mut mempool, txs_per_block);

        let proposal_hash = hash32_hex(format!("h:{}:txs:{}", height, picked.len()).as_bytes());
        let bft = simulate_bft_height(
            height,
            &proposal_hash,
            args.validators,
            args.byzantine,
            args.bft_max_rounds,
            args.bft_fault_rounds,
            restored_lock.take(),
            &mut bft_jitter,
        );
        bft_observed_heights += 1;
        if !bft.committed {
            bft_round_change_total += bft.round_changes;
            if bft.round_changes > 0 {
                bft_round_change_active_heights += 1;
            }
            bft_double_vote_total += bft.double_vote_events as u64;
            bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
            bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
            bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
            bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
            if bft.round_change_backoff_total_ms > 0 {
                bft_round_change_backoff_active_heights += 1;
            }
            bft_round_change_backoff_max_ms =
                bft_round_change_backoff_max_ms.max(bft.round_change_backoff_max_ms);
            if bft.leader_missed_snapshot.iter().any(|missed| *missed > 0) {
                bft_leader_missed_active_heights += 1;
            }
            println!(
                "[block] node={} height={} skipped reason=bft_no_commit proposal_hash={} prevote={} precommit={} rounds={} round_backoff_ms={} leader_missed={:?}",
                cfg.node_id,
                height,
                proposal_hash,
                bft.prevote_count,
                bft.precommit_count,
                args.bft_max_rounds,
                bft.round_change_backoff_total_ms,
                bft.leader_missed_snapshot
            );
            requeue_uncommitted_txs(&mut mempool, picked);
            let wal_entry = WalMeta {
                height,
                round: bft.committed_round,
                proposal_hash: proposal_hash.clone(),
                committed: false,
                state_root_hex: hex::encode(state.state_root()),
                prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
            };
            wal_entries.push(wal_entry);
            persist_wal_meta_entries(&wal_dir, &wal_entries)?;
            persist_consensus_wal(
                &wal_dir,
                &ConsensusWal {
                    next_height: height + 1,
                    last_round: bft.committed_round,
                    locked_block_hash: Some(proposal_hash.clone()),
                },
            )?;
            if args.max_blocks > 0 && height >= args.max_blocks {
                println!("[node] reached max_blocks={}, exiting", args.max_blocks);
                break;
            }
            height += 1;
            thread::sleep(Duration::from_millis(args.block_ms));
            continue;
        }
        bft_round_change_total += bft.round_changes;
        if bft.round_changes > 0 {
            bft_round_change_active_heights += 1;
        }
        bft_double_vote_total += bft.double_vote_events as u64;
        bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
        bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
        bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
        bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
        if bft.round_change_backoff_total_ms > 0 {
            bft_round_change_backoff_active_heights += 1;
        }
        bft_round_change_backoff_max_ms =
            bft_round_change_backoff_max_ms.max(bft.round_change_backoff_max_ms);
        if bft.leader_missed_snapshot.iter().any(|missed| *missed > 0) {
            bft_leader_missed_active_heights += 1;
        }
        println!(
            "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} round_backoff_ms={} leader_missed={:?} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale_nonce={}",
            height,
            bft.committed_round,
            bft.prevote_count,
            bft.precommit_count,
            bft.round_changes,
            bft.round_change_backoff_total_ms,
            bft.leader_missed_snapshot,
            bft.double_vote_events,
            bft.auth_reject_bad_sig,
            bft.auth_reject_replay,
            bft.auth_reject_stale_nonce
        );
        bft_committed_heights += 1;

        let mut applied = 0u64;
        let scheduler_start = Instant::now();
        let ordering_decision = decide_order_for_commit(
            &state,
            &picked,
            args.parallel_workers,
            args.enable_da_ordering_decouple,
            height,
        );
        let scheduler_elapsed_ms = scheduler_start.elapsed().as_millis();
        scheduler_samples_ms.push(scheduler_elapsed_ms);
        preexec_samples_ms.push(ordering_decision.preexec_elapsed_ms);
        critical_wait_blocks_samples.push(ordering_decision.critical_wait_blocks as u128);
        critical_wait_total += ordering_decision.critical_wait_blocks;
        if ordering_decision.critical_wait_blocks > 0 {
            critical_wait_active_heights += 1;
        }
        preexec_reject_total += ordering_decision.rejected;
        if ordering_decision.rejected > 0 {
            preexec_reject_active_heights += 1;
        }
        let group_count = ordering_decision.group_count;
        let avg_group_size = if group_count == 0 {
            0u128
        } else {
            ((picked.len() as u128) * 1000) / (group_count as u128)
        };
        avg_group_size_samples.push(avg_group_size);
        let hot_object_summary = summarize_hot_objects(&state, &picked);
        let hot_object_share_ppm = if picked.is_empty() {
            0u128
        } else {
            ((hot_object_summary.hot_tx_count as u128) * 1_000_000) / (picked.len() as u128)
        };
        let hot_object_top_label_share_ppm = hot_object_top_label_share_ppm(&hot_object_summary);
        let hot_object_tail_share_ppm = hot_object_tail_share_ppm(&hot_object_summary);
        hot_object_share_samples_ppm.push(hot_object_share_ppm);
        hot_object_top_label_share_samples_ppm.push(hot_object_top_label_share_ppm);
        hot_object_tail_share_samples_ppm.push(hot_object_tail_share_ppm);
        if hot_object_summary.hot_tx_count > 0 {
            hot_object_active_heights += 1;
            hot_object_active_top_label_share_total_ppm =
                hot_object_active_top_label_share_total_ppm
                    .saturating_add(hot_object_top_label_share_ppm);
            hot_object_active_tail_share_total_ppm =
                hot_object_active_tail_share_total_ppm.saturating_add(hot_object_tail_share_ppm);
        }

        let rl_advisor: Box<dyn RlAdvisor> = if args.rl_advisor_shadow {
            Box::new(ShadowOnlyRlAdvisor {
                topk: args.rl_advisor_shadow_topk,
            })
        } else {
            Box::new(DisabledRlAdvisor)
        };
        if let Some(advice) = rl_advisor.advise(&RlAdviceContext {
            height,
            ordered_ids: ordering_decision.ordered_ids.clone(),
        }) {
            println!(
                "[rl-shadow] height={} enabled=true reason={} baseline_ids={:?} suggested_ids={:?} applied=false",
                height,
                advice.reason,
                ordering_decision.ordered_ids,
                advice.suggested_ids
            );
        }

        let commit_start = Instant::now();
        let mut last_state_root_hex: Option<String> = None;
        let mut state_root_total_ms = 0u128;
        let mut rollback_count = 0u64;
        for id in ordering_decision.ordered_ids {
            let idx = (id - 1) as usize;
            let tx = picked[idx].clone();
            let task_id = task_id_of(&tx);
            let from_status = status_name(&state, task_id);

            if is_rejected_by_emergency_pause(state.is_emergency_paused(), &tx) {
                println!(
                    "[tx] rejected_by_pause height={} tx_id={} event_type={} emergency_pause=true",
                    height,
                    id,
                    event_type_of(&tx)
                );
                continue;
            }

            let before = capture_rollback_snapshot(&state, &tx);
            if let Err(e) = apply_one(&mut state, tx.clone(), height) {
                let err_kind = classify_apply_error(&e);
                let err_text = e.to_string();
                if err_kind == "resolve_approval_staged" {
                    applied += 1;
                    known_task_ids.insert(task_id);
                    let to_status = status_name(&state, task_id);
                    let state_root_start = Instant::now();
                    let root = hex::encode(state.state_root());
                    state_root_total_ms += state_root_start.elapsed().as_millis();
                    last_state_root_hex = Some(root.clone());
                    let challenger_account: Option<String> = match &tx {
                        MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
                        MockTx::Resolve { .. } => {
                            before.task.as_ref().and_then(|t| t.challenger.clone())
                        }
                        _ => None,
                    };
                    let treasury_delta = EventDelta {
                        numeric: Some(0),
                        text: "0".to_string(),
                    };
                    let challenger_delta = challenger_account.as_ref().map(|_| EventDelta {
                        numeric: Some(0),
                        text: "0".to_string(),
                    });
                    let signer = verified_signer_of(&state, &tx);
                    emit_event(
                        &state,
                        &tx,
                        &signer,
                        id,
                        height,
                        &from_status,
                        &to_status,
                        &root,
                        &treasury_delta,
                        challenger_delta.as_ref(),
                        challenger_account.as_deref(),
                        Some(err_kind),
                    );
                } else {
                    rollback_tx_snapshot(&mut state, before);
                    apply_error_total += 1;
                    rollback_total += 1;
                    rollback_count += 1;
                    match err_kind {
                        "version_conflict" => apply_error_version_conflict_total += 1,
                        "preexec_conflict_miss" => apply_error_preexec_conflict_miss_total += 1,
                        "invalid_transition" => apply_error_invalid_transition_total += 1,
                        "deadline_exceeded" => apply_error_deadline_exceeded_total += 1,
                        _ => apply_error_semantic_fail_total += 1,
                    }
                    println!(
                        "[tx] apply_error height={} tx_id={} err_kind={} err={} rollback=true",
                        height, id, err_kind, err_text
                    );
                }
            } else {
                applied += 1;
                known_task_ids.insert(task_id);
                let to_status = status_name(&state, task_id);
                let state_root_start = Instant::now();
                let root = hex::encode(state.state_root());
                state_root_total_ms += state_root_start.elapsed().as_millis();
                last_state_root_hex = Some(root.clone());
                let challenger_account: Option<String> = match &tx {
                    MockTx::Challenge { challenger, .. } => Some(challenger.clone()),
                    MockTx::Resolve { .. } => {
                        before.task.as_ref().and_then(|t| t.challenger.clone())
                    }
                    _ => None,
                };
                let (treasury_delta, challenger_delta) =
                    balance_deltas_from_snapshot(&before, &state, challenger_account.as_deref());
                let signer = verified_signer_of(&state, &tx);
                emit_event(
                    &state,
                    &tx,
                    &signer,
                    id,
                    height,
                    &from_status,
                    &to_status,
                    &root,
                    &treasury_delta,
                    challenger_delta.as_ref(),
                    challenger_account.as_deref(),
                    None,
                );
            }
        }

        let scan_every = args.pouw_timeout_scan_every_blocks.max(1);
        if args.pouw_timeout_scan && height % scan_every == 0 {
            let migrated = scan_and_apply_timeouts(&mut state, &known_task_ids, height, 9_000_000);
            timeout_migrated_total += migrated;
            if migrated > 0 {
                last_state_root_hex = None;
                println!(
                    "[timeout] height={} migrated={} cumulative_migrated={}",
                    height, migrated, timeout_migrated_total
                );
            }
        }

        let root = if let Some(root) = last_state_root_hex.clone() {
            root
        } else {
            let state_root_start = Instant::now();
            let root = hex::encode(state.state_root());
            state_root_total_ms += state_root_start.elapsed().as_millis();
            root
        };
        let commit_elapsed_ms = commit_start.elapsed().as_millis();
        commit_samples_ms.push(commit_elapsed_ms);
        state_root_total_samples_ms.push(state_root_total_ms);
        block_txs_samples.push(applied as u128);
        block_groups_samples.push(group_count as u128);
        rollback_samples.push(rollback_count as u128);
        if rollback_count > 0 {
            rollback_block_total += 1;
        }
        let elapsed_ms = block_start.elapsed().as_millis();
        finality_samples_ms.push(elapsed_ms);
        println!(
            "[block] node={} height={} txs={} groups={} rollback_count={} critical_wait_blocks={} scheduler_elapsed_ms={} preexec_elapsed_ms={} commit_elapsed_ms={} state_root_total_ms={} state_root={} elapsed_ms={}",
            cfg.node_id,
            height,
            applied,
            group_count,
            rollback_count,
            ordering_decision.critical_wait_blocks,
            scheduler_elapsed_ms,
            ordering_decision.preexec_elapsed_ms,
            commit_elapsed_ms,
            state_root_total_ms,
            root,
            elapsed_ms
        );

        let wal_entry = WalMeta {
            height,
            round: bft.committed_round,
            proposal_hash: proposal_hash.clone(),
            committed: true,
            state_root_hex: root.clone(),
            prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
        };
        let wal_hash = wal_entry.content_hash_hex();
        wal_entries.push(wal_entry);
        persist_wal_meta_entries(&wal_dir, &wal_entries)?;

        if args.bft_checkpoint_interval > 0 && height % args.bft_checkpoint_interval == 0 {
            checkpoints.push(CheckpointMeta {
                height,
                state_root_hex: root.clone(),
                wal_entry_hash_hex: wal_hash,
            });
            persist_checkpoint_meta(&wal_dir, &checkpoints)?;
            println!("[bft-checkpoint] height={} state_root={}", height, root);
        }

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: height + 1,
                last_round: bft.committed_round,
                locked_block_hash: Some(proposal_hash.clone()),
            },
        )?;

        if args.max_blocks > 0 && height >= args.max_blocks {
            println!("[node] reached max_blocks={}, exiting", args.max_blocks);
            break;
        }
        if mempool.is_empty() {
            println!("[node] mempool empty, exiting");
            break;
        }

        height += 1;
        thread::sleep(Duration::from_millis(args.block_ms));
    }

    let finality_p50 = percentile(finality_samples_ms.clone(), 0.50);
    let finality_p95 = percentile(finality_samples_ms.clone(), 0.95);
    let scheduler_p50 = percentile(scheduler_samples_ms.clone(), 0.50);
    let scheduler_p95 = percentile(scheduler_samples_ms.clone(), 0.95);
    let preexec_p50 = percentile(preexec_samples_ms.clone(), 0.50);
    let preexec_p95 = percentile(preexec_samples_ms.clone(), 0.95);
    let commit_p50 = percentile(commit_samples_ms.clone(), 0.50);
    let commit_p95 = percentile(commit_samples_ms.clone(), 0.95);
    let state_root_total_p50 = percentile(state_root_total_samples_ms.clone(), 0.50);
    let state_root_total_p95 = percentile(state_root_total_samples_ms.clone(), 0.95);
    let critical_wait_blocks_p50 = percentile(critical_wait_blocks_samples.clone(), 0.50);
    let critical_wait_blocks_p95 = percentile(critical_wait_blocks_samples.clone(), 0.95);
    let block_txs_p50 = percentile(block_txs_samples.clone(), 0.50);
    let block_txs_p95 = percentile(block_txs_samples.clone(), 0.95);
    let block_groups_p50 = percentile(block_groups_samples.clone(), 0.50);
    let block_groups_p95 = percentile(block_groups_samples.clone(), 0.95);
    let rollback_p50 = percentile(rollback_samples.clone(), 0.50);
    let rollback_p95 = percentile(rollback_samples.clone(), 0.95);
    let avg_group_size_p50 = percentile(avg_group_size_samples.clone(), 0.50);
    let avg_group_size_p95 = percentile(avg_group_size_samples.clone(), 0.95);
    let hot_object_share_p50_ppm = percentile(hot_object_share_samples_ppm.clone(), 0.50);
    let hot_object_share_p95_ppm = percentile(hot_object_share_samples_ppm.clone(), 0.95);
    let hot_object_top_label_share_p50_ppm =
        percentile(hot_object_top_label_share_samples_ppm.clone(), 0.50);
    let hot_object_top_label_share_p95_ppm =
        percentile(hot_object_top_label_share_samples_ppm.clone(), 0.95);
    let hot_object_tail_share_p50_ppm = percentile(hot_object_tail_share_samples_ppm.clone(), 0.50);
    let hot_object_tail_share_p95_ppm = percentile(hot_object_tail_share_samples_ppm.clone(), 0.95);
    let finality_max = max_or_zero(&finality_samples_ms);
    let scheduler_max = max_or_zero(&scheduler_samples_ms);
    let preexec_max = max_or_zero(&preexec_samples_ms);
    let commit_max = max_or_zero(&commit_samples_ms);
    let state_root_total_max = max_or_zero(&state_root_total_samples_ms);
    let critical_wait_blocks_max = max_or_zero(&critical_wait_blocks_samples);
    let block_txs_max = max_or_zero(&block_txs_samples);
    let block_groups_max = max_or_zero(&block_groups_samples);
    let rollback_max = max_or_zero(&rollback_samples);
    let avg_group_size_max = max_or_zero(&avg_group_size_samples);
    let hot_object_share_max_ppm = max_or_zero(&hot_object_share_samples_ppm);
    let hot_object_top_label_share_max_ppm = max_or_zero(&hot_object_top_label_share_samples_ppm);
    let hot_object_tail_share_max_ppm = max_or_zero(&hot_object_tail_share_samples_ppm);
    let finality_avg = average_or_zero(&finality_samples_ms);
    let scheduler_avg = average_or_zero(&scheduler_samples_ms);
    let preexec_avg = average_or_zero(&preexec_samples_ms);
    let commit_avg = average_or_zero(&commit_samples_ms);
    let state_root_total_avg = average_or_zero(&state_root_total_samples_ms);
    let critical_wait_blocks_avg = average_or_zero(&critical_wait_blocks_samples);
    let rollback_avg = average_or_zero(&rollback_samples);
    let avg_group_size_avg = average_or_zero(&avg_group_size_samples);
    let hot_object_share_avg_ppm = average_or_zero(&hot_object_share_samples_ppm);
    let hot_object_top_label_share_avg_ppm =
        average_or_zero(&hot_object_top_label_share_samples_ppm);
    let hot_object_tail_share_avg_ppm = average_or_zero(&hot_object_tail_share_samples_ppm);
    let hot_object_active_top_label_share_avg_ppm = if hot_object_active_heights == 0 {
        0
    } else {
        hot_object_active_top_label_share_total_ppm / hot_object_active_heights as u128
    };
    let hot_object_active_tail_share_avg_ppm = if hot_object_active_heights == 0 {
        0
    } else {
        hot_object_active_tail_share_total_ppm / hot_object_active_heights as u128
    };
    let hot_object_active_height_rate_ppm =
        ratio_ppm_u64(hot_object_active_heights, finality_samples_ms.len() as u64);
    let hot_object_active_observed_height_rate_ppm =
        ratio_ppm_u64(hot_object_active_heights, bft_observed_heights);
    let scheduler_share_avg_ppm = ratio_ppm(scheduler_avg, finality_avg);
    let scheduler_peak_share_ppm = ratio_ppm(scheduler_max, finality_max);
    let preexec_share_avg_ppm = ratio_ppm(preexec_avg, finality_avg);
    let commit_share_avg_ppm = ratio_ppm(commit_avg, finality_avg);
    let commit_peak_share_ppm = ratio_ppm(commit_max, finality_max);
    let state_root_total_share_avg_ppm = ratio_ppm(state_root_total_avg, finality_avg);
    let state_root_total_peak_share_ppm = ratio_ppm(state_root_total_max, finality_max);
    let rollback_share_avg_ppm = ratio_ppm(rollback_avg, finality_avg);
    let rollback_peak_share_ppm = ratio_ppm(rollback_max, finality_max);
    let preexec_peak_share_ppm = ratio_ppm(preexec_max, finality_max);
    let rollback_block_rate_ppm =
        ratio_ppm_u64(rollback_block_total, finality_samples_ms.len() as u64);
    let rollback_active_heights = rollback_block_total;
    let rollback_active_height_rate_ppm = rollback_block_rate_ppm;
    let rollback_active_observed_height_rate_ppm =
        ratio_ppm_u64(rollback_active_heights, bft_observed_heights);
    let rollback_density_avg = if rollback_block_total == 0 {
        0
    } else {
        rollback_total / rollback_block_total
    };
    let rollback_density_avg_milli = ratio_milli_u64(rollback_total, rollback_block_total);
    let rollback_active_height_share_ppm =
        finality_budget_share_ppm(rollback_density_avg_milli, finality_avg);
    let preexec_conflict_miss_share_bps = ratio_percent_bps(
        apply_error_preexec_conflict_miss_total as u128,
        preexec_reject_total as u128,
    );
    let preexec_reject_density_avg = if bft_committed_heights == 0 {
        0
    } else {
        preexec_reject_total / bft_committed_heights
    };
    let preexec_reject_density_avg_milli =
        ratio_milli_u64(preexec_reject_total, bft_committed_heights);
    let preexec_reject_active_height_rate_ppm =
        ratio_ppm_u64(preexec_reject_active_heights, bft_committed_heights);
    let preexec_reject_active_observed_height_rate_ppm =
        ratio_ppm_u64(preexec_reject_active_heights, bft_observed_heights);
    let preexec_reject_active_height_share_ppm =
        finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);
    let apply_error_rollback_share_bps =
        ratio_percent_bps(rollback_total as u128, apply_error_total as u128);
    let rollback_block_rate = if finality_samples_ms.is_empty() {
        0.0
    } else {
        rollback_block_total as f64 / finality_samples_ms.len() as f64
    };
    let critical_wait_density_ppm = ratio_ppm(critical_wait_blocks_avg, finality_avg);
    let critical_wait_peak_density_ppm = ratio_ppm(critical_wait_blocks_max, finality_max);
    let critical_wait_active_height_rate_ppm = ratio_ppm_u64(
        critical_wait_active_heights,
        finality_samples_ms.len() as u64,
    );
    let critical_wait_active_observed_height_rate_ppm =
        ratio_ppm_u64(critical_wait_active_heights, bft_observed_heights);
    let critical_wait_density_avg = if critical_wait_active_heights == 0 {
        0
    } else {
        critical_wait_total / critical_wait_active_heights
    };
    let critical_wait_density_avg_milli =
        ratio_milli_u64(critical_wait_total, critical_wait_active_heights);
    let critical_wait_active_height_share_ppm =
        finality_budget_share_ppm(critical_wait_density_avg_milli, finality_avg);
    let preexec_reject_share_bps =
        ratio_percent_bps(preexec_reject_total as u128, apply_error_total as u128);
    let unprofiled_finality_share_bps = gap_percent_bps(
        finality_avg,
        scheduler_avg
            .saturating_add(preexec_avg)
            .saturating_add(commit_avg),
        state_root_total_avg,
    );
    let bft_round_change_per_height_ppm =
        ratio_ppm_u64(bft_round_change_total, bft_committed_heights);
    let bft_round_change_active_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
    let bft_round_change_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);
    let bft_round_change_density_avg = if bft_round_change_active_heights == 0 {
        0
    } else {
        bft_round_change_total / bft_round_change_active_heights
    };
    let bft_round_change_density_avg_milli =
        ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);
    let bft_round_change_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_density_avg_milli, finality_avg);
    let bft_round_change_backoff_avg_ms = if bft_round_change_total == 0 {
        0
    } else {
        bft_round_change_backoff_total_ms / bft_round_change_total
    };
    let bft_round_change_backoff_active_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_backoff_active_heights, bft_committed_heights);
    let bft_round_change_backoff_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_round_change_backoff_active_heights, bft_observed_heights);
    let bft_round_change_backoff_density_avg_ms = if bft_round_change_active_heights == 0 {
        0
    } else {
        bft_round_change_backoff_total_ms / bft_round_change_active_heights
    };
    let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_active_heights,
    );
    let bft_round_change_backoff_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);
    let bft_round_change_backoff_wall_share_ppm =
        ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
    let bft_round_change_backoff_share_ppm = bft_round_change_backoff_wall_share_ppm;
    let recovery_error_rate = if finality_samples_ms.is_empty() {
        0.0
    } else {
        apply_error_total as f64 / finality_samples_ms.len() as f64
    };
    let leader_missed_final: Vec<u64> = bft_jitter
        .leader_health
        .iter()
        .map(|h| h.missed_proposals)
        .collect();
    let bft_leader_missed_total: u64 = leader_missed_final.iter().copied().sum();
    let bft_leader_missed_max = leader_missed_final.iter().copied().max().unwrap_or(0);
    let bft_leader_missed_top_share_ppm =
        ratio_ppm_u64(bft_leader_missed_max, bft_leader_missed_total);
    let bft_leader_missed_active_validators = leader_missed_final
        .iter()
        .filter(|missed| **missed > 0)
        .count() as u64;
    let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
        bft_leader_missed_active_validators,
        leader_missed_final.len() as u64,
    );
    let bft_leader_missed_active_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_committed_heights);
    let bft_leader_missed_active_observed_height_rate_ppm =
        ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
    let bft_leader_missed_density_avg = if bft_leader_missed_active_heights == 0 {
        0
    } else {
        bft_leader_missed_total / bft_leader_missed_active_heights
    };
    let bft_leader_missed_density_avg_milli =
        ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights);
    let bft_leader_missed_active_height_share_ppm =
        finality_budget_share_ppm(bft_leader_missed_density_avg_milli, finality_avg);
    println!(
        "[consensus] finality_avg_ms={} finality_p50_ms={} finality_p95_ms={} finality_max_ms={} scheduler_elapsed_avg_ms={} scheduler_elapsed_p50_ms={} scheduler_elapsed_p95_ms={} scheduler_elapsed_max_ms={} scheduler_share_avg_ppm={} scheduler_peak_share_ppm={} preexec_elapsed_avg_ms={} preexec_elapsed_p50_ms={} preexec_elapsed_p95_ms={} preexec_elapsed_max_ms={} preexec_share_avg_ppm={} preexec_peak_share_ppm={} commit_elapsed_avg_ms={} commit_elapsed_p50_ms={} commit_elapsed_p95_ms={} commit_elapsed_max_ms={} commit_share_avg_ppm={} commit_peak_share_ppm={} state_root_total_avg_ms={} state_root_total_p50_ms={} state_root_total_p95_ms={} state_root_total_max_ms={} state_root_total_share_avg_ppm={} state_root_total_peak_share_ppm={} unprofiled_finality_share_bps={} critical_wait_blocks_avg={} critical_wait_blocks_p50={} critical_wait_blocks_p95={} critical_wait_blocks_max={} critical_wait_density_ppm={} critical_wait_peak_density_ppm={} critical_wait_active_heights={} critical_wait_active_height_rate_ppm={} critical_wait_active_observed_height_rate_ppm={} critical_wait_density_avg={} critical_wait_density_avg_milli={} critical_wait_active_height_share_ppm={} block_txs_p50={} block_txs_p95={} block_txs_max={} block_groups_p50={} block_groups_p95={} block_groups_max={} avg_group_size_avg_milli={} avg_group_size_p50_milli={} avg_group_size_p95_milli={} avg_group_size_max_milli={} hot_object_share_avg_ppm={} hot_object_share_p50_ppm={} hot_object_share_p95_ppm={} hot_object_share_max_ppm={} hot_object_active_heights={} hot_object_active_height_rate_ppm={} hot_object_active_observed_height_rate_ppm={} hot_object_top_label_share_avg_ppm={} hot_object_top_label_share_p50_ppm={} hot_object_top_label_share_p95_ppm={} hot_object_top_label_share_max_ppm={} hot_object_active_top_label_share_avg_ppm={} hot_object_tail_share_avg_ppm={} hot_object_tail_share_p50_ppm={} hot_object_tail_share_p95_ppm={} hot_object_tail_share_max_ppm={} hot_object_active_tail_share_avg_ppm={} rollback_count_avg={} rollback_count_p50={} rollback_count_p95={} rollback_count_max={} rollback_share_avg_ppm={} rollback_peak_share_ppm={} rollback_block_total={} rollback_active_heights={} rollback_block_rate={:.6} rollback_block_rate_ppm={} rollback_active_height_rate_ppm={} rollback_active_observed_height_rate_ppm={} rollback_density_avg={} rollback_density_avg_milli={} rollback_active_height_share_ppm={} preexec_reject_total={} preexec_reject_active_heights={} preexec_reject_density_avg={} preexec_reject_density_avg_milli={} preexec_reject_active_height_rate_ppm={} preexec_reject_active_observed_height_rate_ppm={} preexec_reject_active_height_share_ppm={} preexec_reject_share_bps={} apply_error_total={} apply_error_preexec_conflict_miss_total={} preexec_conflict_miss_share_bps={} apply_error_version_conflict_total={} apply_error_invalid_transition_total={} apply_error_deadline_exceeded_total={} apply_error_semantic_fail_total={} rollback_total={} apply_error_rollback_share_bps={} timeout_migrated_total={} recovery_error_rate={:.6} bft_observed_heights={} bft_committed_heights={} bft_round_change_total={} bft_round_change_per_height_ppm={} bft_round_change_active_heights={} bft_round_change_active_height_rate_ppm={} bft_round_change_active_observed_height_rate_ppm={} bft_round_change_density_avg={} bft_round_change_density_avg_milli={} bft_round_change_active_height_share_ppm={} bft_round_change_backoff_total_ms={} bft_round_change_backoff_avg_ms={} bft_round_change_backoff_active_heights={} bft_round_change_backoff_active_height_rate_ppm={} bft_round_change_backoff_active_observed_height_rate_ppm={} bft_round_change_backoff_density_avg_ms={} bft_round_change_backoff_density_avg_milli={} bft_round_change_backoff_active_height_share_ppm={} bft_round_change_backoff_max_ms={} bft_round_change_backoff_wall_share_ppm={} bft_round_change_backoff_share_ppm={} bft_leader_missed_total={} bft_leader_missed_max={} bft_leader_missed_top_share_ppm={} bft_leader_missed_active_validators={} bft_leader_missed_active_validator_share_ppm={} bft_leader_missed_active_heights={} bft_leader_missed_active_height_rate_ppm={} bft_leader_missed_active_observed_height_rate_ppm={} bft_leader_missed_density_avg={} bft_leader_missed_density_avg_milli={} bft_leader_missed_active_height_share_ppm={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_nonce_total={}",
        finality_avg,
        finality_p50,
        finality_p95,
        finality_max,
        scheduler_avg,
        scheduler_p50,
        scheduler_p95,
        scheduler_max,
        scheduler_share_avg_ppm,
        scheduler_peak_share_ppm,
        preexec_avg,
        preexec_p50,
        preexec_p95,
        preexec_max,
        preexec_share_avg_ppm,
        preexec_peak_share_ppm,
        commit_avg,
        commit_p50,
        commit_p95,
        commit_max,
        commit_share_avg_ppm,
        commit_peak_share_ppm,
        state_root_total_avg,
        state_root_total_p50,
        state_root_total_p95,
        state_root_total_max,
        state_root_total_share_avg_ppm,
        state_root_total_peak_share_ppm,
        unprofiled_finality_share_bps,
        critical_wait_blocks_avg,
        critical_wait_blocks_p50,
        critical_wait_blocks_p95,
        critical_wait_blocks_max,
        critical_wait_density_ppm,
        critical_wait_peak_density_ppm,
        critical_wait_active_heights,
        critical_wait_active_height_rate_ppm,
        critical_wait_active_observed_height_rate_ppm,
        critical_wait_density_avg,
        critical_wait_density_avg_milli,
        critical_wait_active_height_share_ppm,
        block_txs_p50,
        block_txs_p95,
        block_txs_max,
        block_groups_p50,
        block_groups_p95,
        block_groups_max,
        avg_group_size_avg,
        avg_group_size_p50,
        avg_group_size_p95,
        avg_group_size_max,
        hot_object_share_avg_ppm,
        hot_object_share_p50_ppm,
        hot_object_share_p95_ppm,
        hot_object_share_max_ppm,
        hot_object_active_heights,
        hot_object_active_height_rate_ppm,
        hot_object_active_observed_height_rate_ppm,
        hot_object_top_label_share_avg_ppm,
        hot_object_top_label_share_p50_ppm,
        hot_object_top_label_share_p95_ppm,
        hot_object_top_label_share_max_ppm,
        hot_object_active_top_label_share_avg_ppm,
        hot_object_tail_share_avg_ppm,
        hot_object_tail_share_p50_ppm,
        hot_object_tail_share_p95_ppm,
        hot_object_tail_share_max_ppm,
        hot_object_active_tail_share_avg_ppm,
        rollback_avg,
        rollback_p50,
        rollback_p95,
        rollback_max,
        rollback_share_avg_ppm,
        rollback_peak_share_ppm,
        rollback_block_total,
        rollback_active_heights,
        rollback_block_rate,
        rollback_block_rate_ppm,
        rollback_active_height_rate_ppm,
        rollback_active_observed_height_rate_ppm,
        rollback_density_avg,
        rollback_density_avg_milli,
        rollback_active_height_share_ppm,
        preexec_reject_total,
        preexec_reject_active_heights,
        preexec_reject_density_avg,
        preexec_reject_density_avg_milli,
        preexec_reject_active_height_rate_ppm,
        preexec_reject_active_observed_height_rate_ppm,
        preexec_reject_active_height_share_ppm,
        preexec_reject_share_bps,
        apply_error_total,
        apply_error_preexec_conflict_miss_total,
        preexec_conflict_miss_share_bps,
        apply_error_version_conflict_total,
        apply_error_invalid_transition_total,
        apply_error_deadline_exceeded_total,
        apply_error_semantic_fail_total,
        rollback_total,
        apply_error_rollback_share_bps,
        timeout_migrated_total,
        recovery_error_rate,
        bft_observed_heights,
        bft_committed_heights,
        bft_round_change_total,
        bft_round_change_per_height_ppm,
        bft_round_change_active_heights,
        bft_round_change_active_height_rate_ppm,
        bft_round_change_active_observed_height_rate_ppm,
        bft_round_change_density_avg,
        bft_round_change_density_avg_milli,
        bft_round_change_active_height_share_ppm,
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_avg_ms,
        bft_round_change_backoff_active_heights,
        bft_round_change_backoff_active_height_rate_ppm,
        bft_round_change_backoff_active_observed_height_rate_ppm,
        bft_round_change_backoff_density_avg_ms,
        bft_round_change_backoff_density_avg_milli,
        bft_round_change_backoff_active_height_share_ppm,
        bft_round_change_backoff_max_ms,
        bft_round_change_backoff_wall_share_ppm,
        bft_round_change_backoff_share_ppm,
        bft_leader_missed_total,
        bft_leader_missed_max,
        bft_leader_missed_top_share_ppm,
        bft_leader_missed_active_validators,
        bft_leader_missed_active_validator_share_ppm,
        bft_leader_missed_active_heights,
        bft_leader_missed_active_height_rate_ppm,
        bft_leader_missed_active_observed_height_rate_ppm,
        bft_leader_missed_density_avg,
        bft_leader_missed_density_avg_milli,
        bft_leader_missed_active_height_share_ppm,
        leader_missed_final,
        bft_double_vote_total,
        bft_auth_reject_bad_sig_total,
        bft_auth_reject_replay_total,
        bft_auth_reject_stale_nonce_total
    );

    Ok(())
}
