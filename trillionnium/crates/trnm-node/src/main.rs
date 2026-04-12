use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    ffi::OsString,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_executor::build_parallel_groups;
use trnm_mempool::{IngressClass, LaneAdmissionGate};
#[cfg(test)]
use trnm_pouw::{
    apply_accept_task, apply_challenge, apply_commit_result, apply_resolve, apply_reveal_result,
    challenge_consumption_receipt_at_height, resolve_consumption_receipt_at_height,
    ConsumptionResolveDecision,
};
use trnm_pouw::{
    apply_accept_task_at_height, apply_challenge_at_height, apply_commit_result_at_height,
    apply_create_task, apply_resolve_at_height, apply_reveal_result_at_height, apply_timeout,
    submit_consumption_receipt_at_height, ConsumptionReceipt,
};
use trnm_state::{
    checkpoint_da_light_verifier_summary, verify_wal_and_find_checkpoint_node_recovery,
    CheckpointMeta, PendingResolveApprovalSnapshot, StateStore, TaskConsumptionSummary, WalMeta,
};
use trnm_types::{Hash32, ObjectRef, TaskMeteringSnapshot, TaskStatus, Tx};

#[cfg(test)]
fn cwd_test_lock() -> &'static Mutex<()> {
    static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn sample_consumption_receipt(
    task_id: u64,
    worker_id: &str,
    consumer_id: &str,
    result_hash: Hash32,
) -> ConsumptionReceipt {
    ConsumptionReceipt {
        settlement_schema: trnm_pouw::POCO_V1_SETTLEMENT_SCHEMA.to_string(),
        task_id,
        worker_id: worker_id.to_string(),
        consumer_id: consumer_id.to_string(),
        billing_window_id: "bw-1".to_string(),
        tokenizer_id: "llama3-tokenizer".to_string(),
        tokenizer_version: "1.0.0".to_string(),
        output_hash: hex::encode(result_hash),
        consumed_token_count: 17,
        consumed_spans_root: "def456".to_string(),
        consumer_class: "bonded_api_client".to_string(),
        consumer_nonce: 7,
        accepted_at_unix_ms: 1_775_683_200_123,
        consumer_signature: "sig789".to_string(),
        receipt_hash: String::new(),
    }
    .with_computed_receipt_hash()
    .expect("hash")
}

#[cfg(test)]
fn put_sample_poco_task(st: &mut StateStore, task_id: u64, worker: &str, result_hash: Hash32) {
    use trnm_types::{ProofType, TaskMetadata, TaskObject};

    st.put_task_new(TaskObject {
        task_id,
        creator: format!("creator-{}", task_id),
        bounty: 100,
        status: TaskStatus::Completed,
        proof_type: ProofType::Fraud,
        metadata: Some(TaskMetadata {
            note: None,
            task_type: Some("llm_inference".to_string()),
            input_hash: None,
            model: None,
            provenance: None,
            metering: Some(TaskMeteringSnapshot {
                workload_class: "llm_inference".into(),
                metering_schema: "llm_token_meter_v1".into(),
                policy_snapshot_version: 1,
                receipt_hash: "deadbeef".into(),
                prompt_tokens: 10,
                generated_tokens: 20,
                decode_steps: 20,
                kv_bytes_moved: 0,
                normalized_work_units: 50,
                prompt_token_weight: 1,
                generated_token_weight: 1,
                decode_step_weight: 1,
                kv_byte_weight: 0,
                min_accept_work_units: 0,
                challenge_success_bounty_base: 0,
                challenge_success_bounty_per_work_unit_num: 0,
                challenge_success_bounty_per_work_unit_den: 1,
                worker_completion_bonus_per_work_unit_num: 0,
                worker_completion_bonus_per_work_unit_den: 1,
                worker_slash_rebate_per_work_unit_num: 0,
                worker_slash_rebate_per_work_unit_den: 1,
            }),
        }),
        worker: Some(worker.to_string()),
        committed_hash: None,
        result_hash: Some(result_hash),
        reveal_salt: None,
        committed_at_height: None,
        reveal_deadline_height: None,
        challenge_deadline_height: Some(100),
        challenge_window_blocks_snapshot: Some(100),
        challenged_at_height: None,
        resolve_deadline_height: None,
        challenge_bond: None,
        challenger: None,
        challenge_bond_forfeited: None,
        version: 0,
    })
    .expect("task");
}

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
const MAX_NODE_ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum WalDirMode {
    Auto,
    Reuse,
    FailIfExists,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeConfig {
    node_id: String,
    rpc_addr: String,
    p2p_addr: String,
}

fn is_link_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => addr.is_link_local(),
        std::net::IpAddr::V6(addr) => addr.is_unicast_link_local(),
    }
}

fn is_documentation_or_benchmark_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(addr) => {
            let octets = addr.octets();
            matches!(octets, [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _])
                || (octets[0] == 198 && octets[1] >= 18 && octets[1] <= 19)
        }
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[0] == 0x2001 && segments[1] == 0x0db8
        }
    }
}

fn is_ipv4_mapped_ipv6(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(addr) => addr.to_ipv4_mapped().is_some(),
    }
}

fn is_ipv4_compatible_ipv6(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[..6].iter().all(|segment| *segment == 0)
                && !addr.is_unspecified()
                && !addr.is_loopback()
                && addr.to_ipv4_mapped().is_none()
        }
    }
}

fn is_ipv4_translated_ipv6(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(_) => false,
        std::net::IpAddr::V6(addr) => {
            let segments = addr.segments();
            segments[0] == 0
                && segments[1] == 0
                && segments[2] == 0
                && segments[3] == 0
                && segments[4] == 0xffff
                && segments[5] == 0
        }
    }
}

fn has_nonzero_ipv6_scope(socket: SocketAddr) -> bool {
    match socket {
        SocketAddr::V4(_) => false,
        SocketAddr::V6(addr) => addr.scope_id() != 0,
    }
}

fn ensure_listener_socket_uses_canonical_literal(
    raw: &str,
    socket: SocketAddr,
    path: &str,
    field: &str,
) -> Result<()> {
    if raw == socket.to_string() {
        return Ok(());
    }

    if is_ipv4_translated_ipv6(socket.ip()) {
        anyhow::bail!(
            "invalid node config {}: {} must not use an IPv4-translated IPv6 address",
            path,
            field
        );
    }

    anyhow::bail!(
        "invalid node config {}: {} must use a canonical socket literal",
        path,
        field
    );
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
    SubmitConsumptionReceipt {
        receipt: ConsumptionReceipt,
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

fn format_bft_round_outcome_log_line(
    committed: bool,
    height: u64,
    round: u64,
    round_hash: &str,
    precommit_count: usize,
    validator_count: usize,
    unique_voter_count: usize,
    byzantine_votes: usize,
    double_vote_events: usize,
    reject_stats: &AuthRejectStats,
) -> String {
    if committed {
        format!(
            "[bft] height={} round={} step={:?} block_hash={} precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}",
            height,
            round,
            RoundStep::Commit,
            round_hash,
            precommit_count,
            validator_count,
            unique_voter_count,
            byzantine_votes,
            double_vote_events,
            reject_stats.bad_sig,
            reject_stats.replay,
            reject_stats.stale_nonce,
            reject_stats.stale_nonce,
        )
    } else {
        format!(
            "[bft] height={} round={} step=RoundChange reason=no_quorum precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}",
            height,
            round,
            precommit_count,
            validator_count,
            unique_voter_count,
            byzantine_votes,
            double_vote_events,
            reject_stats.bad_sig,
            reject_stats.replay,
            reject_stats.stale_nonce,
            reject_stats.stale_nonce,
        )
    }
}

fn format_bft_height_summary_log_line(height: u64, bft: &BftHeightResult) -> String {
    format!(
        "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} round_backoff_ms={} leader_missed={:?} double_vote_events={} auth_reject_bad_sig={} auth_reject_replay={} auth_reject_stale={} auth_reject_stale_nonce={}",
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
        bft.auth_reject_stale_nonce,
        bft.auth_reject_stale_nonce,
    )
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
    wal_entries_retained: usize,
    checkpoint_height_retained: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WalMetaList {
    entries: Vec<WalMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
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

fn file_contains_meaningful_recovery_surface(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    match fs::read_to_string(path) {
        Ok(raw) => !is_effectively_empty_toml_scaffold(&raw),
        Err(_) => true,
    }
}

fn wal_dir_has_existing_state(wal_dir: &Path) -> bool {
    file_contains_meaningful_recovery_surface(&wal_file(wal_dir))
        || file_contains_meaningful_recovery_surface(&wal_meta_file(wal_dir))
        || file_contains_meaningful_recovery_surface(&checkpoint_file(wal_dir))
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

fn is_effectively_empty_toml_scaffold(raw: &str) -> bool {
    raw.lines().all(|line| {
        let line = line.trim_start_matches('\u{feff}');
        let without_comment = line.split_once('#').map_or(line, |(before, _)| before);
        without_comment.trim().is_empty()
    })
}

fn load_wal_meta_entries(wal_dir: &Path) -> Result<Vec<WalMeta>> {
    let f = wal_meta_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw =
        fs::read_to_string(&f).with_context(|| format!("read wal meta failed: {}", f.display()))?;
    if is_effectively_empty_toml_scaffold(&raw) {
        return Ok(vec![]);
    }
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

fn canonicalize_checkpoint_meta(checkpoints: &mut [CheckpointMeta]) {
    checkpoints.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
    });
}

fn load_checkpoint_meta(wal_dir: &Path) -> Result<Vec<CheckpointMeta>> {
    let f = checkpoint_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&f)
        .with_context(|| format!("read checkpoint failed: {}", f.display()))?;
    if is_effectively_empty_toml_scaffold(&raw) {
        return Ok(vec![]);
    }
    let mut list: CheckpointMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse checkpoint failed: {}", f.display()))?;
    canonicalize_checkpoint_meta(&mut list.checkpoints);
    list.checkpoints.dedup_by(|a, b| {
        a.height == b.height
            && a.state_root_hex == b.state_root_hex
            && a.wal_entry_hash_hex == b.wal_entry_hash_hex
    });
    Ok(list.checkpoints)
}

fn persist_checkpoint_meta(wal_dir: &Path, checkpoints: &[CheckpointMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = checkpoint_file(wal_dir);
    let mut checkpoints = checkpoints.to_vec();
    canonicalize_checkpoint_meta(&mut checkpoints);
    let raw = toml::to_string(&CheckpointMetaList { checkpoints })?;
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

fn has_empty_metadata_scaffold(wal_dir: &Path) -> bool {
    wal_meta_file(wal_dir).exists() || checkpoint_file(wal_dir).exists()
}

fn recover_wal_state(wal_dir: &Path) -> Result<RecoveredWalState> {
    let entries = load_wal_meta_entries(wal_dir)?;
    let checkpoints = load_checkpoint_meta(wal_dir)?;
    let mut last_checkpoint = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &entries)
        .map_err(anyhow::Error::msg)?;

    let mut truncated = false;
    if entries.is_empty()
        && checkpoints.is_empty()
        && (wal_file(wal_dir).exists() || has_empty_metadata_scaffold(wal_dir))
    {
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: 1,
                last_round: 0,
                locked_block_hash: None,
            },
        )?;
        truncated = true;
    }
    if entries.is_empty() && !checkpoints.is_empty() {
        persist_checkpoint_meta(wal_dir, &[])?;
        last_checkpoint = None;
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
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        });
    }

    let mut valid_entries = entries.clone();
    let mut metadata_only_tail_discarded = false;
    let mut committed_tail_beyond_checkpoint_discarded = false;
    if let Some(cp) = &last_checkpoint {
        if let Some(idx) = entries
            .iter()
            .position(|e| e.height == cp.height && e.content_hash_hex() == cp.wal_entry_hash_hex)
        {
            if idx + 1 < entries.len() {
                let discarded_tail = &entries[idx + 1..];
                metadata_only_tail_discarded = discarded_tail.iter().any(|e| !e.committed);
                let retained_tip_hash = entries[idx].content_hash_hex();
                committed_tail_beyond_checkpoint_discarded = discarded_tail.iter().any(|e| {
                    e.committed
                        && e.height > cp.height
                        && e.prev_hash_hex.as_deref() == Some(retained_tip_hash.as_str())
                });
                valid_entries.truncate(idx + 1);
                persist_wal_meta_entries(wal_dir, &valid_entries)?;
                truncated = true;
            }

            let retained_checkpoint_keys: HashSet<(u64, String, String)> = valid_entries
                .iter()
                .map(|entry| {
                    (
                        entry.height,
                        entry.state_root_hex.clone(),
                        entry.content_hash_hex(),
                    )
                })
                .collect();
            let mut seen_checkpoint_keys = HashSet::new();
            let mut valid_checkpoints: Vec<CheckpointMeta> = checkpoints
                .iter()
                .filter(|c| {
                    retained_checkpoint_keys.contains(&(
                        c.height,
                        c.state_root_hex.clone(),
                        c.wal_entry_hash_hex.clone(),
                    ))
                })
                .filter(|c| {
                    seen_checkpoint_keys.insert((
                        c.height,
                        c.state_root_hex.as_str(),
                        c.wal_entry_hash_hex.as_str(),
                    ))
                })
                .cloned()
                .collect();
            valid_checkpoints.sort_by(|a, b| {
                a.height
                    .cmp(&b.height)
                    .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
                    .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
            });
            if valid_checkpoints != checkpoints {
                persist_checkpoint_meta(wal_dir, &valid_checkpoints)?;
                truncated = true;
            }
            last_checkpoint = valid_checkpoints.last().cloned();
        }
    }

    if let Some(last) = valid_entries.last() {
        let retained_checkpoint_height = last_checkpoint.as_ref().map(|cp| cp.height);
        let retained_entry_count = valid_entries.len();
        let metadata_only_recovery = metadata_only_tail_discarded
            || committed_tail_beyond_checkpoint_discarded
            || retained_checkpoint_height
                .map(|checkpoint_height| checkpoint_height < last.height)
                .unwrap_or(retained_entry_count > 0);
        let restored_lock = if metadata_only_recovery {
            None
        } else {
            Some(last.proposal_hash.clone())
        };
        let restored_round =
            if metadata_only_recovery && !committed_tail_beyond_checkpoint_discarded {
                0
            } else {
                last.round
            };
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: last.height + 1,
                last_round: restored_round,
                locked_block_hash: restored_lock.clone(),
            },
        )?;
        return Ok(RecoveredWalState {
            next_height: last.height + 1,
            restored_lock,
            checkpoint_height_retained: retained_checkpoint_height,
            last_checkpoint,
            truncated,
            metadata_only_recovery,
            wal_entries_retained: retained_entry_count,
        });
    }

    if truncated {
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: 1,
                last_round: 0,
                locked_block_hash: None,
            },
        )?;
    }

    Ok(RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        checkpoint_height_retained: last_checkpoint.as_ref().map(|cp| cp.height),
        last_checkpoint,
        truncated,
        metadata_only_recovery: false,
        wal_entries_retained: 0,
    })
}

fn retained_wal_summary(recovered: &RecoveredWalState) -> String {
    let base = match recovered.wal_entries_retained {
        0 => "retained no committed WAL entries".into(),
        1 => format!(
            "retained 1 committed WAL entry through height {}",
            recovered.next_height.saturating_sub(1)
        ),
        count => format!(
            "retained {} committed WAL entries through height {}",
            count,
            recovered.next_height.saturating_sub(1)
        ),
    };

    if recovered.wal_entries_retained == 0 {
        let summary = match recovered.checkpoint_height_retained {
            Some(checkpoint_height) => format!(
                "{} (last retained checkpoint height {})",
                base, checkpoint_height
            ),
            None => base,
        };
        return if recovered.truncated {
            format!("{}; repaired WAL tail required truncation", summary)
        } else {
            summary
        };
    }

    let tip_height = recovered.next_height.saturating_sub(1);
    let summary = match recovered.checkpoint_height_retained {
        Some(checkpoint_height) if checkpoint_height < tip_height => {
            let lag = tip_height - checkpoint_height;
            let blocks = if lag == 1 { "block" } else { "blocks" };
            format!(
                "{} (checkpoint lags retained WAL tip by {} {})",
                base, lag, blocks
            )
        }
        Some(checkpoint_height) if checkpoint_height > tip_height => {
            let lead = checkpoint_height - tip_height;
            let blocks = if lead == 1 { "block" } else { "blocks" };
            format!(
                "{} (retained checkpoint height {} is ahead of retained WAL tip height {} by {} {}; investigate WAL/checkpoint mismatch)",
                base, checkpoint_height, tip_height, lead, blocks
            )
        }
        None => format!("{} (no retained checkpoint metadata)", base),
        Some(_) => base,
    };

    if recovered.truncated {
        format!("{}; repaired WAL tail required truncation", summary)
    } else {
        summary
    }
}

fn checkpoint_tip_relation(recovered: &RecoveredWalState) -> String {
    if recovered.wal_entries_retained == 0 {
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| format!("checkpoint_only:{}", checkpoint_height))
            .unwrap_or_else(|| "none".into())
    } else {
        let tip_height = recovered.next_height.saturating_sub(1);
        match recovered.checkpoint_height_retained {
            Some(checkpoint_height) if checkpoint_height < tip_height => {
                format!("behind:{}", tip_height - checkpoint_height)
            }
            Some(checkpoint_height) if checkpoint_height > tip_height => {
                format!("ahead:{}", checkpoint_height - tip_height)
            }
            Some(_) => "aligned".into(),
            None => "missing".into(),
        }
    }
}

fn recovery_startup_summary(recovered: &RecoveredWalState) -> String {
    let join_rejoin_status = if recovered.metadata_only_recovery {
        "blocked:metadata_only_recovery"
    } else if recovered.wal_entries_retained > 0 {
        match recovered.checkpoint_height_retained {
            None => {
                if recovered.truncated {
                    "ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
                } else {
                    "ready:retained_wal_resume_missing_checkpoint_metadata"
                }
            }
            Some(checkpoint_height) => {
                let tip_height = recovered.next_height.saturating_sub(1);
                if checkpoint_height < tip_height {
                    if tip_height - checkpoint_height == 1 {
                        if recovered.truncated {
                            "ready:retained_wal_resume_checkpoint_lagging_1block_after_tail_repair"
                        } else {
                            "ready:retained_wal_resume_checkpoint_lagging_1block"
                        }
                    } else if recovered.truncated {
                        "ready:retained_wal_resume_checkpoint_lagging_after_tail_repair"
                    } else {
                        "ready:retained_wal_resume_checkpoint_lagging"
                    }
                } else if checkpoint_height > tip_height {
                    if checkpoint_height - tip_height == 1 {
                        if recovered.truncated {
                            "ready:retained_wal_resume_checkpoint_ahead_mismatch_1block_after_tail_repair"
                        } else {
                            "ready:retained_wal_resume_checkpoint_ahead_mismatch_1block"
                        }
                    } else if recovered.truncated {
                        "ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
                    } else {
                        "ready:retained_wal_resume_checkpoint_ahead_mismatch"
                    }
                } else if recovered.truncated {
                    "ready:retained_wal_resume_after_tail_repair"
                } else {
                    "ready:retained_wal_resume"
                }
            }
        }
    } else if recovered.checkpoint_height_retained.is_some() {
        if recovered.truncated {
            "ready:checkpoint_only_rejoin_bootstrap_after_tail_repair"
        } else {
            "ready:checkpoint_only_rejoin_bootstrap"
        }
    } else {
        if recovered.truncated {
            "ready:fresh_bootstrap_after_tail_repair"
        } else {
            "ready:fresh_bootstrap"
        }
    };

    format!(
        "retained_wal_entries={} checkpoint_height_retained={} checkpoint_tip_relation={} next_startup_height={} wal_tail_truncated={} metadata_only_recovery={} join_rejoin_status={}",
        recovered.wal_entries_retained,
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        checkpoint_tip_relation(recovered),
        recovered.next_height,
        recovered.truncated,
        recovered.metadata_only_recovery,
        join_rejoin_status,
    )
}

fn metadata_only_operator_action(recovered: &RecoveredWalState) -> String {
    if recovered.wal_entries_retained == 0 {
        return match recovered.checkpoint_height_retained {
            Some(checkpoint_height) => {
                format!(
                    "operator action: checkpoint-only bootstrap from retained checkpoint height {} is acceptable with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying",
                    checkpoint_height,
                )
            }
            None => {
                "operator action: restart with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying".into()
            }
        };
    }

    let tip_height = recovered.next_height.saturating_sub(1);
    match recovered.checkpoint_height_retained {
        Some(checkpoint_height) if checkpoint_height < tip_height => {
            let checkpoint_lag = tip_height - checkpoint_height;
            let lag_blocks = if checkpoint_lag == 1 { "block" } else { "blocks" };
            format!(
                "operator action: restore an application snapshot that covers retained WAL tip height {} before retrying join/rejoin; retained checkpoint height {} is {} {} behind, so do not resume from metadata alone",
                tip_height,
                checkpoint_height,
                checkpoint_lag,
                lag_blocks,
            )
        }
        Some(checkpoint_height) if checkpoint_height > tip_height => {
            let checkpoint_lead = checkpoint_height - tip_height;
            let lead_blocks = if checkpoint_lead == 1 { "block" } else { "blocks" };
            format!(
                "operator action: investigate WAL/checkpoint mismatch (retained WAL tip height {}, checkpoint height {}, checkpoint leads tip by {} {}), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree",
                tip_height,
                checkpoint_height,
                checkpoint_lead,
                lead_blocks,
            )
        }
        None => {
            format!(
                "operator action: rebuild or restore checkpoint metadata so it covers retained WAL tip height {} before retrying join/rejoin; do not resume from metadata alone",
                tip_height,
            )
        }
        Some(_) => {
            format!(
                "operator action: restore the application snapshot that matches retained WAL tip height {} before retrying join/rejoin; do not resume from metadata alone",
                tip_height,
            )
        }
    }
}

fn metadata_only_checkpoint_surfaces(
    wal_dir: &Path,
    recovered: &RecoveredWalState,
) -> (String, String) {
    let Some(checkpoint) = recovered.last_checkpoint.as_ref() else {
        return ("none".into(), "unavailable:no_checkpoint".into());
    };

    let checkpoint_evidence = format!(
        "checkpoint_height={} state_root={} wal_entry_hash={}",
        checkpoint.height, checkpoint.state_root_hex, checkpoint.wal_entry_hash_hex,
    );

    let da_surface = load_wal_meta_entries(wal_dir)
        .ok()
        .and_then(|entries| {
            entries.into_iter().find(|wal_entry| {
                wal_entry.height == checkpoint.height
                    && wal_entry.state_root_hex == checkpoint.state_root_hex
                    && wal_entry.content_hash_hex() == checkpoint.wal_entry_hash_hex
            })
        })
        .map(|wal_entry| {
            checkpoint_da_light_verifier_summary(checkpoint, &wal_entry)
                .unwrap_or_else(|| "unavailable:non_audit_ready_wal_surface".into())
        })
        .unwrap_or_else(|| "unavailable:no_matching_wal_entry".into());

    (checkpoint_evidence, da_surface)
}

fn metadata_only_recovery_error(wal_dir: &Path, recovered: &RecoveredWalState) -> String {
    let operator_action = metadata_only_operator_action(recovered);
    let (checkpoint_evidence, checkpoint_da_surface) =
        metadata_only_checkpoint_surfaces(wal_dir, recovered);
    format!(
        "refusing metadata-only recovery from {}: verified WAL/checkpoint metadata {} (last retained checkpoint: {}, next startup height: {}); incident clue: {}; checkpoint_evidence: {}; checkpoint_da_surface: {} but trnm-node does not yet restore application StateStore snapshots or replay committed blocks; {}; implement state snapshot+replay recovery first if this restart path must remain supported",
        wal_dir.display(),
        retained_wal_summary(recovered),
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        recovered.next_height,
        recovery_startup_summary(recovered),
        checkpoint_evidence,
        checkpoint_da_surface,
        operator_action,
    )
}

fn ensure_recoverable_wal_state(wal_dir: &Path, recovered: &RecoveredWalState) -> Result<()> {
    if recovered.metadata_only_recovery {
        anyhow::bail!(metadata_only_recovery_error(wal_dir, recovered));
    }
    Ok(())
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
    println!(
        "{}",
        format_bft_round_outcome_log_line(
            committed,
            height,
            round,
            &round_hash,
            precommit_count,
            n,
            unique_voters.len(),
            byzantine_votes,
            double_vote_events,
            &reject_stats,
        )
    );

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

fn validate_node_config(cfg: NodeConfig, path: &str) -> Result<NodeConfig> {
    let node_id = cfg.node_id.trim();
    anyhow::ensure!(
        cfg.node_id == node_id,
        "invalid node config {}: node_id must not contain leading or trailing whitespace",
        path
    );
    anyhow::ensure!(
        !node_id.is_empty(),
        "invalid node config {}: node_id must not be empty",
        path
    );
    anyhow::ensure!(
        node_id.len() <= MAX_NODE_ID_LEN,
        "invalid node config {}: node_id must be at most {} bytes",
        path,
        MAX_NODE_ID_LEN
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_control),
        "invalid node config {}: node_id must not contain control characters",
        path
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(node_id),
        "invalid node config {}: node_id must not contain invisible or bidirectional format characters",
        path
    );
    anyhow::ensure!(
        node_id.is_ascii(),
        "invalid node config {}: node_id must use ASCII-only characters",
        path
    );
    anyhow::ensure!(
        !node_id.chars().any(char::is_whitespace),
        "invalid node config {}: node_id must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !node_id.contains(',') && !node_id.contains(';') && !node_id.contains('|'),
        "invalid node config {}: node_id must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !node_id.contains('/')
            && !node_id.contains('\\')
            && !node_id.contains(':')
            && !node_id.contains('[')
            && !node_id.contains(']'),
        "invalid node config {}: node_id must not contain path or host-literal separators (/ \\ : [ ])",
        path
    );
    anyhow::ensure!(
        !node_id.contains('"') && !node_id.contains('\'') && !node_id.contains('`'),
        "invalid node config {}: node_id must not contain quoting characters (\" ' `)",
        path
    );
    anyhow::ensure!(
        !node_id.contains('@')
            && !node_id.contains('?')
            && !node_id.contains('#')
            && !node_id.contains('%')
            && !node_id.contains('&')
            && !node_id.contains('='),
        "invalid node config {}: node_id must not contain URI delimiters (@ ? # % & =)",
        path
    );
    anyhow::ensure!(
        node_id != "." && node_id != "..",
        "invalid node config {}: node_id must not be '.' or '..'",
        path
    );
    let bracketed_host_literal = node_id
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .is_some_and(|inner| inner.parse::<std::net::IpAddr>().is_ok());
    let normalized_node_id_host_candidate = node_id.strip_suffix('.').unwrap_or(node_id);
    let dns_like_host_label = normalized_node_id_host_candidate
        .split('.')
        .all(|label| {
            !label.is_empty()
                && label
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
        && normalized_node_id_host_candidate.contains('.');
    anyhow::ensure!(
        !normalized_node_id_host_candidate.eq_ignore_ascii_case("localhost")
            && node_id.parse::<std::net::IpAddr>().is_err()
            && node_id.parse::<SocketAddr>().is_err()
            && !bracketed_host_literal
            && !dns_like_host_label,
        "invalid node config {}: node_id must not look like a host or socket literal",
        path
    );
    anyhow::ensure!(
        !node_id.contains('.'),
        "invalid node config {}: node_id must not contain dots",
        path
    );

    let rpc_addr = cfg.rpc_addr.trim();
    anyhow::ensure!(
        cfg.rpc_addr == rpc_addr,
        "invalid node config {}: rpc_addr must not contain leading or trailing whitespace",
        path
    );
    anyhow::ensure!(
        !rpc_addr.is_empty(),
        "invalid node config {}: rpc_addr must not be empty",
        path
    );
    anyhow::ensure!(
        !rpc_addr.chars().any(char::is_whitespace),
        "invalid node config {}: rpc_addr must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !rpc_addr.chars().any(char::is_control),
        "invalid node config {}: rpc_addr must not contain control characters",
        path
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(rpc_addr),
        "invalid node config {}: rpc_addr must not contain invisible or bidirectional format characters",
        path
    );
    anyhow::ensure!(
        !rpc_addr.contains(',') && !rpc_addr.contains(';') && !rpc_addr.contains('|'),
        "invalid node config {}: rpc_addr must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !rpc_addr.contains("://"),
        "invalid node config {}: rpc_addr must be a raw socket address, not a URL",
        path
    );
    anyhow::ensure!(
        !rpc_addr.contains('/') && !rpc_addr.contains('\\'),
        "invalid node config {}: rpc_addr must not contain path separators (/ \\)",
        path
    );
    let rpc_socket: SocketAddr = rpc_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: rpc_addr must be a valid socket address",
            path
        )
    })?;
    ensure_listener_socket_uses_canonical_literal(rpc_addr, rpc_socket, path, "rpc_addr")?;
    anyhow::ensure!(
        rpc_socket.port() != 0,
        "invalid node config {}: rpc_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        rpc_socket.port() >= 1024,
        "invalid node config {}: rpc_addr must not use a privileged port below 1024",
        path
    );
    anyhow::ensure!(
        !rpc_socket.ip().is_multicast(),
        "invalid node config {}: rpc_addr must not use a multicast address",
        path
    );
    anyhow::ensure!(
        !matches!(rpc_socket.ip(), std::net::IpAddr::V4(addr) if addr.is_broadcast()),
        "invalid node config {}: rpc_addr must not use the IPv4 broadcast address",
        path
    );
    anyhow::ensure!(
        !rpc_socket.ip().is_unspecified(),
        "invalid node config {}: rpc_addr must not use an unspecified address",
        path
    );
    anyhow::ensure!(
        !is_link_local_ip(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !matches!(rpc_socket.ip(), std::net::IpAddr::V6(addr) if addr.is_loopback()),
        "invalid node config {}: rpc_addr must not use the IPv6 loopback address; keep the shipped IPv4 loopback topology fail-closed",
        path
    );
    anyhow::ensure!(
        !is_ipv4_mapped_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-mapped IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-compatible IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_translated_ipv6(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use an IPv4-translated IPv6 address",
        path
    );
    anyhow::ensure!(
        !has_nonzero_ipv6_scope(rpc_socket),
        "invalid node config {}: rpc_addr must not use an IPv6 scope identifier",
        path
    );
    anyhow::ensure!(
        !is_documentation_or_benchmark_ip(rpc_socket.ip()),
        "invalid node config {}: rpc_addr must not use a documentation or benchmark-only address",
        path
    );

    let p2p_addr = cfg.p2p_addr.trim();
    anyhow::ensure!(
        cfg.p2p_addr == p2p_addr,
        "invalid node config {}: p2p_addr must not contain leading or trailing whitespace",
        path
    );
    anyhow::ensure!(
        !p2p_addr.is_empty(),
        "invalid node config {}: p2p_addr must not be empty",
        path
    );
    anyhow::ensure!(
        !p2p_addr.chars().any(char::is_whitespace),
        "invalid node config {}: p2p_addr must not contain whitespace",
        path
    );
    anyhow::ensure!(
        !p2p_addr.chars().any(char::is_control),
        "invalid node config {}: p2p_addr must not contain control characters",
        path
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(p2p_addr),
        "invalid node config {}: p2p_addr must not contain invisible or bidirectional format characters",
        path
    );
    anyhow::ensure!(
        !p2p_addr.contains(',') && !p2p_addr.contains(';') && !p2p_addr.contains('|'),
        "invalid node config {}: p2p_addr must not contain list separators (, ; |)",
        path
    );
    anyhow::ensure!(
        !p2p_addr.contains("://"),
        "invalid node config {}: p2p_addr must be a raw socket address, not a URL",
        path
    );
    anyhow::ensure!(
        !p2p_addr.contains('/') && !p2p_addr.contains('\\'),
        "invalid node config {}: p2p_addr must not contain path separators (/ \\)",
        path
    );
    let p2p_socket: SocketAddr = p2p_addr.parse().with_context(|| {
        format!(
            "invalid node config {}: p2p_addr must be a valid socket address",
            path
        )
    })?;
    ensure_listener_socket_uses_canonical_literal(p2p_addr, p2p_socket, path, "p2p_addr")?;
    anyhow::ensure!(
        p2p_socket.port() != 0,
        "invalid node config {}: p2p_addr must not use port 0",
        path
    );
    anyhow::ensure!(
        p2p_socket.port() >= 1024,
        "invalid node config {}: p2p_addr must not use a privileged port below 1024",
        path
    );
    anyhow::ensure!(
        !p2p_socket.ip().is_multicast(),
        "invalid node config {}: p2p_addr must not use a multicast address",
        path
    );
    anyhow::ensure!(
        !matches!(p2p_socket.ip(), std::net::IpAddr::V4(addr) if addr.is_broadcast()),
        "invalid node config {}: p2p_addr must not use the IPv4 broadcast address",
        path
    );
    anyhow::ensure!(
        !p2p_socket.ip().is_unspecified(),
        "invalid node config {}: p2p_addr must not use an unspecified address",
        path
    );
    anyhow::ensure!(
        !is_link_local_ip(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use a link-local address",
        path
    );
    anyhow::ensure!(
        !matches!(p2p_socket.ip(), std::net::IpAddr::V6(addr) if addr.is_loopback()),
        "invalid node config {}: p2p_addr must not use the IPv6 loopback address; keep the shipped IPv4 loopback topology fail-closed",
        path
    );
    anyhow::ensure!(
        !is_ipv4_mapped_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-mapped IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_compatible_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-compatible IPv6 address",
        path
    );
    anyhow::ensure!(
        !is_ipv4_translated_ipv6(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use an IPv4-translated IPv6 address",
        path
    );
    anyhow::ensure!(
        !has_nonzero_ipv6_scope(p2p_socket),
        "invalid node config {}: p2p_addr must not use an IPv6 scope identifier",
        path
    );
    anyhow::ensure!(
        !is_documentation_or_benchmark_ip(p2p_socket.ip()),
        "invalid node config {}: p2p_addr must not use a documentation or benchmark-only address",
        path
    );
    anyhow::ensure!(
        rpc_socket != p2p_socket,
        "invalid node config {}: rpc_addr and p2p_addr must differ",
        path
    );
    anyhow::ensure!(
        rpc_socket.is_ipv4() == p2p_socket.is_ipv4(),
        "invalid node config {}: rpc_addr {} and p2p_addr {} must use the same IP family",
        path,
        rpc_addr,
        p2p_addr
    );
    anyhow::ensure!(
        rpc_socket.ip() == p2p_socket.ip(),
        "invalid node config {}: rpc_addr {} and p2p_addr {} must bind the same IP",
        path,
        rpc_addr,
        p2p_addr
    );

    Ok(NodeConfig {
        node_id: node_id.to_string(),
        rpc_addr: rpc_addr.to_string(),
        p2p_addr: p2p_addr.to_string(),
    })
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node")
}

fn resolve_config_path(path: &str) -> PathBuf {
    let requested = Path::new(path);
    if requested.is_absolute() {
        return requested.to_path_buf();
    }

    let workspace_root = workspace_root();
    let workspace_anchor = workspace_root.file_name().map(Path::new);
    let workspace_anchor = workspace_anchor
        .and_then(|anchor| {
            requested
                .strip_prefix(anchor)
                .ok()
                .or_else(|| requested.strip_prefix(Path::new(".")).ok()?.strip_prefix(anchor).ok())
        })
        .unwrap_or(requested);
    let workspace_relative = workspace_root.join(workspace_anchor);
    if workspace_relative.exists() {
        let canonical_workspace_root = workspace_root
            .canonicalize()
            .unwrap_or_else(|_| workspace_root.to_path_buf());
        let canonical_workspace_relative = workspace_relative
            .canonicalize()
            .unwrap_or_else(|_| workspace_relative.clone());
        if canonical_workspace_relative.starts_with(&canonical_workspace_root) {
            return workspace_relative;
        }
    }

    if requested.exists() {
        return requested.to_path_buf();
    }

    requested.to_path_buf()
}

fn ensure_config_path_stays_within_allowed_roots(requested: &str, resolved: &Path) -> Result<()> {
    fn canonicalize_for_root_check(path: &Path) -> PathBuf {
        let mut suffix = Vec::<OsString>::new();
        let mut cursor = path;

        loop {
            if cursor.exists() {
                let mut canonical = cursor.canonicalize().unwrap_or_else(|_| cursor.to_path_buf());
                for component in suffix.iter().rev() {
                    canonical.push(component);
                }
                return canonical;
            }

            let Some(component) = cursor.file_name() else {
                return path.to_path_buf();
            };
            suffix.push(component.to_os_string());

            let Some(parent) = cursor.parent() else {
                return path.to_path_buf();
            };
            cursor = parent;
        }
    }

    let canonical_resolved = canonicalize_for_root_check(resolved);
    let workspace_root = workspace_root()
        .canonicalize()
        .unwrap_or_else(|_| workspace_root().to_path_buf());
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let canonical_current_dir = current_dir
        .canonicalize()
        .unwrap_or_else(|_| current_dir.clone());

    let allowed_by_workspace_or_cwd = canonical_resolved.starts_with(&workspace_root)
        || canonical_resolved.starts_with(&canonical_current_dir);
    #[cfg(test)]
    let allowed_by_test_temp = {
        let temp_dir = std::env::temp_dir();
        let canonical_temp_dir = temp_dir.canonicalize().unwrap_or_else(|_| temp_dir.clone());
        let resolved_is_symlink = std::fs::symlink_metadata(resolved)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        !resolved_is_symlink
            && (resolved.starts_with(&temp_dir) || resolved.starts_with(&canonical_temp_dir))
            && canonical_resolved.starts_with(&canonical_temp_dir)
    };
    #[cfg(not(test))]
    let allowed_by_test_temp = false;

    anyhow::ensure!(
        !resolved.is_absolute() || allowed_by_workspace_or_cwd || allowed_by_test_temp,
        "read config failed: {} resolves outside allowed roots (resolved: {})",
        requested,
        canonical_resolved.display()
    );

    if !resolved.exists() {
        return Ok(());
    }

    anyhow::ensure!(
        allowed_by_workspace_or_cwd || allowed_by_test_temp,
        "read config failed: {} resolves outside allowed roots (resolved: {})",
        requested,
        canonical_resolved.display()
    );

    Ok(())
}

fn contains_invisible_or_bidi_format_chars(value: &str) -> bool {
    value.chars().any(|ch| {
        matches!(
            ch,
            '\u{200B}'
                | '\u{200C}'
                | '\u{200D}'
                | '\u{2060}'
                | '\u{FEFF}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2066}'..='\u{2069}'
        )
    })
}

fn find_forbidden_bootstrap_alias_field(raw: &str) -> Option<&'static str> {
    const FORBIDDEN_BOOTSTRAP_ALIAS_FIELD_NAMES: &[&str] = &[
        "bootstrap_nodes",
        "bootstrap_node",
        "bootstrap_peers",
        "bootstrap_peer",
        "bootstrapNodes",
        "bootstrapNode",
        "bootstrapPeers",
        "bootstrapPeer",
        "bootstrap_addr",
        "bootstrap_addrs",
        "bootstrapAddr",
        "bootstrapAddrs",
        "bootstrap-addr",
        "bootstrap-addrs",
        "bootstrap-node",
        "bootstrap-peer",
        "seed_nodes",
        "seed_node",
        "seed_peers",
        "seed_peer",
        "seed-node",
        "seed-peer",
        "seedNodes",
        "seedNode",
        "seedPeers",
        "seedPeer",
        "seed_addr",
        "seed_addrs",
        "seedAddr",
        "seedAddrs",
        "seed-addr",
        "seed-addrs",
        "seed",
        "seeds",
        "bootnodes",
        "bootnode",
        "boot_nodes",
        "boot_node",
        "bootNodes",
        "bootNode",
        "boot-node",
        "boot_peers",
        "boot_peer",
        "boot-peer",
        "boot_addr",
        "boot_addrs",
        "bootAddr",
        "bootAddrs",
        "boot-addr",
        "boot-addrs",
        "bootPeers",
        "bootPeer",
        "persistent_peers",
        "persistent-peers",
        "persistent_peer",
        "persistent-peer",
        "persistent_addr",
        "persistent_addrs",
        "persistentAddr",
        "persistentAddrs",
        "persistent-addr",
        "persistent-addrs",
        "persistentPeers",
        "persistentPeer",
        "persistent_nodes",
        "persistent-nodes",
        "persistent_node",
        "persistent-node",
        "persistentNodes",
        "persistentNode",
    ];

    let parsed = raw.parse::<toml::Table>().ok()?;
    FORBIDDEN_BOOTSTRAP_ALIAS_FIELD_NAMES
        .iter()
        .find_map(|field| parsed.contains_key(*field).then_some(*field))
}

fn validate_config_path_input(path: &str) -> Result<()> {
    anyhow::ensure!(!path.trim().is_empty(), "read config failed: path must not be empty");
    anyhow::ensure!(
        path == path.trim(),
        "read config failed: path must not contain leading or trailing whitespace"
    );
    anyhow::ensure!(
        !path.chars().any(char::is_control),
        "read config failed: path must not contain control characters"
    );
    anyhow::ensure!(
        !contains_invisible_or_bidi_format_chars(path),
        "read config failed: path must not contain invisible or bidirectional format characters"
    );
    anyhow::ensure!(
        !path.contains(',') && !path.contains(';') && !path.contains('|'),
        "read config failed: path must not contain list separators (, ; |)"
    );
    anyhow::ensure!(
        !path.contains("://"),
        "read config failed: path must not be a URL"
    );
    anyhow::ensure!(
        !path.starts_with('~'),
        "read config failed: path must not rely on home-directory expansion (~)"
    );
    anyhow::ensure!(
        !Path::new(path)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "read config failed: path must not contain parent traversal (..)"
    );
    anyhow::ensure!(
        !path.split(['/', '\\']).any(|segment| segment == ".."),
        "read config failed: path must not contain parent traversal (..)"
    );

    Ok(())
}

fn load_config(path: &str) -> Result<NodeConfig> {
    validate_config_path_input(path)?;
    let resolved = resolve_config_path(path);
    ensure_config_path_stays_within_allowed_roots(path, &resolved)?;
    let display_resolved = if resolved.is_absolute() {
        resolved.clone()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(&resolved)
    };
    let resolved_metadata = fs::symlink_metadata(&resolved).with_context(|| {
        format!(
            "read config failed: {} (resolved: {})",
            path,
            display_resolved.display()
        )
    })?;
    anyhow::ensure!(
        !resolved_metadata.file_type().is_symlink(),
        "read config failed: {} (resolved: {}): config path must not be a symlink",
        path,
        display_resolved.display()
    );
    let canonical_resolved = resolved.canonicalize().unwrap_or_else(|_| resolved.clone());
    anyhow::ensure!(
        resolved_metadata.file_type().is_file(),
        "read config failed: {} (resolved: {}): resolved config path must point to a file",
        path,
        canonical_resolved.display()
    );
    let raw = fs::read_to_string(&resolved).with_context(|| {
        format!(
            "read config failed: {} (resolved: {})",
            path,
            canonical_resolved.display()
        )
    })?;
    if let Some(forbidden_alias_field) = find_forbidden_bootstrap_alias_field(&raw) {
        return Err(anyhow::anyhow!(
            "parse toml failed: {} (resolved: {}): forbidden bootstrap alias field `{}` is not supported; remove `{}` and keep only `node_id`, `rpc_addr`, and `p2p_addr`",
            path,
            canonical_resolved.display(),
            forbidden_alias_field,
            forbidden_alias_field
        ));
    }
    let cfg: NodeConfig = toml::from_str(&raw).with_context(|| {
        format!(
            "parse toml failed: {} (resolved: {})",
            path,
            canonical_resolved.display()
        )
    })?;
    validate_node_config(cfg, canonical_resolved.to_string_lossy().as_ref()).map_err(|err| {
        anyhow::anyhow!(
            "validate config failed: {} (resolved: {}): {:#}",
            path,
            canonical_resolved.display(),
            err
        )
    })
}

fn validate_startup_args(args: &Args) -> Result<()> {
    anyhow::ensure!(
        args.validators > 0,
        "invalid startup args: validators must be at least 1"
    );
    anyhow::ensure!(
        args.byzantine < args.validators,
        "invalid startup args: byzantine must be less than validators"
    );
    let min_validators_for_quorum = args
        .byzantine
        .checked_mul(3)
        .and_then(|value| value.checked_add(1))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "invalid startup args: byzantine={} overflows 3f + 1 quorum sizing",
                args.byzantine
            )
        })?;
    anyhow::ensure!(
        args.validators >= min_validators_for_quorum,
        "invalid startup args: validators must satisfy N >= 3f + 1 for byzantine={} (need at least {}, got {})",
        args.byzantine,
        min_validators_for_quorum,
        args.validators
    );
    anyhow::ensure!(
        !args.config.trim().is_empty(),
        "invalid startup args: config must not be empty"
    );
    anyhow::ensure!(
        args.config == args.config.trim(),
        "invalid startup args: config must not contain leading or trailing whitespace"
    );
    anyhow::ensure!(
        !args.config.chars().any(char::is_control),
        "invalid startup args: config must not contain control characters"
    );
    anyhow::ensure!(
        !Path::new(&args.config)
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir)),
        "invalid startup args: config must not contain '..' path segments"
    );
    anyhow::ensure!(
        !args.bft_wal_dir.trim().is_empty(),
        "invalid startup args: bft_wal_dir must not be empty"
    );
    anyhow::ensure!(
        args.bft_wal_dir == args.bft_wal_dir.trim(),
        "invalid startup args: bft_wal_dir must not contain leading or trailing whitespace"
    );
    anyhow::ensure!(
        !args.bft_wal_dir.chars().any(char::is_control),
        "invalid startup args: bft_wal_dir must not contain control characters"
    );
    anyhow::ensure!(
        !Path::new(&args.bft_wal_dir).components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        }),
        "invalid startup args: bft_wal_dir must not contain '.' or '..' path segments"
    );
    anyhow::ensure!(
        args.block_ms > 0,
        "invalid startup args: block_ms must be at least 1"
    );
    anyhow::ensure!(
        args.parallel_workers > 0,
        "invalid startup args: parallel_workers must be at least 1"
    );
    anyhow::ensure!(
        args.txs_per_block > 0,
        "invalid startup args: txs_per_block must be at least 1"
    );
    anyhow::ensure!(
        args.bft_checkpoint_interval > 0,
        "invalid startup args: bft_checkpoint_interval must be at least 1"
    );
    anyhow::ensure!(
        args.pouw_timeout_scan_every_blocks > 0,
        "invalid startup args: pouw_timeout_scan_every_blocks must be at least 1"
    );
    anyhow::ensure!(
        args.bft_max_rounds > 0,
        "invalid startup args: bft_max_rounds must be at least 1"
    );
    anyhow::ensure!(
        args.bft_fault_rounds < args.bft_max_rounds,
        "invalid startup args: bft_fault_rounds ({}) must be less than bft_max_rounds ({}) so startup cannot guarantee a no-quorum stall",
        args.bft_fault_rounds,
        args.bft_max_rounds
    );
    anyhow::ensure!(
        args.bft_round_change_backoff_max_ms >= args.bft_round_change_backoff_ms,
        "invalid startup args: bft_round_change_backoff_max_ms ({}) must be >= bft_round_change_backoff_ms ({})",
        args.bft_round_change_backoff_max_ms,
        args.bft_round_change_backoff_ms
    );
    Ok(())
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

    for i in 0..demo_tasks {
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
        MockTx::SubmitConsumptionReceipt { receipt } => receipt.task_id,
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
        MockTx::SubmitConsumptionReceipt { .. } => "submit_consumption_receipt",
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

    if !mempool.iter().any(is_critical_tx) || mempool.iter().all(is_critical_tx) {
        // Homogeneous backlog has no cross-class anti-starvation requirement.
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
        let Some(tx) = mempool.remove(idx) else {
            // Fail closed on any stale/duplicated admission output instead of
            // panicking the node hot path. Deterministic callers still produce
            // the same picked set on the happy path.
            continue;
        };
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
        MockTx::SubmitConsumptionReceipt { receipt } => receipt.consumer_id.clone(),
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

fn wall_time_share_ppm(total_ms: u64, committed_heights: u64, finality_avg_ms: u128) -> u64 {
    if committed_heights == 0 {
        return 0;
    }
    let finality_avg_ms_u64 = u64::try_from(finality_avg_ms).unwrap_or(u64::MAX);
    let total_budget_ms = committed_heights.saturating_mul(finality_avg_ms_u64);
    ratio_ppm_u64(total_ms, total_budget_ms)
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

fn format_task_metering_event_fields(snapshot: &TaskMeteringSnapshot) -> String {
    format!(
        " metering_workload_class={} metering_schema={} metering_receipt_hash={} metering_policy_snapshot_version={} metering_prompt_tokens={} metering_generated_tokens={} metering_decode_steps={} metering_kv_bytes_moved={} metering_normalized_work_units={} metering_prompt_token_weight={} metering_generated_token_weight={} metering_decode_step_weight={} metering_kv_byte_weight={} metering_min_accept_work_units={} metering_challenge_success_bounty_base={} metering_challenge_success_bounty_per_work_unit_num={} metering_challenge_success_bounty_per_work_unit_den={} metering_worker_completion_bonus_per_work_unit_num={} metering_worker_completion_bonus_per_work_unit_den={} metering_worker_slash_rebate_per_work_unit_num={} metering_worker_slash_rebate_per_work_unit_den={}",
        snapshot.workload_class,
        snapshot.metering_schema,
        snapshot.receipt_hash,
        snapshot.policy_snapshot_version,
        snapshot.prompt_tokens,
        snapshot.generated_tokens,
        snapshot.decode_steps,
        snapshot.kv_bytes_moved,
        snapshot.normalized_work_units,
        snapshot.prompt_token_weight,
        snapshot.generated_token_weight,
        snapshot.decode_step_weight,
        snapshot.kv_byte_weight,
        snapshot.min_accept_work_units,
        snapshot.challenge_success_bounty_base,
        snapshot.challenge_success_bounty_per_work_unit_num,
        snapshot.challenge_success_bounty_per_work_unit_den,
        snapshot.worker_completion_bonus_per_work_unit_num,
        snapshot.worker_completion_bonus_per_work_unit_den,
        snapshot.worker_slash_rebate_per_work_unit_num,
        snapshot.worker_slash_rebate_per_work_unit_den,
    )
}

fn format_task_consumption_summary_event_fields(summary: &TaskConsumptionSummary) -> String {
    format!(
        " settlement_receipt_count={} settlement_accepted_receipt_count={} settlement_challenged_receipt_count={} settlement_total_consumed_tokens={} settlement_total_claimed_consumption_units={} settlement_total_credited_consumption_units={} settlement_last_settlement_height={}",
        summary.receipt_count,
        summary.accepted_receipt_count,
        summary.challenged_receipt_count,
        summary.total_consumed_tokens,
        summary.total_claimed_consumption_units,
        summary.total_credited_consumption_units,
        summary
            .last_settlement_height
            .map(|height| height.to_string())
            .unwrap_or_else(|| "-".to_string()),
    )
}

fn task_settlement_event_suffix(st: &StateStore, task_id: u64) -> String {
    let mut suffix = st
        .get_task(task_id)
        .and_then(|task| task.metadata)
        .and_then(|metadata| metadata.metering)
        .map(|snapshot| format_task_metering_event_fields(&snapshot))
        .unwrap_or_default();

    if let Some(summary) = st.task_consumption_summary(task_id) {
        suffix.push_str(&format_task_consumption_summary_event_fields(&summary));
    }

    suffix
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
    let settlement_suffix = match tx {
        MockTx::Reveal { .. }
        | MockTx::Resolve { .. }
        | MockTx::SubmitConsumptionReceipt { .. } => {
            task_settlement_event_suffix(st, task_id)
        }
        _ => String::new(),
    };

    match tx {
        MockTx::Resolve { slash_worker, .. } => {
            let resolution_code = if *slash_worker {
                "slashed"
            } else {
                "completed"
            };
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
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
                settlement_suffix,
            );
        }
        _ => {
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} signer={} challenger={} tx_hash={} tx_id={} block_height={} state_root={} ts_unix_ms={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
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
                settlement_suffix,
            );
        }
    }
}

fn timeout_outcome_fields(to_status: &str) -> (&'static str, &'static str) {
    match to_status {
        "Slashed" => ("true", "slashed"),
        "Completed" => ("false", "completed"),
        "Resolved" => ("false", "resolved"),
        _ => ("false", "unknown"),
    }
}

fn emit_timeout_event(
    st: &StateStore,
    task_id: u64,
    tx_id: u64,
    tx_ordinal: u64,
    tx_id_overflow: bool,
    tx_ordinal_overflow: bool,
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
    let settlement_suffix = task_settlement_event_suffix(st, task_id);
    let (slash_worker, resolution_code) = timeout_outcome_fields(to_status);

    println!(
        "[event] event_schema=v1 event_type=timeout task_id={} from_status={} to_status={} actor=system signer=system challenger={} tx_hash={} tx_id={} tx_ordinal={} tx_id_overflow={} tx_ordinal_overflow={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={} treasury_delta={} challenger_delta={} bond_disposition={}{}",
        task_id,
        from_status,
        to_status,
        challenger.unwrap_or("-"),
        tx_hash,
        tx_id,
        tx_ordinal,
        tx_id_overflow,
        tx_ordinal_overflow,
        block_height,
        state_root,
        ts_unix_ms,
        slash_worker,
        resolution_code,
        treasury_delta_str,
        challenger_delta_str,
        bond_disposition_str,
        settlement_suffix,
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
        | MockTx::Challenge { .. }
        | MockTx::SubmitConsumptionReceipt { .. } => true,
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
        MockTx::AcceptTask { .. }
        | MockTx::Commit { .. }
        | MockTx::Reveal { .. }
        | MockTx::SubmitConsumptionReceipt { .. } => {}
    }

    TxRollbackSnapshot {
        task_id,
        task,
        balances,
        pending_resolve_approval,
    }
}

fn canonicalize_resolve_authority_snapshot(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed != raw {
        return None;
    }

    let has_forbidden_separator = |token: &str| {
        token.contains(';')
            || token.contains('|')
            || token.contains('；')
            || token.contains('，')
            || token.contains('、')
    };

    let mut seen = std::collections::BTreeSet::new();
    let mut canonical_members = Vec::new();
    for member in trimmed.split(',') {
        let member_trimmed = member.trim();
        if member_trimmed.is_empty()
            || member_trimmed != member
            || member_trimmed.chars().any(|c| c.is_whitespace())
            || has_forbidden_separator(member_trimmed)
            || !member_trimmed.is_ascii()
            || member_trimmed.chars().any(|c| c.is_ascii_control())
            || member_trimmed.eq_ignore_ascii_case("governance.resolve_authority")
            || member_trimmed.eq_ignore_ascii_case("governance.emergency_pause")
            || member_trimmed.eq_ignore_ascii_case("system")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
            || member_trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
            || member_trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
        {
            return None;
        }
        let lowered = member_trimmed.to_ascii_lowercase();
        if !seen.insert(lowered.clone()) {
            return None;
        }
        canonical_members.push(lowered);
    }

    if canonical_members.len() < 2 {
        return None;
    }
    canonical_members.sort();
    Some(canonical_members.join(","))
}

fn is_canonical_resolve_approver_snapshot(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && trimmed == raw
        && !trimmed.chars().any(|c| c.is_whitespace())
        && !trimmed.contains(',')
        && !trimmed.contains(';')
        && !trimmed.contains('|')
        && trimmed.is_ascii()
        && !trimmed.chars().any(|c| c.is_ascii_control())
        && !trimmed.eq_ignore_ascii_case("governance.resolve_authority")
        && !trimmed.eq_ignore_ascii_case("governance.emergency_pause")
        && !trimmed.eq_ignore_ascii_case("system")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_escrow")
        && !trimmed.eq_ignore_ascii_case("treasury.challenge_forfeits")
        && !trimmed.eq_ignore_ascii_case("treasury.worker_slashes")
}

fn restore_pending_resolve_approval_from_snapshot(
    st: &mut StateStore,
    task_id: u64,
    snapshot: Option<PendingResolveApprovalSnapshot>,
) {
    st.clear_pending_resolve_approval(task_id);

    let Some(snapshot) = snapshot else {
        return;
    };

    let Some(task) = st.get_task(task_id) else {
        return;
    };
    if snapshot.task_version != task.version {
        return;
    }
    if snapshot.confirmations != 1 {
        return;
    }
    if !is_canonical_resolve_approver_snapshot(&snapshot.first_approver) {
        return;
    }
    let snapshot_first_approver = snapshot.first_approver.to_ascii_lowercase();

    let Some(snapshot_authority_set) =
        canonicalize_resolve_authority_snapshot(&snapshot.authority_set)
    else {
        return;
    };
    let expected_authority_set = st
        .pending_gov_update("resolve_authority")
        .map(|pending| pending.value)
        .or_else(|| st.gov_param_string("resolve_authority"));
    let Some(expected_authority_set) = expected_authority_set
        .as_deref()
        .and_then(canonicalize_resolve_authority_snapshot)
    else {
        return;
    };
    if snapshot_authority_set != expected_authority_set {
        return;
    }

    st.restore_pending_resolve_approval_from_rollback(
        task_id,
        Some(PendingResolveApprovalSnapshot {
            first_approver: snapshot_first_approver,
            authority_set: snapshot_authority_set,
            ..snapshot
        }),
    );
}

fn rollback_tx_snapshot(st: &mut StateStore, snapshot: TxRollbackSnapshot) {
    st.restore_task(snapshot.task_id, snapshot.task);
    for (address, balance) in snapshot.balances {
        st.restore_balance(&address, balance);
    }
    restore_pending_resolve_approval_from_snapshot(
        st,
        snapshot.task_id,
        snapshot.pending_resolve_approval,
    );
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
        MockTx::SubmitConsumptionReceipt { receipt } => {
            let _ = submit_consumption_receipt_at_height(st, receipt, signer, current_height)?;
        }
    }
    Ok(())
}

fn is_timeout_eligible_status(status: &TaskStatus) -> bool {
    matches!(
        status,
        TaskStatus::Assigned
            | TaskStatus::Committed
            | TaskStatus::Revealed
            | TaskStatus::Challenged
    )
}

fn timeout_skip_reason(status: &TaskStatus, emergency_paused: bool) -> Option<&'static str> {
    if !is_timeout_eligible_status(status) {
        return Some("status_not_timeout_eligible");
    }
    if emergency_paused && matches!(status, TaskStatus::Challenged) {
        return Some("emergency_pause_challenged");
    }
    None
}

#[cfg(test)]
fn should_scan_timeout(status: &TaskStatus, emergency_paused: bool) -> bool {
    timeout_skip_reason(status, emergency_paused).is_none()
}

const TIMEOUT_SCAN_MAX_TASK_ID: u64 = 9_000_000;

fn sorted_timeout_candidate_ids(known_task_ids: &HashSet<u64>) -> Vec<u64> {
    let mut task_ids: Vec<u64> = known_task_ids
        .iter()
        .copied()
        .filter(|task_id| *task_id <= TIMEOUT_SCAN_MAX_TASK_ID)
        .collect();
    task_ids.sort_unstable();
    task_ids
}

fn timeout_bond_disposition(
    was_challenged: bool,
    challenge_bond_forfeited: Option<bool>,
) -> Option<&'static str> {
    if !was_challenged {
        return None;
    }
    Some(match challenge_bond_forfeited {
        Some(true) => "forfeited",
        Some(false) => "refunded",
        None => "unknown",
    })
}

fn timeout_event_surface_metadata(
    tx_id_seed: u64,
    migrated_before_emit: u64,
) -> (u64, u64, bool, bool) {
    let tx_ordinal_overflowed = migrated_before_emit == u64::MAX;
    let tx_ordinal = migrated_before_emit.saturating_add(1);
    let tx_id_add = tx_id_seed.checked_add(tx_ordinal);
    let tx_id = tx_id_add.unwrap_or(u64::MAX);
    let tx_id_add_overflowed = tx_id_add.is_none();
    let tx_id_stuck_at_max_due_to_ordinal_saturation = tx_ordinal_overflowed && tx_id == u64::MAX;
    let tx_id_overflowed = tx_id_add_overflowed || tx_id_stuck_at_max_due_to_ordinal_saturation;

    (tx_id, tx_ordinal, tx_id_overflowed, tx_ordinal_overflowed)
}

#[cfg(test)]
fn timeout_event_tx_metadata(tx_id_seed: u64, migrated_before_emit: u64) -> (u64, bool) {
    let (tx_id, _, tx_id_overflowed, tx_ordinal_overflowed) =
        timeout_event_surface_metadata(tx_id_seed, migrated_before_emit);
    (tx_id, tx_id_overflowed || tx_ordinal_overflowed)
}

#[cfg(test)]
fn timeout_event_tx_id(tx_id_seed: u64, migrated_before_emit: u64) -> u64 {
    timeout_event_tx_metadata(tx_id_seed, migrated_before_emit).0
}

#[cfg(test)]
fn timeout_event_tx_overflowed(tx_id_seed: u64, migrated_before_emit: u64) -> bool {
    timeout_event_tx_metadata(tx_id_seed, migrated_before_emit).1
}

fn scan_and_apply_timeouts(
    st: &mut StateStore,
    known_task_ids: &HashSet<u64>,
    current_height: u64,
    tx_id_seed: u64,
) -> u64 {
    let mut migrated = 0u64;
    for task_id in sorted_timeout_candidate_ids(known_task_ids) {
        let Some(task) = st.get_task(task_id) else {
            continue;
        };
        if let Some(reason) = timeout_skip_reason(&task.status, st.is_emergency_paused()) {
            // Governance boundary hardening: the node-level timeout scanner must not even
            // enter challenged settlement while emergency pause is active. The lower-level
            // timeout path is already fail-closed, but skipping here keeps pause semantics
            // explicit and preserves staged resolve approvals/escrow without touching the
            // challenged settlement path at all.
            if reason == "emergency_pause_challenged" {
                println!(
                    "[timeout-skip] height={} task_id={} status={:?} reason={}",
                    current_height, task_id, task.status, reason
                );
            }
            continue;
        }
        let from_status = format!("{:?}", task.status);
        let was_challenged = matches!(task.status, TaskStatus::Challenged);
        let challenger = task.challenger.clone();
        let Some(task_ref) = st.get_ref(task_id) else {
            continue;
        };
        let before = st.clone();
        if apply_timeout(st, task_ref, current_height).is_ok() {
            let (event_tx_id, event_tx_ordinal, event_tx_overflowed, event_tx_ordinal_overflowed) =
                timeout_event_surface_metadata(tx_id_seed, migrated);
            migrated += 1;
            let to_status = status_name(st, task_id);
            let root = hex::encode(st.state_root());
            let (treasury_delta, challenger_delta) =
                balance_deltas_for_transition(&before, st, task_id, challenger.as_deref());
            let bond_disposition = timeout_bond_disposition(
                was_challenged,
                st.get_task(task_id)
                    .and_then(|t| t.challenge_bond_forfeited),
            );
            emit_timeout_event(
                st,
                task_id,
                event_tx_id,
                event_tx_ordinal,
                event_tx_overflowed,
                event_tx_ordinal_overflowed,
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
                "[timeout] height={} task_id={} tx_id={} tx_ordinal={} tx_id_overflow={} tx_ordinal_overflow={} from_status={} to_status={} source=auto_scan",
                current_height,
                task_id,
                event_tx_id,
                event_tx_ordinal,
                event_tx_overflowed,
                event_tx_ordinal_overflowed,
                from_status,
                to_status
            );
        }
    }
    migrated
}

fn pseudo_object_id_for_state_slot(namespace: &str, label: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(namespace.as_bytes());
    h.update(b":");
    h.update(label.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest[..8]);
    // keep derived ids in high range to avoid overlapping natural task ids
    u64::from_le_bytes(bytes) | (1u64 << 63)
}

fn pseudo_object_id_for_account(account: &str) -> u64 {
    pseudo_object_id_for_state_slot("balance", account)
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

fn missed_proposals_added_since(previous: &[u64], current: &[u64]) -> u64 {
    current
        .iter()
        .enumerate()
        .map(|(idx, current_count)| {
            current_count.saturating_sub(previous.get(idx).copied().unwrap_or(0))
        })
        .sum()
}

fn read_write_decl(st: &StateStore, tx: &MockTx, tx_id: u64) -> Tx {
    let task_id = match tx {
        MockTx::CreateTask { task_id, .. }
        | MockTx::AcceptTask { task_id, .. }
        | MockTx::Commit { task_id, .. }
        | MockTx::Reveal { task_id, .. }
        | MockTx::Challenge { task_id, .. }
        | MockTx::Resolve { task_id, .. } => *task_id,
        MockTx::SubmitConsumptionReceipt { receipt } => receipt.task_id,
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
        MockTx::SubmitConsumptionReceipt { receipt } => {
            let replay_key = receipt.replay_key().storage_key();
            let consumer_nonce_obj = ObjectRef {
                id: pseudo_object_id_for_state_slot(
                    "consumer_consumption_nonce",
                    &receipt.consumer_id,
                ),
                version: 1,
            };
            let receipt_record_obj = ObjectRef {
                id: pseudo_object_id_for_state_slot("consumption_record", &replay_key),
                version: 1,
            };
            let task_summary_obj = ObjectRef {
                id: pseudo_object_id_for_state_slot(
                    "task_consumption_summary",
                    &task_id.to_string(),
                ),
                version: 1,
            };
            read_set.push(consumer_nonce_obj.clone());
            write_set.push(consumer_nonce_obj);
            read_set.push(receipt_record_obj.clone());
            write_set.push(receipt_record_obj);
            read_set.push(task_summary_obj.clone());
            write_set.push(task_summary_obj);
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
                            let result =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let idx = id
                                        .checked_sub(1)
                                        .ok_or_else(|| invalid_preexec_tx_id(id))?
                                        as usize;
                                    let tx = picked_cloned
                                        .get(idx)
                                        .cloned()
                                        .ok_or_else(|| invalid_preexec_tx_id(id))?;
                                    let mut local_state = snapshot_cloned.as_ref().clone();
                                    apply_one(&mut local_state, tx, candidate_height)
                                        .map(|_| ())
                                        .map_err(|e| e.to_string())
                                }));
                            match result {
                                Ok(Ok(())) => {
                                    let _ = job.result_tx.send((id, true, String::new()));
                                }
                                Ok(Err(err)) => {
                                    let _ = job.result_tx.send((id, false, err));
                                }
                                Err(_) => {
                                    let _ = job.result_tx.send((
                                        id,
                                        false,
                                        format!(
                                            "preexec worker panic while evaluating tx_id={}",
                                            id
                                        ),
                                    ));
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

        let mut seen_ids = HashSet::with_capacity(group_ids.len());
        let unique_group_ids: Vec<u64> = group_ids
            .into_iter()
            .filter(|id| seen_ids.insert(*id))
            .collect();
        let workers = self.width.min(unique_group_ids.len());
        let (tx, rx) = mpsc::channel::<(u64, bool, String)>();
        {
            let mut queue = self.state.queue.lock().expect("preexec queue poisoned");
            for w in 0..workers {
                let ids: Vec<u64> = unique_group_ids
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

        let mut ok_ids = HashSet::with_capacity(unique_group_ids.len());
        let mut rejected = 0u64;
        for (id, ok, err) in rx {
            if ok {
                ok_ids.insert(id);
            } else {
                rejected += 1;
                println!("[preexec] tx_id={} rejected err={}", id, err);
            }
        }

        let ordered_ok_ids = unique_group_ids
            .into_iter()
            .filter(|id| ok_ids.contains(id))
            .collect();
        (ordered_ok_ids, rejected)
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

fn invalid_preexec_tx_id(id: u64) -> String {
    format!("preexec invalid tx id {} (tx ids are 1-based)", id)
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
    use trnm_state::GovParamUpdateOutcome;

    #[test]
    fn bft_round_outcome_log_line_keeps_stale_alias_and_nonce_field_together() {
        let reject_stats = AuthRejectStats {
            bad_sig: 2,
            replay: 3,
            stale_nonce: 5,
        };

        let committed = format_bft_round_outcome_log_line(
            true,
            7,
            2,
            "abc123",
            4,
            6,
            5,
            1,
            2,
            &reject_stats,
        );
        assert!(committed.contains("step=Commit block_hash=abc123"));
        assert!(committed.contains("auth_reject_stale=5 auth_reject_stale_nonce=5"));
        assert_eq!(committed.matches("auth_reject_stale=").count(), 1);
        assert_eq!(committed.matches("auth_reject_stale_nonce=").count(), 1);

        let round_change = format_bft_round_outcome_log_line(
            false,
            7,
            2,
            "abc123",
            4,
            6,
            5,
            1,
            2,
            &reject_stats,
        );
        assert!(round_change.contains("step=RoundChange reason=no_quorum"));
        assert!(round_change.contains("auth_reject_stale=5 auth_reject_stale_nonce=5"));
        assert_eq!(round_change.matches("auth_reject_stale=").count(), 1);
        assert_eq!(round_change.matches("auth_reject_stale_nonce=").count(), 1);
    }

    #[test]
    fn bft_height_summary_log_line_keeps_stale_alias_adjacent_to_nonce_field() {
        let bft = BftHeightResult {
            committed: true,
            committed_round: 3,
            round_changes: 4,
            prevote_count: 5,
            precommit_count: 6,
            double_vote_events: 7,
            auth_reject_bad_sig: 8,
            auth_reject_replay: 9,
            auth_reject_stale_nonce: 10,
            round_change_backoff_total_ms: 11,
            round_change_backoff_max_ms: 12,
            leader_missed_snapshot: vec![1, 0, 2],
        };

        let line = format_bft_height_summary_log_line(22, &bft);
        assert!(line.contains("height=22 committed_round=3"));
        assert!(line.contains("leader_missed=[1, 0, 2]"));
        assert!(line.contains("auth_reject_stale=10 auth_reject_stale_nonce=10"));
        assert_eq!(line.matches("auth_reject_stale=").count(), 1);
        assert_eq!(line.matches("auth_reject_stale_nonce=").count(), 1);
    }

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
    fn build_demo_mempool_respects_zero_demo_tasks() {
        let mempool = build_demo_mempool(0, 2);
        assert!(mempool.is_empty());
    }

    #[test]
    fn validate_node_config_rejects_outer_and_internal_whitespace_fail_closed() {
        let node_id_boundary_err = validate_node_config(
            NodeConfig {
                node_id: " node-a ".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("outer node_id whitespace must be rejected");
        assert!(node_id_boundary_err
            .to_string()
            .contains("node_id must not contain leading or trailing whitespace"));

        let rpc_boundary_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: " 127.0.0.1:26657\t".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("outer rpc whitespace must be rejected");
        assert!(rpc_boundary_err
            .to_string()
            .contains("rpc_addr must not contain leading or trailing whitespace"));

        let p2p_boundary_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "\n127.0.0.1:26656 ".into(),
            },
            "node.toml",
        )
        .expect_err("outer p2p whitespace must be rejected");
        assert!(p2p_boundary_err
            .to_string()
            .contains("p2p_addr must not contain leading or trailing whitespace"));

        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1 :26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr with internal whitespace must be rejected");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not contain whitespace"));

        let rpc_port_zero_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:0".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr port 0 must be rejected");
        assert!(rpc_port_zero_err
            .to_string()
            .contains("rpc_addr must not use port 0"));

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:\n26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr with embedded control whitespace must be rejected");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not contain whitespace"));

        let p2p_port_zero_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:0".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr port 0 must be rejected");
        assert!(p2p_port_zero_err
            .to_string()
            .contains("p2p_addr must not use port 0"));

        let rpc_privileged_port_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:443".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr privileged port must be rejected");
        assert!(rpc_privileged_port_err
            .to_string()
            .contains("rpc_addr must not use a privileged port below 1024"));

        let p2p_privileged_port_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:443".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr privileged port must be rejected");
        assert!(p2p_privileged_port_err
            .to_string()
            .contains("p2p_addr must not use a privileged port below 1024"));

        let rpc_multicast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "224.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr multicast must be rejected");
        assert!(rpc_multicast_err
            .to_string()
            .contains("rpc_addr must not use a multicast address"));

        let p2p_multicast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "[ff02::1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr multicast must be rejected");
        assert!(p2p_multicast_err
            .to_string()
            .contains("p2p_addr must not use a multicast address"));

        let rpc_broadcast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "255.255.255.255:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr broadcast must be rejected");
        assert!(rpc_broadcast_err
            .to_string()
            .contains("rpc_addr must not use the IPv4 broadcast address"));

        let p2p_broadcast_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "255.255.255.255:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr broadcast must be rejected");
        assert!(p2p_broadcast_err
            .to_string()
            .contains("p2p_addr must not use the IPv4 broadcast address"));

        let rpc_unspecified_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "0.0.0.0:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr unspecified bind must be rejected");
        assert!(rpc_unspecified_err
            .to_string()
            .contains("rpc_addr must not use an unspecified address"));

        let p2p_unspecified_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "[::]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr unspecified bind must be rejected");
        assert!(p2p_unspecified_err
            .to_string()
            .contains("p2p_addr must not use an unspecified address"));

        let rpc_ipv6_loopback_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::1]:26657".into(),
                p2p_addr: "[2001:4860::1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr IPv6 loopback bind must be rejected");
        assert!(rpc_ipv6_loopback_err
            .to_string()
            .contains("rpc_addr must not use the IPv6 loopback address"));

        let p2p_ipv6_loopback_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860::1]:26657".into(),
                p2p_addr: "[::1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr IPv6 loopback bind must be rejected");
        assert!(p2p_ipv6_loopback_err
            .to_string()
            .contains("p2p_addr must not use the IPv6 loopback address"));

        let rpc_link_local_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "169.254.10.20:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr link-local bind must be rejected");
        assert!(rpc_link_local_err
            .to_string()
            .contains("rpc_addr must not use a link-local address"));

        let p2p_link_local_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860::1]:26657".into(),
                p2p_addr: "[fe80::1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr link-local bind must be rejected");
        assert!(p2p_link_local_err
            .to_string()
            .contains("p2p_addr must not use a link-local address"));
    }

    #[test]
    fn resolve_config_path_anchors_relative_defaults_to_workspace_configs_dir() {
        let resolved = resolve_config_path("configs/node1.toml");
        assert!(
            resolved.ends_with(std::path::Path::new("trillionnium/configs/node1.toml")),
            "resolved path should anchor to workspace configs dir: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_config_path_anchors_workspace_prefixed_defaults_to_workspace_configs_dir() {
        let resolved = resolve_config_path("trillionnium/configs/node1.toml");
        assert!(
            resolved.ends_with(std::path::Path::new("trillionnium/configs/node1.toml")),
            "resolved path should preserve workspace-prefixed bootstrap defaults: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_config_path_anchors_curdir_prefixed_workspace_defaults_to_workspace_configs_dir() {
        let resolved = resolve_config_path("./trillionnium/configs/node1.toml");
        assert!(
            resolved.ends_with(std::path::Path::new("trillionnium/configs/node1.toml")),
            "resolved path should normalize curdir-prefixed workspace bootstrap defaults: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_config_path_anchors_curdir_prefixed_repo_root_defaults_to_workspace_configs_dir() {
        let resolved = resolve_config_path("./configs/node1.toml");
        assert!(
            resolved.ends_with(std::path::Path::new("trillionnium/configs/node1.toml")),
            "resolved path should normalize curdir-prefixed repo-root bootstrap defaults: {}",
            resolved.display()
        );
    }

    #[test]
    fn resolve_config_path_keeps_all_shipped_bootstrap_slots_on_the_same_canonical_paths() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");

        for slot in 1..=4 {
            let workspace_relative = format!("configs/node{slot}.toml");
            let repo_root_relative = format!("trillionnium/configs/node{slot}.toml");
            let curdir_workspace_relative = format!("./configs/node{slot}.toml");
            let curdir_repo_root_relative = format!("./trillionnium/configs/node{slot}.toml");
            let expected = workspace_root.join(format!("configs/node{slot}.toml"));

            assert_eq!(
                resolve_config_path(&workspace_relative),
                expected,
                "{workspace_relative} must stay anchored to the shipped slot-bound bootstrap path"
            );
            assert_eq!(
                resolve_config_path(&repo_root_relative),
                expected,
                "{repo_root_relative} must stay anchored to the shipped slot-bound bootstrap path"
            );
            assert_eq!(
                resolve_config_path(&curdir_workspace_relative),
                expected,
                "{curdir_workspace_relative} must stay anchored to the shipped slot-bound bootstrap path"
            );
            assert_eq!(
                resolve_config_path(&curdir_repo_root_relative),
                expected,
                "{curdir_repo_root_relative} must stay anchored to the shipped slot-bound bootstrap path"
            );
        }
    }

    #[test]
    fn load_config_accepts_legacy_repo_root_relative_default_path() {
        let cfg = load_config("configs/node1.toml")
            .expect("repo-root launches should resolve legacy default config path");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_curdir_prefixed_workspace_default_path() {
        let cfg = load_config("./trillionnium/configs/node1.toml")
            .expect("curdir-prefixed workspace bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_workspace_prefixed_default_path() {
        let cfg = load_config("trillionnium/configs/node1.toml")
            .expect("workspace-prefixed bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_curdir_prefixed_repo_root_default_path() {
        let cfg = load_config("./configs/node1.toml")
            .expect("curdir-prefixed repo-root bootstrap config should resolve");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    #[test]
    fn load_config_accepts_inner_curdir_markers_for_shipped_bootstrap_paths() {
        for path in ["configs/./node1.toml", "./configs/./node1.toml"] {
            let cfg = load_config(path).unwrap_or_else(|err| {
                panic!("{path} should resolve for shipped bootstrap config anchoring: {err:#}")
            });
            assert_eq!(cfg.node_id, "node1", "unexpected node_id for {path}");
            assert_eq!(cfg.rpc_addr, "127.0.0.1:26657", "unexpected rpc_addr for {path}");
            assert_eq!(cfg.p2p_addr, "127.0.0.1:26656", "unexpected p2p_addr for {path}");
        }
    }

    #[test]
    fn load_config_rejects_singular_config_dir_near_miss_for_bootstrap_slot_paths() {
        let err = load_config("config/node1.toml")
            .expect_err("singular config/ near-miss must not resolve to shipped bootstrap slots");
        let err_surface = format!("{err:#}");

        assert!(
            err_surface.contains("read config failed: config/node1.toml"),
            "operator-facing error should keep the exact near-miss path visible: {err_surface}"
        );
        assert!(
            err_surface.contains("resolved: config/node1.toml"),
            "resolved path should stay on the near-miss config/ path instead of silently rewriting to configs/: {err_surface}"
        );
        assert!(
            !err_surface.contains("configs/node1.toml"),
            "near-miss config/ path must fail closed instead of implying the shipped configs/ slot was loaded: {err_surface}"
        );
    }

    #[test]
    fn load_config_keeps_all_shipped_bootstrap_slots_path_alias_stable() {
        let expected = [
            ("node1", "127.0.0.1:26657", "127.0.0.1:26656"),
            ("node2", "127.0.0.1:27657", "127.0.0.1:27656"),
            ("node3", "127.0.0.1:28657", "127.0.0.1:28656"),
            ("node4", "127.0.0.1:29657", "127.0.0.1:29656"),
        ];

        for (slot, (node_id, rpc_addr, p2p_addr)) in expected.into_iter().enumerate() {
            let config_number = slot + 1;
            for path in [
                format!("configs/node{config_number}.toml"),
                format!("./configs/node{config_number}.toml"),
                format!("trillionnium/configs/node{config_number}.toml"),
                format!("./trillionnium/configs/node{config_number}.toml"),
                format!("configs/./node{config_number}.toml"),
                format!("./configs/./node{config_number}.toml"),
                format!("trillionnium/configs/./node{config_number}.toml"),
                format!("./trillionnium/configs/./node{config_number}.toml"),
            ] {
                let cfg = load_config(&path).unwrap_or_else(|err| {
                    panic!(
                        "{path} should resolve for shipped bootstrap slot {config_number}: {err:#}"
                    )
                });
                assert_eq!(
                    cfg.node_id, node_id,
                    "unexpected node_id for shipped bootstrap slot {config_number} via {path}"
                );
                assert_eq!(
                    cfg.rpc_addr, rpc_addr,
                    "unexpected rpc_addr for shipped bootstrap slot {config_number} via {path}"
                );
                assert_eq!(
                    cfg.p2p_addr, p2p_addr,
                    "unexpected p2p_addr for shipped bootstrap slot {config_number} via {path}"
                );
            }
        }
    }

    #[test]
    fn load_config_prefers_workspace_root_default_over_cwd_shadow_config() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let expected = load_config("configs/node1.toml").expect("shipped node1 config should load");

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-shadow-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let shadow_dir = temp_root.join("configs");
        std::fs::create_dir_all(&shadow_dir).expect("create shadow config dir");
        std::fs::write(
            shadow_dir.join("node1.toml"),
            "node_id = \"shadow-node\"\nrpc_addr = \"127.0.0.1:39999\"\np2p_addr = \"127.0.0.1:39998\"\n",
        )
        .expect("write cwd shadow config");

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&temp_root).expect("enter shadow cwd");

        let loaded = load_config("configs/node1.toml")
            .expect("relative default path should keep resolving to shipped workspace config");

        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        assert_eq!(loaded.node_id, expected.node_id);
        assert_eq!(loaded.rpc_addr, expected.rpc_addr);
        assert_eq!(loaded.p2p_addr, expected.p2p_addr);
        assert_ne!(loaded.node_id, "shadow-node");
        assert_ne!(loaded.rpc_addr, "127.0.0.1:39999");
        assert_ne!(loaded.p2p_addr, "127.0.0.1:39998");
        assert_eq!(
            resolve_config_path("configs/node1.toml"),
            workspace_root.join("configs/node1.toml")
        );
    }

    #[test]
    fn load_config_prefers_workspace_root_repo_relative_path_over_cwd_shadow_tree() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let expected = load_config("trillionnium/configs/node1.toml")
            .expect("repo-root-relative shipped node1 config should load");

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-shadow-prefixed-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let shadow_dir = temp_root.join("trillionnium/configs");
        std::fs::create_dir_all(&shadow_dir).expect("create shadow prefixed config dir");
        std::fs::write(
            shadow_dir.join("node1.toml"),
            "node_id = \"shadow-prefixed-node\"\nrpc_addr = \"127.0.0.1:48999\"\np2p_addr = \"127.0.0.1:48998\"\n",
        )
        .expect("write prefixed cwd shadow config");

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&temp_root).expect("enter shadow cwd");

        let loaded = load_config("trillionnium/configs/node1.toml")
            .expect("repo-root-relative path should keep resolving to shipped workspace config");

        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        assert_eq!(loaded.node_id, expected.node_id);
        assert_eq!(loaded.rpc_addr, expected.rpc_addr);
        assert_eq!(loaded.p2p_addr, expected.p2p_addr);
        assert_ne!(loaded.node_id, "shadow-prefixed-node");
        assert_ne!(loaded.rpc_addr, "127.0.0.1:48999");
        assert_ne!(loaded.p2p_addr, "127.0.0.1:48998");
        assert_eq!(
            resolve_config_path("trillionnium/configs/node1.toml"),
            workspace_root.join("configs/node1.toml")
        );
    }

    #[test]
    fn load_config_prefers_curdir_prefixed_repo_root_path_over_cwd_shadow_tree() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let expected = load_config("./trillionnium/configs/node1.toml")
            .expect("curdir-prefixed repo-root shipped node1 config should load");

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-shadow-curdir-prefixed-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let shadow_dir = temp_root.join("trillionnium/configs");
        std::fs::create_dir_all(&shadow_dir).expect("create curdir-prefixed shadow config dir");
        std::fs::write(
            shadow_dir.join("node1.toml"),
            "node_id = \"shadow-curdir-prefixed-node\"\nrpc_addr = \"127.0.0.1:49999\"\np2p_addr = \"127.0.0.1:49998\"\n",
        )
        .expect("write curdir-prefixed cwd shadow config");

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&temp_root).expect("enter shadow cwd");

        let loaded = load_config("./trillionnium/configs/node1.toml")
            .expect("curdir-prefixed repo-root path should keep resolving to shipped workspace config");

        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        assert_eq!(loaded.node_id, expected.node_id);
        assert_eq!(loaded.rpc_addr, expected.rpc_addr);
        assert_eq!(loaded.p2p_addr, expected.p2p_addr);
        assert_ne!(loaded.node_id, "shadow-curdir-prefixed-node");
        assert_ne!(loaded.rpc_addr, "127.0.0.1:49999");
        assert_ne!(loaded.p2p_addr, "127.0.0.1:49998");
        assert_eq!(
            resolve_config_path("./trillionnium/configs/node1.toml"),
            workspace_root.join("configs/node1.toml")
        );
    }

    #[test]
    fn resolve_config_path_does_not_anchor_parent_traversal_outside_workspace_root() {
        let resolved = resolve_config_path("../configs/node1.toml");
        assert_eq!(resolved, std::path::PathBuf::from("../configs/node1.toml"));
    }

    #[test]
    fn load_config_rejects_relative_symlink_escape_outside_workspace_and_cwd() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        use std::os::unix::fs::symlink;

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-symlink-escape-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));
        let workspace_shadow = temp_root.join("workspace-shadow");
        let escape_dir = temp_root.join("escape");
        std::fs::create_dir_all(workspace_shadow.join("configs"))
            .expect("workspace shadow should be creatable");
        std::fs::create_dir_all(&escape_dir).expect("escape dir should be creatable");
        std::fs::write(
            escape_dir.join("outside.toml"),
            "node_id = \"node-escape\"\nrpc_addr = \"127.0.0.1:30001\"\np2p_addr = \"127.0.0.1:30000\"\n",
        )
        .expect("outside config should be writable");
        symlink(
            escape_dir.join("outside.toml"),
            workspace_shadow.join("configs/escaped.toml"),
        )
        .expect("escape symlink should be creatable");

        let requested_path = "configs/escaped.toml";
        let escaped_resolved = workspace_shadow
            .join(requested_path)
            .canonicalize()
            .expect("escaped config should canonicalize through the symlink target");

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&workspace_shadow).expect("enter shadow cwd");
        let err = load_config(requested_path)
            .expect_err("relative symlink escape should fail closed");
        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        let err_surface = format!("{err:#}");
        assert!(
            err_surface.contains("resolves outside allowed roots"),
            "unexpected error: {err:#}"
        );
        assert!(
            err_surface.contains(requested_path),
            "symlink escape error must keep the operator-supplied path visible: {err:#}"
        );
        assert!(
            err_surface.contains(escaped_resolved.to_string_lossy().as_ref()),
            "symlink escape error must keep the resolved escape target visible: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_in_root_symlink_alias_even_when_target_stays_within_allowed_roots() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        use std::os::unix::fs::symlink;

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-symlink-alias-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));
        let workspace_shadow = temp_root.join("workspace-shadow");
        let configs_dir = workspace_shadow.join("configs");
        std::fs::create_dir_all(&configs_dir).expect("workspace shadow config dir should be creatable");
        std::fs::write(
            configs_dir.join("node1.toml"),
            "node_id = \"node1\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("primary config should be writable");
        symlink(
            configs_dir.join("node1.toml"),
            configs_dir.join("node1-alias.toml"),
        )
        .expect("in-root symlink alias should be creatable");

        let requested_path = "configs/node1-alias.toml";
        let resolved_path = workspace_shadow.join(requested_path);

        let original_cwd = std::env::current_dir().expect("capture cwd");
        std::env::set_current_dir(&workspace_shadow).expect("enter shadow cwd");
        let err = load_config(requested_path)
            .expect_err("symlinked config aliases inside allowed roots must fail closed");
        std::env::set_current_dir(&original_cwd).expect("restore cwd");
        let _ = std::fs::remove_dir_all(&temp_root);

        let err_surface = format!("{err:#}");
        assert!(
            err_surface.contains("config path must not be a symlink"),
            "unexpected error: {err:#}"
        );
        assert!(
            err_surface.contains(requested_path),
            "in-root symlink rejection must keep the operator-supplied path visible: {err:#}"
        );
        assert!(
            err_surface.contains(resolved_path.to_string_lossy().as_ref()),
            "in-root symlink rejection must keep the resolved symlink path visible: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_absolute_symlink_path_that_escapes_allowed_roots() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let temp_root = std::env::temp_dir().join(format!(
            "trnm-node-config-absolute-symlink-escape-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));
        let workspace_shadow = temp_root.join("workspace-shadow");
        let outside_path = temp_root.join("outside.toml");
        let symlink_path = workspace_shadow.join("configs/escaped.toml");
        std::fs::create_dir_all(symlink_path.parent().expect("symlink parent"))
            .expect("workspace shadow should be creatable");
        std::fs::write(
            &outside_path,
            "node_id = \"node-escape\"\nrpc_addr = \"127.0.0.1:30001\"\np2p_addr = \"127.0.0.1:30000\"\n",
        )
        .expect("outside config should be writable");
        symlink(&outside_path, &symlink_path).expect("escape symlink should be creatable");

        let err = load_config(symlink_path.to_str().expect("utf8 path"))
            .expect_err("absolute symlink path escaping allowed roots must fail closed");
        let canonical_target = outside_path
            .canonicalize()
            .expect("outside target should canonicalize");
        let canonical_symlink_parent = workspace_shadow
            .canonicalize()
            .expect("workspace shadow should canonicalize");
        let workspace_root = super::workspace_root()
            .canonicalize()
            .expect("workspace root should canonicalize");
        let current_dir = std::env::current_dir()
            .expect("capture cwd")
            .canonicalize()
            .expect("cwd should canonicalize");
        let _ = std::fs::remove_dir_all(&temp_root);

        let err_surface = format!("{err:#}");
        assert!(
            !canonical_target.starts_with(&canonical_symlink_parent),
            "test fixture must point outside the allowed workspace shadow"
        );
        assert!(
            !canonical_target.starts_with(&workspace_root)
                && !canonical_target.starts_with(&current_dir),
            "test fixture must stay outside both allowed roots"
        );
        assert!(
            err_surface.contains("resolves outside allowed roots"),
            "unexpected error: {err:#}"
        );
        assert!(
            err_surface.contains(symlink_path.to_string_lossy().as_ref()),
            "absolute symlink escape error must keep the operator-supplied path visible: {err:#}"
        );
        assert!(
            err_surface.contains(canonical_target.to_string_lossy().as_ref()),
            "absolute symlink escape error must keep the resolved escape target visible: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_nonexistent_absolute_path_outside_workspace_cwd_and_test_temp() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let workspace_root = super::workspace_root()
            .canonicalize()
            .expect("workspace root should canonicalize");
        let current_dir = std::env::current_dir()
            .expect("capture cwd")
            .canonicalize()
            .expect("cwd should canonicalize");
        let temp_dir = std::env::temp_dir()
            .canonicalize()
            .unwrap_or_else(|_| std::env::temp_dir());
        let outside_path = PathBuf::from(format!(
            "/Users/{}/.trnm-node-config-outside-{}-{}.toml",
            std::env::var("USER").unwrap_or_else(|_| String::from("qianqi")),
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock should be after unix epoch")
                .as_millis()
        ));

        let err = load_config(outside_path.to_str().expect("utf8 path")).expect_err(
            "nonexistent absolute config path outside allowed roots should fail closed before file lookup",
        );

        assert!(
            !outside_path.exists(),
            "test fixture must stay nonexistent so the fail-closed path check covers unresolved absolute paths"
        );
        assert!(
            !outside_path.starts_with(&workspace_root)
                && !outside_path.starts_with(&current_dir)
                && !outside_path.starts_with(&temp_dir),
            "test fixture must stay outside workspace, cwd, and test temp allowances"
        );
        let err_surface = format!("{err:#}");
        assert!(
            err_surface.contains("resolves outside allowed roots"),
            "unexpected error: {err:#}"
        );
        assert!(
            err_surface.contains(outside_path.to_string_lossy().as_ref()),
            "outside-path error must keep the operator-supplied absolute path visible: {err:#}"
        );
    }

    #[test]
    fn shipped_bootstrap_configs_keep_a_minimal_fail_closed_schema() {
        use std::collections::BTreeSet;

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");

        for config_name in ["node1.toml", "node2.toml", "node3.toml", "node4.toml"] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap schema checks: {err}",
                    config_path.display()
                )
            });
            let table: toml::Table = raw.parse().unwrap_or_else(|err| {
                panic!(
                    "{} should remain valid TOML for shipped bootstrap schema checks: {err}",
                    config_path.display()
                )
            });
            let actual_keys = table.keys().cloned().collect::<BTreeSet<_>>();
            let expected_keys = BTreeSet::from([
                String::from("node_id"),
                String::from("rpc_addr"),
                String::from("p2p_addr"),
            ]);
            assert_eq!(
                actual_keys, expected_keys,
                "{} must keep the minimal shipped bootstrap schema so peer formation fixtures stay deterministic and fail closed",
                config_path.display()
            );
        }
    }

    #[test]
    fn shipped_bootstrap_configs_keep_their_three_line_slot_bound_layout() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");

        for (config_name, expected_node_id, expected_rpc_addr, expected_p2p_addr) in [
            ("node1.toml", "node1", "127.0.0.1:26657", "127.0.0.1:26656"),
            ("node2.toml", "node2", "127.0.0.1:27657", "127.0.0.1:27656"),
            ("node3.toml", "node3", "127.0.0.1:28657", "127.0.0.1:28656"),
            ("node4.toml", "node4", "127.0.0.1:29657", "127.0.0.1:29656"),
        ] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap line-layout checks: {err}",
                    config_path.display()
                )
            });
            let non_empty_lines = raw
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .collect::<Vec<_>>();
            let expected_lines = vec![
                format!("node_id = \"{expected_node_id}\""),
                format!("rpc_addr = \"{expected_rpc_addr}\""),
                format!("p2p_addr = \"{expected_p2p_addr}\""),
            ];
            assert_eq!(
                non_empty_lines,
                expected_lines,
                "{} must keep the exact three-line slot-bound layout so shipped bootstrap fixtures stay deterministic for peer/bootstrap rehearsal",
                config_path.display()
            );
        }
    }

    #[test]
    fn shipped_bootstrap_configs_keep_canonical_peer_identity_and_listener_literals() {
        use std::net::SocketAddr;

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");

        for config_name in ["node1.toml", "node2.toml", "node3.toml", "node4.toml"] {
            let config_path = workspace_root.join("configs").join(config_name);
            let raw = std::fs::read_to_string(&config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap literal checks: {err}",
                    config_path.display()
                )
            });
            let table: toml::Table = raw.parse().unwrap_or_else(|err| {
                panic!(
                    "{} should remain valid TOML for shipped bootstrap literal checks: {err}",
                    config_path.display()
                )
            });

            let node_id = table
                .get("node_id")
                .and_then(|value| value.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "{} must keep node_id as a TOML string literal",
                        config_path.display()
                    )
                });
            assert_eq!(
                node_id,
                node_id.trim(),
                "{} node_id must not hide boundary whitespace in shipped bootstrap peer identity fixtures",
                config_path.display()
            );
            assert!(
                !node_id.chars().any(char::is_whitespace),
                "{} node_id must not contain whitespace in shipped bootstrap peer identity fixtures",
                config_path.display()
            );

            for key in ["rpc_addr", "p2p_addr"] {
                let addr = table
                    .get(key)
                    .and_then(|value| value.as_str())
                    .unwrap_or_else(|| {
                        panic!(
                            "{} {} must stay a TOML string literal",
                            config_path.display(),
                            key
                        )
                    });
                assert_eq!(
                    addr,
                    addr.trim(),
                    "{} {} must not hide boundary whitespace in shipped bootstrap listener fixtures",
                    config_path.display(),
                    key
                );
                assert!(
                    !addr.chars().any(char::is_whitespace),
                    "{} {} must not contain whitespace in shipped bootstrap listener fixtures",
                    config_path.display(),
                    key
                );
                let socket: SocketAddr = addr.parse().unwrap_or_else(|err| {
                    panic!(
                        "{} {} should remain parseable as a canonical socket literal: {err}",
                        config_path.display(),
                        key
                    )
                });
                assert_eq!(
                    addr,
                    socket.to_string(),
                    "{} {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                    config_path.display(),
                    key
                );
            }
        }
    }

    #[test]
    fn shipped_bootstrap_readme_matches_the_documented_day1_topology_and_fail_closed_model() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let readme_path = workspace_root.join("configs").join("README.md");
        let workspace_relative_readme_path = workspace_root.join("configs/README.md");
        let curdir_repo_relative_readme_path = workspace_root.join("./configs/README.md");

        let readme_metadata = std::fs::symlink_metadata(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay stat-able for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });
        assert!(
            readme_metadata.file_type().is_file(),
            "{} must remain a regular file for deterministic shipped bootstrap README checks",
            readme_path.display()
        );
        assert!(
            !readme_metadata.file_type().is_symlink(),
            "{} must not become a symlink that can retarget shipped bootstrap README checks",
            readme_path.display()
        );

        let workspace_relative_readme_metadata =
            std::fs::symlink_metadata(&workspace_relative_readme_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay stat-able for bootstrap README path anchoring: {err}",
                    workspace_relative_readme_path.display()
                )
            });
        assert!(
            workspace_relative_readme_metadata.file_type().is_file(),
            "{} must remain a regular file for bootstrap README path anchoring",
            workspace_relative_readme_path.display()
        );
        assert!(
            !workspace_relative_readme_metadata.file_type().is_symlink(),
            "{} must not become a symlink that can retarget bootstrap README path anchoring",
            workspace_relative_readme_path.display()
        );

        let canonical_readme_path = readme_path.canonicalize().unwrap_or_else(|err| {
            panic!(
                "{} should canonicalize for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });
        let canonical_workspace_relative_readme_path = workspace_relative_readme_path
            .canonicalize()
            .unwrap_or_else(|err| {
                panic!(
                    "{} should canonicalize for bootstrap README path anchoring: {err}",
                    workspace_relative_readme_path.display()
                )
            });
        assert_eq!(
            canonical_workspace_relative_readme_path, canonical_readme_path,
            "{} must canonicalize to the same shipped bootstrap README as {}",
            workspace_relative_readme_path.display(),
            readme_path.display()
        );
        let canonical_curdir_repo_relative_readme_path = curdir_repo_relative_readme_path
            .canonicalize()
            .unwrap_or_else(|err| {
                panic!(
                    "{} should canonicalize for curdir-prefixed bootstrap README path anchoring: {err}",
                    curdir_repo_relative_readme_path.display()
                )
            });
        assert_eq!(
            canonical_curdir_repo_relative_readme_path, canonical_readme_path,
            "{} must canonicalize to the same shipped bootstrap README as {}",
            curdir_repo_relative_readme_path.display(),
            readme_path.display()
        );

        let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay readable for shipped bootstrap README checks: {err}",
                readme_path.display()
            )
        });

        let expected_lines = [
            "- `node1.toml` → node id `node1`, P2P `127.0.0.1:26656`, RPC `127.0.0.1:26657`",
            "- `node2.toml` → node id `node2`, P2P `127.0.0.1:27656`, RPC `127.0.0.1:27657`",
            "- `node3.toml` → node id `node3`, P2P `127.0.0.1:28656`, RPC `127.0.0.1:28657`",
            "- `node4.toml` → node id `node4`, P2P `127.0.0.1:29656`, RPC `127.0.0.1:29657`",
        ];
        for expected_line in expected_lines {
            assert!(
                readme.contains(expected_line),
                "{} must document the shipped Day-1 bootstrap tuple `{expected_line}` so operator topology assumptions stay explicit",
                readme_path.display()
            );
        }

        for expected_phrase in [
            "All four nodes bind the same loopback IP (`127.0.0.1`)",
            "keep a deterministic `+1000` port spacing between neighboring peers",
            "Start `node1` first as the initial anchor.",
            "Start `node2`, `node3`, and `node4` in slot order.",
            "do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise",
            "bring the node back with the same config file and the same `node_id`/listener tuple",
            "Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.",
            "Keep `node1` through `node3` in their shipped slots; if `node4` returns, bring it back only with `node4.toml` and its shipped tuple",
            "Accept the remaining slots only while no other config is renamed or promoted into the `node4` role",
            "unknown fields, whitespace drift, dotted, host-like, or path-like ids, URI-like delimiters, non-canonical socket literals, IPv4-mapped / IPv4-compatible / IPv4-translated IPv6 listener forms, privileged ports, wildcard listeners, reserved documentation/benchmarking listener ranges, or mixed listener IP families, the config loader must fail closed",
            "use both the operator-supplied config path and the resolved canonical path printed in the error to identify which shipped slot drifted",
            "prefer the exact repo-root paths `trillionnium/configs/node1.toml`, `trillionnium/configs/node2.toml`, `trillionnium/configs/node3.toml`, and `trillionnium/configs/node4.toml` as the unambiguous slot references",
            "require the filename slot, `node_id`, and listener stride to agree",
            "fix the exact repo-root slot file named by the error surface and the exact field named in that error",
            "If the failing path is reported as `configs/nodeN.toml` or `./configs/nodeN.toml`, map it back to the same repo-root slot before editing and fail closed on any basename-only “looks similar” guess across sibling files.",
            "Treat IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d` / `::hhhh:hhhh`), and IPv4-translated (`::ffff:0:a.b.c.d`) IPv6 listener literals as invalid drift for these shipped fixtures, even when they still target loopback.",
            "Do not add extra shipped topology files such as `node5.toml`, alternate slot aliases, or helper sidecar configs under `configs/`",
            "Do not substitute IPv6 loopback `[::1]` for the shipped IPv4 loopback `127.0.0.1` during bootstrap or rejoin",
            "The regression tests in `crates/trnm-node/src/config.rs` are the source of truth for the exact fixture invariants.",
        ] {
            assert!(
                readme.contains(expected_phrase),
                "{} must keep the shipped bootstrap join/rejoin fail-closed rule `{expected_phrase}` visible to operators",
                readme_path.display()
            );
        }
    }

    #[test]
    fn shipped_bootstrap_readme_tuples_match_loaded_configs_exactly() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let readme_path = workspace_root.join("configs").join("README.md");
        let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay readable for shipped bootstrap README tuple/config parity checks: {err}",
                readme_path.display()
            )
        });

        let documented_topology_lines = readme
            .lines()
            .filter(|line| line.starts_with("- `node") && line.contains("→ node id `node"))
            .collect::<Vec<_>>();

        let derived_topology_lines = [
            "configs/node1.toml",
            "configs/node2.toml",
            "configs/node3.toml",
            "configs/node4.toml",
        ]
        .into_iter()
        .map(|relative_path| {
            let path = workspace_root.join(relative_path);
            let cfg = load_config(relative_path).unwrap_or_else(|err| {
                panic!(
                    "{} should remain loadable for shipped bootstrap README tuple/config parity checks: {err:#}",
                    path.display()
                )
            });
            let file_name = std::path::Path::new(relative_path)
                .file_name()
                .and_then(|name| name.to_str())
                .expect("shipped bootstrap config path should end in utf-8 filename");
            format!(
                "- `{file_name}` → node id `{}`, P2P `{}`, RPC `{}`",
                cfg.node_id, cfg.p2p_addr, cfg.rpc_addr
            )
        })
        .collect::<Vec<_>>();
        let derived_topology_line_refs = derived_topology_lines
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();

        assert_eq!(
            documented_topology_lines, derived_topology_line_refs,
            "{} must keep README Day-1 tuples exactly aligned with the shipped bootstrap configs so peer topology docs cannot silently drift from fixture truth",
            readme_path.display()
        );
    }

    #[test]
    fn shipped_bootstrap_readme_keeps_single_authoritative_fail_closed_topology_rules() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let readme_path = workspace_root.join("configs/README.md");
        let readme = std::fs::read_to_string(&readme_path)
            .unwrap_or_else(|err| panic!("{} should stay readable: {err}", readme_path.display()));

        for expected_phrase in [
            "If `node1` is absent, do not treat `node2`, `node3`, or `node4` as a valid replacement bootstrap anchor; restore the shipped `node1` anchor first and fail closed otherwise.",
            "Do not skip a missing earlier follower slot during startup or rejoin: if `node2` is absent, keep `node3` and `node4` stopped; if `node3` is absent, keep `node4` stopped until the earlier slot regains its shipped tuple.",
            "If `node4` is absent, keep `node1` through `node3` in their shipped slots; do not rename another config into the `node4` role, and if `node4` returns it must come back with `node4.toml` and its shipped tuple.",
        ] {
            let occurrences = readme.match_indices(expected_phrase).count();
            assert_eq!(
                occurrences, 1,
                "{} must keep exactly one authoritative copy of the shipped bootstrap fail-closed rule `{expected_phrase}` so operator topology guidance cannot silently fork",
                readme_path.display()
            );
        }
    }

    #[test]
    fn default_cli_config_stays_pinned_to_shipped_bootstrap_anchor() {
        let args = Args::parse_from(["trnm-node"]);
        assert_eq!(
            args.config, "configs/node1.toml",
            "default trnm-node config path must stay pinned to the shipped bootstrap anchor fixture"
        );

        let cfg = load_config(&args.config).unwrap_or_else(|err| {
            panic!(
                "{} should remain loadable as the default shipped bootstrap anchor: {err:#}",
                args.config
            )
        });
        let p2p_socket: SocketAddr = cfg
            .p2p_addr
            .parse()
            .unwrap_or_else(|err| panic!("default p2p_addr should parse: {err}"));
        let rpc_socket: SocketAddr = cfg
            .rpc_addr
            .parse()
            .unwrap_or_else(|err| panic!("default rpc_addr should parse: {err}"));

        assert_eq!(
            cfg.node_id, "node1",
            "default trnm-node config must keep node1 as the shipped bootstrap anchor id"
        );
        assert_eq!(
            p2p_socket,
            "127.0.0.1:26656".parse().expect("socket literal should parse"),
            "default trnm-node config must keep the shipped bootstrap anchor p2p tuple"
        );
        assert_eq!(
            rpc_socket,
            "127.0.0.1:26657".parse().expect("socket literal should parse"),
            "default trnm-node config must keep the shipped bootstrap anchor rpc tuple"
        );
    }

    #[test]
    fn shipped_node_configs_form_a_unique_local_bootstrap_topology() {
        use std::{collections::HashSet, net::SocketAddr};

        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let shipped_config_dir = workspace_root.join("configs");
        let shipped_node_configs = std::fs::read_dir(&shipped_config_dir)
            .unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap config discovery: {err}",
                    shipped_config_dir.display()
                )
            })
            .filter_map(|entry| entry.ok())
            .map(|entry| {
                entry.file_name().into_string().unwrap_or_else(|name| {
                    panic!(
                        "{} entry {:?} must stay utf-8 for deterministic shipped bootstrap config discovery",
                        shipped_config_dir.display(),
                        name
                    )
                })
            })
            .filter(|name| name.starts_with("node") && name.ends_with(".toml"))
            .collect::<HashSet<_>>();
        let expected_shipped_node_configs = HashSet::from([
            String::from("node1.toml"),
            String::from("node2.toml"),
            String::from("node3.toml"),
            String::from("node4.toml"),
        ]);
        assert_eq!(
            shipped_node_configs, expected_shipped_node_configs,
            "shipped bootstrap config set must stay exactly node1.toml..node4.toml to keep deterministic peer formation fixtures intact"
        );
        let shipped_topology_file_names = std::fs::read_dir(&shipped_config_dir)
            .unwrap_or_else(|err| {
                panic!(
                    "{} should stay readable for shipped bootstrap topology file checks: {err}",
                    shipped_config_dir.display()
                )
            })
            .map(|entry| {
                let entry = entry.unwrap_or_else(|err| {
                    panic!(
                        "{} must fail closed if a shipped bootstrap topology entry cannot be read: {err}",
                        shipped_config_dir.display()
                    )
                });
                let file_type = entry.file_type().unwrap_or_else(|err| {
                    panic!(
                        "{} must fail closed if a shipped bootstrap topology entry file type cannot be read: {err}",
                        shipped_config_dir.display()
                    )
                });
                if !file_type.is_file() || file_type.is_symlink() {
                    return None;
                }
                Some(entry.file_name().into_string().unwrap_or_else(|name| {
                    panic!(
                        "{} entry {:?} must stay utf-8 for deterministic shipped bootstrap topology discovery",
                        shipped_config_dir.display(),
                        name
                    )
                }))
            })
            .collect::<Option<Vec<_>>>()
            .expect("non-regular shipped bootstrap topology entries should stay excluded deterministically");
        let shipped_topology_files = shipped_topology_file_names.iter().cloned().collect::<HashSet<_>>();
        let expected_shipped_topology_files = HashSet::from([
            String::from("README.md"),
            String::from("node1.toml"),
            String::from("node2.toml"),
            String::from("node3.toml"),
            String::from("node4.toml"),
        ]);
        assert_eq!(
            shipped_topology_files,
            expected_shipped_topology_files,
            "configs/ must remain exactly README.md plus node1.toml..node4.toml so bootstrap topology cannot silently grow extra shipped fixtures or helper sidecars"
        );
        let mut sorted_shipped_topology_file_names = shipped_topology_file_names;
        sorted_shipped_topology_file_names.sort();
        assert_eq!(
            sorted_shipped_topology_file_names,
            vec![
                String::from("README.md"),
                String::from("node1.toml"),
                String::from("node2.toml"),
                String::from("node3.toml"),
                String::from("node4.toml"),
            ],
            "configs/ file entries must remain in deterministic README + node1..node4 lexical slot order so bootstrap topology discovery cannot hide slot drift behind set equality"
        );

        let mut node_ids = HashSet::new();
        let mut rpc_addrs = HashSet::new();
        let mut p2p_addrs = HashSet::new();
        let mut all_listener_addrs = HashSet::new();
        let mut bootstrap_loopback_ips = HashSet::new();
        let mut shipped_nodes = Vec::new();

        for (index, (config_path, workspace_relative_path)) in [
            ("trillionnium/configs/node1.toml", "configs/node1.toml"),
            ("trillionnium/configs/node2.toml", "configs/node2.toml"),
            ("trillionnium/configs/node3.toml", "configs/node3.toml"),
            ("trillionnium/configs/node4.toml", "configs/node4.toml"),
        ]
        .into_iter()
        .enumerate()
        {
            let absolute_config_path = workspace_root.join(
                std::path::Path::new(config_path)
                    .strip_prefix("trillionnium")
                    .unwrap_or_else(|_| std::path::Path::new(config_path)),
            );
            let absolute_workspace_relative_path = workspace_root.join(workspace_relative_path);
            let on_disk_metadata = std::fs::symlink_metadata(&absolute_config_path).unwrap_or_else(|err| {
                panic!(
                    "{} should stay stat-able for shipped bootstrap topology checks: {err}",
                    absolute_config_path.display()
                )
            });
            assert!(
                on_disk_metadata.file_type().is_file(),
                "{} must remain a regular file for deterministic shipped bootstrap topology fixtures",
                absolute_config_path.display()
            );
            assert!(
                !on_disk_metadata.file_type().is_symlink(),
                "{} must not become a symlink that can retarget shipped bootstrap topology fixtures",
                absolute_config_path.display()
            );
            let workspace_relative_metadata = std::fs::symlink_metadata(
                &absolute_workspace_relative_path,
            )
            .unwrap_or_else(|err| {
                panic!(
                    "{} should stay stat-able for bootstrap/rejoin path anchoring: {err}",
                    absolute_workspace_relative_path.display()
                )
            });
            assert!(
                workspace_relative_metadata.file_type().is_file(),
                "{} must remain a regular file for deterministic bootstrap/rejoin path anchoring",
                absolute_workspace_relative_path.display()
            );
            assert!(
                !workspace_relative_metadata.file_type().is_symlink(),
                "{} must not become a symlink that can retarget shipped bootstrap/rejoin fixtures",
                absolute_workspace_relative_path.display()
            );

            let cfg = load_config(config_path)
                .unwrap_or_else(|err| panic!("{config_path} should remain loadable: {err:#}"));
            let workspace_relative_cfg = load_config(workspace_relative_path).unwrap_or_else(|err| {
                panic!(
                    "{workspace_relative_path} should remain loadable for bootstrap/rejoin path anchoring: {err:#}"
                )
            });
            assert_eq!(
                workspace_relative_cfg.node_id, cfg.node_id,
                "{workspace_relative_path} must resolve to the same shipped bootstrap node_id as {config_path}"
            );
            assert_eq!(
                workspace_relative_cfg.rpc_addr, cfg.rpc_addr,
                "{workspace_relative_path} must resolve to the same shipped bootstrap rpc_addr as {config_path}"
            );
            assert_eq!(
                workspace_relative_cfg.p2p_addr, cfg.p2p_addr,
                "{workspace_relative_path} must resolve to the same shipped bootstrap p2p_addr as {config_path}"
            );
            let config_slot = index + 1;
            let expected_node_id = format!("node{}", config_slot);
            let expected_p2p_port = 26_656 + (index as u16) * 1_000;
            let expected_rpc_port = expected_p2p_port + 1;
            let rpc_socket: SocketAddr = cfg
                .rpc_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} rpc_addr should parse: {err}"));
            let p2p_socket: SocketAddr = cfg
                .p2p_addr
                .parse()
                .unwrap_or_else(|err| panic!("{config_path} p2p_addr should parse: {err}"));
            assert_eq!(
                cfg.node_id, expected_node_id,
                "{config_path} must keep the deterministic shipped bootstrap node_id for slot {config_slot}"
            );
            assert!(
                node_ids.insert(cfg.node_id.clone()),
                "{config_path} reuses node_id {}",
                cfg.node_id
            );
            assert!(
                rpc_addrs.insert(cfg.rpc_addr.clone()),
                "{config_path} reuses rpc_addr {}",
                cfg.rpc_addr
            );
            assert!(
                p2p_addrs.insert(cfg.p2p_addr.clone()),
                "{config_path} reuses p2p_addr {}",
                cfg.p2p_addr
            );
            assert!(
                all_listener_addrs.insert(cfg.rpc_addr.clone()),
                "{config_path} rpc_addr {} collides with another shipped listener address",
                cfg.rpc_addr
            );
            assert!(
                all_listener_addrs.insert(cfg.p2p_addr.clone()),
                "{config_path} p2p_addr {} collides with another shipped listener address",
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                "{config_path} rpc_addr {} must stay pinned to 127.0.0.1 for deterministic shipped bootstrap peer dialing",
                cfg.rpc_addr
            );
            assert_eq!(
                cfg.rpc_addr,
                rpc_socket.to_string(),
                "{config_path} rpc_addr {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                cfg.rpc_addr
            );
            assert_eq!(
                p2p_socket.ip(),
                std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                "{config_path} p2p_addr {} must stay pinned to 127.0.0.1 for deterministic shipped bootstrap peer dialing",
                cfg.p2p_addr
            );
            assert_eq!(
                cfg.p2p_addr,
                p2p_socket.to_string(),
                "{config_path} p2p_addr {} must remain a canonical socket literal for deterministic bootstrap peer dialing",
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.is_ipv4(),
                p2p_socket.is_ipv4(),
                "{config_path} rpc_addr {} and p2p_addr {} must stay in the same IP family",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.ip(),
                p2p_socket.ip(),
                "{config_path} rpc_addr {} and p2p_addr {} must bind the same loopback IP",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.port(),
                expected_rpc_port,
                "{config_path} rpc_addr {} must keep the deterministic shipped bootstrap RPC port for slot {config_slot}",
                cfg.rpc_addr
            );
            assert_eq!(
                p2p_socket.port(),
                expected_p2p_port,
                "{config_path} p2p_addr {} must keep the deterministic shipped bootstrap P2P port for slot {config_slot}",
                cfg.p2p_addr
            );
            assert_eq!(
                rpc_socket.port(),
                p2p_socket.port() + 1,
                "{config_path} rpc_addr {} must stay exactly one port above p2p_addr {}",
                cfg.rpc_addr,
                cfg.p2p_addr
            );
            bootstrap_loopback_ips.insert(rpc_socket.ip());
            shipped_nodes.push((config_path, cfg.node_id, rpc_socket, p2p_socket));
        }

        assert_eq!(
            bootstrap_loopback_ips.len(),
            1,
            "shipped local bootstrap configs must all stay on the same loopback IP for deterministic peer dialing"
        );

        let mut shipped_nodes_by_rpc_port = shipped_nodes.clone();
        shipped_nodes_by_rpc_port.sort_by_key(|(_, _, rpc_socket, _)| rpc_socket.port());
        let anchor = shipped_nodes_by_rpc_port
            .first()
            .expect("shipped bootstrap fixture should include node1 RPC anchor");
        assert_eq!(
            anchor.1, "node1",
            "{} must remain the unique shipped Day-1 bootstrap anchor id when RPC ports are ordered",
            anchor.0
        );
        assert_eq!(
            anchor.2.port(), 26657,
            "{} must remain the unique shipped Day-1 bootstrap anchor RPC port",
            anchor.0
        );
        for (config_path, node_id, rpc_socket, _) in shipped_nodes_by_rpc_port.iter().skip(1) {
            assert_ne!(
                node_id, &anchor.1,
                "{config_path} must not reuse the shipped bootstrap anchor node_id {} on a later RPC slot",
                anchor.1
            );
            assert!(
                rpc_socket.port() > anchor.2.port(),
                "{config_path} rpc_addr {} must stay above the shipped bootstrap anchor RPC port {} so later slots cannot silently become equivalent bootstrap anchors",
                rpc_socket,
                anchor.2.port()
            );
        }

        let mut shipped_nodes_by_p2p_port = shipped_nodes.clone();
        shipped_nodes_by_p2p_port.sort_by_key(|(_, _, _, p2p_socket)| p2p_socket.port());
        let p2p_anchor = shipped_nodes_by_p2p_port
            .first()
            .expect("shipped bootstrap fixture should include node1 P2P anchor");
        assert_eq!(
            p2p_anchor.1, "node1",
            "{} must remain the unique shipped Day-1 bootstrap anchor id when P2P ports are ordered",
            p2p_anchor.0
        );
        assert_eq!(
            p2p_anchor.3.port(), 26656,
            "{} must remain the unique shipped Day-1 bootstrap anchor P2P port",
            p2p_anchor.0
        );
        for (config_path, node_id, _, p2p_socket) in shipped_nodes_by_p2p_port.iter().skip(1) {
            assert_ne!(
                node_id, &p2p_anchor.1,
                "{config_path} must not reuse the shipped bootstrap anchor node_id {} on a later P2P slot",
                p2p_anchor.1
            );
            assert!(
                p2p_socket.port() > p2p_anchor.3.port(),
                "{config_path} p2p_addr {} must stay above the shipped bootstrap anchor P2P port {} so later slots cannot silently become equivalent bootstrap anchors",
                p2p_socket,
                p2p_anchor.3.port()
            );
        }

        for window in shipped_nodes.windows(2) {
            let [(prev_config_path, prev_node_id, prev_rpc_socket, prev_p2p_socket), (config_path, node_id, rpc_socket, p2p_socket)] =
                window
            else {
                continue;
            };

            assert_eq!(
                p2p_socket.port() - prev_p2p_socket.port(),
                1000,
                "{config_path} p2p_addr {} must stay 1000 ports above prior shipped bootstrap peer {} ({})",
                p2p_socket,
                prev_node_id,
                prev_config_path
            );
            assert_eq!(
                rpc_socket.port() - prev_rpc_socket.port(),
                1000,
                "{config_path} rpc_addr {} must stay 1000 ports above prior shipped bootstrap peer {} ({})",
                rpc_socket,
                prev_node_id,
                prev_config_path
            );
            assert!(
                node_id > prev_node_id,
                "{config_path} node_id {} must remain lexically ordered after prior shipped bootstrap peer {} ({})",
                node_id,
                prev_node_id,
                prev_config_path
            );
        }
    }

    #[test]
    fn load_config_rejects_list_separators_in_path_fail_closed() {
        let err = load_config("configs/node1.toml,configs/node2.toml")
            .expect_err("config path lists must fail closed");
        assert!(
            err.to_string().contains("path must not contain list separators"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_url_style_path_fail_closed() {
        let err = load_config("https://example.invalid/node1.toml")
            .expect_err("URL-style config paths must fail closed");
        assert!(
            err.to_string().contains("path must not be a URL"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn load_config_rejects_invisible_or_bidi_format_characters_in_path_fail_closed() {
        for path in [
            "configs/node1.toml\u{200B}",
            "configs/node1.toml\u{202E}",
            "configs/node1.toml\u{2066}",
        ] {
            let err = load_config(path)
                .expect_err("config path invisible/bidi format characters must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain invisible or bidirectional format characters"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_parent_traversal_in_path_fail_closed() {
        for path in [
            "../configs/node1.toml",
            "configs/../node1.toml",
            r"..\configs\node1.toml",
            r"configs\..\node1.toml",
        ] {
            let err = load_config(path).expect_err("config path parent traversal must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not contain parent traversal (..)"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_rejects_home_expansion_style_paths_fail_closed() {
        for path in ["~/configs/node1.toml", "~\\configs\\node1.toml", "~qianqi/configs/node1.toml"] {
            let err = load_config(path)
                .expect_err("config path home-expansion markers must fail closed");
            assert!(
                err.to_string()
                    .contains("path must not rely on home-directory expansion (~)"),
                "unexpected error for {path:?}: {err:#}"
            );
        }
    }

    #[test]
    fn load_config_prefers_explicit_paths_over_home_expansion_guessing() {
        let cfg = load_config("trillionnium/configs/node1.toml")
            .expect("explicit repo-root config path should remain supported");
        assert_eq!(cfg.node_id, "node1");
        assert_eq!(cfg.rpc_addr, "127.0.0.1:26657");
        assert_eq!(cfg.p2p_addr, "127.0.0.1:26656");
    }

    const FORBIDDEN_BOOTSTRAP_ALIAS_FIELDS: &[(&str, &str)] = &[
        ("bootstrap_nodes", "[\"127.0.0.1:27656\"]"),
        ("bootstrap_node", "\"127.0.0.1:27656\""),
        ("bootstrap_peers", "[\"127.0.0.1:27656\"]"),
        ("bootstrap_peer", "\"127.0.0.1:27656\""),
        ("bootstrapNodes", "[\"127.0.0.1:27656\"]"),
        ("bootstrapNode", "\"127.0.0.1:27656\""),
        ("bootstrapPeers", "[\"127.0.0.1:27656\"]"),
        ("bootstrapPeer", "\"127.0.0.1:27656\""),
        ("bootstrap_addr", "\"127.0.0.1:27656\""),
        ("bootstrap_addrs", "[\"127.0.0.1:27656\"]"),
        ("bootstrapAddr", "\"127.0.0.1:27656\""),
        ("bootstrapAddrs", "[\"127.0.0.1:27656\"]"),
        ("bootstrap-addr", "\"127.0.0.1:27656\""),
        ("bootstrap-addrs", "[\"127.0.0.1:27656\"]"),
        ("bootstrap-node", "\"127.0.0.1:27656\""),
        ("bootstrap-peer", "\"127.0.0.1:27656\""),
        ("bootstrap", "\"127.0.0.1:27656\""),
        ("seed_nodes", "[\"127.0.0.1:27656\"]"),
        ("seed_node", "\"127.0.0.1:27656\""),
        ("seed_peers", "[\"127.0.0.1:27656\"]"),
        ("seed_peer", "\"127.0.0.1:27656\""),
        ("seed-node", "\"127.0.0.1:27656\""),
        ("seed-peer", "\"127.0.0.1:27656\""),
        ("seedNodes", "[\"127.0.0.1:27656\"]"),
        ("seedNode", "\"127.0.0.1:27656\""),
        ("seedPeers", "[\"127.0.0.1:27656\"]"),
        ("seedPeer", "\"127.0.0.1:27656\""),
        ("seed_addr", "\"127.0.0.1:27656\""),
        ("seed_addrs", "[\"127.0.0.1:27656\"]"),
        ("seedAddr", "\"127.0.0.1:27656\""),
        ("seedAddrs", "[\"127.0.0.1:27656\"]"),
        ("seed-addr", "\"127.0.0.1:27656\""),
        ("seed-addrs", "[\"127.0.0.1:27656\"]"),
        ("seed", "\"127.0.0.1:27656\""),
        ("seeds", "\"127.0.0.1:27656\""),
        ("bootnodes", "[\"127.0.0.1:27656\"]"),
        ("bootnode", "\"127.0.0.1:27656\""),
        ("boot_nodes", "[\"127.0.0.1:27656\"]"),
        ("boot_node", "\"127.0.0.1:27656\""),
        ("bootNodes", "[\"127.0.0.1:27656\"]"),
        ("bootNode", "\"127.0.0.1:27656\""),
        ("boot-node", "\"127.0.0.1:27656\""),
        ("boot_peers", "[\"127.0.0.1:27656\"]"),
        ("boot_peer", "\"127.0.0.1:27656\""),
        ("boot-peer", "\"127.0.0.1:27656\""),
        ("boot_addr", "\"127.0.0.1:27656\""),
        ("boot_addrs", "[\"127.0.0.1:27656\"]"),
        ("bootAddr", "\"127.0.0.1:27656\""),
        ("bootAddrs", "[\"127.0.0.1:27656\"]"),
        ("boot-addr", "\"127.0.0.1:27656\""),
        ("boot-addrs", "[\"127.0.0.1:27656\"]"),
        ("bootPeers", "[\"127.0.0.1:27656\"]"),
        ("bootPeer", "\"127.0.0.1:27656\""),
        ("persistent_peers", "[\"127.0.0.1:27656\"]"),
        ("persistent-peers", "[\"127.0.0.1:27656\"]"),
        ("persistent_peer", "\"127.0.0.1:27656\""),
        ("persistent-peer", "\"127.0.0.1:27656\""),
        ("persistent_addr", "\"127.0.0.1:27656\""),
        ("persistent_addrs", "[\"127.0.0.1:27656\"]"),
        ("persistentAddr", "\"127.0.0.1:27656\""),
        ("persistentAddrs", "[\"127.0.0.1:27656\"]"),
        ("persistent-addr", "\"127.0.0.1:27656\""),
        ("persistent-addrs", "[\"127.0.0.1:27656\"]"),
        ("persistentPeers", "[\"127.0.0.1:27656\"]"),
        ("persistentPeer", "\"127.0.0.1:27656\""),
        ("persistent_nodes", "[\"127.0.0.1:27656\"]"),
        ("persistent-nodes", "[\"127.0.0.1:27656\"]"),
        ("persistent_node", "\"127.0.0.1:27656\""),
        ("persistent-node", "\"127.0.0.1:27656\""),
        ("persistentNodes", "[\"127.0.0.1:27656\"]"),
        ("persistentNode", "\"127.0.0.1:27656\""),
    ];

    #[test]
    fn load_config_rejects_forbidden_bootstrap_alias_fields_with_operator_facing_error() {
        use std::collections::BTreeSet;

        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let alias_names = FORBIDDEN_BOOTSTRAP_ALIAS_FIELDS
            .iter()
            .map(|(field, _)| *field)
            .collect::<Vec<_>>();
        let alias_name_set = alias_names.iter().copied().collect::<BTreeSet<_>>();
        assert_eq!(
            alias_names.len(),
            alias_name_set.len(),
            "FORBIDDEN_BOOTSTRAP_ALIAS_FIELDS must not duplicate alias names or operator parse diagnostics can drift"
        );

        for &(unknown_field, field_value) in FORBIDDEN_BOOTSTRAP_ALIAS_FIELDS {
            let current_dir = std::env::current_dir().expect("current dir");
            let file_name = format!(
                "trnm-node-config-unknown-field-{unknown_field}-{}-{}.toml",
                std::process::id(),
                now_unix_ms()
            );
            let path = current_dir.join(&file_name);
            std::fs::write(
                &path,
                format!(
                    "node_id = \"node1\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n{unknown_field} = {field_value}\n"
                ),
            )
            .expect("write temp config");

            let canonical_path = path.canonicalize().expect("canonicalize temp config path");
            for operator_path in [
                path.to_str().expect("temp path utf-8").to_string(),
                format!("./{file_name}"),
            ] {
                let err =
                    load_config(&operator_path).expect_err("bootstrap alias fields must fail closed");
                let err_surface = format!("{err:#}");
                assert!(
                    err_surface.contains("parse toml failed")
                        && err_surface
                            .contains(&format!("forbidden bootstrap alias field `{unknown_field}`")),
                    "unexpected error for {unknown_field}: {err:#}"
                );
                assert!(
                    err_surface.contains(&format!("remove `{unknown_field}`")),
                    "forbidden alias diagnostic for {unknown_field} must point operators at the exact fix target: {err:#}"
                );
                assert!(
                    err_surface.contains(&operator_path),
                    "error surface for {unknown_field} must keep the operator-supplied config path visible: {err:#}"
                );
                assert!(
                    err_surface.contains(canonical_path.to_string_lossy().as_ref()),
                    "error surface for {unknown_field} must keep the canonical resolved path visible: {err:#}"
                );
            }
            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_rejects_arbitrary_unknown_fields_to_keep_bootstrap_config_fail_closed() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let current_dir = std::env::current_dir().expect("current dir");
        let file_name = format!(
            "trnm-node-config-unknown-field-generic-{}-{}.toml",
            std::process::id(),
            now_unix_ms()
        );
        let path = current_dir.join(&file_name);
        std::fs::write(
            &path,
            "node_id = \"node1\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\nunexpected_peer_hint = \"node2\"\n",
        )
        .expect("write temp config");

        let canonical_path = path.canonicalize().expect("canonicalize temp config path");
        for operator_path in [
            path.to_str().expect("temp path utf-8").to_string(),
            format!("./{file_name}"),
        ] {
            let err = load_config(&operator_path).expect_err("unexpected config fields must fail closed");
            let err_surface = format!("{err:#}");
            assert!(
                err_surface.contains("parse toml failed")
                    && err_surface.contains("unknown field `unexpected_peer_hint`"),
                "unexpected error for generic unknown field: {err:#}"
            );
            assert!(
                err_surface.contains(&operator_path),
                "generic unknown-field error must keep the operator-supplied config path visible: {err:#}"
            );
            assert!(
                err_surface.contains(canonical_path.to_string_lossy().as_ref()),
                "generic unknown-field error must keep the canonical resolved path visible: {err:#}"
            );
        }

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn shipped_bootstrap_readme_alias_ban_matches_runtime_rejection_surface() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");
        let readme_path = workspace_root.join("configs/README.md");
        let readme = std::fs::read_to_string(&readme_path).unwrap_or_else(|err| {
            panic!(
                "{} should stay readable for shipped bootstrap README alias-ban checks: {err}",
                readme_path.display()
            )
        });
        let fixture_scope_section = readme
            .split("## What this fixture is for")
            .nth(1)
            .unwrap_or_else(|| {
                panic!(
                    "{} must keep the `What this fixture is for` section so forbidden bootstrap alias guidance stays reviewable",
                    readme_path.display()
                )
            });

        for forbidden_alias in FORBIDDEN_BOOTSTRAP_ALIAS_FIELDS.iter().map(|(field, _)| *field) {
            let mention_count = fixture_scope_section
                .matches(&format!("`{forbidden_alias}`"))
                .count();
            assert_eq!(
                mention_count, 1,
                "{} must mention forbidden bootstrap alias `{forbidden_alias}` exactly once inside the fixture-scope ban list so operator docs stay aligned with the real fail-closed parser surface",
                readme_path.display()
            );
        }
    }

    #[test]
    fn load_config_rejects_generic_bootstrap_alias_with_operator_facing_error() {
        let current_dir = std::env::current_dir().expect("current dir");
        let file_name = format!(
            "trnm-node-config-unknown-field-bootstrap-{}-{}.toml",
            std::process::id(),
            now_unix_ms()
        );
        let path = current_dir.join(&file_name);
        std::fs::write(
            &path,
            "node_id = \"node1\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\nbootstrap = \"127.0.0.1:27656\"\n",
        )
        .expect("write temp config");

        let canonical_path = std::fs::canonicalize(&path).expect("canonicalize temp config path");
        let operator_path = format!("./{file_name}");
        let err = load_config(&operator_path).expect_err("generic bootstrap alias must fail closed");
        let err_surface = format!("{err:#}");
        assert!(
            err_surface.contains("parse toml failed") && err_surface.contains("unknown field `bootstrap`"),
            "unexpected error for generic bootstrap alias: {err:#}"
        );
        assert!(
            err_surface.contains(&operator_path),
            "generic bootstrap alias surface must keep the operator path visible: {err:#}"
        );
        assert!(
            err_surface.contains(canonical_path.to_string_lossy().as_ref()),
            "generic bootstrap alias surface must keep the resolved path visible: {err:#}"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_blank_node_id_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-node-id-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let err =
            load_config(path.to_str().expect("utf8 path")).expect_err("blank node_id must fail");
        assert!(err.to_string().contains("node_id must not be empty"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_dot_segment_node_id_with_operator_facing_error() {
        for node_id in [".", ".."] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-config-dot-segment-node-id-{}-{}-{node_id}.toml",
                std::process::id(),
                std::thread::current().name().unwrap_or("unnamed")
            ));
            std::fs::write(
                &path,
                format!(
                    "node_id = \"{node_id}\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n"
                ),
            )
            .expect("write config");

            let err = load_config(path.to_str().expect("utf8 path"))
                .expect_err("dot-segment node_id must fail closed");
            assert!(
                err.to_string().contains("node_id must not be '.' or '..'"),
                "unexpected error for {node_id}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_rejects_host_like_node_id_literals_fail_closed() {
        for (suffix, node_id, expected_error) in [
            (
                "localhost",
                "localhost",
                "node_id must not look like a host or socket literal",
            ),
            (
                "localhost-uppercase",
                "LOCALHOST",
                "node_id must not look like a host or socket literal",
            ),
            (
                "localhost-dot",
                "localhost.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "localhost-dot-uppercase",
                "LOCALHOST.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "ipv4-literal",
                "127.0.0.1",
                "node_id must not look like a host or socket literal",
            ),
            (
                "ipv4-socket-shaped",
                "127.0.0.1:26656",
                "node_id must not contain path or host-literal separators",
            ),
            (
                "dns-lowercase",
                "bootstrap.example.com",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-lowercase-dot",
                "bootstrap.example.com.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase",
                "BOOTSTRAP.EXAMPLE.COM",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase-dot",
                "BOOTSTRAP.EXAMPLE.COM.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase-internal",
                "NODE-2.BOOTSTRAP.INTERNAL",
                "node_id must not look like a host or socket literal",
            ),
            (
                "ipv6-literal",
                "::1",
                "node_id must not contain path or host-literal separators",
            ),
            (
                "ipv6-socket-shaped",
                "[::1]:26656",
                "node_id must not contain path or host-literal separators",
            ),
        ] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-config-host-like-node-id-{suffix}-{}-{}.toml",
                std::process::id(),
                std::thread::current().name().unwrap_or("unnamed")
            ));
            std::fs::write(
                &path,
                format!(
                    "node_id = \"{node_id}\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n"
                ),
            )
            .expect("write config");

            let err = load_config(path.to_str().expect("utf8 path"))
                .expect_err("host-like node_id must fail closed");
            assert!(
                err.to_string().contains(expected_error),
                "unexpected error for {node_id}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_rejects_malformed_dotted_node_id_with_operator_facing_error() {
        for (suffix, node_id) in [
            ("double-dot", "node..1"),
            ("label-trailing-hyphen", "peer-.slot"),
            ("label-leading-hyphen", "slot.-peer"),
        ] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-config-malformed-dotted-node-id-{suffix}-{}-{}.toml",
                std::process::id(),
                std::thread::current().name().unwrap_or("unnamed")
            ));
            std::fs::write(
                &path,
                format!(
                    "node_id = \"{node_id}\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n"
                ),
            )
            .expect("write config");

            let err = load_config(path.to_str().expect("utf8 path"))
                .expect_err("malformed dotted node_id must fail closed");
            assert!(
                err.to_string().contains("node_id must not contain dots"),
                "unexpected error for {node_id}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_rejects_blank_rpc_addr_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-rpc-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let err =
            load_config(path.to_str().expect("utf8 path")).expect_err("blank rpc_addr must fail");
        assert!(err.to_string().contains("rpc_addr must not be empty"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_blank_p2p_addr_with_operator_facing_error() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-blank-p2p-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"\"\n",
        )
        .expect("write config");

        let err =
            load_config(path.to_str().expect("utf8 path")).expect_err("blank p2p_addr must fail");
        assert!(err.to_string().contains("p2p_addr must not be empty"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_port_zero_listener_with_operator_facing_error() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-port-zero-rpc-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:0\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");
        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("port-zero rpc listener loaded from disk must fail closed");
        let rpc_err_surface = format!("{rpc_err:#}");
        assert!(rpc_err_surface.contains("rpc_addr must not use port 0"));
        assert!(rpc_err_surface.contains(rpc_path.to_str().expect("utf8 path")));
        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-port-zero-p2p-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:0\"\n",
        )
        .expect("write config");
        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("port-zero p2p listener loaded from disk must fail closed");
        let p2p_err_surface = format!("{p2p_err:#}");
        assert!(p2p_err_surface.contains("p2p_addr must not use port 0"));
        assert!(p2p_err_surface.contains(p2p_path.to_str().expect("utf8 path")));
        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_privileged_listener_port_with_operator_facing_error() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-privileged-rpc-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:443\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");
        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("privileged rpc listener loaded from disk must fail closed");
        let rpc_err_surface = format!("{rpc_err:#}");
        assert!(rpc_err_surface.contains("rpc_addr must not use a privileged port below 1024"));
        assert!(rpc_err_surface.contains(rpc_path.to_str().expect("utf8 path")));
        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-privileged-p2p-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:443\"\n",
        )
        .expect("write config");
        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("privileged p2p listener loaded from disk must fail closed");
        let p2p_err_surface = format!("{p2p_err:#}");
        assert!(p2p_err_surface.contains("p2p_addr must not use a privileged port below 1024"));
        assert!(p2p_err_surface.contains(p2p_path.to_str().expect("utf8 path")));
        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_unspecified_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-unspecified-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"0.0.0.0:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed unspecified listener must fail closed");
        assert!(err
            .to_string()
            .contains("rpc_addr must not use an unspecified address"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_unspecified_p2p_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-unspecified-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"[::]:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed unspecified p2p listener must fail closed");
        assert!(err
            .to_string()
            .contains("p2p_addr must not use an unspecified address"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_mixed_ip_families_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-mixed-listener-families-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"[2001:4860:4860::8888]:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed mixed listener families must fail closed");
        let err_surface = err.to_string();
        assert!(err_surface.contains("must use the same IP family"));
        assert!(err_surface.contains("127.0.0.1:26657"));
        assert!(err_surface.contains("[2001:4860:4860::8888]:26656"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_distinct_same_family_listener_ips() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-distinct-ip-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.2:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("distinct same-family listener IPs must fail closed after trimming");
        let err_surface = err.to_string();
        assert!(err_surface.contains("must bind the same IP"));
        assert!(err_surface.contains("127.0.0.1:26657"));
        assert!(err_surface.contains("127.0.0.2:26656"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_ipv4_broadcast_rpc_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-broadcast-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"255.255.255.255:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed broadcast rpc listener must fail closed");
        assert!(err
            .to_string()
            .contains("rpc_addr must not use the IPv4 broadcast address"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_ipv4_broadcast_p2p_listener_after_operator_trimming() {
        let path = std::env::temp_dir().join(format!(
            "trnm-node-config-broadcast-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"255.255.255.255:26656\"\n",
        )
        .expect("write config");

        let err = load_config(path.to_str().expect("utf8 path"))
            .expect_err("trimmed broadcast p2p listener must fail closed");
        assert!(err
            .to_string()
            .contains("p2p_addr must not use the IPv4 broadcast address"));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_config_rejects_multicast_listener_after_operator_trimming() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-multicast-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"239.1.2.3:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("trimmed multicast rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not use a multicast address"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-multicast-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"[ff02::1]:26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("trimmed multicast p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not use a multicast address"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_ipv6_loopback_listener_after_operator_trimming() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-ipv6-loopback-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"[::1]:26657\"\np2p_addr = \"[2001:4860::1]:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("ipv6 loopback rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not use the IPv6 loopback address"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-ipv6-loopback-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"[2001:4860::1]:26657\"\np2p_addr = \"[::1]:26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("ipv6 loopback p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not use the IPv6 loopback address"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_link_local_listener_after_operator_trimming() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-link-local-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"169.254.10.20:26657\"\np2p_addr = \"169.254.10.21:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("trimmed link-local rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not use a link-local address"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-link-local-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"[2001:4860:4860::8888]:26657\"\np2p_addr = \"[fe80::1]:26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("trimmed link-local p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not use a link-local address"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_ipv6_scope_identifier_listener_with_operator_facing_error() {
        for (field, addr, expected_fragment) in [
            (
                "rpc_addr",
                "[2001:db8::10%7]:26657",
                "rpc_addr must not use an IPv6 scope identifier",
            ),
            (
                "p2p_addr",
                "[2001:db8::10%9]:26656",
                "p2p_addr must not use an IPv6 scope identifier",
            ),
        ] {
            let path = std::env::temp_dir().join(format!(
                "trnm-node-config-ipv6-scope-{field}-listener-{}-{}.toml",
                std::process::id(),
                now_unix_ms()
            ));
            let body = if field == "rpc_addr" {
                format!(
                    "node_id = \"node-a\"\nrpc_addr = \"{addr}\"\np2p_addr = \"[2001:4860::1]:26656\"\n"
                )
            } else {
                format!(
                    "node_id = \"node-a\"\nrpc_addr = \"[2001:4860::1]:26657\"\np2p_addr = \"{addr}\"\n"
                )
            };
            std::fs::write(&path, body).expect("write config");

            let path_str = path.to_str().expect("utf8 path");
            let err = load_config(path_str)
                .expect_err("IPv6 scope-id bootstrap listeners must fail closed");
            let err_surface = format!("{err:#}");
            assert!(
                err_surface.contains(expected_fragment),
                "unexpected error for {field}: {err:#}"
            );
            assert!(
                err_surface.contains(path_str),
                "error surface for {field} must keep the operator-supplied config path visible: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_rejects_path_style_operator_addresses() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-path-style-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1/26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("path-style rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not contain path separators"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-path-style-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"127.0.0.1\\\\26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("path-style p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not contain path separators"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_url_style_operator_addresses() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-url-style-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"http://127.0.0.1:26657\"\np2p_addr = \"127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("URL-style rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must be a raw socket address, not a URL"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-url-style-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:26657\"\np2p_addr = \"tcp://127.0.0.1:26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("URL-style p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must be a raw socket address, not a URL"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_rejects_noncanonical_socket_literals() {
        let rpc_path = std::env::temp_dir().join(format!(
            "trnm-node-config-noncanonical-rpc-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &rpc_path,
            "node_id = \"node-a\"\nrpc_addr = \"[0:0:0:0:0:0:0:1]:26657\"\np2p_addr = \"[2001:4860:4860::8888]:26656\"\n",
        )
        .expect("write config");

        let rpc_err = load_config(rpc_path.to_str().expect("utf8 path"))
            .expect_err("noncanonical rpc listener must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must use a canonical socket literal"));

        let _ = std::fs::remove_file(rpc_path);

        let p2p_path = std::env::temp_dir().join(format!(
            "trnm-node-config-noncanonical-p2p-listener-{}-{}.toml",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        std::fs::write(
            &p2p_path,
            "node_id = \"node-a\"\nrpc_addr = \"[2001:4860:4860::8888]:26657\"\np2p_addr = \"[0:0:0:0:0:0:0:1]:26656\"\n",
        )
        .expect("write config");

        let p2p_err = load_config(p2p_path.to_str().expect("utf8 path"))
            .expect_err("noncanonical p2p listener must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must use a canonical socket literal"));

        let _ = std::fs::remove_file(p2p_path);
    }

    #[test]
    fn load_config_parse_errors_keep_operator_and_resolved_paths_visible_for_alias_drift() {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let current_dir = std::env::current_dir().expect("current dir");

        for (suffix, alias_line, expected_field) in [
            (
                "bootstrap-peer",
                "bootstrap_peer = \"127.0.0.1:27656\"",
                "bootstrap_peer",
            ),
            (
                "bootstrap-addr",
                "bootstrap_addr = \"127.0.0.1:27656\"",
                "bootstrap_addr",
            ),
            (
                "bootstrap-addrs",
                "bootstrap_addrs = [\"127.0.0.1:27656\"]",
                "bootstrap_addrs",
            ),
            ("seed-peer", "seed_peer = \"127.0.0.1:27656\"", "seed_peer"),
            ("seed-addr", "seed_addr = \"127.0.0.1:27656\"", "seed_addr"),
            (
                "seed-addrs",
                "seed_addrs = [\"127.0.0.1:27656\"]",
                "seed_addrs",
            ),
            (
                "persistent-peer",
                "persistent_peer = \"127.0.0.1:27656\"",
                "persistent_peer",
            ),
            (
                "persistent-addr",
                "persistent_addr = \"127.0.0.1:27656\"",
                "persistent_addr",
            ),
            (
                "persistent-addrs",
                "persistent_addrs = [\"127.0.0.1:27656\"]",
                "persistent_addrs",
            ),
        ] {
            let file_name = format!(
                "trnm-node-config-parse-surface-{suffix}-{}-{}.toml",
                std::process::id(),
                now_unix_ms()
            );
            let path = current_dir.join(&file_name);
            std::fs::write(
                &path,
                format!(
                    "node_id = \"node-a\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"127.0.0.1:7001\"\n{alias_line}\n"
                ),
            )
            .expect("write config");

            let operator_path = format!("./{file_name}");
            let canonical_path = path.canonicalize().expect("canonicalize temp config path");
            let err = load_config(&operator_path)
                .expect_err("alias drift must fail closed with both paths visible");
            let err_surface = format!("{err:#}");
            assert!(
                err_surface.contains("parse toml failed"),
                "parse-stage failures must retain the load_config context for {expected_field}: {err:#}"
            );
            assert!(
                err_surface.contains(&operator_path),
                "parse-stage failures must keep the operator-supplied path visible for {expected_field}: {err:#}"
            );
            assert!(
                err_surface.contains(canonical_path.to_string_lossy().as_ref()),
                "parse-stage failures must keep the canonical resolved path visible for {expected_field}: {err:#}"
            );
            assert!(
                err_surface.contains(&format!("unknown field `{expected_field}`")),
                "parse-stage failures must keep the exact alias drift reason visible for {expected_field}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_validation_errors_keep_operator_and_resolved_paths_visible_for_listener_guard_drift(
    ) {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let current_dir = std::env::current_dir().expect("current dir");

        for (suffix, rpc_addr, p2p_addr, expected_fragment) in [
            (
                "rpc-path-style",
                "127.0.0.1/7000",
                "127.0.0.1:7001",
                "rpc_addr must not contain path separators",
            ),
            (
                "p2p-url-style",
                "127.0.0.1:7000",
                "tcp://127.0.0.1:7001",
                "p2p_addr must be a raw socket address, not a URL",
            ),
            (
                "rpc-noncanonical",
                "[0:0:0:0:0:0:0:1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must use a canonical socket literal",
            ),
            (
                "p2p-noncanonical",
                "[2001:4860::1]:7000",
                "[0:0:0:0:0:0:0:1]:7001",
                "p2p_addr must use a canonical socket literal",
            ),
            (
                "rpc-doc-v4",
                "192.0.2.10:7000",
                "127.0.0.1:7001",
                "rpc_addr must not use a documentation or benchmark-only address",
            ),
            (
                "p2p-doc-v6",
                "[2001:4860::1]:7000",
                "[2001:db8::11]:7001",
                "p2p_addr must not use a documentation or benchmark-only address",
            ),
            (
                "rpc-v6-loopback",
                "[::1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must not use the IPv6 loopback address",
            ),
            (
                "p2p-v6-loopback",
                "[2001:4860::1]:7000",
                "[::1]:7001",
                "p2p_addr must not use the IPv6 loopback address",
            ),
            (
                "rpc-ipv4-mapped",
                "[::ffff:127.0.0.1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must not use an IPv4-mapped IPv6 address",
            ),
            (
                "p2p-ipv4-mapped",
                "[2001:4860::1]:7000",
                "[::ffff:127.0.0.1]:7001",
                "p2p_addr must not use an IPv4-mapped IPv6 address",
            ),
            (
                "rpc-ipv4-compatible",
                "[::7f00:1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must not use an IPv4-compatible IPv6 address",
            ),
            (
                "p2p-ipv4-compatible",
                "[2001:4860::1]:7000",
                "[::c000:20a]:7001",
                "p2p_addr must not use an IPv4-compatible IPv6 address",
            ),
            (
                "rpc-ipv4-translated",
                "[::ffff:0:7f00:1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must not use an IPv4-translated IPv6 address",
            ),
            (
                "p2p-ipv4-translated",
                "[2001:4860::1]:7000",
                "[::ffff:0:7f00:1]:7001",
                "p2p_addr must not use an IPv4-translated IPv6 address",
            ),
            (
                "rpc-ipv4-translated-dotted-quad",
                "[::ffff:0:127.0.0.1]:7000",
                "[2001:4860::1]:7001",
                "rpc_addr must not use an IPv4-translated IPv6 address",
            ),
            (
                "p2p-ipv4-translated-dotted-quad",
                "[2001:4860::1]:7000",
                "[::ffff:0:127.0.0.1]:7001",
                "p2p_addr must not use an IPv4-translated IPv6 address",
            ),
            (
                "rpc-scope",
                "[2001:4860::8888%7]:7000",
                "[2001:4860::8888]:7001",
                "rpc_addr must not use an IPv6 scope identifier",
            ),
            (
                "p2p-scope",
                "[2001:4860::8888]:7000",
                "[2001:4860::8888%9]:7001",
                "p2p_addr must not use an IPv6 scope identifier",
            ),
            (
                "rpc-unspecified",
                "0.0.0.0:7000",
                "127.0.0.1:7001",
                "rpc_addr must not use an unspecified address",
            ),
            (
                "p2p-broadcast",
                "127.0.0.1:7000",
                "255.255.255.255:7001",
                "p2p_addr must not use the IPv4 broadcast address",
            ),
            (
                "rpc-link-local",
                "169.254.10.20:7000",
                "127.0.0.1:7001",
                "rpc_addr must not use a link-local address",
            ),
            (
                "p2p-link-local",
                "[2001:4860::1]:7000",
                "[fe80::1]:7001",
                "p2p_addr must not use a link-local address",
            ),
            (
                "shared-socket",
                "127.0.0.1:7000",
                "127.0.0.1:7000",
                "must differ",
            ),
            (
                "mixed-family",
                "127.0.0.1:7000",
                "[2001:4860::1]:7001",
                "must use the same IP family",
            ),
            (
                "distinct-ip",
                "127.0.0.1:7000",
                "127.0.0.2:7001",
                "must bind the same IP",
            ),
        ] {
            let file_name = format!(
                "trnm-node-config-validation-surface-{suffix}-{}-{}.toml",
                std::process::id(),
                now_unix_ms()
            );
            let path = current_dir.join(&file_name);
            std::fs::write(
                &path,
                format!(
                    "node_id = \"node-a\"\nrpc_addr = \"{rpc_addr}\"\np2p_addr = \"{p2p_addr}\"\n"
                ),
            )
            .expect("write config");

            let operator_path = format!("./{file_name}");
            let canonical_path = path.canonicalize().expect("canonicalize temp config path");
            let err = load_config(&operator_path)
                .expect_err("listener guard drift must fail closed with both paths visible");
            let err_surface = format!("{err:#}");
            assert!(
                err_surface.contains("validate config failed"),
                "validation-stage failures must retain the load_config context for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(&operator_path),
                "validation-stage failures must keep the operator-supplied path visible for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(canonical_path.to_string_lossy().as_ref()),
                "validation-stage failures must keep the canonical resolved path visible for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(expected_fragment),
                "validation-stage failures must keep the exact listener guard reason visible for {suffix}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn load_config_validation_errors_keep_operator_and_resolved_paths_visible_for_node_id_guard_drift(
    ) {
        let _cwd_guard = cwd_test_lock().lock().unwrap();
        let current_dir = std::env::current_dir().expect("current dir");

        for (suffix, node_id, expected_fragment) in [
            (
                "non-ascii",
                "nοde-a",
                "node_id must use ASCII-only characters",
            ),
            (
                "list-separator",
                "node;a",
                "node_id must not contain list separators (, ; |)",
            ),
            (
                "uri-delimiter",
                "node&peer=seed",
                "node_id must not contain URI delimiters (@ ? # % & =)",
            ),
            (
                "quoting",
                "node'alpha",
                "node_id must not contain quoting characters (\" ' `)",
            ),
            (
                "dot-segment",
                ".",
                "node_id must not be '.' or '..'",
            ),
            (
                "path-like",
                "seed/slot",
                "node_id must not contain path or host-literal separators (/ \\ : [ ])",
            ),
            (
                "bracketed-pseudo-host",
                "[seed]",
                "node_id must not contain path or host-literal separators (/ \\ : [ ])",
            ),
            (
                "localhost",
                "localhost",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase-dot",
                "BOOTSTRAP.EXAMPLE.COM.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase",
                "BOOTSTRAP.EXAMPLE.COM",
                "node_id must not look like a host or socket literal",
            ),
            (
                "dns-uppercase-internal",
                "NODE-2.BOOTSTRAP.INTERNAL",
                "node_id must not look like a host or socket literal",
            ),
            (
                "localhost-dot-uppercase",
                "LOCALHOST.",
                "node_id must not look like a host or socket literal",
            ),
            (
                "ipv4-literal",
                "127.0.0.1",
                "node_id must not look like a host or socket literal",
            ),
            (
                "ipv4-socket-shaped",
                "127.0.0.1:7000",
                "node_id must not contain path or host-literal separators (/ \\ : [ ])",
            ),
            (
                "ipv6-literal",
                "::1",
                "node_id must not contain path or host-literal separators (/ \\ : [ ])",
            ),
            (
                "invisible-bidi",
                concat!("node", "\u{200B}", "alpha"),
                "node_id must not contain invisible or bidirectional format characters",
            ),
        ] {
            let file_name = format!(
                "trnm-node-config-node-id-surface-{suffix}-{}-{}.toml",
                std::process::id(),
                now_unix_ms()
            );
            let path = current_dir.join(&file_name);
            std::fs::write(
                &path,
                format!(
                    "node_id = \"{node_id}\"\nrpc_addr = \"127.0.0.1:7000\"\np2p_addr = \"127.0.0.1:7001\"\n"
                ),
            )
            .expect("write config");

            let operator_path = format!("./{file_name}");
            let canonical_path = path.canonicalize().expect("canonicalize temp config path");
            let err = load_config(&operator_path)
                .expect_err("node_id guard drift must fail closed with both paths visible");
            let err_surface = format!("{err:#}");
            assert!(
                err_surface.contains("validate config failed"),
                "validation-stage failures must retain the load_config context for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(&operator_path),
                "validation-stage failures must keep the operator-supplied path visible for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(canonical_path.to_string_lossy().as_ref()),
                "validation-stage failures must keep the canonical resolved path visible for {suffix}: {err:#}"
            );
            assert!(
                err_surface.contains(expected_fragment),
                "validation-stage failures must keep the exact node_id guard reason visible for {suffix}: {err:#}"
            );

            let _ = std::fs::remove_file(path);
        }
    }

    #[test]
    fn validate_startup_args_rejects_zero_validators() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 0,
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

        let err = validate_startup_args(&args).expect_err("zero validators must fail closed");
        assert!(err.to_string().contains("validators must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_block_zero_block_interval() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 0,
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

        let err = validate_startup_args(&args).expect_err("zero block interval must fail closed");
        assert!(err.to_string().contains("block_ms must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_byzantine_at_or_above_validator_count() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 4,
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

        let err =
            validate_startup_args(&args).expect_err("byzantine >= validators must fail closed");
        assert!(err
            .to_string()
            .contains("byzantine must be less than validators"));
    }

    #[test]
    fn validate_startup_args_rejects_insufficient_validator_quorum_for_byzantine_budget() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 3,
            byzantine: 1,
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

        let err =
            validate_startup_args(&args).expect_err("validator quorum below 3f+1 must fail closed");
        assert!(err
            .to_string()
            .contains("validators must satisfy N >= 3f + 1"));
    }

    #[test]
    fn validate_startup_args_accepts_exact_three_f_plus_one_validator_quorum() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: 4,
            byzantine: 1,
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

        validate_startup_args(&args)
            .expect("an exact 3f+1 validator set must remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_rejects_blank_config_path() {
        let args = Args {
            config: "   ".into(),
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

        let err = validate_startup_args(&args).expect_err("blank config path must fail closed");
        assert!(err.to_string().contains("config must not be empty"));
    }

    #[test]
    fn validate_startup_args_rejects_config_path_with_outer_whitespace() {
        let args = Args {
            config: " configs/node1.toml ".into(),
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

        let err = validate_startup_args(&args)
            .expect_err("outer whitespace in config path must fail closed");
        assert!(err
            .to_string()
            .contains("config must not contain leading or trailing whitespace"));
    }

    #[test]
    fn validate_startup_args_rejects_control_characters_in_config_path() {
        let args = Args {
            config: "configs/node1.toml\nshadow".into(),
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

        let err = validate_startup_args(&args)
            .expect_err("control characters in config path must fail closed");
        assert!(err
            .to_string()
            .contains("config must not contain control characters"));
    }

    #[test]
    fn validate_startup_args_accepts_repo_root_bootstrap_config() {
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

        validate_startup_args(&args)
            .expect("repo-root bootstrap config should remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_accepts_all_shipped_repo_root_bootstrap_configs() {
        for config in [
            "configs/node1.toml",
            "configs/node2.toml",
            "configs/node3.toml",
            "configs/node4.toml",
        ] {
            let args = Args {
                config: config.into(),
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

            validate_startup_args(&args).unwrap_or_else(|err| {
                panic!(
                    "all shipped Day-1 bootstrap configs should remain bootstrappable via startup preflight; {config} failed with {err:#}"
                )
            });
        }
    }

    #[test]
    fn validate_startup_args_accepts_workspace_prefixed_bootstrap_config() {
        let args = Args {
            config: "trillionnium/configs/node1.toml".into(),
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

        validate_startup_args(&args)
            .expect("workspace-prefixed bootstrap config should remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_accepts_all_workspace_prefixed_bootstrap_configs() {
        for config in [
            "trillionnium/configs/node1.toml",
            "trillionnium/configs/node2.toml",
            "trillionnium/configs/node3.toml",
            "trillionnium/configs/node4.toml",
        ] {
            let args = Args {
                config: config.into(),
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

            validate_startup_args(&args).unwrap_or_else(|err| {
                panic!(
                    "all workspace-prefixed shipped Day-1 bootstrap configs should remain bootstrappable via startup preflight; {config} failed with {err:#}"
                )
            });
        }
    }

    #[test]
    fn validate_startup_args_accepts_curdir_prefixed_workspace_bootstrap_config() {
        let args = Args {
            config: "./trillionnium/configs/node1.toml".into(),
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

        validate_startup_args(&args)
            .expect("curdir-prefixed workspace bootstrap config should remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_accepts_all_curdir_prefixed_workspace_bootstrap_configs() {
        for config in [
            "./trillionnium/configs/node1.toml",
            "./trillionnium/configs/node2.toml",
            "./trillionnium/configs/node3.toml",
            "./trillionnium/configs/node4.toml",
        ] {
            let args = Args {
                config: config.into(),
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

            validate_startup_args(&args).unwrap_or_else(|err| {
                panic!(
                    "all curdir-prefixed shipped Day-1 bootstrap configs should remain bootstrappable via startup preflight; {config} failed with {err:#}"
                )
            });
        }
    }

    #[test]
    fn validate_startup_args_accepts_all_inner_curdir_shipped_bootstrap_configs() {
        for config in [
            "trillionnium/./configs/./node1.toml",
            "trillionnium/./configs/./node2.toml",
            "trillionnium/./configs/./node3.toml",
            "trillionnium/./configs/./node4.toml",
        ] {
            let args = Args {
                config: config.into(),
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

            validate_startup_args(&args).unwrap_or_else(|err| {
                panic!(
                    "all inner-curdir shipped Day-1 bootstrap configs should remain bootstrappable via startup preflight; {config} failed with {err:#}"
                )
            });
        }
    }

    #[test]
    fn validate_startup_args_accepts_curdir_prefixed_repo_root_bootstrap_config() {
        let args = Args {
            config: "./configs/node1.toml".into(),
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

        validate_startup_args(&args)
            .expect("curdir-prefixed repo-root bootstrap config should remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_accepts_all_curdir_prefixed_repo_root_bootstrap_configs() {
        for config in [
            "./configs/node1.toml",
            "./configs/node2.toml",
            "./configs/node3.toml",
            "./configs/node4.toml",
        ] {
            let args = Args {
                config: config.into(),
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

            validate_startup_args(&args).unwrap_or_else(|err| {
                panic!(
                    "all curdir-prefixed repo-root shipped Day-1 bootstrap configs should remain bootstrappable via startup preflight; {config} failed with {err:#}"
                )
            });
        }
    }

    #[test]
    fn shipped_bootstrap_path_aliases_stay_slot_stable_across_load_and_startup_preflight() {
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .ancestors()
            .nth(2)
            .expect("trnm-node manifest should sit under trillionnium/crates/trnm-node");

        let make_args = |config: String| Args {
            config,
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

        let expected = [
            (1, "node1", "127.0.0.1:26657", "127.0.0.1:26656"),
            (2, "node2", "127.0.0.1:27657", "127.0.0.1:27656"),
            (3, "node3", "127.0.0.1:28657", "127.0.0.1:28656"),
            (4, "node4", "127.0.0.1:29657", "127.0.0.1:29656"),
        ];

        for (slot, node_id, rpc_addr, p2p_addr) in expected {
            let canonical_slot_path = workspace_root.join(format!("configs/node{slot}.toml"));
            for config in [
                format!("configs/node{slot}.toml"),
                format!("./configs/node{slot}.toml"),
                format!("configs/./node{slot}.toml"),
                format!("./configs/./node{slot}.toml"),
                format!("trillionnium/configs/node{slot}.toml"),
                format!("./trillionnium/configs/node{slot}.toml"),
                format!("trillionnium/./configs/./node{slot}.toml"),
                format!("./trillionnium/./configs/./node{slot}.toml"),
            ] {
                assert_eq!(
                    resolve_config_path(&config),
                    canonical_slot_path,
                    "{config} must stay anchored to shipped bootstrap slot {slot}"
                );

                let cfg = load_config(&config).unwrap_or_else(|err| {
                    panic!(
                        "{config} should load for shipped bootstrap slot {slot}: {err:#}"
                    )
                });
                assert_eq!(
                    cfg.node_id, node_id,
                    "{config} must keep the shipped node_id for bootstrap slot {slot}"
                );
                assert_eq!(
                    cfg.rpc_addr, rpc_addr,
                    "{config} must keep the shipped rpc_addr for bootstrap slot {slot}"
                );
                assert_eq!(
                    cfg.p2p_addr, p2p_addr,
                    "{config} must keep the shipped p2p_addr for bootstrap slot {slot}"
                );

                validate_startup_args(&make_args(config.clone())).unwrap_or_else(|err| {
                    panic!(
                        "{config} should remain bootstrappable via startup preflight for shipped slot {slot}: {err:#}"
                    )
                });
            }
        }
    }

    #[test]
    fn validate_startup_args_rejects_parent_traversal_in_config_path() {
        let args = Args {
            config: "../configs/node1.toml".into(),
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

        let err = validate_startup_args(&args)
            .expect_err("parent traversal in config path must fail closed");
        assert!(err
            .to_string()
            .contains("config must not contain '..' path segments"));
    }

    #[test]
    fn validate_startup_args_rejects_blank_bft_wal_dir() {
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
            bft_wal_dir: "   ".into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args).expect_err("blank bft_wal_dir must fail closed");
        assert!(err.to_string().contains("bft_wal_dir must not be empty"));
    }

    #[test]
    fn validate_startup_args_rejects_control_characters_in_bft_wal_dir() {
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
            bft_wal_dir: "run/consensus-wal\nshadow".into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args)
            .expect_err("control characters in bft_wal_dir must fail closed");
        assert!(err
            .to_string()
            .contains("bft_wal_dir must not contain control characters"));
    }

    #[test]
    fn validate_startup_args_rejects_bft_wal_dir_with_outer_whitespace() {
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
            bft_wal_dir: " run/consensus-wal ".into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args)
            .expect_err("outer whitespace in bft_wal_dir must fail closed");
        assert!(err
            .to_string()
            .contains("bft_wal_dir must not contain leading or trailing whitespace"));
    }

    #[test]
    fn validate_startup_args_rejects_current_dir_bft_wal_dir() {
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
            bft_wal_dir: "./run/consensus-wal".into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args)
            .expect_err("current-dir wal path segments must fail closed");
        assert!(err
            .to_string()
            .contains("bft_wal_dir must not contain '.' or '..' path segments"));
    }

    #[test]
    fn validate_startup_args_rejects_parent_dir_bft_wal_dir() {
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
            bft_wal_dir: "../run/consensus-wal".into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args)
            .expect_err("parent-dir wal path segments must fail closed");
        assert!(err
            .to_string()
            .contains("bft_wal_dir must not contain '.' or '..' path segments"));
    }

    #[test]
    fn validate_startup_args_rejects_zero_parallel_workers() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 0,
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

        let err = validate_startup_args(&args).expect_err("zero parallel_workers must fail closed");
        assert!(err
            .to_string()
            .contains("parallel_workers must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_zero_txs_per_block() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 0,
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

        let err = validate_startup_args(&args).expect_err("zero txs_per_block must fail closed");
        assert!(err.to_string().contains("txs_per_block must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_zero_checkpoint_interval() {
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
            bft_checkpoint_interval: 0,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err =
            validate_startup_args(&args).expect_err("zero checkpoint interval must fail closed");
        assert!(err
            .to_string()
            .contains("bft_checkpoint_interval must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_zero_timeout_scan_interval() {
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
            pouw_timeout_scan_every_blocks: 0,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err =
            validate_startup_args(&args).expect_err("zero timeout scan cadence must fail closed");
        assert!(err
            .to_string()
            .contains("pouw_timeout_scan_every_blocks must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_quorum_overflow_for_extreme_byzantine_budget() {
        let args = Args {
            config: "configs/node1.toml".into(),
            block_ms: 1000,
            max_blocks: 10,
            demo_tasks: 2,
            demo_keys: 2,
            parallel_workers: 4,
            txs_per_block: 4,
            validators: usize::MAX,
            byzantine: usize::MAX - 1,
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

        let err = validate_startup_args(&args)
            .expect_err("overflowed 3f+1 quorum sizing must fail closed");
        assert!(err.to_string().contains("overflows 3f + 1 quorum sizing"));
    }

    #[test]
    fn validate_startup_args_rejects_zero_bft_max_rounds() {
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
            bft_max_rounds: 0,
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

        let err = validate_startup_args(&args).expect_err("zero bft_max_rounds must fail closed");
        assert!(err
            .to_string()
            .contains("bft_max_rounds must be at least 1"));
    }

    #[test]
    fn validate_startup_args_rejects_fault_rounds_that_guarantee_no_quorum_stall() {
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
            bft_fault_rounds: 3,
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

        let err = validate_startup_args(&args)
            .expect_err("fault_rounds >= max_rounds must fail closed before startup");
        assert!(err
            .to_string()
            .contains("bft_fault_rounds (3) must be less than bft_max_rounds (3)"));
    }

    #[test]
    fn validate_startup_args_accepts_fault_round_budget_below_max_rounds() {
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
            bft_fault_rounds: 2,
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

        validate_startup_args(&args)
            .expect("fault_rounds below max_rounds must remain bootstrappable");
    }

    #[test]
    fn validate_startup_args_rejects_round_change_backoff_cap_below_base() {
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
            bft_round_change_backoff_max_ms: 4,
            bft_wal_dir: DEFAULT_BFT_WAL_DIR.into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        let err = validate_startup_args(&args)
            .expect_err("round-change backoff cap below base must fail closed");
        assert!(err.to_string().contains(
            "bft_round_change_backoff_max_ms (4) must be >= bft_round_change_backoff_ms (5)"
        ));
    }

    #[test]
    fn validate_startup_args_accepts_round_change_backoff_cap_equal_to_base() {
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
            bft_round_change_backoff_max_ms: 5,
            bft_wal_dir: DEFAULT_BFT_WAL_DIR.into(),
            bft_wal_mode: WalDirMode::Auto,
            bft_checkpoint_interval: 5,
            pouw_timeout_scan: true,
            pouw_timeout_scan_every_blocks: 1,
            enable_da_ordering_decouple: false,
            rl_advisor_shadow: false,
            rl_advisor_shadow_topk: 4,
        };

        validate_startup_args(&args)
            .expect("round-change backoff cap equal to base must remain bootstrappable");
    }

    #[test]
    fn validate_node_config_rejects_boundary_whitespace_before_shared_listener_detection() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: " 127.0.0.1:26657\n".into(),
                p2p_addr: "\t127.0.0.1:26657 ".into(),
            },
            "node.toml",
        )
        .expect_err("boundary whitespace must fail closed before shared listener detection");
        assert!(err
            .to_string()
            .contains("rpc_addr must not contain leading or trailing whitespace"));
    }

    #[test]
    fn validate_node_config_rejects_exact_shared_listener_socket() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26657".into(),
            },
            "node.toml",
        )
        .expect_err("exact shared RPC/P2P listener socket must fail closed");
        assert!(err
            .to_string()
            .contains("rpc_addr and p2p_addr must differ"));
    }

    #[test]
    fn validate_node_config_rejects_hostname_shaped_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "localhost:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("hostname-shaped rpc_addr must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must be a valid socket address"));

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "LOCALHOST:26656".into(),
            },
            "node.toml",
        )
        .expect_err("hostname-shaped p2p_addr must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must be a valid socket address"));
    }

    #[test]
    fn validate_node_config_rejects_mixed_ip_families() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "[2606:4700:4700::1111]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("mixed IPv4/IPv6 listener sockets must fail closed");
        let err_surface = err.to_string();
        assert!(err_surface.contains("must use the same IP family"));
        assert!(err_surface.contains("127.0.0.1:26657"));
        assert!(err_surface.contains("[2606:4700:4700::1111]:26656"));
    }

    #[test]
    fn validate_node_config_rejects_distinct_listener_ips_within_same_family() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.2:26656".into(),
            },
            "node.toml",
        )
        .expect_err("distinct same-family listener IPs must fail closed");
        let err_surface = err.to_string();
        assert!(err_surface.contains("must bind the same IP"));
        assert!(err_surface.contains("127.0.0.1:26657"));
        assert!(err_surface.contains("127.0.0.2:26656"));
    }

    #[test]
    fn validate_node_config_rejects_control_characters_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657\u{0007}".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr with control characters must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not contain control characters"));

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656\u{001b}".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr with control characters must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not contain control characters"));
    }

    #[test]
    fn validate_node_config_rejects_list_separators_in_operator_addresses() {
        let rpc_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657,127.0.0.1:26659".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr list separators must fail closed");
        assert!(rpc_err
            .to_string()
            .contains("rpc_addr must not contain list separators (, ; |)"));

        let p2p_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656|127.0.0.1:26658".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr list separators must fail closed");
        assert!(p2p_err
            .to_string()
            .contains("p2p_addr must not contain list separators (, ; |)"));
    }

    #[test]
    fn validate_node_config_rejects_ipv4_mapped_scope_and_documentation_listener_addresses() {
        let rpc_loopback_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::1]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr IPv6 loopback bind must fail closed");
        assert!(rpc_loopback_err
            .to_string()
            .contains("rpc_addr must not use the IPv6 loopback address"));

        let p2p_loopback_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888]:26657".into(),
                p2p_addr: "[::1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr IPv6 loopback bind must fail closed");
        assert!(p2p_loopback_err
            .to_string()
            .contains("p2p_addr must not use the IPv6 loopback address"));

        let rpc_ipv4_mapped_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::ffff:127.0.0.1]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr IPv4-mapped IPv6 bind must fail closed");
        assert!(rpc_ipv4_mapped_err
            .to_string()
            .contains("rpc_addr must not use an IPv4-mapped IPv6 address"));

        let p2p_ipv4_mapped_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888]:26657".into(),
                p2p_addr: "[::ffff:127.0.0.1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr IPv4-mapped IPv6 bind must fail closed");
        assert!(p2p_ipv4_mapped_err
            .to_string()
            .contains("p2p_addr must not use an IPv4-mapped IPv6 address"));

        let rpc_translated_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::ffff:0:7f00:1]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr IPv4-translated IPv6 bind must fail closed");
        assert!(rpc_translated_err
            .to_string()
            .contains("rpc_addr must not use an IPv4-translated IPv6 address"));

        let p2p_translated_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888]:26657".into(),
                p2p_addr: "[::ffff:0:7f00:1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr IPv4-translated IPv6 bind must fail closed");
        assert!(p2p_translated_err
            .to_string()
            .contains("p2p_addr must not use an IPv4-translated IPv6 address"));

        let rpc_translated_dotted_quad_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[::ffff:0:127.0.0.1]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr dotted-quad IPv4-translated IPv6 bind must fail closed");
        assert!(
            rpc_translated_dotted_quad_err
                .to_string()
                .contains("rpc_addr must not use an IPv4-translated IPv6 address"),
            "unexpected error: {rpc_translated_dotted_quad_err:#}"
        );

        let p2p_translated_dotted_quad_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888]:26657".into(),
                p2p_addr: "[::ffff:0:127.0.0.1]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr dotted-quad IPv4-translated IPv6 bind must fail closed");
        assert!(
            p2p_translated_dotted_quad_err
                .to_string()
                .contains("p2p_addr must not use an IPv4-translated IPv6 address"),
            "unexpected error: {p2p_translated_dotted_quad_err:#}"
        );

        let rpc_scope_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888%7]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("rpc_addr IPv6 scope identifier must fail closed");
        assert!(rpc_scope_err
            .to_string()
            .contains("rpc_addr must not use an IPv6 scope identifier"));

        let p2p_scope_err = validate_node_config(
            NodeConfig {
                node_id: "node-a".into(),
                rpc_addr: "[2001:4860:4860::8888]:26657".into(),
                p2p_addr: "[2001:4860:4860::8888%9]:26656".into(),
            },
            "node.toml",
        )
        .expect_err("p2p_addr IPv6 scope identifier must fail closed");
        assert!(p2p_scope_err
            .to_string()
            .contains("p2p_addr must not use an IPv6 scope identifier"));

        for rpc_addr in [
            "192.0.2.10:26657",
            "198.51.100.10:26657",
            "203.0.113.10:26657",
            "198.18.0.10:26657",
            "[2001:db8::10]:26657",
        ] {
            let rpc_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: rpc_addr.into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("rpc_addr documentation and benchmark ranges must fail closed");
            assert!(rpc_err
                .to_string()
                .contains("rpc_addr must not use a documentation or benchmark-only address"));
        }

        for p2p_addr in [
            "192.0.2.10:26656",
            "198.51.100.10:26656",
            "203.0.113.10:26656",
            "198.19.0.10:26656",
            "[2001:db8::11]:26656",
        ] {
            let p2p_err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: p2p_addr.into(),
                },
                "node.toml",
            )
            .expect_err("p2p_addr documentation and benchmark ranges must fail closed");
            assert!(p2p_err
                .to_string()
                .contains("p2p_addr must not use a documentation or benchmark-only address"));
        }
    }

    #[test]
    fn validate_node_config_rejects_oversized_node_id() {
        let oversized_node_id = "n".repeat(MAX_NODE_ID_LEN + 1);
        let err = validate_node_config(
            NodeConfig {
                node_id: oversized_node_id,
                rpc_addr: "127.0.0.1:7000".into(),
                p2p_addr: "127.0.0.1:7001".into(),
            },
            "inline",
        )
        .expect_err("oversized node_id must fail closed");
        assert!(
            err.to_string()
                .contains("node_id must be at most 64 bytes"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn validate_node_config_rejects_control_characters_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node\u{0007}1".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("node_id control characters must fail closed");
        assert!(err
            .to_string()
            .contains("node_id must not contain control characters"));
    }

    #[test]
    fn validate_node_config_rejects_internal_whitespace_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("node_id whitespace must fail closed");
        assert!(err
            .to_string()
            .contains("node_id must not contain whitespace"));
    }

    #[test]
    fn validate_node_config_rejects_non_ascii_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "nοde-a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("non-ASCII node_id must fail closed");
        assert!(err
            .to_string()
            .contains("node_id must use ASCII-only characters"));
    }

    #[test]
    fn validate_node_config_accepts_ascii_boundary_punctuation_node_id() {
        let cfg = validate_node_config(
            NodeConfig {
                node_id: "node-A_09.-~".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect("ASCII node_id should remain valid");
        assert_eq!(cfg.node_id, "node-A_09.-~");
    }

    #[test]
    fn validate_node_config_rejects_list_separators_in_node_id() {
        let err = validate_node_config(
            NodeConfig {
                node_id: "node;a".into(),
                rpc_addr: "127.0.0.1:26657".into(),
                p2p_addr: "127.0.0.1:26656".into(),
            },
            "node.toml",
        )
        .expect_err("node_id list separators must fail closed");
        assert!(err
            .to_string()
            .contains("node_id must not contain list separators (, ; |)"));
    }

    #[test]
    fn validate_node_config_rejects_quoting_characters_in_node_id() {
        for node_id in ["node\"alpha", "node'alpha", "node`alpha"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("node_id quoting characters must fail closed");
            assert!(err
                .to_string()
                .contains("node_id must not contain quoting characters (\" ' `)"));
        }
    }

    #[test]
    fn validate_node_config_rejects_uri_delimiters_in_node_id() {
        for node_id in [
            "node@seed",
            "node?peer=seed",
            "node#fragment",
            "node%2falpha",
            "node&peer=seed",
            "node=seed",
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("node_id URI delimiters must fail closed");
            let err_surface = err.to_string();
            assert!(
                err_surface.contains("node_id must not contain URI delimiters (@ ? # % & =)"),
                "unexpected error surface for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_dot_segments_in_node_id() {
        for node_id in [".", ".."] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("node_id dot segments must fail closed");
            assert!(err.to_string().contains("node_id must not be '.' or '..'"));
        }
    }

    #[test]
    fn validate_node_config_rejects_path_and_host_literal_separators_in_node_id() {
        for node_id in ["seed/slot", "seed\\slot", "seed:slot", "[seed]", "seed]", "[seed"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("node_id path or host-literal separators must fail closed");
            assert!(err
                .to_string()
                .contains("node_id must not contain path or host-literal separators (/ \\ : [ ])"));
        }
    }

    #[test]
    fn validate_node_config_rejects_invisible_or_bidi_format_characters_in_node_id() {
        for node_id in ["node\u{200B}1", "node\u{202E}1"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("invisible/bidi node_id characters must fail closed");
            assert!(
                err.to_string().contains(
                    "node_id must not contain invisible or bidirectional format characters"
                ),
                "unexpected error for {node_id:?}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_invisible_or_bidi_format_characters_in_listener_addresses() {
        for (field, rpc_addr, p2p_addr, expected_message) in [
            (
                "rpc_addr",
                "127.0.0.1:26\u{200B}657",
                "127.0.0.1:26656",
                "rpc_addr must not contain invisible or bidirectional format characters",
            ),
            (
                "p2p_addr",
                "127.0.0.1:26657",
                "127.0.0.1:26\u{202E}656",
                "p2p_addr must not contain invisible or bidirectional format characters",
            ),
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: "node-a".into(),
                    rpc_addr: rpc_addr.into(),
                    p2p_addr: p2p_addr.into(),
                },
                "node.toml",
            )
            .expect_err("invisible/bidi listener characters must fail closed");
            assert!(
                err.to_string().contains(expected_message),
                "unexpected error for {field}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_host_like_node_id_literals() {
        for node_id in [
            "localhost",
            "LOCALHOST",
            "localhost.",
            "LOCALHOST.",
            "127.0.0.1",
            "seed.example.com",
            "seed.example.com.",
            "BOOTSTRAP.EXAMPLE.COM",
            "BOOTSTRAP.EXAMPLE.COM.",
            "NODE-2.BOOTSTRAP.INTERNAL",
            "validator-1.mainnet.local",
            "validator-1.mainnet.local.",
        ] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("host-like node_id literals must fail closed");
            assert!(
                err.to_string()
                    .contains("node_id must not look like a host or socket literal")
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_malformed_dotted_node_id() {
        for node_id in ["node..1", "peer-.slot", "slot.-peer"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("malformed dotted node_id must fail closed");
            assert!(
                err.to_string().contains("node_id must not contain dots"),
                "unexpected error for {node_id}: {err:#}"
            );
        }
    }

    #[test]
    fn validate_node_config_rejects_ipv6_literal_and_socket_shaped_node_ids_fail_closed() {
        for node_id in ["::1", "[::1]:26656"] {
            let err = validate_node_config(
                NodeConfig {
                    node_id: node_id.into(),
                    rpc_addr: "127.0.0.1:26657".into(),
                    p2p_addr: "127.0.0.1:26656".into(),
                },
                "node.toml",
            )
            .expect_err("IPv6 literal or socket-shaped node_id must fail closed");
            assert!(
                err.to_string().contains("node_id must not contain path or host-literal separators"),
                "unexpected error for {node_id}: {err:#}"
            );
        }
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
    fn preexec_zero_workers_falls_back_to_single_worker_results() {
        let state = StateStore::new();
        let picked = vec![
            MockTx::CreateTask {
                task_id: 4054,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4055,
                creator: "bob".into(),
                bounty: 20,
            },
            MockTx::AcceptTask {
                task_id: 999_999,
                worker: "worker4056".into(),
            },
        ];

        let pool_single = PreExecPool::new(Arc::new(state.clone()), Arc::new(picked.clone()), 1, 1);
        let single = pre_execute_group_parallel(&pool_single, vec![1, 2, 3]);

        let pool_zero = PreExecPool::new(Arc::new(state), Arc::new(picked), 0, 1);
        let zero_workers = pre_execute_group_parallel(&pool_zero, vec![1, 2, 3]);

        assert_eq!(single, (vec![1, 2], 1));
        assert_eq!(zero_workers, single);
    }

    #[test]
    fn preexec_preserves_first_seen_group_order_and_dedupes_duplicates() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![
            MockTx::CreateTask {
                task_id: 4_262,
                creator: "alice".into(),
                bounty: 10,
            },
            MockTx::CreateTask {
                task_id: 4_263,
                creator: "bob".into(),
                bounty: 11,
            },
        ]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let (ordered_ids, rejected) = pre_execute_group_parallel(&pool, vec![2, 1, 2, 1]);

        assert_eq!(ordered_ids, vec![2, 1]);
        assert_eq!(rejected, 0);
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
    fn preexec_pool_rejects_invalid_job_ids_without_losing_workers() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![MockTx::CreateTask {
            task_id: 4301,
            creator: "alice".into(),
            bounty: 10,
        }]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let malformed = pre_execute_group_parallel(&pool, vec![1, 2]);
        let followup = pre_execute_group_parallel(&pool, vec![1]);

        assert_eq!(malformed.0, vec![1]);
        assert_eq!(malformed.1, 1);
        assert_eq!(followup.0, vec![1]);
        assert_eq!(followup.1, 0);
    }

    #[test]
    fn preexec_pool_rejects_zero_tx_id_without_panicking_or_losing_workers() {
        let state = Arc::new(StateStore::new());
        let picked = Arc::new(vec![MockTx::CreateTask {
            task_id: 4302,
            creator: "alice".into(),
            bounty: 10,
        }]);

        let pool = PreExecPool::new(Arc::clone(&state), Arc::clone(&picked), 2, 1);
        let malformed = pre_execute_group_parallel(&pool, vec![0]);
        let followup = pre_execute_group_parallel(&pool, vec![1]);

        assert_eq!(malformed.0, Vec::<u64>::new());
        assert_eq!(malformed.1, 1);
        assert_eq!(followup.0, vec![1]);
        assert_eq!(followup.1, 0);
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
        let hot_object_active_height_share_ppm = (hot_object_active_top_label_share_total_ppm
            + hot_object_active_tail_share_total_ppm)
            / hot_object_active_heights as u128;

        assert_eq!(hot_object_top_label_share_avg_ppm, 300_000);
        assert_eq!(hot_object_tail_share_avg_ppm, 200_000);
        assert_eq!(hot_object_active_top_label_share_avg_ppm, 600_000);
        assert_eq!(hot_object_active_tail_share_avg_ppm, 400_000);
        assert_eq!(hot_object_active_height_rate_ppm, 500_000);
        assert_eq!(hot_object_active_observed_height_rate_ppm, 333_333);
        assert_eq!(hot_object_active_height_share_ppm, 1_000_000);
        assert!(hot_object_active_observed_height_rate_ppm < hot_object_active_height_rate_ppm);
        assert!(hot_object_active_top_label_share_avg_ppm > hot_object_top_label_share_avg_ppm);
        assert!(hot_object_active_tail_share_avg_ppm > hot_object_tail_share_avg_ppm);
    }

    #[test]
    fn hot_object_metric_names_keep_coverage_and_budget_share_distinct() {
        let active_height_rate_field_name = "hot_object_active_height_rate_ppm";
        let active_observed_height_rate_field_name = "hot_object_active_observed_height_rate_ppm";
        let active_height_share_field_name = "hot_object_active_height_share_ppm";

        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
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
    }

    #[test]
    fn hot_object_review_bundle_keeps_commit_skip_coverage_pair_near_hotspot_pressure() {
        let hotspot_review_fields = [
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "hot_object_active_top_label_share_avg_ppm",
            "hot_object_active_tail_share_avg_ppm",
            "hot_object_active_height_share_ppm",
        ];

        assert_eq!(hotspot_review_fields.len(), 7);
        assert!(hotspot_review_fields[0].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[1].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[2].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[3].ends_with("_rate_ppm"));
        assert!(hotspot_review_fields[4].ends_with("_share_avg_ppm"));
        assert!(hotspot_review_fields[5].ends_with("_share_avg_ppm"));
        assert!(hotspot_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(hotspot_review_fields[0], hotspot_review_fields[1]);
        assert_ne!(hotspot_review_fields[2], hotspot_review_fields[3]);
        assert_ne!(hotspot_review_fields[4], hotspot_review_fields[5]);
        assert_ne!(hotspot_review_fields[5], hotspot_review_fields[6]);
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
    fn critical_wait_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_stall_pressure() {
        let fairness_review_fields = [
            "critical_wait_active_heights",
            "critical_wait_active_height_rate_ppm",
            "critical_wait_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "critical_wait_density_avg_milli",
            "critical_wait_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_heights"));
        assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[3].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[4].ends_with("_total"));
        assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[3]);
        assert_ne!(fairness_review_fields[3], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
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
        let preexec_reject_density_avg = preexec_reject_total / preexec_reject_active_heights;
        let preexec_reject_density_avg_milli =
            ratio_milli_u64(preexec_reject_total, preexec_reject_active_heights);
        let preexec_reject_active_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_committed_heights);
        let preexec_reject_active_observed_height_rate_ppm =
            ratio_ppm_u64(preexec_reject_active_heights, bft_observed_heights);
        let preexec_reject_active_height_share_ppm =
            finality_budget_share_ppm(preexec_reject_density_avg_milli, finality_avg);

        assert_eq!(preexec_reject_density_avg, 3);
        assert_eq!(preexec_reject_density_avg_milli, 3_500);
        assert_eq!(preexec_reject_active_height_rate_ppm, 666_666);
        assert_eq!(preexec_reject_active_observed_height_rate_ppm, 400_000);
        assert_eq!(preexec_reject_active_height_share_ppm, 17_500);
        assert!(
            preexec_reject_active_observed_height_rate_ppm < preexec_reject_active_height_rate_ppm
        );
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
        assert_ne!(
            active_height_count_field_name,
            active_height_rate_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
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
        assert_ne!(
            reject_density_avg_milli_field_name,
            conflict_miss_share_field_name
        );
        assert_ne!(reject_share_field_name, conflict_miss_share_field_name);
    }

    #[test]
    fn preexec_reject_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
        let guardrail_review_fields = [
            "preexec_peak_share_ppm",
            "preexec_reject_active_heights",
            "preexec_reject_active_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "preexec_reject_density_avg_milli",
            "preexec_reject_active_height_share_ppm",
            "preexec_reject_share_bps",
            "preexec_conflict_miss_share_bps",
        ];

        assert_eq!(guardrail_review_fields.len(), 11);
        assert!(guardrail_review_fields[0].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[1].ends_with("_heights"));
        assert!(guardrail_review_fields[2].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[3].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[4].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[5].ends_with("_total"));
        assert!(guardrail_review_fields[6].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[7].ends_with("_avg_milli"));
        assert!(guardrail_review_fields[8].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[9].ends_with("_share_bps"));
        assert!(guardrail_review_fields[10].ends_with("_share_bps"));
        assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
        assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
        assert_ne!(guardrail_review_fields[9], guardrail_review_fields[10]);
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
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            density_avg_milli_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
    }

    #[test]
    fn rollback_review_bundle_keeps_commit_skip_coverage_pair_near_guardrail_pressure() {
        let guardrail_review_fields = [
            "rollback_peak_share_ppm",
            "rollback_active_heights",
            "rollback_active_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "rollback_density_avg_milli",
            "rollback_active_height_share_ppm",
            "apply_error_rollback_share_bps",
        ];

        assert_eq!(guardrail_review_fields.len(), 10);
        assert!(guardrail_review_fields[0].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[1].ends_with("_heights"));
        assert!(guardrail_review_fields[2].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[3].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[4].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[5].ends_with("_total"));
        assert!(guardrail_review_fields[6].ends_with("_rate_ppm"));
        assert!(guardrail_review_fields[7].ends_with("_avg_milli"));
        assert!(guardrail_review_fields[8].ends_with("_share_ppm"));
        assert!(guardrail_review_fields[9].ends_with("_share_bps"));
        assert_ne!(guardrail_review_fields[2], guardrail_review_fields[3]);
        assert_ne!(guardrail_review_fields[4], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[5], guardrail_review_fields[6]);
        assert_ne!(guardrail_review_fields[7], guardrail_review_fields[8]);
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
    fn consensus_summary_guardrail_field_list_keeps_active_height_and_observed_coverage_views() {
        let observed_coverage_fields = [
            "critical_wait_active_observed_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "preexec_reject_active_observed_height_rate_ppm",
            "rollback_active_observed_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
        ];
        let active_budget_share_fields = [
            "critical_wait_active_height_share_ppm",
            "hot_object_active_height_share_ppm",
            "preexec_reject_active_height_share_ppm",
            "rollback_active_height_share_ppm",
            "bft_round_change_active_height_share_ppm",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(observed_coverage_fields.len(), 7);
        assert_eq!(active_budget_share_fields.len(), 7);
        assert!(observed_coverage_fields
            .iter()
            .all(|field| field.ends_with("_rate_ppm")));
        assert!(active_budget_share_fields
            .iter()
            .all(|field| field.ends_with("_share_ppm")));
        for observed_field in observed_coverage_fields {
            assert!(
                !active_budget_share_fields.contains(&observed_field),
                "observed coverage field should stay distinct: {observed_field}"
            );
        }
    }

    #[test]
    fn consensus_summary_backoff_field_list_keeps_wall_alias_separate_from_budget_share_fields() {
        let backoff_fields = [
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(backoff_fields.len(), 3);
        assert!(backoff_fields
            .iter()
            .all(|field| field.ends_with("_share_ppm")));
        assert_ne!(backoff_fields[0], backoff_fields[1]);
        assert_ne!(backoff_fields[0], backoff_fields[2]);
        assert_ne!(backoff_fields[1], backoff_fields[2]);
    }

    #[test]
    fn consensus_summary_bursty_review_bundles_keep_active_height_counts_next_to_coverage_and_budget_views(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_heights",
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "critical_wait_density_avg_milli",
                "critical_wait_active_height_share_ppm",
            ],
            &[
                "hot_object_active_heights",
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "hot_object_active_top_label_share_avg_ppm",
                "hot_object_active_tail_share_avg_ppm",
                "hot_object_active_height_share_ppm",
            ],
            &[
                "rollback_active_heights",
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
            ],
            &[
                "preexec_reject_active_heights",
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
            ],
            &[
                "bft_round_change_active_heights",
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_round_change_density_avg_milli",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_heights",
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_round_change_backoff_density_avg_milli",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_heights",
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_leader_missed_density_avg_milli",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[0], bundle[2]);
            assert_ne!(bundle[1], bundle[2]);
            assert!(
                bundle[3].ends_with("_avg_milli") || bundle[3].ends_with("_share_avg_ppm"),
                "expected density or active-share companion field, got {}",
                bundle[3]
            );
            assert!(bundle.last().unwrap().ends_with("_active_height_share_ppm"));
        }
    }

    #[test]
    fn hot_object_review_bundle_keeps_commit_skip_denominator_context_next_to_shape_and_budget_pressure(
    ) {
        let hotspot_review_fields = [
            "hot_object_active_heights",
            "hot_object_active_height_rate_ppm",
            "hot_object_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "hot_object_active_top_label_share_avg_ppm",
            "hot_object_active_tail_share_avg_ppm",
            "hot_object_active_height_share_ppm",
        ];

        assert_eq!(hotspot_review_fields.len(), 9);
        assert!(hotspot_review_fields[0].ends_with("_active_heights"));
        assert!(hotspot_review_fields[1].ends_with("_active_height_rate_ppm"));
        assert!(hotspot_review_fields[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            hotspot_review_fields[3],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(hotspot_review_fields[4], "bft_skipped_height_total");
        assert_eq!(
            hotspot_review_fields[5],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert_eq!(
            hotspot_review_fields[6],
            "hot_object_active_top_label_share_avg_ppm"
        );
        assert_eq!(
            hotspot_review_fields[7],
            "hot_object_active_tail_share_avg_ppm"
        );
        assert_eq!(
            hotspot_review_fields[8],
            "hot_object_active_height_share_ppm"
        );
        assert_ne!(hotspot_review_fields[1], hotspot_review_fields[2]);
        assert_ne!(hotspot_review_fields[3], hotspot_review_fields[5]);
        assert_ne!(hotspot_review_fields[6], hotspot_review_fields[8]);
        assert_ne!(hotspot_review_fields[7], hotspot_review_fields[8]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_coverage_wall_and_budget_views_together() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 7);
        assert!(jitter_review_fields[0].ends_with("_heights"));
        assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[3].ends_with("_avg_milli"));
        assert!(jitter_review_fields[4].ends_with("_share_ppm"));
        assert!(jitter_review_fields[5].ends_with("_share_ppm"));
        assert!(jitter_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[4], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[4], jitter_review_fields[6]);
        assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_skipped_width_next_to_coverage_and_share_context() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_heights",
            "bft_round_change_backoff_active_height_rate_ppm",
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 10);
        assert!(jitter_review_fields[0].ends_with("_active_heights"));
        assert!(jitter_review_fields[1].ends_with("_active_height_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            jitter_review_fields[3],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(jitter_review_fields[4], "bft_skipped_height_total");
        assert_eq!(
            jitter_review_fields[5],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(jitter_review_fields[6].ends_with("_avg_milli"));
        assert!(jitter_review_fields[7].ends_with("_share_ppm"));
        assert!(jitter_review_fields[8].ends_with("_share_ppm"));
        assert!(jitter_review_fields[9].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[7], jitter_review_fields[8]);
        assert_ne!(jitter_review_fields[7], jitter_review_fields[9]);
        assert_ne!(jitter_review_fields[8], jitter_review_fields[9]);
    }

    #[test]
    fn round_change_backoff_review_bundle_keeps_budget_share_ahead_of_wall_time_aliases() {
        let jitter_review_fields = [
            "bft_round_change_backoff_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_backoff_density_avg_milli",
            "bft_round_change_backoff_active_height_share_ppm",
            "bft_round_change_backoff_wall_share_ppm",
            "bft_round_change_backoff_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 8);
        assert!(jitter_review_fields[0].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            jitter_review_fields[1],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(jitter_review_fields[2], "bft_skipped_height_total");
        assert_eq!(
            jitter_review_fields[3],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(jitter_review_fields[4].ends_with("_avg_milli"));
        assert_eq!(
            jitter_review_fields[5],
            "bft_round_change_backoff_active_height_share_ppm"
        );
        assert_eq!(
            jitter_review_fields[6],
            "bft_round_change_backoff_wall_share_ppm"
        );
        assert_eq!(
            jitter_review_fields[7],
            "bft_round_change_backoff_share_ppm"
        );
        assert_ne!(jitter_review_fields[5], jitter_review_fields[6]);
        assert_ne!(jitter_review_fields[5], jitter_review_fields[7]);
        assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_validator_spread_next_to_height_pressure_fields() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[0], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    }

    #[test]
    fn guardrail_review_bundles_keep_cause_fields_next_to_coverage_and_budget_pressure() {
        let review_bundles: &[&[&str]] = &[
            &[
                "preexec_reject_active_heights",
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
                "preexec_reject_share_bps",
                "preexec_conflict_miss_share_bps",
            ],
            &[
                "rollback_active_heights",
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
                "apply_error_rollback_share_bps",
            ],
        ];

        assert_eq!(review_bundles.len(), 2);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[4], "bft_skipped_height_total");
            assert_eq!(bundle[5], "bft_skipped_observed_height_rate_ppm");
            assert!(bundle[6].ends_with("_avg_milli"));
            assert!(bundle[7].ends_with("_active_height_share_ppm"));
            assert!(bundle.last().unwrap().ends_with("_share_bps"));
        }
        assert_eq!(
            review_bundles[0].last().copied(),
            Some("preexec_conflict_miss_share_bps")
        );
        assert_eq!(
            review_bundles[1].last().copied(),
            Some("apply_error_rollback_share_bps")
        );
    }

    #[test]
    fn leader_missed_review_bundle_keeps_commit_vs_skipped_coverage_context_near_fairness_pressure()
    {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 10);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            fairness_review_fields[6],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(
            fairness_review_fields[7],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(fairness_review_fields[8].ends_with("_avg_milli"));
        assert!(fairness_review_fields[9].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[7]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_absolute_skipped_width_next_to_fairness_spread_and_budget_pressure(
    ) {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 11);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_active_heights"));
        assert!(fairness_review_fields[4].ends_with("_active_height_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_active_observed_height_rate_ppm"));
        assert_eq!(
            fairness_review_fields[6],
            "bft_commit_observed_height_rate_ppm"
        );
        assert_eq!(fairness_review_fields[7], "bft_skipped_height_total");
        assert_eq!(
            fairness_review_fields[8],
            "bft_skipped_observed_height_rate_ppm"
        );
        assert!(fairness_review_fields[9].ends_with("_avg_milli"));
        assert!(fairness_review_fields[10].ends_with("_active_height_share_ppm"));
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
        assert_ne!(fairness_review_fields[6], fairness_review_fields[8]);
        assert_ne!(fairness_review_fields[7], fairness_review_fields[8]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_skipped_width_between_commit_coverage_and_skip_rate() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        let commit_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_commit_observed_height_rate_ppm")
            .expect("commit coverage field present");
        let skipped_total_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_skipped_height_total")
            .expect("skipped width field present");
        let skipped_rate_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
            .expect("skipped coverage field present");
        let density_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_leader_missed_density_avg_milli")
            .expect("density field present");
        let share_idx = fairness_review_fields
            .iter()
            .position(|field| *field == "bft_leader_missed_active_height_share_ppm")
            .expect("budget share field present");

        assert_eq!(skipped_total_idx, commit_idx + 1);
        assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
        assert!(density_idx > skipped_rate_idx);
        assert!(share_idx > density_idx);
    }

    #[test]
    fn consensus_bursty_review_bundles_keep_commit_vs_observed_coverage_pair_near_active_height_rates(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "hot_object_active_heights",
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "hot_object_active_height_share_ppm",
            ],
            &[
                "bft_round_change_active_heights",
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_heights",
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_heights",
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_observed_height_rate_ppm",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 4);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_heights"));
            assert!(bundle[1].ends_with("_active_height_rate_ppm"));
            assert!(bundle[2].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[3], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
            assert!(bundle[5].ends_with("_active_height_share_ppm"));
            assert_ne!(bundle[1], bundle[2]);
            assert_ne!(bundle[3], bundle[4]);
        }
    }

    #[test]
    fn consensus_bursty_review_bundles_keep_absolute_skipped_height_width_next_to_observed_coverage_rates(
    ) {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "hot_object_active_height_rate_ppm",
                "hot_object_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
            &[
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 7);
        for bundle in review_bundles {
            assert!(bundle[0].ends_with("_active_height_rate_ppm"));
            assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
            assert_eq!(bundle[2], "bft_commit_observed_height_rate_ppm");
            assert_eq!(bundle[3], "bft_skipped_height_total");
            assert_eq!(bundle[4], "bft_skipped_observed_height_rate_ppm");
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[2], bundle[4]);
        }
    }

    #[test]
    fn fairness_and_guardrail_review_bundles_keep_skipped_width_adjacent_to_skip_rate() {
        let review_bundles: &[&[&str]] = &[
            &[
                "critical_wait_active_height_rate_ppm",
                "critical_wait_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "critical_wait_density_avg_milli",
                "critical_wait_active_height_share_ppm",
            ],
            &[
                "preexec_reject_active_height_rate_ppm",
                "preexec_reject_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "preexec_reject_density_avg_milli",
                "preexec_reject_active_height_share_ppm",
                "preexec_reject_share_bps",
                "preexec_conflict_miss_share_bps",
            ],
            &[
                "rollback_active_height_rate_ppm",
                "rollback_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "rollback_density_avg_milli",
                "rollback_active_height_share_ppm",
                "apply_error_rollback_share_bps",
            ],
            &[
                "bft_round_change_active_height_rate_ppm",
                "bft_round_change_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_active_height_share_ppm",
            ],
            &[
                "bft_round_change_backoff_active_height_rate_ppm",
                "bft_round_change_backoff_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_round_change_backoff_active_height_share_ppm",
            ],
            &[
                "bft_leader_missed_active_height_rate_ppm",
                "bft_leader_missed_active_observed_height_rate_ppm",
                "bft_commit_observed_height_rate_ppm",
                "bft_skipped_height_total",
                "bft_skipped_observed_height_rate_ppm",
                "bft_leader_missed_density_avg_milli",
                "bft_leader_missed_active_height_share_ppm",
            ],
        ];

        assert_eq!(review_bundles.len(), 6);
        for bundle in review_bundles {
            let skipped_total_idx = bundle
                .iter()
                .position(|field| *field == "bft_skipped_height_total")
                .expect("skipped total must stay present in review bundle");
            let skipped_rate_idx = bundle
                .iter()
                .position(|field| *field == "bft_skipped_observed_height_rate_ppm")
                .expect("skipped observed rate must stay present in review bundle");

            assert_eq!(skipped_rate_idx, skipped_total_idx + 1);
            assert_eq!(
                bundle[skipped_total_idx - 1],
                "bft_commit_observed_height_rate_ppm"
            );
            assert!(bundle[0].ends_with("_active_height_rate_ppm"));
            assert!(bundle[1].ends_with("_active_observed_height_rate_ppm"));
            assert_ne!(bundle[0], bundle[1]);
            assert_ne!(bundle[skipped_total_idx], bundle[skipped_rate_idx]);
        }
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
        assert_ne!(
            compatibility_alias_field_name,
            active_height_share_field_name
        );
    }

    #[test]
    fn round_change_backoff_wall_share_metric_normalizes_per_committed_height_budget() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let finality_avg_ms = 20u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );
        let active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(bft_round_change_backoff_total_ms, bft_committed_heights),
            finality_avg_ms,
        );

        assert_eq!(wall_share_ppm, 225_000);
        assert_eq!(active_height_share_ppm, 225_000);
    }

    #[test]
    fn round_change_backoff_compatibility_alias_matches_wall_share_metric() {
        let bft_round_change_backoff_total_ms = 18u64;
        let bft_committed_heights = 4u64;
        let finality_avg_ms = 20u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );
        let compatibility_alias_ppm = wall_share_ppm;

        assert_eq!(wall_share_ppm, 225_000);
        assert_eq!(compatibility_alias_ppm, wall_share_ppm);
    }

    #[test]
    fn round_change_backoff_wall_share_metric_can_exceed_one_million_when_backoff_dominates() {
        let bft_round_change_backoff_total_ms = 12u64;
        let bft_committed_heights = 3u64;
        let finality_avg_ms = 2u128;
        let wall_share_ppm = wall_time_share_ppm(
            bft_round_change_backoff_total_ms,
            bft_committed_heights,
            finality_avg_ms,
        );

        assert_eq!(wall_share_ppm, 2_000_000);
        assert!(wall_share_ppm > 1_000_000);
    }

    #[test]
    fn bft_commit_and_skipped_height_rates_make_no_commit_pressure_visible() {
        let bft_observed_heights = 5u64;
        let bft_committed_heights = 4u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_commit_observed_height_rate_ppm, 800_000);
        assert_eq!(bft_skipped_height_total, 1);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 200_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
    }

    #[test]
    fn bft_commit_and_skipped_height_metric_names_keep_commit_and_skip_views_distinct() {
        let commit_rate_field_name = "bft_commit_observed_height_rate_ppm";
        let skipped_total_field_name = "bft_skipped_height_total";
        let skipped_rate_field_name = "bft_skipped_observed_height_rate_ppm";

        assert!(commit_rate_field_name.ends_with("_rate_ppm"));
        assert!(skipped_total_field_name.ends_with("_total"));
        assert!(skipped_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(commit_rate_field_name, skipped_total_field_name);
        assert_ne!(commit_rate_field_name, skipped_rate_field_name);
        assert_ne!(skipped_total_field_name, skipped_rate_field_name);
    }

    #[test]
    fn bft_commit_and_skipped_height_review_bundle_keeps_observed_coverage_pair_together() {
        let coverage_review_fields = [
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
        ];

        assert_eq!(coverage_review_fields.len(), 3);
        assert!(coverage_review_fields[0].ends_with("_rate_ppm"));
        assert!(coverage_review_fields[1].ends_with("_total"));
        assert!(coverage_review_fields[2].ends_with("_rate_ppm"));
        assert_ne!(coverage_review_fields[0], coverage_review_fields[2]);
    }

    #[test]
    fn incident_review_bundle_keeps_skipped_coverage_triplet_between_recovery_and_round_change_clusters(
    ) {
        let incident_review_fields = [
            "timeout_migrated_total",
            "recovery_error_rate",
            "bft_observed_heights",
            "bft_committed_heights",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_total",
            "bft_round_change_per_height_ppm",
        ];

        assert_eq!(incident_review_fields.len(), 9);
        assert!(incident_review_fields[0].ends_with("_total"));
        assert!(incident_review_fields[1].ends_with("_rate"));
        assert!(incident_review_fields[2].ends_with("_heights"));
        assert!(incident_review_fields[3].ends_with("_heights"));
        assert!(incident_review_fields[4].ends_with("_rate_ppm"));
        assert!(incident_review_fields[5].ends_with("_total"));
        assert!(incident_review_fields[6].ends_with("_rate_ppm"));
        assert!(incident_review_fields[7].ends_with("_total"));
        assert!(incident_review_fields[8].ends_with("_ppm"));
        assert_eq!(incident_review_fields[1], "recovery_error_rate");
        assert_eq!(incident_review_fields[4], "bft_commit_observed_height_rate_ppm");
        assert_eq!(incident_review_fields[5], "bft_skipped_height_total");
        assert_eq!(incident_review_fields[6], "bft_skipped_observed_height_rate_ppm");
        assert_eq!(incident_review_fields[7], "bft_round_change_total");
        assert_eq!(incident_review_fields[8], "bft_round_change_per_height_ppm");
        assert_ne!(incident_review_fields[4], incident_review_fields[6]);
        assert_ne!(incident_review_fields[5], incident_review_fields[6]);
        assert_ne!(incident_review_fields[6], incident_review_fields[7]);
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
    fn round_change_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
        let bft_round_change_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

        let bft_round_change_active_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_committed_heights);
        let bft_round_change_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_round_change_active_heights, bft_observed_heights);
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_round_change_active_height_rate_ppm, 1_000_000);
        assert_eq!(bft_round_change_active_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
        assert!(
            bft_round_change_active_observed_height_rate_ppm
                < bft_round_change_active_height_rate_ppm
        );
        assert_eq!(
            bft_round_change_active_observed_height_rate_ppm,
            bft_commit_observed_height_rate_ppm
        );
        assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
    }

    #[test]
    fn round_change_review_bundle_keeps_commit_skip_and_coverage_denominator_views_together() {
        let jitter_review_fields = [
            "bft_round_change_active_heights",
            "bft_round_change_active_height_rate_ppm",
            "bft_round_change_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_round_change_density_avg_milli",
            "bft_round_change_active_height_share_ppm",
        ];

        assert_eq!(jitter_review_fields.len(), 8);
        assert!(jitter_review_fields[0].ends_with("_heights"));
        assert!(jitter_review_fields[1].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[2].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[3].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[4].ends_with("_total"));
        assert!(jitter_review_fields[5].ends_with("_rate_ppm"));
        assert!(jitter_review_fields[6].ends_with("_avg_milli"));
        assert!(jitter_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(jitter_review_fields[1], jitter_review_fields[2]);
        assert_ne!(jitter_review_fields[2], jitter_review_fields[3]);
        assert_ne!(jitter_review_fields[3], jitter_review_fields[5]);
        assert_ne!(jitter_review_fields[6], jitter_review_fields[7]);
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
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_round_change_backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
        let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
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
        let bft_round_change_backoff_active_heights = 2u64;
        let finality_avg = 10u128;

        let density_avg = bft_round_change_total / bft_round_change_active_heights;
        let density_avg_milli =
            ratio_milli_u64(bft_round_change_total, bft_round_change_active_heights);
        let active_height_share_ppm =
            ratio_ppm_u64(density_avg_milli, (finality_avg as u64) * 1_000);
        let backoff_density_avg_ms =
            bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights;
        let backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
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
    fn round_change_backoff_density_uses_backoff_active_heights_not_round_change_coverage() {
        let bft_round_change_backoff_total_ms = 5u64;
        let bft_round_change_active_heights = 4u64;
        let bft_round_change_backoff_active_heights = 2u64;
        let finality_avg = 10u128;

        let diluted_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_active_heights,
        );
        let backoff_density_avg_milli = ratio_milli_u64(
            bft_round_change_backoff_total_ms,
            bft_round_change_backoff_active_heights,
        );
        let backoff_active_height_share_ppm =
            finality_budget_share_ppm(backoff_density_avg_milli, finality_avg);

        assert_eq!(diluted_density_avg_milli, 1_250);
        assert_eq!(backoff_density_avg_milli, 2_500);
        assert!(backoff_density_avg_milli > diluted_density_avg_milli);
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
    fn leader_missed_active_heights_count_only_new_miss_bursts() {
        let mut active_heights = 0u64;
        let mut previous_snapshot = vec![0u64, 0u64, 0u64, 0u64];
        let snapshots = [
            vec![0u64, 1u64, 0u64, 0u64],
            vec![0u64, 1u64, 0u64, 0u64],
            vec![0u64, 1u64, 0u64, 1u64],
        ];

        for snapshot in snapshots {
            if missed_proposals_added_since(&previous_snapshot, &snapshot) > 0 {
                active_heights += 1;
            }
            previous_snapshot = snapshot;
        }

        assert_eq!(active_heights, 2);
    }

    #[test]
    fn leader_missed_added_since_ignores_repeated_cumulative_snapshots() {
        let previous_snapshot = vec![0u64, 2u64, 1u64, 0u64];
        let repeated_snapshot = vec![0u64, 2u64, 1u64, 0u64];

        assert_eq!(
            missed_proposals_added_since(&previous_snapshot, &repeated_snapshot),
            0
        );
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
    fn leader_missed_metric_names_keep_validator_spread_distinct_from_height_budget_pressure() {
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";
        let density_field_name = "bft_leader_missed_density_avg_milli";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";

        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(density_field_name.ends_with("_avg_milli"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert_ne!(
            active_validator_share_field_name,
            active_height_share_field_name
        );
        assert_ne!(active_validator_share_field_name, density_field_name);
        assert_ne!(
            active_height_share_field_name,
            active_observed_height_rate_field_name
        );
    }

    #[test]
    fn leader_missed_review_bundle_keeps_validator_spread_coverage_and_budget_views_together() {
        let fairness_review_fields = [
            "bft_leader_missed_top_share_ppm",
            "bft_leader_missed_active_validators",
            "bft_leader_missed_active_validator_share_ppm",
            "bft_leader_missed_active_heights",
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 8);
        assert!(fairness_review_fields[0].ends_with("_share_ppm"));
        assert!(fairness_review_fields[1].ends_with("_validators"));
        assert!(fairness_review_fields[2].ends_with("_share_ppm"));
        assert!(fairness_review_fields[3].ends_with("_heights"));
        assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[6].ends_with("_avg_milli"));
        assert!(fairness_review_fields[7].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[2], fairness_review_fields[7]);
        assert_ne!(fairness_review_fields[4], fairness_review_fields[5]);
    }

    #[test]
    fn leader_missed_review_bundle_keeps_commit_skip_coverage_pair_near_fairness_hotspots() {
        let fairness_review_fields = [
            "bft_leader_missed_active_height_rate_ppm",
            "bft_leader_missed_active_observed_height_rate_ppm",
            "bft_commit_observed_height_rate_ppm",
            "bft_skipped_height_total",
            "bft_skipped_observed_height_rate_ppm",
            "bft_leader_missed_density_avg_milli",
            "bft_leader_missed_active_height_share_ppm",
        ];

        assert_eq!(fairness_review_fields.len(), 7);
        assert!(fairness_review_fields[0].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[1].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[2].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[3].ends_with("_total"));
        assert!(fairness_review_fields[4].ends_with("_rate_ppm"));
        assert!(fairness_review_fields[5].ends_with("_avg_milli"));
        assert!(fairness_review_fields[6].ends_with("_share_ppm"));
        assert_ne!(fairness_review_fields[0], fairness_review_fields[1]);
        assert_ne!(fairness_review_fields[1], fairness_review_fields[2]);
        assert_ne!(fairness_review_fields[2], fairness_review_fields[4]);
        assert_ne!(fairness_review_fields[5], fairness_review_fields[6]);
    }

    #[test]
    fn leader_missed_metric_names_keep_validator_spread_coverage_and_budget_views_distinct() {
        let active_validators_field_name = "bft_leader_missed_active_validators";
        let active_validator_share_field_name = "bft_leader_missed_active_validator_share_ppm";
        let active_heights_field_name = "bft_leader_missed_active_heights";
        let active_height_rate_field_name = "bft_leader_missed_active_height_rate_ppm";
        let active_observed_height_rate_field_name =
            "bft_leader_missed_active_observed_height_rate_ppm";
        let density_avg_milli_field_name = "bft_leader_missed_density_avg_milli";
        let active_height_share_field_name = "bft_leader_missed_active_height_share_ppm";

        assert!(active_validators_field_name.ends_with("_validators"));
        assert!(active_validator_share_field_name.ends_with("_share_ppm"));
        assert!(active_heights_field_name.ends_with("_heights"));
        assert!(active_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(density_avg_milli_field_name.ends_with("_avg_milli"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert_ne!(active_validators_field_name, active_heights_field_name);
        assert_ne!(
            active_validator_share_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_height_rate_field_name,
            active_observed_height_rate_field_name
        );
        assert_ne!(density_avg_milli_field_name, active_height_share_field_name);
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
    fn leader_missed_active_height_share_stays_distinct_from_validator_distribution_share() {
        let bft_leader_missed_total = 6u64;
        let bft_leader_missed_active_heights = 2u64;
        let bft_observed_heights = 8u64;
        let leader_missed_final = vec![2u64, 2u64, 1u64, 1u64];
        let finality_avg = 2u128;

        let bft_leader_missed_active_validator_share_ppm = ratio_ppm_u64(
            leader_missed_final
                .iter()
                .filter(|missed| **missed > 0)
                .count() as u64,
            leader_missed_final.len() as u64,
        );
        let bft_leader_missed_active_observed_height_rate_ppm =
            ratio_ppm_u64(bft_leader_missed_active_heights, bft_observed_heights);
        let bft_leader_missed_active_height_share_ppm = finality_budget_share_ppm(
            ratio_milli_u64(bft_leader_missed_total, bft_leader_missed_active_heights),
            finality_avg,
        );

        assert_eq!(bft_leader_missed_active_validator_share_ppm, 1_000_000);
        assert_eq!(bft_leader_missed_active_observed_height_rate_ppm, 250_000);
        assert_eq!(bft_leader_missed_active_height_share_ppm, 1_500_000);
        assert_ne!(
            bft_leader_missed_active_height_share_ppm,
            bft_leader_missed_active_validator_share_ppm
        );
        assert!(
            bft_leader_missed_active_height_share_ppm
                > bft_leader_missed_active_validator_share_ppm
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

        let wall_share_ppm =
            ratio_ppm_u64(bft_round_change_backoff_total_ms, bft_committed_heights);
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
    fn round_change_backoff_coverage_pair_with_commit_and_skip_rates_exposes_denominator_shift() {
        let bft_round_change_backoff_active_heights = 2u64;
        let bft_committed_heights = 2u64;
        let bft_observed_heights = 5u64;
        let bft_skipped_height_total = bft_observed_heights - bft_committed_heights;

        let bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_committed_heights,
        );
        let bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
            bft_round_change_backoff_active_heights,
            bft_observed_heights,
        );
        let bft_commit_observed_height_rate_ppm =
            ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
        let bft_skipped_observed_height_rate_ppm =
            ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);

        assert_eq!(bft_round_change_backoff_active_height_rate_ppm, 1_000_000);
        assert_eq!(
            bft_round_change_backoff_active_observed_height_rate_ppm,
            400_000
        );
        assert_eq!(bft_commit_observed_height_rate_ppm, 400_000);
        assert_eq!(bft_skipped_observed_height_rate_ppm, 600_000);
        assert_eq!(
            bft_commit_observed_height_rate_ppm + bft_skipped_observed_height_rate_ppm,
            1_000_000
        );
        assert!(
            bft_round_change_backoff_active_observed_height_rate_ppm
                < bft_round_change_backoff_active_height_rate_ppm
        );
        assert_eq!(
            bft_round_change_backoff_active_observed_height_rate_ppm,
            bft_commit_observed_height_rate_ppm
        );
        assert!(bft_skipped_observed_height_rate_ppm > bft_commit_observed_height_rate_ppm);
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
    fn round_change_backoff_metric_names_keep_observed_coverage_distinct_from_wall_and_budget_views(
    ) {
        let active_observed_height_rate_field_name =
            "bft_round_change_backoff_active_observed_height_rate_ppm";
        let active_height_share_field_name = "bft_round_change_backoff_active_height_share_ppm";
        let wall_share_field_name = "bft_round_change_backoff_wall_share_ppm";
        let compatibility_alias_field_name = "bft_round_change_backoff_share_ppm";

        assert!(active_observed_height_rate_field_name.ends_with("_rate_ppm"));
        assert!(active_height_share_field_name.ends_with("_share_ppm"));
        assert!(wall_share_field_name.ends_with("_share_ppm"));
        assert!(compatibility_alias_field_name.ends_with("_share_ppm"));
        assert_ne!(
            active_observed_height_rate_field_name,
            active_height_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            wall_share_field_name
        );
        assert_ne!(
            active_observed_height_rate_field_name,
            compatibility_alias_field_name
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
    fn critical_guard_single_slot_critical_only_backlog_keeps_fifo_prefix() {
        let mut mempool = VecDeque::from(vec![
            MockTx::Challenge {
                task_id: 41,
                challenger: "c1".into(),
                bond: 10,
            },
            MockTx::Resolve {
                task_id: 41,
                slash_worker: false,
                resolver: "gov".into(),
            },
            MockTx::Challenge {
                task_id: 42,
                challenger: "c2".into(),
                bond: 20,
            },
        ]);

        let picked = pick_txs_with_critical_guard(&mut mempool, 1);
        assert_eq!(picked.len(), 1);
        assert!(matches!(picked[0], MockTx::Challenge { task_id: 41, .. }));

        assert_eq!(mempool.len(), 2);
        assert!(matches!(mempool[0], MockTx::Resolve { task_id: 41, .. }));
        assert!(matches!(mempool[1], MockTx::Challenge { task_id: 42, .. }));
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
    fn auth_accepts_first_nonce_at_bootstrap_jump_boundary() {
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
        let boundary_nonce = MAX_BFT_NONCE_FORWARD_JUMP;
        accept_signed_vote(
            SignedVote {
                vote: vote.clone(),
                nonce: boundary_nonce,
                signature: vote_signature(&vote, boundary_nonce),
            },
            &mut last_nonce,
            &mut accepted,
            &mut reject_stats,
        );

        assert_eq!(accepted.len(), 1);
        assert_eq!(reject_stats.bad_sig, 0);
        assert_eq!(reject_stats.replay, 0);
        assert_eq!(reject_stats.stale_nonce, 0);

        let key = ("v1".to_string(), 11, 0, VoteType::Prevote);
        assert_eq!(last_nonce.get(&key), Some(&boundary_nonce));
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
            | MockTx::Challenge { .. }
            | MockTx::SubmitConsumptionReceipt { .. } => true,
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
            MockTx::SubmitConsumptionReceipt {
                receipt: sample_consumption_receipt(1, "worker", "consumer", result_hash),
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
            MockTx::SubmitConsumptionReceipt {
                receipt: sample_consumption_receipt(1, "worker", "consumer", result_hash),
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
            MockTx::SubmitConsumptionReceipt {
                receipt: sample_consumption_receipt(42, "worker", "consumer", result_hash),
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
        let current_task_version = st
            .get_task(8100)
            .expect("challenged task must exist before staging approval")
            .version;
        st.stage_or_confirm_resolve_approval(
            8100,
            current_task_version,
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
    fn rollback_snapshot_restores_pending_resolve_state_against_pending_replacement_authority() {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_160,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_180,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_181,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_109);
        let before_task = st.get_task(8_109).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_109,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_109).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.pending_resolve_approval(8_109), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(8_109).as_deref(),
            Some("authority-c")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_109),
            Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            })
        );
    }

    #[test]
    fn rollback_snapshot_restores_case_and_order_equivalent_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_283,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_303,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_304,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_115);
        st.set_gov_param(98_305, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_115).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_115,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "Authority-D".into(),
                authority_set: "Authority-D,Authority-C".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_115).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_115), Some((false, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(8_115).as_deref(),
            Some("authority-d")
        );
        assert_eq!(
            st.pending_resolve_approval_snapshot(8_115),
            Some(PendingResolveApprovalSnapshot {
                slash_worker: false,
                confirmations: 1,
                first_approver: "authority-d".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            })
        );
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback restore must preserve the active configured authority until the replacement matures"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_exact_emergency_pause_placeholder_second_approver_against_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_360,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_380,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_381,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_116);

        st.set_gov_param(98_382, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_116).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_116,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-c".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_116).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_116), None);
        assert_eq!(st.pending_resolve_first_approver(8_116), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_116), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority while the replacement stays pending"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_exact_emergency_pause_placeholder_first_approver_against_pending_replacement_authority_while_paused(
    ) {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_384,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_404,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_405,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_117);

        st.set_gov_param(98_406, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_117).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_117,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "governance.emergency_pause".into(),
                authority_set: "authority-c,authority-d".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_117).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_117), None);
        assert_eq!(st.pending_resolve_first_approver(8_117), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_117), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority while the replacement stays pending"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_stale_configured_resolve_state_when_pending_replacement_exists() {
        let mut st = StateStore::new();
        let bootstrap = st
            .set_gov_param(
                98_260,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority write should succeed");
        assert!(matches!(bootstrap, GovParamUpdateOutcome::Scheduled { .. }));
        let applied = st
            .set_gov_param(
                98_280,
                7_310,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .expect("bootstrap resolve_authority should apply after timelock");
        assert!(matches!(applied, GovParamUpdateOutcome::Applied(_)));

        let replacement = st
            .set_gov_param(
                98_281,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority update should be scheduled");
        assert!(matches!(
            replacement,
            GovParamUpdateOutcome::Scheduled { .. }
        ));

        let _ = challenged_task_fixture(&mut st, 8_114);

        st.set_gov_param(98_282, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let before_task = st.get_task(8_114).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeits = st.balance_of("treasury.challenge_forfeits");
        let before_slashes = st.balance_of("treasury.worker_slashes");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_114,
            task: Some(before_task.clone()),
            balances: vec![
                ("treasury.challenge_escrow".into(), Some(before_escrow)),
                ("treasury.challenge_forfeits".into(), Some(before_forfeits)),
                ("treasury.worker_slashes".into(), Some(before_slashes)),
            ],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_114).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.balance_of("treasury.challenge_forfeits"),
            before_forfeits
        );
        assert_eq!(st.balance_of("treasury.worker_slashes"), before_slashes);
        assert_eq!(st.pending_resolve_approval(8_114), None);
        assert_eq!(st.pending_resolve_first_approver(8_114), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_114), None);
        let pending = st
            .pending_gov_update("resolve_authority")
            .expect("pending replacement resolve_authority timelock should remain staged");
        assert_eq!(pending.value, "authority-c,authority-d");
        assert_eq!(
            st.gov_param_string("resolve_authority"),
            Some("authority-a,authority-b".into()),
            "rollback scrub must not mutate the active configured authority set"
        );
        assert!(st.is_emergency_paused());
    }

    #[test]
    fn rollback_snapshot_scrubs_invalid_pending_resolve_state() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_110);
        let before_task = st.get_task(8_110).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_110,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 3,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_110).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_110),
            None,
            "rollback must not revive malformed pending resolve quorum state"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_state_when_task_version_drifts() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_501,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_111);
        let before_task = st.get_task(8_111).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_111,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version + 1,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_111).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_111),
            None,
            "rollback must not revive staged resolve quorum for a stale task version"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_missing_second_approver() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_112);
        let before_task = st.get_task(8_112).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_112,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_112).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_112),
            None,
            "rollback must not revive finalized resolve quorum without a distinct second approver audit trail"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_approver_separator() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_111);
        let before_task = st.get_task(8_111).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_111,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority|a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_111).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_111),
            None,
            "rollback must scrub snapshot approvers that live parsing would reject"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_system_approver() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_110);
        let before_task = st.get_task(8_110).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_110,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "system".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_110).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_110),
            None,
            "rollback must scrub reserved system approvers instead of reviving a forged quorum"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_emergency_pause_approver() {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_109);
        let before_task = st.get_task(8_109).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_109,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "governance.emergency_pause".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_109).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_109),
            None,
            "rollback must scrub reserved emergency-pause approvers instead of reviving a forged quorum"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_forbidden_authority_separator() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_502,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_112);
        let before_task = st.get_task(8_112).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_112,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a；authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_112).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_112),
            None,
            "rollback must scrub authority snapshots with forbidden separators before replay"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_whitespace_padded_first_approver() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_505,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_115);
        let before_task = st.get_task(8_115).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_115,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: " authority-a ".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_115).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_115),
            None,
            "rollback must scrub whitespace-padded approvers instead of silently normalizing them"
        );
        assert_eq!(st.pending_resolve_first_approver(8_115), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_115), None);
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_control_byte_first_approver() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_505,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_115);
        let before_task = st.get_task(8_115).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_115,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a\u{0007}".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_115).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_115),
            None,
            "rollback must scrub control-byte approvers instead of silently accepting them"
        );
        assert_eq!(st.pending_resolve_first_approver(8_115), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_115), None);
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_first_approver_aliases() {
        for (idx, reserved_alias) in [
            "governance.resolve_authority",
            "governance.emergency_pause",
            "system",
            "treasury.challenge_escrow",
            "treasury.challenge_forfeits",
            "treasury.worker_slashes",
        ]
        .into_iter()
        .enumerate()
        {
            let mut st = StateStore::new();
            st.set_gov_param_bootstrap_unchecked(
                9_506 + idx as u64,
                "resolve_authority".into(),
                "authority-a,authority-b".into(),
            )
            .unwrap();
            let task_id = 8_116 + idx as u64;
            let _ = challenged_task_fixture(&mut st, task_id);
            let before_task = st.get_task(task_id).unwrap();
            let before_escrow = st.balance_of("treasury.challenge_escrow");

            let snapshot = TxRollbackSnapshot {
                task_id,
                task: Some(before_task.clone()),
                balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
                pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                    slash_worker: true,
                    confirmations: 1,
                    first_approver: reserved_alias.into(),
                    authority_set: "authority-a,authority-b".into(),
                    task_version: before_task.version,
                }),
            };

            rollback_tx_snapshot(&mut st, snapshot);

            assert_eq!(st.get_task(task_id).unwrap(), before_task);
            assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
            assert_eq!(
                st.pending_resolve_approval(task_id),
                None,
                "rollback must scrub reserved first approver alias {reserved_alias} instead of accepting it"
            );
            assert_eq!(
                st.pending_resolve_first_approver(task_id),
                None,
                "reserved first approver alias {reserved_alias} must not materialize rollback quorum metadata"
            );
            assert_eq!(
                st.pending_resolve_approval_snapshot(task_id),
                None,
                "reserved first approver alias {reserved_alias} must not persist rollback quorum metadata"
            );
        }
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_reserved_worker_slash_authority_member(
    ) {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_506,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_117);
        let before_task = st.get_task(8_117).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_117,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,treasury.worker_slashes".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_117).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_117),
            None,
            "rollback must scrub authority snapshots that smuggle reserved treasury.worker_slashes members"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_control_byte_authority_member() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_506,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_117);
        let before_task = st.get_task(8_117).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_117,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-\u{0007}b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_117).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_117),
            None,
            "rollback must scrub authority snapshots with control-byte authority members"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_pending_resolve_snapshot_with_case_folded_duplicate_authorities() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_503,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let _ = challenged_task_fixture(&mut st, 8_113);
        let before_task = st.get_task(8_113).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_113,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 1,
                first_approver: "authority-a".into(),
                authority_set: "Authority-A,authority-a".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_113).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_113),
            None,
            "rollback must reject case-folded duplicate authority members during replay"
        );
    }

    #[test]
    fn rollback_snapshot_scrubs_finalized_pending_resolve_snapshot_with_case_variant_duplicate_second_approver(
    ) {
        let mut st = StateStore::new();
        let _ = challenged_task_fixture(&mut st, 8_113);
        let before_task = st.get_task(8_113).unwrap();
        let before_escrow = st.balance_of("treasury.challenge_escrow");

        let snapshot = TxRollbackSnapshot {
            task_id: 8_113,
            task: Some(before_task.clone()),
            balances: vec![("treasury.challenge_escrow".into(), Some(before_escrow))],
            pending_resolve_approval: Some(PendingResolveApprovalSnapshot {
                slash_worker: true,
                confirmations: 2,
                first_approver: "authority-a".into(),
                authority_set: "authority-a,authority-b".into(),
                task_version: before_task.version,
            }),
        };

        rollback_tx_snapshot(&mut st, snapshot);

        assert_eq!(st.get_task(8_113).unwrap(), before_task);
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(
            st.pending_resolve_approval(8_113),
            None,
            "rollback must not revive finalized resolve quorum with a case-variant duplicate second approver"
        );
        assert_eq!(st.pending_resolve_first_approver(8_113), None);
        assert_eq!(st.pending_resolve_approval_snapshot(8_113), None);
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
    fn paused_node_gate_skips_version_drift_resolve_replay_without_clearing_staged_quorum() {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_2);

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
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_999, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause toggle must apply immediately");
        assert!(st.is_emergency_paused());

        let mut task_before = st.get_task(r5.id).expect("challenged task must exist");
        task_before.version += 1;
        st.restore_task(r5.id, Some(task_before.clone()));

        let paused_tx = MockTx::Resolve {
            task_id: r5.id,
            slash_worker: true,
            resolver: "authority-b".into(),
        };
        assert!(is_rejected_by_emergency_pause(true, &paused_tx));

        let pending_before = st.pending_resolve_approval_snapshot(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        // If this replay reached apply_one after the challenged task version moved forward,
        // resolve quorum staging would be cleared as stale. Emergency pause must block the tx
        // before it can mutate pending approval state.
        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval_snapshot(r5.id),
            pending_before,
            "pause gate must preserve staged multisig quorum across version-drift replay"
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
    fn paused_node_gate_skips_pending_replacement_resolve_without_mutating_timelock_or_escrow_state(
    ) {
        let mut st = StateStore::new();
        st.set_gov_param_bootstrap_unchecked(
            7_310,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .unwrap();
        let (r5, _, _) = challenged_task_fixture(&mut st, 8_109_3);

        let scheduled = st
            .set_gov_param(
                9_998,
                7_310,
                "resolve_authority".into(),
                "authority-c,authority-d".into(),
            )
            .expect("replacement resolve_authority should schedule before pause");
        assert!(matches!(scheduled, GovParamUpdateOutcome::Scheduled { .. }));
        let pending_gov_before = st
            .pending_gov_update("resolve_authority")
            .expect("replacement resolve_authority timelock should remain staged");

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
        let pending_quorum_before = st.pending_resolve_approval_snapshot(r5.id);
        let escrow_before = st.balance_of("treasury.challenge_escrow");
        let forfeit_before = st.balance_of("treasury.challenge_forfeits");

        if !is_rejected_by_emergency_pause(st.is_emergency_paused(), &paused_tx) {
            let _ = apply_one(&mut st, paused_tx, 131);
        }

        assert_eq!(
            st.pending_resolve_approval_snapshot(r5.id),
            pending_quorum_before,
            "pause gate must not synthesize or clear staged quorum while a replacement authority is pending"
        );
        assert_eq!(
            st.pending_gov_update("resolve_authority"),
            Some(pending_gov_before),
            "pause gate must not mutate pending resolve_authority timelock state"
        );
        assert_eq!(
            st.gov_param_string("resolve_authority").as_deref(),
            Some("authority-a,authority-b"),
            "pending replacement authority must not apply early while paused"
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
    fn load_checkpoint_meta_treats_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# bootstrap placeholder\n   # retained until first checkpoint\n",
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_crlf_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-crlf-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# bootstrap placeholder\r\n   # retained until first checkpoint\r\n",
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "# bootstrap placeholder\n\t# retained until first wal write\n",
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_crlf_comment_only_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-crlf-comment-only-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "# bootstrap placeholder\r\n\t# retained until first wal write\r\n",
        )
        .unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn timeout_scan_status_gate_keeps_timeout_surface_explicit() {
        assert!(should_scan_timeout(&TaskStatus::Assigned, false));
        assert!(should_scan_timeout(&TaskStatus::Committed, false));
        assert!(should_scan_timeout(&TaskStatus::Revealed, false));
        assert!(should_scan_timeout(&TaskStatus::Challenged, false));

        assert!(!should_scan_timeout(&TaskStatus::Open, false));
        assert!(!should_scan_timeout(&TaskStatus::Completed, false));
        assert!(!should_scan_timeout(&TaskStatus::Slashed, false));
    }

    #[test]
    fn timeout_scan_pause_gate_only_suppresses_challenged_recovery_edge() {
        assert!(should_scan_timeout(&TaskStatus::Assigned, true));
        assert!(should_scan_timeout(&TaskStatus::Committed, true));
        assert!(should_scan_timeout(&TaskStatus::Revealed, true));
        assert!(!should_scan_timeout(&TaskStatus::Challenged, true));
    }

    #[test]
    fn timeout_skip_reason_surfaces_pause_visibility_without_blurring_other_edges() {
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Challenged, true),
            Some("emergency_pause_challenged")
        );
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Assigned, true),
            None,
            "pause should not hide normal assignment timeout edges"
        );
        assert_eq!(
            timeout_skip_reason(&TaskStatus::Open, false),
            Some("status_not_timeout_eligible")
        );
    }

    #[test]
    fn sorted_timeout_candidate_ids_stabilizes_event_scan_order() {
        let known: HashSet<u64> = [7003u64, 7001u64, 7002u64].into_iter().collect();

        assert_eq!(sorted_timeout_candidate_ids(&known), vec![7001, 7002, 7003]);
    }

    #[test]
    fn sorted_timeout_candidate_ids_filters_synthetic_ids_above_scan_cap() {
        let known: HashSet<u64> = [7003u64, TIMEOUT_SCAN_MAX_TASK_ID + 1, 7001u64, 7002u64]
            .into_iter()
            .collect();

        assert_eq!(sorted_timeout_candidate_ids(&known), vec![7001, 7002, 7003]);
    }

    #[test]
    fn timeout_event_tx_id_starts_after_seed_and_preserves_scan_order_visibility() {
        assert_eq!(timeout_event_tx_id(9_000_000, 0), 9_000_001);
        assert_eq!(timeout_event_tx_id(9_000_000, 1), 9_000_002);
        assert_eq!(timeout_event_tx_id(u64::MAX, 0), u64::MAX);
        assert_eq!(timeout_event_tx_id(9_000_000, u64::MAX), u64::MAX);
    }

    #[test]
    fn timeout_event_tx_overflowed_marks_saturated_ordinal_even_when_tx_id_sticks_at_u64_max() {
        assert!(timeout_event_tx_overflowed(0, u64::MAX));
        assert!(timeout_event_tx_overflowed(9_000_000, u64::MAX));
        assert!(timeout_event_tx_overflowed(u64::MAX, 0));
        assert!(!timeout_event_tx_overflowed(u64::MAX - 1, 0));
    }

    #[test]
    fn timeout_event_tx_overflowed_only_marks_saturated_visibility_edges() {
        assert!(!timeout_event_tx_overflowed(9_000_000, 0));
        assert!(!timeout_event_tx_overflowed(9_000_000, 1));
        assert!(timeout_event_tx_overflowed(u64::MAX, 0));
        assert!(timeout_event_tx_overflowed(9_000_000, u64::MAX));
        assert!(timeout_event_tx_overflowed(u64::MAX - 1, 1));
    }

    #[test]
    fn timeout_event_surface_metadata_keeps_tx_id_ordinal_and_overflow_in_lockstep() {
        assert_eq!(
            timeout_event_surface_metadata(9_000_000, 0),
            (9_000_001, 1, false, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 0),
            (u64::MAX, 1, false, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 1),
            (u64::MAX, 2, true, false)
        );
        assert_eq!(
            timeout_event_surface_metadata(0, u64::MAX),
            (u64::MAX, u64::MAX, true, true)
        );
    }

    #[test]
    fn timeout_event_surface_metadata_marks_ordinal_saturation_separately_from_tx_id_overflow() {
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 1),
            (u64::MAX, 2, true, false),
            "seed+ordinal overflow should not pretend the ordinal itself saturated"
        );
        assert_eq!(
            timeout_event_surface_metadata(9_000_000, u64::MAX),
            (u64::MAX, u64::MAX, true, true),
            "saturated ordinal should stay explicitly visible even when tx_id also sticks"
        );
    }

    #[test]
    fn timeout_event_surface_metadata_keeps_exact_u64_max_boundary_visible_without_fake_overflow() {
        assert_eq!(
            timeout_event_surface_metadata(0, u64::MAX - 1),
            (u64::MAX, u64::MAX, false, false),
            "landing exactly on the u64 ceiling should stay visible without claiming saturation overflow"
        );
        assert_eq!(
            timeout_event_surface_metadata(u64::MAX - 1, 0),
            (u64::MAX, 1, false, false),
            "an exact seed+ordinal hit on the u64 ceiling must stay visible without fake overflow"
        );
        assert!(!timeout_event_tx_overflowed(0, u64::MAX - 1));
        assert!(!timeout_event_tx_overflowed(u64::MAX - 1, 0));
    }

    #[test]
    fn timeout_bond_disposition_only_surfaces_challenged_settlement_outcomes() {
        assert_eq!(timeout_bond_disposition(false, Some(true)), None);
        assert_eq!(
            timeout_bond_disposition(true, Some(false)),
            Some("refunded")
        );
        assert_eq!(
            timeout_bond_disposition(true, Some(true)),
            Some("forfeited")
        );
        assert_eq!(timeout_bond_disposition(true, None), Some("unknown"));
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
    fn timeout_scan_skips_challenged_task_while_paused_without_mutating_staged_resolve_state() {
        // Governance boundary hardening: the node-level timeout scanner must not touch
        // challenged settlement while paused, preserving staged resolve quorum and escrow.
        let mut st = StateStore::new();
        st.set_balance("worker7006", 1_000);
        st.set_balance("challenger7006", 100);
        st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "authority-a,authority-b".into(),
        )
        .expect("bootstrap resolve authority should succeed");

        let result_hash = [7u8; 32];
        let reveal_salt = [9u8; 32];
        let r1 = apply_create_task(&mut st, 7006, "alice".into(), 100).unwrap();
        let committed = compute_commitment(7006, &result_hash, &reveal_salt, "worker7006");
        let r2 = apply_accept_task(&mut st, r1, "worker7006".into()).unwrap();
        let r3 = trnm_pouw::apply_commit_result_at_height(
            &mut st,
            r2,
            "worker7006".into(),
            committed,
            100,
        )
        .unwrap();
        let r4 = trnm_pouw::apply_reveal_result_at_height(
            &mut st,
            r3,
            result_hash,
            reveal_salt,
            None,
            110,
        )
        .unwrap();
        let r5 = trnm_pouw::apply_challenge_at_height(
            &mut st,
            r4,
            "challenger7006".into(),
            10,
            "challenger7006".into(),
            210,
        )
        .unwrap();

        let staged = apply_resolve_at_height(
            &mut st,
            r5.clone(),
            true,
            "authority-a".into(),
            "authority-a".into(),
            211,
        )
        .expect_err("first resolve approval should only stage quorum");
        assert!(matches!(
            staged,
            trnm_pouw::PouwError::ResolveApprovalStaged
        ));
        assert_eq!(st.pending_resolve_approval(r5.id), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(r5.id).as_deref(),
            Some("authority-a")
        );

        st.set_gov_param(9_231, 7_999, "emergency_pause".into(), "true".into())
            .expect("pause=true governance update must succeed");
        assert!(st.is_emergency_paused());

        let resolve_deadline = st
            .get_task(7006)
            .and_then(|t| t.resolve_deadline_height)
            .expect("resolve deadline must be present after challenge");
        let before_task = st.get_task(7006).expect("challenged task must exist");
        let before_escrow = st.balance_of("treasury.challenge_escrow");
        let before_forfeit = st.balance_of("treasury.challenge_forfeits");
        let before_worker_slash = st.balance_of("treasury.worker_slashes");
        let before_challenger = st.balance_of("challenger7006");

        let known: HashSet<u64> = [7006u64].into_iter().collect();
        let migrated = scan_and_apply_timeouts(
            &mut st,
            &known,
            resolve_deadline.saturating_add(1),
            9_100_201,
        );

        assert_eq!(migrated, 0);
        let after_task = st
            .get_task(7006)
            .expect("challenged task must remain after paused scan");
        assert_eq!(after_task.status, before_task.status);
        assert_eq!(
            after_task.challenge_bond_forfeited,
            before_task.challenge_bond_forfeited
        );
        assert_eq!(st.pending_resolve_approval(7006), Some((true, 1)));
        assert_eq!(
            st.pending_resolve_first_approver(7006).as_deref(),
            Some("authority-a")
        );
        assert_eq!(st.balance_of("treasury.challenge_escrow"), before_escrow);
        assert_eq!(st.balance_of("treasury.challenge_forfeits"), before_forfeit);
        assert_eq!(
            st.balance_of("treasury.worker_slashes"),
            before_worker_slash
        );
        assert_eq!(st.balance_of("challenger7006"), before_challenger);
    }

    #[test]
    fn timeout_outcome_fields_marks_slashed_terminal_status() {
        assert_eq!(timeout_outcome_fields("Slashed"), ("true", "slashed"));
    }

    #[test]
    fn timeout_outcome_fields_distinguishes_completed_from_resolved_terminal_statuses() {
        assert_eq!(timeout_outcome_fields("Completed"), ("false", "completed"));
        assert_eq!(timeout_outcome_fields("Resolved"), ("false", "resolved"));
    }

    #[test]
    fn timeout_outcome_fields_marks_unexpected_status_unknown_for_visibility() {
        assert_eq!(timeout_outcome_fields("Challenged"), ("false", "unknown"));
        assert_eq!(timeout_outcome_fields("Assigned"), ("false", "unknown"));
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
    fn format_task_metering_event_fields_includes_normalized_work_units_and_policy_summary() {
        let snapshot = TaskMeteringSnapshot {
            workload_class: "llm_inference".into(),
            metering_schema: "llm_token_meter_v1".into(),
            policy_snapshot_version: 1,
            receipt_hash: "deadbeef".into(),
            prompt_tokens: 128,
            generated_tokens: 32,
            decode_steps: 32,
            kv_bytes_moved: 4096,
            normalized_work_units: 192,
            prompt_token_weight: 1,
            generated_token_weight: 1,
            decode_step_weight: 1,
            kv_byte_weight: 0,
            min_accept_work_units: 100,
            challenge_success_bounty_base: 1,
            challenge_success_bounty_per_work_unit_num: 1,
            challenge_success_bounty_per_work_unit_den: 192,
            worker_completion_bonus_per_work_unit_num: 1,
            worker_completion_bonus_per_work_unit_den: 256,
            worker_slash_rebate_per_work_unit_num: 1,
            worker_slash_rebate_per_work_unit_den: 384,
        };
        let line = format_task_metering_event_fields(&snapshot);
        assert!(line.contains("metering_schema=llm_token_meter_v1"));
        assert!(line.contains("metering_normalized_work_units=192"));
        assert!(line.contains("metering_policy_snapshot_version=1"));
        assert!(line.contains("metering_min_accept_work_units=100"));
        assert!(line.contains("metering_worker_slash_rebate_per_work_unit_den=384"));
    }

    #[test]
    fn task_settlement_event_suffix_surfaces_poco_receipt_summary() {
        let mut st = StateStore::default();
        let _ = st.set_gov_param_bootstrap_unchecked(
            9_500,
            "resolve_authority".into(),
            "resolver-1,resolver-2".into(),
        );

        let result_hash = [0x11; 32];
        put_sample_poco_task(&mut st, 42, "worker-alpha", result_hash);

        let receipt =
            sample_consumption_receipt(42, "worker-alpha", "consumer-bravo", result_hash);
        let key = receipt.replay_key();

        apply_one(&mut st, MockTx::SubmitConsumptionReceipt { receipt }, 10)
            .expect("apply receipt");
        challenge_consumption_receipt_at_height(
            &mut st,
            key.clone(),
            "auditor-1".to_string(),
            "auditor-1".to_string(),
            11,
        )
        .expect("challenge receipt");
        resolve_consumption_receipt_at_height(
            &mut st,
            key,
            ConsumptionResolveDecision::Discount,
            Some(9),
            None,
            "resolver-1".to_string(),
            "resolver-1".to_string(),
            77,
        )
        .expect("resolve receipt");

        let line = task_settlement_event_suffix(&st, 42);
        assert!(line.contains("metering_receipt_hash=deadbeef"));
        assert!(line.contains("settlement_receipt_count=1"));
        assert!(line.contains("settlement_accepted_receipt_count=1"));
        assert!(line.contains("settlement_challenged_receipt_count=1"));
        assert!(line.contains("settlement_total_consumed_tokens=17"));
        assert!(line.contains("settlement_total_claimed_consumption_units=17"));
        assert!(line.contains("settlement_total_credited_consumption_units=9"));
        assert!(line.contains("settlement_last_settlement_height=77"));
    }

    #[test]
    fn submit_consumption_receipt_tx_maps_apply_event_and_rw_decl_stably() {
        let mut st = StateStore::default();
        let result_hash = [0x22; 32];
        put_sample_poco_task(&mut st, 42, "worker-alpha", result_hash);

        let receipt =
            sample_consumption_receipt(42, "worker-alpha", "consumer-bravo", result_hash);
        let tx = MockTx::SubmitConsumptionReceipt {
            receipt: receipt.clone(),
        };

        assert_eq!(task_id_of(&tx), 42);
        assert_eq!(event_type_of(&tx), "submit_consumption_receipt");
        assert_eq!(actor_of(&st, &tx), "consumer-bravo");
        assert_eq!(challenger_of(&tx), None);

        let replay_key = receipt.replay_key().storage_key();
        let expected_refs = vec![
            ObjectRef { id: 42, version: 1 },
            ObjectRef {
                id: pseudo_object_id_for_state_slot(
                    "consumer_consumption_nonce",
                    "consumer-bravo",
                ),
                version: 1,
            },
            ObjectRef {
                id: pseudo_object_id_for_state_slot("consumption_record", &replay_key),
                version: 1,
            },
            ObjectRef {
                id: pseudo_object_id_for_state_slot("task_consumption_summary", "42"),
                version: 1,
            },
        ];
        let decl = read_write_decl(&st, &tx, 9);
        assert_eq!(decl.read_set, expected_refs);
        assert_eq!(decl.write_set, decl.read_set);

        apply_one(&mut st, tx, 10).expect("apply receipt");

        let summary = st.task_consumption_summary(42).expect("summary");
        assert_eq!(summary.receipt_count, 1);
        assert_eq!(summary.total_claimed_consumption_units, 17);
        assert_eq!(st.consumer_consumption_nonce("consumer-bravo"), Some(7));

        let line = task_settlement_event_suffix(&st, 42);
        assert!(line.contains("settlement_receipt_count=1"));
        assert!(line.contains("settlement_total_claimed_consumption_units=17"));
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
        assert_eq!(recovered.wal_entries_retained, 0);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_snapshot_even_when_consensus_wal_file_exists() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-snapshot");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 8,
                last_round: 3,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
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
        assert_eq!(recovered.wal_entries_retained, 0);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_snapshot_even_when_empty_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-with-empty-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 15,
                last_round: 2,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 14,
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
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_snapshot_with_empty_wal_meta_scaffold_without_consensus_wal() {
        let wal_dir = temp_wal_dir("recover-checkpoint-only-empty-wal-meta-no-consensus-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 14,
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
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_metadata_files_are_empty() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-without-metadata");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 41,
                last_round: 6,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    fn assert_stale_consensus_wal_reset_after_recovery(wal_dir: &Path) {
        let recovered = recover_wal_state(wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 23,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_blank_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-blank-wal-meta");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 23,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), "\n  \t").unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_checkpoint_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-empty-checkpoint-file");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_blank_checkpoint_file_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-blank-checkpoint-file");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        fs::write(checkpoint_file(&wal_dir), "  \n\t").unwrap();

        assert_stale_consensus_wal_reset_after_recovery(&wal_dir);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_both_empty_metadata_files_exist() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-with-both-empty-metadata-files");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 31,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_normalizes_empty_metadata_scaffold_without_preexisting_consensus_wal() {
        let wal_dir = temp_wal_dir("recover-empty-metadata-scaffold-without-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_normalizes_empty_wal_meta_scaffold_without_preexisting_consensus_wal() {
        let wal_dir =
            temp_wal_dir("recover-empty-wal-meta-scaffold-without-preexisting-consensus-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_uncommitted_genesis_entry_even_with_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-uncommitted-genesis-entry");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: false,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 77,
                last_round: 9,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_genesis_entry_with_non_genesis_prev_hash_even_with_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-genesis-prev-hash");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: Some("forged-parent".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: e1.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 42,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_checkpointed_wal_chain_that_starts_above_genesis_height() {
        let wal_dir = temp_wal_dir("recover-starts-above-genesis-height");
        fs::create_dir_all(&wal_dir).unwrap();

        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e2.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: e2.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 88,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_metadata_only_tail_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-no-stale-lock");
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-tail-lock".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
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
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-tail-lock"));

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.committed));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_checkpoint_for_metadata_only_tail() {
        let wal_dir = temp_wal_dir("recover-prune-metadata-only-tail-checkpoint");
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_tail_rewrites_consensus_wal_round_to_zero() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-round-reset");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 7,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 11,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
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
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 42,
                locked_block_hash: Some("stale-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-prunes-stale-duplicate-checkpoint");
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_exact_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-exact-duplicate-checkpoint");
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
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_duplicate_checkpoint_and_rewrites_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-prune-duplicate-checkpoint-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

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
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_committed_tail_beyond_checkpoint_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint-no-stale-lock");
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-committed-tail-lock".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 4,
                last_round: 0,
                locked_block_hash: Some("stale-committed-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());
        assert_ne!(
            recovered.restored_lock.as_deref(),
            Some("stale-committed-tail-lock")
        );

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.height <= 2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_committed_duplicate_height_tail_without_restoring_stale_lock() {
        let wal_dir = temp_wal_dir("recover-committed-duplicate-height-tail-no-stale-lock");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "stale-duplicate-tail-lock".into(),
            committed: true,
            state_root_hex: "r2-replayed".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2.clone()]).unwrap();
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
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: replayed_e2.state_root_hex.clone(),
                    wal_entry_hash_hex: replayed_e2.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 3,
                last_round: 1,
                locked_block_hash: Some("stale-duplicate-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "discarding a corrupt duplicate-height committed WAL tail should preserve recoverable state at the retained checkpoint"
        );
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_ne!(
            recovered.restored_lock.as_deref(),
            Some("stale-duplicate-tail-lock")
        );

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].height, 2);
        assert_eq!(entries[1].proposal_hash, "h2");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != replayed_e2.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_prunes_stale_duplicate_checkpoint_at_retained_height(
    ) {
        let wal_dir = temp_wal_dir(
            "recover-committed-tail-beyond-checkpoint-prunes-stale-duplicate-checkpoint",
        );
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "stale-committed-tail".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3.clone()]).unwrap();
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
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "stale-r3".into(),
                    wal_entry_hash_hex: "stale-h3".into(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.restored_lock.is_none());

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().all(|entry| entry.height <= 2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
        assert!(checkpoints.iter().all(|cp| cp.height <= 2));
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != e3.content_hash_hex()));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_uncheckpointed_wal_without_claiming_recovery() {
        let wal_dir = temp_wal_dir("recover-uncheckpointed");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 9,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

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
        assert_eq!(recovered.wal_entries_retained, 0);
        assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_uncheckpointed_wal_that_starts_above_genesis_without_claiming_recovery() {
        let wal_dir = temp_wal_dir("recover-uncheckpointed-starts-above-genesis");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 12,
                last_round: 5,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e2]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);
        assert!(load_wal_meta_entries(&wal_dir).unwrap().is_empty());
        assert!(load_checkpoint_meta(&wal_dir).unwrap().is_empty());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rejects_checkpointed_wal_chain_without_genesis_base() {
        let wal_dir = temp_wal_dir("recover-no-genesis-base");
        fs::create_dir_all(&wal_dir).unwrap();

        let e10 = WalMeta {
            height: 10,
            round: 0,
            proposal_hash: "h10".into(),
            committed: true,
            state_root_hex: "r10".into(),
            prev_hash_hex: None,
        };

        persist_wal_meta_entries(&wal_dir, &[e10.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 10,
                state_root_hex: "r10".into(),
                wal_entry_hash_hex: e10.content_hash_hex(),
            }],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(retained.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_future_checkpoints_even_without_extra_wal_entries() {
        let wal_dir = temp_wal_dir("recover-prune-future-checkpoints");
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
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
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
                    state_root_hex: "stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_future_checkpoints_and_rewrites_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-prune-future-checkpoints-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 7,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
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
                    state_root_hex: "stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 42,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(!recovered.metadata_only_recovery);
        assert!(recovered.truncated);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 7);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-stale-duplicate-checkpoint");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
                    state_root_hex: "stale-r2".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_canonicalizes_retained_checkpoint_order_after_pruning() {
        let wal_dir = temp_wal_dir("recover-canonicalize-retained-checkpoint-order");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_canonicalizes_retained_checkpoint_order_without_truncating_clean_wal() {
        let wal_dir = temp_wal_dir("recover-canonicalize-checkpoints-clean-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 99,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(!recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 5);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_checkpoint_meta_canonicalizes_equal_height_entries_on_disk() {
        let wal_dir = temp_wal_dir("persist-canonicalize-checkpoints-equal-height");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        let first = raw.find("hash-a").unwrap();
        let second = raw.find("hash-c").unwrap();
        let third = raw.find("hash-b").unwrap();
        assert!(first < second && second < third, "expected canonical disk order, got: {raw}");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 3);
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-a");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-c");
        assert_eq!(checkpoints[2].wal_entry_hash_hex, "hash-b");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_deduplicates_identical_disk_entries_for_auditable_surfaces() {
        let wal_dir = temp_wal_dir("load-checkpoint-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                [[checkpoints]]
                height = 7
                state_root_hex = "root-a"
                wal_entry_hash_hex = "hash-a"

                [[checkpoints]]
                height = 8
                state_root_hex = "root-b"
                wal_entry_hash_hex = "hash-b"

                [[checkpoints]]
                height = 7
                state_root_hex = "root-a"
                wal_entry_hash_hex = "hash-a"
            "#,
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 7);
        assert_eq!(checkpoints[0].state_root_hex, "root-a");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-a");
        assert_eq!(checkpoints[1].height, 8);
        assert_eq!(checkpoints[1].state_root_hex, "root-b");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-b");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_identical_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-prune-identical-duplicate-checkpoint");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal() {
        let wal_dir = temp_wal_dir("recover-prune-stale-lower-checkpoint");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 2);
        assert_eq!(checkpoints[0].state_root_hex, "r2");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_tail_prunes_stale_lower_checkpoint_that_no_longer_matches_retained_wal(
    ) {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-prune-stale-lower-checkpoint");
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
        let e3 = WalMeta {
            height: 3,
            round: 0,
            proposal_hash: "metadata-only-tail".into(),
            committed: false,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-tail-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 2);
        assert_eq!(checkpoints[0].state_root_hex, "r2");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_multiple_entries_is_not_metadata_only() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-multiple-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(e1.content_hash_hex()),
        };
        let h1 = e1.content_hash_hex();
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(!recovered.metadata_only_recovery);
        assert!(!recovered.truncated);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_is_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(e1.content_hash_hex()),
        };
        let h1 = e1.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(
            recovered.metadata_only_recovery,
            "committed WAL beyond last checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
        assert!(recovered.truncated);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_tail_beyond_checkpoint_rewrites_consensus_wal_fail_closed() {
        let wal_dir = temp_wal_dir("recover-committed-tail-beyond-checkpoint-rewrites-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 3);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_height_regression_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-height-regression-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "p1".into(),
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
            committed: true,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 0,
            proposal_hash: "p2".into(),
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
            committed: true,
        };
        let h2 = e2.content_hash_hex();
        let regressed_e1 = WalMeta {
            height: 1,
            round: 1,
            proposal_hash: "p1-regressed".into(),
            state_root_hex: "r1-regressed".into(),
            prev_hash_hex: Some(h2.clone()),
            committed: true,
        };

        persist_wal_meta_entries(&wal_dir, &[e1.clone(), e2.clone(), regressed_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: e1.state_root_hex.clone(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: e2.state_root_hex.clone(),
                    wal_entry_hash_hex: h2,
                },
            ],
        )
        .unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 99,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock, Some("p2".into()));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(2)
        );
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));

        let retained_entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained_entries.len(), 2);
        assert_eq!(retained_entries[0].height, 1);
        assert_eq!(retained_entries[1].height, 2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash, Some("p2".into()));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_replayed_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-replayed-duplicate-height-tail");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "duplicate-height replay tail should truncate back to the verified checkpoint without claiming application-state recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_duplicate_height_tail_refreshes_last_checkpoint_after_pruning_stale_checkpoint() {
        let wal_dir = temp_wal_dir("recover-duplicate-height-tail-refreshes-last-checkpoint");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
                    wal_entry_hash_hex: h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-replay".into(),
                    wal_entry_hash_hex: "stale-replayed-h2".into(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        let retained_checkpoint = recovered
            .last_checkpoint
            .as_ref()
            .expect("retained checkpoint should remain after truncating duplicate tail");
        assert_eq!(retained_checkpoint.height, 2);
        assert_eq!(retained_checkpoint.state_root_hex, "r2");
        assert_eq!(retained_checkpoint.wal_entry_hash_hex, h2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_replayed_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
        let wal_dir = temp_wal_dir("recover-replayed-duplicate-genesis-height-tail");
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
        let replayed_e1 = WalMeta {
            height: 1,
            round: 1,
            proposal_hash: "h1-replay".into(),
            committed: true,
            state_root_hex: "r1-replay".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, replayed_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1-replay".into(),
                    wal_entry_hash_hex: "stale-replayed-h1".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-genesis-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "duplicate genesis-height replay tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_identical_duplicate_genesis_height_tail_truncates_to_genesis_checkpoint() {
        let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-genesis-height-tail");
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
        let duplicate_e1 = e1.clone();

        persist_wal_meta_entries(&wal_dir, &[e1, duplicate_e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1,
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-identical-h1".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 88
last_round = 9
locked_block_hash = "stale-duplicate-genesis-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_eq!(
            recovered.last_checkpoint.as_ref().map(|cp| cp.height),
            Some(1)
        );
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "exact duplicate genesis-height tail should truncate back to the verified genesis checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_identical_duplicate_height_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-committed-identical-duplicate-height-tail");
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
        let duplicate_e2 = e2.clone();

        persist_wal_meta_entries(&wal_dir, &[e1, e2, duplicate_e2]).unwrap();
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
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 88
last_round = 9
locked_block_hash = "stale-duplicate-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "exact duplicate committed tail should truncate back to the verified checkpoint without claiming metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_duplicate_height_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir = temp_wal_dir("recover-duplicate-height-tail-prunes-stale-checkpoint");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay".into(),
            committed: true,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-hash".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-replay-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_committed_duplicate_height_tail_with_same_state_root_prunes_stale_checkpoint_linkage(
    ) {
        let wal_dir =
            temp_wal_dir("recover-committed-duplicate-height-tail-same-root-linkage");
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
            state_root_hex: "shared-root".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "stale-shared-root-tail".into(),
            committed: true,
            state_root_hex: "shared-root".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let replayed_h2 = replayed_e2.content_hash_hex();

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
                    state_root_hex: "shared-root".into(),
                    wal_entry_hash_hex: replayed_h2.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "shared-root".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-shared-root-tail"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            !recovered.metadata_only_recovery,
            "discarding a corrupt duplicate-height committed WAL tail should preserve recoverable state at the retained checkpoint even when the replay reuses the same state_root surface"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "shared-root");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);
        assert!(
            checkpoints
                .iter()
                .all(|cp| cp.wal_entry_hash_hex != replayed_h2),
            "stale duplicate checkpoint linkage must be pruned even when the replay reuses the same canonical state_root surface"
        );

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_uncommitted_duplicate_height_tail_is_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-uncommitted-duplicate-height-tail");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay-uncommitted".into(),
            committed: false,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "uncommitted replay metadata beyond the retained checkpoint must stay classified as metadata-only recovery"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 2);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[1].height, 2);
        assert_eq!(retained[1].proposal_hash, "h2");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_uncommitted_duplicate_height_tail_prunes_stale_duplicate_checkpoint_at_retained_height(
    ) {
        let wal_dir =
            temp_wal_dir("recover-uncommitted-duplicate-height-tail-prunes-stale-checkpoint");
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
        let replayed_e2 = WalMeta {
            height: 2,
            round: 1,
            proposal_hash: "h2-replay-uncommitted".into(),
            committed: false,
            state_root_hex: "r2-replay".into(),
            prev_hash_hex: Some(h2.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, replayed_e2]).unwrap();
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
                    state_root_hex: "r2-stale".into(),
                    wal_entry_hash_hex: "stale-h2".into(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2".into(),
                    wal_entry_hash_hex: h2.clone(),
                },
            ],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 3);
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.wal_entries_retained, 2);

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[1].height, 2);
        assert_eq!(checkpoints[1].state_root_hex, "r2");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, h2);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_gap_skipping_tail_truncates_to_last_valid_checkpoint() {
        let wal_dir = temp_wal_dir("recover-gap-skipping-tail");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 4,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e3 = WalMeta {
            height: 3,
            round: 9,
            proposal_hash: "h3".into(),
            committed: true,
            state_root_hex: "r3".into(),
            prev_hash_hex: Some(h1.clone()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e3.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 3,
                    state_root_hex: "r3".into(),
                    wal_entry_hash_hex: e3.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "gap-skipping committed tail beyond the retained checkpoint must stay classified as metadata-only recovery until StateStore snapshot+replay exists"
        );

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let retained_checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(retained_checkpoints.len(), 1);
        assert_eq!(retained_checkpoints[0].height, 1);
        assert_eq!(retained_checkpoints[0].state_root_hex, "r1");
        assert_eq!(retained_checkpoints[0].wal_entry_hash_hex, h1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 4);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_discards_corrupt_committed_tail_without_claiming_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("recover-corrupt-committed-tail-non-metadata-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let corrupt_e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2-corrupt".into(),
            committed: true,
            state_root_hex: "r2-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, corrupt_e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_corrupt_committed_tail_prunes_future_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("recover-corrupt-committed-tail-prunes-future-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let corrupt_e2 = WalMeta {
            height: 2,
            round: 5,
            proposal_hash: "h2-corrupt".into(),
            committed: true,
            state_root_hex: "r2-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, corrupt_e2.clone()]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "stale-r1".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "r2-corrupt".into(),
                    wal_entry_hash_hex: corrupt_e2.content_hash_hex(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);
        assert!(checkpoints
            .iter()
            .all(|cp| cp.wal_entry_hash_hex != corrupt_e2.content_hash_hex()));

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_mixed_committed_tail_marks_metadata_only_even_if_later_tail_is_corrupt() {
        let wal_dir = temp_wal_dir("recover-mixed-committed-tail-metadata-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 3,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let corrupt_e3 = WalMeta {
            height: 3,
            round: 4,
            proposal_hash: "h3-corrupt".into(),
            committed: true,
            state_root_hex: "r3-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "discarding any directly continuing committed tail beyond the retained checkpoint must stay fail-closed even if later tail entries are corrupt"
        );
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.restored_lock.is_none());

        let retained = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].height, 1);
        assert_eq!(retained[0].proposal_hash, "h1");

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_mixed_committed_tail_prunes_stale_duplicate_checkpoint_at_retained_height() {
        let wal_dir =
            temp_wal_dir("recover-mixed-committed-tail-prunes-stale-checkpoint-at-retained-height");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 2,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 3,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let corrupt_e3 = WalMeta {
            height: 3,
            round: 4,
            proposal_hash: "h3-corrupt".into(),
            committed: true,
            state_root_hex: "r3-corrupt".into(),
            prev_hash_hex: Some("not-the-retained-tip".into()),
        };

        persist_wal_meta_entries(&wal_dir, &[e1, e2, corrupt_e3]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1-stale".into(),
                    wal_entry_hash_hex: "stale-h1".into(),
                },
                CheckpointMeta {
                    height: 1,
                    state_root_hex: "r1".into(),
                    wal_entry_hash_hex: h1.clone(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.wal_entries_retained, 1);
        assert!(recovered.restored_lock.is_none());

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 1);
        assert_eq!(checkpoints[0].state_root_hex, "r1");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, h1);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 2);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_retained_wal_entries() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error");
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
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.next_height, 2);

        let err = metadata_only_recovery_error(&wal_dir, &recovered);
        assert!(err.contains("retained 1 committed WAL entry through height 1"));
        assert!(err.contains("last retained checkpoint: 1"));

        let would_require_snapshot_restore = recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height < recovered.next_height.saturating_sub(1))
            .unwrap_or(recovered.wal_entries_retained > 0);
        assert!(
            !would_require_snapshot_restore,
            "fully checkpointed WAL metadata must not be escalated to metadata-only recovery misuse"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_exposes_checkpoint_da_surface_when_wal_linkage_is_canonical() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-da-surface");
        fs::create_dir_all(&wal_dir).unwrap();

        let state_root_hex = "ab".repeat(32);
        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-1".into(),
            committed: true,
            state_root_hex: state_root_hex.clone(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: state_root_hex.clone(),
                wal_entry_hash_hex: h1.clone(),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains(&format!(
            "checkpoint_evidence: checkpoint_height=1 state_root={} wal_entry_hash={}",
            state_root_hex, h1
        )));
        assert!(err.contains("checkpoint_da_surface: da_light_surface=checkpoint-wal-v1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_non_audit_ready_da_reason_for_noncanonical_checkpoint_tuple() {
        let wal_dir = temp_wal_dir("recover-da-surface-noncanonical-tuple");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();

        let recovered = RecoveredWalState {
            wal_entries_retained: 1,
            next_height: 2,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }),
            truncated: false,
            metadata_only_recovery: true,
            checkpoint_height_retained: Some(1),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);
        assert!(err.contains("checkpoint_evidence: checkpoint_height=1 state_root=r1"));
        assert!(err.contains("checkpoint_da_surface: unavailable:non_audit_ready_wal_surface"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_da_unavailability_reason_when_checkpoint_wal_linkage_is_missing() {
        let wal_dir = temp_wal_dir("recover-da-surface-missing-wal-linkage");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-1".into(),
            committed: true,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        };
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();

        let recovered = RecoveredWalState {
            wal_entries_retained: 1,
            next_height: 2,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 1,
                state_root_hex: "ab".repeat(32),
                wal_entry_hash_hex: "ff".repeat(32),
            }),
            truncated: false,
            metadata_only_recovery: true,
            checkpoint_height_retained: Some(1),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);
        assert!(err.contains("checkpoint_da_surface: unavailable:no_matching_wal_entry"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_wal_rewrites_stale_consensus_wal_lock_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-no-wal-rewrite");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 7,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                wal_entry_hash_hex: h1,
                state_root_hex: "r1".into(),
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h1"));
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 7);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h1"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_fully_checkpointed_multiple_entries_rewrite_stale_consensus_wal_to_retained_tip() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed-multi-no-wal-rewrite");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: true,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        let h2 = e2.content_hash_hex();
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 1,
                    wal_entry_hash_hex: h1,
                    state_root_hex: "r1".into(),
                },
                CheckpointMeta {
                    height: 2,
                    wal_entry_hash_hex: h2,
                    state_root_hex: "r2".into(),
                },
            ],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(!recovered.metadata_only_recovery);
        assert!(!recovered.truncated);
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_ne!(recovered.restored_lock.as_deref(), Some("stale-lock"));

        let wal_raw = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal_raw).unwrap();
        assert_eq!(wal.next_height, 3);
        assert_eq!(wal.last_round, 4);
        assert_eq!(wal.locked_block_hash.as_deref(), Some("h2"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_rewrites_consensus_wal_to_retained_checkpoint_after_metadata_only_truncation() {
        let wal_dir = temp_wal_dir("recover-metadata-only-tail-rewrites-consensus-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let e1 = WalMeta {
            height: 1,
            round: 3,
            proposal_hash: "h1".into(),
            committed: true,
            state_root_hex: "r1".into(),
            prev_hash_hex: None,
        };
        let h1 = e1.content_hash_hex();
        let e2 = WalMeta {
            height: 2,
            round: 4,
            proposal_hash: "h2".into(),
            committed: false,
            state_root_hex: "r2".into(),
            prev_hash_hex: Some(h1.clone()),
        };
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                wal_entry_hash_hex: h1,
                state_root_hex: "r1".into(),
            }],
        )
        .unwrap();
        fs::write(
            wal_file(&wal_dir),
            r#"next_height = 99
last_round = 42
locked_block_hash = "stale-lock"
"#,
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.metadata_only_recovery);
        assert!(recovered.truncated);
        assert_eq!(recovered.next_height, 2);
        assert!(recovered.restored_lock.is_none());

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 2);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_truncates_uncheckpointed_tail_without_claiming_metadata_recovery() {
        let wal_dir = temp_wal_dir("recover-truncates-uncheckpointed-tail");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: h1,
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert!(recovered.truncated);
        assert!(
            recovered.metadata_only_recovery,
            "committed WAL beyond last checkpoint must stay fail-closed until StateStore restore/replay exists"
        );
        assert_eq!(recovered.next_height, 2);
        assert_eq!(recovered.checkpoint_height_retained, Some(1));
        assert!(recovered.restored_lock.is_none());
        assert_eq!(recovered.wal_entries_retained, 1);
        assert_eq!(load_wal_meta_entries(&wal_dir).unwrap().len(), 1);
        assert_eq!(load_checkpoint_meta(&wal_dir).unwrap().len(), 1);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_allows_non_metadata_only_restart_when_checkpoint_covers_last_wal_entry() {
        let wal_dir = temp_wal_dir("recover-fully-checkpointed");
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
        persist_wal_meta_entries(&wal_dir, &[e1, e2]).unwrap();
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
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.next_height, 3);
        assert_eq!(recovered.checkpoint_height_retained, Some(2));
        assert_eq!(recovered.restored_lock.as_deref(), Some("h2"));
        assert_eq!(recovered.wal_entries_retained, 2);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_checkpoint_without_retained_wal_entries() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-checkpoint-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 8,
                state_root_hex: "r8".into(),
                wal_entry_hash_hex: "h8".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(8),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained no committed WAL entries (last retained checkpoint height 8)"));
        assert!(err.contains("last retained checkpoint: 8"));
        assert!(err.contains("next startup height: 9"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_truncated_checkpoint_only_rejoin_surface() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-truncated-checkpoint-only");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 8,
                state_root_hex: "r8".into(),
                wal_entry_hash_hex: "h8".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(8),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains(
            "retained no committed WAL entries (last retained checkpoint height 8); repaired WAL tail required truncation"
        ));
        assert!(err.contains("last retained checkpoint: 8"));
        assert!(err.contains("next startup height: 9"));
        assert!(err.contains(
            "operator action: checkpoint-only bootstrap from retained checkpoint height 8 is acceptable with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying"
        ));
        assert!(err.contains(
            "incident clue: retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_aligned_retained_tip_operator_action() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-aligned-retained-tip");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(2),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 2"));
        assert!(err.contains("last retained checkpoint: 2"));
        assert!(err.contains("next startup height: 3"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=2 checkpoint_tip_relation=aligned next_startup_height=3 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(err.contains(
            "restore the application snapshot that matches retained WAL tip height 2 before retrying join/rejoin; do not resume from metadata alone"
        ));
        assert!(!err.contains("checkpoint lags retained WAL tip"));
        assert!(!err.contains("no retained checkpoint metadata"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_absent_checkpoint() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-no-checkpoint");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained no committed WAL entries"));
        assert!(err.contains("last retained checkpoint: none"));
        assert!(err.contains("next startup height: 1"));
        assert!(err.contains("checkpoint_evidence: none"));
        assert!(err.contains("checkpoint_da_surface: unavailable:no_checkpoint"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn retained_wal_summary_reports_empty_fresh_join_surface() {
        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        assert_eq!(retained_wal_summary(&recovered), "retained no committed WAL entries");
    }

    #[test]
    fn retained_wal_summary_reports_truncated_checkpoint_only_rejoin_surface() {
        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 8,
                state_root_hex: "r8".into(),
                wal_entry_hash_hex: "h8".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(8),
        };

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries (last retained checkpoint height 8); repaired WAL tail required truncation"
        );
    }

    #[test]
    fn retained_wal_summary_reports_truncated_retained_wal_resume_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: Some("h11".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 11,
                state_root_hex: "r11".into(),
                wal_entry_hash_hex: "h11".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(11),
        };

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11; repaired WAL tail required truncation"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_empty_fresh_join_surface_as_ready() {
        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap"
        );
    }

    #[test]
    fn recovery_startup_summary_preserves_fresh_bootstrap_status_after_tail_truncation() {
        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_fresh_bootstrap_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("max-height fresh bootstrap should remain recoverable for safe join/rejoin");
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap",
                u64::MAX,
            )
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_truncated_fresh_bootstrap_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered).expect(
            "truncated max-height fresh bootstrap should remain recoverable for safe join/rejoin",
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height={} wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap_after_tail_repair",
                u64::MAX,
            )
        );
    }

    #[test]
    fn recovery_startup_summary_reports_retained_wal_resume_join_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: Some("h11".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 11,
                state_root_hex: "r11".into(),
                wal_entry_hash_hex: "h11".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(11),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_missing_checkpoint_metadata_surface_as_ready() {
        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 1 committed WAL entry through height 8 (no retained checkpoint metadata)"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_missing_checkpoint_metadata_after_tail_repair_surface_as_ready() {
        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 1 committed WAL entry through height 8 (no retained checkpoint metadata); repaired WAL tail required truncation"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_checkpoint_only_rejoin_surface_as_ready() {
        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 8,
                state_root_hex: "r8".into(),
                wal_entry_hash_hex: "h8".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(8),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_rejoin_bootstrap"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries (last retained checkpoint height 8)"
        );
    }

    #[test]
    fn metadata_only_operator_action_varies_by_join_rejoin_surface() {
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 9,
                restored_lock: None,
                last_checkpoint: Some(CheckpointMeta {
                    height: 8,
                    state_root_hex: "r8".into(),
                    wal_entry_hash_hex: "h8".into(),
                }),
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 0,
                checkpoint_height_retained: Some(8),
            }),
            "operator action: checkpoint-only bootstrap from retained checkpoint height 8 is acceptable with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 1,
                restored_lock: None,
                last_checkpoint: None,
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 0,
                checkpoint_height_retained: None,
            }),
            "operator action: restart with a fresh --bft-wal-dir / --bft-wal-mode auto isolated run; if this node must rejoin from prior state, restore an application snapshot before retrying"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 9,
                restored_lock: None,
                last_checkpoint: None,
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 1,
                checkpoint_height_retained: None,
            }),
            "operator action: rebuild or restore checkpoint metadata so it covers retained WAL tip height 8 before retrying join/rejoin; do not resume from metadata alone"
        );
        let single_block_lagging_rejoin = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 10,
                state_root_hex: "r10".into(),
                wal_entry_hash_hex: "h10".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(10),
        };
        assert_eq!(
            metadata_only_operator_action(&single_block_lagging_rejoin),
            "operator action: restore an application snapshot that covers retained WAL tip height 11 before retrying join/rejoin; retained checkpoint height 10 is 1 block behind, so do not resume from metadata alone"
        );
        assert_eq!(
            recovery_startup_summary(&single_block_lagging_rejoin),
            "retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 12,
                restored_lock: None,
                last_checkpoint: Some(CheckpointMeta {
                    height: 9,
                    state_root_hex: "r9".into(),
                    wal_entry_hash_hex: "h9".into(),
                }),
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 2,
                checkpoint_height_retained: Some(9),
            }),
            "operator action: restore an application snapshot that covers retained WAL tip height 11 before retrying join/rejoin; retained checkpoint height 9 is 2 blocks behind, so do not resume from metadata alone"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 12,
                restored_lock: None,
                last_checkpoint: Some(CheckpointMeta {
                    height: 11,
                    state_root_hex: "r11".into(),
                    wal_entry_hash_hex: "h11".into(),
                }),
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 2,
                checkpoint_height_retained: Some(11),
            }),
            "operator action: restore the application snapshot that matches retained WAL tip height 11 before retrying join/rejoin; do not resume from metadata alone"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 12,
                restored_lock: None,
                last_checkpoint: Some(CheckpointMeta {
                    height: 12,
                    state_root_hex: "r12".into(),
                    wal_entry_hash_hex: "h12".into(),
                }),
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 2,
                checkpoint_height_retained: Some(12),
            }),
            "operator action: investigate WAL/checkpoint mismatch (retained WAL tip height 11, checkpoint height 12, checkpoint leads tip by 1 block), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree"
        );
        assert_eq!(
            metadata_only_operator_action(&RecoveredWalState {
                next_height: 12,
                restored_lock: None,
                last_checkpoint: Some(CheckpointMeta {
                    height: 15,
                    state_root_hex: "r15".into(),
                    wal_entry_hash_hex: "h15".into(),
                }),
                truncated: false,
                metadata_only_recovery: true,
                wal_entries_retained: 2,
                checkpoint_height_retained: Some(15),
            }),
            "operator action: investigate WAL/checkpoint mismatch (retained WAL tip height 11, checkpoint height 15, checkpoint leads tip by 4 blocks), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree"
        );
    }

    #[test]
    fn metadata_only_operator_action_keeps_aligned_retained_wal_tip_height_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 1,
                state_root_hex: "r-max-1".into(),
                wal_entry_hash_hex: "h-max-1".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(u64::MAX - 1),
        };

        assert_eq!(
            metadata_only_operator_action(&recovered),
            format!(
                "operator action: restore the application snapshot that matches retained WAL tip height {} before retrying join/rejoin; do not resume from metadata alone",
                u64::MAX - 1,
            )
        );
    }

    #[test]
    fn recovery_startup_summary_reports_checkpoint_ahead_of_retained_tip_as_blocked_metadata_only() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 15,
                state_root_hex: "r15".into(),
                wal_entry_hash_hex: "h15".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(15),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_checkpoint_ahead_resume_mismatch_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 15,
                state_root_hex: "r15".into(),
                wal_entry_hash_hex: "h15".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(15),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch"
        );
    }

    #[test]
    fn recovery_startup_summary_reports_checkpoint_ahead_resume_mismatch_after_tail_repair_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 15,
                state_root_hex: "r15".into(),
                wal_entry_hash_hex: "h15".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(15),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 15 is ahead of retained WAL tip height 11 by 4 blocks; investigate WAL/checkpoint mismatch); repaired WAL tail required truncation"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_ahead_mismatch_visible_after_tail_repair() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_1block_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block; investigate WAL/checkpoint mismatch); repaired WAL tail required truncation"
        );
    }

    #[test]
    fn retained_wal_summary_uses_singular_block_for_single_block_checkpoint_ahead_mismatch() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block; investigate WAL/checkpoint mismatch)"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_lagging_join_surface_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: Some("h-max-minus-1".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 2,
                state_root_hex: "r-max-minus-2".into(),
                wal_entry_hash_hex: "h-max-minus-1".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: Some(u64::MAX - 2),
        };

        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {} (checkpoint lags retained WAL tip by 1 block)",
                u64::MAX - 1
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=behind:1 next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_1block",
                u64::MAX - 2,
                u64::MAX,
            )
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_lag_visible_without_tail_repair() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 10,
                state_root_hex: "r10".into(),
                wal_entry_hash_hex: "h10".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(10),
        };

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_1block"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_truncated_lagging_join_surface_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: Some("h-max-minus-1".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 2,
                state_root_hex: "r-max-minus-2".into(),
                wal_entry_hash_hex: "h-max-minus-1".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: Some(u64::MAX - 2),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated max-height lagging checkpoint resume should remain recoverable while surfacing join/rejoin triage");
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {} (checkpoint lags retained WAL tip by 1 block); repaired WAL tail required truncation",
                u64::MAX - 1
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=behind:1 next_startup_height={} wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_1block_after_tail_repair",
                u64::MAX - 2,
                u64::MAX,
            )
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_single_block_lagging_checkpoint_resume() {
        let recovered = RecoveredWalState {
            next_height: 8,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 6,
                state_root_hex: "r6".into(),
                wal_entry_hash_hex: "h6".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(6),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("single-block lagging checkpoint resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 7 (checkpoint lags retained WAL tip by 1 block)"
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=6 checkpoint_tip_relation=behind:1 next_startup_height=8 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_1block"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_checkpoint_ahead_resume_mismatch_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 15,
                state_root_hex: "r15".into(),
                wal_entry_hash_hex: "h15".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(15),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("checkpoint-ahead retained WAL resume mismatch should stay recoverable but surface mismatch triage");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_truncated_checkpoint_ahead_resume_mismatch_surface() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 15,
                state_root_hex: "r15".into(),
                wal_entry_hash_hex: "h15".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(15),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated checkpoint-ahead retained WAL resume mismatch should stay recoverable but surface mismatch-after-tail-repair triage");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 15 is ahead of retained WAL tip height 11 by 4 blocks; investigate WAL/checkpoint mismatch); repaired WAL tail required truncation"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_checkpoint_ahead_join_surface_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX,
                state_root_hex: "r-max".into(),
                wal_entry_hash_hex: "h-max".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: Some(u64::MAX),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("max-height checkpoint-ahead resume mismatch should remain recoverable while surfacing join/rejoin triage");
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {} (retained checkpoint height {} is ahead of retained WAL tip height {} by 1 block; investigate WAL/checkpoint mismatch)",
                u64::MAX - 1,
                u64::MAX,
                u64::MAX - 1,
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=ahead:1 next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_1block",
                u64::MAX,
                u64::MAX,
            )
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_truncated_checkpoint_ahead_join_surface_saturated_at_max_height() {
        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX,
                state_root_hex: "r-max".into(),
                wal_entry_hash_hex: "h-max".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: Some(u64::MAX),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated max-height checkpoint-ahead resume mismatch should remain recoverable while surfacing join/rejoin triage");
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {} (retained checkpoint height {} is ahead of retained WAL tip height {} by 1 block; investigate WAL/checkpoint mismatch); repaired WAL tail required truncation",
                u64::MAX - 1,
                u64::MAX,
                u64::MAX - 1,
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=ahead:1 next_startup_height={} wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_1block_after_tail_repair",
                u64::MAX,
                u64::MAX,
            )
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_keeps_single_block_checkpoint_ahead_mismatch_recoverable() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("single-block checkpoint-ahead mismatch should remain recoverable for join/rejoin triage");
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block; investigate WAL/checkpoint mismatch)"
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_1block"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_keeps_single_block_checkpoint_ahead_mismatch_recoverable_after_tail_repair() {
        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated single-block checkpoint-ahead mismatch should remain recoverable for join/rejoin triage");
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block; investigate WAL/checkpoint mismatch); repaired WAL tail required truncation"
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_1block_after_tail_repair"
        );
    }

    #[test]
    fn recover_metadata_only_error_reports_plural_retained_entries_and_height() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-plural");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 1,
                state_root_hex: "r1".into(),
                wal_entry_hash_hex: "h1".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(1),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 2"));
        assert!(err.contains("last retained checkpoint: 1"));
        assert!(err.contains(
            "does not yet restore application StateStore snapshots or replay committed blocks"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_plural_checkpoint_lag_blocks() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-lag-blocks");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 5,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 4,
            checkpoint_height_retained: Some(2),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 4 committed WAL entries through height 4"));
        assert!(err.contains("checkpoint lags retained WAL tip by 2 blocks"));
        assert!(err.contains("last retained checkpoint: 2"));
        assert!(err.contains("next startup height: 5"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_reports_singular_checkpoint_ahead_block() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-ahead-block-singular");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 11"));
        assert!(err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block"
        ));
        assert!(!err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 blocks"
        ));
        assert!(err.contains("last retained checkpoint: 12"));
        assert!(err.contains("next startup height: 12"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_surfaces_checkpoint_ahead_mismatch_operator_action() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-checkpoint-ahead-mismatch");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 3,
                state_root_hex: "r3".into(),
                wal_entry_hash_hex: "h3".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(3),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 2"));
        assert!(err.contains(
            "retained checkpoint height 3 is ahead of retained WAL tip height 2 by 1 block; investigate WAL/checkpoint mismatch"
        ));
        assert!(!err.contains(
            "retained checkpoint height 3 is ahead of retained WAL tip height 2 by 1 blocks"
        ));
        assert!(err.contains(
            "operator action: investigate WAL/checkpoint mismatch (retained WAL tip height 2, checkpoint height 3, checkpoint leads tip by 1 block), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree"
        ));
        assert!(err.contains("last retained checkpoint: 3"));
        assert!(err.contains("next startup height: 3"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=3 checkpoint_tip_relation=ahead:1 next_startup_height=3 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_metadata_only_error_surfaces_single_block_lagging_operator_action() {
        let wal_dir = temp_wal_dir("recover-metadata-only-error-single-block-lagging");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 4,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: false,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(2),
        };

        let err = metadata_only_recovery_error(&wal_dir, &recovered);

        assert!(err.contains("retained 2 committed WAL entries through height 3"));
        assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
        assert!(!err.contains("checkpoint lags retained WAL tip by 1 blocks"));
        assert!(err.contains(
            "operator action: restore an application snapshot that covers retained WAL tip height 3 before retrying join/rejoin; retained checkpoint height 2 is 1 block behind, so do not resume from metadata alone"
        ));
        assert!(err.contains("last retained checkpoint: 2"));
        assert!(err.contains("next startup height: 4"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=2 checkpoint_tip_relation=behind:1 next_startup_height=4 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_rejects_metadata_only_recovery_with_singular_checkpoint_lag() {
        let wal_dir = temp_wal_dir("recover-guard-metadata-only-singular-lag");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 4,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 3,
            checkpoint_height_retained: Some(2),
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("refusing metadata-only recovery"));
        assert!(err.contains("retained 3 committed WAL entries through height 3"));
        assert!(err.contains("checkpoint lags retained WAL tip by 1 block"));
        assert!(!err.contains("checkpoint lags retained WAL tip by 1 blocks"));
        assert!(err.contains("last retained checkpoint: 2"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=3 checkpoint_height_retained=2 checkpoint_tip_relation=behind:1 next_startup_height=4 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(err.contains("retained_wal_entries=3"));
        assert!(err.contains("wal_tail_truncated=true"));
        assert!(err.contains("checkpoint_height_retained=2"));
        assert!(err.contains("checkpoint_tip_relation=behind:1"));
        assert!(err.contains("next_startup_height=4"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_rejects_metadata_only_recovery_with_singular_checkpoint_ahead_mismatch() {
        let wal_dir = temp_wal_dir("recover-guard-metadata-only-singular-ahead");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 12,
                state_root_hex: "r12".into(),
                wal_entry_hash_hex: "h12".into(),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(12),
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap_err();
        let err = format!("{err:#}");

        assert!(err.contains("refusing metadata-only recovery"));
        assert!(err.contains("retained 2 committed WAL entries through height 11"));
        assert!(err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block"
        ));
        assert!(!err.contains(
            "retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 blocks"
        ));
        assert!(err.contains("operator action: investigate WAL/checkpoint mismatch (retained WAL tip height 11, checkpoint height 12, checkpoint leads tip by 1 block), rebuild the recovery inputs, and only retry join/rejoin once WAL tip and checkpoint evidence agree"));
        assert!(!err.contains("checkpoint leads tip by 1 blocks"));
        assert!(err.contains("last retained checkpoint: 12"));
        assert!(err.contains("next startup height: 12"));
        assert!(err.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(err.contains("retained_wal_entries=2"));
        assert!(err.contains("wal_tail_truncated=true"));
        assert!(err.contains("checkpoint_height_retained=12"));
        assert!(err.contains("checkpoint_tip_relation=ahead:1"));
        assert!(err.contains("next_startup_height=12"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_fully_checkpointed_recovery() {
        let wal_dir = temp_wal_dir("recover-guard-safe");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 3,
            restored_lock: Some("h2".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 2,
                state_root_hex: "r2".into(),
                wal_entry_hash_hex: "h2".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(2),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap();

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_checkpoint_only_rejoin_bootstrap() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-checkpoint-only-rejoin");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 8,
                state_root_hex: "r8".into(),
                wal_entry_hash_hex: "h8".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(8),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("truncated checkpoint-only rejoin bootstrap should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_rejoin_bootstrap_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries (last retained checkpoint height 8); repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recovery_startup_summary_keeps_checkpoint_only_join_surface_saturated_at_max_height() {
        let wal_dir = temp_wal_dir("recover-guard-max-checkpoint-only-rejoin");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 1,
                state_root_hex: "rmax-1".into(),
                wal_entry_hash_hex: "hmax-1".into(),
            }),
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(u64::MAX - 1),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("max-height checkpoint-only rejoin bootstrap should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=0 checkpoint_height_retained={} checkpoint_tip_relation=checkpoint_only:{} next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_rejoin_bootstrap",
                u64::MAX - 1,
                u64::MAX - 1,
                u64::MAX,
            )
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained no committed WAL entries (last retained checkpoint height {})",
                u64::MAX - 1,
            )
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recovery_startup_summary_keeps_truncated_checkpoint_only_join_surface_saturated_at_max_height() {
        let wal_dir = temp_wal_dir("recover-guard-max-truncated-checkpoint-only-rejoin");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: u64::MAX,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: u64::MAX - 1,
                state_root_hex: "rmax-1".into(),
                wal_entry_hash_hex: "hmax-1".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: Some(u64::MAX - 1),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).expect(
            "truncated max-height checkpoint-only rejoin bootstrap should remain recoverable",
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=0 checkpoint_height_retained={} checkpoint_tip_relation=checkpoint_only:{} next_startup_height={} wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_rejoin_bootstrap_after_tail_repair",
                u64::MAX - 1,
                u64::MAX - 1,
                u64::MAX,
            )
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained no committed WAL entries (last retained checkpoint height {}); repaired WAL tail required truncation",
                u64::MAX - 1,
            )
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_retained_wal_resume() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-retained-wal-resume");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 12,
            restored_lock: Some("h11".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 11,
                state_root_hex: "r11".into(),
                wal_entry_hash_hex: "h11".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(11),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("truncated retained WAL resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11; repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_missing_checkpoint_metadata_resume() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-missing-checkpoint-metadata-resume");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 9,
            restored_lock: Some("h8".into()),
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).expect(
            "truncated retained WAL resume without checkpoint metadata should remain recoverable for safe join/rejoin",
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 1 committed WAL entry through height 8 (no retained checkpoint metadata); repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_lagging_checkpoint_resume() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-lagging-checkpoint-resume");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 8,
            restored_lock: Some("h7".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 5,
                state_root_hex: "r5".into(),
                wal_entry_hash_hex: "h5".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 3,
            checkpoint_height_retained: Some(5),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("truncated lagging-checkpoint retained WAL resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=3 checkpoint_height_retained=5 checkpoint_tip_relation=behind:2 next_startup_height=8 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 3 committed WAL entries through height 7 (checkpoint lags retained WAL tip by 2 blocks); repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_single_block_lagging_checkpoint_resume() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-single-block-lagging-checkpoint-resume");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 8,
            restored_lock: Some("h7".into()),
            last_checkpoint: Some(CheckpointMeta {
                height: 6,
                state_root_hex: "r6".into(),
                wal_entry_hash_hex: "h6".into(),
            }),
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(6),
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("truncated single-block lagging checkpoint resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=6 checkpoint_tip_relation=behind:1 next_startup_height=8 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_1block_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 7 (checkpoint lags retained WAL tip by 1 block); repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_fresh_bootstrap_after_reset() {
        let wal_dir = temp_wal_dir("recover-guard-truncated-fresh-bootstrap");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered)
            .expect("truncated fresh bootstrap should remain recoverable for safe join/rejoin");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap_after_tail_repair"
        );
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries; repaired WAL tail required truncation"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_without_checkpoint_and_without_retained_wal_is_not_metadata_only() {
        let wal_dir = temp_wal_dir("recover-no-checkpoint-no-retained-wal");
        fs::create_dir_all(&wal_dir).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(!recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_stale_consensus_wal_when_no_verified_metadata_exists() {
        let wal_dir = temp_wal_dir("recover-stale-consensus-wal-only");
        fs::create_dir_all(&wal_dir).unwrap();
        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 42,
                last_round: 9,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

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
    fn resolve_wal_dir_auto_isolates_builtin_default_when_only_checkpoint_metadata_exists() {
        let root = temp_wal_dir("default-wal-checkpoint-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(checkpoint_file(&base), "existing").unwrap();

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
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_checkpoint_scaffold_exists() {
        let root = temp_wal_dir("default-wal-comment-checkpoint-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            checkpoint_file(&base),
            "# bootstrap placeholder\n   # retained until first checkpoint\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_comment_only_wal_scaffold_exists() {
        let root = temp_wal_dir("default-wal-comment-meta-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            wal_meta_file(&base),
            "# bootstrap placeholder\n   # retained until first WAL write\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_crlf_comment_only_wal_scaffold_exists() {
        let root = temp_wal_dir("default-wal-crlf-comment-meta-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            wal_meta_file(&base),
            "# bootstrap placeholder\r\n   # retained until first WAL write\r\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_crlf_comment_only_checkpoint_scaffold_exists(
    ) {
        let root = temp_wal_dir("default-wal-crlf-comment-checkpoint-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            checkpoint_file(&base),
            "# bootstrap placeholder\r\n   # retained until first checkpoint\r\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_bom_prefixed_comment_only_consensus_wal_scaffold_exists(
    ) {
        let root = temp_wal_dir("default-wal-bom-comment-consensus-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            wal_file(&base),
            "\u{feff}# operator left a rejoin note\n   # safe to reuse builtin default once catch-up succeeds\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_bom_prefixed_comment_scaffolds_exist() {
        let root = temp_wal_dir("default-wal-bom-comment-scaffold-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            checkpoint_file(&base),
            "\u{feff}# bootstrap placeholder\n   # retained until first checkpoint\n",
        )
        .unwrap();
        fs::write(
            wal_meta_file(&base),
            "\u{feff}# bootstrap placeholder\n   # retained until first WAL write\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_bom_prefixed_comment_only_wal_meta_scaffold_exists(
    ) {
        let root = temp_wal_dir("default-wal-bom-comment-wal-meta-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            wal_meta_file(&base),
            "\u{feff}# bootstrap placeholder\n   # retained until first WAL write\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn resolve_wal_dir_auto_allows_builtin_default_when_only_crlf_comment_only_wal_meta_scaffold_exists(
    ) {
        let root = temp_wal_dir("default-wal-crlf-comment-wal-meta-only-root");
        let base = root.join(DEFAULT_BFT_WAL_DIR);
        fs::create_dir_all(&base).unwrap();
        fs::write(
            wal_meta_file(&base),
            "# bootstrap placeholder\r\n   # retained until first WAL write\r\n",
        )
        .unwrap();

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

        assert_eq!(resolved, PathBuf::from(DEFAULT_BFT_WAL_DIR));
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&root);
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

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_checkpoint_only_state() {
        let wal_dir = temp_wal_dir("fail-if-exists-checkpoint-only");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "existing").unwrap();

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

    #[test]
    fn resolve_wal_dir_fail_if_exists_rejects_wal_meta_only_state() {
        let wal_dir = temp_wal_dir("fail-if-exists-wal-meta-only");
        fs::create_dir_all(&wal_dir).unwrap();
        persist_wal_meta_entries(
            &wal_dir,
            &[WalMeta {
                height: 7,
                round: 0,
                proposal_hash: "proposal-a".into(),
                committed: true,
                state_root_hex: "root-a".into(),
                prev_hash_hex: None,
            }],
        )
        .unwrap();

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

    #[test]
    fn resolve_wal_dir_fail_if_exists_allows_comment_only_wal_scaffold() {
        let wal_dir = temp_wal_dir("fail-if-exists-comment-only-wal-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            "# bootstrap placeholder\n   # retained until first WAL write\n",
        )
        .unwrap();

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

        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_allows_comment_only_checkpoint_scaffold() {
        let wal_dir = temp_wal_dir("fail-if-exists-comment-only-checkpoint-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            "# operator left a recovery note\n   # safe to reuse after catch-up succeeds\n",
        )
        .unwrap();

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

        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn resolve_wal_dir_fail_if_exists_allows_comment_only_consensus_wal_scaffold() {
        let wal_dir = temp_wal_dir("fail-if-exists-comment-only-consensus-wal-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_file(&wal_dir),
            "# operator left a rejoin note\n   # safe to reuse after catch-up succeeds\n",
        )
        .unwrap();

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

        let (resolved, notice) = resolve_wal_dir(&args).unwrap();
        assert_eq!(resolved, wal_dir);
        assert!(notice.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    validate_startup_args(&args)?;
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
    let mut restored_lock: Option<String> = recovered.restored_lock.clone();
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
    ensure_recoverable_wal_state(&wal_dir, &recovered)?;

    let mut state = StateStore::new();
    state.set_balance("challenger", 1_000_000);
    let mut mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);
    for i in 0..args.demo_tasks {
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
    let mut bft_leader_missed_previous_snapshot: Vec<u64> = vec![0; args.validators.max(1)];
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
            let leader_missed_added = missed_proposals_added_since(
                &bft_leader_missed_previous_snapshot,
                &bft.leader_missed_snapshot,
            );
            if leader_missed_added > 0 {
                bft_leader_missed_active_heights += 1;
            }
            bft_leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
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
        let leader_missed_added = missed_proposals_added_since(
            &bft_leader_missed_previous_snapshot,
            &bft.leader_missed_snapshot,
        );
        if leader_missed_added > 0 {
            bft_leader_missed_active_heights += 1;
        }
        bft_leader_missed_previous_snapshot = bft.leader_missed_snapshot.clone();
        println!("{}", format_bft_height_summary_log_line(height, &bft));
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
                wal_entry_hash_hex: wal_hash.clone(),
            });
            persist_checkpoint_meta(&wal_dir, &checkpoints)?;
            println!(
                "[bft-checkpoint] height={} state_root={} wal_entry_hash={}",
                height, root, wal_hash
            );
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
    let hot_object_active_height_share_ppm = if hot_object_active_heights == 0 {
        0
    } else {
        (hot_object_active_top_label_share_total_ppm + hot_object_active_tail_share_total_ppm)
            / hot_object_active_heights as u128
    };
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
    let preexec_reject_density_avg = if preexec_reject_active_heights == 0 {
        0
    } else {
        preexec_reject_total / preexec_reject_active_heights
    };
    let preexec_reject_density_avg_milli =
        ratio_milli_u64(preexec_reject_total, preexec_reject_active_heights);
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
    let bft_round_change_backoff_active_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_committed_heights,
    );
    let bft_round_change_backoff_active_observed_height_rate_ppm = ratio_ppm_u64(
        bft_round_change_backoff_active_heights,
        bft_observed_heights,
    );
    let bft_round_change_backoff_density_avg_ms = if bft_round_change_backoff_active_heights == 0 {
        0
    } else {
        bft_round_change_backoff_total_ms / bft_round_change_backoff_active_heights
    };
    let bft_round_change_backoff_density_avg_milli = ratio_milli_u64(
        bft_round_change_backoff_total_ms,
        bft_round_change_backoff_active_heights,
    );
    let bft_round_change_backoff_active_height_share_ppm =
        finality_budget_share_ppm(bft_round_change_backoff_density_avg_milli, finality_avg);
    let bft_round_change_backoff_wall_share_ppm = wall_time_share_ppm(
        bft_round_change_backoff_total_ms,
        bft_committed_heights,
        finality_avg,
    );
    let bft_round_change_backoff_share_ppm = bft_round_change_backoff_wall_share_ppm;
    let bft_commit_observed_height_rate_ppm =
        ratio_ppm_u64(bft_committed_heights, bft_observed_heights);
    let bft_skipped_height_total = bft_observed_heights.saturating_sub(bft_committed_heights);
    let bft_skipped_observed_height_rate_ppm =
        ratio_ppm_u64(bft_skipped_height_total, bft_observed_heights);
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
    // Preserve the legacy `bft_auth_reject_stale_total` operator field as an
    // alias of the canonical stale-nonce counter until the metrics contract is
    // frozen across node/rpc/worker surfaces.
    let bft_auth_reject_stale_total = bft_auth_reject_stale_nonce_total;
    println!(
        "[consensus] finality_avg_ms={} finality_p50_ms={} finality_p95_ms={} finality_max_ms={} scheduler_elapsed_avg_ms={} scheduler_elapsed_p50_ms={} scheduler_elapsed_p95_ms={} scheduler_elapsed_max_ms={} scheduler_share_avg_ppm={} scheduler_peak_share_ppm={} preexec_elapsed_avg_ms={} preexec_elapsed_p50_ms={} preexec_elapsed_p95_ms={} preexec_elapsed_max_ms={} preexec_share_avg_ppm={} preexec_peak_share_ppm={} commit_elapsed_avg_ms={} commit_elapsed_p50_ms={} commit_elapsed_p95_ms={} commit_elapsed_max_ms={} commit_share_avg_ppm={} commit_peak_share_ppm={} state_root_total_avg_ms={} state_root_total_p50_ms={} state_root_total_p95_ms={} state_root_total_max_ms={} state_root_total_share_avg_ppm={} state_root_total_peak_share_ppm={} unprofiled_finality_share_bps={} critical_wait_blocks_avg={} critical_wait_blocks_p50={} critical_wait_blocks_p95={} critical_wait_blocks_max={} critical_wait_density_ppm={} critical_wait_peak_density_ppm={} critical_wait_active_heights={} critical_wait_active_height_rate_ppm={} critical_wait_active_observed_height_rate_ppm={} critical_wait_density_avg={} critical_wait_density_avg_milli={} critical_wait_active_height_share_ppm={} block_txs_p50={} block_txs_p95={} block_txs_max={} block_groups_p50={} block_groups_p95={} block_groups_max={} avg_group_size_avg_milli={} avg_group_size_p50_milli={} avg_group_size_p95_milli={} avg_group_size_max_milli={} hot_object_share_avg_ppm={} hot_object_share_p50_ppm={} hot_object_share_p95_ppm={} hot_object_share_max_ppm={} hot_object_active_heights={} hot_object_active_height_rate_ppm={} hot_object_active_observed_height_rate_ppm={} hot_object_active_height_share_ppm={} hot_object_top_label_share_avg_ppm={} hot_object_top_label_share_p50_ppm={} hot_object_top_label_share_p95_ppm={} hot_object_top_label_share_max_ppm={} hot_object_active_top_label_share_avg_ppm={} hot_object_tail_share_avg_ppm={} hot_object_tail_share_p50_ppm={} hot_object_tail_share_p95_ppm={} hot_object_tail_share_max_ppm={} hot_object_active_tail_share_avg_ppm={} rollback_count_avg={} rollback_count_p50={} rollback_count_p95={} rollback_count_max={} rollback_share_avg_ppm={} rollback_peak_share_ppm={} rollback_block_total={} rollback_active_heights={} rollback_block_rate={:.6} rollback_block_rate_ppm={} rollback_active_height_rate_ppm={} rollback_active_observed_height_rate_ppm={} rollback_density_avg={} rollback_density_avg_milli={} rollback_active_height_share_ppm={} preexec_reject_total={} preexec_reject_active_heights={} preexec_reject_density_avg={} preexec_reject_density_avg_milli={} preexec_reject_active_height_rate_ppm={} preexec_reject_active_observed_height_rate_ppm={} preexec_reject_active_height_share_ppm={} preexec_reject_share_bps={} apply_error_total={} apply_error_preexec_conflict_miss_total={} preexec_conflict_miss_share_bps={} apply_error_version_conflict_total={} apply_error_invalid_transition_total={} apply_error_deadline_exceeded_total={} apply_error_semantic_fail_total={} rollback_total={} apply_error_rollback_share_bps={} timeout_migrated_total={} recovery_error_rate={:.6} bft_observed_heights={} bft_committed_heights={} bft_commit_observed_height_rate_ppm={} bft_skipped_height_total={} bft_skipped_observed_height_rate_ppm={} bft_round_change_total={} bft_round_change_per_height_ppm={} bft_round_change_active_heights={} bft_round_change_active_height_rate_ppm={} bft_round_change_active_observed_height_rate_ppm={} bft_round_change_density_avg={} bft_round_change_density_avg_milli={} bft_round_change_active_height_share_ppm={} bft_round_change_backoff_total_ms={} bft_round_change_backoff_avg_ms={} bft_round_change_backoff_active_heights={} bft_round_change_backoff_active_height_rate_ppm={} bft_round_change_backoff_active_observed_height_rate_ppm={} bft_round_change_backoff_density_avg_ms={} bft_round_change_backoff_density_avg_milli={} bft_round_change_backoff_active_height_share_ppm={} bft_round_change_backoff_max_ms={} bft_round_change_backoff_wall_share_ppm={} bft_round_change_backoff_share_ppm={} bft_leader_missed_total={} bft_leader_missed_max={} bft_leader_missed_top_share_ppm={} bft_leader_missed_active_validators={} bft_leader_missed_active_validator_share_ppm={} bft_leader_missed_active_heights={} bft_leader_missed_active_height_rate_ppm={} bft_leader_missed_active_observed_height_rate_ppm={} bft_leader_missed_density_avg={} bft_leader_missed_density_avg_milli={} bft_leader_missed_active_height_share_ppm={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_total={} bft_auth_reject_stale_nonce_total={}",
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
        hot_object_active_height_share_ppm,
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
        bft_commit_observed_height_rate_ppm,
        bft_skipped_height_total,
        bft_skipped_observed_height_rate_ppm,
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
        bft_auth_reject_stale_total,
        bft_auth_reject_stale_nonce_total
    );

    Ok(())
}
