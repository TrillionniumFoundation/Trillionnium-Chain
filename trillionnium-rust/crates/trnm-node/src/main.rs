use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use trnm_executor::build_parallel_groups;
use trnm_pouw::{
    apply_accept_task, apply_challenge, apply_commit_result, apply_create_task, apply_resolve,
    apply_reveal_result,
};
use trnm_state::{verify_wal_and_find_checkpoint, CheckpointMeta, StateStore, WalMeta};
use trnm_types::{Hash32, ObjectRef, Tx};

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
    #[arg(long, default_value = "run/consensus-wal")]
    bft_wal_dir: String,
    /// Write one checkpoint metadata every N committed blocks
    #[arg(long, default_value_t = 5)]
    bft_checkpoint_interval: u64,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    node_id: String,
    rpc_addr: String,
    p2p_addr: String,
}

#[derive(Debug, Clone)]
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
    },
    Resolve {
        task_id: u64,
        slash_worker: bool,
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
    leader_missed_snapshot: Vec<u64>,
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
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WalMetaList {
    entries: Vec<WalMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CheckpointMetaList {
    checkpoints: Vec<CheckpointMeta>,
}

fn wal_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal.toml")
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
    let raw = fs::read_to_string(&f)
        .with_context(|| format!("read wal meta failed: {}", f.display()))?;
    let list: WalMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse wal meta failed: {}", f.display()))?;
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
    let last_checkpoint = verify_wal_and_find_checkpoint(&checkpoints, &entries)
        .map_err(anyhow::Error::msg)?;

    let mut truncated = false;
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
        });
    }

    let mut valid_entries = entries.clone();
    if let Some(cp) = &last_checkpoint {
        if let Some(idx) = entries.iter().position(|e| e.height == cp.height && e.content_hash_hex() == cp.wal_entry_hash_hex) {
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
        });
    }

    Ok(RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        last_checkpoint,
        truncated,
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

fn aggregate_votes(votes: &[BftVote], vote_type: VoteType) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        *m.entry(v.block_hash.clone()).or_insert(0) += 1;
    }
    m
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

fn accept_signed_vote(
    msg: SignedVote,
    last_nonce: &mut HashMap<(String, VoteType), u64>,
    accepted: &mut Vec<BftVote>,
    reject_stats: &mut AuthRejectStats,
) {
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

    let key = (msg.vote.validator.clone(), msg.vote.vote_type);
    if let Some(prev) = last_nonce.get(&key) {
        if msg.nonce == *prev {
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
    let mut auth_nonce: HashMap<(String, VoteType), u64> = HashMap::new();
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

fn build_demo_mempool(demo_tasks: u64, _demo_keys: u64) -> VecDeque<MockTx> {
    let mut q = VecDeque::new();

    for i in 0..demo_tasks.max(1) {
        let task_id = 1001u64 + i;
        let worker = format!("worker{}", task_id);
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
        q.push_back(MockTx::Challenge { task_id });
        q.push_back(MockTx::Resolve {
            task_id,
            slash_worker: false,
        });
    }

    q
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
        | MockTx::Challenge { task_id }
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

fn actor_of(tx: &MockTx) -> String {
    match tx {
        MockTx::CreateTask { creator, .. } => creator.clone(),
        MockTx::AcceptTask { worker, .. } => worker.clone(),
        MockTx::Commit { worker, .. } => worker.clone(),
        MockTx::Reveal { task_id, .. } => format!("worker{}", task_id),
        MockTx::Challenge { .. } => "challenger".to_string(),
        MockTx::Resolve { .. } => "authority".to_string(),
    }
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

fn emit_event(
    tx: &MockTx,
    tx_id: u64,
    block_height: u64,
    from_status: &str,
    to_status: &str,
    state_root: &str,
) {
    let task_id = task_id_of(tx);
    let event_type = event_type_of(tx);
    let actor = actor_of(tx);
    let ts_unix_ms = now_unix_ms();

    match tx {
        MockTx::Resolve { slash_worker, .. } => {
            let resolution_code = if *slash_worker {
                "slashed"
            } else {
                "completed"
            };
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} tx_id={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms,
                slash_worker,
                resolution_code
            );
        }
        _ => {
            println!(
                "[event] event_schema=v1 event_type={} task_id={} from_status={} to_status={} actor={} tx_id={} block_height={} state_root={} ts_unix_ms={}",
                event_type,
                task_id,
                from_status,
                to_status,
                actor,
                tx_id,
                block_height,
                state_root,
                ts_unix_ms
            );
        }
    }
}

fn is_high_risk_tx(tx: &MockTx) -> bool {
    matches!(
        tx,
        MockTx::CreateTask { .. }
            | MockTx::AcceptTask { .. }
            | MockTx::Commit { .. }
            | MockTx::Reveal { .. }
            | MockTx::Challenge { .. }
    )
}

fn apply_one(st: &mut StateStore, tx: MockTx) -> Result<()> {
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
            let _ = apply_accept_task(st, r, worker)?;
        }
        MockTx::Commit {
            task_id,
            worker,
            committed_hash,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_commit_result(st, r, worker, committed_hash)?;
        }
        MockTx::Reveal {
            task_id,
            result_hash,
            reveal_salt,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_reveal_result(st, r, result_hash, reveal_salt)?;
        }
        MockTx::Challenge { task_id } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_challenge(st, r)?;
        }
        MockTx::Resolve {
            task_id,
            slash_worker,
        } => {
            let r = task_ref(st, task_id)?;
            let _ = apply_resolve(st, r, slash_worker)?;
        }
    }
    Ok(())
}

fn read_write_decl(tx: &MockTx, tx_id: u64, demo_keys: u64) -> Tx {
    let task_id = match tx {
        MockTx::CreateTask { task_id, .. } => *task_id,
        MockTx::AcceptTask { task_id, .. } => *task_id,
        MockTx::Commit { task_id, .. } => *task_id,
        MockTx::Reveal { task_id, .. } => *task_id,
        MockTx::Challenge { task_id } => *task_id,
        MockTx::Resolve { task_id, .. } => *task_id,
    };
    let key = task_id % demo_keys.max(1);
    let write_obj = ObjectRef {
        id: key,
        version: 1,
    };

    Tx {
        id: tx_id,
        read_set: vec![write_obj.clone()],
        write_set: vec![write_obj],
        payload: vec![],
    }
}

fn pre_execute_group_parallel(
    snapshot: &StateStore,
    group_ids: Vec<u64>,
    picked: &[MockTx],
    workers: usize,
) -> (Vec<u64>, u64) {
    if group_ids.is_empty() {
        return (vec![], 0);
    }
    let workers = workers.max(1).min(group_ids.len());
    let (tx, rx) = mpsc::channel::<(u64, bool, String)>();

    let mut handles = Vec::with_capacity(workers);
    for w in 0..workers {
        let txc = tx.clone();
        let ids: Vec<u64> = group_ids
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(i, id)| if i % workers == w { Some(id) } else { None })
            .collect();
        let local_picked = picked.to_vec();
        let base = snapshot.clone();

        handles.push(thread::spawn(move || {
            for id in ids {
                let idx = (id - 1) as usize;
                let mut local_state = base.clone();
                let res = apply_one(&mut local_state, local_picked[idx].clone());
                match res {
                    Ok(_) => {
                        let _ = txc.send((id, true, String::new()));
                    }
                    Err(e) => {
                        let _ = txc.send((id, false, e.to_string()));
                    }
                }
            }
        }));
    }
    drop(tx);

    for h in handles {
        let _ = h.join();
    }

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

#[cfg(test)]
mod tests {
    use super::*;

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

    fn temp_wal_dir(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("trnm-node-{}-{}", name, now_unix_ms()));
        p
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

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 2);

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
        "[node] bft validators={} byzantine={} max_rounds={} fault_rounds={} missed_threshold={} penalty_rounds={} rc_backoff_ms={} rc_backoff_cap_ms={} wal_dir={} checkpoint_interval={}",
        args.validators,
        args.byzantine,
        args.bft_max_rounds,
        args.bft_fault_rounds,
        args.bft_missed_proposal_threshold,
        args.bft_leader_penalty_rounds,
        args.bft_round_change_backoff_ms,
        args.bft_round_change_backoff_max_ms,
        args.bft_wal_dir,
        args.bft_checkpoint_interval
    );

    let wal_dir = PathBuf::from(&args.bft_wal_dir);
    let recovered = recover_wal_state(&wal_dir)?;
    let mut restored_lock: Option<String> = recovered.restored_lock;
    let mut height: u64 = recovered.next_height.max(1);
    println!(
        "[bft-recover] restored height={} lock={} checkpoint={} truncated={}",
        height,
        restored_lock.clone().unwrap_or_else(|| "none".to_string()),
        recovered
            .last_checkpoint
            .as_ref()
            .map(|cp| cp.height.to_string())
            .unwrap_or_else(|| "none".to_string()),
        recovered.truncated
    );

    let mut state = StateStore::new();
    let mut mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);
    let mut finality_samples_ms: Vec<u128> = Vec::new();
    let mut preexec_reject_total: u64 = 0;
    let mut apply_error_total: u64 = 0;
    let mut rollback_total: u64 = 0;
    let mut bft_committed_heights: u64 = 0;
    let mut bft_round_change_total: u64 = 0;
    let mut bft_double_vote_total: u64 = 0;
    let mut bft_auth_reject_bad_sig_total: u64 = 0;
    let mut bft_auth_reject_replay_total: u64 = 0;
    let mut bft_auth_reject_stale_nonce_total: u64 = 0;
    let mut bft_round_change_backoff_total_ms: u64 = 0;
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
        let txs_per_block = 4usize;
        let mut picked: Vec<MockTx> = Vec::new();
        for _ in 0..txs_per_block {
            if let Some(tx) = mempool.pop_front() {
                picked.push(tx);
            }
        }

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
        if !bft.committed {
            bft_round_change_total += bft.round_changes;
            bft_double_vote_total += bft.double_vote_events as u64;
            bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
            bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
            bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
            bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
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
        bft_double_vote_total += bft.double_vote_events as u64;
        bft_auth_reject_bad_sig_total += bft.auth_reject_bad_sig as u64;
        bft_auth_reject_replay_total += bft.auth_reject_replay as u64;
        bft_auth_reject_stale_nonce_total += bft.auth_reject_stale_nonce as u64;
        bft_round_change_backoff_total_ms += bft.round_change_backoff_total_ms;
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

        let plan: Vec<Tx> = picked
            .iter()
            .enumerate()
            .map(|(i, tx)| read_write_decl(tx, (i as u64) + 1, args.demo_keys))
            .collect();
        let groups = build_parallel_groups(&plan);
        let group_count = groups.len();

        let mut applied = 0u64;
        for g in groups {
            let group_ids: Vec<u64> = g.iter().map(|t| t.id).collect();
            let (ordered_ids, rejected) =
                pre_execute_group_parallel(&state, group_ids, &picked, args.parallel_workers);
            preexec_reject_total += rejected;

            for id in ordered_ids {
                let idx = (id - 1) as usize;
                let tx = picked[idx].clone();
                let task_id = task_id_of(&tx);
                let from_status = status_name(&state, task_id);

                if state.is_emergency_paused() && is_high_risk_tx(&tx) {
                    println!(
                        "[tx] rejected_by_pause height={} tx_id={} event_type={} emergency_pause=true",
                        height,
                        id,
                        event_type_of(&tx)
                    );
                    continue;
                }

                let before = state.clone();
                if let Err(e) = apply_one(&mut state, tx.clone()) {
                    state = before; // rollback on failed commit
                    apply_error_total += 1;
                    rollback_total += 1;
                    println!(
                        "[tx] apply_error height={} tx_id={} err={} rollback=true",
                        height, id, e
                    );
                } else {
                    applied += 1;
                    let to_status = status_name(&state, task_id);
                    let root = hex::encode(state.state_root());
                    emit_event(&tx, id, height, &from_status, &to_status, &root);
                }
            }
        }

        let root = hex::encode(state.state_root());
        let elapsed_ms = block_start.elapsed().as_millis();
        finality_samples_ms.push(elapsed_ms);
        println!(
            "[block] node={} height={} txs={} groups={} state_root={} elapsed_ms={}",
            cfg.node_id, height, applied, group_count, root, elapsed_ms
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
    println!(
        "[consensus] finality_p50_ms={} finality_p95_ms={} preexec_reject_total={} apply_error_total={} rollback_total={} recovery_error_rate={:.6} bft_committed_heights={} bft_round_change_total={} bft_round_change_backoff_total_ms={} bft_leader_missed_proposals={:?} bft_double_vote_total={} bft_auth_reject_bad_sig_total={} bft_auth_reject_replay_total={} bft_auth_reject_stale_nonce_total={}",
        finality_p50,
        finality_p95,
        preexec_reject_total,
        apply_error_total,
        rollback_total,
        recovery_error_rate,
        bft_committed_heights,
        bft_round_change_total,
        bft_round_change_backoff_total_ms,
        leader_missed_final,
        bft_double_vote_total,
        bft_auth_reject_bad_sig_total,
        bft_auth_reject_replay_total,
        bft_auth_reject_stale_nonce_total
    );

    Ok(())
}

