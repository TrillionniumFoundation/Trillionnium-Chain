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
use trnm_state::StateStore;
use trnm_types::{Hash32, ObjectRef, Tx};

#[derive(Debug, Parser)]
#[command(name = "trnm-node", version, about = "Trillionnium Rust node (mock execution loop)")]
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
    /// Consensus WAL directory for restart recovery
    #[arg(long, default_value = "run/consensus-wal")]
    bft_wal_dir: String,
}

#[derive(Debug, Deserialize)]
struct NodeConfig {
    node_id: String,
    rpc_addr: String,
    p2p_addr: String,
}

#[derive(Debug, Clone)]
enum MockTx {
    CreateTask { task_id: u64, creator: String, bounty: u128 },
    AcceptTask { task_id: u64, worker: String },
    Commit { task_id: u64, worker: String, committed_hash: Hash32 },
    Reveal { task_id: u64, result_hash: Hash32, reveal_salt: [u8; 32] },
    Challenge { task_id: u64 },
    Resolve { task_id: u64, slash_worker: bool },
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
struct BftHeightResult {
    committed: bool,
    committed_round: u64,
    round_changes: u64,
    prevote_count: usize,
    precommit_count: usize,
    double_vote_events: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConsensusWal {
    next_height: u64,
    last_round: u64,
    locked_block_hash: Option<String>,
}

fn wal_file(wal_dir: &Path) -> PathBuf {
    wal_dir.join("consensus-wal.toml")
}

fn load_consensus_wal(wal_dir: &Path) -> Result<Option<ConsensusWal>> {
    let f = wal_file(wal_dir);
    if !f.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&f).with_context(|| format!("read wal failed: {}", f.display()))?;
    let wal: ConsensusWal = toml::from_str(&raw).with_context(|| format!("parse wal failed: {}", f.display()))?;
    Ok(Some(wal))
}

fn persist_consensus_wal(wal_dir: &Path, wal: &ConsensusWal) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_file(wal_dir);
    let raw = toml::to_string(wal)?;
    fs::write(&f, raw).with_context(|| format!("write wal failed: {}", f.display()))?;
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

fn aggregate_votes(votes: &[BftVote], vote_type: VoteType) -> HashMap<String, usize> {
    let mut m = HashMap::new();
    for v in votes.iter().filter(|v| v.vote_type == vote_type) {
        *m.entry(v.block_hash.clone()).or_insert(0) += 1;
    }
    m
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
) -> (bool, usize, usize, Option<String>, usize) {
    let n = validators.max(1);
    let b = byzantine.min(n.saturating_sub(1));
    let q = quorum_threshold(n);
    let proposer_idx = proposer(height, round, n);
    let proposer_id = format!("v{}", proposer_idx + 1);
    let round_hash = locked_hash.unwrap_or(proposal_hash).to_string();

    println!("[bft] height={} round={} step={:?} proposer={} validators={} byzantine={} quorum={} locked={}", height, round, RoundStep::Propose, proposer_id, n, b, q, locked_hash.is_some());

    let mut votes = Vec::new();
    let bad_hash = hash32_hex(&[b"byzantine", round_hash.as_bytes()].concat());
    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let vh = if is_bad { bad_hash.clone() } else { round_hash.clone() };
        votes.push(BftVote { validator: vid.clone(), vote_type: VoteType::Prevote, block_hash: vh, byzantine: is_bad, height, round });
        // Byzantine equivocation sample: same validator emits conflicting prevote.
        if is_bad {
            votes.push(BftVote { validator: vid, vote_type: VoteType::Prevote, block_hash: round_hash.clone(), byzantine: true, height, round });
        }
    }
    println!("[bft] height={} round={} step={:?}", height, round, RoundStep::Prevote);

    let prevote_tally = aggregate_votes(&votes, VoteType::Prevote);
    let prevote_count = *prevote_tally.get(&round_hash).unwrap_or(&0);
    let new_lock = if prevote_count >= q { Some(round_hash.clone()) } else { None };

    for i in 0..n {
        let vid = format!("v{}", i + 1);
        let is_bad = i < b;
        let vote_hash = if prevote_count >= q && !is_bad { round_hash.clone() } else { bad_hash.clone() };
        votes.push(BftVote { validator: vid.clone(), vote_type: VoteType::Precommit, block_hash: vote_hash, byzantine: is_bad, height, round });
        if is_bad {
            votes.push(BftVote { validator: vid, vote_type: VoteType::Precommit, block_hash: round_hash.clone(), byzantine: true, height, round });
        }
    }
    println!("[bft] height={} round={} step={:?}", height, round, RoundStep::Precommit);

    let precommit_tally = aggregate_votes(&votes, VoteType::Precommit);
    let precommit_count = *precommit_tally.get(&round_hash).unwrap_or(&0);
    let unique_voters: HashSet<String> = votes.iter().map(|v| v.validator.clone()).collect();
    let byzantine_votes = votes.iter().filter(|v| v.byzantine).count();
    let double_vote_events = detect_double_votes(&votes, VoteType::Prevote)
        + detect_double_votes(&votes, VoteType::Precommit);
    let committed = precommit_count >= q;
    if committed {
        println!("[bft] height={} round={} step={:?} block_hash={} precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={}", height, round, RoundStep::Commit, round_hash, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events);
    } else {
        println!("[bft] height={} round={} step=RoundChange reason=no_quorum precommit={}/{} unique_voters={} byzantine_votes={} double_vote_events={}", height, round, precommit_count, n, unique_voters.len(), byzantine_votes, double_vote_events);
    }

    (committed, prevote_count, precommit_count, new_lock, double_vote_events)
}

fn simulate_bft_height(
    height: u64,
    proposal_hash: &str,
    validators: usize,
    byzantine: usize,
    max_rounds: u64,
    fault_rounds: u64,
    initial_lock: Option<String>,
) -> BftHeightResult {
    let mut locked: Option<String> = initial_lock;
    let mut round_changes = 0u64;
    let mut last_prevote = 0usize;
    let mut last_precommit = 0usize;
    let mut total_double_vote_events = 0usize;

    for round in 0..max_rounds.max(1) {
        let effective_byz = if round < fault_rounds { validators.saturating_sub(1) } else { byzantine };
        let (committed, pv, pc, new_lock, dv) = simulate_bft_round(
            height,
            round,
            proposal_hash,
            locked.as_deref(),
            validators,
            effective_byz,
        );
        last_prevote = pv;
        last_precommit = pc;
        total_double_vote_events += dv;
        if new_lock.is_some() {
            locked = new_lock;
        }
        if committed {
            return BftHeightResult {
                committed: true,
                committed_round: round,
                round_changes,
                prevote_count: pv,
                precommit_count: pc,
                double_vote_events: total_double_vote_events,
            };
        }
        round_changes += 1;
    }

    BftHeightResult {
        committed: false,
        committed_round: max_rounds.saturating_sub(1),
        round_changes,
        prevote_count: last_prevote,
        precommit_count: last_precommit,
        double_vote_events: total_double_vote_events,
    }
}

fn hash32_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn load_config(path: &str) -> Result<NodeConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("read config failed: {}", path))?;
    let cfg: NodeConfig = toml::from_str(&raw).with_context(|| format!("parse toml failed: {}", path))?;
    Ok(cfg)
}

fn compute_commitment(task_id: u64, result_hash: &Hash32, reveal_salt: &[u8; 32], worker: &str) -> Hash32 {
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
            let resolution_code = if *slash_worker { "slashed" } else { "completed" };
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
    let write_obj = ObjectRef { id: key, version: 1 };

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

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args.config)?;

    println!("[node] start");
    println!("[node] id={} rpc={} p2p={}", cfg.node_id, cfg.rpc_addr, cfg.p2p_addr);
    println!("[node] block_ms={} max_blocks={}", args.block_ms, args.max_blocks);
    println!("[node] load demo_tasks={} demo_keys={}", args.demo_tasks, args.demo_keys);
    println!("[node] parallel_workers={}", args.parallel_workers);
    println!("[node] bft validators={} byzantine={} max_rounds={} fault_rounds={} wal_dir={}", args.validators, args.byzantine, args.bft_max_rounds, args.bft_fault_rounds, args.bft_wal_dir);

    let wal_dir = PathBuf::from(&args.bft_wal_dir);
    let mut restored_lock: Option<String> = None;
    let mut height: u64 = 1;
    if let Some(wal) = load_consensus_wal(&wal_dir)? {
        height = wal.next_height.max(1);
        restored_lock = wal.locked_block_hash.clone();
        println!(
            "[bft-recover] restored height={} round={} lock={}",
            wal.next_height,
            wal.last_round,
            wal.locked_block_hash.unwrap_or_else(|| "none".to_string())
        );
    }

    let mut state = StateStore::new();
    let mut mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);
    let mut finality_samples_ms: Vec<u128> = Vec::new();
    let mut preexec_reject_total: u64 = 0;
    let mut apply_error_total: u64 = 0;
    let mut rollback_total: u64 = 0;
    let mut bft_committed_heights: u64 = 0;
    let mut bft_round_change_total: u64 = 0;
    let mut bft_double_vote_total: u64 = 0;

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
        );
        if !bft.committed {
            bft_round_change_total += bft.round_changes;
            bft_double_vote_total += bft.double_vote_events as u64;
            println!(
                "[block] node={} height={} skipped reason=bft_no_commit proposal_hash={} prevote={} precommit={} rounds={}",
                cfg.node_id,
                height,
                proposal_hash,
                bft.prevote_count,
                bft.precommit_count,
                args.bft_max_rounds
            );
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
        println!(
            "[bft] height={} committed_round={} prevote={} precommit={} round_changes={} double_vote_events={}",
            height, bft.committed_round, bft.prevote_count, bft.precommit_count, bft.round_changes, bft.double_vote_events
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
            let (ordered_ids, rejected) = pre_execute_group_parallel(&state, group_ids, &picked, args.parallel_workers);
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
                    println!("[tx] apply_error height={} tx_id={} err={} rollback=true", height, id, e);
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
        println!("[block] node={} height={} txs={} groups={} state_root={} elapsed_ms={}", cfg.node_id, height, applied, group_count, root, elapsed_ms);

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
    println!(
        "[consensus] finality_p50_ms={} finality_p95_ms={} preexec_reject_total={} apply_error_total={} rollback_total={} recovery_error_rate={:.6} bft_committed_heights={} bft_round_change_total={} bft_double_vote_total={}",
        finality_p50,
        finality_p95,
        preexec_reject_total,
        apply_error_total,
        rollback_total,
        recovery_error_rate,
        bft_committed_heights,
        bft_round_change_total,
        bft_double_vote_total
    );

    Ok(())
}
