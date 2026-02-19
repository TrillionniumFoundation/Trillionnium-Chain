use anyhow::{Context, Result};
use clap::Parser;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fs,
    sync::mpsc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
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
                "[event] event_type={} task_id={} from_status={} to_status={} actor={} tx_id={} block_height={} state_root={} ts_unix_ms={} slash_worker={} resolution_code={}",
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
                "[event] event_type={} task_id={} from_status={} to_status={} actor={} tx_id={} block_height={} state_root={} ts_unix_ms={}",
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
) -> Vec<u64> {
    if group_ids.is_empty() {
        return vec![];
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
    for (id, ok, err) in rx {
        if ok {
            ok_ids.push(id);
        } else {
            println!("[preexec] tx_id={} rejected err={}", id, err);
        }
    }

    ok_ids.sort_unstable();
    ok_ids
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = load_config(&args.config)?;

    println!("[node] start");
    println!("[node] id={} rpc={} p2p={}", cfg.node_id, cfg.rpc_addr, cfg.p2p_addr);
    println!("[node] block_ms={} max_blocks={}", args.block_ms, args.max_blocks);
    println!("[node] load demo_tasks={} demo_keys={}", args.demo_tasks, args.demo_keys);
    println!("[node] parallel_workers={}", args.parallel_workers);

    let mut state = StateStore::new();
    let mut mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);

    let mut height: u64 = 1;
    loop {
        let txs_per_block = 4usize;
        let mut picked: Vec<MockTx> = Vec::new();
        for _ in 0..txs_per_block {
            if let Some(tx) = mempool.pop_front() {
                picked.push(tx);
            }
        }

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
            let ordered_ids = pre_execute_group_parallel(&state, group_ids, &picked, args.parallel_workers);

            for id in ordered_ids {
                let idx = (id - 1) as usize;
                let tx = picked[idx].clone();
                let task_id = task_id_of(&tx);
                let from_status = status_name(&state, task_id);

                let before = state.clone();
                if let Err(e) = apply_one(&mut state, tx.clone()) {
                    state = before; // rollback on failed commit
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
        println!("[block] node={} height={} txs={} groups={} state_root={}", cfg.node_id, height, applied, group_count, root);

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

    Ok(())
}
