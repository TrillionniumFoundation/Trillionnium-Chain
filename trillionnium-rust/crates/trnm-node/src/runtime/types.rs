pub(crate) use anyhow::{Context, Result};
pub(crate) use clap::{Parser, ValueEnum};
pub(crate) use serde::{Deserialize, Serialize};
pub(crate) use sha2::{Digest, Sha256};
pub(crate) use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fs,
    path::{Path, PathBuf},
    sync::{mpsc, Arc, Condvar, Mutex},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{pre_execute_group_parallel, PreExecPool};
pub(crate) use trnm_executor::build_parallel_groups;
pub(crate) use trnm_mempool::{IngressClass, LaneAdmissionGate};
#[cfg(test)]
pub(crate) use trnm_pouw::{
    apply_accept_task, apply_challenge, apply_commit_result, apply_resolve, apply_reveal_result,
};
pub(crate) use trnm_pouw::{
    apply_accept_task_at_height, apply_challenge_at_height, apply_commit_result_at_height,
    apply_create_task, apply_resolve_at_height, apply_reveal_result_at_height, apply_timeout,
};
pub(crate) use trnm_state::{
    checkpoint_evidence_surface_is_canonical, verify_wal_and_find_checkpoint, CheckpointMeta,
    PendingResolveApprovalSnapshot, StateStore, WalMeta,
};
pub(crate) use trnm_types::{Hash32, ObjectRef, TaskMeteringSnapshot, TaskStatus, Tx};

#[path = "types/bft.rs"]
mod bft;
pub(crate) use bft::*;

#[path = "types/wal.rs"]
mod wal;
pub(crate) use wal::*;

#[path = "types/ordering.rs"]
mod ordering;
pub(crate) use ordering::*;

#[derive(Debug, Parser)]
#[command(
    name = "trnm-node",
    version,
    about = "Trillionnium Rust node (mock execution loop)"
)]
pub(crate) struct Args {
    #[arg(long, default_value = "configs/node1.toml")]
    pub(crate) config: String,
    #[arg(long, default_value_t = 1000)]
    pub(crate) block_ms: u64,
    #[arg(long, default_value_t = 10)]
    pub(crate) max_blocks: u64,
    /// Number of task flows injected into demo mempool
    #[arg(long, default_value_t = 2)]
    pub(crate) demo_tasks: u64,
    /// Number of distinct task ids used by injected load (smaller => higher conflict)
    #[arg(long, default_value_t = 2)]
    pub(crate) demo_keys: u64,
    /// Worker count used for group parallel pre-execution
    #[arg(long, default_value_t = 4)]
    pub(crate) parallel_workers: usize,
    /// Number of mempool txs attempted per committed block
    #[arg(long, default_value_t = 4)]
    pub(crate) txs_per_block: usize,
    /// Validator set size for BFT round simulation
    #[arg(long, default_value_t = 4)]
    pub(crate) validators: usize,
    /// Byzantine validators simulated in BFT vote aggregation
    #[arg(long, default_value_t = 0)]
    pub(crate) byzantine: usize,
    /// Max rounds per height before giving up commit (round-change path)
    #[arg(long, default_value_t = 3)]
    pub(crate) bft_max_rounds: u64,
    /// Inject no-quorum faulty rounds at beginning of each height
    #[arg(long, default_value_t = 0)]
    pub(crate) bft_fault_rounds: u64,
    /// Missed proposal threshold before leader is de-weighted/skipped
    #[arg(long, default_value_t = 2)]
    pub(crate) bft_missed_proposal_threshold: u64,
    /// Rounds to penalize leader after crossing missed proposal threshold
    #[arg(long, default_value_t = 2)]
    pub(crate) bft_leader_penalty_rounds: u64,
    /// Base backoff milliseconds applied on each round-change
    #[arg(long, default_value_t = 5)]
    pub(crate) bft_round_change_backoff_ms: u64,
    /// Max cap for round-change backoff milliseconds
    #[arg(long, default_value_t = 40)]
    pub(crate) bft_round_change_backoff_max_ms: u64,
    /// Consensus WAL directory for restart recovery
    #[arg(long, default_value = DEFAULT_BFT_WAL_DIR)]
    pub(crate) bft_wal_dir: String,
    /// How to handle the default WAL directory when no explicit isolated dir is provided.
    /// `auto` isolates repeated runs that use the built-in default path, while explicit custom
    /// paths keep legacy restart-recovery behavior.
    #[arg(long, value_enum, default_value_t = WalDirMode::Auto)]
    pub(crate) bft_wal_mode: WalDirMode,
    /// Write one checkpoint metadata every N committed blocks
    #[arg(long, default_value_t = 5)]
    pub(crate) bft_checkpoint_interval: u64,
    /// Enable PoUW timeout scanner in block loop (rollback switch)
    #[arg(long, default_value_t = true)]
    pub(crate) pouw_timeout_scan: bool,
    /// Run timeout scanner every N committed blocks (1 = every block)
    #[arg(long, default_value_t = 1)]
    pub(crate) pouw_timeout_scan_every_blocks: u64,
    /// P2 scaffold switch: enable DA/ordering decoupled path (default false keeps legacy path)
    #[arg(long, default_value_t = false)]
    pub(crate) enable_da_ordering_decouple: bool,
    /// Enable RL advisor in shadow mode (suggest only, never execute)
    #[arg(long, default_value_t = false)]
    pub(crate) rl_advisor_shadow: bool,
    /// Maximum suggested tx ids printed by shadow advisor
    #[arg(long, default_value_t = 4)]
    pub(crate) rl_advisor_shadow_topk: usize,
}

pub(crate) const DEFAULT_BFT_WAL_DIR: &str = "run/consensus-wal";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum WalDirMode {
    Auto,
    Reuse,
    FailIfExists,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeConfig {
    pub(crate) node_id: String,
    pub(crate) rpc_addr: String,
    pub(crate) p2p_addr: String,
}

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
