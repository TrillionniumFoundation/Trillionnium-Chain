use std::{collections::VecDeque, path::PathBuf};

use anyhow::Result;
use trnm_state::{CheckpointMeta, StateStore, WalMeta};

use crate::args::Args;
use crate::bft::model::{BftJitterControl, LeaderHealth};
use crate::config::{load_config, NodeConfig};
use crate::demo::init_demo_state_and_mempool;
use crate::recovery::{
    ensure_recoverable_wal_state, recover_wal_state, recovery_startup_summary,
};
use crate::types::MockTx;
use crate::wal::{load_checkpoint_meta, load_wal_meta_entries, resolve_wal_dir};

pub(crate) struct BootstrappedNodeRuntime {
    pub(crate) cfg: NodeConfig,
    pub(crate) wal_dir: PathBuf,
    pub(crate) restored_lock: Option<String>,
    pub(crate) height: u64,
    pub(crate) state: StateStore,
    pub(crate) mempool: VecDeque<MockTx>,
    pub(crate) wal_entries: Vec<WalMeta>,
    pub(crate) checkpoints: Vec<CheckpointMeta>,
    pub(crate) bft_jitter: BftJitterControl,
}

pub(crate) fn bootstrap_node_runtime(args: &Args) -> Result<BootstrappedNodeRuntime> {
    let cfg = load_config(&args.config)?;

    println!("[node] start development_only=true legacy_harness=true production_ready=false");
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

    let (wal_dir, wal_notice) = resolve_wal_dir(args)?;
    if let Some(notice) = wal_notice {
        println!("{}", notice);
    }
    println!("[bft-wal] using wal_dir={}", wal_dir.display());
    let recovered = recover_wal_state(&wal_dir)?;
    let restored_lock = recovered.restored_lock.clone();
    let height = recovered.next_height.max(1);
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
    println!("[bft-recover] {}", recovery_startup_summary(&recovered));
    ensure_recoverable_wal_state(&wal_dir, &recovered)?;

    let (state, mempool) = init_demo_state_and_mempool(args.demo_tasks, args.demo_keys);
    let wal_entries = load_wal_meta_entries(&wal_dir)?;
    let checkpoints = load_checkpoint_meta(&wal_dir)?;
    let bft_jitter = BftJitterControl {
        missed_threshold: args.bft_missed_proposal_threshold,
        penalty_rounds: args.bft_leader_penalty_rounds,
        round_change_backoff_ms: args.bft_round_change_backoff_ms,
        round_change_backoff_cap_ms: args.bft_round_change_backoff_max_ms,
        leader_health: vec![LeaderHealth::default(); args.validators.max(1)],
    };

    Ok(BootstrappedNodeRuntime {
        cfg,
        wal_dir,
        restored_lock,
        height,
        state,
        mempool,
        wal_entries,
        checkpoints,
        bft_jitter,
    })
}
