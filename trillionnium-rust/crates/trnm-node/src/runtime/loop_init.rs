use super::*;

pub(crate) fn log_runtime_start(args: &Args, cfg: &NodeConfig) {
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
}

pub(crate) fn initialize_runtime_recovery(
    args: &Args,
) -> Result<(PathBuf, RecoveredWalState, Option<String>)> {
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
    Ok((wal_dir, recovered, restored_lock))
}

pub(crate) fn build_runtime_state(
    args: &Args,
    cfg: NodeConfig,
    wal_dir: PathBuf,
    recovered: RecoveredWalState,
    restored_lock: Option<String>,
) -> Result<RuntimeState> {
    let mut state = StateStore::new();
    state.set_balance("challenger", 1_000_000);
    let mempool = build_demo_mempool(args.demo_tasks, args.demo_keys);
    for i in 0..args.demo_tasks.max(1) {
        let worker = demo_worker_name(1001u64 + i);
        state.set_balance(&worker, 1_000_000);
    }

    Ok(RuntimeState {
        cfg,
        wal_dir: wal_dir.clone(),
        restored_lock,
        height: recovered.next_height.max(1),
        state,
        mempool,
        known_task_ids: HashSet::new(),
        wal_entries: load_wal_meta_entries(&wal_dir)?,
        checkpoints: load_checkpoint_meta(&wal_dir)?,
        bft_jitter: BftJitterControl {
            missed_threshold: args.bft_missed_proposal_threshold,
            penalty_rounds: args.bft_leader_penalty_rounds,
            round_change_backoff_ms: args.bft_round_change_backoff_ms,
            round_change_backoff_cap_ms: args.bft_round_change_backoff_max_ms,
            leader_health: vec![LeaderHealth::default(); args.validators.max(1)],
        },
    })
}
