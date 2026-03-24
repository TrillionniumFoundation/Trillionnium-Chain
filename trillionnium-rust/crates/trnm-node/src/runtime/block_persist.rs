use super::*;

pub(crate) fn persist_height_wal(
    runtime: &mut RuntimeState,
    proposal_hash: &str,
    state_root_hex: Option<String>,
    committed_round: u64,
    committed: bool,
) -> Result<()> {
    let wal_entry = WalMeta {
        height: runtime.height,
        round: committed_round,
        proposal_hash: proposal_hash.to_string(),
        committed,
        state_root_hex: state_root_hex.unwrap_or_else(|| hex::encode(runtime.state.state_root())),
        prev_hash_hex: runtime.wal_entries.last().map(|e| e.content_hash_hex()),
    };
    runtime.wal_entries.push(wal_entry);
    persist_wal_meta_entries(&runtime.wal_dir, &runtime.wal_entries)?;
    persist_consensus_wal(
        &runtime.wal_dir,
        &ConsensusWal {
            next_height: runtime.height + 1,
            last_round: committed_round,
            locked_block_hash: Some(proposal_hash.to_string()),
        },
    )?;
    Ok(())
}

pub(crate) fn persist_checkpoint_if_needed(args: &Args, runtime: &mut RuntimeState) -> Result<()> {
    if args.bft_checkpoint_interval > 0 && runtime.height % args.bft_checkpoint_interval == 0 {
        let Some(wal_entry) = runtime.wal_entries.last() else {
            return Ok(());
        };
        let checkpoint = CheckpointMeta {
            height: runtime.height,
            state_root_hex: wal_entry.state_root_hex.clone(),
            wal_entry_hash_hex: wal_entry.content_hash_hex(),
        };
        if checkpoint_evidence_surface_is_canonical(&checkpoint, wal_entry) {
            runtime.checkpoints.push(checkpoint.clone());
            persist_checkpoint_meta(&runtime.wal_dir, &runtime.checkpoints)?;
            println!(
                "[bft-checkpoint] height={} state_root={} wal_entry_hash={} proposal_hash={}",
                runtime.height,
                checkpoint.state_root_hex,
                checkpoint.wal_entry_hash_hex,
                proposal_hash
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_fixture(name: &str, height: u64) -> RuntimeState {
        let mut wal_dir = std::env::temp_dir();
        wal_dir.push(format!("trnm-node-checkpoint-surface-{name}-{}", std::process::id()));
        wal_dir.push(format!("{}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&wal_dir).unwrap();
        RuntimeState {
            cfg: NodeConfig {
                node_id: "node-test".into(),
                rpc_addr: "127.0.0.1:0".into(),
                p2p_addr: "127.0.0.1:0".into(),
            },
            wal_dir,
            restored_lock: None,
            height,
            state: StateStore::new(),
            mempool: VecDeque::new(),
            known_task_ids: HashSet::new(),
            wal_entries: Vec::new(),
            checkpoints: Vec::new(),
            bft_jitter: BftJitterControl {
                missed_threshold: 0,
                penalty_rounds: 0,
                round_change_backoff_ms: 0,
                round_change_backoff_cap_ms: 0,
                leader_health: vec![],
            },
        }
    }

    #[test]
    fn persist_checkpoint_if_needed_skips_uncommitted_wal_surface() {
        let args = Args::parse_from(["trnm-node", "--bft-checkpoint-interval", "1"]);
        let mut runtime = runtime_fixture("skip-uncommitted", 1);
        runtime.wal_entries.push(WalMeta {
            height: 1,
            round: 0,
            proposal_hash: "proposal-1".into(),
            committed: false,
            state_root_hex: "ab".repeat(32),
            prev_hash_hex: None,
        });

        persist_checkpoint_if_needed(&args, &mut runtime).unwrap();

        assert!(runtime.checkpoints.is_empty());
    }
}

pub(crate) enum StopCondition {
    MaxBlocksOnly,
    MaxBlocksOrEmpty,
}

pub(crate) fn advance_or_stop(
    args: &Args,
    runtime: &mut RuntimeState,
    stop: StopCondition,
) -> Result<bool> {
    if args.max_blocks > 0 && runtime.height >= args.max_blocks {
        println!("[node] reached max_blocks={}, exiting", args.max_blocks);
        return Ok(false);
    }
    if matches!(stop, StopCondition::MaxBlocksOrEmpty) && runtime.mempool.is_empty() {
        println!("[node] mempool empty, exiting");
        return Ok(false);
    }
    runtime.height += 1;
    thread::sleep(Duration::from_millis(args.block_ms));
    Ok(true)
}
