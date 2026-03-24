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
        let wal_hash = runtime
            .wal_entries
            .last()
            .map(|entry| entry.content_hash_hex())
            .unwrap_or_default();
        runtime.checkpoints.push(CheckpointMeta {
            height: runtime.height,
            state_root_hex: runtime
                .wal_entries
                .last()
                .map(|entry| entry.state_root_hex.clone())
                .unwrap_or_default(),
            wal_entry_hash_hex: wal_hash,
        });
        persist_checkpoint_meta(&runtime.wal_dir, &runtime.checkpoints)?;
        println!(
            "[bft-checkpoint] height={} state_root={} wal_entry_hash={}",
            runtime.height,
            runtime
                .wal_entries
                .last()
                .map(|entry| entry.state_root_hex.as_str())
                .unwrap_or_default(),
            runtime
                .checkpoints
                .last()
                .map(|checkpoint| checkpoint.wal_entry_hash_hex.as_str())
                .unwrap_or_default()
        );
    }
    Ok(())
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
