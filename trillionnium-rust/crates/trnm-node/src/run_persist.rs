use std::path::Path;

use anyhow::Result;
use trnm_state::{CheckpointMeta, WalMeta};

use crate::types::ConsensusWal;
use crate::wal::{persist_checkpoint_meta, persist_consensus_wal, persist_wal_meta_entries};

pub(crate) fn persist_uncommitted_height(
    wal_dir: &Path,
    wal_entries: &mut Vec<WalMeta>,
    height: u64,
    committed_round: u64,
    proposal_hash: &str,
    state_root_hex: String,
) -> Result<()> {
    let wal_entry = WalMeta {
        height,
        round: committed_round,
        proposal_hash: proposal_hash.to_string(),
        committed: false,
        state_root_hex,
        prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
    };
    wal_entries.push(wal_entry);
    persist_wal_meta_entries(wal_dir, wal_entries)?;
    persist_consensus_wal(
        wal_dir,
        &ConsensusWal {
            next_height: height + 1,
            last_round: committed_round,
            locked_block_hash: Some(proposal_hash.to_string()),
        },
    )?;
    Ok(())
}

pub(crate) fn persist_committed_height(
    wal_dir: &Path,
    wal_entries: &mut Vec<WalMeta>,
    checkpoints: &mut Vec<CheckpointMeta>,
    height: u64,
    committed_round: u64,
    proposal_hash: &str,
    state_root_hex: &str,
    checkpoint_interval: u64,
) -> Result<()> {
    let wal_entry = WalMeta {
        height,
        round: committed_round,
        proposal_hash: proposal_hash.to_string(),
        committed: true,
        state_root_hex: state_root_hex.to_string(),
        prev_hash_hex: wal_entries.last().map(|e| e.content_hash_hex()),
    };
    let wal_hash = wal_entry.content_hash_hex();
    wal_entries.push(wal_entry);
    persist_wal_meta_entries(wal_dir, wal_entries)?;

    if checkpoint_interval > 0 && height % checkpoint_interval == 0 {
        checkpoints.push(CheckpointMeta {
            height,
            state_root_hex: state_root_hex.to_string(),
            wal_entry_hash_hex: wal_hash.clone(),
        });
        persist_checkpoint_meta(wal_dir, checkpoints)?;
        println!(
            "[bft-checkpoint] height={} state_root={} wal_entry_hash={}",
            height, state_root_hex, wal_hash
        );
    }

    persist_consensus_wal(
        wal_dir,
        &ConsensusWal {
            next_height: height + 1,
            last_round: committed_round,
            locked_block_hash: Some(proposal_hash.to_string()),
        },
    )?;
    Ok(())
}
