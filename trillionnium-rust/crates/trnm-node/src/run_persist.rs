use std::path::Path;

use anyhow::Result;
use trnm_state::{
    checkpoint_da_light_verifier_summary, checkpoint_evidence_surface_is_canonical, CheckpointMeta,
    WalMeta,
};

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
        let checkpoint = CheckpointMeta {
            height,
            state_root_hex: state_root_hex.to_string(),
            wal_entry_hash_hex: wal_hash.clone(),
        };
        if checkpoint_evidence_surface_is_canonical(
            &checkpoint,
            wal_entries
                .last()
                .expect("just-pushed committed WAL entry must exist"),
        ) {
            let wal_entry = wal_entries
                .last()
                .expect("just-pushed committed WAL entry must exist");
            let checkpoint_summary = checkpoint.evidence_summary();
            let wal_summary = wal_entry.evidence_summary();
            let da_summary = checkpoint_da_light_verifier_summary(&checkpoint, wal_entry)
                .expect("canonical checkpoint evidence must produce a DA/light-verifier summary");
            checkpoints.push(checkpoint);
            persist_checkpoint_meta(wal_dir, checkpoints)?;
            println!(
                "[bft-checkpoint] {} {} da_light_summary={}",
                checkpoint_summary, wal_summary, da_summary
            );
        }
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
