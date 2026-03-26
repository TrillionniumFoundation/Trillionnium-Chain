use super::*;

pub(crate) fn recover_wal_state(wal_dir: &Path) -> Result<RecoveredWalState> {
    let entries = load_wal_meta_entries(wal_dir)?;
    let checkpoints = load_checkpoint_meta(wal_dir)?;
    let last_checkpoint =
        verify_wal_and_find_checkpoint(&checkpoints, &entries).map_err(anyhow::Error::msg)?;

    let mut truncated = false;
    if entries.is_empty() && checkpoints.is_empty() && wal_file(wal_dir).exists() {
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: 1,
                last_round: 0,
                locked_block_hash: None,
            },
        )?;
        truncated = true;
    }
    if entries.is_empty() && !checkpoints.is_empty() {
        persist_checkpoint_meta(wal_dir, &[])?;
        truncated = true;
    }
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
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        });
    }

    let mut valid_entries = entries.clone();
    let mut metadata_only_tail_discarded = false;
    let mut committed_tail_beyond_checkpoint_discarded = false;
    if let Some(cp) = &last_checkpoint {
        if let Some(idx) = entries
            .iter()
            .position(|e| e.height == cp.height && e.content_hash_hex() == cp.wal_entry_hash_hex)
        {
            if idx + 1 < entries.len() {
                let discarded_tail = &entries[idx + 1..];
                metadata_only_tail_discarded = discarded_tail.iter().any(|e| !e.committed);
                let retained_tip_hash = entries[idx].content_hash_hex();
                committed_tail_beyond_checkpoint_discarded = discarded_tail.iter().any(|e| {
                    e.committed
                        && e.height > cp.height
                        && e.prev_hash_hex.as_deref() == Some(retained_tip_hash.as_str())
                });
                valid_entries.truncate(idx + 1);
                persist_wal_meta_entries(wal_dir, &valid_entries)?;
                truncated = true;
            }

            let retained_checkpoint_keys: HashSet<(u64, String, String)> = valid_entries
                .iter()
                .map(|entry| {
                    (
                        entry.height,
                        entry.state_root_hex.clone(),
                        entry.content_hash_hex(),
                    )
                })
                .collect();
            let mut seen_checkpoint_keys = HashSet::new();
            let mut valid_checkpoints: Vec<CheckpointMeta> = checkpoints
                .iter()
                .filter(|c| {
                    retained_checkpoint_keys.contains(&(
                        c.height,
                        c.state_root_hex.clone(),
                        c.wal_entry_hash_hex.clone(),
                    ))
                })
                .filter(|c| {
                    seen_checkpoint_keys.insert((
                        c.height,
                        c.state_root_hex.as_str(),
                        c.wal_entry_hash_hex.as_str(),
                    ))
                })
                .cloned()
                .collect();
            valid_checkpoints.sort_by(|a, b| {
                a.height
                    .cmp(&b.height)
                    .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
                    .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            });
            if valid_checkpoints != checkpoints {
                persist_checkpoint_meta(wal_dir, &valid_checkpoints)?;
                truncated = true;
            }
        }
    }

    if let Some(last) = valid_entries.last() {
        let retained_checkpoint_height = last_checkpoint.as_ref().map(|cp| cp.height);
        let retained_entry_count = valid_entries.len();
        let metadata_only_recovery = metadata_only_tail_discarded
            || committed_tail_beyond_checkpoint_discarded
            || retained_checkpoint_height
                .map(|checkpoint_height| checkpoint_height < last.height)
                .unwrap_or(retained_entry_count > 0);
        let restored_lock = if metadata_only_recovery {
            None
        } else {
            Some(last.proposal_hash.clone())
        };
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: last.height + 1,
                last_round: last.round,
                locked_block_hash: restored_lock.clone(),
            },
        )?;
        return Ok(RecoveredWalState {
            next_height: last.height + 1,
            restored_lock,
            checkpoint_height_retained: retained_checkpoint_height,
            last_checkpoint,
            truncated,
            metadata_only_recovery,
            wal_entries_retained: retained_entry_count,
        });
    }

    if truncated {
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height: 1,
                last_round: 0,
                locked_block_hash: None,
            },
        )?;
    }

    Ok(RecoveredWalState {
        next_height: 1,
        restored_lock: None,
        checkpoint_height_retained: last_checkpoint.as_ref().map(|cp| cp.height),
        last_checkpoint,
        truncated,
        metadata_only_recovery: false,
        wal_entries_retained: 0,
    })
}

fn retained_wal_summary(recovered: &RecoveredWalState) -> String {
    match recovered.wal_entries_retained {
        0 => "retained no committed WAL entries".into(),
        1 => format!(
            "retained 1 committed WAL entry through height {}",
            recovered.next_height.saturating_sub(1)
        ),
        count => format!(
            "retained {} committed WAL entries through height {}",
            count,
            recovered.next_height.saturating_sub(1)
        ),
    }
}

fn retained_checkpoint_surface(recovered: &RecoveredWalState) -> String {
    match &recovered.last_checkpoint {
        Some(checkpoint) => checkpoint.evidence_summary(),
        None => "none".into(),
    }
}

fn retained_checkpoint_da_surface(wal_dir: &Path, recovered: &RecoveredWalState) -> String {
    let Some(checkpoint) = &recovered.last_checkpoint else {
        return "none".into();
    };

    let Ok(entries) = load_wal_meta_entries(wal_dir) else {
        return "unavailable:wal_meta_unreadable".into();
    };

    let Some(entry) = entries.iter().find(|entry| {
        entry.height == checkpoint.height && entry.content_hash_hex() == checkpoint.wal_entry_hash_hex
    }) else {
        return "unavailable:no_matching_wal_entry".into();
    };

    trnm_state::checkpoint_da_light_verifier_summary(checkpoint, entry)
        .unwrap_or_else(|| "unavailable:noncanonical_checkpoint_wal_pair".into())
}

pub(crate) fn metadata_only_recovery_error(
    wal_dir: &Path,
    recovered: &RecoveredWalState,
) -> String {
    format!(
        "refusing metadata-only recovery from {}: verified WAL/checkpoint metadata {} (last retained checkpoint: {}; checkpoint_evidence: {}; checkpoint_da_surface: {}) but trnm-node does not yet restore application StateStore snapshots or replay committed blocks; start from a fresh --bft-wal-dir / --bft-wal-mode auto isolated run, or implement state snapshot+replay recovery first",
        wal_dir.display(),
        retained_wal_summary(recovered),
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        retained_checkpoint_surface(recovered),
        retained_checkpoint_da_surface(wal_dir, recovered)
    )
}

pub(crate) fn ensure_recoverable_wal_state(
    wal_dir: &Path,
    recovered: &RecoveredWalState,
) -> Result<()> {
    if recovered.metadata_only_recovery {
        anyhow::bail!(metadata_only_recovery_error(wal_dir, recovered));
    }
    Ok(())
}
