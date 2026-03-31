use super::*;

fn has_empty_metadata_scaffold(wal_dir: &Path) -> bool {
    wal_meta_file(wal_dir).exists() || checkpoint_file(wal_dir).exists()
}

pub(crate) fn recover_wal_state(wal_dir: &Path) -> Result<RecoveredWalState> {
    let entries = load_wal_meta_entries(wal_dir)?;
    let checkpoints = load_checkpoint_meta(wal_dir)?;
    let mut last_checkpoint = verify_wal_and_find_checkpoint_node_recovery(&checkpoints, &entries)
        .map_err(anyhow::Error::msg)?;

    let mut truncated = false;
    if entries.is_empty()
        && checkpoints.is_empty()
        && (wal_file(wal_dir).exists() || has_empty_metadata_scaffold(wal_dir))
    {
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
        last_checkpoint = None;
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
                    .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
                    .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
            });
            if valid_checkpoints != checkpoints {
                persist_checkpoint_meta(wal_dir, &valid_checkpoints)?;
                truncated = true;
            }
            last_checkpoint = valid_checkpoints.last().cloned();
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
        let restored_round =
            if metadata_only_recovery && !committed_tail_beyond_checkpoint_discarded {
                0
            } else {
                last.round
            };
        let next_height = last.height.saturating_add(1);
        persist_consensus_wal(
            wal_dir,
            &ConsensusWal {
                next_height,
                last_round: restored_round,
                locked_block_hash: restored_lock.clone(),
            },
        )?;
        return Ok(RecoveredWalState {
            next_height,
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
    let base = match recovered.wal_entries_retained {
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
    };

    if recovered.wal_entries_retained == 0 {
        return base;
    }

    let tip_height = recovered.next_height.saturating_sub(1);
    match recovered.checkpoint_height_retained {
        Some(checkpoint_height) if checkpoint_height < tip_height => {
            let lag = tip_height - checkpoint_height;
            let blocks = if lag == 1 { "block" } else { "blocks" };
            format!(
                "{} (checkpoint lags retained WAL tip by {} {})",
                base, lag, blocks
            )
        }
        None => format!("{} (no retained checkpoint metadata)", base),
        Some(_) => base,
    }
}

pub(crate) fn metadata_only_recovery_error(
    wal_dir: &Path,
    recovered: &RecoveredWalState,
) -> String {
    format!(
        "refusing metadata-only recovery from {}: verified WAL/checkpoint metadata {} (last retained checkpoint: {}, next startup height: {}); incident clue: metadata_only_recovery=1 wal_entries_retained={} wal_tail_truncated={} checkpoint_height_retained={} next_startup_height={} but trnm-node does not yet restore application StateStore snapshots or replay committed blocks; start from a fresh --bft-wal-dir / --bft-wal-mode auto isolated run, or implement state snapshot+replay recovery first",
        wal_dir.display(),
        retained_wal_summary(recovered),
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        recovered.next_height,
        recovered.wal_entries_retained,
        recovered.truncated,
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        recovered.next_height,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_wal_dir(name: &str) -> PathBuf {
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "trnm-node-runtime-recovery-scan-{}-{}-{}",
            name,
            std::process::id(),
            now_nanos
        ))
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_wal_meta_file_exists() {
        let wal_dir = temp_wal_dir("empty-wal-meta-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_only_empty_checkpoint_file_exists() {
        let wal_dir = temp_wal_dir("empty-checkpoint-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_resets_stale_consensus_wal_when_empty_metadata_scaffolds_both_exist() {
        let wal_dir = temp_wal_dir("empty-both-scaffolds");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 29,
                last_round: 4,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_wal_meta_entries(&wal_dir, &[]).unwrap();
        persist_checkpoint_meta(&wal_dir, &[]).unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn recover_clears_checkpoint_only_metadata_and_resets_consensus_wal() {
        let wal_dir = temp_wal_dir("checkpoint-only-metadata");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_consensus_wal(
            &wal_dir,
            &ConsensusWal {
                next_height: 41,
                last_round: 7,
                locked_block_hash: Some("stale-lock".into()),
            },
        )
        .unwrap();
        persist_checkpoint_meta(
            &wal_dir,
            &[CheckpointMeta {
                height: 40,
                state_root_hex: "ab".repeat(32),
                wal_entry_hash_hex: "cd".repeat(32),
            }],
        )
        .unwrap();

        let recovered = recover_wal_state(&wal_dir).unwrap();
        assert_eq!(recovered.next_height, 1);
        assert!(recovered.restored_lock.is_none());
        assert!(recovered.last_checkpoint.is_none());
        assert!(recovered.truncated);
        assert!(!recovered.metadata_only_recovery);
        assert_eq!(recovered.wal_entries_retained, 0);
        assert_eq!(recovered.checkpoint_height_retained, None);

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());
        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());
        let wal = fs::read_to_string(wal_file(&wal_dir)).unwrap();
        let wal: ConsensusWal = toml::from_str(&wal).unwrap();
        assert_eq!(wal.next_height, 1);
        assert_eq!(wal.last_round, 0);
        assert!(wal.locked_block_hash.is_none());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn ensure_recoverable_wal_state_rejects_metadata_only_recovery_with_checkpoint_context() {
        let wal_dir = temp_wal_dir("metadata-only-rejection");
        let recovered = RecoveredWalState {
            next_height: 18,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 17,
                state_root_hex: "aa".repeat(32),
                wal_entry_hash_hex: "bb".repeat(32),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(16),
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("refusing metadata-only recovery")
                && err.contains("checkpoint lags retained WAL tip by 1 block")
                && err.contains("last retained checkpoint: 16")
                && err.contains("next startup height: 18")
                && err.contains("incident clue: metadata_only_recovery=1")
                && err.contains("wal_entries_retained=2")
                && err.contains("wal_tail_truncated=true")
                && err.contains("checkpoint_height_retained=16")
                && err.contains("next_startup_height=18"),
            "unexpected metadata-only recovery error: {err}"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_rejects_metadata_only_recovery_without_retained_checkpoint_metadata() {
        let wal_dir = temp_wal_dir("metadata-only-no-checkpoint");
        let recovered = RecoveredWalState {
            next_height: 6,
            restored_lock: None,
            last_checkpoint: None,
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 1,
            checkpoint_height_retained: None,
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("refusing metadata-only recovery")
                && err.contains("retained 1 committed WAL entry through height 5")
                && err.contains("no retained checkpoint metadata")
                && err.contains("last retained checkpoint: none")
                && err.contains("next startup height: 6"),
            "unexpected metadata-only recovery error: {err}"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_plural_checkpoint_lag_for_metadata_only_recovery() {
        let wal_dir = temp_wal_dir("metadata-only-two-block-lag");
        let recovered = RecoveredWalState {
            next_height: 8,
            restored_lock: None,
            last_checkpoint: Some(CheckpointMeta {
                height: 5,
                state_root_hex: "aa".repeat(32),
                wal_entry_hash_hex: "bb".repeat(32),
            }),
            truncated: true,
            metadata_only_recovery: true,
            wal_entries_retained: 2,
            checkpoint_height_retained: Some(5),
        };

        let err = ensure_recoverable_wal_state(&wal_dir, &recovered)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("refusing metadata-only recovery")
                && err.contains("retained 2 committed WAL entries through height 7")
                && err.contains("checkpoint lags retained WAL tip by 2 blocks")
                && err.contains("last retained checkpoint: 5")
                && err.contains("next startup height: 8"),
            "unexpected metadata-only recovery error: {err}"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_fresh_or_fully_replayable_state() {
        let wal_dir = temp_wal_dir("recoverable-state-ok");
        let recovered = RecoveredWalState {
            next_height: 1,
            restored_lock: None,
            last_checkpoint: None,
            truncated: false,
            metadata_only_recovery: false,
            wal_entries_retained: 0,
            checkpoint_height_retained: None,
        };

        ensure_recoverable_wal_state(&wal_dir, &recovered).unwrap();
    }
}
