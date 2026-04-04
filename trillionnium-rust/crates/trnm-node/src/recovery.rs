use crate::types::{ConsensusWal, RecoveredWalState};
use crate::wal::{
    checkpoint_file, load_checkpoint_meta, load_wal_meta_entries, persist_checkpoint_meta,
    persist_consensus_wal, persist_wal_meta_entries, wal_file, wal_meta_file,
};
use anyhow::Result;
use std::{collections::HashSet, path::Path};
use trnm_state::{verify_wal_and_find_checkpoint_node_recovery, CheckpointMeta};

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

    let summary = if recovered.wal_entries_retained == 0 {
        match recovered.checkpoint_height_retained {
            Some(checkpoint_height) => format!(
                "{} (last retained checkpoint height {})",
                base, checkpoint_height
            ),
            None => base,
        }
    } else {
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
            Some(checkpoint_height) if checkpoint_height > tip_height => {
                let lead = checkpoint_height - tip_height;
                let blocks = if lead == 1 { "block" } else { "blocks" };
                format!(
                    "{} (retained checkpoint height {} is ahead of retained WAL tip height {} by {} {}; investigate WAL/checkpoint mismatch)",
                    base, checkpoint_height, tip_height, lead, blocks
                )
            },
            None => format!("{} (no retained checkpoint metadata)", base),
            Some(_) => base,
        }
    };

    if recovered.truncated {
        format!("{}; repaired WAL tail required truncation", summary)
    } else {
        summary
    }
}

fn checkpoint_tip_relation(recovered: &RecoveredWalState) -> String {
    if recovered.wal_entries_retained == 0 {
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| format!("checkpoint_only:{}", checkpoint_height))
            .unwrap_or_else(|| "none".into())
    } else {
        let tip_height = recovered.next_height.saturating_sub(1);
        match recovered.checkpoint_height_retained {
            Some(checkpoint_height) if checkpoint_height < tip_height => {
                format!("behind:{}", tip_height - checkpoint_height)
            }
            Some(checkpoint_height) if checkpoint_height > tip_height => {
                format!("ahead:{}", checkpoint_height - tip_height)
            }
            Some(_) => "aligned".into(),
            None => "missing".into(),
        }
    }
}

pub(crate) fn metadata_only_recovery_error(
    wal_dir: &Path,
    recovered: &RecoveredWalState,
) -> String {
    let recovery_summary = recovery_startup_summary(recovered);
    format!(
        "refusing metadata-only recovery from {}: verified WAL/checkpoint metadata {} (last retained checkpoint: {}, next startup height: {}); incident clue: {} but trnm-node does not yet restore application StateStore snapshots or replay committed blocks; start from a fresh --bft-wal-dir / --bft-wal-mode auto isolated run, or implement state snapshot+replay recovery first",
        wal_dir.display(),
        retained_wal_summary(recovered),
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        recovered.next_height,
        recovery_summary,
    )
}

fn join_rejoin_status(recovered: &RecoveredWalState) -> &'static str {
    if recovered.metadata_only_recovery {
        "blocked:metadata_only_recovery"
    } else if recovered.wal_entries_retained > 0 {
        match recovered.checkpoint_height_retained {
            None => {
                if recovered.truncated {
                    "ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
                } else {
                    "ready:retained_wal_resume_missing_checkpoint_metadata"
                }
            }
            Some(checkpoint_height) => {
                let tip_height = recovered.next_height.saturating_sub(1);
                if checkpoint_height < tip_height {
                    if recovered.truncated {
                        "ready:retained_wal_resume_checkpoint_lagging_after_tail_repair"
                    } else {
                        "ready:retained_wal_resume_checkpoint_lagging"
                    }
                } else if checkpoint_height > tip_height {
                    if recovered.truncated {
                        "ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
                    } else {
                        "ready:retained_wal_resume_checkpoint_ahead_mismatch"
                    }
                } else {
                    if recovered.truncated {
                        "ready:retained_wal_resume_after_tail_repair"
                    } else {
                        "ready:retained_wal_resume"
                    }
                }
            }
        }
    } else if recovered.checkpoint_height_retained.is_some() {
        if recovered.truncated {
            "ready:checkpoint_only_bootstrap_after_tail_repair"
        } else {
            "ready:checkpoint_only_bootstrap"
        }
    } else {
        if recovered.truncated {
            "ready:fresh_bootstrap_after_tail_repair"
        } else {
            "ready:fresh_bootstrap"
        }
    }
}

pub(crate) fn recovery_startup_summary(recovered: &RecoveredWalState) -> String {
    format!(
        "retained_wal_entries={} checkpoint_height_retained={} checkpoint_tip_relation={} next_startup_height={} wal_tail_truncated={} metadata_only_recovery={} join_rejoin_status={}",
        recovered.wal_entries_retained,
        recovered
            .checkpoint_height_retained
            .map(|checkpoint_height| checkpoint_height.to_string())
            .unwrap_or_else(|| "none".into()),
        checkpoint_tip_relation(recovered),
        recovered.next_height,
        recovered.truncated,
        recovered.metadata_only_recovery,
        join_rejoin_status(recovered),
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
    use super::{
        ensure_recoverable_wal_state, metadata_only_recovery_error, recovery_startup_summary,
        retained_wal_summary,
    };
    use crate::types::RecoveredWalState;
    use std::path::Path;

    fn recovered_state(
        wal_entries_retained: usize,
        next_height: u64,
        checkpoint_height_retained: Option<u64>,
        truncated: bool,
        metadata_only_recovery: bool,
    ) -> RecoveredWalState {
        RecoveredWalState {
            next_height,
            restored_lock: None,
            last_checkpoint: None,
            truncated,
            metadata_only_recovery,
            wal_entries_retained,
            checkpoint_height_retained,
        }
    }

    #[test]
    fn retained_wal_summary_reports_checkpoint_lag_for_retained_tip() {
        let recovered = recovered_state(3, 8, Some(5), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 3 committed WAL entries through height 7 (checkpoint lags retained WAL tip by 2 blocks)"
        );
    }

    #[test]
    fn retained_wal_summary_reports_missing_checkpoint_metadata() {
        let recovered = recovered_state(1, 9, None, false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 1 committed WAL entry through height 8 (no retained checkpoint metadata)"
        );
    }

    #[test]
    fn retained_wal_summary_uses_singular_block_for_single_height_lag() {
        let recovered = recovered_state(2, 12, Some(10), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (checkpoint lags retained WAL tip by 1 block)"
        );
    }

    #[test]
    fn retained_wal_summary_reports_checkpoint_ahead_of_retained_tip() {
        let recovered = recovered_state(2, 12, Some(15), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 15 is ahead of retained WAL tip height 11 by 4 blocks; investigate WAL/checkpoint mismatch)"
        );
    }

    #[test]
    fn retained_wal_summary_uses_singular_block_for_single_height_ahead_mismatch() {
        let recovered = recovered_state(2, 12, Some(12), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 12 is ahead of retained WAL tip height 11 by 1 block; investigate WAL/checkpoint mismatch)"
        );
    }

    #[test]
    fn retained_wal_summary_omits_extra_note_when_checkpoint_matches_retained_tip() {
        let recovered = recovered_state(2, 12, Some(11), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 11"
        );
    }

    #[test]
    fn retained_wal_summary_appends_truncation_notice() {
        let recovered = recovered_state(0, 1, None, true, false);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries; repaired WAL tail required truncation"
        );
    }

    #[test]
    fn retained_wal_summary_reports_checkpoint_height_without_retained_wal_entries() {
        let recovered = recovered_state(0, 9, Some(8), false, true);

        assert_eq!(
            retained_wal_summary(&recovered),
            "retained no committed WAL entries (last retained checkpoint height 8)"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_join_rejoin_triage_fields() {
        let recovered = recovered_state(2, 12, Some(10), true, true);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        );
    }

    #[test]
    fn recovery_startup_summary_handles_missing_checkpoint_metadata() {
        let recovered = recovered_state(1, 9, None, false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata"
        );
    }

    #[test]
    fn recovery_startup_summary_marks_missing_checkpoint_metadata_after_tail_repair() {
        let recovered = recovered_state(1, 9, None, true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_lagging_checkpoint_resume_state() {
        let recovered = recovered_state(3, 8, Some(5), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=3 checkpoint_height_retained=5 checkpoint_tip_relation=behind:2 next_startup_height=8 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_lag_visible_without_tail_repair() {
        let recovered = recovered_state(2, 12, Some(10), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_checkpoint_ahead_relation() {
        let recovered = recovered_state(2, 12, Some(15), false, true);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_checkpoint_ahead_resume_mismatch_surface() {
        let recovered = recovered_state(2, 12, Some(15), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_ahead_mismatch_visible() {
        let recovered = recovered_state(2, 12, Some(12), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch"
        );
    }

    #[test]
    fn recovery_startup_summary_marks_checkpoint_ahead_resume_mismatch_after_tail_repair() {
        let recovered = recovered_state(2, 12, Some(15), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_ahead_mismatch_visible_after_tail_repair() {
        let recovered = recovered_state(2, 12, Some(12), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=12 checkpoint_tip_relation=ahead:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_aligned_checkpoint_relation() {
        let recovered = recovered_state(2, 12, Some(11), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume"
        );
    }

    #[test]
    fn recovery_startup_summary_surfaces_checkpoint_only_relation_without_wal_entries() {
        let recovered = recovered_state(0, 9, Some(8), false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_bootstrap"
        );
    }

    #[test]
    fn recovery_startup_summary_marks_checkpoint_only_bootstrap_after_tail_repair() {
        let recovered = recovered_state(0, 9, Some(8), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_bootstrap_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_handles_empty_rejoin_bootstrap_state() {
        let recovered = recovered_state(0, 1, None, false, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap"
        );
    }

    #[test]
    fn recovery_startup_summary_handles_truncated_empty_rejoin_bootstrap_state() {
        let recovered = recovered_state(0, 1, None, true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_marks_truncated_retained_wal_resume_after_tail_repair() {
        let recovered = recovered_state(2, 12, Some(11), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_marks_truncated_lagging_resume_after_tail_repair() {
        let recovered = recovered_state(3, 8, Some(5), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=3 checkpoint_height_retained=5 checkpoint_tip_relation=behind:2 next_startup_height=8 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_after_tail_repair"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_single_block_checkpoint_lag_visible_after_tail_repair() {
        let recovered = recovered_state(2, 12, Some(10), true, false);

        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging_after_tail_repair"
        );
    }

    #[test]
    fn metadata_only_recovery_error_includes_operator_facing_summary() {
        let recovered = recovered_state(2, 12, Some(10), true, true);
        let error = metadata_only_recovery_error(Path::new("/tmp/trnm-wal"), &recovered);

        assert!(error.contains("/tmp/trnm-wal"));
        assert!(error.contains(
            "retained 2 committed WAL entries through height 11 (checkpoint lags retained WAL tip by 1 block); repaired WAL tail required truncation"
        ));
        assert!(error.contains("last retained checkpoint: 10"));
        assert!(error.contains("next startup height: 12"));
        assert!(error.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=10 checkpoint_tip_relation=behind:1 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(error.contains("wal_entries_retained=2"));
        assert!(error.contains("wal_tail_truncated=true"));
        assert!(error.contains("checkpoint_height_retained=10"));
        assert!(error.contains("checkpoint_tip_relation=behind:1"));
        assert!(error.contains("next_startup_height=12"));
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_missing_checkpoint_metadata_for_triage() {
        let recovered = recovered_state(1, 9, None, false, true);
        let error = metadata_only_recovery_error(Path::new("/tmp/trnm-wal"), &recovered);

        assert!(error.contains(
            "retained 1 committed WAL entry through height 8 (no retained checkpoint metadata)"
        ));
        assert!(error.contains("last retained checkpoint: none"));
        assert!(error.contains("next startup height: 9"));
        assert!(error.contains(
            "incident clue: retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(error.contains("wal_entries_retained=1"));
        assert!(error.contains("wal_tail_truncated=false"));
        assert!(error.contains("checkpoint_height_retained=none"));
        assert!(error.contains("checkpoint_tip_relation=missing"));
        assert!(error.contains("next_startup_height=9"));
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_checkpoint_ahead_mismatch_for_triage() {
        let recovered = recovered_state(2, 12, Some(15), false, true);
        let error = metadata_only_recovery_error(Path::new("/tmp/trnm-wal"), &recovered);

        assert!(error.contains(
            "retained 2 committed WAL entries through height 11 (retained checkpoint height 15 is ahead of retained WAL tip height 11 by 4 blocks; investigate WAL/checkpoint mismatch)"
        ));
        assert!(error.contains("last retained checkpoint: 15"));
        assert!(error.contains("next startup height: 12"));
        assert!(error.contains(
            "incident clue: retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(error.contains("wal_entries_retained=2"));
        assert!(error.contains("wal_tail_truncated=false"));
        assert!(error.contains("checkpoint_height_retained=15"));
        assert!(error.contains("checkpoint_tip_relation=ahead:4"));
        assert!(error.contains("next_startup_height=12"));
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_checkpoint_without_retained_wal_for_triage() {
        let recovered = recovered_state(0, 9, Some(8), false, true);
        let error = metadata_only_recovery_error(Path::new("/tmp/trnm-wal"), &recovered);

        assert!(error.contains(
            "retained no committed WAL entries (last retained checkpoint height 8)"
        ));
        assert!(error.contains("last retained checkpoint: 8"));
        assert!(error.contains("next startup height: 9"));
        assert!(error.contains(
            "incident clue: retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(error.contains("wal_entries_retained=0"));
        assert!(error.contains("wal_tail_truncated=false"));
        assert!(error.contains("checkpoint_height_retained=8"));
        assert!(error.contains("checkpoint_tip_relation=checkpoint_only:8"));
        assert!(error.contains("next_startup_height=9"));
    }

    #[test]
    fn metadata_only_recovery_error_surfaces_truncated_checkpoint_only_bootstrap_for_join_rejoin_triage() {
        let recovered = recovered_state(0, 9, Some(8), true, true);
        let error = metadata_only_recovery_error(Path::new("/tmp/trnm-wal"), &recovered);

        assert!(error.contains(
            "retained no committed WAL entries (last retained checkpoint height 8); repaired WAL tail required truncation"
        ));
        assert!(error.contains("last retained checkpoint: 8"));
        assert!(error.contains("next startup height: 9"));
        assert!(error.contains(
            "incident clue: retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=true join_rejoin_status=blocked:metadata_only_recovery"
        ));
        assert!(error.contains("checkpoint_tip_relation=checkpoint_only:8"));
        assert!(error.contains("wal_tail_truncated=true"));
        assert!(!error.contains("through height 0"));
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_plural_checkpoint_lag_for_metadata_only_recovery() {
        let recovered = recovered_state(2, 8, Some(5), true, true);
        let err = ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .unwrap_err()
            .to_string();

        assert!(err.contains("refusing metadata-only recovery"));
        assert!(err.contains("retained 2 committed WAL entries through height 7"));
        assert!(err.contains("checkpoint lags retained WAL tip by 2 blocks"));
        assert!(err.contains("last retained checkpoint: 5"));
        assert!(err.contains("next startup height: 8"));
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_checkpoint_only_rejoin_bootstrap() {
        let recovered = recovered_state(0, 9, Some(8), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("checkpoint-only rejoin bootstrap should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_bootstrap"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_checkpoint_only_rejoin_bootstrap() {
        let recovered = recovered_state(0, 9, Some(8), true, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated checkpoint-only rejoin bootstrap should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=8 checkpoint_tip_relation=checkpoint_only:8 next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:checkpoint_only_bootstrap_after_tail_repair"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_retained_wal_resume_surface() {
        let recovered = recovered_state(2, 12, Some(11), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("retained WAL resume state should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_truncated_retained_wal_resume_surface() {
        let recovered = recovered_state(2, 12, Some(11), true, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated retained WAL resume should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=11 checkpoint_tip_relation=aligned next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_after_tail_repair"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_missing_checkpoint_resume_surface() {
        let recovered = recovered_state(1, 9, None, false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("retained WAL resume without checkpoint metadata should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_missing_checkpoint_resume_surface_after_tail_repair() {
        let recovered = recovered_state(1, 9, None, true, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("retained WAL resume without checkpoint metadata should remain recoverable after tail repair");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=1 checkpoint_height_retained=none checkpoint_tip_relation=missing next_startup_height=9 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_missing_checkpoint_metadata_after_tail_repair"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_lagging_checkpoint_resume_surface() {
        let recovered = recovered_state(3, 8, Some(5), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("retained WAL resume with lagging checkpoint should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=3 checkpoint_height_retained=5 checkpoint_tip_relation=behind:2 next_startup_height=8 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_checkpoint_ahead_resume_mismatch_surface() {
        let recovered = recovered_state(2, 12, Some(15), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("checkpoint-ahead retained WAL resume mismatch should stay recoverable but surface mismatch triage");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_single_block_lagging_checkpoint_resume() {
        let recovered = recovered_state(2, 8, Some(6), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("single-block lagging checkpoint resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            retained_wal_summary(&recovered),
            "retained 2 committed WAL entries through height 7 (checkpoint lags retained WAL tip by 1 block)"
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=6 checkpoint_tip_relation=behind:1 next_startup_height=8 wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging"
        );
    }

    #[test]
    fn recovery_startup_summary_keeps_lagging_join_surface_saturated_at_max_height() {
        let recovered = recovered_state(1, u64::MAX, Some(u64::MAX - 2), false, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("max-height lagging checkpoint resume should remain recoverable for safe join/rejoin");
        assert_eq!(
            retained_wal_summary(&recovered),
            format!(
                "retained 1 committed WAL entry through height {} (checkpoint lags retained WAL tip by 1 block)",
                u64::MAX - 1
            )
        );
        assert_eq!(
            recovery_startup_summary(&recovered),
            format!(
                "retained_wal_entries=1 checkpoint_height_retained={} checkpoint_tip_relation=behind:1 next_startup_height={} wal_tail_truncated=false metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_lagging",
                u64::MAX - 2,
                u64::MAX,
            )
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_reports_checkpoint_ahead_resume_mismatch_surface_after_tail_repair() {
        let recovered = recovered_state(2, 12, Some(15), true, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("checkpoint-ahead retained WAL resume mismatch should stay recoverable after tail repair while surfacing mismatch triage");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=2 checkpoint_height_retained=15 checkpoint_tip_relation=ahead:4 next_startup_height=12 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:retained_wal_resume_checkpoint_ahead_mismatch_after_tail_repair"
        );
    }

    #[test]
    fn ensure_recoverable_wal_state_allows_truncated_fresh_bootstrap() {
        let recovered = recovered_state(0, 1, None, true, false);

        ensure_recoverable_wal_state(Path::new("/tmp/trnm-wal"), &recovered)
            .expect("truncated fresh bootstrap state should remain recoverable");
        assert_eq!(
            recovery_startup_summary(&recovered),
            "retained_wal_entries=0 checkpoint_height_retained=none checkpoint_tip_relation=none next_startup_height=1 wal_tail_truncated=true metadata_only_recovery=false join_rejoin_status=ready:fresh_bootstrap_after_tail_repair"
        );
    }
}
