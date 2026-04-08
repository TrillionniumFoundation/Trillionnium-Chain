use super::*;

fn canonicalize_wal_meta(entries: &mut Vec<WalMeta>) {
    entries.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.round.cmp(&b.round))
            .then_with(|| a.proposal_hash.cmp(&b.proposal_hash))
            .then_with(|| a.committed.cmp(&b.committed))
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            .then_with(|| a.prev_hash_hex.cmp(&b.prev_hash_hex))
    });
    entries.dedup_by(|a, b| a == b);
}

pub(crate) fn load_wal_meta_entries(wal_dir: &Path) -> Result<Vec<WalMeta>> {
    let f = wal_meta_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw =
        fs::read_to_string(&f).with_context(|| format!("read wal meta failed: {}", f.display()))?;
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut list: WalMetaList =
        toml::from_str(&raw).with_context(|| format!("parse wal meta failed: {}", f.display()))?;
    canonicalize_wal_meta(&mut list.entries);
    Ok(list.entries)
}

pub(crate) fn persist_wal_meta_entries(wal_dir: &Path, entries: &[WalMeta]) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_meta_file(wal_dir);
    let mut entries = entries.to_vec();
    canonicalize_wal_meta(&mut entries);
    let raw = toml::to_string(&WalMetaList { entries })?;
    fs::write(&f, raw).with_context(|| format!("write wal meta failed: {}", f.display()))?;
    Ok(())
}

fn canonicalize_checkpoint_meta(checkpoints: &mut [CheckpointMeta]) {
    checkpoints.sort_by(|a, b| {
        a.height
            .cmp(&b.height)
            .then_with(|| a.state_root_hex.cmp(&b.state_root_hex))
            .then_with(|| a.wal_entry_hash_hex.cmp(&b.wal_entry_hash_hex))
    });
}

pub(crate) fn load_checkpoint_meta(wal_dir: &Path) -> Result<Vec<CheckpointMeta>> {
    let f = checkpoint_file(wal_dir);
    if !f.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&f)
        .with_context(|| format!("read checkpoint failed: {}", f.display()))?;
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }
    let mut list: CheckpointMetaList = toml::from_str(&raw)
        .with_context(|| format!("parse checkpoint failed: {}", f.display()))?;
    canonicalize_checkpoint_meta(&mut list.checkpoints);
    Ok(list.checkpoints)
}

pub(crate) fn persist_checkpoint_meta(
    wal_dir: &Path,
    checkpoints: &[CheckpointMeta],
) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = checkpoint_file(wal_dir);
    let mut checkpoints = checkpoints.to_vec();
    canonicalize_checkpoint_meta(&mut checkpoints);
    checkpoints.dedup_by(|a, b| {
        a.height == b.height
            && a.state_root_hex == b.state_root_hex
            && a.wal_entry_hash_hex == b.wal_entry_hash_hex
    });
    let raw = toml::to_string(&CheckpointMetaList { checkpoints })?;
    fs::write(&f, raw).with_context(|| format!("write checkpoint failed: {}", f.display()))?;
    Ok(())
}

pub(crate) fn persist_consensus_wal(wal_dir: &Path, wal: &ConsensusWal) -> Result<()> {
    fs::create_dir_all(wal_dir)?;
    let f = wal_file(wal_dir);
    let raw = toml::to_string(wal)?;
    fs::write(&f, raw).with_context(|| format!("write wal failed: {}", f.display()))?;
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
            "trnm-node-runtime-recovery-wal-{}-{}-{}",
            name,
            std::process::id(),
            now_nanos
        ))
    }

    #[test]
    fn load_wal_meta_canonicalizes_out_of_order_disk_entries_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-load-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&WalMetaList {
            entries: vec![
                WalMeta {
                    height: 3,
                    round: 0,
                    proposal_hash: "proposal-c".into(),
                    committed: true,
                    state_root_hex: "cc".repeat(32),
                    prev_hash_hex: Some("33".repeat(32)),
                },
                WalMeta {
                    height: 1,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "aa".repeat(32),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 2,
                    round: 0,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "bb".repeat(32),
                    prev_hash_hex: Some("22".repeat(32)),
                },
            ],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].height, 1);
        assert_eq!(entries[0].state_root_hex, "aa".repeat(32));
        assert_eq!(entries[1].height, 2);
        assert_eq!(entries[1].state_root_hex, "bb".repeat(32));
        assert_eq!(entries[2].height, 3);
        assert_eq!(entries[2].state_root_hex, "cc".repeat(32));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_canonicalizes_disk_order_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-persist-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(
            &wal_dir,
            &[
                WalMeta {
                    height: 2,
                    round: 0,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "bb".repeat(32),
                    prev_hash_hex: Some("prev-b".into()),
                },
                WalMeta {
                    height: 1,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "aa".repeat(32),
                    prev_hash_hex: Some("prev-a".into()),
                },
                WalMeta {
                    height: 2,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "aa".repeat(32),
                    prev_hash_hex: Some("prev-c".into()),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        let first = raw.find("proposal-a").unwrap();
        let second = raw.rfind("proposal-b").unwrap();
        assert!(first < second, "expected canonical disk order, got: {raw}");

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries[0].height, 1);
        assert_eq!(entries[0].proposal_hash, "proposal-a");
        assert_eq!(entries[1].height, 2);
        assert_eq!(entries[1].proposal_hash, "proposal-a");
        assert_eq!(entries[2].height, 2);
        assert_eq!(entries[2].proposal_hash, "proposal-b");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_canonicalizes_equal_height_entries_for_recovery_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-equal-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&WalMetaList {
            entries: vec![
                WalMeta {
                    height: 7,
                    round: 2,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "root-b".into(),
                    prev_hash_hex: Some("prev-b".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-c".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: false,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(
            entries,
            vec![
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: false,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
                WalMeta {
                    height: 7,
                    round: 1,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-c".into()),
                },
                WalMeta {
                    height: 7,
                    round: 2,
                    proposal_hash: "proposal-b".into(),
                    committed: true,
                    state_root_hex: "root-b".into(),
                    prev_hash_hex: Some("prev-b".into()),
                },
            ]
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_canonicalizes_missing_prev_hash_before_linked_successors_for_recovery_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-persist-canonical-missing-prev-hash-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_wal_meta_entries(
            &wal_dir,
            &[
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-z".into()),
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        let parsed: WalMetaList = toml::from_str(&raw).unwrap();
        assert_eq!(parsed.entries.len(), 3);
        assert_eq!(parsed.entries[0].prev_hash_hex, None);
        assert_eq!(parsed.entries[1].prev_hash_hex.as_deref(), Some("prev-a"));
        assert_eq!(parsed.entries[2].prev_hash_hex.as_deref(), Some("prev-z"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_canonicalizes_missing_prev_hash_before_linked_successors_for_recovery_audit_surfaces() {
        let wal_dir = temp_wal_dir("wal-canonical-missing-prev-hash-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&WalMetaList {
            entries: vec![
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-z".into()),
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: None,
                },
                WalMeta {
                    height: 11,
                    round: 0,
                    proposal_hash: "proposal-a".into(),
                    committed: true,
                    state_root_hex: "root-a".into(),
                    prev_hash_hex: Some("prev-a".into()),
                },
            ],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].prev_hash_hex, None);
        assert_eq!(entries[1].prev_hash_hex.as_deref(), Some("prev-a"));
        assert_eq!(entries[2].prev_hash_hex.as_deref(), Some("prev-z"));

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_wal_meta_deduplicates_identical_entries_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let entry = WalMeta {
            height: 7,
            round: 1,
            proposal_hash: "proposal-7".into(),
            committed: true,
            state_root_hex: "aa".repeat(32),
            prev_hash_hex: Some("bb".repeat(32)),
        };
        persist_wal_meta_entries(&wal_dir, &[entry.clone(), entry.clone()]).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries, vec![entry.clone()]);

        let raw = fs::read_to_string(wal_meta_file(&wal_dir)).unwrap();
        assert_eq!(raw.matches("height = 7").count(), 1, "unexpected raw WAL file: {raw}");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_deduplicates_identical_disk_entries_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-load-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        let entry = WalMeta {
            height: 9,
            round: 0,
            proposal_hash: "proposal-9".into(),
            committed: true,
            state_root_hex: "cc".repeat(32),
            prev_hash_hex: Some("dd".repeat(32)),
        };
        let raw = toml::to_string(&WalMetaList {
            entries: vec![entry.clone(), entry.clone()],
        })
        .unwrap();
        fs::write(wal_meta_file(&wal_dir), raw).unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert_eq!(entries, vec![entry]);

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_checkpoint_meta_canonicalizes_disk_order_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-persist-order");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
            ],
        )
        .unwrap();

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        let parsed: CheckpointMetaList = toml::from_str(&raw).unwrap();
        assert_eq!(
            parsed.checkpoints,
            vec![
                CheckpointMeta {
                    height: 2,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
            ]
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_canonicalizes_equal_height_entries_for_recovery_audit_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-canonical-equal-height-order");
        fs::create_dir_all(&wal_dir).unwrap();

        let raw = toml::to_string(&CheckpointMetaList {
            checkpoints: vec![
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
            ],
        })
        .unwrap();
        fs::write(checkpoint_file(&wal_dir), raw).unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(
            checkpoints,
            vec![
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-c".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ]
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn persist_checkpoint_meta_deduplicates_identical_entries_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-dedup-identical-entries");
        fs::create_dir_all(&wal_dir).unwrap();

        persist_checkpoint_meta(
            &wal_dir,
            &[
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 7,
                    state_root_hex: "root-a".into(),
                    wal_entry_hash_hex: "hash-a".into(),
                },
                CheckpointMeta {
                    height: 8,
                    state_root_hex: "root-b".into(),
                    wal_entry_hash_hex: "hash-b".into(),
                },
            ],
        )
        .unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert_eq!(checkpoints.len(), 2);
        assert_eq!(checkpoints[0].height, 7);
        assert_eq!(checkpoints[0].state_root_hex, "root-a");
        assert_eq!(checkpoints[0].wal_entry_hash_hex, "hash-a");
        assert_eq!(checkpoints[1].height, 8);
        assert_eq!(checkpoints[1].state_root_hex, "root-b");
        assert_eq!(checkpoints[1].wal_entry_hash_hex, "hash-b");

        let raw = fs::read_to_string(checkpoint_file(&wal_dir)).unwrap();
        assert_eq!(raw.matches("height = 7").count(), 1, "unexpected raw checkpoint file: {raw}");

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_treats_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("checkpoint-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(checkpoint_file(&wal_dir), "  \n\t").unwrap();

        let checkpoints = load_checkpoint_meta(&wal_dir).unwrap();
        assert!(checkpoints.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_unknown_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-unknown-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                checkpoints = []
                forged = true
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_checkpoint_meta_rejects_unknown_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("checkpoint-unknown-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            checkpoint_file(&wal_dir),
            r#"
                [[checkpoints]]
                height = 7
                state_root_hex = "aa"
                wal_entry_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap();

        let err = load_checkpoint_meta(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_treats_blank_files_as_empty_metadata_scaffolds() {
        let wal_dir = temp_wal_dir("wal-blank-scaffold");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(wal_meta_file(&wal_dir), "\n  \t").unwrap();

        let entries = load_wal_meta_entries(&wal_dir).unwrap();
        assert!(entries.is_empty());

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_unknown_top_level_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-unknown-top-level-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                entries = []
                forged = true
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }

    #[test]
    fn load_wal_meta_rejects_unknown_entry_fields_for_recovery_surfaces() {
        let wal_dir = temp_wal_dir("wal-unknown-entry-field");
        fs::create_dir_all(&wal_dir).unwrap();
        fs::write(
            wal_meta_file(&wal_dir),
            r#"
                [[entries]]
                height = 7
                round = 1
                proposal_hash = "proposal-7"
                committed = true
                state_root_hex = "aa"
                prev_hash_hex = "bb"
                forged = true
            "#,
        )
        .unwrap();

        let err = load_wal_meta_entries(&wal_dir).unwrap_err().to_string();
        assert!(
            err.contains("unknown field") && err.contains("forged"),
            "unexpected parse error: {err}"
        );

        let _ = fs::remove_dir_all(&wal_dir);
    }
}
